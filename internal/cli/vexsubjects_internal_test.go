// `derive vex-subjects` through the verb: the argument surface, the
// document it places, and the write guards on every stream it uses.
// The derivation itself is the engine's (internal/vexsubjects); what
// is pinned here is that the verb reaches it with the org's own
// declarations and reports what it found.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/vexsubjects"
)

// vexSubjectsSnapshot writes a replayable org: one release shipping an
// attested inventory that names the decided package, its checksum
// manifest, and one release that ships neither. Returns the snapshot
// dir, the assert policy path and the decision document path.
//
//nolint:gocritic // unnamedResult: three homogeneous paths, named in the comment
func vexSubjectsSnapshot(t *testing.T) (string, string, string) {
	t.Helper()

	dir := t.TempDir()
	sbom := `{"spdxVersion": "SPDX-2.3"}`
	digest := chain.SHA256Hex([]byte(sbom))
	sums := strings.Repeat("a", 64) + "  widget-1.0.0.tar.gz\n" +
		strings.Repeat("b", 64) + "  app.spdx.json\n"

	files := map[string]string{
		"snap/acme/repos.json":                                  `[{"name": "widget"}]`,
		"snap/acme/widget/tags.json":                            `["v1.0.0"]`,
		"snap/acme/widget/releases/v1.0.0/assets.json":          `["app.spdx.json", "checksums.txt"]`,
		"snap/acme/widget/releases/v1.0.0/assets/app.spdx.json": sbom,
		"snap/acme/widget/releases/v1.0.0/assets/checksums.txt": sums,
		"snap/acme/widget/attestations/" + digest + ".json":     `[{"bundle": 1}]`,
		"policy.json": `{"schema": 7, "evidence": {"sbomSuffix": ".spdx.json", ` +
			`"checksums": "checksums.txt", "umbrellaBundle": "attestations.intoto.jsonl", ` +
			`"manifestAsset": "evidence-manifest.json", ` +
			`"classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}}, ` +
			`"blastRadius": {"osEcosystems": ["debian"]}}`,
		"decision.openvex.json": `{"timestamp": "2026-01-01T00:00:00Z",
	  "statements": [{"vulnerability": {"name": "RUSTSEC-2021-0127"}, "status": "not_affected",
	   "products": [{"@id": "pkg:cargo/serde_cbor@0.11.2"}]}]}`,
	}

	for path, content := range files {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return filepath.Join(dir, "snap"), filepath.Join(dir, "policy.json"),
		filepath.Join(dir, "decision.openvex.json")
}

// vexSubjectsScan is the scripted scan: the inventory carries the
// decided package version.
const vexSubjectsScan = `{"results": [{"packages": [{
  "package": {"name": "serde_cbor", "version": "0.11.2", "ecosystem": "crates.io"},
  "vulnerabilities": [{"id": "RUSTSEC-2021-0127", "affected": []}]}]}]}`

func TestDeriveVEXSubjectsEndToEnd(t *testing.T) {
	snap, policy, decision := vexSubjectsSnapshot(t)
	swapScanner(t, cliScanner{out: vexSubjectsScan})

	out := filepath.Join(t.TempDir(), "subjects.json")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"derive", "vex-subjects", "--org", "acme", "--policy", policy,
		"--decision", decision, "--snapshot", snap, "--out", out,
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	written, err := os.ReadFile(out) //nolint:gosec // a path this test named
	if err != nil {
		t.Fatalf("the document was not written: %v", err)
	}

	doc, err := jsonx.DecodeBytes[vexsubjects.Document](written)
	if err != nil {
		t.Fatalf("the document does not decode: %v\n%s", err, written)
	}

	if len(doc.Releases) != 1 || doc.Releases[0].Subject() != "widget@v1.0.0" {
		t.Fatalf("releases = %+v, want the affected release", doc.Releases)
	}

	if len(doc.Subjects) != 2 {
		t.Errorf("subjects = %+v, want the release's whole manifest", doc.Subjects)
	}

	if doc.Decision != decision {
		t.Errorf("decision = %q, want the document it was derived for", doc.Decision)
	}

	// The verb says what it found on the progress stream: a derivation
	// nobody can read is one nobody can check.
	if !strings.Contains(stdout.String(), "widget@v1.0.0") {
		t.Errorf("stdout = %q, want the affected release named", stdout.String())
	}
}

// TestDeriveVEXSubjectsRefusals pins the argument surface and the two
// refusals the verb owns: a policy that cannot answer the join, and a
// decision reaching no published release.
func TestDeriveVEXSubjectsRefusals(t *testing.T) {
	snap, policy, decision := vexSubjectsSnapshot(t)

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no policy", []string{"derive", "vex-subjects", "--org", "acme"}, exitUsage},
		{
			"no decision",
			[]string{"derive", "vex-subjects", "--org", "acme", "--policy", policy},
			exitUsage,
		},
		{
			"no population",
			[]string{"derive", "vex-subjects", "--policy", policy, "--decision", decision},
			exitUsage,
		},
		{
			"two populations",
			[]string{
				"derive", "vex-subjects", "--policy", policy, "--decision", decision,
				"--org", "acme", "--repo", "acme/widget",
			},
			exitUsage,
		},
		{
			"a repo that is not owner/name",
			[]string{"derive", "vex-subjects", "--policy", policy, "--decision", decision, "--repo", "widget"},
			exitUsage,
		},
		{
			"a decision document that is not there",
			[]string{
				"derive", "vex-subjects", "--org", "acme", "--policy", policy,
				"--decision", filepath.Join(t.TempDir(), "absent.openvex.json"), "--snapshot", snap,
			},
			exitRefused,
		},
		{
			"a policy that is not there",
			[]string{
				"derive", "vex-subjects", "--org", "acme",
				"--policy", filepath.Join(t.TempDir(), "absent.json"),
				"--decision", decision, "--snapshot", snap,
			},
			exitRefused,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swapScanner(t, cliScanner{out: vexSubjectsScan})

			var stdout, stderr bytes.Buffer

			if code := Run(tt.args, &stdout, &stderr); code != tt.want {
				t.Fatalf("Run = %d, want %d; stderr: %s", code, tt.want, stderr.String())
			}
		})
	}
}

// TestDeriveVEXSubjectsWithoutBlastRadius pins the policy guard: the
// base-layer classification the join reads is declared in the
// blastRadius section, and a policy without one cannot answer it.
func TestDeriveVEXSubjectsWithoutBlastRadius(t *testing.T) {
	snap, _, decision := vexSubjectsSnapshot(t)
	swapScanner(t, cliScanner{out: vexSubjectsScan})

	policy := filepath.Join(t.TempDir(), "policy.json")
	body := `{"schema": 7, "evidence": {"sbomSuffix": ".spdx.json", ` +
		`"checksums": "checksums.txt", "umbrellaBundle": "attestations.intoto.jsonl", ` +
		`"manifestAsset": "evidence-manifest.json", ` +
		`"classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}}}`

	if err := os.WriteFile(policy, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"derive", "vex-subjects", "--org", "acme", "--policy", policy,
		"--decision", decision, "--snapshot", snap,
	}, &stdout, &stderr)
	if code != exitRefused {
		t.Fatalf("Run = %d, want %d; stderr: %s", code, exitRefused, stderr.String())
	}

	if !strings.Contains(stderr.String(), "declares no blastRadius section") {
		t.Errorf("stderr = %q, want the undeclared-section refusal", stderr.String())
	}
}

// TestDeriveVEXSubjectsReachingNothing pins the bound-to-nothing
// refusal end to end: a decision no published release ships is a claim
// with no subject, and signing one would bind a judgment to nothing.
func TestDeriveVEXSubjectsReachingNothing(t *testing.T) {
	snap, policy, decision := vexSubjectsSnapshot(t)
	swapScanner(t, cliScanner{out: `{"results": []}`})

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"derive", "vex-subjects", "--org", "acme", "--policy", policy,
		"--decision", decision, "--snapshot", snap,
	}, &stdout, &stderr)
	if code != exitRefused {
		t.Fatalf("Run = %d, want %d; stderr: %s", code, exitRefused, stderr.String())
	}

	if !strings.Contains(stderr.String(), "no published release ships a package") {
		t.Errorf("stderr = %q, want the bound-to-nothing refusal", stderr.String())
	}
}

// TestDeriveVEXSubjectsWriteFailures sweeps every write the mode
// makes: a derivation that failed to say what it found must not exit
// clean.
func TestDeriveVEXSubjectsWriteFailures(t *testing.T) {
	snap, policy, decision := vexSubjectsSnapshot(t)
	swapScanner(t, cliScanner{out: vexSubjectsScan})

	sweepWriteFailures(t, []string{
		"derive", "vex-subjects", "--org", "acme", "--policy", policy,
		"--decision", decision, "--snapshot", snap,
	})
}
