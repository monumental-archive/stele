// Internal tests for the assert verb's dispatch: the registry seam
// is swapped for a scripted fake so every guard, exit path and the
// three-way verdict→exit mapping are table rows.

package cli

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/oci"
	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

const (
	assertDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	assertChild  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// scriptedOCI serves one index and one label map for every read.
type scriptedOCI struct {
	index    string
	indexErr error
	labels   map[string]string
}

func (s scriptedOCI) Index(_, _ string) ([]byte, error) {
	if s.indexErr != nil {
		return nil, s.indexErr
	}

	return []byte(s.index), nil
}

func (s scriptedOCI) ConfigLabels(_, _ string) (map[string]string, error) {
	return s.labels, nil
}

func swapOCI(t *testing.T, r oci.Reader) {
	t.Helper()

	orig := newOCIReader
	newOCIReader = func() oci.Reader { return r }

	t.Cleanup(func() { newOCIReader = orig })
}

func cleanOCI() scriptedOCI {
	return scriptedOCI{
		index: `{"mediaType": "application/vnd.oci.image.index.v1+json",
		  "annotations": {"rev": "abc"},
		  "manifests": [{"digest": "` + assertChild + `", "platform": {"os": "linux", "architecture": "amd64"}}]}`,
		labels: map[string]string{"rev": "abc"},
	}
}

func setImageFactsEnv(t *testing.T, facts string) {
	t.Helper()
	t.Setenv("IMAGE", "ghcr.io/acme/widget")
	t.Setenv("DIGEST", assertDigest)
	t.Setenv("FACTS", facts)
}

func TestAssertImageFactsExitCodes(t *testing.T) {
	tests := []struct {
		name  string
		reg   scriptedOCI
		facts string
		want  int
		out   string
	}{
		{"equal facts pass", cleanOCI(), `{"rev": "abc"}`, exitOK, "assert: PASS"},
		{"drifted facts fail", cleanOCI(), `{"rev": "zzz"}`, exitRefused, "diverges"},
		{
			"a dead registry is blind, not a verdict",
			scriptedOCI{indexErr: errors.New("registry torn")},
			`{"rev": "abc"}`,
			exitBlind, "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swapOCI(t, tt.reg)
			setImageFactsEnv(t, tt.facts)

			var stdout, stderr bytes.Buffer

			code := Run([]string{"assert", "image-facts"}, &stdout, &stderr)
			if code != tt.want {
				t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s", code, tt.want, stdout.String(), stderr.String())
			}

			if tt.out != "" && !strings.Contains(stdout.String(), tt.out) {
				t.Fatalf("stdout = %q, want substring %q", stdout.String(), tt.out)
			}
		})
	}
}

// TestAssertImageFactsJSON pins the --json contract: one document on
// stdout in every outcome, including the blind one.
func TestAssertImageFactsJSON(t *testing.T) {
	t.Run("blind run still emits a CANNOT_JUDGE document", func(t *testing.T) {
		swapOCI(t, scriptedOCI{indexErr: errors.New("registry torn")})
		setImageFactsEnv(t, `{"rev": "abc"}`)

		var stdout, stderr bytes.Buffer

		if code := Run([]string{"assert", "image-facts", "--json"}, &stdout, &stderr); code != exitBlind {
			t.Fatalf("Run = %d, want %d", code, exitBlind)
		}

		doc := decodeReport(t, &stdout)
		if doc.Verdict == nil || *doc.Verdict != "CANNOT_JUDGE" {
			t.Fatalf("verdict = %v, want CANNOT_JUDGE", doc.Verdict)
		}

		if len(doc.Findings) != 1 || !strings.Contains(doc.Findings[0].Detail, "registry torn") {
			t.Fatalf("findings = %+v, want the registry error carried", doc.Findings)
		}
	})

	t.Run("passing run emits a PASS document", func(t *testing.T) {
		swapOCI(t, cleanOCI())
		setImageFactsEnv(t, `{"rev": "abc"}`)

		var stdout, stderr bytes.Buffer

		if code := Run([]string{"assert", "image-facts", "--json"}, &stdout, &stderr); code != exitOK {
			t.Fatalf("Run = %d, stderr: %s", code, stderr.String())
		}

		doc := decodeReport(t, &stdout)
		if doc.Verdict == nil || *doc.Verdict != "PASS" {
			t.Fatalf("verdict = %v, want PASS", doc.Verdict)
		}
	})
}

func TestAssertUsageRefusals(t *testing.T) {
	rows := [][]string{
		{"assert"},
		{"assert", "conjure"},
		{"assert", "image-facts", "--no-such-flag"},
	}

	for _, args := range rows {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := Run(args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("Run = %d, want %d", code, exitUsage)
			}
		})
	}

	t.Run("each missing env input refuses by name", func(t *testing.T) {
		swapOCI(t, cleanOCI())

		for _, unset := range []string{"IMAGE", "DIGEST", "FACTS"} {
			setImageFactsEnv(t, `{"rev": "abc"}`)
			t.Setenv(unset, "")

			var stdout, stderr bytes.Buffer

			if code := Run([]string{"assert", "image-facts"}, &stdout, &stderr); code != exitUsage {
				t.Fatalf("unset %s: Run = %d, want %d", unset, code, exitUsage)
			}

			if !strings.Contains(stderr.String(), unset+" must be set") {
				t.Fatalf("unset %s: stderr = %q, want the name", unset, stderr.String())
			}
		}
	})
}

// TestAssertOutputFailures pins the stream contract for the verb.
func TestAssertOutputFailures(t *testing.T) {
	t.Run("dead stdout during a passing run", func(t *testing.T) {
		swapOCI(t, cleanOCI())
		setImageFactsEnv(t, `{"rev": "abc"}`)

		var stderr bytes.Buffer

		if code := Run([]string{"assert", "image-facts"}, failWriterI{}, &stderr); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})

	t.Run("dead stdout during a --json run", func(t *testing.T) {
		swapOCI(t, cleanOCI())
		setImageFactsEnv(t, `{"rev": "abc"}`)

		var stderr bytes.Buffer

		if code := Run([]string{"assert", "image-facts", "--json"}, failWriterI{}, &stderr); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})

	t.Run("dead stderr on a usage error", func(t *testing.T) {
		if code := Run([]string{"assert"}, failWriterI{}, failWriterI{}); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})
}

// evidenceSnapshot writes a replayable snapshot of one conforming
// release, plus the policy and debt files — the whole evidence walk
// end to end with no live API.
func evidenceSnapshot(t *testing.T) (string, string) { //nolint:gocritic // snapshot dir, policy path
	t.Helper()

	dir := t.TempDir()
	digest := strings.Repeat("5", 64)
	stmt := `{"_type": "https://in-toto.io/Statement/v1",` +
		`"subject": [{"name": "app", "digest": {"sha256": "` + digest + `"}}],` +
		`"predicateType": "https://slsa.dev/verification_summary/v1", "predicate": {}}`
	bundle := `{"dsseEnvelope": {"payload": "` + base64.StdEncoding.EncodeToString([]byte(stmt)) + `"}}`

	files := map[string]string{
		"snap/acme/repos.json":       `["widget"]`,
		"snap/acme/widget/tags.json": `["v1.0.0"]`,
		"snap/acme/widget/releases/v1.0.0/assets.json": `["evidence-manifest.json", "app.spdx.json", ` +
			`"checksums.txt", "attestations-image.intoto.jsonl"]`,
		"snap/acme/widget/releases/v1.0.0/assets/evidence-manifest.json": `{"schema": 1, ` +
			`"classes": ["oci-image"], "storeVsa": true}`,
		"snap/acme/widget/releases/v1.0.0/assets/attestations-image.intoto.jsonl": bundle,
		"snap/acme/widget/attestations/" + digest + ".json":                       `[` + bundle + `]`,
		"policy.json": `{"schema": 1, "evidence": {"sbomSuffix": ".spdx.json", ` +
			`"checksums": "checksums.txt", "umbrellaBundle": "attestations.intoto.jsonl", ` +
			`"manifestAsset": "evidence-manifest.json", "debtFile": "no-such-debt.txt", ` +
			`"classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}}}`,
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

	return filepath.Join(dir, "snap"), filepath.Join(dir, "policy.json")
}

// TestAssertEvidenceSnapshotEndToEnd replays a captured snapshot
// through the whole verb: PASS as text and as a document.
func TestAssertEvidenceSnapshotEndToEnd(t *testing.T) {
	snap, policy := evidenceSnapshot(t)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "evidence", "--org", "acme", "--policy", policy, "--snapshot", snap, "--json",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	doc := decodeReport(t, &stdout)
	if doc.Verdict == nil || *doc.Verdict != "PASS" {
		t.Fatalf("verdict = %v, want PASS", doc.Verdict)
	}
}

func TestAssertEvidenceUsageRefusals(t *testing.T) {
	snap, policy := evidenceSnapshot(t)

	rows := [][]string{
		{"assert", "evidence", "--policy", policy},
		{"assert", "evidence", "--org", "acme"},
		{"assert", "evidence", "--org", "acme", "--repo", "acme/widget", "--policy", policy},
		{"assert", "evidence", "--repo", "solo", "--policy", policy},
		{"assert", "evidence", "--org", "acme", "--policy", policy, "--snapshot", snap, "--capture", snap},
		{"assert", "evidence", "--org", "acme", "--policy", "/no/such/policy.json"},
	}

	for _, args := range rows {
		t.Run(strings.Join(args[2:], " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := Run(args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("Run = %d, want %d; stderr: %s", code, exitUsage, stderr.String())
			}
		})
	}

	t.Run("a malformed debt file refuses", func(t *testing.T) {
		debt := filepath.Join(t.TempDir(), "debt.txt")
		if err := os.WriteFile(debt, []byte("not a debt line\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"assert", "evidence", "--org", "acme", "--policy", policy, "--snapshot", snap, "--debt", debt,
		}, &stdout, &stderr)
		if code != exitUsage {
			t.Fatalf("Run = %d, want %d", code, exitUsage)
		}
	})
}

// blastSnapshot writes a replayable snapshot of one release carrying
// an attested SBOM, plus the blast-radius policy and a VEX directory
// deciding the one scripted finding. Returns the snapshot dir, policy path and vex dir.
//
//nolint:gocritic // unnamedResult: three homogeneous paths, named in the comment
func blastSnapshot(t *testing.T) (string, string, string) {
	t.Helper()

	dir := t.TempDir()
	sbom := `{"spdxVersion": "SPDX-2.3"}`
	digest := chain.SHA256Hex([]byte(sbom))

	files := map[string]string{
		"snap/acme/repos.json":                                  `["widget"]`,
		"snap/acme/widget/tags.json":                            `["v1.0.0"]`,
		"snap/acme/widget/releases/v1.0.0/assets.json":          `["app.spdx.json"]`,
		"snap/acme/widget/releases/v1.0.0/assets/app.spdx.json": sbom,
		"snap/acme/widget/attestations/" + digest + ".json":     `[{"bundle": 1}]`,
		"policy.json": `{"schema": 1, "evidence": {"sbomSuffix": ".spdx.json", ` +
			`"checksums": "checksums.txt", "umbrellaBundle": "attestations.intoto.jsonl", ` +
			`"manifestAsset": "evidence-manifest.json", "debtFile": "no-such-debt.txt", ` +
			`"classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}}, ` +
			`"blastRadius": {"osEcosystems": ["debian"], ` +
			`"canary": {"repo": "widget", "tag": "v1.0.0", "advisory": "RUSTSEC-2021-0127"}}}`,
		"vex/decided.openvex.json": `{"statements": [{"vulnerability": {"name": "RUSTSEC-2021-0127"}, ` +
			`"products": [{"@id": "pkg:cargo/serde_cbor@0.11.2"}]}]}`,
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

	return filepath.Join(dir, "snap"), filepath.Join(dir, "policy.json"), filepath.Join(dir, "vex")
}

// cliScanner scripts the scanner seam for CLI tests.
type cliScanner struct{ out string }

func (s cliScanner) Scan([]byte) ([]byte, error) { return []byte(s.out), nil }

func swapScanner(t *testing.T, s osv.Scanner) {
	t.Helper()

	orig := newScanner
	newScanner = func() osv.Scanner { return s }

	t.Cleanup(func() { newScanner = orig })
}

func TestAssertBlastRadiusEndToEnd(t *testing.T) {
	snap, policy, vex := blastSnapshot(t)
	swapScanner(t, cliScanner{out: `{"results": [{"packages": [{
	  "package": {"name": "serde_cbor", "version": "0.11.2", "ecosystem": "crates.io"},
	  "vulnerabilities": [{"id": "RUSTSEC-2021-0127", "affected": []}]}]}]}`})

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "blast-radius", "--org", "acme", "--policy", policy, "--vex", vex,
		"--snapshot", snap, "--json",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	doc := decodeReport(t, &stdout)
	if doc.Verdict == nil || *doc.Verdict != "PASS" {
		t.Fatalf("verdict = %v, want PASS", doc.Verdict)
	}
}

func TestAssertBlastRadiusUsageRefusals(t *testing.T) {
	snap, policy, vex := blastSnapshot(t)

	rows := [][]string{
		{"assert", "blast-radius", "--policy", policy, "--vex", vex},
		{"assert", "blast-radius", "--org", "acme", "--vex", vex},
		{"assert", "blast-radius", "--org", "acme", "--policy", policy},
		{
			"assert", "blast-radius", "--org", "acme", "--policy", policy, "--vex", vex,
			"--snapshot", snap, "--capture", snap,
		},
	}

	for _, args := range rows {
		t.Run(strings.Join(args[2:], " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := Run(args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("Run = %d, want %d", code, exitUsage)
			}
		})
	}

	t.Run("a malformed vex document refuses", func(t *testing.T) {
		bad := t.TempDir()
		if err := os.WriteFile(filepath.Join(bad, "x.openvex.json"), []byte("not json"), 0o600); err != nil {
			t.Fatal(err)
		}

		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"assert", "blast-radius", "--org", "acme", "--policy", policy, "--vex", bad, "--snapshot", snap,
		}, &stdout, &stderr)
		if code != exitUsage {
			t.Fatalf("Run = %d, want %d", code, exitUsage)
		}
	})

	t.Run("an absent vex directory decides nothing and gates", func(t *testing.T) {
		swapScanner(t, cliScanner{out: `{"results": [{"packages": [{
		  "package": {"name": "serde_cbor", "version": "0.11.2", "ecosystem": "crates.io"},
		  "vulnerabilities": [{"id": "RUSTSEC-2021-0127", "affected": []}]}]}]}`})

		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"assert", "blast-radius", "--org", "acme", "--policy", policy,
			"--vex", filepath.Join(t.TempDir(), "no-such-dir"), "--snapshot", snap,
		}, &stdout, &stderr)
		if code != exitRefused {
			t.Fatalf("Run = %d, want %d — nothing decided must gate", code, exitRefused)
		}
	})
}

// storeForge serves scripted attestation bundles for the attestor.
type storeForge struct {
	scriptedOCI

	bundles []jsonx.Raw
	err     error
}

func (s *storeForge) Attestations(_, _, _ string) ([]jsonx.Raw, error) { return s.bundles, s.err }
func (s *storeForge) Repos(string) ([]string, error)                   { return nil, nil }
func (s *storeForge) ReleaseTags(_, _ string) ([]string, error)        { return nil, nil }
func (s *storeForge) ReleaseAssets(_, _, _ string) ([]string, error)   { return nil, nil }
func (s *storeForge) Asset(_, _, _, _ string) ([]byte, error)          { return nil, nil }

//nolint:gocritic // unnamedResult: the Forge interface documents the results
func (s *storeForge) FileAt(_, _, _, _ string) ([]byte, bool, error)      { return nil, false, nil }
func (s *storeForge) PackageVersionDigest(_, _, _ string) (string, error) { return "", nil }
func (s *storeForge) WorkflowContents(_, _ string) ([][]byte, error)      { return nil, nil }
func (s *storeForge) FailedRuns(_, _, _ string) ([]string, error)         { return nil, nil }
func (s *storeForge) TagCommit(_, _, _ string) (string, error)            { return "", nil }

// attestorBV scripts the cryptographic boundary.
type attestorBV struct {
	err     error
	payload string
	pin     string
}

func (b attestorBV) Attestation([]byte, trust.Identity, string) (*trust.Verified, error) {
	if b.err != nil {
		return nil, b.err
	}

	v := &trust.Verified{Payload: []byte(b.payload)}
	v.Extensions.BuildSignerDigest = b.pin

	return v, nil
}

func (b attestorBV) Blob([]byte, trust.Identity, string) (*trust.Verified, error) {
	return nil, errUnusedSeam
}

var errUnusedSeam = errors.New("this seam is not exercised by the attestor tests")

func (b attestorBV) Peek([]byte) ([]byte, error) { return nil, errUnusedSeam }

const okStatement = `{"predicateType": "https://acme.example/approval/v1"}`

// TestStoreAttestor pins the rule that decides whether a stored
// attestation counts: it must verify, carry the required predicate,
// and (when pins are given) be signed from one of them.
func TestStoreAttestor(t *testing.T) {
	t.Parallel()

	one := []jsonx.Raw{jsonx.Raw(`{"bundle": 1}`)}
	pin := strings.Repeat("a", 40)

	tests := []struct {
		name      string
		forge     storeForge
		bv        attestorBV
		pins      []string
		predicate string
		wantErr   string
	}{
		{
			"a verifying bundle with no pin required passes",
			storeForge{bundles: one},
			attestorBV{payload: okStatement},
			nil, "", "",
		},
		{
			"a verifying bundle signed at an expected pin passes",
			storeForge{bundles: one},
			attestorBV{payload: okStatement, pin: pin},
			[]string{pin},
			"", "",
		},
		{
			"a bundle signed at an unexpected pin refuses",
			storeForge{bundles: one},
			attestorBV{payload: okStatement, pin: "b"},
			[]string{pin},
			"", "not the declared pin",
		},
		{
			"a bundle carrying the wrong predicate refuses",
			storeForge{bundles: one},
			attestorBV{payload: okStatement},
			nil,
			"https://acme.example/other/v1", "predicate type is not",
		},
		{
			"a bundle carrying the required predicate passes",
			storeForge{bundles: one},
			attestorBV{payload: okStatement},
			nil,
			"https://acme.example/approval/v1", "",
		},
		{
			"an empty store refuses by name",
			storeForge{},
			attestorBV{payload: okStatement},
			nil, "", "holds no attestation",
		},
		{
			"a refused signature surfaces",
			storeForge{bundles: one},
			attestorBV{err: errors.New("cert not trusted")},
			nil, "", "cert not trusted",
		},
		{
			"a store read failure surfaces as such",
			storeForge{err: errors.New("store torn")},
			attestorBV{payload: okStatement},
			nil, "", "store torn",
		},
		{
			"a verified payload that is not a statement refuses",
			storeForge{bundles: one},
			attestorBV{payload: "not json"},
			nil,
			"https://acme.example/approval/v1", "not a statement",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := storeAttestor{forge: &tt.forge, bv: tt.bv, issuer: "https://issuer.example"}

			candidates := []assert.Candidate{{
				Identity: "https://github.com/acme/signer/.github/workflows/sign.yml@refs/heads/main",
			}}
			if len(tt.pins) > 0 {
				candidates = nil
				for _, p := range tt.pins {
					candidates = append(candidates, assert.Candidate{
						Identity: "https://github.com/acme/signer/.github/workflows/sign.yml@" + p, SignerPin: p,
					})
				}
			}

			err := a.Verify("acme", "widget", "sha256:"+strings.Repeat("c", 64), candidates, tt.predicate)

			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("Verify = %v, want nil", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("Verify = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

// storeSnapshot writes a snapshot plus a policy declaring the store
// halves, so the CLI's trusted-root and pin-file guards are reachable.
//
//nolint:gocritic // unnamedResult: snapshot dir, policy path
func storeSnapshot(t *testing.T) (string, string) {
	t.Helper()

	snap, _ := evidenceSnapshot(t)
	dir := filepath.Dir(snap)
	policy := filepath.Join(dir, "store-policy.json")

	content := `{"schema": 1, "issuer": "https://token.actions.githubusercontent.com",
	  "evidence": {"sbomSuffix": ".spdx.json", "checksums": "checksums.txt",
	    "umbrellaBundle": "attestations.intoto.jsonl", "manifestAsset": "evidence-manifest.json",
	    "debtFile": "no-such-debt.txt",
	    "classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}},
	    "baseImages": {"pinFile": "no-such-pins.toml", "attestorRepo": ".github",
	      "attestorIdentity": "https://github.com/acme/.github/.github/workflows/base-attest.yml@refs/heads/main",
	      "predicateType": "https://acme.example/approval/v1"}}}`

	if err := os.WriteFile(policy, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return snap, policy
}

// TestAssertEvidenceStoreGuards pins the CLI contract for the store
// halves: declaring them without a trusted root is a usage refusal
// (never a silent skip), and so is a declared pin file absent from
// the checkout — the likelier cause is the wrong working directory,
// and proceeding would judge nothing while looking green.
func TestAssertEvidenceStoreGuards(t *testing.T) {
	snap, policy := storeSnapshot(t)

	t.Run("no trusted root refuses by name", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"assert", "evidence", "--org", "acme", "--policy", policy, "--snapshot", snap,
		}, &stdout, &stderr)
		if code != exitUsage {
			t.Fatalf("Run = %d, want %d", code, exitUsage)
		}

		if !strings.Contains(stderr.String(), "trusted-root") {
			t.Fatalf("stderr = %q, want the named refusal", stderr.String())
		}
	})

	t.Run("an unreadable trusted root refuses", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"assert", "evidence", "--org", "acme", "--policy", policy, "--snapshot", snap,
			"--trusted-root", "/no/such/root.json",
		}, &stdout, &stderr)
		if code != exitUsage {
			t.Fatalf("Run = %d, want %d", code, exitUsage)
		}
	})

	t.Run("a declared pin file absent from the checkout refuses by name", func(t *testing.T) {
		swapOCI(t, cleanOCI())

		root := filepath.Join(t.TempDir(), "root.json")
		if err := os.WriteFile(root, []byte(`{"any": "bytes — the seam swallows them"}`), 0o600); err != nil {
			t.Fatal(err)
		}

		orig := newBundleVerifier
		newBundleVerifier = func([]byte) (verify.BundleVerifier, error) { return attestorBV{payload: okStatement}, nil }

		t.Cleanup(func() { newBundleVerifier = orig })

		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"assert", "evidence", "--org", "acme", "--policy", policy, "--snapshot", snap,
			"--trusted-root", root, "--json",
		}, &stdout, &stderr)
		if code != exitUsage {
			t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s", code, exitUsage, stdout.String(), stderr.String())
		}

		if !strings.Contains(stderr.String(), "no-such-pins.toml") {
			t.Fatalf("stderr = %q, want the refusal to name the declared pin file", stderr.String())
		}
	})

	t.Run("an unknown depth refuses by name", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"assert", "evidence", "--org", "acme", "--policy", policy, "--snapshot", snap,
			"--trusted-root", "/no/such/root.json", "--depth", "bottomless",
		}, &stdout, &stderr)
		if code != exitUsage || !strings.Contains(stderr.String(), "bottomless") {
			t.Fatalf("Run = %d, stderr = %q — want the depth refusal", code, stderr.String())
		}
	})

	t.Run("full depth without a verify policy refuses by name", func(t *testing.T) {
		swapOCI(t, cleanOCI())

		root := filepath.Join(t.TempDir(), "root.json")
		if err := os.WriteFile(root, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}

		orig := newBundleVerifier
		newBundleVerifier = func([]byte) (verify.BundleVerifier, error) { return attestorBV{payload: okStatement}, nil }

		t.Cleanup(func() { newBundleVerifier = orig })

		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"assert", "evidence", "--org", "acme", "--policy", policy, "--snapshot", snap,
			"--trusted-root", root, "--depth", "full",
		}, &stdout, &stderr)
		if code != exitUsage || !strings.Contains(stderr.String(), "verify-policy") {
			t.Fatalf("Run = %d, stderr = %q — full depth must not silently run shallow", code, stderr.String())
		}
	})

	t.Run("a root plus a present pin file walks clean", func(t *testing.T) {
		swapOCI(t, cleanOCI())

		dir := t.TempDir()

		root := filepath.Join(dir, "root.json")
		if err := os.WriteFile(root, []byte(`{"any": "bytes — the seam swallows them"}`), 0o600); err != nil {
			t.Fatal(err)
		}

		pins := filepath.Join(dir, "pins.toml")
		baseHex := strings.Repeat("8", 64)
		pinLine := `images = ["docker.io/library/debian:trixie@sha256:` + baseHex + `"]`

		if err := os.WriteFile(pins, []byte(pinLine), 0o600); err != nil {
			t.Fatal(err)
		}

		// The snapshot's store must hold a bundle for the pin — the
		// seam-swapped verifier accepts any bytes it is handed.
		attDir := filepath.Join(snap, "acme", ".github", "attestations")
		if err := os.MkdirAll(attDir, 0o750); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(attDir, baseHex+".json"), []byte(`[{"bundle": true}]`), 0o600); err != nil {
			t.Fatal(err)
		}

		orig := newBundleVerifier
		newBundleVerifier = func([]byte) (verify.BundleVerifier, error) { return attestorBV{payload: okStatement}, nil }

		t.Cleanup(func() { newBundleVerifier = orig })

		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"assert", "evidence", "--org", "acme", "--policy", policy, "--snapshot", snap,
			"--trusted-root", root, "--base-pins", pins, "--json",
		}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}
	})
}
