// The release leg's passing path, end to end through the verb. The
// cryptography is the only thing stood in for: truthfulBV checks the
// identity and the covered digest exactly as the real boundary does,
// and internal/trust proves the signatures themselves against real
// signed material. Everything above — the policy, the provenance
// content, the decision, the coverage close — is the production code
// path a stranger runs.

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

// The release coordinates every fixture below agrees on. The pins are
// the two the verb takes on the command line.
const (
	relTag      = "v1.2.3"
	relSignerWF = "acme/signer/.github/workflows/sign.yml"
	relDecideWF = "acme/canon/.github/workflows/publish.yml"
	relSrcRev   = "cccccccccccccccccccccccccccccccccccccccc"
)

// prepared is one stored bundle and what verifying it must yield: the
// identity it was signed under, the digests it covers, and the
// certificate facts the policy reads. truthfulBV serves exactly this.
type prepared struct {
	raw     []byte
	san     string
	digests map[string]bool
	stmt    []byte
	ext     certificate.Extensions
}

// truthfulBV verifies a prepared bundle the way the real boundary
// does — identity exact, digest covered, payload from the signed
// bytes — and refuses anything it was not handed.
type truthfulBV struct {
	byRaw  map[string]*prepared
	issuer string
}

func (b truthfulBV) Attestation(raw []byte, id trust.Identity, sha256Hex string) (*trust.Verified, error) {
	p, err := b.find(raw)
	if err != nil {
		return nil, err
	}

	if id.SAN != p.san || id.Issuer != b.issuer {
		return nil, errWrongIdentity
	}

	if !p.digests[sha256Hex] {
		return nil, errUncoveredDigest
	}

	return &trust.Verified{Payload: p.stmt, SAN: p.san, Extensions: p.ext}, nil
}

func (b truthfulBV) Blob(raw []byte, id trust.Identity, sha256Hex string) (*trust.Verified, error) {
	v, err := b.Attestation(raw, id, sha256Hex)
	if err != nil {
		return nil, err
	}

	v.Payload = nil

	return v, nil
}

func (b truthfulBV) Peek(raw []byte) ([]byte, error) {
	p, err := b.find(raw)
	if err != nil {
		return nil, err
	}

	return p.stmt, nil
}

func (b truthfulBV) find(raw []byte) (*prepared, error) {
	p, ok := b.byRaw[string(raw)]
	if !ok {
		return nil, errUnknownBundle
	}

	return p, nil
}

// releaseWorld is the store plus the verifier that agree on it.
type releaseWorld struct {
	appSHA, sbomSHA string
	bv              truthfulBV
	store           mapStore
}

// mapStore serves the prepared bundles by subject digest.
type mapStore map[string][]verify.StoredBundle

func (m mapStore) Bundles(_, sha256Hex string) ([]verify.StoredBundle, error) {
	return m[sha256Hex], nil
}

// newReleaseWorld builds one clean release: two subjects covered by
// one provenance attestation, and a release decision over the SBOM.
func newReleaseWorld(t *testing.T) *releaseWorld {
	t.Helper()

	appSHA := chain.SHA256Hex([]byte("app bytes"))
	sbomSHA := chain.SHA256Hex([]byte("sbom bytes"))
	signerPin := strings.Repeat("a", 40)
	machineryPin := strings.Repeat("b", 40)

	provStmt := `{
	  "_type": "https://in-toto.io/Statement/v1",
	  "subject": [
	    {"name": "app.tar.gz", "digest": {"sha256": "` + appSHA + `"}},
	    {"name": "app.spdx.json", "digest": {"sha256": "` + sbomSHA + `"}}
	  ],
	  "predicateType": "https://slsa.dev/provenance/v1",
	  "predicate": {
	    "buildDefinition": {
	      "buildType": "https://actions.github.io/buildtypes/workflow/v1",
	      "externalParameters": {
	        "workflow": {
	          "repository": "https://github.com/acme/widget",
	          "ref": "refs/tags/` + relTag + `",
	          "path": ".github/workflows/publish.yml"
	        },
	        "inputs": {}
	      },
	      "resolvedDependencies": [
	        {"uri": "pkg:decoy/first"},
	        {"uri": "git+https://github.com/acme/widget@refs/tags/` + relTag + `",
	         "digest": {"gitCommit": "` + relSrcRev + `"}}
	      ]
	    },
	    "runDetails": {
	      "builder": {"id": "https://github.com/` + relSignerWF + `@` + signerPin + `"}
	    }
	  }
	}`

	decStmt := `{
	  "_type": "https://in-toto.io/Statement/v1",
	  "subject": [{"name": "app.spdx.json", "digest": {"sha256": "` + sbomSHA + `"}}],
	  "predicateType": "https://acme.example/attestations/release-decision/v1",
	  "predicate": {
	    "tag": "` + relTag + `",
	    "classes": ["oci-image"],
	    "conclusion": "OPEN",
	    "decidedAt": "2026-08-01T00:00:00Z",
	    "proofs": {}
	  }
	}`

	prov := &prepared{
		raw:     []byte(`{"prepared": "provenance"}`),
		san:     "https://github.com/" + relSignerWF + "@" + signerPin,
		digests: map[string]bool{appSHA: true, sbomSHA: true},
		stmt:    []byte(provStmt),
		ext: certificate.Extensions{
			BuildSignerDigest:   signerPin,
			RunnerEnvironment:   "github-hosted",
			SourceRepositoryURI: "https://github.com/acme/widget",
			BuildConfigURI: "https://github.com/acme/widget/.github/workflows/publish.yml@refs/tags/" +
				relTag,
		},
	}

	dec := &prepared{
		raw:     []byte(`{"prepared": "decision"}`),
		san:     "https://github.com/" + relDecideWF + "@" + machineryPin,
		digests: map[string]bool{sbomSHA: true},
		stmt:    []byte(decStmt),
		ext:     certificate.Extensions{BuildSignerDigest: machineryPin},
	}

	return &releaseWorld{
		appSHA:  appSHA,
		sbomSHA: sbomSHA,
		bv: truthfulBV{
			issuer: "https://token.actions.githubusercontent.com",
			byRaw:  map[string]*prepared{string(prov.raw): prov, string(dec.raw): dec},
		},
		store: mapStore{
			appSHA: {{URI: "https://store.example/prov", Bundle: jsonx.Raw(prov.raw)}},
			sbomSHA: {
				{URI: "https://store.example/prov", Bundle: jsonx.Raw(prov.raw)},
				{URI: "https://store.example/dec", Bundle: jsonx.Raw(dec.raw)},
			},
		},
	}
}

// manifests writes the two sha256sum manifests the verb reads.
//
//nolint:gocritic // unnamedResult: the subject and sbom manifest paths
func (w *releaseWorld) manifests(t *testing.T) (string, string) {
	t.Helper()

	dir := t.TempDir()
	subjects := filepath.Join(dir, "subjects.sha256")
	sboms := filepath.Join(dir, "sboms.sha256")

	docs := map[string]string{
		subjects: w.appSHA + "  app.tar.gz\n" + w.sbomSHA + "  app.spdx.json\n",
		sboms:    w.sbomSHA + "  app.spdx.json\n",
	}

	for path, content := range docs {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return subjects, sboms
}

// TestVerifyReleasePasses drives the release mode over that world:
// exit 0, and the report carries the folded source revision — the one
// fact the orchestration layer reads back.
func TestVerifyReleasePasses(t *testing.T) {
	w := newReleaseWorld(t)
	swap(t, w.bv, w.store)

	px := files(t)
	subjects, sboms := w.manifests(t)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "release", "--json",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", relTag,
		"--subjects", subjects, "--sboms", sboms,
		"--signer-digest", strings.Repeat("a", 40), "--machinery-digest", strings.Repeat("b", 40),
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	doc := decodeReport(t, &stdout)
	if doc.Verdict == nil || *doc.Verdict != "PASS" {
		t.Fatalf("verdict = %v, want PASS", doc.Verdict)
	}

	if got := factOf(doc, "sourceRevision"); got != relSrcRev {
		t.Fatalf("sourceRevision = %q, want %q", got, relSrcRev)
	}

	if doc.Population == nil || doc.Population.Size == nil || *doc.Population.Size != 2 {
		t.Fatalf("population = %+v, want the two release subjects", doc.Population)
	}
}

// TestEmitVSAWritesThePredicate drives `emit vsa` over the same world:
// the predicate goes to the named file whole, and to the stream when
// unnamed. The rendered document is the engine's; what this pins is
// that the verb writes it where it was asked to.
func TestEmitVSAWritesThePredicate(t *testing.T) {
	w := newReleaseWorld(t)

	px := files(t)
	subjects, sboms := w.manifests(t)

	args := func(extra ...string) []string {
		return append([]string{
			"emit", "vsa",
			"--policy", px.policy, "--trusted-root", px.root,
			"--repo", "acme/widget", "--tag", relTag,
			"--subjects", subjects, "--sboms", sboms,
			"--signer-digest", strings.Repeat("a", 40), "--machinery-digest", strings.Repeat("b", 40),
			"--policy-uri", "https://github.com/acme/canon/blob/x/slsa/verify-policy.json",
		}, extra...)
	}

	t.Run("to a named file", func(t *testing.T) {
		swap(t, w.bv, w.store)

		out := filepath.Join(t.TempDir(), "vsa.json")

		var stdout, stderr bytes.Buffer

		if code := Run(args("--out", out), &stdout, &stderr); code != exitOK {
			t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}

		written, err := os.ReadFile(out) //nolint:gosec // a path this test named
		if err != nil {
			t.Fatalf("the predicate was not written: %v", err)
		}

		if !strings.Contains(string(written), `"verificationResult":"PASSED"`) {
			t.Errorf("predicate = %s, want the passing verdict", written)
		}

		if !strings.HasSuffix(string(written), "\n") {
			t.Error("the written predicate carries no trailing newline")
		}

		if !strings.Contains(stdout.String(), out) {
			t.Errorf("stdout = %q, want it to name where the predicate went", stdout.String())
		}
	})

	t.Run("to the stream when unnamed", func(t *testing.T) {
		swap(t, w.bv, w.store)

		var stdout, stderr bytes.Buffer

		if code := Run(args(), &stdout, &stderr); code != exitOK {
			t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}

		if !strings.Contains(stdout.String(), `"verificationResult":"PASSED"`) {
			t.Errorf("stdout = %q, want the predicate", stdout.String())
		}

		if !strings.Contains(stdout.String(), relSrcRev) {
			t.Errorf("stdout = %q, want the folded source revision reported", stdout.String())
		}
	})

	t.Run("an unwritable --out refuses", func(t *testing.T) {
		swap(t, w.bv, w.store)

		var stdout, stderr bytes.Buffer

		out := filepath.Join(t.TempDir(), "absent", "vsa.json")

		code := Run(args("--out", out), &stdout, &stderr)
		if code != exitRefused || !strings.Contains(stderr.String(), "writing the predicate") {
			t.Fatalf("Run = %d, stderr %q — want the write refusal", code, stderr.String())
		}
	})
}

// The refusals truthfulBV makes, named so a failing row says which
// half of the boundary refused.
var (
	errUnknownBundle   = errors.New("no such bundle in this world")
	errWrongIdentity   = errors.New("the bundle was not signed under that identity")
	errUncoveredDigest = errors.New("the bundle covers no such digest")
)

// writeManifest drops one sha256sum document in a temp dir and names
// it — the plan arrives as exactly the manifest shape the subject and
// SBOM lists already use.
func writeManifest(t *testing.T, name, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// TestVerifyReleaseWithAPlan drives the release mode as a release
// shipping per-artifact inventories runs it (stele#158): the planned
// inventory carries the decision, the release view beside it carries
// none, and the verdict aggregates over the plan rather than
// demanding one decision for the whole release.
func TestVerifyReleaseWithAPlan(t *testing.T) {
	w := newReleaseWorld(t)
	swap(t, w.bv, w.store)

	px := files(t)
	subjects, _ := w.manifests(t)

	viewSHA := chain.SHA256Hex([]byte("the release view"))
	sboms := writeManifest(t, "sboms.sha256",
		w.sbomSHA+"  app.spdx.json\n"+viewSHA+"  widget-1.2.3.spdx.json\n")
	plan := writeManifest(t, "plan.sha256", w.sbomSHA+"  app.spdx.json\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "release", "--json",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", relTag,
		"--subjects", subjects, "--sboms", sboms, "--inventories", plan,
		"--signer-digest", strings.Repeat("a", 40), "--machinery-digest", strings.Repeat("b", 40),
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	doc := decodeReport(t, &stdout)
	if doc.Verdict == nil || *doc.Verdict != "PASS" {
		t.Fatalf("verdict = %v, want PASS", doc.Verdict)
	}
}

// TestVerifyReleasePlanRefusals pins the plan flag's own surface: a
// plan that cannot be read, one that names nothing, and one naming a
// document the release does not carry.
func TestVerifyReleasePlanRefusals(t *testing.T) {
	w := newReleaseWorld(t)

	px := files(t)
	subjects, sboms := w.manifests(t)

	tests := []struct {
		name string
		plan func(t *testing.T) string
		want int
	}{
		{
			"a plan file that is not there",
			func(t *testing.T) string { t.Helper(); return filepath.Join(t.TempDir(), "absent.sha256") },
			exitUsage,
		},
		{
			"a plan that names nothing",
			func(t *testing.T) string { t.Helper(); return writeManifest(t, "empty.sha256", "\n") },
			exitUsage,
		},
		{
			"a plan line that is not a sha256sum record",
			func(t *testing.T) string { t.Helper(); return writeManifest(t, "bad.sha256", "not a record\n") },
			exitUsage,
		},
		{
			"a plan naming a document the release does not carry",
			func(t *testing.T) string {
				t.Helper()

				return writeManifest(t, "absent-doc.sha256",
					chain.SHA256Hex([]byte("never shipped"))+"  sbom-npm-widget-1.2.3.spdx.json\n")
			},
			exitRefused,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swap(t, w.bv, w.store)

			var stdout, stderr bytes.Buffer

			code := Run([]string{
				"verify", "release",
				"--policy", px.policy, "--trusted-root", px.root,
				"--repo", "acme/widget", "--tag", relTag,
				"--subjects", subjects, "--sboms", sboms, "--inventories", tt.plan(t),
				"--signer-digest", strings.Repeat("a", 40), "--machinery-digest", strings.Repeat("b", 40),
			}, &stdout, &stderr)
			if code != tt.want {
				t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s", code, tt.want, stdout.String(), stderr.String())
			}
		})
	}
}

// TestEmitVSAWithAPlan pins the same input on the verb that renders
// the verdict: `emit vsa` runs the identical engine, so the plan
// reaches it through the identical flag — one description, one
// loader, no second spelling of what the denominator is.
func TestEmitVSAWithAPlan(t *testing.T) {
	w := newReleaseWorld(t)
	swap(t, w.bv, w.store)

	px := files(t)
	subjects, _ := w.manifests(t)

	viewSHA := chain.SHA256Hex([]byte("the release view"))
	sboms := writeManifest(t, "sboms.sha256",
		w.sbomSHA+"  app.spdx.json\n"+viewSHA+"  widget-1.2.3.spdx.json\n")
	plan := writeManifest(t, "plan.sha256", w.sbomSHA+"  app.spdx.json\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"emit", "vsa",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", relTag,
		"--subjects", subjects, "--sboms", sboms, "--inventories", plan,
		"--signer-digest", strings.Repeat("a", 40), "--machinery-digest", strings.Repeat("b", 40),
		"--policy-uri", "https://github.com/acme/canon/blob/x/slsa/verify-policy.json",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	if !strings.Contains(stdout.String(), `"verificationResult":"PASSED"`) {
		t.Errorf("stdout = %q, want the predicate", stdout.String())
	}
}
