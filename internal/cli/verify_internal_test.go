// Internal tests for the verify verb's dispatch: the effect seams
// are swapped for scripted fakes so every guard and exit path is a
// table row. The real constructors are proven in their own packages
// and in shadow mode.

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

const testPolicy = `{
  "schema": 2,
  "issuer": "https://token.actions.githubusercontent.com",
  "trust": {
    "provenance": {"signerWorkflow": "acme/signer/.github/workflows/sign.yml"},
    "verdict": {"verifierWorkflow": "acme/canon/.github/workflows/verify-release.yml"},
    "decision": {
      "signerWorkflow": "acme/canon/.github/workflows/publish.yml",
      "predicateType": "https://acme.example/attestations/release-decision/v1",
      "requiredConclusion": "OPEN"
    }
  },
  "build": {
    "buildTypes": {
      "https://actions.github.io/buildtypes/workflow/v1": {"externalParameterKeys": ["workflow", "inputs"]}
    },
    "resourceUri": "pkg:github/{owner}/{repo}@v{version}",
    "sourceRepository": "https://github.com/{owner}/{repo}",
    "targetLevel": "SLSA_BUILD_LEVEL_3",
    "denySelfHostedRunners": true
  },
  "source": {
    "identity": "https://github.com/{owner}/{repo}/.github/workflows/source-attest.yml@refs/heads/main",
    "notesRef": "refs/notes/commits",
    "provenancePredicateType": "https://acme.example/attestations/source-provenance/v1",
    "propertyPrefix": "ORG_SOURCE_",
    "resourceUri": "git+https://github.com/{owner}/{repo}",
    "protectedBranches": [
      {
        "name": "main",
        "targetLevel": "SLSA_SOURCE_LEVEL_3",
        "requiredProperties": [{"name": "ORG_SOURCE_GATED", "since": "2020-01-01T00:00:00Z"}]
      }
    ],
    "healedContinuity": true,
    "underclaimLevel": "SLSA_SOURCE_LEVEL_2",
    "legacyLeaves": []
  }
}`

const subjectSHA = "1111111111111111111111111111111111111111111111111111111111111111"

// vsaStatement passes every check the vsa mode makes when served by
// the scripted verifier below.
const vsaStatement = `{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "app.tar.gz", "digest": {"sha256": "` + subjectSHA + `"}}],
  "predicateType": "https://slsa.dev/verification_summary/v1",
  "predicate": {
    "verifier": {"id": "https://github.com/acme/canon/.github/workflows/verify-release.yml"},
    "resourceUri": "pkg:github/acme/widget@v1.2.3",
    "policy": {"uri": "https://github.com/acme/canon/tree/v1.0.0"},
    "verificationResult": "PASSED",
    "verifiedLevels": ["SLSA_BUILD_LEVEL_3"]
  }
}`

// scriptedBV serves one fixed payload for every bundle — the cli
// layer under test only routes; judging payloads is the engine's
// table-tested job.
type scriptedBV struct {
	payload []byte
}

func (s scriptedBV) Attestation([]byte, trust.Identity, string) (*trust.Verified, error) {
	return &trust.Verified{
		Payload:    s.payload,
		Extensions: certificate.Extensions{BuildSignerDigest: strings.Repeat("b", 40)},
	}, nil
}

func (s scriptedBV) Blob([]byte, trust.Identity, string) (*trust.Verified, error) {
	return &trust.Verified{}, nil
}

func (s scriptedBV) Peek([]byte) ([]byte, error) { return s.payload, nil }

type scriptedStore struct {
	err error
}

func (s scriptedStore) Bundles(string, string) ([]verify.StoredBundle, error) {
	if s.err != nil {
		return nil, s.err
	}

	return []verify.StoredBundle{{URI: "https://store.example/a", Bundle: []byte(`{}`)}}, nil
}

// swap installs scripted seams for one test and restores them after.
func swap(t *testing.T, bv verify.BundleVerifier, store verify.Store) {
	t.Helper()

	origBV, origStore, origHist := newBundleVerifier, newStore, openHistory

	newBundleVerifier = func([]byte) (verify.BundleVerifier, error) { return bv, nil }
	newStore = func(bool) verify.Store { return store }
	openHistory = func(string, string) (verify.History, error) {
		return nil, errors.New("no history in this test")
	}

	t.Cleanup(func() {
		newBundleVerifier, newStore, openHistory = origBV, origStore, origHist
	})
}

// paths is one run's file inputs.
type paths struct {
	policy, root, subjects string
}

// files writes the policy, trusted-root stand-in and manifest for a
// run.
func files(t *testing.T) paths {
	t.Helper()

	dir := t.TempDir()
	px := paths{
		policy:   filepath.Join(dir, "policy.json"),
		root:     filepath.Join(dir, "root.json"),
		subjects: filepath.Join(dir, "subjects.sha256"),
	}

	for path, content := range map[string]string{
		px.policy:   testPolicy,
		px.root:     `{"any": "bytes — the seam swallows them"}`,
		px.subjects: subjectSHA + "  app.tar.gz\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return px
}

func TestVerifyVSAPasses(t *testing.T) {
	swap(t, scriptedBV{payload: []byte(vsaStatement)}, scriptedStore{})

	px := files(t)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "vsa",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", "v1.2.3", "--subjects", px.subjects,
		"--signer-digest", strings.Repeat("a", 40), "--machinery-digest", strings.Repeat("b", 40),
	}, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("Run = %d, stderr: %s", code, stderr.String())
	}

	if !strings.Contains(stdout.String(), "verdict verified") {
		t.Errorf("stdout = %q, want the verdict line", stdout.String())
	}
}

func TestVerifyRefusalExitsOne(t *testing.T) {
	swap(t, scriptedBV{payload: []byte(vsaStatement)}, scriptedStore{err: errors.New("store torn")})

	px := files(t)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "release",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", "v1.2.3", "--subjects", px.subjects, "--sboms", px.subjects,
		"--signer-digest", strings.Repeat("a", 40), "--machinery-digest", strings.Repeat("b", 40),
	}, &stdout, &stderr)

	if code != exitRefused {
		t.Fatalf("Run = %d, want %d", code, exitRefused)
	}

	if !strings.Contains(stderr.String(), "store torn") {
		t.Errorf("stderr = %q, want the refusal cause", stderr.String())
	}
}

func TestVerifyChainHistoryFailure(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})

	px := files(t)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "chain",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--git-dir", t.TempDir(),
	}, &stdout, &stderr)

	if code != exitRefused || !strings.Contains(stderr.String(), "no history in this test") {
		t.Fatalf("Run = %d, stderr %q — want the history refusal", code, stderr.String())
	}
}

func TestVerifyUsageRefusals(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})

	px := files(t)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no mode", []string{"verify"}, "a mode is required"},
		{"unknown mode", []string{"verify", "conjure"}, "unknown mode"},
		{"bad flag", []string{"verify", "chain", "--conjure"}, ""},
		{
			"repo not owner/repo",
			[]string{"verify", "chain", "--policy", px.policy, "--trusted-root", px.root, "--repo", "solo"},
			"owner/repo",
		},
		{
			"policy missing",
			[]string{"verify", "chain", "--repo", "acme/widget", "--trusted-root", px.root},
			"--policy is required",
		},
		{
			"policy unreadable",
			[]string{"verify", "chain", "--repo", "acme/widget", "--policy", "/nonexistent", "--trusted-root", px.root},
			"nonexistent",
		},
		{
			"policy invalid",
			[]string{"verify", "chain", "--repo", "acme/widget", "--policy", px.root, "--trusted-root", px.root},
			"policy",
		},
		{
			"trusted root missing",
			[]string{"verify", "chain", "--repo", "acme/widget", "--policy", px.policy},
			"--trusted-root is required",
		},
		{
			"trusted root unreadable",
			[]string{"verify", "chain", "--repo", "acme/widget", "--policy", px.policy, "--trusted-root", "/nonexistent"},
			"nonexistent",
		},
		{
			"git dir missing",
			[]string{"verify", "chain", "--repo", "acme/widget", "--policy", px.policy, "--trusted-root", px.root},
			"--git-dir is required",
		},
		{
			"subjects missing",
			[]string{
				"verify", "vsa", "--repo", "acme/widget",
				"--policy", px.policy, "--trusted-root", px.root,
			},
			"--subjects is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := Run(tt.args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("Run = %d, want %d (stderr: %s)", code, exitUsage, stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr = %q, want it to name %q", stderr.String(), tt.want)
			}
		})
	}
}

func TestVerifyManifestRefusals(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})

	px := files(t)
	bad := filepath.Join(t.TempDir(), "bad.sha256")

	if err := os.WriteFile(bad, []byte("not a manifest line\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "vsa",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", "v1.2.3", "--subjects", bad,
		"--signer-digest", strings.Repeat("a", 40), "--machinery-digest", strings.Repeat("b", 40),
	}, &stdout, &stderr)

	if code != exitUsage || !strings.Contains(stderr.String(), "not a sha256sum record") {
		t.Fatalf("Run = %d, stderr %q — want the manifest refusal", code, stderr.String())
	}
}

func TestVerifyOutputFailures(t *testing.T) {
	swap(t, scriptedBV{payload: []byte(vsaStatement)}, scriptedStore{})

	px := files(t)

	args := []string{
		"verify", "vsa",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", "v1.2.3", "--subjects", px.subjects,
		"--signer-digest", strings.Repeat("a", 40), "--machinery-digest", strings.Repeat("b", 40),
	}

	t.Run("dead stdout during a passing run", func(t *testing.T) {
		var stderr bytes.Buffer

		if code := Run(args, failWriterI{}, &stderr); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})

	t.Run("dead stderr during a refusal", func(t *testing.T) {
		swap(t, scriptedBV{}, scriptedStore{err: errors.New("store torn")})

		var stdout bytes.Buffer

		if code := Run(args, &stdout, failWriterI{}); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})

	t.Run("dead stderr on a usage error", func(t *testing.T) {
		if code := Run([]string{"verify"}, failWriterI{}, failWriterI{}); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}

		if code := Run([]string{"verify", "conjure"}, failWriterI{}, failWriterI{}); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})
}

// failWriterI fails every write — the internal-test twin of the
// external suite's failing writer.
type failWriterI struct{}

func (failWriterI) Write([]byte) (int, error) { return 0, errors.New("sink closed") }

// jsonReportDoc mirrors the --json wire shape the tests read back.
type jsonReportDoc struct {
	Target     *string `json:"target"`
	Subject    *string `json:"subject"`
	Verdict    *string `json:"verdict"`
	Population *struct {
		Size   *int    `json:"size"`
		Source *string `json:"source"`
	} `json:"population"`
	Facts []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"facts"`
	Findings []struct {
		Assertion string `json:"assertion"`
		Detail    string `json:"detail"`
	} `json:"findings"`
}

func decodeReport(t *testing.T, stdout *bytes.Buffer) *jsonReportDoc {
	t.Helper()

	doc, err := jsonx.DecodeForeign[jsonReportDoc](stdout.Bytes())
	if err != nil {
		t.Fatalf("stdout is not one JSON report: %v\nstdout: %s", err, stdout.String())
	}

	return doc
}

// TestVerifyVSAJSONPasses pins the --json contract on success: exit 0,
// stdout carries exactly one PASS document with the population and the
// levels fact, and the progress lines moved to stderr.
func TestVerifyVSAJSONPasses(t *testing.T) {
	swap(t, scriptedBV{payload: []byte(vsaStatement)}, scriptedStore{})

	px := files(t)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "vsa", "--json",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", "v1.2.3", "--subjects", px.subjects,
		"--signer-digest", strings.Repeat("a", 40), "--machinery-digest", strings.Repeat("b", 40),
	}, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("Run = %d, stderr: %s", code, stderr.String())
	}

	doc := decodeReport(t, &stdout)

	switch {
	case doc.Verdict == nil || *doc.Verdict != "PASS":
		t.Fatalf("verdict = %v, want PASS", doc.Verdict)
	case doc.Subject == nil || *doc.Subject != "acme/widget@v1.2.3":
		t.Fatalf("subject = %v", doc.Subject)
	case doc.Population == nil || doc.Population.Size == nil || *doc.Population.Size != 1:
		t.Fatalf("population = %+v", doc.Population)
	case len(doc.Facts) != 1 || doc.Facts[0].Name != "verifiedLevels" ||
		doc.Facts[0].Value != "SLSA_BUILD_LEVEL_3":
		t.Fatalf("facts = %+v", doc.Facts)
	}

	if !strings.Contains(stderr.String(), "verdict verified") {
		t.Errorf("stderr = %q, want the progress line moved there", stderr.String())
	}
}

// TestVerifyJSONRefusal pins the --json contract on refusal: the exit
// code stays 1, and stdout still carries one document — a FAIL whose
// finding is the engine's message, over the declared population.
func TestVerifyJSONRefusal(t *testing.T) {
	swap(t, scriptedBV{payload: []byte(vsaStatement)}, scriptedStore{err: errors.New("store torn")})

	px := files(t)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "vsa", "--json",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", "v1.2.3", "--subjects", px.subjects,
		"--signer-digest", strings.Repeat("a", 40), "--machinery-digest", strings.Repeat("b", 40),
	}, &stdout, &stderr)

	if code != exitRefused {
		t.Fatalf("Run = %d, want %d; stderr: %s", code, exitRefused, stderr.String())
	}

	doc := decodeReport(t, &stdout)

	switch {
	case doc.Verdict == nil || *doc.Verdict != "FAIL":
		t.Fatalf("verdict = %v, want FAIL", doc.Verdict)
	case len(doc.Findings) != 1 || doc.Findings[0].Assertion != "vsa":
		t.Fatalf("findings = %+v", doc.Findings)
	case !strings.Contains(doc.Findings[0].Detail, "store torn"):
		t.Fatalf("finding detail = %q, want the engine's message", doc.Findings[0].Detail)
	}
}

// TestVerifyJSONDeadStdout pins the stream contract under --json: a
// report that cannot be written is exit 3, never a silent success.
func TestVerifyJSONDeadStdout(t *testing.T) {
	swap(t, scriptedBV{payload: []byte(vsaStatement)}, scriptedStore{})

	px := files(t)

	var stderr bytes.Buffer

	code := Run([]string{
		"verify", "vsa", "--json",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", "v1.2.3", "--subjects", px.subjects,
		"--signer-digest", strings.Repeat("a", 40), "--machinery-digest", strings.Repeat("b", 40),
	}, failWriterI{}, &stderr)

	if code != exitIO {
		t.Fatalf("Run = %d, want %d", code, exitIO)
	}
}
