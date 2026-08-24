// The policy load-check's guards (stele#210). The command's whole
// contract is that its exit status is the engine loader's verdict and
// its output is the loader's message, so the tests assert exactly
// those two things — and assert the message by CALLING the loader,
// never by spelling its text here. A test carrying its own copy of the
// refusal would pass while the engine said something else, which is
// the drift this command exists to catch.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

// The minimal document of each kind, at the implemented epoch. Both
// are floors, not samples: every field present is one its loader
// demands, so a row that breaks one field breaks exactly that field.
const (
	cleanVerifyPolicy = `{
	  "schema": 7,
	  "issuer": "https://token.actions.githubusercontent.com",
	  "trust": {
	    "provenance": {
	      "signerWorkflow": "{owner}/{repo}/.github/workflows/release.yml"
	    }
	  }
	}`

	cleanAssertPolicy = `{
	  "schema": 7,
	  "issuer": "https://token.actions.githubusercontent.com",
	  "evidence": {
	    "sbomSuffix": ".spdx.json",
	    "checksums": "checksums.txt",
	    "umbrellaBundle": "attestations.intoto.jsonl",
	    "manifestAsset": "evidence-manifest.json",
	    "classes": {"go-binary": {"bundles": ["attestations-go-binaries.intoto.jsonl"]}}
	  }
	}`
)

// The two base-approval shapes the epoch moved between (stele#247),
// as whole documents a consumer could have committed. The command is
// how an adopter asks "does what I committed still load against what
// I pin", so both directions are measured through it.
const (
	// bothScopesAssertPolicy names both mechanisms — the world the
	// closed four-field block could not describe at any value.
	bothScopesAssertPolicy = `{
	  "schema": 7,
	  "issuer": "https://token.actions.githubusercontent.com",
	  "evidence": {
	    "sbomSuffix": ".spdx.json",
	    "checksums": "checksums.txt",
	    "umbrellaBundle": "attestations.intoto.jsonl",
	    "manifestAsset": "evidence-manifest.json",
	    "classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}},
	    "baseImages": {"scopes": [
	      {
	        "name": "pgrx-bases",
	        "mechanism": "pin-file",
	        "pinFile": "docker/pgrx-base-images.toml",
	        "attestorRepo": ".github",
	        "attestorIdentity": "https://github.com/acme/.github/.github/workflows/base-attest.yml@refs/heads/main",
	        "predicateType": "https://acme.example/attestations/base-image-approval/v1"
	      },
	      {
	        "name": "org-bases",
	        "mechanism": "provenance-verified",
	        "fromFile": "Dockerfile",
	        "registryPrefix": "ghcr.io/acme/",
	        "pinPattern": "^ghcr\\.io/acme/(?P<repo>[a-z-]+):(?P<version>[0-9.]+)[^@]*@sha256:[0-9a-f]{64}$",
	        "identity": "https://github.com/acme/${repo}/.github/workflows/publish.yml@refs/tags/v${version}",
	        "predicateType": "https://slsa.dev/provenance/v1"
	      }
	    ]}
	  }
	}`

	// preScopesAssertPolicy is the block as it stood before the
	// reshape, at the CURRENT epoch: the document a consumer holds
	// when the pin moves ahead of the policy edit.
	preScopesAssertPolicy = `{
	  "schema": 7,
	  "issuer": "https://token.actions.githubusercontent.com",
	  "evidence": {
	    "sbomSuffix": ".spdx.json",
	    "checksums": "checksums.txt",
	    "umbrellaBundle": "attestations.intoto.jsonl",
	    "manifestAsset": "evidence-manifest.json",
	    "classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}},
	    "baseImages": {
	      "pinFile": "docker/pgrx-base-images.toml",
	      "attestorRepo": ".github",
	      "attestorIdentity": "https://github.com/acme/.github/.github/workflows/base-attest.yml@refs/heads/main",
	      "predicateType": "https://acme.example/attestations/base-image-approval/v1"
	    }
	  }
	}`
)

// writePolicyDoc puts one document on disk and hands back its path.
func writePolicyDoc(t *testing.T, name, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}

	return path
}

// TestVerifyPolicyMirrorsTheLoader walks the document shapes the
// command exists to tell apart, for both kinds. The oracle for every
// refusing row is the loader itself, run here on the same bytes: the
// command must exit non-zero exactly when the loader errors, and print
// exactly what it said.
func TestVerifyPolicyMirrorsTheLoader(t *testing.T) {
	t.Parallel()

	// The epoch-5 shape is the canon's live incident (.github#617):
	// a document one epoch behind the binary that reads it. The
	// wrong-shape rows are at the RIGHT epoch, so they prove the gate
	// let them through to the strict decode that refused them —
	// #107's order, observed from outside.
	rows := []struct {
		name    string
		flag    string
		content string
		code    int
	}{
		{"a clean verify policy", "--verify-policy", cleanVerifyPolicy, exitOK},
		{"a clean assert policy", "--assert-policy", cleanAssertPolicy, exitOK},
		{
			"a verify policy one epoch behind", "--verify-policy",
			strings.Replace(cleanVerifyPolicy, `"schema": 7`, `"schema": 5`, 1), exitRefused,
		},
		{
			"an assert policy one epoch behind", "--assert-policy",
			strings.Replace(cleanAssertPolicy, `"schema": 7`, `"schema": 5`, 1), exitRefused,
		},
		{
			// proofFloor as a string is the shape the live incident
			// carried before it became a floor-with-a-from: right
			// epoch, wrong type, so only the strict decode can refuse
			// it.
			"an assert policy whose proofFloor is a string", "--assert-policy",
			strings.Replace(cleanAssertPolicy, `"classes"`,
				`"proofFloor": "certificate-transparency", "classes"`, 1), exitRefused,
		},
		{
			"a verify policy declaring a key this engine has no field for", "--verify-policy",
			strings.Replace(cleanVerifyPolicy, `"schema": 7`, `"schema": 7, "sourceLevel": 4`, 1), exitRefused,
		},
		{
			"a document carrying no schema at all", "--verify-policy",
			strings.Replace(cleanVerifyPolicy, `"schema": 7,`, ``, 1), exitRefused,
		},
		// The stele#247 reshape, measured from outside in both
		// directions: the scoped shape loads at this epoch, and the
		// block it replaced refuses here rather than at whatever verb
		// the consumer next runs.
		{"an assert policy naming both approval scopes", "--assert-policy", bothScopesAssertPolicy, exitOK},
		{"an assert policy carrying the pre-scopes block", "--assert-policy", preScopesAssertPolicy, exitRefused},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			path := writePolicyDoc(t, "policy.json", row.content)

			var stdout, stderr bytes.Buffer

			code := Run([]string{"verify", modePolicy, row.flag, path}, &stdout, &stderr)
			if code != row.code {
				t.Errorf("exit = %d, want %d (stderr: %s)", code, row.code, stderr.String())
			}

			if stdout.Len() != 0 {
				t.Errorf("wrote %q to stdout — the load-check answers with its exit status", stdout.String())
			}

			want := loaderVerdict(t, row.flag, row.content)

			switch row.code {
			case exitOK:
				if want != "" {
					t.Fatalf("the row claims this document loads, and the loader refuses it: %s", want)
				}

				if stderr.Len() != 0 {
					t.Errorf("a clean load wrote %q — silence is the whole answer", stderr.String())
				}
			default:
				if want == "" {
					t.Fatal("the row claims this document refuses, and the loader accepts it")
				}

				if got := stderr.String(); got != want+"\n" {
					t.Errorf("printed %q, the loader itself says %q — the message must cross unimproved", got, want)
				}
			}
		})
	}
}

// loaderVerdict runs the engine loader the flag names over the same
// bytes, and reports its message ("" when it accepts them). This is
// the oracle: the command is correct when it says what this says.
func loaderVerdict(t *testing.T, flag, content string) string {
	t.Helper()

	var err error

	switch flag {
	case "--assert-policy":
		_, err = assert.LoadPolicy(strings.NewReader(content))
	case "--verify-policy":
		_, err = policy.Load(strings.NewReader(content))
	default:
		t.Fatalf("no loader for %q", flag)
	}

	if err == nil {
		return ""
	}

	return err.Error()
}

// TestVerifyPolicyRefusesItsOwnUsage covers the branches that answer
// before any document is read. Each names one broken thing: a run that
// silently loaded the wrong document, or loaded nothing and reported
// success, is the failure these guards exist for.
func TestVerifyPolicyRefusesItsOwnUsage(t *testing.T) {
	t.Parallel()

	good := writePolicyDoc(t, "policy.json", cleanVerifyPolicy)
	assertGood := writePolicyDoc(t, "assert.json", cleanAssertPolicy)

	rows := []struct {
		name string
		args []string
		want string
	}{
		{"neither kind named", nil, "one of --assert-policy or --verify-policy is required"},
		{
			"both kinds named",
			[]string{"--verify-policy", good, "--assert-policy", assertGood},
			"--assert-policy and --verify-policy are exclusive",
		},
		{
			"a path that is not there",
			[]string{"--verify-policy", filepath.Join(t.TempDir(), "absent.json")},
			"no such file",
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			if code := Run(append([]string{"verify", modePolicy}, row.args...), &stdout, &stderr); code != exitUsage {
				t.Errorf("exit = %d, want exitUsage — a usage error is not a document verdict", code)
			}

			if got := stderr.String(); !strings.Contains(got, row.want) {
				t.Errorf("refusal %q does not name %q", got, row.want)
			}

			// Every usage refusal is the command's own, so it wears the
			// command's name — the loader's messages are the ones that
			// must arrive bare.
			if got := stderr.String(); !strings.HasPrefix(got, "stele verify policy: ") {
				t.Errorf("refusal %q does not name the command that refused", got)
			}
		})
	}
}

// TestVerifyPolicyReadFailureIsTheLoadersVerdict pins the boundary
// between the two non-zero answers, which sits where the operating
// system puts it and not where a reader might guess. A path that does
// not open never reaches the loader, so it is a usage error; a path
// that OPENS and then fails to read — a directory, on every Unix — is
// refused inside the loader, so it is a document verdict and crosses
// with the loader's own message. The command does not stat the path to
// pre-empt this: deciding what a readable document is would be an
// opinion of its own, beside the engine's.
func TestVerifyPolicyReadFailureIsTheLoadersVerdict(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer

	code := Run([]string{"verify", modePolicy, "--assert-policy", t.TempDir()}, &stdout, &stderr)
	if code != exitRefused {
		t.Errorf("exit = %d, want exitRefused — the loader ran and refused", code)
	}

	got := stderr.String()
	if strings.HasPrefix(got, "stele verify policy: ") {
		t.Errorf("refusal %q wears the command's name — a loader verdict crosses unimproved", got)
	}

	if !strings.Contains(got, "is a directory") {
		t.Errorf("refusal %q does not say what went wrong", got)
	}
}

// TestVerifyPolicyRefusesAnUnknownFlag: flag.ContinueOnError writes its
// own message, so this proves the exit code rather than the text.
func TestVerifyPolicyRefusesAnUnknownFlag(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer

	code := Run([]string{"verify", modePolicy, "--kind", "assert"}, &stdout, &stderr)
	if code != exitUsage {
		t.Errorf("exit = %d, want exitUsage", code)
	}
}

// TestVerifyPolicyReachesNothing is the offline claim, held to the
// seams rather than asserted in a comment. Every effectful constructor
// in this package is replaced with one that fails the test if it is
// called; a clean load and a refusal must both complete without
// touching any of them.
func TestVerifyPolicyReachesNothing(t *testing.T) {
	origBV, origStore, origHist, origRoot := newBundleVerifier, newStore, openHistory, resolveTrustedRoot

	t.Cleanup(func() {
		newBundleVerifier, newStore, openHistory, resolveTrustedRoot = origBV, origStore, origHist, origRoot
	})

	newBundleVerifier = func([]byte) (verify.BundleVerifier, error) {
		t.Error("the load-check built a bundle verifier — it holds no trust material")

		return nil, errSinkI
	}
	newStore = func(bool) verify.Store {
		t.Error("the load-check opened the attestation store — it reads no evidence")

		return nil
	}
	openHistory = func(string, string) (verify.History, error) {
		t.Error("the load-check opened a repository — it walks no history")

		return nil, errSinkI
	}
	resolveTrustedRoot = func(trust.RootPlan) ([]byte, error) {
		t.Error("the load-check resolved a trusted root — TUF is a network reach")

		return nil, errSinkI
	}

	clean := writePolicyDoc(t, "clean.json", cleanVerifyPolicy)
	stale := writePolicyDoc(t, "stale.json", strings.Replace(cleanVerifyPolicy, `"schema": 7`, `"schema": 5`, 1))

	for _, row := range []struct {
		name string
		path string
		want int
	}{
		{"a clean load", clean, exitOK},
		{"a refusal", stale, exitRefused},
	} {
		t.Run(row.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := Run([]string{"verify", modePolicy, "--verify-policy", row.path}, &stdout, &stderr); code != row.want {
				t.Errorf("exit = %d, want %d", code, row.want)
			}
		})
	}
}

// TestVerifyPolicyStreamGuards sweeps the paths that write: the
// loader's refusal and the command's own usage error. A clean load
// writes nothing, so there is no stream on it to fail.
func TestVerifyPolicyStreamGuards(t *testing.T) {
	stale := writePolicyDoc(t, "stale.json", strings.Replace(cleanAssertPolicy, `"schema": 7`, `"schema": 5`, 1))

	t.Run("a refused document", func(t *testing.T) {
		sweepWriteFailures(t, []string{"verify", modePolicy, "--assert-policy", stale})
	})

	t.Run("a usage refusal", func(t *testing.T) {
		sweepWriteFailures(t, []string{"verify", modePolicy})
	})
}
