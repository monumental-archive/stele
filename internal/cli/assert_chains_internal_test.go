// Wiring tests for `stele assert chains` (stele#94): usage refusals,
// the section and source-authority gates, and the end-to-end snapshot
// paths that never need the crypto engine — an unactivated repo is
// judged before verification, which is exactly the case the walk owns.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/verify"
)

// chainsWorld writes an assert policy (chains section with one
// declared exception), a chains-only verify policy, and a snapshot
// with an unactivated repository.
func chainsWorld(t *testing.T) (string, string, string, string) { //nolint:gocritic // snap, policy, verify policy, root
	t.Helper()

	dir := t.TempDir()

	files := map[string]string{
		// The org listing: one repository, no notes captured for it —
		// replay reads the absence as an empty chain.
		"snap/acme/repos.json": `["lab"]`,
		"policy.json": `{"schema": 5, ` +
			`"evidence": {"sbomSuffix": ".spdx.json", "checksums": "checksums.txt", ` +
			`"umbrellaBundle": "attestations.intoto.jsonl", "manifestAsset": "evidence-manifest.json", ` +
			`"classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}}, ` +
			`"chains": {"exceptions": [{"repo": "lab", "reason": "lab-first activation"}]}}`,
		"verify-policy.json": `{"schema": 5, "issuer": "https://token.example.com", ` +
			`"trust": {"provenance": {"signerWorkflow": "{owner}/{repo}/.github/workflows/source-attest.yml"}}, ` +
			`"source": {` +
			`"identity": "https://github.com/{owner}/{repo}/.github/workflows/source-attest.yml@refs/heads/main", ` +
			`"notesRef": "refs/notes/commits", ` +
			`"provenancePredicateType": "https://example.com/source-provenance/v1", ` +
			`"propertyPrefix": "ORG_SOURCE_", ` +
			`"resourceUri": "git+https://github.com/{owner}/{repo}", ` +
			`"protectedBranches": [{"name": "main", "targetLevel": "SLSA_SOURCE_LEVEL_2", ` +
			`"levels": [{"level": "SLSA_SOURCE_LEVEL_2", ` +
			`"requiredProperties": [{"name": "ORG_SOURCE_GATED", "since": "2026-01-01T00:00:00Z"}]}]}], ` +
			`"healedContinuity": false, "underclaimLevel": "SLSA_SOURCE_LEVEL_1"}}`,
		"root.json": `{"seam": "swallows this"}`,
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
		filepath.Join(dir, "verify-policy.json"), filepath.Join(dir, "root.json")
}

// swapChainsBV installs a bundle-verifier seam that never verifies —
// these tests exercise routing; the trust boundary is proven in
// internal/trust and internal/verify.
func swapChainsBV(t *testing.T) {
	t.Helper()

	orig := newBundleVerifier

	newBundleVerifier = func([]byte) (verify.BundleVerifier, error) { return attestorBV{payload: okStatement}, nil }

	t.Cleanup(func() { newBundleVerifier = orig })
}

func TestAssertChainsDeclaredExceptionPasses(t *testing.T) {
	snap, policy, vpolicy, root := chainsWorld(t)
	swapChainsBV(t)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "chains", "--org", "acme", "--policy", policy, "--verify-policy", vpolicy,
		"--trusted-root", root, "--snapshot", snap,
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	if !strings.Contains(stdout.String(), "PASS") {
		t.Errorf("stdout = %q, want the PASS verdict", stdout.String())
	}
}

func TestAssertChainsUnactivatedWithoutExceptionFails(t *testing.T) {
	snap, policy, vpolicy, root := chainsWorld(t)
	swapChainsBV(t)

	// Rewrite the policy with no exceptions: the same unactivated
	// repository is now a finding.
	bare := filepath.Join(t.TempDir(), "policy.json")

	content, err := os.ReadFile(policy) //nolint:gosec // test-owned path
	if err != nil {
		t.Fatal(err)
	}

	stripped := strings.Replace(string(content),
		`[{"repo": "lab", "reason": "lab-first activation"}]`, `[]`, 1)
	if err := os.WriteFile(bare, []byte(stripped), 0o600); err != nil { //nolint:gosec // test-owned path
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "chains", "--org", "acme", "--policy", bare, "--verify-policy", vpolicy,
		"--trusted-root", root, "--snapshot", snap, "--json",
	}, &stdout, &stderr)
	if code != exitRefused {
		t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s", code, exitRefused, stdout.String(), stderr.String())
	}

	doc := decodeReport(t, &stdout)
	if doc.Verdict == nil || *doc.Verdict != "FAIL" {
		t.Fatalf("verdict = %v, want FAIL", doc.Verdict)
	}
}

// TestAssertChainsFoundedButRefusedFails drives the real chainWalker
// binding: the repository IS founded (a link-shaped note exists), so
// the walk reaches verify.Chain over the snapshot-backed history —
// and the note fails the engine's stricter decode, leaving the tip
// unlinked. The declared opt-out matches the subject and must not
// excuse the defect.
func TestAssertChainsFoundedButRefusedFails(t *testing.T) {
	snap, policy, vpolicy, root := chainsWorld(t)
	swapChainsBV(t)

	const tip = "5555555555555555555555555555555555555555"

	files := map[string]string{
		"acme/lab/refs/refs%2Fheads%2Fmain.json": `"` + tip + `"`,
		"acme/lab/notes/refs%2Fnotes%2Fcommits.json": `[{"Rev": "` + tip +
			`", "Note": {"version": 2, "provenance": {"bundle": {}}}}]`,
		"acme/lab/commits/" + tip + ".json": `{"Parents": [], "CommitEpoch": 100}`,
	}

	for path, content := range files {
		full := filepath.Join(snap, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "chains", "--org", "acme", "--policy", policy, "--verify-policy", vpolicy,
		"--trusted-root", root, "--snapshot", snap, "--json",
	}, &stdout, &stderr)
	if code != exitRefused {
		t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s", code, exitRefused, stdout.String(), stderr.String())
	}

	doc := decodeReport(t, &stdout)
	if doc.Verdict == nil || *doc.Verdict != "FAIL" {
		t.Fatalf("verdict = %v, want FAIL — an opt-out excuses absence, never a founded chain's defect", doc.Verdict)
	}
}

func TestAssertChainsUsageRefusals(t *testing.T) {
	snap, policy, vpolicy, root := chainsWorld(t)

	rows := [][]string{
		{"assert", "chains", "--policy", policy, "--verify-policy", vpolicy, "--trusted-root", root},
		{
			"assert", "chains", "--org", "acme", "--repo", "acme/lab", "--policy", policy,
			"--verify-policy", vpolicy, "--trusted-root", root,
		},
		{
			"assert", "chains", "--repo", "solo", "--policy", policy, "--verify-policy", vpolicy,
			"--trusted-root", root,
		},
		{"assert", "chains", "--org", "acme", "--verify-policy", vpolicy, "--trusted-root", root},
		{"assert", "chains", "--org", "acme", "--policy", policy, "--trusted-root", root},
		{
			"assert", "chains", "--org", "acme", "--policy", policy, "--verify-policy", vpolicy,
			"--trusted-root", root, "--snapshot", snap, "--capture", snap,
		},
		{
			"assert", "chains", "--org", "acme", "--policy", policy, "--verify-policy", vpolicy,
			"--snapshot", snap,
		},
		{
			"assert", "chains", "--org", "acme", "--policy", "/no/such", "--verify-policy", vpolicy,
			"--trusted-root", root,
		},
		{
			"assert", "chains", "--org", "acme", "--policy", policy, "--verify-policy", "/no/such",
			"--trusted-root", root,
		},
		{"assert", "chains", "--conjure"},
	}

	for _, args := range rows {
		t.Run(strings.Join(args[2:], " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := Run(args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("Run = %d, want %d; stderr: %s", code, exitUsage, stderr.String())
			}
		})
	}
}

func TestAssertChainsSectionGates(t *testing.T) {
	snap, policy, vpolicy, root := chainsWorld(t)
	swapChainsBV(t)

	t.Run("no chains section in the assert policy", func(t *testing.T) {
		bare := filepath.Join(t.TempDir(), "policy.json")

		content, err := os.ReadFile(policy) //nolint:gosec // test-owned path
		if err != nil {
			t.Fatal(err)
		}

		stripped := strings.Replace(string(content),
			`, "chains": {"exceptions": [{"repo": "lab", "reason": "lab-first activation"}]}`, ``, 1)
		if err := os.WriteFile(bare, []byte(stripped), 0o600); err != nil { //nolint:gosec // test-owned path
			t.Fatal(err)
		}

		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"assert", "chains", "--org", "acme", "--policy", bare, "--verify-policy", vpolicy,
			"--trusted-root", root, "--snapshot", snap,
		}, &stdout, &stderr)
		if code != exitUsage || !strings.Contains(stderr.String(), "no chains section") {
			t.Fatalf("Run = %d, stderr = %q, want the section refusal", code, stderr.String())
		}
	})

	t.Run("no source section in the verify policy", func(t *testing.T) {
		bare := filepath.Join(t.TempDir(), "verify-policy.json")
		doc := `{"schema": 5, "issuer": "https://token.example.com", ` +
			`"trust": {"provenance": {"signerWorkflow": "{owner}/{repo}/.github/workflows/source-attest.yml"}}}`

		if err := os.WriteFile(bare, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}

		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"assert", "chains", "--org", "acme", "--policy", policy, "--verify-policy", bare,
			"--trusted-root", root, "--snapshot", snap,
		}, &stdout, &stderr)
		if code != exitUsage || !strings.Contains(stderr.String(), "no source section") {
			t.Fatalf("Run = %d, stderr = %q, want the source refusal", code, stderr.String())
		}
	})

	t.Run("a torn listing seals CANNOT_JUDGE", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"assert", "chains", "--org", "acme", "--policy", policy, "--verify-policy", vpolicy,
			"--trusted-root", root, "--snapshot", t.TempDir(),
		}, &stdout, &stderr)
		if code != exitBlind {
			t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s",
				code, exitBlind, stdout.String(), stderr.String())
		}
	})
}
