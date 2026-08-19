// Wiring tests for `assert plans`: every usage refusal, the file
// reads, and the verdict→exit mapping — the target runs pre-publish
// in a guard job, where a refusal that exits like a verdict would
// burn a release for the wrong reason.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const plansTestPolicy = `{
  "schema": 4,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "debtFile": "debt.txt",
    "classes": {
      "wasm-npm": {
        "bundles": ["attestations-npm.intoto.jsonl"],
        "assetPrefixes": [{ "prefix": "sbom-npm-", "owedFrom": "1.42.0", "planned": true }]
      }
    }
  }
}`

//nolint:gocritic // unnamedResult: the policy path, then the plan path
func writePlansFixtures(t *testing.T, plan string) (string, string) {
	t.Helper()

	dir := t.TempDir()

	policyPath := filepath.Join(dir, "assert-policy.json")
	if err := os.WriteFile(policyPath, []byte(plansTestPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	planPath := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(planPath, []byte(plan), 0o600); err != nil {
		t.Fatal(err)
	}

	return policyPath, planPath
}

func TestAssertPlansExitCodes(t *testing.T) {
	goodPlan := `[{"class": "wasm-npm", "doc": "sbom-npm-lab-wasm"}]`
	badPlan := `[{"class": "wasm-npm", "doc": "sbom-cargo-lab-wasm"}]`

	tests := []struct {
		name string
		plan string
		want int
		out  string
	}{
		{"a satisfied obligation passes", goodPlan, exitOK, "assert: PASS"},
		{"the .github#544 misnaming fails", badPlan, exitRefused, "sbom-npm-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyPath, planPath := writePlansFixtures(t, tt.plan)

			var stdout, stderr bytes.Buffer

			code := Run([]string{
				"assert", "plans", "--policy", policyPath,
				"--classes", "wasm-npm", "--machinery-version", "1.43.0", planPath,
			}, &stdout, &stderr)
			if code != tt.want {
				t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s", code, tt.want, stdout.String(), stderr.String())
			}

			if !strings.Contains(stdout.String(), tt.out) {
				t.Fatalf("stdout = %q, want substring %q", stdout.String(), tt.out)
			}
		})
	}
}

func TestAssertPlansUsageRefusals(t *testing.T) {
	policyPath, planPath := writePlansFixtures(t, `[]`)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"policy is required", []string{"--classes", "wasm-npm", "--machinery-version", "1.43.0"}, "--policy is required"},
		{"classes are required", []string{"--policy", policyPath, "--machinery-version", "1.43.0"}, "--classes is required"},
		{
			"a comma is not a class list",
			[]string{"--policy", policyPath, "--classes", ",", "--machinery-version", "1.43.0"},
			"--classes is required",
		},
		{
			"the machinery version is required",
			[]string{"--policy", policyPath, "--classes", "wasm-npm"},
			"--machinery-version is required",
		},
		{
			"an unreadable policy refuses",
			[]string{"--policy", policyPath + ".gone", "--classes", "wasm-npm", "--machinery-version", "1.43.0"},
			"no such file",
		},
		{
			"a malformed policy refuses",
			[]string{"--policy", planPath, "--classes", "wasm-npm", "--machinery-version", "1.43.0"},
			"policy",
		},
		{
			"an unreadable plan refuses as usage, not as a defective leg",
			[]string{"--policy", policyPath, "--classes", "wasm-npm", "--machinery-version", "1.43.0", planPath + ".gone"},
			"no such file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := Run(append([]string{"assert", "plans"}, tt.args...), &stdout, &stderr)
			if code != exitUsage {
				t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitUsage, stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), tt.want)
			}
		})
	}
}

// TestAssertPlansJSON pins the --json contract: one document on
// stdout, progress on stderr, the verdict mapped to the exit code.
func TestAssertPlansJSON(t *testing.T) {
	policyPath, planPath := writePlansFixtures(t,
		`[{"class": "wasm-npm", "doc": "sbom-npm-lab-wasm"}]`)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "plans", "--json", "--policy", policyPath,
		"--classes", "wasm-npm", "--machinery-version", "1.43.0", planPath,
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
	}

	if !strings.Contains(stdout.String(), `"PASS"`) {
		t.Fatalf("stdout = %q, want a PASS document", stdout.String())
	}
}
