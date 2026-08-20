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
  "schema": 6,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
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

// TestAssertPlansOutSet pins stele#151's contract at the surface: the
// file the derivation leg iterates carries the judged set VERBATIM as
// the report document carries it. One rendering reaches both, so the
// canon's `jq -s 'add | unique'` — a second derivation of the same
// bytes — has nothing left to disagree with.
func TestAssertPlansOutSet(t *testing.T) {
	policyPath, planPath := writePlansFixtures(t,
		`[{"class": "wasm-npm", "doc": "sbom-npm-lab-wasm", "params": {"b": 2, "a": 1}}]`)
	setPath := filepath.Join(t.TempDir(), "plan-set.json")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "plans", "--json", "--policy", policyPath, "--out", setPath,
		"--classes", "wasm-npm", "--machinery-version", "1.43.0", planPath,
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
	}

	written, err := os.ReadFile(setPath) //nolint:gosec // a path this test named in its own temp dir
	if err != nil {
		t.Fatalf("the judged set was not written: %v", err)
	}

	set := strings.TrimSuffix(string(written), "\n")

	const want = `[{"class":"wasm-npm","doc":"sbom-npm-lab-wasm","params":{"a":1,"b":2}}]`
	if set != want {
		t.Fatalf("judged set = %s, want %s", set, want)
	}

	if !strings.Contains(stdout.String(), `"judged":`+set) {
		t.Fatalf("the report does not carry the written set verbatim\nreport: %s", stdout.String())
	}
}

// TestAssertPlansOutRefusedVerdict pins the other half: a set that
// failed judgment is not there to iterate. A workflow that reads the
// file regardless of the exit code must find nothing rather than a
// plan the guard refused.
func TestAssertPlansOutRefusedVerdict(t *testing.T) {
	policyPath, planPath := writePlansFixtures(t, `[{"class": "wasm-npm", "doc": "sbom-cargo-lab-wasm"}]`)
	setPath := filepath.Join(t.TempDir(), "plan-set.json")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "plans", "--policy", policyPath, "--out", setPath,
		"--classes", "wasm-npm", "--machinery-version", "1.43.0", planPath,
	}, &stdout, &stderr)
	if code != exitRefused {
		t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitRefused, stderr.String())
	}

	if _, err := os.Stat(setPath); !os.IsNotExist(err) {
		t.Fatalf("a refused judgment left a set to iterate: %v", err)
	}

	if !strings.Contains(stdout.String(), "the judged set is not emitted") {
		t.Fatalf("the refusal did not say the set was withheld\nstdout: %s", stdout.String())
	}
}

// TestAssertPlansOutWriteFailure sweeps the placement guard: every
// way the file cannot be placed exits exitIO. A guard job that
// reported PASS after failing to write the set the next job reads
// would hand that job a stale file or none at all — the failing-writer
// law applied to a document instead of a stream.
func TestAssertPlansOutWriteFailure(t *testing.T) {
	policyPath, planPath := writePlansFixtures(t,
		`[{"class": "wasm-npm", "doc": "sbom-npm-lab-wasm"}]`)

	dir := t.TempDir()

	tests := []struct {
		name string
		path string
	}{
		{"a path under a directory that does not exist", filepath.Join(dir, "no-such-dir", "set.json")},
		{"a path that is itself a directory", dir},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := Run([]string{
				"assert", "plans", "--policy", policyPath, "--out", tt.path,
				"--classes", "wasm-npm", "--machinery-version", "1.43.0", planPath,
			}, &stdout, &stderr)
			if code != exitIO {
				t.Fatalf("Run = %d, want %d — an unwritable set is an output failure", code, exitIO)
			}

			if strings.Contains(stdout.String(), "assert: PASS") {
				t.Fatalf("the run reported PASS after failing to write the set\nstdout: %s", stdout.String())
			}
		})
	}
}
