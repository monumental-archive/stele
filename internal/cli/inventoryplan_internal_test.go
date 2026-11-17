// Wiring tests for `derive inventory-plan` (stele#396): every usage
// refusal, the planned-prefix read from the assert policy, and the
// placement of the plan. The producer's own guards are tabled in
// internal/release.
//
// The prefix rows are the canon's plan-producer join
// (`mise/test_plan_producers.py`) where it concerns the rust-crate
// plan: there a marker in the workflow had to match the policy's
// planned prefix; here the producer READS that prefix, so a rename on
// the policy side is followed rather than refused, and what is left to
// refuse is a class the policy does not declare, one owing no planned
// inventory, and one whose prefix is ambiguous.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// inventoryPlanPolicy declares the canon's two producing shapes (the
// extension class with an unplanned asset beside its planned one), a
// class whose binaries carry their own inventory, and a class with no
// inventory declared.
const inventoryPlanPolicy = `{
  "schema": 9,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "classes": {
      "rust-crate": {
        "bundles": ["attestations-crates.intoto.jsonl"],
        "assetPrefixes": [{"prefix": "sbom-cargo-", "owedFrom": "1.42.0", "planned": true}],
        "inventory": {"kind": "crates", "artifactSuffix": "-crate"}
      },
      "pgrx-extension": {
        "bundles": ["attestations-extensions.intoto.jsonl"],
        "assetPrefixes": [
          {"prefix": "attestations-extimg-pg"},
          {"prefix": "sbom-pgrx-", "owedFrom": "1.42.0", "planned": true}
        ],
        "inventory": {"kind": "variants", "artifact": "{package}-pg{variant}", "features": ["pg{variant}"],
          "noDefaultFeatures": true}
      },
      "go-binary": {"bundles": ["attestations-binaries.intoto.jsonl"], "inventory": {"kind": "binaries"}},
      "source-archive": {"bundles": ["attestations-source.intoto.jsonl"]}
    }
  }
}`

const planFixtures = "../release/testdata/plans"

// fixtureCrateDir lays the extension fixture's manifest (committed as
// Cargo.toml.fixture, so the gate sees no Rust crate here) out as a
// crate directory.
func fixtureCrateDir(t *testing.T) string {
	t.Helper()

	manifest, err := os.ReadFile(filepath.Join(planFixtures, "extension", "Cargo.toml.fixture"))
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	//nolint:gosec // G703: the path is the test's own temp dir; the fixture's bytes are content, not a path
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), manifest, ownerRW); err != nil {
		t.Fatal(err)
	}

	return dir
}

func writeInventoryPlanPolicy(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "assert-policy.json")
	if err := os.WriteFile(path, []byte(body), ownerRW); err != nil {
		t.Fatal(err)
	}

	return path
}

func cratesArgs(policy string) []string {
	return []string{
		"inventory-plan", "--class", "rust-crate", "--policy", policy,
		"--dir", filepath.Join(planFixtures, "crates", "package"), "--version", "0.4.2",
	}
}

// TestDeriveInventoryPlanWritesTheShellsBytes: the plan on stdout is
// the golden the canon's block wrote, and every planned document is
// named on stderr the way the block's notices named it.
func TestDeriveInventoryPlanWritesTheShellsBytes(t *testing.T) {
	policy := writeInventoryPlanPolicy(t, inventoryPlanPolicy)

	tests := []struct {
		name   string
		args   []string
		golden string
		logs   []string
	}{
		{
			name:   "packaged crates",
			args:   cratesArgs(policy),
			golden: filepath.Join(planFixtures, "crates", "plan.golden"),
			logs: []string{
				"plans inventory sbom-cargo-edtf-crate for package edtf",
				"plans inventory sbom-cargo-edtf-cli-crate for package edtf-cli",
				"plans inventory sbom-cargo-edtf_core-crate for package edtf_core",
			},
		},
		{
			name: "one extension cell",
			args: []string{
				"inventory-plan", "--class", "pgrx-extension", "--policy", policy,
				"--crate-dir", fixtureCrateDir(t), "--variant", "16",
			},
			golden: filepath.Join(planFixtures, "extension", "plan.golden"),
			logs:   []string{"plans inventory sbom-pgrx-pg_edtf-pg16 for package pg_edtf"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if got := deriveCmd(tt.args, &stdout, &stderr); got != exitOK {
				t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
			}

			want, err := os.ReadFile(tt.golden)
			if err != nil {
				t.Fatal(err)
			}

			if stdout.String() != string(want) {
				t.Errorf("stdout differs from the shell's plan\ngot:\n%s\nwant:\n%s", stdout.String(), want)
			}

			for _, l := range tt.logs {
				if !strings.Contains(stderr.String(), l) {
					t.Errorf("stderr %q does not name %q", stderr.String(), l)
				}
			}
		})
	}
}

// TestDeriveInventoryPlanOut: --out writes the same bytes, and a plan
// that cannot be written is a refusal, never a success.
func TestDeriveInventoryPlanOut(t *testing.T) {
	policy := writeInventoryPlanPolicy(t, inventoryPlanPolicy)

	t.Run("written where asked", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "plan.json")

		var stdout, stderr bytes.Buffer

		if got := deriveCmd(append(cratesArgs(policy), "--out", out), &stdout, &stderr); got != exitOK {
			t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
		}

		got, err := os.ReadFile(out) //nolint:gosec // the test's own temp file
		if err != nil {
			t.Fatal(err)
		}

		want, err := os.ReadFile(filepath.Join(planFixtures, "crates", "plan.golden"))
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(got, want) {
			t.Errorf("--out differs from the shell's plan\ngot:\n%s", got)
		}
	})

	t.Run("an unwritable out", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "absent", "plan.json")

		var stdout, stderr bytes.Buffer

		if got := deriveCmd(append(cratesArgs(policy), "--out", out), &stdout, &stderr); got != exitRefused {
			t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, exitRefused, stderr.String())
		}

		if !strings.Contains(stderr.String(), "derive inventory-plan: open ") {
			t.Errorf("stderr = %q, want the write refusal", stderr.String())
		}
	})

	t.Run("a failing stdout", func(t *testing.T) {
		var stderr bytes.Buffer

		if got := deriveCmd(cratesArgs(policy), failWriterI{}, &stderr); got != exitIO {
			t.Fatalf("deriveCmd = %d, want %d", got, exitIO)
		}
	})
}

// TestDeriveInventoryPlanRefusals: usage and policy refusals, each
// asserted by message.
func TestDeriveInventoryPlanRefusals(t *testing.T) {
	policy := writeInventoryPlanPolicy(t, inventoryPlanPolicy)
	notAPolicy := writeInventoryPlanPolicy(t, `{"schema": 9}`)

	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{
			name: "no class",
			args: []string{"inventory-plan", "--policy", policy},
			code: exitUsage,
			want: "stele derive inventory-plan: --class is required",
		},
		{
			name: "no policy",
			args: []string{"inventory-plan", "--class", "rust-crate"},
			code: exitUsage,
			want: "stele derive inventory-plan: --policy is required",
		},
		{
			name: "an unexpected argument",
			args: []string{"inventory-plan", "--class", "rust-crate", "--policy", policy, "extra"},
			code: exitUsage,
			want: `stele derive inventory-plan: unexpected argument "extra"`,
		},
		{
			name: "an unknown flag",
			args: []string{"inventory-plan", "--nope"},
			code: exitUsage,
			want: "flag provided but not defined: -nope",
		},
		{
			name: "a class whose kind stele writes no plan for",
			args: []string{"inventory-plan", "--class", "go-binary", "--policy", policy},
			code: exitRefused,
			want: `derive inventory-plan: class "go-binary" declares inventory kind "binaries", which stele writes no` +
				` plan for`,
		},
		{
			name: "a class declaring no inventory",
			args: []string{"inventory-plan", "--class", "source-archive", "--policy", policy},
			code: exitRefused,
			want: `derive inventory-plan: class "source-archive" declares no inventory — its leg has no plan to write`,
		},
		{
			name: "a policy that is not there",
			args: []string{
				"inventory-plan", "--class", "rust-crate", "--policy", filepath.Join(t.TempDir(), "absent.json"),
			},
			code: exitRefused,
			want: "derive inventory-plan: open ",
		},
		{
			name: "a policy that does not load",
			args: []string{"inventory-plan", "--class", "rust-crate", "--policy", notAPolicy},
			code: exitRefused,
			want: "derive inventory-plan: ",
		},
		{
			name: "a class the policy does not declare",
			args: []string{
				"inventory-plan", "--class", "rust-crate",
				"--policy", writeInventoryPlanPolicy(t, strings.Replace(inventoryPlanPolicy, `"rust-crate"`, `"crates"`, 1)),
			},
			code: exitRefused,
			want: `derive inventory-plan: class "rust-crate" is not declared in the assert policy`,
		},
		{
			name: "a class declaring two planned prefixes refuses at load",
			args: []string{
				"inventory-plan", "--class", "rust-crate",
				"--policy", writeInventoryPlanPolicy(t, strings.Replace(inventoryPlanPolicy,
					`[{"prefix": "sbom-cargo-", "owedFrom": "1.42.0", "planned": true}]`,
					`[{"prefix": "sbom-cargo-", "planned": true}, {"prefix": "sbom-crates-", "planned": true}]`, 1)),
			},
			code: exitRefused,
			want: `evidence.classes.rust-crate.inventory.kind "crates" writes the plan under the class's one planned` +
				` prefix, and the class declares 2`,
		},
		{
			name: "the producer's own refusal",
			args: []string{
				"inventory-plan", "--class", "rust-crate", "--policy", policy,
				"--dir", t.TempDir(), "--version", "0.4.2",
			},
			code: exitRefused,
			want: "derive inventory-plan: cargo package produced no crates — a class that ships nothing plans nothing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if got := deriveCmd(tt.args, &stdout, &stderr); got != tt.code {
				t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, tt.code, stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr = %q\nwant it to carry %q", stderr.String(), tt.want)
			}
		})
	}
}

// TestDeriveInventoryPlanFollowsAPolicyRename: the canon's
// "a rename on the policy side only is refused" row, inverted by
// construction — the producer reads the prefix, so the plan follows
// the policy and `assert plans` can never see the two disagree.
func TestDeriveInventoryPlanFollowsAPolicyRename(t *testing.T) {
	renamed := writeInventoryPlanPolicy(t, strings.Replace(inventoryPlanPolicy, "sbom-cargo-", "sbom-crates-", 1))

	var stdout, stderr bytes.Buffer

	if got := deriveCmd(cratesArgs(renamed), &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	if !strings.Contains(stdout.String(), `"doc": "sbom-crates-edtf-crate"`) ||
		strings.Contains(stdout.String(), "sbom-cargo-") {
		t.Errorf("the plan did not follow the policy's prefix:\n%s", stdout.String())
	}
}
