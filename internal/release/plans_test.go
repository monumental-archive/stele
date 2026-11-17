// The inventory plan producers' table (stele#396). The goldens under
// testdata/plans were written by the canon's own shell blocks, run
// verbatim (testdata/plans/SOURCE.md), so a passing golden row is the
// producer writing the bytes the build leg wrote.

package release_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/release"
)

const plansFixtures = "testdata/plans"

// producerPolicy carries the canon's two producing shapes and one a
// stranger's org might declare — a class this org does not have, with
// its own naming shape — which must pass with no code change.
const producerPolicy = `{"schema": 9, "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",
  "umbrellaBundle": "u.jsonl", "manifestAsset": "m.json", "classes": {
    "rust-crate": {"bundles": ["a.intoto.jsonl"],
      "assetPrefixes": [{"prefix": "sbom-cargo-", "planned": true}],
      "inventory": {"kind": "crates", "artifactSuffix": "-crate"}},
    "pgrx-extension": {"bundles": ["b.intoto.jsonl"],
      "assetPrefixes": [{"prefix": "sbom-pgrx-", "planned": true}],
      "inventory": {"kind": "variants", "artifact": "{package}-pg{variant}", "features": ["pg{variant}"],
        "noDefaultFeatures": true}},
    "lua-module": {"bundles": ["c.intoto.jsonl"],
      "assetPrefixes": [{"prefix": "inv-lua-", "planned": true}],
      "inventory": {"kind": "variants", "artifact": "{package}_lua{variant}", "features": ["lua{variant}", "vendored"],
        "noDefaultFeatures": false}},
    "go-binary": {"bundles": ["d.intoto.jsonl"], "inventory": {"kind": "binaries"}},
    "source-archive": {"bundles": ["e.intoto.jsonl"]}}}}`

func producerClass(t *testing.T, class string) *assert.ClassPolicy {
	t.Helper()

	pol, err := assert.LoadPolicy(strings.NewReader(producerPolicy))
	if err != nil {
		t.Fatalf("LoadPolicy = %v", err)
	}

	cp, ok := pol.Evidence.Classes[class]
	if !ok {
		t.Fatalf("the fixture declares no %q", class)
	}

	return &cp
}

func render(t *testing.T, entries []release.PlanEntry) string {
	t.Helper()

	var b bytes.Buffer
	if err := jsonx.EncodeIndent(&b, entries); err != nil {
		t.Fatalf("EncodeIndent = %v", err)
	}

	return b.String()
}

// TestPlanGoldens: the canon's two shapes, byte-identical to the
// bytes the canon's own blocks wrote.
func TestPlanGoldens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		class  string
		in     func(t *testing.T) release.PlanInputs
		golden string
	}{
		{
			name:  "packaged crates",
			class: "rust-crate",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{Dir: filepath.Join(plansFixtures, "crates", "package"), Version: "0.4.2"}
			},
			golden: filepath.Join(plansFixtures, "crates", "plan.golden"),
		},
		{
			name:  "one extension cell",
			class: "pgrx-extension",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{CrateDir: fixtureCrate(t), Variant: "16"}
			},
			golden: filepath.Join(plansFixtures, "extension", "plan.golden"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			in := tt.in(t)

			entries, err := release.InventoryPlan(tt.class, producerClass(t, tt.class), &in)
			if err != nil {
				t.Fatalf("InventoryPlan = %v", err)
			}

			want, err := os.ReadFile(tt.golden)
			if err != nil {
				t.Fatal(err)
			}

			if got := render(t, entries); got != string(want) {
				t.Errorf("plan differs from the shell's\ngot:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

// TestPlanForAStranger: a class this org does not have, naming its
// artifacts its own way, planned with no code change.
func TestPlanForAStranger(t *testing.T) {
	t.Parallel()

	in := release.PlanInputs{CrateDir: fixtureCrate(t), Variant: "54"}

	entries, err := release.InventoryPlan("lua-module", producerClass(t, "lua-module"), &in)
	if err != nil {
		t.Fatalf("InventoryPlan = %v", err)
	}

	want := `[
  {
    "class": "lua-module",
    "doc": "inv-lua-pg_edtf_lua54",
    "artifact": "pg_edtf_lua54",
    "params": {
      "cargoPackage": "pg_edtf",
      "features": [
        "lua54",
        "vendored"
      ]
    }
  }
]
`
	if got := render(t, entries); got != want {
		t.Errorf("plan =\n%s\nwant:\n%s", got, want)
	}
}

// fixtureCrate lays the extension fixture's manifest out as a crate
// directory. The manifest is committed as Cargo.toml.fixture: a tracked
// Cargo.toml would make this Go repository's gate see a Rust crate.
func fixtureCrate(t *testing.T) string {
	t.Helper()

	manifest, err := os.ReadFile(filepath.Join(plansFixtures, "extension", "Cargo.toml.fixture"))
	if err != nil {
		t.Fatal(err)
	}

	return writeCrate(t, string(manifest))
}

// writeCrates lays out a packaged-crates directory.
func writeCrates(t *testing.T, names ...string) string {
	t.Helper()

	dir := t.TempDir()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

// writeCrate lays out a crate with the given manifest; manifest ""
// writes none.
func writeCrate(t *testing.T, manifest string) string {
	t.Helper()

	dir := t.TempDir()
	if manifest != "" {
		//nolint:gosec // G703: the path is the test's own temp dir; the manifest's bytes are content, not a path
		if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

// TestPlanRefusals: every guard, with the shell's message where the
// shell had one.
func TestPlanRefusals(t *testing.T) {
	t.Parallel()

	crate := func(manifest string) func(t *testing.T) release.PlanInputs {
		return func(t *testing.T) release.PlanInputs {
			t.Helper()

			return release.PlanInputs{CrateDir: writeCrate(t, manifest), Variant: "16"}
		}
	}

	tests := []struct {
		name  string
		class string
		in    func(t *testing.T) release.PlanInputs
		want  string
	}{
		{
			name:  "a class declaring no inventory",
			class: "source-archive",
			in:    func(*testing.T) release.PlanInputs { return release.PlanInputs{} },
			want:  `class "source-archive" declares no inventory — its leg has no plan to write`,
		},
		{
			name:  "a kind stele writes no plan for",
			class: "go-binary",
			in:    func(*testing.T) release.PlanInputs { return release.PlanInputs{} },
			want:  `class "go-binary" declares inventory kind "binaries", which stele writes no plan for`,
		},
		{
			name:  "a crates leg with no version",
			class: "rust-crate",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{Dir: writeCrates(t, "a-1.0.0.crate")}
			},
			want: "rust-crate plans from packaged crates: the directory and the version are required",
		},
		{
			name:  "a crate not named for the version",
			class: "rust-crate",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{Dir: writeCrates(t, "a-1.0.0.crate", "b-0.9.0.crate"), Version: "1.0.0"}
			},
			want: "packaged crate b-0.9.0.crate is not named for version 1.0.0",
		},
		{
			name:  "a crate that is only the version",
			class: "rust-crate",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{Dir: writeCrates(t, "-1.0.0.crate"), Version: "1.0.0"}
			},
			want: "packaged crate -1.0.0.crate is not named for version 1.0.0",
		},
		{
			name:  "no crates",
			class: "rust-crate",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{Dir: writeCrates(t, "notes.txt"), Version: "1.0.0"}
			},
			want: "cargo package produced no crates — a class that ships nothing plans nothing",
		},
		{
			name:  "a malformed crate directory pattern",
			class: "rust-crate",
			in:    func(*testing.T) release.PlanInputs { return release.PlanInputs{Dir: "[", Version: "1.0.0"} },
			want:  "rust-crate: syntax error in pattern",
		},
		{
			name:  "a variants cell with no variant",
			class: "pgrx-extension",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{CrateDir: writeCrate(t, "[package]\nname = \"x\"\n")}
			},
			want: `pgrx-extension plans one cell: the crate directory and a plain variant are required (variant "")`,
		},
		{
			name:  "a variant that is not one plain segment",
			class: "pgrx-extension",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{CrateDir: writeCrate(t, "[package]\nname = \"x\"\n"), Variant: "16/amd64"}
			},
			want: `a plain variant are required (variant "16/amd64")`,
		},
		{
			name:  "no crate manifest",
			class: "pgrx-extension",
			in:    crate(""),
			want:  "reading the crate manifest:",
		},
		{
			name:  "a manifest that is not TOML",
			class: "pgrx-extension",
			in:    crate("[package\n"),
			want:  "Cargo.toml:",
		},
		{
			name:  "a manifest with no package",
			class: "pgrx-extension",
			in:    crate("[workspace]\n"),
			want:  "names no package — a cell plans the crate it built",
		},
		{
			name:  "a package with no name",
			class: "pgrx-extension",
			in:    crate("[package]\nversion = \"1.0.0\"\n"),
			want:  "names no package — a cell plans the crate it built",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			in := tt.in(t)

			_, err := release.InventoryPlan(tt.class, producerClass(t, tt.class), &in)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("InventoryPlan error = %v\nwant it to carry %q", err, tt.want)
			}
		})
	}
}
