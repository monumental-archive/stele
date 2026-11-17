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

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/release"
)

const plansFixtures = "testdata/plans"

func producer(t *testing.T, class string) *release.PlanClass {
	t.Helper()

	c, ok := release.PlanClassNamed(class)
	if !ok {
		t.Fatalf("no plan producer for %q", class)
	}

	return c
}

func render(t *testing.T, entries []release.PlanEntry) string {
	t.Helper()

	var b bytes.Buffer
	if err := jsonx.EncodeIndent(&b, entries); err != nil {
		t.Fatalf("EncodeIndent = %v", err)
	}

	return b.String()
}

func TestPlanGoldens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		class  string
		in     release.PlanInputs
		golden string
	}{
		{
			name:  "packaged crates",
			class: "rust-crate",
			in: release.PlanInputs{
				Prefix: "sbom-cargo-", Dir: filepath.Join(plansFixtures, "crates", "package"), Version: "0.4.2",
			},
			golden: filepath.Join(plansFixtures, "crates", "plan.golden"),
		},
		{
			name:  "one extension cell",
			class: "pgrx-extension",
			in: release.PlanInputs{
				Prefix: "sbom-pgrx-", CrateDir: fixtureCrate(t), Major: "16",
			},
			golden: filepath.Join(plansFixtures, "extension", "plan.golden"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			entries, err := producer(t, tt.class).Plan(&tt.in)
			if err != nil {
				t.Fatalf("Plan = %v", err)
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

// writeCrate lays out an extension crate with the given manifest;
// manifest "" writes none.
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

	tests := []struct {
		name  string
		class string
		in    func(t *testing.T) release.PlanInputs
		want  string
	}{
		{
			name:  "no prefix",
			class: "rust-crate",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{Dir: writeCrates(t, "a-1.0.0.crate"), Version: "1.0.0"}
			},
			want: "rust-crate: no planned prefix — the policy names the documents, the leg does not",
		},
		{
			name:  "a crates leg with no version",
			class: "rust-crate",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{Prefix: "sbom-cargo-", Dir: writeCrates(t, "a-1.0.0.crate")}
			},
			want: "rust-crate plans from packaged crates: the directory and the version are required",
		},
		{
			name:  "a crate not named for the version",
			class: "rust-crate",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{
					Prefix: "sbom-cargo-", Dir: writeCrates(t, "a-1.0.0.crate", "b-0.9.0.crate"), Version: "1.0.0",
				}
			},
			want: "packaged crate b-0.9.0.crate is not named for version 1.0.0",
		},
		{
			name:  "a crate that is only the version",
			class: "rust-crate",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{Prefix: "sbom-cargo-", Dir: writeCrates(t, "-1.0.0.crate"), Version: "1.0.0"}
			},
			want: "packaged crate -1.0.0.crate is not named for version 1.0.0",
		},
		{
			name:  "no crates",
			class: "rust-crate",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{Prefix: "sbom-cargo-", Dir: writeCrates(t, "notes.txt"), Version: "1.0.0"}
			},
			want: "cargo package produced no crates — a class that ships nothing plans nothing",
		},
		{
			name:  "a malformed crate directory pattern",
			class: "rust-crate",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{Prefix: "sbom-cargo-", Dir: "[", Version: "1.0.0"}
			},
			want: "rust-crate: syntax error in pattern",
		},
		{
			name:  "an extension cell with no major",
			class: "pgrx-extension",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{Prefix: "sbom-pgrx-", CrateDir: writeCrate(t, "[package]\nname = \"x\"\n")}
			},
			want: `pgrx-extension plans one cell: the crate directory and a numeric Postgres major are required (major "")`,
		},
		{
			name:  "a major that is not a number",
			class: "pgrx-extension",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{
					Prefix: "sbom-pgrx-", CrateDir: writeCrate(t, "[package]\nname = \"x\"\n"), Major: "pg16",
				}
			},
			want: `a numeric Postgres major are required (major "pg16")`,
		},
		{
			name:  "no crate manifest",
			class: "pgrx-extension",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{Prefix: "sbom-pgrx-", CrateDir: writeCrate(t, ""), Major: "16"}
			},
			want: "reading the crate manifest:",
		},
		{
			name:  "a manifest that is not TOML",
			class: "pgrx-extension",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{Prefix: "sbom-pgrx-", CrateDir: writeCrate(t, "[package\n"), Major: "16"}
			},
			want: "Cargo.toml:",
		},
		{
			name:  "a manifest with no package",
			class: "pgrx-extension",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{Prefix: "sbom-pgrx-", CrateDir: writeCrate(t, "[workspace]\n"), Major: "16"}
			},
			want: "names no package — a cell plans the crate it built",
		},
		{
			name:  "a package with no name",
			class: "pgrx-extension",
			in: func(t *testing.T) release.PlanInputs {
				t.Helper()

				return release.PlanInputs{
					Prefix: "sbom-pgrx-", CrateDir: writeCrate(t, "[package]\nversion = \"1.0.0\"\n"), Major: "16",
				}
			},
			want: "names no package — a cell plans the crate it built",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			in := tt.in(t)

			_, err := producer(t, tt.class).Plan(&in)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Plan error = %v\nwant it to carry %q", err, tt.want)
			}
		})
	}
}

// TestPlanClasses: the rows, their lookup, and the one artifact name
// the producer writes and the coverage check reads.
func TestPlanClasses(t *testing.T) {
	t.Parallel()

	if got := strings.Join(release.PlanClasses(), ","); got != "pgrx-extension,rust-crate" {
		t.Errorf("PlanClasses = %q", got)
	}

	if _, ok := release.PlanClassNamed("go-binary"); ok {
		t.Error("go-binary has no plan producer: its binaries carry their inventory")
	}

	if !producer(t, "rust-crate").Crates() || producer(t, "pgrx-extension").Crates() {
		t.Error("Crates() does not match the rows' shapes")
	}

	if got := release.ExtensionArtifact("pg_edtf", "16"); got != "pg_edtf-pg16" {
		t.Errorf("ExtensionArtifact = %q", got)
	}
}
