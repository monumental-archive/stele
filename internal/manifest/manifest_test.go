package manifest_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/manifest"
)

// The canonical workspace shape prepare-release.sh assumes, with the
// traps that make pattern-matching wrong: an external dependency that
// legitimately shares the released version string, a sub-table spelling
// of an internal dependency, and comments that must survive a rewrite
// byte for byte.
const workspaceToml = `# workspace manifest
[workspace]
members = ["crates/core", "crates/cli"]

[workspace.package]
version = "0.9.0" # the mirrored version
edition = "2024"

[workspace.dependencies]
demo-core = { path = "crates/core", version = "0.9.0" }
serde = { version = "0.9.0", features = ["derive"] }
local-tool = { path = "tools/local" }

[workspace.dependencies.demo-cli]
path = "crates/cli"
version = "0.9.0"
`

const citationCff = `cff-version: 1.2.0
title: demo
version: 0.9.0
date-released: 2026-01-01
`

// write lays a tree out in a temp dir.
func write(t *testing.T, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()

	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	return dir
}

func TestDetectKinds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		kind  string
		sites int
	}{
		{
			name:  "cargo workspace with citation",
			files: map[string]string{"Cargo.toml": workspaceToml, "CITATION.cff": citationCff},
			kind:  manifest.KindCargoWorkspace,
			// workspace version, two internal constraints, citation version
			// — and NOT serde (external) or local-tool (no version).
			sites: 4,
		},
		{
			name:  "single crate",
			files: map[string]string{"Cargo.toml": "[package]\nname = \"demo\"\nversion = \"0.9.0\"\n"},
			kind:  manifest.KindCargoPackage,
			sites: 1,
		},
		{
			name:  "no manifest at all",
			files: map[string]string{},
			kind:  manifest.KindNone,
			sites: 0,
		},
		{
			name:  "citation only",
			files: map[string]string{"CITATION.cff": citationCff},
			kind:  manifest.KindNone,
			sites: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, err := manifest.Detect(write(t, tc.files))
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}

			if set.Kind != tc.kind {
				t.Errorf("Kind = %q, want %q", set.Kind, tc.kind)
			}

			if len(set.Sites) != tc.sites {
				t.Errorf("len(Sites) = %d, want %d: %+v", len(set.Sites), tc.sites, set.Sites)
			}
		})
	}
}

func TestDetectRefuses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		match string
	}{
		{
			name:  "a Cargo.toml with no version anywhere",
			files: map[string]string{"Cargo.toml": "[workspace]\nmembers = []\n"},
			match: "neither",
		},
		{
			name:  "a Cargo.toml that does not parse",
			files: map[string]string{"Cargo.toml": "[package\n"},
			match: "parsing",
		},
		{
			name:  "a citation with no version",
			files: map[string]string{"CITATION.cff": "title: demo\ndate-released: 2026-01-01\n"},
			match: "no version",
		},
		{
			name:  "a citation with no date-released",
			files: map[string]string{"CITATION.cff": "title: demo\nversion: 0.9.0\n"},
			match: "no date-released",
		},
		{
			name:  "a quoted citation version",
			files: map[string]string{"CITATION.cff": "version: \"0.9.0\"\ndate-released: 2026-01-01\n"},
			match: "plain scalar",
		},
		{
			name:  "a citation that is not a mapping",
			files: map[string]string{"CITATION.cff": "- just\n- a list\n"},
			match: "not a YAML mapping",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := manifest.Detect(write(t, tc.files))
			if err == nil || !strings.Contains(err.Error(), tc.match) {
				t.Fatalf("Detect() error = %v, want a refusal mentioning %q", err, tc.match)
			}
		})
	}
}

func TestVersionAgreement(t *testing.T) {
	t.Run("agreeing mirrors report the version", func(t *testing.T) {
		set, err := manifest.Detect(write(t, map[string]string{
			"Cargo.toml": workspaceToml, "CITATION.cff": citationCff,
		}))
		if err != nil {
			t.Fatalf("Detect: %v", err)
		}

		v, err := set.Version()
		if err != nil {
			t.Fatalf("Version: %v", err)
		}

		if v != "0.9.0" {
			t.Errorf("Version = %q, want 0.9.0", v)
		}
	})

	t.Run("a disagreeing mirror is refused by name", func(t *testing.T) {
		set, err := manifest.Detect(write(t, map[string]string{
			"Cargo.toml":   workspaceToml,
			"CITATION.cff": "version: 0.8.7\ndate-released: 2026-01-01\n",
		}))
		if err != nil {
			t.Fatalf("Detect: %v", err)
		}

		_, err = set.Version()
		if err == nil || !strings.Contains(err.Error(), "CITATION.cff version = \"0.8.7\"") {
			t.Fatalf("Version() error = %v, want the disagreeing site named", err)
		}
	})

	t.Run("no mirrors is its own fact", func(t *testing.T) {
		set, err := manifest.Detect(write(t, nil))
		if err != nil {
			t.Fatalf("Detect: %v", err)
		}

		if _, err := set.Version(); err == nil {
			t.Fatal("Version() reported a version for a tree with no mirrors")
		}
	})
}

func TestCheck(t *testing.T) {
	set, err := manifest.Detect(write(t, map[string]string{
		"Cargo.toml": workspaceToml, "CITATION.cff": citationCff,
	}))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if cerr := set.Check("0.9.0"); cerr != nil {
		t.Errorf("Check(0.9.0) = %v, want pass", cerr)
	}

	cerr := set.Check("0.10.0")
	if cerr == nil || !strings.Contains(cerr.Error(), "workspace.package.version") {
		t.Errorf("Check(0.10.0) = %v, want every wrong mirror named", cerr)
	}
}

func TestRewrite(t *testing.T) {
	dir := write(t, map[string]string{"Cargo.toml": workspaceToml, "CITATION.cff": citationCff})

	set, err := manifest.Detect(dir)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	files, err := set.Rewrite("0.10.0", "2026-08-18")
	if err != nil {
		t.Fatalf("Rewrite: %v", err)
	}

	if got := strings.Join(files, " "); got != "CITATION.cff Cargo.toml" {
		t.Errorf("files = %q", got)
	}

	cargo, err := os.ReadFile(filepath.Join(dir, "Cargo.toml")) //nolint:gosec // a path this test just wrote
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}

	for _, tc := range []struct {
		name, needle string
		want         bool
	}{
		{name: "the workspace version moved", needle: "version = \"0.10.0\" # the mirrored version", want: true},
		{
			name:   "the inline internal constraint moved",
			needle: "demo-core = { path = \"crates/core\", version = \"0.10.0\" }",
			want:   true,
		},
		{name: "the sub-table internal constraint moved", needle: "version = \"0.10.0\"\n", want: true},
		{
			name:   "the external dependency did not move",
			needle: "serde = { version = \"0.9.0\", features = [\"derive\"] }",
			want:   true,
		},
		{
			name:   "the version-less path dependency is untouched",
			needle: "local-tool = { path = \"tools/local\" }",
			want:   true,
		},
		{name: "comments survive", needle: "# workspace manifest", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(string(cargo), tc.needle) != tc.want {
				t.Errorf("Cargo.toml contains %q = %v, want %v\n%s", tc.needle, !tc.want, tc.want, cargo)
			}
		})
	}

	citation, err := os.ReadFile(filepath.Join(dir, "CITATION.cff")) //nolint:gosec // a path this test just wrote
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}

	want := "cff-version: 1.2.0\ntitle: demo\nversion: 0.10.0\ndate-released: 2026-08-18\n"
	if string(citation) != want {
		t.Errorf("CITATION.cff = %q, want %q", citation, want)
	}

	t.Run("safe to repeat", func(t *testing.T) {
		again, err := manifest.Detect(dir)
		if err != nil {
			t.Fatalf("Detect: %v", err)
		}

		if _, err := again.Rewrite("0.10.0", "2026-08-18"); err != nil {
			t.Fatalf("a re-run of the same rewrite was refused: %v", err)
		}
	})
}

func TestFiles(t *testing.T) {
	set, err := manifest.Detect(write(t, map[string]string{
		"Cargo.toml": workspaceToml, "CITATION.cff": citationCff,
	}))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if got := strings.Join(set.Files(), " "); got != "CITATION.cff Cargo.toml" {
		t.Errorf("Files = %q", got)
	}
}
