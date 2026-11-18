package manifest_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/manifest"
)

func tree(t *testing.T, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()

	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

const inherits = "[package]\nname = \"m\"\nversion.workspace = true\n"

// TestMemberVersion: the version Cargo would give the package at a
// directory — its own, or its workspace's by each way Cargo finds the
// workspace — named by the file and field that carry it.
func TestMemberVersion(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		files map[string]string
		dir   string
		path  string
		field string
		value string
	}{
		{
			name:  "a member stating its own version",
			files: map[string]string{"a/Cargo.toml": "[package]\nname = \"a\"\nversion = \"0.3.0\"\n"},
			dir:   "a", path: filepath.Join("a", "Cargo.toml"), field: "package.version", value: "0.3.0",
		},
		{
			name: "a member inheriting from the nearest enclosing workspace",
			files: map[string]string{
				"Cargo.toml":     "[workspace.package]\nversion = \"9.0.0\"\n",
				"x/Cargo.toml":   "[workspace]\nmembers = [\"m\"]\n\n[workspace.package]\nversion = \"2.1.0\"\n",
				"x/m/Cargo.toml": inherits,
			},
			dir: "x/m", path: filepath.Join("x", "Cargo.toml"),
			field: "workspace.package.version, inherited by x/m/Cargo.toml", value: "2.1.0",
		},
		{
			// [workspace] declared only by keys under it, no bare header.
			name: "a workspace declared by its keys alone",
			files: map[string]string{
				"Cargo.toml":     "workspace.package.version = \"1.0.0\"\nworkspace.members = [\"m\"]\n",
				"x/m/Cargo.toml": inherits,
			},
			dir: "x/m", path: "Cargo.toml",
			field: "workspace.package.version, inherited by x/m/Cargo.toml", value: "1.0.0",
		},
		{
			name: "a root package inheriting from its own workspace",
			files: map[string]string{
				"Cargo.toml": "[workspace.package]\nversion = \"4.0.0\"\n\n" + inherits,
			},
			dir: ".", path: "Cargo.toml",
			field: "workspace.package.version, inherited by Cargo.toml", value: "4.0.0",
		},
		{
			name: "a member naming its workspace",
			files: map[string]string{
				"ws/Cargo.toml": "[workspace]\n\n[workspace.package]\nversion = \"3.3.3\"\n",
				"m/Cargo.toml":  "[package]\nname = \"m\"\nworkspace = \"../ws\"\nversion.workspace = true\n",
			},
			dir: "m", path: filepath.Join("ws", "Cargo.toml"),
			field: "workspace.package.version, inherited by m/Cargo.toml", value: "3.3.3",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			root := tree(t, tt.files)

			site, err := manifest.MemberVersion(root, tt.dir)
			if err != nil {
				t.Fatalf("MemberVersion = %v", err)
			}

			if site.Path != tt.path || site.Field != tt.field || site.Value != tt.value {
				t.Fatalf("site = %s %s %q, want %s %s %q", site.Path, site.Field, site.Value, tt.path, tt.field, tt.value)
			}
		})
	}

	t.Run("an absolute directory inside the tree", func(t *testing.T) {
		t.Parallel()

		root := tree(t, map[string]string{"a/Cargo.toml": "[package]\nversion = \"0.1.0\"\n"})

		if site, err := manifest.MemberVersion(root, filepath.Join(root, "a")); err != nil || site.Value != "0.1.0" {
			t.Fatalf("MemberVersion = %+v, %v", site, err)
		}
	})
}

// TestMemberVersionRefusals: every guard branch, by message.
func TestMemberVersionRefusals(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		files   map[string]string
		dir     string
		arrange func(t *testing.T, root string)
		want    string
	}{
		{name: "outside the tree", dir: "../x", want: "../x is outside the tree"},
		{name: "no manifest", files: map[string]string{"a/README": ""}, dir: "a", want: "no Cargo.toml at a"},
		{
			name:  "a manifest that will not parse",
			files: map[string]string{"a/Cargo.toml": "[package\n"}, dir: "a",
			want: "manifest: parsing Cargo.toml",
		},
		{
			name:  "no version and no inheritance",
			files: map[string]string{"a/Cargo.toml": "[package]\nname = \"a\"\n"}, dir: "a",
			want: "a/Cargo.toml states neither package.version nor version.workspace = true",
		},
		{
			name:  "inheritance switched off is no inheritance",
			files: map[string]string{"a/Cargo.toml": "[package]\nversion.workspace = false\n"}, dir: "a",
			want: "states neither package.version nor version.workspace = true",
		},
		{
			name:  "no enclosing workspace in the tree",
			files: map[string]string{"a/Cargo.toml": inherits}, dir: "a",
			want: "a/Cargo.toml inherits its version: no enclosing Cargo.toml in the tree declares [workspace]",
		},
		{
			name: "a workspace root with no workspace.package.version",
			files: map[string]string{
				"Cargo.toml":   "[workspace]\nmembers = [\"a\"]\n",
				"a/Cargo.toml": inherits,
			},
			dir:  "a",
			want: "inherits its version, but its workspace root Cargo.toml carries no workspace.package.version",
		},
		{
			name: "a named workspace that is not there",
			files: map[string]string{
				"a/Cargo.toml": "[package]\nworkspace = \"../gone\"\nversion.workspace = true\n",
			},
			dir:  "a",
			want: "a/Cargo.toml inherits its version: open",
		},
		{
			name: "a workspace root that will not parse",
			files: map[string]string{
				"ws/Cargo.toml": "[workspace\n",
				"a/Cargo.toml":  "[package]\nworkspace = \"../ws\"\nversion.workspace = true\n",
			},
			dir:  "a",
			want: "a/Cargo.toml inherits its version: manifest: parsing Cargo.toml",
		},
		{
			name: "an enclosing manifest on the walk that will not parse",
			files: map[string]string{
				"x/Cargo.toml":   "[workspace\n",
				"x/a/Cargo.toml": inherits,
			},
			dir:  "x/a",
			want: "x/Cargo.toml: manifest: parsing Cargo.toml",
		},
		{
			name:  "a member manifest that cannot be read",
			files: map[string]string{"a/Cargo.toml": "[package]\nversion = \"1.0.0\"\n"}, dir: "a",
			arrange: func(t *testing.T, root string) {
				t.Helper()

				if err := os.Chmod(filepath.Join(root, "a", "Cargo.toml"), 0o000); err != nil {
					t.Fatal(err)
				}
			},
			want: "manifest: reading",
		},
		{
			name: "an enclosing manifest that cannot be read",
			files: map[string]string{
				"x/Cargo.toml":   "[workspace]\n",
				"x/a/Cargo.toml": inherits,
			},
			dir: "x/a",
			arrange: func(t *testing.T, root string) {
				t.Helper()

				if err := os.Chmod(filepath.Join(root, "x", "Cargo.toml"), 0o000); err != nil {
					t.Fatal(err)
				}
			},
			want: "inherits its version: reading",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			root := tree(t, tt.files)
			if tt.arrange != nil {
				tt.arrange(t, root)
			}

			_, err := manifest.MemberVersion(root, tt.dir)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("MemberVersion = %v, want it to name %q", err, tt.want)
			}
		})
	}
}
