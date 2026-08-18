// The mirror set refusing rather than rewriting. Every guard here
// protects the same property: what lands on the filesystem re-reads to
// exactly the sites and values the rewrite claimed. A mirror written
// wrong is a released version that disagrees with itself, discovered by
// whoever installs it.

package manifest_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/manifest"
)

// TestArrayTablesCarryNoVersionSites: [[bin]] and friends are members
// of an array table, not of the table around them, so a `version` key
// inside one must not be mistaken for the package's own mirror.
func TestArrayTablesCarryNoVersionSites(t *testing.T) {
	t.Parallel()

	dir := write(t, map[string]string{
		"Cargo.toml": `[package]
name = "demo"
version = "0.9.0"

[[bin]]
name = "demo"
path = "src/main.rs"

[[test]]
name = "integration"
`,
	})

	set, err := manifest.Detect(dir)
	if err != nil {
		t.Fatalf("Detect = %v", err)
	}

	if len(set.Sites) != 1 || set.Sites[0].Field != "package.version" {
		t.Fatalf("sites = %+v, want the package version alone", set.Sites)
	}
}

// TestDetectRefusesAnUnreadableManifest: a manifest in the tree that
// cannot be read is not an absent manifest — that is exactly how a
// mirror escapes the rewrite and drifts.
func TestDetectRefusesAnUnreadableManifest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "Cargo.toml"), 0o750); err != nil {
		t.Fatal(err)
	}

	if _, err := manifest.Detect(dir); err == nil || !strings.Contains(err.Error(), "reading Cargo.toml") {
		t.Fatalf("Detect = %v, want the read refusal", err)
	}
}

// TestCitationThatIsNotYAML: the citation reader parses before it looks
// for fields, so bytes that are not YAML refuse by name rather than as
// a missing convention.
func TestCitationThatIsNotYAML(t *testing.T) {
	t.Parallel()

	dir := write(t, map[string]string{"CITATION.cff": "title: [unclosed\n"})

	if _, err := manifest.Detect(dir); err == nil || !strings.Contains(err.Error(), "parsing CITATION.cff") {
		t.Fatalf("Detect = %v, want the parse refusal", err)
	}
}

// TestRewriteRefusesAValueItCannotReadBack is the read-back guard doing
// its job: a replacement that would restructure the file rather than
// sit in the slot measured for it is refused, and NOTHING is written.
func TestRewriteRefusesAValueItCannotReadBack(t *testing.T) {
	t.Parallel()

	t.Run("a version that escapes its own slot", func(t *testing.T) {
		t.Parallel()

		dir := write(t, map[string]string{"Cargo.toml": "[package]\nname = \"demo\"\nversion = \"0.9.0\"\n"})
		before := read(t, filepath.Join(dir, "Cargo.toml"))

		set, err := manifest.Detect(dir)
		if err != nil {
			t.Fatalf("Detect = %v", err)
		}

		if _, err := set.Rewrite("1.0.0\"\nname = \"other", "2026-01-01"); err == nil ||
			!strings.Contains(err.Error(), "reads back") {
			t.Fatalf("Rewrite = %v, want the read-back refusal", err)
		}

		if after := read(t, filepath.Join(dir, "Cargo.toml")); after != before {
			t.Fatalf("the file changed despite the refusal:\n%s", after)
		}
	})

	t.Run("a date that escapes its own slot", func(t *testing.T) {
		t.Parallel()

		dir := write(t, map[string]string{"CITATION.cff": citationCff})
		before := read(t, filepath.Join(dir, "CITATION.cff"))

		set, err := manifest.Detect(dir)
		if err != nil {
			t.Fatalf("Detect = %v", err)
		}

		if _, err := set.Rewrite("1.0.0", "2026-01-01 # and a comment"); err == nil ||
			!strings.Contains(err.Error(), "date-released reads back") {
			t.Fatalf("Rewrite = %v, want the date read-back refusal", err)
		}

		if after := read(t, filepath.Join(dir, "CITATION.cff")); after != before {
			t.Fatalf("the file changed despite the refusal:\n%s", after)
		}
	})
}

// TestRewriteRefusesAVanishedTree: the bytes are prepared in memory and
// written last, so a tree that disappeared between the read and the
// write refuses by path — a partially rewritten mirror set is the one
// state worse than none.
func TestRewriteRefusesAVanishedTree(t *testing.T) {
	t.Parallel()

	dir := write(t, map[string]string{"Cargo.toml": "[package]\nname = \"demo\"\nversion = \"0.9.0\"\n"})

	set, err := manifest.Detect(dir)
	if err != nil {
		t.Fatalf("Detect = %v", err)
	}

	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	if _, err := set.Rewrite("1.0.0", "2026-01-01"); err == nil ||
		!strings.Contains(err.Error(), "writing Cargo.toml") {
		t.Fatalf("Rewrite = %v, want the write refusal", err)
	}
}

// TestRewriteInTheWorkingDirectory: a set detected with no root writes
// the paths it read, in place — the shape a caller gets by naming the
// directory it already stands in.
func TestRewriteInTheWorkingDirectory(t *testing.T) {
	dir := write(t, map[string]string{"Cargo.toml": "[package]\nname = \"demo\"\nversion = \"0.9.0\"\n"})
	t.Chdir(dir)

	set, err := manifest.Detect("")
	if err != nil {
		t.Fatalf("Detect = %v", err)
	}

	files, err := set.Rewrite("1.0.0", "2026-01-01")
	if err != nil {
		t.Fatalf("Rewrite = %v", err)
	}

	if len(files) != 1 || files[0] != "Cargo.toml" {
		t.Fatalf("files = %v, want the relative path", files)
	}

	if got := read(t, filepath.Join(dir, "Cargo.toml")); !strings.Contains(got, `version = "1.0.0"`) {
		t.Fatalf("Cargo.toml = %q, want the rewritten version", got)
	}
}

// read is one file's contents, for before/after comparisons.
func read(t *testing.T, path string) string {
	t.Helper()

	b, err := os.ReadFile(path) //nolint:gosec // a path this test just wrote
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}
