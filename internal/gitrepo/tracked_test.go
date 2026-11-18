package gitrepo_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gitrepo"
	"github.com/monumental-archive/stele/internal/gittest"
)

// TestTrackedPaths: what the index tracks, at any depth, and nothing
// that is merely on disk.
func TestTrackedPaths(t *testing.T) {
	t.Parallel()

	src := gittest.New(t)
	src.File("Cargo.lock", "x", "root lock")
	src.File("crates/inner/Cargo.lock", "x", "nested lock")
	src.File("README.md", "x", "readme")

	// A build leftover: on disk, never committed.
	if err := os.WriteFile(filepath.Join(src.Dir, "go.mod"), []byte("module x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := gitrepo.OpenObjects(src.Dir)
	if err != nil {
		t.Fatal(err)
	}

	got, err := r.TrackedPaths("Cargo.lock", "*/Cargo.lock", "go.mod", "*/go.mod")
	if err != nil {
		t.Fatalf("TrackedPaths = %v", err)
	}

	if want := []string{"Cargo.lock", "crates/inner/Cargo.lock"}; !slices.Equal(got, want) {
		t.Errorf("TrackedPaths = %q, want %q", got, want)
	}

	none, err := r.TrackedPaths("package.json")
	if err != nil || len(none) != 0 {
		t.Errorf("TrackedPaths(untracked) = %q, %v; want none", none, err)
	}

	if _, err := r.TrackedPaths(); err == nil || !strings.Contains(err.Error(), "at least one pathspec") {
		t.Errorf("TrackedPaths() = %v, want the empty-pathspec refusal", err)
	}

	// git refusing the read: a pathspec it rejects outright.
	if _, err := r.TrackedPaths(":(bogus)x"); err == nil || !strings.Contains(err.Error(), "gitrepo: git ls-files") {
		t.Errorf("TrackedPaths(bad magic) = %v, want git's refusal named", err)
	}
}
