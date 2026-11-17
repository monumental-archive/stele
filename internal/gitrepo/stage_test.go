package gitrepo_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gitrepo"
	"github.com/monumental-archive/stele/internal/gittest"
)

// notesRefs lists every ref under refs/notes/, the place a staged
// ledger lives and must not outlive its release.
func notesRefs(r *gittest.Repo) string {
	return r.Git("for-each-ref", "--format=%(refname) %(objectname)", "refs/notes/")
}

// TestStageNotes: notes written while staged land under a scratch ref
// git stores exactly as the ledger would, the ledger never moves, and
// release leaves no scratch ref behind — with a ledger and without one
// (the chain not yet founded).
func TestStageNotes(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name   string
		ledger bool
	}{
		{"an existing ledger is seeded, never moved", true},
		{"an absent ledger stays absent", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stageOnce(t, tt.ledger)
		})
	}
}

// stageOnce stages a repository's ledger (or its absence), writes a
// note while staged, and proves the ledger never moved.
func stageOnce(t *testing.T, withLedger bool) {
	t.Helper()

	g := gittest.New(t)
	root := g.Commit("one")
	tip := g.Commit("two")

	if withLedger {
		g.Note(notesRef, root, []byte("founding"))
	}

	before := notesRefs(g)

	r, err := gitrepo.Open(g.Dir, notesRef)
	if err != nil {
		t.Fatal(err)
	}

	release, err := r.StageNotes()
	if err != nil {
		t.Fatalf("StageNotes = %v", err)
	}

	if aerr := r.AddNote(tip, []byte("staged")); aerr != nil {
		t.Fatal(aerr)
	}

	if staged, nerr := r.Note(tip); nerr != nil || string(staged) != "staged\n" {
		t.Fatalf("staged note = %q, %v; want git's stored bytes", staged, nerr)
	}

	if withLedger {
		if seeded, nerr := r.Note(root); nerr != nil || string(seeded) != "founding\n" {
			t.Fatalf("the staged ledger does not carry the ledger's notes: %q, %v", seeded, nerr)
		}
	}

	if got := notesRefs(g); !strings.Contains(got, "stele-staging-") {
		t.Fatalf("no scratch ref while staged: %q", got)
	}

	if rerr := release(); rerr != nil {
		t.Fatalf("release = %v", rerr)
	}

	if after := notesRefs(g); after != before {
		t.Fatalf("refs/notes/ moved: before %q, after %q", before, after)
	}

	if note, nerr := r.Note(tip); nerr != nil || note != nil {
		t.Fatalf("after release the repository reads the ledger again; got %q, %v", note, nerr)
	}
}

// TestStageNotesRefusals: every guard branch — no ledger to stage, a
// scratch ref git cannot create, a scratch ref git cannot delete.
func TestStageNotesRefusals(t *testing.T) {
	t.Parallel()

	t.Run("no notes ref", func(t *testing.T) {
		t.Parallel()

		g := gittest.New(t)
		g.Commit("one")

		r, err := gitrepo.OpenObjects(g.Dir)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := r.StageNotes(); err == nil || !strings.Contains(err.Error(), "no notes ref") {
			t.Fatalf("StageNotes = %v, want the no-ledger refusal", err)
		}
	})

	t.Run("seeding the scratch ref fails", func(t *testing.T) {
		t.Parallel()

		g := gittest.New(t)
		g.Note(notesRef, g.Commit("one"), []byte("founding"))
		g.Git("pack-refs", "--all")
		lockDir(t, filepath.Join(g.Dir, ".git", "refs", "notes"))

		r, err := gitrepo.Open(g.Dir, notesRef)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := r.StageNotes(); err == nil || !strings.Contains(err.Error(), "seeding refs/notes/stele-staging-") {
			t.Fatalf("StageNotes = %v, want the seeding refusal", err)
		}
	})

	t.Run("deleting the scratch ref fails", func(t *testing.T) {
		t.Parallel()

		g := gittest.New(t)
		g.Note(notesRef, g.Commit("one"), []byte("founding"))

		r, err := gitrepo.Open(g.Dir, notesRef)
		if err != nil {
			t.Fatal(err)
		}

		release, err := r.StageNotes()
		if err != nil {
			t.Fatal(err)
		}

		lockDir(t, filepath.Join(g.Dir, ".git", "refs", "notes"))

		if err := release(); err == nil || !strings.Contains(err.Error(), "deleting refs/notes/stele-staging-") {
			t.Fatalf("release = %v, want the deletion refusal", err)
		}
	})
}

// lockDir makes dir read-only for the rest of the test, so git cannot
// take a ref lock in it, and restores it for cleanup.
func lockDir(t *testing.T, dir string) {
	t.Helper()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // G302: a test directory made read-only on purpose
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700) //nolint:gosec,errcheck // G302: restoring the test directory; best-effort cleanup
	})
}
