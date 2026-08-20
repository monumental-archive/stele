// The revision walk that feeds the source track.
//
// Two properties carry this file, and they pull in opposite
// directions. The walk is FIRST-PARENT, because a branch's own line of
// development is what a level is claimed about — a side branch's
// commits landed through the merge, not on the branch. But the parent
// COUNT is read from the full parent list, because a merge has to be
// visible AS a merge: two-party review and history requirements are
// judged per revision, and a first-parent walk that also reported one
// parent per commit would hide the one property an evaluator is
// looking for.

package gitrepo_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gitrepo"
)

// gitAt runs git in dir with a fixed identity and a caller-chosen
// commit instant, so the `since` cutoff is asserted against dates the
// test set rather than against the clock it ran on.
func gitAt(t *testing.T, dir string) func(when string, args ...string) string {
	t.Helper()

	return func(when string, args ...string) string {
		t.Helper()

		cmd := exec.Command("git", //nolint:gosec,noctx // fixed executable, test-owned args
			append([]string{"-C", dir}, args...)...)
		cmd.Env = gitrepo.Env(
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
			"GIT_AUTHOR_DATE="+when, "GIT_COMMITTER_DATE="+when,
		)

		var out bytes.Buffer

		cmd.Stdout = &out
		cmd.Stderr = &out

		if err := cmd.Run(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out.String())
		}

		return strings.TrimSpace(out.String())
	}
}

// mergedRepo is a branch that took work through a merge: a root
// commit, a side branch off it, one more commit on the line, the merge
// itself, and a commit after. First-parent from the tip therefore
// reaches everything EXCEPT the side commit.
func mergedRepo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	git := gitAt(t, dir)

	git("", "init", "-q", "-b", "main")
	git("", "config", "user.name", "t")
	git("", "config", "user.email", "t@example.com")

	commit := func(when, name, message string) {
		t.Helper()

		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}

		git(when, "add", name)
		git(when, "commit", "-q", "-m", message)
	}

	commit("2026-01-01T00:00:00+00:00", "a", "feat: the root")

	git("", "checkout", "-q", "-b", "side")
	commit("2026-01-02T00:00:00+00:00", "s", "feat: on the side")

	git("", "checkout", "-q", "main")
	commit("2026-01-03T00:00:00+00:00", "b", "feat: on the line")

	git("2026-01-04T00:00:00+00:00", "merge", "-q", "--no-ff", "-m", "merge: take the side branch", "side")

	commit("2026-01-05T00:00:00+00:00", "c", "docs: after the merge")

	return dir
}

func subjects(revs []gitrepo.Revision) []string {
	out := make([]string, 0, len(revs))
	for _, r := range revs {
		out = append(out, r.Subject)
	}

	return out
}

func TestRevisionsWalksTheBranchesOwnLine(t *testing.T) {
	t.Parallel()

	dir := mergedRepo(t)

	got, err := openHistory(t, dir).Revisions("HEAD", time.Time{})
	if err != nil {
		t.Fatalf("Revisions = %v", err)
	}

	// Newest first, and the side commit is absent: it reached the
	// branch through the merge, and the merge is the revision this
	// branch is judged on.
	want := []string{
		"docs: after the merge",
		"merge: take the side branch",
		"feat: on the line",
		"feat: the root",
	}
	if strings.Join(subjects(got), "|") != strings.Join(want, "|") {
		t.Fatalf("Revisions = %v, want %v", subjects(got), want)
	}

	if strings.Contains(strings.Join(subjects(got), "|"), "on the side") {
		t.Error("a side branch's own commit appeared on the branch's line")
	}
}

// TestRevisionsCountsEveryParent is the half the first-parent walk
// must not swallow. The merge is reached BY the first-parent walk and
// still reports two parents; asking git for one parent per commit
// would have hidden it.
func TestRevisionsCountsEveryParent(t *testing.T) {
	t.Parallel()

	dir := mergedRepo(t)

	got, err := openHistory(t, dir).Revisions("HEAD", time.Time{})
	if err != nil {
		t.Fatalf("Revisions = %v", err)
	}

	parents := map[string]int{}
	for _, r := range got {
		parents[r.Subject] = r.Parents
	}

	for subject, want := range map[string]int{
		"merge: take the side branch": 2,
		"docs: after the merge":       1,
		"feat: the root":              0,
	} {
		if parents[subject] != want {
			t.Errorf("%q has %d parent(s), want %d", subject, parents[subject], want)
		}
	}

	// Every revision is identified by its own digest and carries the
	// time the walk cut on.
	for _, r := range got {
		if len(r.ID) != 40 || r.Time.IsZero() {
			t.Errorf("revision %+v is not fully read", r)
		}
	}
}

// TestRevisionsStopsAtTheCutoff: the walk is bounded by a horizon, and
// it stops at the first revision older than it rather than filtering —
// history runs newest first, so everything past that point is older
// too, and continuing would read a whole repository to discard it.
func TestRevisionsStopsAtTheCutoff(t *testing.T) {
	t.Parallel()

	dir := mergedRepo(t)
	r := openHistory(t, dir)

	for _, tt := range []struct {
		name  string
		since string
		want  int
	}{
		{"a horizon before everything keeps the whole line", "2025-12-31T00:00:00Z", 4},
		{"a horizon mid-history cuts the older revisions", "2026-01-03T00:00:00Z", 3},
		{"a horizon at the tip keeps the tip alone", "2026-01-05T00:00:00Z", 1},
		{"a horizon after everything keeps nothing", "2026-02-01T00:00:00Z", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			since, perr := time.Parse(time.RFC3339, tt.since)
			if perr != nil {
				t.Fatal(perr)
			}

			got, err := r.Revisions("HEAD", since)
			if err != nil {
				t.Fatalf("Revisions = %v", err)
			}

			if len(got) != tt.want {
				t.Fatalf("Revisions = %v, want %d revision(s)", subjects(got), tt.want)
			}
		})
	}
}

// TestRevisionsRefusesAnUnreadableCommitTime. A commit's date is
// whatever was written into the object, and git will render one
// outside the representable range without complaint — here a
// five-digit year, which is not RFC 3339.
//
// Refusing is the only safe answer. A time that failed to parse would
// otherwise land as the zero time, which sorts before every horizon: a
// revision would silently survive a cutoff meant to exclude it, and
// the contemporaneity a source level rests on would be measured
// against a date nobody wrote.
func TestRevisionsRefusesAnUnreadableCommitTime(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	git := gitAt(t, dir)

	git("", "init", "-q", "-b", "main")
	git("", "config", "user.name", "t")
	git("", "config", "user.email", "t@example.com")

	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}

	git("2026-01-01T00:00:00+00:00", "add", "a")
	git("2026-01-01T00:00:00+00:00", "commit", "-q", "-m", "feat: the root")

	// Hand-built so the timestamp bypasses git's own date parsing —
	// which is exactly how such an object reaches a repository.
	tree := git("", "rev-parse", "HEAD^{tree}")
	object := filepath.Join(dir, "farfuture")
	body := "tree " + tree + "\n" +
		"author t <t@example.com> 999999999999 +0000\n" +
		"committer t <t@example.com> 999999999999 +0000\n\nfeat: beyond the calendar\n"

	if err := os.WriteFile(object, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	rev := git("", "hash-object", "-w", "-t", "commit", "--literally", object)
	git("", "update-ref", "refs/heads/main", rev)

	_, err := openHistory(t, dir).Revisions("refs/heads/main", time.Time{})
	if err == nil || !strings.Contains(err.Error(), "commit time") {
		t.Fatalf("Revisions = %v, want a refusal naming the commit time it could not read", err)
	}
}

// TestRevisionsRefusesAShallowClone: the same trap the other two
// history reads refuse. A shallow clone answers with a truncated past
// and nothing about the answer looks wrong — here it would report a
// branch founded at the fetch depth, which is a history requirement
// judged against a history that was never there.
func TestRevisionsRefusesAShallowClone(t *testing.T) {
	t.Parallel()

	dir := mergedRepo(t)

	shallowDir := t.TempDir()
	gitIn(t, shallowDir)("clone", "-q", "--depth", "1", "file://"+dir, ".")

	shallow := openHistory(t, shallowDir)

	got, err := shallow.Revisions("HEAD", time.Time{})
	if err == nil {
		t.Fatalf("Revisions = %v on a shallow clone, want a refusal", subjects(got))
	}

	var shallowErr *gitrepo.ShallowError
	if !errors.As(err, &shallowErr) {
		t.Errorf("Revisions error = %v, want a ShallowError", err)
	}

	// AllTags is the third read through the same guard, and the one the
	// version derivation depends on: a shallow clone has no tags, which
	// reads as a repository that has never released.
	if _, terr := shallow.AllTags(); !errors.As(terr, &shallowErr) {
		t.Errorf("AllTags error = %v, want a ShallowError", terr)
	}
}
