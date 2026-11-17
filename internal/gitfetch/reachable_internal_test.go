package gitfetch

import (
	"errors"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gittest"
)

// TestReachableAnswersFromEveryBranchAndTag (stele#408): over a fetch of
// every branch and every tag at full depth, a commit the fetch holds is
// reachable, and a commit whose only branch was deleted is the typed
// false — never an error, never fetched.
func TestReachableAnswersFromEveryBranchAndTag(t *testing.T) {
	t.Parallel()

	r := gittest.New(t)
	held := r.Commit("feat: on main")
	r.Git("checkout", "-q", "-b", "gone")
	deleted := r.Commit("feat: on a branch about to be deleted")
	r.Git("checkout", "-q", "main")
	tagged := r.Commit("feat: tagged")
	r.Annotated("v1.0.0", tagged, "release-mint[bot]", true)
	r.Git("branch", "-D", "gone")

	s := &Session{
		Remote: func(_, _ string) string { return r.URL() },
		Want:   Want{Heads: true, Tags: true, NotesRef: notesRef},
	}
	t.Cleanup(func() { _ = s.Close() }) //nolint:errcheck // the test's own scratch

	for _, tc := range []struct {
		name, rev string
		want      bool
	}{
		{name: "a branch commit", rev: held, want: true},
		{name: "a tagged commit", rev: tagged, want: true},
		{name: "a commit no branch or tag reaches", rev: deleted, want: false},
	} {
		got, err := s.Reachable("acme", "widget", tc.rev)
		if err != nil || got != tc.want {
			t.Fatalf("%s: Reachable = %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}

	// An id that is not a full object id is git's presence read
	// refusing, by name — never a false.
	if _, err := s.Reachable("acme", "widget", deleted[:12]); err == nil ||
		!strings.Contains(err.Error(), "is not a full hex object id") {
		t.Fatalf("Reachable(short id) = %v, want the presence read's refusal", err)
	}
}

// TestReachableRefusesANarrowerFetch: false is an answer only from every
// branch and every tag at full depth; a session that fetched less
// refuses by name rather than turn "not fetched" into "not reachable".
func TestReachableRefusesANarrowerFetch(t *testing.T) {
	t.Parallel()

	const want = "gitfetch: whether a commit is reachable from a branch or a tag is answered only from every" +
		" branch and every tag fetched at full depth (Want.Heads and Want.Tags, not Shallow) — a commit a" +
		" narrower fetch did not bring down may still be reachable"

	for _, tc := range []struct {
		name string
		want Want
	}{
		{name: "named branches only", want: Want{Branches: []string{"refs/heads/main"}, Tags: true}},
		{name: "no tags", want: Want{Heads: true}},
		{name: "tags at depth one", want: Want{Heads: true, Tags: true, Shallow: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := &Session{Remote: func(_, _ string) string { return "file:///nowhere" }, Want: tc.want}

			_, err := s.Reachable("acme", "widget", strings.Repeat("a", 40))
			if err == nil || err.Error() != want {
				t.Fatalf("Reachable = %v, want %q", err, want)
			}
		})
	}
}

// TestReachableCarriesAFailedFetch: a repository the walk could not
// fetch is the fetch's own refusal, never an unreachable commit.
func TestReachableCarriesAFailedFetch(t *testing.T) {
	t.Parallel()

	s := &Session{
		Remote: func(_, _ string) string { return "file:///nowhere/at/all.git" },
		Want:   Want{Heads: true, Tags: true},
	}

	if _, err := s.Reachable("acme", "widget", strings.Repeat("a", 40)); !errors.Is(err, ErrFetch) {
		t.Fatalf("Reachable = %v, want the failed fetch", err)
	}
}
