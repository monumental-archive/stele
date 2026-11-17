package gitfetch

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gittest"
)

// TestOnBranch: whether a commit is on a branch, from every branch
// fetched at full depth — a commit on the branch, one held off it, one
// whose branch was deleted after the push (held by no branch, and so
// on none), one that never existed, and every refusal by name.
func TestOnBranch(t *testing.T) {
	t.Parallel()

	src := gittest.New(t)
	root := src.Commit("feat: the root")
	tip := src.Commit("feat: the tip of main")
	src.Git("checkout", "-q", "-b", "side")
	side := src.Commit("feat: on another branch")
	src.Git("checkout", "-q", "-b", "gone")
	gone := src.Commit("feat: on a branch deleted after the push")
	src.Git("checkout", "-q", "main")
	src.Git("branch", "-q", "-D", "gone")

	_, tagSHA := src.Annotated("v1.0.0", tip, "release-mint[bot]", false)

	session := func(t *testing.T, want Want) *Session {
		t.Helper()

		s := &Session{
			Remote: func(owner, repo string) string {
				if owner == "acme" && repo == "signer" {
					return src.URL()
				}

				return "file://" + filepath.Join(t.TempDir(), "nothing-here")
			},
			Want: want,
		}
		t.Cleanup(func() { _ = s.Close() }) //nolint:errcheck // the test's own scratch

		return s
	}

	whole := Want{Heads: true}

	cases := []struct {
		name   string
		want   Want
		repo   string
		commit string
		branch string
		on     bool
		err    string
		is     error
	}{
		{name: "the branch tip", want: whole, commit: tip, on: true},
		{name: "an ancestor of the tip", want: whole, commit: root, on: true},
		{name: "a commit held on another branch", want: whole, commit: side},
		{name: "a commit whose branch was deleted after the push", want: whole, commit: gone},
		{name: "a full-length id no branch ever held", want: whole, commit: "0123456789abcdef0123456789abcdef01234567"},
		{
			name: "every branch and the tags too", want: Want{Heads: true, Tags: true}, commit: gone,
		},
		{
			name: "a tag object, which is not a commit", want: Want{Heads: true, Tags: true}, commit: tagSHA,
			err: "gitrepo: " + tagSHA + " is a tag, not a commit",
		},
		{
			name: "a name, not an id", want: whole, commit: "main",
			err: `gitrepo: "main" is not a full hex object id`,
		},
		{
			name: "a repository the fetch cannot reach", want: whole, repo: "elsewhere", commit: tip,
			err: "gitfetch:", is: ErrFetch,
		},
		{
			name: "a branch the history does not have", want: whole, commit: tip, branch: "refs/heads/never",
			err: "gitrepo: ancestry of " + tip + " in refs/heads/never",
		},
		{
			name: "a ref that is not a branch", want: whole, commit: tip, branch: "refs/tags/v1.0.0",
			err: `gitfetch: "refs/tags/v1.0.0" is not a fully qualified branch`,
		},
		{
			name: "a session that fetched named branches alone", want: Want{Branches: []string{"refs/heads/main"}},
			commit: gone, is: errNotWholeHistory,
			err: "answered only from every branch fetched at full depth (Want.Heads, not Shallow)",
		},
		{
			name: "a shallow session", want: Want{Heads: true, Shallow: true}, commit: gone, is: errNotWholeHistory,
			err: "a commit a narrower fetch did not bring down may still be on one",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			repo, branch := tc.repo, tc.branch
			if repo == "" {
				repo = "signer"
			}

			if branch == "" {
				branch = "refs/heads/main"
			}

			on, err := session(t, tc.want).OnBranch("acme", repo, tc.commit, branch)

			switch {
			case tc.err == "" && err != nil:
				t.Fatalf("err = %v", err)
			case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
				t.Fatalf("err = %v, want it to say %q", err, tc.err)
			case tc.is != nil && !errors.Is(err, tc.is):
				t.Fatalf("err = %v, want it to be %v", err, tc.is)
			}

			if on != tc.on {
				t.Fatalf("OnBranch(%s, %s) = %v, want %v", tc.commit, branch, on, tc.on)
			}
		})
	}
}
