package gitrepo_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gitrepo"
)

// history builds a repository with a release history: three commits,
// two of them tagged, in more than one tag namespace — the monorepo
// shape measured in the corpus, where "the latest tag" is meaningless
// without naming which component is being released.
type history struct {
	dir             string
	first, mid, tip string
}

func historyRepo(t *testing.T) history {
	t.Helper()

	dir := t.TempDir()
	git := gitIn(t, dir)

	git("init", "-q", "-b", "main")
	git("config", "user.name", "t")
	git("config", "user.email", "t@example.com")

	commit := func(name, message string) string {
		t.Helper()

		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}

		git("add", name)
		git("commit", "-q", "-m", message)

		return git("rev-parse", "HEAD")
	}

	first := commit("a", "feat: the first thing")
	git("tag", "v0.1.0")
	git("tag", "core-v0.9.0")

	mid := commit("b", "fix: repair the thing\n\nBREAKING CHANGE: the old flag is gone")
	git("tag", "v0.2.0")

	tip := commit("c", "docs: explain it")

	return history{dir: dir, first: first, mid: mid, tip: tip}
}

func gitIn(t *testing.T, dir string) func(args ...string) string {
	t.Helper()

	return func(args ...string) string {
		t.Helper()

		cmd := exec.Command("git", //nolint:gosec,noctx // fixed executable, test-owned args
			append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_CONFIG_SYSTEM=/dev/null",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
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

func openHistory(t *testing.T, dir string) *gitrepo.Repo {
	t.Helper()

	r, err := gitrepo.Open(dir, "refs/notes/commits")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	return r
}

func TestTags(t *testing.T) {
	h := historyRepo(t)

	got, err := openHistory(t, h.dir).Tags()
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}

	want := map[string]bool{"v0.1.0": true, "v0.2.0": true, "core-v0.9.0": true}
	if len(got) != len(want) {
		t.Fatalf("Tags() = %v, want %d tags", got, len(want))
	}

	for _, tag := range got {
		if !want[tag] {
			t.Errorf("Tags() returned %q, which was never created", tag)
		}

		// Unqualified: selecting a namespace by prefix would break if
		// every tag arrived as "refs/tags/…".
		if strings.HasPrefix(tag, "refs/") {
			t.Errorf("Tags() returned %q, want an unqualified tag name", tag)
		}
	}
}

// A project that has never released is a fact, not a failure — and it
// is the base case for a first release.
func TestTagsWhenNothingIsReleased(t *testing.T) {
	dir := t.TempDir()
	git := gitIn(t, dir)
	git("init", "-q", "-b", "main")
	git("config", "user.name", "t")
	git("config", "user.email", "t@example.com")
	git("commit", "-q", "--allow-empty", "-m", "feat: the first thing")

	got, err := openHistory(t, dir).Tags()
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}

	if len(got) != 0 {
		t.Errorf("Tags() = %v, want none", got)
	}
}

// The guard that matters most in practice: a shallow clone answers "no
// tags, one commit" for a repository with a full release history, and
// nothing about that answer looks wrong. Both history reads must refuse
// it rather than derive a version from a truncated past.
func TestShallowCloneIsRefused(t *testing.T) {
	h := historyRepo(t)

	shallowDir := t.TempDir()
	gitIn(t, shallowDir)("clone", "-q", "--depth", "1", "file://"+h.dir, ".")

	shallow := openHistory(t, shallowDir)

	t.Run("Tags", func(t *testing.T) {
		got, err := shallow.Tags()
		if err == nil {
			t.Fatalf("Tags() = %v on a shallow clone, want a refusal", got)
		}

		var shallowErr *gitrepo.ShallowError
		if !errors.As(err, &shallowErr) {
			t.Errorf("Tags() error = %v, want an ShallowError", err)
		}

		if !strings.Contains(err.Error(), "fetch-depth") {
			t.Errorf("Tags() error = %q, want it to name the remedy", err)
		}
	})

	t.Run("Commits", func(t *testing.T) {
		got, err := shallow.Commits("", "HEAD")
		if err == nil {
			t.Fatalf("Commits() = %v on a shallow clone, want a refusal", got)
		}

		var shallowErr *gitrepo.ShallowError
		if !errors.As(err, &shallowErr) {
			t.Errorf("Commits() error = %v, want an ShallowError", err)
		}
	})
}

func TestMessage(t *testing.T) {
	h := historyRepo(t)
	r := openHistory(t, h.dir)

	// %B, not %s: the footer lives in the body, and it is one of the two
	// ways Conventional Commits declares a break.
	got, err := r.Message(h.mid)
	if err != nil {
		t.Fatalf("Message: %v", err)
	}

	const want = "fix: repair the thing\n\nBREAKING CHANGE: the old flag is gone"
	if got != want {
		t.Errorf("Message() = %q, want %q", got, want)
	}

	if _, err := r.Message("0000000000000000000000000000000000000000"); err == nil {
		t.Error("Message() of an absent revision returned no error")
	}
}

func TestCommits(t *testing.T) {
	h := historyRepo(t)
	r := openHistory(t, h.dir)

	for _, tc := range []struct {
		name string
		from string
		want []string
	}{
		{name: "since the last release", from: "v0.2.0", want: []string{h.tip}},
		{name: "since an earlier release", from: "v0.1.0", want: []string{h.mid, h.tip}},
		// The first release of a project that has never tagged.
		{name: "the whole history", from: "", want: []string{h.first, h.mid, h.tip}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := r.Commits(tc.from, "HEAD")
			if err != nil {
				t.Fatalf("Commits(%q): %v", tc.from, err)
			}

			if len(got) != len(tc.want) {
				t.Fatalf("Commits(%q) = %v, want %v", tc.from, got, tc.want)
			}

			// Oldest first: a changelog reads in the order things
			// happened, and a reversed range would render backwards.
			for i, want := range tc.want {
				if got[i] != want {
					t.Errorf("Commits(%q)[%d] = %s, want %s", tc.from, i, got[i], want)
				}
			}
		})
	}

	t.Run("nothing since the tip", func(t *testing.T) {
		got, err := r.Commits("HEAD", "HEAD")
		if err != nil {
			t.Fatalf("Commits: %v", err)
		}

		if len(got) != 0 {
			t.Errorf("Commits() = %v, want none", got)
		}
	})

	t.Run("an unknown revision is an error", func(t *testing.T) {
		if _, err := r.Commits("", "no-such-ref"); err == nil {
			t.Error("Commits() over an unknown revision returned no error")
		}
	})
}
