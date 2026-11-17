package gitfetch

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gitrepo"
)

// counting is a session over one world whose fetches are counted.
//
//nolint:gocritic // unnamedResult: the session, its fetch count, its log
func counting(t *testing.T, w *world, want Want) (*Session, *int, *[]string) {
	t.Helper()

	fetches := 0
	logged := []string{}

	s := &Session{
		Remote: func(owner, repo string) string {
			fetches++

			if owner != "acme" || repo != "widget" {
				return "file://" + filepath.Join(t.TempDir(), "nothing-here")
			}

			return w.src.URL()
		},
		Want: want,
		Log:  func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) },
	}
	t.Cleanup(func() { _ = s.Close() }) //nolint:errcheck // the test's own scratch

	return s, &fetches, &logged
}

// TestSessionFetchesEachRepositoryOnce: a walk reads one repository
// many times and fetches it once.
func TestSessionFetchesEachRepositoryOnce(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	s, fetches, _ := counting(t, &w, everything)

	refs, err := s.TagRefs("acme", "widget")
	if err != nil || len(refs) != 3 {
		t.Fatalf("TagRefs = %v, %v", refs, err)
	}

	for _, ref := range refs {
		if _, _, err := s.ResolveTag("acme", "widget", ref); err != nil {
			t.Fatalf("ResolveTag(%s) = %v", ref.Name, err)
		}
	}

	if got, err := s.TagCommit("acme", "widget", "v1.0.0"); err != nil || got != w.merge {
		t.Fatalf("TagCommit = %s, %v", got, err)
	}

	if notes, err := s.ChainNotes("acme", "widget", notesRef); err != nil || len(notes) != 2 {
		t.Fatalf("ChainNotes = %v, %v", notes, err)
	}

	if meta, err := s.CommitMeta("acme", "widget", w.merge); err != nil || len(meta.Parents) != 2 {
		t.Fatalf("CommitMeta = %+v, %v", meta, err)
	}

	if ok, err := s.IsAncestor("acme", "widget", w.root, w.tip); err != nil || !ok {
		t.Fatalf("IsAncestor = %v, %v", ok, err)
	}

	if *fetches != 1 {
		t.Fatalf("fetched %d times, want once", *fetches)
	}

	if s.IgnoredFilter("acme", "widget") || s.FilterIgnored() != 0 {
		t.Fatal("a remote that honoured the filter was counted as ignoring it")
	}

	dir := s.repos["acme/widget"].dir

	if err := s.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}

	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat(%s) = %v — the session left a repository behind", dir, err)
	}
}

// TestSessionRemembersAFailedFetch: a repository the run could not
// see is not fetched again on every read, and every read of it says
// so in the fetch's own words.
func TestSessionRemembersAFailedFetch(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	s, fetches, _ := counting(t, &w, everything)

	ref := gitrepo.TagRef{Name: "v1.0.0", ObjectSHA: w.signedSHA, Annotated: true}

	for name, read := range map[string]func() error{
		"TagRefs":    func() error { _, err := s.TagRefs("acme", "gone"); return err },
		"ResolveTag": func() error { _, _, err := s.ResolveTag("acme", "gone", ref); return err },
		"TagCommit":  func() error { _, err := s.TagCommit("acme", "gone", "v1.0.0"); return err },
		"ChainNotes": func() error { _, err := s.ChainNotes("acme", "gone", notesRef); return err },
		"CommitMeta": func() error { _, err := s.CommitMeta("acme", "gone", w.tip); return err },
		"IsAncestor": func() error { _, err := s.IsAncestor("acme", "gone", w.root, w.tip); return err },
	} {
		if err := read(); err == nil || !errors.Is(err, ErrFetch) {
			t.Errorf("%s = %v, want the failed fetch", name, err)
		}
	}

	if *fetches != 1 {
		t.Fatalf("fetched %d times, want once", *fetches)
	}
}

func TestSessionRefusals(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	_, err := (&Session{Want: everything}).Repo("acme", "widget")
	if err == nil ||
		!strings.Contains(err.Error(), "names no remote") {
		t.Fatalf("Repo without a remote = %v", err)
	}

	s, fetches, _ := counting(t, &w, everything)

	_, err = s.ChainNotes("acme", "widget", "refs/notes/other")
	if err == nil ||
		!strings.Contains(err.Error(), `asked for refs/notes/other, but this session fetched "refs/notes/commits"`) {
		t.Fatalf("ChainNotes(other ref) = %v", err)
	}

	if *fetches != 0 {
		t.Fatal("a refused read fetched anyway")
	}

	if err := (&Session{Fetcher: &Fetcher{Git: filepath.Join(t.TempDir(), "no-git")}}).Check(); !errors.Is(err, ErrGit) {
		t.Fatalf("Check = %v, want the git refusal", err)
	}

	if err := (&Session{}).Check(); err != nil {
		t.Fatalf("Check = %v on a machine whose git runs this suite", err)
	}
}

// TestSessionCountsAndSaysAnIgnoredFilter: an ignored filter is
// repeated in the walk's own output and counted for its report.
func TestSessionCountsAndSaysAnIgnoredFilter(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.src.Git("config", "uploadpack.allowFilter", "false")

	s, _, logged := counting(t, &w, everything)

	if _, err := s.Repo("acme", "widget"); err != nil {
		t.Fatalf("Repo = %v", err)
	}

	if !s.IgnoredFilter("acme", "widget") || s.IgnoredFilter("acme", "elsewhere") {
		t.Fatal("IgnoredFilter must answer for the fetched repository, and false for one never fetched")
	}

	const said = "gitfetch: acme/widget ignored the commits-only filter — the walk is still correct," +
		" the download was larger"

	if s.FilterIgnored() != 1 || len(*logged) != 2 ||
		!strings.HasPrefix((*logged)[0], "gitfetch: acme/widget fetched in ") || (*logged)[1] != said {
		t.Fatalf("FilterIgnored = %d, logged %q", s.FilterIgnored(), *logged)
	}
}

func TestGitHubRemote(t *testing.T) {
	t.Parallel()

	if got := GitHubRemote("https://github.com")("acme", "widget"); got != "https://github.com/acme/widget.git" {
		t.Fatalf("GitHubRemote = %s", got)
	}
}
