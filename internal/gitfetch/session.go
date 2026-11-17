package gitfetch

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/monumental-archive/stele/internal/gitrepo"
)

// Session serves one walk's git reads over many repositories: each is
// fetched once, on the walk's first read of it, and every fetched
// repository is removed when the walk ends (Close). A fetch that
// failed is remembered for the walk, so a repository the run could
// not see is not fetched again on every read of it.
//
// It answers in the vocabulary the walks already judge through — tag
// refs, tag objects, the ledger, commit facts, ancestry — so the walks
// are unchanged by where the bytes come from.
type Session struct {
	// Fetcher runs the fetches; nil means the git on PATH.
	Fetcher *Fetcher
	// Remote names one repository's fetch URL.
	Remote func(owner, repo string) string
	// Token authenticates the fetch; "" for public repositories.
	Token string
	// Want is what every repository is fetched for.
	Want Want
	// Log reports what the fetch saw that the walk should repeat.
	Log func(format string, args ...any)

	mu      sync.Mutex
	repos   map[string]*Fetched
	failed  map[string]error
	ignored int
}

// GitHubRemote names a repository's fetch URL on a forge server, by
// the forge's own convention.
func GitHubRemote(server string) func(owner, repo string) string {
	return func(owner, repo string) string {
		return server + "/" + owner + "/" + repo + ".git"
	}
}

// Check refuses a machine whose git cannot do this job, before a walk
// starts rather than at its first read.
func (s *Session) Check() error {
	return s.fetcher().Check()
}

// Repo is one repository's fetched history, fetched on first use.
func (s *Session) Repo(owner, repo string) (*gitrepo.Repo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := owner + "/" + repo

	if f, ok := s.repos[key]; ok {
		return f.Repo, nil
	}

	if err, ok := s.failed[key]; ok {
		return nil, err
	}

	if s.Remote == nil {
		return nil, errors.New("gitfetch: the session names no remote")
	}

	start := time.Now()

	f, err := s.fetcher().Fetch(s.Remote(owner, repo), s.Token, s.Want)
	if err != nil {
		if s.failed == nil {
			s.failed = map[string]error{}
		}

		s.failed[key] = err

		return nil, err
	}

	if s.repos == nil {
		s.repos = map[string]*Fetched{}
	}

	s.repos[key] = f
	s.logf("gitfetch: %s fetched in %s", key, time.Since(start).Round(time.Millisecond))

	if f.FilterIgnored {
		s.ignored++
		s.logf("gitfetch: %s ignored the commits-only filter — the walk is still correct, the download was larger", key)
	}

	return f.Repo, nil
}

// IgnoredFilter reports whether one fetched repository's remote
// ignored the commits-only filter — false for a repository this walk
// has not fetched.
func (s *Session) IgnoredFilter(owner, repo string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.repos[owner+"/"+repo]

	return ok && f.FilterIgnored
}

// FilterIgnored counts the repositories whose remote ignored the
// commits-only filter this walk.
func (s *Session) FilterIgnored() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.ignored
}

// Close removes every repository this walk fetched.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error

	for key, f := range s.repos {
		if err := f.Close(); err != nil {
			errs = append(errs, err)
		}

		delete(s.repos, key)
	}

	return errors.Join(errs...)
}

// TagRefs lists one repository's tag refs.
func (s *Session) TagRefs(owner, repo string) ([]gitrepo.TagRef, error) {
	r, err := s.Repo(owner, repo)
	if err != nil {
		return nil, err
	}

	return r.TagRefs()
}

// ResolveTag resolves one tag ref to its target, through the one
// resolution (gitrepo.ResolveTag).
func (s *Session) ResolveTag(owner, repo string, ref gitrepo.TagRef) (string, *gitrepo.TagObject, error) {
	r, err := s.Repo(owner, repo)
	if err != nil {
		return "", nil, err
	}

	return r.ResolveTag(ref)
}

// TagCommit resolves one tag, by name, through the same resolution.
func (s *Session) TagCommit(owner, repo, tag string) (string, error) {
	r, err := s.Repo(owner, repo)
	if err != nil {
		return "", err
	}

	return r.TagCommit(tag)
}

// ChainNotes reads one repository's ledger. The notes ref is the one
// the session fetched: asked for another, it refuses rather than read
// a ledger it never brought down.
func (s *Session) ChainNotes(owner, repo, notesRef string) ([]gitrepo.ChainNote, error) {
	if notesRef != s.Want.NotesRef {
		return nil, fmt.Errorf("gitfetch: the walk asked for %s, but this session fetched %q", notesRef, s.Want.NotesRef)
	}

	r, err := s.Repo(owner, repo)
	if err != nil {
		return nil, err
	}

	return r.ChainNotes()
}

// CommitMeta reads one commit's parents, time and subject.
func (s *Session) CommitMeta(owner, repo, rev string) (*gitrepo.CommitMeta, error) {
	r, err := s.Repo(owner, repo)
	if err != nil {
		return nil, err
	}

	return r.CommitMeta(rev)
}

// IsAncestor reports whether base is an ancestor of (or is) head,
// answered from the fetched history.
func (s *Session) IsAncestor(owner, repo, base, head string) (bool, error) {
	r, err := s.Repo(owner, repo)
	if err != nil {
		return false, err
	}

	return r.IsAncestor(base, head)
}

func (s *Session) fetcher() *Fetcher {
	if s.Fetcher == nil {
		return &Fetcher{}
	}

	return s.Fetcher
}

func (s *Session) logf(format string, args ...any) {
	if s.Log != nil {
		s.Log(format, args...)
	}
}
