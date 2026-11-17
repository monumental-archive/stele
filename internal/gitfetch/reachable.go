package gitfetch

import "errors"

// errNotEveryRef refuses Reachable on a session that fetched less than
// every branch and every tag at full depth.
var errNotEveryRef = errors.New(
	"gitfetch: whether a commit is reachable from a branch or a tag is answered only from every branch and" +
		" every tag fetched at full depth (Want.Heads and Want.Tags, not Shallow) — a commit a narrower fetch" +
		" did not bring down may still be reachable",
)

// Reachable reports whether commit is reachable from some branch or
// some tag of one repository: whether the fetched history holds it
// (stele#408). It reads through the one presence read
// (gitrepo.HasCommit), so an id the store does not hold is the typed
// false and git failing is an error, never an absence.
//
// false is an answer only because this session fetched every branch
// and every tag, commits-only, at full depth: a commit no such fetch
// brought down is reachable from none of them — and so is an ancestor
// of no tag's target. A session that fetched less refuses by name
// rather than turn "not fetched" into "not reachable".
func (s *Session) Reachable(owner, repo, commit string) (bool, error) {
	if !s.Want.Heads || !s.Want.Tags || s.Want.Shallow {
		return false, errNotEveryRef
	}

	r, err := s.Repo(owner, repo)
	if err != nil {
		return false, err
	}

	return r.HasCommit(commit)
}
