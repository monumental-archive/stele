package gitfetch

import (
	"errors"
	"fmt"
	"strings"
)

// errNotWholeHistory refuses OnBranch on a session that fetched less
// than every branch at full depth.
var errNotWholeHistory = errors.New(
	"gitfetch: whether a commit is on a branch is answered only from every branch fetched at full depth" +
		" (Want.Heads, not Shallow) — a commit a narrower fetch did not bring down may still be on one",
)

// OnBranch reports whether commit is on branch, a fully qualified
// refs/heads/ ref, of one repository (stele#387). true: the history
// holds the commit and it is the branch tip or an ancestor of it.
// false covers both a held commit that is not, and a commit the
// history does not hold at all — the forgery case of a branch pushed,
// a certificate minted, the branch deleted.
//
// That second false is an answer only because this session fetched
// every branch, commits-only, at full depth: a commit no such fetch
// brought down is reachable from no branch, so from none of them. A
// session that fetched less refuses by name rather than turn "not
// fetched" into "not on the branch". IsAncestor is unchanged: it asks
// about commits a walk already holds.
func (s *Session) OnBranch(owner, repo, commit, branch string) (bool, error) {
	if !s.Want.Heads || s.Want.Shallow {
		return false, errNotWholeHistory
	}

	if !strings.HasPrefix(branch, "refs/heads/") {
		return false, fmt.Errorf("gitfetch: %q is not a fully qualified branch — OnBranch answers for refs/heads/ alone",
			branch)
	}

	r, err := s.Repo(owner, repo)
	if err != nil {
		return false, err
	}

	held, err := r.HasCommit(commit)
	if err != nil || !held {
		return false, err
	}

	return r.IsAncestor(commit, branch)
}
