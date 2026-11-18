// Which paths the index tracks (stele#396): the question "does this
// release's tree carry a dependency manifest" is answered by what git
// tracks, never by what happens to be on disk — a build leaves
// lockfiles behind that no commit carries.

package gitrepo

import (
	"bytes"
	"errors"
	"fmt"
)

// TrackedPaths lists the tracked paths matching any of the pathspecs,
// in git's order. git's own pathspec rules apply: `*/Cargo.lock`
// matches at any depth, because a pathspec's `*` crosses `/`.
func (r *Repo) TrackedPaths(pathspecs ...string) ([]string, error) {
	if len(pathspecs) == 0 {
		return nil, errors.New("gitrepo: a tracked-paths read names at least one pathspec")
	}

	out, err := r.git(append([]string{"ls-files", "-z", "--"}, pathspecs...)...)
	if err != nil {
		return nil, fmt.Errorf("gitrepo: %w", err)
	}

	var paths []string

	for p := range bytes.SplitSeq(out, []byte{0}) {
		if len(p) > 0 {
			paths = append(paths, string(p))
		}
	}

	return paths, nil
}
