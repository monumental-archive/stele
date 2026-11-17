// Whether the object store holds a commit (stele#387): the one read
// that lets a fetched history say "this commit is on no branch" — the
// signer watch's forgery case, a branch pushed, a certificate minted,
// the branch deleted — instead of failing on the commit it never
// fetched.
//
// The answer is typed from git's own, as measured on git 2.50.1 in a
// commits-only partial clone under GIT_NO_LAZY_FETCH=1 (stele#387):
//
//	cat-file -e <oid>   a present commit, tag or blob       exit 0
//	                    a full-length id the store lacks    exit 1, stderr empty
//	                    a store git cannot read             exit 128, fatal: …
//	cat-file -t <oid>   a present object                    exit 0, its type
//
// Only the second line is "not held". Everything else is git failing,
// or an object that is not a commit — both errors by name, never an
// absence. `<oid>^{commit}` is deliberately not the probe: it peels a
// tag to its commit (exit 0) and answers a blob with the same exit as
// an absent object (128), so it can tell neither apart.

package gitrepo

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// objectIDRE is a full object id in either of git's object formats:
// SHA-1 (40 hex) or SHA-256 (64 hex). Nothing shorter, and no ref name.
var objectIDRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// notHeld is cat-file -e's exit status for a well-formed id the store
// does not hold.
const notHeld = 1

// HasCommit reports whether the object store holds oid and oid is a
// commit. false, nil is the one measured answer for an id the store
// does not hold; a present object of another type, a store git cannot
// read, and an id that is not a full hex object id are errors by name.
//
// The id must already be a full object id: a ref name or an
// abbreviation would be resolved by git, and a question about a commit
// must not become a question about whatever a name points at today.
func (r *Repo) HasCommit(oid string) (bool, error) {
	if !objectIDRE.MatchString(oid) {
		return false, fmt.Errorf("gitrepo: %q is not a full hex object id — a commit is asked about by its id", oid)
	}

	held, err := r.holds(oid)
	if err != nil || !held {
		return false, err
	}

	out, err := r.git("cat-file", "-t", oid)
	if err != nil {
		return false, fmt.Errorf("gitrepo: type of %s: %w", oid, err)
	}

	if kind := strings.TrimSpace(string(out)); kind != "commit" {
		return false, fmt.Errorf("gitrepo: %s is a %s, not a commit", oid, kind)
	}

	return true, nil
}

// holds asks whether the store holds oid at all. It reads git's exit
// status and stderr apart, which the package's runner folds into one
// error: the measured "not held" is exit 1 with nothing on stderr, and
// it is the only status typed as an answer.
func (r *Repo) holds(oid string) (bool, error) {
	// The hermetic environment is the package's one definition (Env);
	// the id is validated hex.
	//nolint:gosec,noctx // fixed executable, a validated object id; local read, no cancellation surface
	cmd := exec.Command("git", "-C", r.dir, "cat-file", "-e", oid)
	cmd.Env = Env()

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		return true, nil
	}

	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == notHeld && stderr.Len() == 0 {
		return false, nil
	}

	return false, fmt.Errorf("gitrepo: is %s held: git cat-file -e: %w: %s", oid, err, strings.TrimSpace(stderr.String()))
}
