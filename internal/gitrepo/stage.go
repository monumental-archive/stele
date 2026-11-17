// This file: staging the ledger — the signing half of a split chain
// emission (stele#390) writes its links where git stores them, so the
// bytes the next link hashes are git's own, and still leaves the
// ledger the repository carries untouched.

package gitrepo

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// stagingPrefix is where a staged ledger lives while a run signs
// against it: under refs/notes/ so `git notes --ref` takes it as is.
const stagingPrefix = "refs/notes/stele-staging-"

// StageNotes points this repository at a scratch copy of its ledger —
// a fresh notes ref seeded at the ledger's current commit, or absent
// when the ledger is — so every note written from here on lands
// there, stored by git exactly as AddNote would store it, while the
// ledger ref itself never moves. The returned release points the
// repository back at the ledger and deletes the scratch ref; call it
// once the staged notes have been read out.
func (r *Repo) StageNotes() (func() error, error) {
	ledger := r.notesRef
	if ledger == "" {
		return nil, errNoLedger
	}

	staging := stagingPrefix + strings.ToLower(rand.Text())

	// An absent ledger (a chain not yet founded) stages as an absent
	// scratch ref: the first note written creates it.
	if out, err := r.git("rev-parse", "--verify", "--quiet", ledger); err == nil {
		if _, uerr := r.git("update-ref", staging, strings.TrimSpace(string(out))); uerr != nil {
			return nil, fmt.Errorf("gitrepo: seeding %s: %w", staging, uerr)
		}
	}

	r.notesRef = staging

	release := func() error {
		r.notesRef = ledger

		if _, err := r.git("update-ref", "-d", staging); err != nil {
			return fmt.Errorf("gitrepo: deleting %s: %w", staging, err)
		}

		return nil
	}

	return release, nil
}
