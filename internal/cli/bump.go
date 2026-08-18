// `derive bump`: the release's version mirrors rewritten from the same
// derivation that decided the version. The version never passes through
// a shell between being derived and being written — the mirrors are set
// by the code that derived the number, and the caller learns what
// happened from the outputs, never the other way round.

package cli

import (
	"fmt"
	"strings"

	"github.com/monumental-archive/stele/internal/derive"
	"github.com/monumental-archive/stele/internal/manifest"
)

// deriveBump is the fourth derivation mode.
const deriveBump = "bump"

// bumpArgs is everything `derive bump` reads beyond the version flags.
type bumpArgs struct {
	check bool
	date  string
}

// runDeriveBump derives the release and either rewrites the tree's
// version mirrors to it, or — in check mode — holds them against the
// version already released.
func runDeriveBump(da *deriveArgs, bump *bumpArgs, out *latch) error {
	d, err := deriveRelease(da, out)
	if err != nil {
		return err
	}

	set, err := manifest.Detect(da.gitDir)
	if err != nil {
		return err
	}

	out.logf("kind=%s", set.Kind)

	if bump.check {
		return runBumpCheck(d, set, out)
	}

	next, releases := d.decision.Next()
	if !releases {
		out.logf("release=false")
		out.logf("nothing to release: no version-bumping commits since %s", d.decision.Base())

		return nil
	}

	files := []string{}

	if len(set.Sites) > 0 || set.DateSite != nil {
		// The pre-write state must be one of exactly two facts: the
		// mirrors carry the version last released (a fresh run), or they
		// already carry the version being released (a re-run of a release
		// step, which must be safe to repeat). Anything else is drift,
		// and drift is surfaced, never overwritten.
		current, verr := set.Version()
		if verr != nil {
			return verr
		}

		if base := d.base.Version; base != nil && current != base.String() && current != next.String() {
			return fmt.Errorf(
				"derive bump: mirrors carry %q but the last release is %s; "+
					"a mirror that moved on its own is evidence, not something to overwrite",
				current, base)
		}

		date := bump.date
		if date == "" {
			if date, err = d.date(); err != nil {
				return err
			}
		}

		files, err = set.Rewrite(next.String(), date)
		if err != nil {
			return err
		}
	} else {
		out.logf("no version mirrors in this tree; tags are the only version source")
	}

	out.logf("release=true")
	out.logf("version=%s", next)
	out.logf("tag=%s", derive.Tag(da.prefix, next))
	out.logf("files=%s", strings.Join(files, " "))

	return nil
}

// runBumpCheck is the drift gate: every mirror equals the version last
// released, so a hand-edited mirror fails the pull request that edits
// it instead of surfacing at the next release.
func runBumpCheck(d *derived, set *manifest.Set, out *latch) error {
	if len(set.Sites) == 0 {
		out.logf("check=no-mirrors")
		out.logf("no version mirrors in this tree; nothing to drift")

		return nil
	}

	// Before a first release there is no released version for mirrors to
	// equal, so the only checkable fact is their agreement with each
	// other. Stated as its own outcome, never folded into a pass: a
	// reader of the log must not conclude the released-version check ran.
	base := d.base.Version
	if base == nil {
		if _, err := set.Version(); err != nil {
			return err
		}

		out.logf("check=agreement-only")
		out.logf("no release in this namespace yet; mirrors agree with each other, which is all there is to check")

		return nil
	}

	if err := set.Check(base.String()); err != nil {
		// The one state that is not drift: the mirrors carry exactly
		// the version this range derives at this ref — the release
		// being cut, written by this same derivation (the Release PR
		// branch, and the merged release commit before phase 2 mints
		// its tag; stele#115). A hand edit passes only by writing
		// exactly what the machinery would have written, at which
		// point it is not drift. Mirrors ahead of a range that
		// releases nothing stay refused: that is a bump nothing
		// called for.
		if next, releases := d.decision.Next(); releases && set.Check(next.String()) == nil {
			out.logf("check=pending")
			out.logf("mirrors carry %s, the release this range calls for; its tag follows", next)

			return nil
		}

		return err
	}

	out.logf("check=ok")
	out.logf("every mirror carries %s", base)

	return nil
}
