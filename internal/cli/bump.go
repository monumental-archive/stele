// `derive bump`: the release's version mirrors rewritten from the same
// derivation that decided the version. The version never passes through
// a shell between being derived and being written — the mirrors are set
// by the code that derived the number, and the caller learns what
// happened from the outputs, never the other way round.

package cli

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/derive"
	"github.com/monumental-archive/stele/internal/manifest"
)

// deriveBump is the fourth derivation mode.
const deriveBump = "bump"

// bumpArgs is everything `derive bump` reads beyond the version flags.
type bumpArgs struct {
	check       bool
	date        string
	expect      string
	manifestDir string
}

// refusal is the flags' own contradictions, or "" when they stand.
func (b *bumpArgs) refusal() string {
	switch {
	case (b.expect != "" || b.manifestDir != "") && !b.check:
		return "--expect and --manifest-dir judge, so they need --check; a rewrite takes its version from history"
	case b.expect != "":
		// Strict: a mirror carries 1.2.3, never v1.2.3, so a stated
		// version spelled with the tag's prefix could never agree.
		if _, err := semver.StrictNewVersion(b.expect); err != nil {
			return fmt.Sprintf("--expect %q is not a version (MAJOR.MINOR.PATCH, no prefix): %v", b.expect, err)
		}
	}

	return ""
}

// runDeriveBump derives the release and either rewrites the tree's
// version mirrors to it, or — in check mode — holds them against the
// version already released.
func runDeriveBump(da *deriveArgs, bump *bumpArgs, out *latch) error {
	// A stated version needs no history: it is the whole question, so
	// the tree is read and git is not.
	if bump.check && bump.expect != "" {
		set, err := judgedMirrors(da.gitDir, bump.manifestDir, out)
		if err != nil {
			return err
		}

		return runBumpExpect(bump.expect, set, out)
	}

	d, err := deriveRelease(da, out)
	if err != nil {
		return err
	}

	if bump.check {
		set, jerr := judgedMirrors(da.gitDir, bump.manifestDir, out)
		if jerr != nil {
			return jerr
		}

		return runBumpCheck(d, set, out)
	}

	set, err := manifest.Detect(da.gitDir)
	if err != nil {
		return err
	}

	out.logf("kind=%s", set.Kind)

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
				current, base,
			)
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

// judgedMirrors is the set a check holds against a version: the tree's
// mirrors, or — with a manifest directory — that package's version
// alone, the root's mirrors held only to agree with each other.
func judgedMirrors(root, manifestDir string, out *latch) (*manifest.Set, error) {
	set, err := manifest.Detect(root)
	if err != nil {
		return nil, err
	}

	out.logf("kind=%s", set.Kind)

	if manifestDir == "" {
		return set, nil
	}

	if len(set.Sites) > 0 {
		if _, verr := set.Version(); verr != nil {
			return nil, verr
		}
	}

	member, err := manifest.MemberVersion(root, manifestDir)
	if err != nil {
		return nil, err
	}

	out.logf("judging %s %s = %q", member.Path, member.Field, member.Value)

	return &manifest.Set{Kind: set.Kind, Sites: []manifest.Site{member}}, nil
}

// runBumpExpect holds the judged mirrors against a stated version. An
// expectation with nothing in the tree to hold it against is refused:
// passing it would be the silent green this check exists to end.
func runBumpExpect(expect string, set *manifest.Set, out *latch) error {
	if len(set.Sites) == 0 {
		return fmt.Errorf("derive bump: --expect %s, but nothing in this tree states a version to hold it against",
			expect)
	}

	if err := set.Check(expect); err != nil {
		return err
	}

	out.logf("check=ok")
	out.logf("every judged mirror carries %s", expect)

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
