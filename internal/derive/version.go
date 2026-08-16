// Package derive turns facts into claims. This file holds the version
// decision: which release a range of conventional commits calls for.
//
// Semantic Versioning itself is not implemented here. Masterminds/semver
// is the library for it, and StrictNewVersion is exactly SemVer 2.0.0 —
// measured against the spec's own rows before adopting it. Its
// conventions are used as written: *semver.Version is the version type
// everywhere, and IncMajor/IncMinor/IncPatch are the bumps. Only the
// decisions the spec does NOT make live in this file.
//
// Two of those decisions are structural rather than checked:
//
//   - Precedence is the ORDER of the Bump type, so "the largest change
//     in the range decides" is a max over an ordered enum. There is no
//     pairwise precedence table to get wrong, and no fold that can take
//     the last commit's vote instead of the highest.
//   - A decision that releases nothing has no version to read. Next
//     returns comma-ok, so "there is nothing to release" cannot be
//     mistaken for "release the base version again".
//
// Requested and Applied are deliberately separate: a range containing a
// breaking change on a 0.x line requested a major and applied a minor,
// and a changelog that reports the applied bump as the requested one
// tells a reader there was no breaking change in it.
package derive

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/convcommit"
)

// DefaultTagPrefix is git's usual spelling for a version tag. SemVer
// itself has no such prefix (§2) and StrictNewVersion rightly refuses
// one, so the two spellings are converted here — where tags are read —
// rather than by a parser that quietly accepts both.
const DefaultTagPrefix = "v"

// A prefix names a TAG NAMESPACE, not decoration. One history routinely
// carries several: a workspace releasing under "v" while each member
// releases under its own ("edtf-core-v", "edtf-cli-v", and five more in
// one repository measured). "The latest tag" is therefore meaningless
// until a namespace is named, and a derivation that ignores prefixes
// reads another component's version as its own.

// ParseTag reads one tag in the given namespace. A tag outside the
// namespace, or one inside it that is not a version, is an error here;
// LatestTag is the caller that decides which of those to tolerate.
func ParseTag(prefix, tag string) (*semver.Version, error) {
	rest, found := strings.CutPrefix(tag, prefix)
	if !found {
		return nil, fmt.Errorf("derive: tag %q is not in the %q namespace", tag, prefix)
	}

	version, err := semver.StrictNewVersion(rest)
	if err != nil {
		return nil, fmt.Errorf("derive: tag %q: %w", tag, err)
	}

	return version, nil
}

// Tag renders a version as a git tag in the given namespace. The inverse
// of ParseTag.
func Tag(prefix string, version *semver.Version) string { return prefix + version.String() }

// Base is the starting point a range is measured from: the highest
// version in the namespace, plus every tag that claimed the namespace
// and could not be read.
//
// Skipped is not a diagnostic afterthought. A repository adopting this
// tool brings whatever its tags were before — "v0.9-pre-import" and
// "style-v1" are both real, from a real repository — and those must not
// stop a derivation, because the repositories most in need of adopting
// are exactly the ones carrying them. But dropping them in silence is
// the same defect as a silent cap: the run would report a clean base it
// only reached by ignoring things. So they are skipped AND named.
type Base struct {
	Version *semver.Version
	Skipped []string
}

// LatestTag selects the base from a tag list.
//
// Tags outside the namespace are not skipped and not reported — they
// belong to another component and were never candidates. Only a tag that
// claims the namespace and then fails to parse is worth a reader's
// attention.
//
// An empty namespace yields a nil Version rather than a zero one: "this
// project has never released" and "this project released 0.0.0" are
// different facts, and the caller states which base an unreleased
// project starts from.
func LatestTag(prefix string, tags []string) Base {
	var base Base

	for _, tag := range tags {
		if !strings.HasPrefix(tag, prefix) {
			continue
		}

		version, err := ParseTag(prefix, tag)
		if err != nil {
			base.Skipped = append(base.Skipped, tag)

			continue
		}

		if base.Version == nil || version.GreaterThan(base.Version) {
			base.Version = version
		}
	}

	return base
}

// Unreleased is the version a project that has never released measures
// its first range from. A feature therefore lands on 0.1.0 and a fix on
// 0.0.1, which is the rules deciding the first release rather than a
// constant asserting it.
//
// It is a function and not a package variable because *semver.Version is
// a pointer: a shared one could be mutated by any caller, and the first
// release of every project would move together.
func Unreleased() *semver.Version { return semver.New(0, 0, 0, "", "") }

// Bump is the size of a version change. The values are ordered smallest
// to largest so that deciding a range is max(), and that ordering is the
// type's contract — not an implementation detail.
type Bump int

// The bump sizes, in increasing order.
const (
	BumpNone Bump = iota
	BumpPatch
	BumpMinor
	BumpMajor
)

// String renders the bump for diagnostics.
func (b Bump) String() string {
	switch b {
	case BumpNone:
		return "none"
	case BumpPatch:
		return "patch"
	case BumpMinor:
		return "minor"
	case BumpMajor:
		return "major"
	default:
		return fmt.Sprintf("Bump(%d)", int(b))
	}
}

// Rules are the project's conventions: which commit types raise the
// minor, which release nothing at all, and whether a 0.x line absorbs
// breaking changes into its minor.
//
// The default is a PATCH, and the lists are exceptions to it — a
// deny-list, not an allow-list. The two models are both legal
// (Conventional Commits maps only feat, fix and breaking to SemVer and
// says nothing about other types), and they fail differently: an
// unexpected patch release is visible and harmless, while a "revert:"
// that repairs a live bug and silently ships nothing is the exact class
// this tool exists to prevent. A type nobody has classified yet should
// therefore ship, not vanish.
//
// A breaking declaration always votes major regardless of type, silent
// types included: §13 of Conventional Commits puts the marker on any
// type, and a "docs!:" that removed a documented flag broke something
// whatever noun it chose.
type Rules struct {
	minor               map[string]bool
	silent              map[string]bool
	zeroMajorBumpsMinor bool
	valid               bool
}

// NewRules builds the convention set. A type named in both lists is
// refused rather than resolved by order: two answers for one type is a
// configuration defect, and silently preferring one buries it.
func NewRules(minor, silent []string, zeroMajorBumpsMinor bool) (Rules, error) {
	rules := Rules{
		minor:               make(map[string]bool, len(minor)),
		silent:              make(map[string]bool, len(silent)),
		zeroMajorBumpsMinor: zeroMajorBumpsMinor,
		valid:               true,
	}

	for _, group := range []struct {
		types []string
		into  map[string]bool
	}{{minor, rules.minor}, {silent, rules.silent}} {
		for _, typ := range group.types {
			if typ == "" {
				return Rules{}, errors.New("derive: an empty commit type cannot vote")
			}

			if rules.minor[typ] || rules.silent[typ] {
				return Rules{}, fmt.Errorf("derive: commit type %q is listed twice", typ)
			}

			group.into[typ] = true
		}
	}

	return rules, nil
}

// Decision is the outcome of reading a commit range against the rules.
// Its fields are unexported because the only honest way to read it is
// through Next's comma-ok: a caller that can reach a version without
// asking whether anything releases will eventually publish the base
// version a second time.
type Decision struct {
	requested Bump
	applied   Bump
	base      *semver.Version
	next      *semver.Version
}

// Requested reports the bump the commits called for, before any rule
// about 0.x lines is applied.
func (d *Decision) Requested() Bump { return d.requested }

// Applied reports the bump actually made to the version.
func (d *Decision) Applied() Bump { return d.applied }

// Base reports the version the range was measured from.
func (d *Decision) Base() *semver.Version { return d.base }

// Releases reports whether this range releases anything.
func (d *Decision) Releases() bool { return d.applied != BumpNone }

// Next reports the version to release, and false when the range
// releases nothing.
func (d *Decision) Next() (*semver.Version, bool) {
	if d.applied == BumpNone {
		return nil, false
	}

	return d.next, true
}

// Decide reads a parsed commit range against the rules and reports what
// to release.
//
// The commits must already be parsed: a message that is not a
// conventional commit says nothing about versioning, and what to do with
// one — drop it, or refuse the range — is a judgement for the caller
// that read the history. The consequence is worth stating plainly: a
// breaking change described only in prose is invisible to every
// implementation of this format, this one included.
func (r Rules) Decide(base *semver.Version, commits []convcommit.Commit) (Decision, error) {
	if !r.valid {
		return Decision{}, errors.New("derive: rules were not built by NewRules")
	}

	if base == nil {
		return Decision{}, errors.New("derive: no base version to measure the range from")
	}

	// A prerelease base has two defensible answers — promote the
	// candidate, or increment past it — and picking one here would bury
	// the choice. It is also the one input where the library's IncPatch
	// means "promote" rather than "increment", so refusing it keeps that
	// ambiguity out of reach rather than resolved by accident.
	if base.Prerelease() != "" {
		return Decision{}, fmt.Errorf("derive: base %s is a prerelease; promote or pin it before deciding a bump", base)
	}

	requested := BumpNone

	for i := range commits {
		requested = max(requested, r.vote(&commits[i]))
	}

	applied := requested

	// The 0.x rule, applied once to the decided bump: below 1.0.0 the
	// major is not yet a compatibility promise, so a break raises the
	// minor instead of declaring 1.0.0 by accident.
	if r.zeroMajorBumpsMinor && base.Major() == 0 && applied == BumpMajor {
		applied = BumpMinor
	}

	return Decision{
		requested: requested,
		applied:   applied,
		base:      base,
		next:      apply(base, applied),
	}, nil
}

// vote reports what one commit calls for. The order is the contract: a
// break outranks silence, and everything unclassified is a patch.
func (r Rules) vote(c *convcommit.Commit) Bump {
	switch {
	case c.IsBreaking():
		return BumpMajor
	case r.silent[c.Type()]:
		return BumpNone
	case r.minor[c.Type()]:
		return BumpMinor
	default:
		return BumpPatch
	}
}

// apply performs the bump. BumpNone yields the base unchanged, which
// Decision.Next refuses to hand out.
func apply(base *semver.Version, bump Bump) *semver.Version {
	var next semver.Version

	switch bump {
	case BumpMajor:
		next = base.IncMajor()
	case BumpMinor:
		next = base.IncMinor()
	case BumpPatch:
		next = base.IncPatch()
	case BumpNone:
		return base
	}

	return &next
}
