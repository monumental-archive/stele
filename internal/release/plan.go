// Package release turns one repository's state into the release plan a
// forge executor runs: the version, the notes, the commit's contents,
// the branch it lands on, and the tag that follows it — as data.
//
// The plan exists because the org's release scripts were classified as
// orchestration for being shaped like shell (stele#155). They were not:
// staging a branch is orchestration, but deciding which files a release
// commit carries, whether the tree's state permits a release at all,
// and what the tag may be called are engine work, and they were spread
// across three bash files that each re-derived what the others knew.
//
// Two properties make this a plan rather than a script:
//
//   - it is safe to compute twice. Assembling reads; nothing here
//     writes. The caller that prepares the tree does so from the plan,
//     so the preparation and the plan cannot disagree about what was
//     prepared.
//   - a refused plan is a document saying why. A tree state that
//     forbids a release produces a plan carrying refusals and no
//     instructions — never a partial plan an executor could half-run.
//
// What deliberately does not move here: signing, token capability, the
// job graph, the OIDC grants. The plan is JSON, not capability
// (.github#392's "not signing / not workflows" is untouched).
package release

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// Schema is the document epoch every stele document carries — one
// number across the tree, defined at the version gate. See
// docs/versioning.md.
const Schema = jsonx.Epoch

// The refusal causes. A cause is a vocabulary word an executor can
// branch on; the detail is for the human reading the log.
const (
	CauseMirrorDrift = "mirror-drift"
	CauseTagTaken    = "tag-taken"
)

// VersionToken is the placeholder a subject template carries. The
// spelling is the tool's own (derive's templates use the same braces),
// and substitution is verbatim: nothing else is interpolated.
const VersionToken = "{version}"

// Plan is the release decisions as data. Absent sections mean absent
// decisions: a plan that releases nothing carries no commit, no branch
// and no tag, so an executor reading it cannot act on a field that was
// never decided.
type Plan struct {
	Schema  int  `json:"schema"`
	Release bool `json:"release"`
	// Refusals name the tree states that forbid this release. Present
	// only on a refused plan, and a refused plan carries nothing else
	// an executor could act on.
	Refusals []Refusal `json:"refusals,omitempty"`
	// Version is the release being cut, and Base the one it is measured
	// from — the same pair `derive version` reports, from the same
	// decision, so no leg re-derives either.
	Version string `json:"version,omitempty"`
	Base    string `json:"base,omitempty"`
	Tag     string `json:"tag,omitempty"`
	Bump    *Bump  `json:"bump,omitempty"`
	// Notes is the changelog section for this release, rendered once.
	// The section spliced into the changelog and the body a release
	// carries are this one string, so the reviewed text and the
	// published text cannot be two renderings.
	Notes  string  `json:"notes,omitempty"`
	Commit *Commit `json:"commit,omitempty"`
	Branch *Branch `json:"branch,omitempty"`
}

// Refusal is one tree state that forbids the release.
type Refusal struct {
	Cause  string `json:"cause"`
	Detail string `json:"detail"`
}

// Bump reports what moved and what the range asked for. They differ
// when the 0.x rule absorbed a break, or when a human declared the
// number (stele#146) — and a reader shown only what moved would
// conclude the commits asked for it.
type Bump struct {
	Applied   string `json:"applied"`
	Requested string `json:"requested"`
	Declared  bool   `json:"declared"`
}

// Commit is the release commit's contents. Additions and deletions are
// split here rather than by the executor: a path the release names and
// the tree no longer has is the old half of a rename, and classifying
// it at execution time is a decision made by whoever happens to be
// holding the file list.
//
// The sign-off is deliberately absent. It names an identity only the
// executing token knows (an App installation's bot user), so composing
// it here would be this tool asserting a fact about a credential it
// does not hold.
type Commit struct {
	Subject   string   `json:"subject"`
	Additions []string `json:"additions,omitempty"`
	Deletions []string `json:"deletions,omitempty"`
}

// Branch is where the release commit lands. The staging ref exists
// because the release branch must never momentarily equal the default
// branch: a pull request whose diff is empty is closed by the forge,
// which churns the number and discards the review thread.
type Branch struct {
	Name    string `json:"name"`
	Staging string `json:"staging"`
}

// Inputs is everything Assemble reads. Every org-shaped value arrives
// here from the caller — branch names, the subject template, the extra
// files an ecosystem's own derivation refreshes — because which of
// those a repository uses is that repository's fact and belongs in no
// tool's code.
type Inputs struct {
	// Root is the tree the release is cut from; paths are read
	// relative to it.
	Root string
	// Next and Base are the decision's two versions. A nil Next is a
	// range that releases nothing.
	Next *semver.Version
	Base *semver.Version
	// Taken is every version the tag namespace already carries,
	// reachable or not — a released version is a name, and a name is
	// taken once.
	Taken []*semver.Version
	// TagPrefix is the namespace the tag is minted in.
	TagPrefix string
	// AppliedBump, RequestedBump and Declared come from the shared
	// version decision.
	AppliedBump, RequestedBump string
	Declared                   bool
	// Notes is the rendered changelog section.
	Notes string
	// MirrorFiles are the version mirrors the release commit carries,
	// from the one detection that also rewrites them.
	MirrorFiles []string
	// MirrorVersion is what those mirrors carry now, and MirrorsFound
	// whether the tree has any — a tree with none is a fact, not a
	// missing read.
	MirrorVersion string
	MirrorsFound  bool
	// Changelog is the file the notes are spliced into, when the
	// caller keeps one.
	Changelog string
	// Also names further files the release commit carries: the
	// lockfiles an ecosystem's own derivation refreshes beside the
	// mirrors. Declared, never guessed — which files those are is the
	// caller's ecosystem, not this tool's.
	Also []string
	// Subject is the release commit's subject template, carrying
	// {version}. The tag leg compares a candidate commit's subject
	// against the rendering, so one template decides both.
	Subject string
	// Branch and Staging name the refs the executor moves.
	Branch, Staging string
}

// Assemble reads the inputs and returns the plan they support. It
// writes nothing: a plan is a statement about what should happen, and
// one that acted while being computed could not be computed twice.
//
// The error return is for inputs that make a plan impossible to state
// at all (an unreadable tree, a template naming no version). A tree
// state that FORBIDS the release is not that: it is a refused plan,
// because the executor still has something to read.
func Assemble(in *Inputs) (*Plan, error) {
	if in == nil {
		return nil, errors.New("release: no inputs")
	}

	if in.Next == nil {
		// Nothing to release is a plan, not a refusal: the range said
		// so, and an executor reading it has one correct action, which
		// is none.
		return &Plan{Schema: Schema, Release: false}, nil
	}

	if !strings.Contains(in.Subject, VersionToken) {
		return nil, fmt.Errorf(
			"release: the commit subject template %q names no %s — the tag leg would compare against a constant",
			in.Subject, VersionToken)
	}

	version := in.Next.String()
	tag := in.TagPrefix + version

	if refusals := in.refusals(version, tag); len(refusals) > 0 {
		return &Plan{Schema: Schema, Release: false, Refusals: refusals}, nil
	}

	additions, deletions, err := in.contents()
	if err != nil {
		return nil, err
	}

	base := ""
	if in.Base != nil {
		base = in.Base.String()
	}

	return &Plan{
		Schema: Schema, Release: true,
		Version: version, Base: base, Tag: tag,
		Bump:  &Bump{Applied: in.AppliedBump, Requested: in.RequestedBump, Declared: in.Declared},
		Notes: in.Notes,
		Commit: &Commit{
			Subject:   strings.ReplaceAll(in.Subject, VersionToken, version),
			Additions: additions,
			Deletions: deletions,
		},
		Branch: &Branch{Name: in.Branch, Staging: in.Staging},
	}, nil
}

// refusals judges the tree states that forbid a release. Both are
// states a release would burn something irreversible on: an immutable
// version number, or a set of published mirrors.
func (in *Inputs) refusals(version, tag string) []Refusal {
	var out []Refusal

	for _, taken := range in.Taken {
		if taken.Equal(in.Next) {
			out = append(out, Refusal{
				Cause: CauseTagTaken,
				Detail: fmt.Sprintf(
					"the namespace already carries %s, so minting %s would name one release twice", version, tag),
			})

			break
		}
	}

	// The mirrors must carry either the version last released (a fresh
	// run) or the one being released (a re-run of a release step, which
	// must be safe to repeat). Anything else is a mirror that moved on
	// its own, which is evidence — surfaced, never overwritten.
	if in.MirrorsFound && in.MirrorVersion != version {
		if in.Base == nil {
			out = append(out, Refusal{
				Cause: CauseMirrorDrift,
				Detail: fmt.Sprintf(
					"the mirrors carry %q before any release in this namespace; nothing released them",
					in.MirrorVersion),
			})
		} else if in.MirrorVersion != in.Base.String() {
			out = append(out, Refusal{
				Cause: CauseMirrorDrift,
				Detail: fmt.Sprintf(
					"the mirrors carry %q but the last release is %s; a mirror that moved on its own is evidence",
					in.MirrorVersion, in.Base),
			})
		}
	}

	return out
}

// contents splits the release commit's files into what the tree has
// and what it no longer does. A named path that is gone is the old half
// of a rename — a deletion the commit must carry, or the rename never
// lands.
//
//nolint:gocritic // unnamedResult: the additions, then the deletions
func (in *Inputs) contents() ([]string, []string, error) {
	named := make([]string, 0, len(in.MirrorFiles)+len(in.Also)+1)
	named = append(named, in.MirrorFiles...)
	named = append(named, in.Also...)

	if in.Changelog != "" {
		named = append(named, in.Changelog)
	}

	var (
		additions []string
		deletions []string
		seen      = map[string]bool{}
	)

	for _, path := range named {
		if path == "" || seen[path] {
			continue
		}

		seen[path] = true

		// A commit's contents are paths inside the tree, by
		// definition. An absolute path, or one that climbs out, names
		// something no commit can carry — and joining it to the root
		// would produce a plausible path pointing somewhere else.
		if filepath.IsAbs(path) || strings.HasPrefix(filepath.Clean(path), "..") {
			return nil, nil, fmt.Errorf(
				"release: %q is not a path inside the tree — a release commit carries tree-relative files", path)
		}

		info, err := os.Stat(filepath.Join(in.Root, path))

		switch {
		case err == nil && info.IsDir():
			return nil, nil, fmt.Errorf("release: %s is a directory, not a release commit's content", path)
		case err == nil:
			additions = append(additions, path)
		case os.IsNotExist(err):
			deletions = append(deletions, path)
		default:
			return nil, nil, fmt.Errorf("release: reading %s: %w", path, err)
		}
	}

	sort.Strings(additions)
	sort.Strings(deletions)

	return additions, deletions, nil
}
