// Release notes: the Keep a Changelog section a release adds to its
// changelog, rendered from the same commits that decided its version.
//
// A FIXED shape with named knobs, deliberately, and not a template
// engine. Every widely used release tool in this space — release-please,
// semantic-release, changesets, goreleaser — ships one format and
// configures it; git-cliff's templating is the outlier, and the template
// it is usually configured with reproduces exactly the standard shape.
//
// The reason that matters here is specific to an evidence tool: a
// changelog rendered from an arbitrary template is prose nothing can
// check. A known shape is a document a verifier can later hold against
// the commits it claims to describe. That is the difference between
// output and evidence, and it is worth more than the ability to make a
// changelog look different.

package derive

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/convcommit"
)

// GitHub's squash merge appends the pull request number to the subject,
// and it is the only record of that number in a repository that has not
// been asked to network. Extracted rather than left in the text, so the
// number appears once — as a link — instead of twice.
var prSuffixRE = regexp.MustCompile(`\s*\(#(\d+)\)$`)

// NotesOptions is the whole configurable surface: which commit type
// lands under which heading, the order headings appear in, and the URL
// prefixes links are built from.
//
// URL PREFIXES rather than templates. A prefix composes for any forge —
// GitHub's ".../compare/" and GitLab's ".../-/compare/" differ only in
// the prefix — and it cannot be malformed the way a template with
// placeholders can. Leaving one empty renders that link as plain text
// rather than a broken href.
type NotesOptions struct {
	// Groups maps a commit type to its heading. A type with no heading
	// contributes no entry, which is how the silent types stay out of a
	// changelog without a second list to disagree with the first.
	Groups map[string]string

	// Order lists headings in the order they render. Rendering must not
	// depend on map iteration: Go randomises it, and a changelog whose
	// sections shuffle between runs cannot be diffed, reviewed, or
	// reproduced.
	Order []string

	// BreakingGroup heads the breaking changes, which are lifted out of
	// their type's group. A break rendered identically to a feature is
	// the one fact a reader most needs and cannot recover; Keep a
	// Changelog has no group for it, so this one is named here.
	BreakingGroup string

	// CompareURL is the prefix a "<previous>...<version>" range appends
	// to. ReleaseURL is the prefix a lone tag appends to, used for a
	// first release, which has nothing to compare against.
	CompareURL string
	ReleaseURL string

	// PullURL is the prefix a pull request number appends to.
	PullURL string
}

// Notes renders release notes under one set of conventions.
type Notes struct {
	opts  NotesOptions
	valid bool
}

// NewNotes validates the conventions.
//
// A heading that no ordering mentions is refused rather than appended at
// the end: silently ordering it last is a decision nobody made, and it
// would move the day another heading is added.
func NewNotes(opts *NotesOptions) (Notes, error) {
	ordered := make(map[string]bool, len(opts.Order))

	for _, heading := range opts.Order {
		if heading == "" {
			return Notes{}, errors.New("derive: an empty heading cannot be ordered")
		}

		if ordered[heading] {
			return Notes{}, fmt.Errorf("derive: heading %q is ordered twice", heading)
		}

		ordered[heading] = true
	}

	for typ, heading := range opts.Groups {
		if heading == "" {
			return Notes{}, fmt.Errorf("derive: commit type %q maps to an empty heading", typ)
		}

		if !ordered[heading] {
			return Notes{}, fmt.Errorf("derive: heading %q for type %q appears in no ordering", heading, typ)
		}
	}

	if opts.BreakingGroup != "" && !ordered[opts.BreakingGroup] {
		return Notes{}, fmt.Errorf("derive: breaking heading %q appears in no ordering", opts.BreakingGroup)
	}

	return Notes{opts: *opts, valid: true}, nil
}

// Release is what one rendered section describes.
type Release struct {
	// Version is the release being described.
	Version *semver.Version

	// Previous is the release before it, nil for a first release.
	Previous *semver.Version

	// TagPrefix spells both versions as the repository tags them.
	TagPrefix string

	// Date is the release date, already formatted. Supplied rather than
	// read from a clock: a renderer that reads the time renders a
	// different document every run, and this one must be reproducible
	// from its inputs alone.
	Date string
}

// entry is one rendered line.
type entry struct {
	text string
	pr   string
}

// Render writes the release notes for one version.
func (n *Notes) Render(rel Release, commits []convcommit.Commit) (string, error) {
	if !n.valid {
		return "", errors.New("derive: notes conventions were not built by NewNotes")
	}

	if rel.Version == nil {
		return "", errors.New("derive: no version to render notes for")
	}

	grouped := n.group(commits)

	var b strings.Builder

	b.WriteString(n.heading(rel))

	for _, headline := range n.opts.Order {
		entries := grouped[headline]
		if len(entries) == 0 {
			continue // an empty section says nothing and reads as an omission
		}

		fmt.Fprintf(&b, "\n### %s\n\n", headline)

		for _, e := range entries {
			b.WriteString(n.line(e))
		}
	}

	return b.String(), nil
}

// group sorts commits under their headings, lifting breaking changes out
// of their type's group. Order within a group is the order the commits
// landed — the history's own order, not one this package invents.
func (n *Notes) group(commits []convcommit.Commit) map[string][]entry {
	grouped := make(map[string][]entry, len(n.opts.Order))

	for i := range commits {
		commit := &commits[i]

		headline := n.opts.Groups[commit.Type()]
		if commit.IsBreaking() && n.opts.BreakingGroup != "" {
			headline = n.opts.BreakingGroup
		}

		if headline == "" {
			continue // a type with no heading is not a changelog entry
		}

		// The pull request number lives in the subject whatever the entry
		// ends up saying, so it is taken from there in every case.
		e := splitPR(commit.Description())

		// Under a breaking heading, a footer-declared break describes
		// itself: s12 makes the footer the description of what broke,
		// while the subject describes the change that broke it. "docs: a
		// note" under Breaking tells a reader nothing; the footer tells
		// them what to fix. A break declared by "!" alone has no footer,
		// and s13 says the subject serves — which is what remains here.
		if headline == n.opts.BreakingGroup {
			if broke := commit.BreakingDescription(); broke != "" {
				e.text = broke
			}
		}

		grouped[headline] = append(grouped[headline], e)
	}

	return grouped
}

// heading renders the version line: a compare link when there is a
// previous release to compare against, a release link when there is not.
func (n *Notes) heading(rel Release) string {
	tag := rel.TagPrefix + rel.Version.String()

	var href string

	switch {
	case rel.Previous != nil && n.opts.CompareURL != "":
		href = n.opts.CompareURL + rel.TagPrefix + rel.Previous.String() + "..." + tag
	case n.opts.ReleaseURL != "":
		href = n.opts.ReleaseURL + tag
	}

	if href == "" {
		return fmt.Sprintf("## %s - %s\n", rel.Version, rel.Date)
	}

	return fmt.Sprintf("## [%s](%s) - %s\n", rel.Version, href, rel.Date)
}

// line renders one entry, linking its pull request when there is both a
// number and somewhere to point it.
func (n *Notes) line(e entry) string {
	if e.pr == "" {
		return "- " + e.text + "\n"
	}

	if n.opts.PullURL == "" {
		return fmt.Sprintf("- %s (#%s)\n", e.text, e.pr)
	}

	return fmt.Sprintf("- %s ([#%s](%s))\n", e.text, e.pr, n.opts.PullURL+e.pr)
}

// splitPR separates a trailing "(#123)" from the description. Returning
// an entry rather than two bare strings: they are both strings in a fixed
// order, which is the pair a caller transposes without the compiler
// noticing.
func splitPR(description string) entry {
	m := prSuffixRE.FindStringSubmatch(description)
	if m == nil {
		return entry{text: description}
	}

	return entry{text: strings.TrimSpace(description[:len(description)-len(m[0])]), pr: m[1]}
}
