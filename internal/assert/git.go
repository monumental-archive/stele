// The git read surface the tag and chain audits judge through, and
// the one the full-depth leg resolves its pins with (stele#384). Git
// is the only way stele reads git objects: the CLI binds these to one
// fetch per repository (internal/gitfetch); tests script them.

package assert

import (
	"strconv"

	"github.com/monumental-archive/stele/internal/gitrepo"
	"github.com/monumental-archive/stele/internal/report"
)

// GitReader is the per-repository git surface the tag and chain
// audits read: tag refs, the one tag resolution, the ledger, commit
// facts and ancestry. A separate seam from gh.Forge — none of it is a
// forge read, and a fake that scripts tags should not have to script
// releases.
type GitReader interface {
	// TagRefs lists every tag ref of one repository.
	TagRefs(owner, repo string) ([]gitrepo.TagRef, error)
	// ResolveTag resolves one tag ref to its target: an annotated tag
	// through its object, which is returned beside it; a lightweight
	// one directly, with a nil object.
	ResolveTag(owner, repo string, ref gitrepo.TagRef) (string, *gitrepo.TagObject, error)
	// ChainNotes reads every note blob on the given notes ref. An
	// absent ref is an empty chain — an answer, not an error.
	ChainNotes(owner, repo, notesRef string) ([]gitrepo.ChainNote, error)
	// CommitMeta reads one commit's parents and committer time.
	CommitMeta(owner, repo, rev string) (*gitrepo.CommitMeta, error)
	// IsAncestor reports whether base is an ancestor of (or is) head.
	IsAncestor(owner, repo, base, head string) (bool, error)
	// Reachable reports whether a commit is reachable from some branch
	// or some tag: false means no branch and no tag reaches it, so it is
	// an ancestor of no tag's target. Absence is typed; a reader that
	// cannot tell refuses rather than answer false.
	Reachable(owner, repo, rev string) (bool, error)
}

// TagResolver resolves one release tag to the commit it targets — the
// pin the full-depth leg verifies identities against. Bound to the
// same resolution the tag audit reads every tag through, so the two
// cannot come to disagree about what a tag points at.
type TagResolver interface {
	TagCommit(owner, repo, tag string) (string, error)
}

// fetchReporter is what a reader that fetched may report about its
// fetches: how many remotes ignored the commits-only filter.
type fetchReporter interface {
	FilterIgnored() int
}

// fetchFacts states, beside the verdict, what the run's fetches saw.
// A reader that did not fetch (a test's script) states nothing.
func fetchFacts(r any) []report.Fact {
	fr, ok := r.(fetchReporter)
	if !ok {
		return nil
	}

	return []report.Fact{{Name: "gitFilterIgnored", Value: strconv.Itoa(fr.FilterIgnored())}}
}
