// Property evaluators: the universal half of the charter's division.
// An org DECLARES which properties it claims and since when; this file
// carries the pure functions that PROVE some of them from evidence
// anyone holds. Zero org vocabulary — an evaluator that needed a
// pattern from policy to find its evidence would be the extractor the
// disabled-rule law refuses, and the fix for that is always to move
// the evidence, never to write the extractor.
//
// The asymmetry is the point, and it mirrors the report package's
// declared-versus-derived exceptions: a property the SCS signed for is
// ATTESTED, a property this code recomputed is PROVEN, and a claim an
// evaluator REFUTES is a finding rather than a quieter level. A signed
// statement contradicted by the evidence it describes is a defect in
// the evidence, not a smaller amount of it.

package level

import (
	"fmt"
	"time"

	"github.com/monumental-archive/stele/internal/convcommit"
)

// Revision is one revision as an evaluator reads it: enough to judge
// the shape of a history, and nothing about its contents.
type Revision struct {
	// ID is the revision identifier.
	ID string
	// Subject is the first line of the commit message.
	Subject string
	// Parents is how many parents the revision has — one for a
	// squashed or rebased commit, two or more for a merge.
	Parents int
	// Time is the revision's commit time.
	Time time.Time
}

// History is the evidence surface evaluators read. It is deliberately
// one method: an evaluator that needed to go back to the repository
// for more would be a walk, and walks belong to the engine.
type History interface {
	// Revisions lists the branch's revisions from the tip back to the
	// oldest revision at or after since, newest first. An empty result
	// means the window holds no revisions — an answer, not an error.
	Revisions(ref string, since time.Time) ([]Revision, error)
}

// Evaluator proves one property over a continuity window. Pure: it
// receives the revisions and returns a judgment, so every branch of
// every evaluator is reachable from a table test with no repository.
type Evaluator interface {
	// Name is the policy-facing name of this evaluator.
	Name() string
	// Evaluate reports whether the property holds over these
	// revisions, and why. The reason is required in both directions:
	// a proof that cannot say what it proved is not evidence.
	Evaluate(revs []Revision) (bool, string)
}

// evaluators is the closed built-in vocabulary. A policy naming
// anything else is refused at use — silently ignoring an unknown
// evaluator would turn a typo into an unproven property that still
// reads as claimed.
//
//nolint:gochecknoglobals // the vocabulary is a constant; Go has no const map
var evaluators = map[string]Evaluator{
	linearHistory{}.Name():       linearHistory{},
	conventionalHistory{}.Name(): conventionalHistory{},
}

// EvaluatorFor returns the built-in of that name.
//
//nolint:ireturn // the vocabulary is a set of behaviours; an interface IS the return
func EvaluatorFor(name string) (Evaluator, bool) {
	e, ok := evaluators[name]

	return e, ok
}

// EvaluatorNames lists the built-in vocabulary, for error messages
// that tell a policy author what they may have meant.
func EvaluatorNames() []string {
	return []string{linearHistory{}.Name(), conventionalHistory{}.Name()}
}

// linearHistory proves that every revision in the window has exactly
// one parent.
//
// This is the consequence of the squash-merge control the spec's own
// example controls require ("Every revision reachable from a branch
// was approved"): with a standard merge commit, every unreviewed
// commit on the topic branch becomes reachable from the protected
// branch through the second parent, and a clone plus a reset lands on
// code no one approved. One parent per revision is that control's
// observable effect, and it is readable from git by anyone.
type linearHistory struct{}

func (linearHistory) Name() string { return "linear-history" }

//nolint:gocritic // unnamedResult: held then why, the Evaluator contract
func (linearHistory) Evaluate(revs []Revision) (bool, string) {
	for _, r := range revs {
		if r.Parents > 1 {
			return false, fmt.Sprintf(
				"revision %.12s has %d parents — a merge commit makes every unreviewed topic-branch"+
					" revision reachable from this branch", r.ID, r.Parents)
		}
	}

	return true, fmt.Sprintf("every one of %d revision(s) in the window has a single parent", len(revs))
}

// conventionalHistory proves that every revision's subject parses as a
// conventional commit.
//
// Universal by construction: Conventional Commits is a public
// specification, and this evaluator judges only whether the subject
// conforms to it. WHICH types and scopes an organization allows is
// that repository's own commit configuration, enforced in its own
// gate — reading it here would drag org vocabulary into a universal
// judge for no gain.
type conventionalHistory struct{}

func (conventionalHistory) Name() string { return "conventional-history" }

//nolint:gocritic // unnamedResult: held then why, the Evaluator contract
func (conventionalHistory) Evaluate(revs []Revision) (bool, string) {
	for _, r := range revs {
		if _, err := convcommit.Parse(r.Subject); err != nil {
			return false, fmt.Sprintf("revision %.12s: %v", r.ID, err)
		}
	}

	return true, fmt.Sprintf("every one of %d revision(s) in the window parses as a conventional commit", len(revs))
}
