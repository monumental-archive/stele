// The rebuild-target population (stele#223): what a caller declared
// to be under rebuild, reconciled against what a release's manifest
// says it published.
//
// It lives beside the repository population because it is the same
// law at a different grain, and the law is easiest to keep in one
// place: the population is DECLARED, it is reconciled against an
// observation BY NAME, an undeclared member produces nothing at all,
// and a declared member the observation cannot account for is loud
// rather than quietly dropped.

package population

import (
	"errors"
	"fmt"
	"slices"

	"github.com/monumental-archive/stele/internal/report"
)

// Artifact is one released build artifact and the target that
// produced it, as the released manifest types it. Target is empty
// only where the manifest carries no target answer at all — a
// release published before targets were typed, or one that never
// typed them — which is a different fact from a target no artifact
// carries, and the two must reach different verdicts.
type Artifact struct {
	Name   string
	SHA256 string
	Target string
}

// TargetScope is the caller's declaration of which build targets a
// rebuild covered — the same values it fed the rebuild matrix,
// stated UP FRONT.
//
// Up front is the whole point. A population derived from what the
// rebuild produced would pass a rebuild that silently produced
// nothing, which is the inversion the reproducibility walk exists to
// catch (stele#96); because the declaration precedes the rebuild, a
// target that produced nothing is a target whose artifacts are
// missing, and missing is loud.
type TargetScope struct {
	// Targets are the declared targets. A set: order carries no
	// meaning, and a name repeated is a caller stating one fact
	// twice.
	Targets []string
}

// Validate refuses a declaration that cannot mean what it says.
//
// The names themselves are never judged. What a target IS belongs to
// the publisher — a platform triple, a runtime major, whatever its
// matrix varies — and a tool that held a vocabulary of them would be
// asserting a fact about the world from one organisation's build
// configuration. That it PARSED is this package's business; what it
// means is not.
func (s TargetScope) Validate() error {
	if len(s.Targets) == 0 {
		return errors.New(
			"population: no target was declared — a declared population of nothing cannot be reconciled" +
				" against any manifest; declare the targets the rebuild covered, or none at all")
	}

	seen := make(map[string]bool, len(s.Targets))

	for i, name := range s.Targets {
		if name == "" {
			return fmt.Errorf("population: declared target %d is empty — a target with no name declares"+
				" nothing", i)
		}

		if seen[name] {
			return fmt.Errorf("population: target %q is declared twice — what a rebuild covered is a set",
				name)
		}

		seen[name] = true
	}

	return nil
}

// TargetSet is a resolved rebuild population: the artifacts of the
// declared targets, and the declared targets the release's own typing
// could not account for. It is the ONLY thing a judge receives — a
// judge holds a set, never the means to enumerate one, so a second
// population is unrepresentable rather than merely discouraged.
type TargetSet struct {
	declared   []string
	answered   []string
	unanswered []string
	artifacts  []Artifact
}

// Resolve reconciles the declaration against what the release
// published, in both directions.
//
// An artifact of an UNDECLARED target produces nothing: no artifact
// in the judged set, no finding, no count. That is an exclusion, not
// an exception — nobody claimed to have rebuilt it, so there is
// nothing to say about it, and saying something quieter instead is
// how a class of false findings is born (release-lab v0.26.0: three
// of four artifacts reported missing from a rebuild that was healthy
// and covered one target).
//
// A DECLARED target no artifact carries is the opposite fact and
// stays loud: the caller says it rebuilt something this release does
// not show, so the run cannot judge that target and must report which
// one by name. The two directions may never share a vocabulary.
func (s TargetScope) Resolve(published []Artifact) (*TargetSet, error) {
	// Validated HERE as well as at the caller's flag parse, so this
	// package is total over its own inputs: a package that misbehaves
	// on a hand-built value is one a test cannot exercise honestly.
	if err := s.Validate(); err != nil {
		return nil, err
	}

	declared := make(map[string]bool, len(s.Targets))
	for _, name := range s.Targets {
		declared[name] = true
	}

	set := &TargetSet{declared: slices.Clone(s.Targets)}

	answered := make(map[string]bool, len(s.Targets))

	// In the order the release published them: the judged set carries
	// the manifest's own order, so a verdict reads in the order a
	// reader sees the release.
	for _, a := range published {
		if a.Target == "" || !declared[a.Target] {
			continue
		}

		answered[a.Target] = true

		set.artifacts = append(set.artifacts, a)
	}

	for _, name := range s.Targets {
		if answered[name] {
			set.answered = append(set.answered, name)

			continue
		}

		set.unanswered = append(set.unanswered, name)
	}

	return set, nil
}

// Artifacts are the released artifacts of the declared targets — the
// population a rebuild is judged against.
func (t *TargetSet) Artifacts() []Artifact { return slices.Clone(t.artifacts) }

// Declared are the targets the caller declared under rebuild, in
// declaration order — what a verdict names as the set it was asked to
// judge, whatever the release turned out to answer for.
func (t *TargetSet) Declared() []string { return slices.Clone(t.declared) }

// Unanswered are the declared targets the release's typing does not
// account for, in declaration order. Names, never a count: a count
// cannot say which target went unjudged, and the target that went
// unjudged is the whole finding.
func (t *TargetSet) Unanswered() []string { return slices.Clone(t.unanswered) }

// Population is the coverage claim a judge over this set seals with:
// how many declared targets the release could answer for, against how
// many were declared. A shortfall is CANNOT_JUDGE by the report's
// coverage law — an unseen subject is unchecked, not clean — which is
// exactly the reading a declared target nobody can place deserves.
func (t *TargetSet) Population(detail string) report.Population {
	return report.PopulationAgainstDeclared(len(t.answered), len(t.declared), detail)
}
