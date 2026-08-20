// The enrichment leg: the org's build-enrichment claim, judged as a
// DECLARED obligation. Absent from the policy, no such obligation
// exists and nothing here runs. Declared, a verdict is not proven
// until the claim beside it is — which is the whole point, because a
// signed claim nobody reads is decoration with a signature on it.
//
// Boundary, stated once: this leg proves the claim is BOUND and
// COMPLETE — signed under the verdict identity at the machinery pin,
// over the same subject, naming the resource and source repository
// the policy declares, carrying exactly the declared dependency
// names with well-formed digests. It never re-derives what those
// digests cover: that needs the policy tree at the claimed pin, and
// a check that re-runs the writer's derivation is the writer
// inverted, which passes its own exam. The uris in the predicate are
// what make the values checkable, by anyone, without trusting this.

package verify

import (
	"fmt"
	"slices"

	"github.com/monumental-archive/stele/internal/enrichment"
	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
)

// EnrichmentDemand is what one release's artifacts owe their
// enrichment claims. nil means the obligation is not owed at all
// (pre-epoch history), so "not owed" and "owed nothing extra" cannot
// be confused — the absent-vs-zero discipline the decode types already
// keep, applied to the seam itself.
type EnrichmentDemand struct {
	// ByArtifact maps a subject's asset NAME to the names that
	// subject's class owes on top of the verify policy's universal
	// required set. A subject absent from the map owes nothing
	// class-specific, which is what a stranger's read owes and what an
	// artifact whose class nothing states owes (stele#206).
	//
	// Keyed per artifact because the obligation is: a release's classes
	// describe what it shipped, and holding every artifact to all of
	// them asks one artifact to answer for another's build. Names must
	// live inside the policy's required ∪ permitted — one vocabulary,
	// no second truth (docs/policy-schema.md).
	ByArtifact map[string][]string
}

// forArtifact reports what one subject owes beyond the universal set.
// A nil demand owes nothing extra, which keeps the three states of the
// seam readable at the one place that reads them.
func (d *EnrichmentDemand) forArtifact(name string) []string {
	if d == nil {
		return nil
	}

	return d.ByArtifact[name]
}

// validateDemand refuses an incoherent demand before any subject is
// judged: extras against an undeclared obligation, or extras outside
// the closed set, mean the class declarations and the verify policy
// have become two truths about one vocabulary. That is a defect in
// the POLICIES, not a fact about the release — so it is a refusal of
// the run, distinct in text from any unmet obligation, and it fires
// at the one place that holds both documents.
//
// Every artifact's names are checked, not the first artifact's: a
// vocabulary that has diverged for one class has diverged, and a walk
// that stopped at the first entry would pass whichever release
// happened to list its sound class first.
func validateDemand(e *policy.Enrichment, demand *EnrichmentDemand) error {
	names := demand.demanded()
	if len(names) == 0 {
		return nil
	}

	if e == nil {
		return fmt.Errorf(
			"verify: the demand requires enrichment names %v but the policy declares no build.enrichment — "+
				"a class demands what no obligation covers", names)
	}

	allowed := make(map[string]bool, len(e.Required)+len(e.Permitted))
	for _, n := range e.Required {
		allowed[n] = true
	}

	for _, n := range e.Permitted {
		allowed[n] = true
	}

	for _, n := range names {
		if !allowed[n] {
			return fmt.Errorf(
				"verify: the demand requires enrichment name %q, which the policy neither requires nor permits — "+
					"class expectations and the closed set have diverged", n)
		}
	}

	return nil
}

// demanded is every name the demand asks of any artifact, sorted and
// deduplicated — the vocabulary the closed set is judged against, in
// one spelling so the refusal text does not depend on map order.
func (d *EnrichmentDemand) demanded() []string {
	if d == nil {
		return nil
	}

	var names []string

	for _, owed := range d.ByArtifact {
		names = append(names, owed...)
	}

	slices.Sort(names)

	return slices.Compact(names)
}

// judgeEnrichment proves one subject's enrichment claim. Exactly one
// claim per subject: none means the declared obligation is unmet,
// and two are two answers rather than more evidence — the same rule
// the decision-bearing SBOM selection already takes.
func judgeEnrichment(
	p *policy.Policy, c Coords, s Subject, found []StoredBundle, root verdictRoot, resource string,
	extras []string, bv BundleVerifier,
) (*enrichment.Predicate, error) {
	switch len(found) {
	case 1:
	case 0:
		return nil, fmt.Errorf(
			"verify: %s: the policy declares an enrichment obligation and no enrichment claim covers this subject",
			s.Name)
	default:
		return nil, fmt.Errorf(
			"verify: %s: %d enrichment claims cover this subject — two claims are two answers, not more evidence",
			s.Name, len(found))
	}

	verified, err := bv.Attestation(found[0].Bundle, root.id, s.SHA256)
	if err != nil {
		return nil, fmt.Errorf("verify: %s: enrichment bundle refused: %w", s.Name, err)
	}

	// The commit-level binding, exactly as the verdict beside it: the
	// workflow tree that signed must BE the pinned one.
	if got := verified.Extensions.BuildSignerDigest; got != root.pin {
		return nil, fmt.Errorf("verify: %s: enrichment signed at %q, pin is %q", s.Name, got, root.pin)
	}

	pred, err := enrichmentPredicate(s, verified.Payload, *p.Build.Enrichment.PredicateType)
	if err != nil {
		return nil, err
	}

	if *pred.ResourceURI != resource {
		return nil, fmt.Errorf(
			"verify: %s: enrichment names resource %q, expected %q — facts about another resource are not these facts",
			s.Name, *pred.ResourceURI, resource)
	}

	if srcRepo := expand(*p.Build.SourceRepository, c); *pred.SourceRevision.URI != srcRepo {
		return nil, fmt.Errorf(
			"verify: %s: enrichment binds to source repository %q, expected %q",
			s.Name, *pred.SourceRevision.URI, srcRepo)
	}

	if err := judgeNames(p.Build.Enrichment, extras, pred, s); err != nil {
		return nil, err
	}

	return pred, nil
}

// enrichmentPredicate decodes the VERIFIED payload — never the peek —
// down to a validated predicate.
func enrichmentPredicate(s Subject, payload []byte, predicateType string) (*enrichment.Predicate, error) {
	stmt, err := jsonx.DecodeBytes[intoto.Statement](payload)
	if err != nil {
		return nil, fmt.Errorf("verify: %s: verified payload is not a statement: %w", s.Name, err)
	}

	if verr := stmt.Validate(); verr != nil {
		return nil, fmt.Errorf("verify: %s: %w", s.Name, verr)
	}

	if *stmt.PredicateType != predicateType {
		return nil, fmt.Errorf("verify: %s: verified payload is not an enrichment claim", s.Name)
	}

	pred, err := jsonx.DecodeBytes[enrichment.Predicate](stmt.Predicate)
	if err != nil {
		return nil, fmt.Errorf("verify: %s: enrichment predicate: %w", s.Name, err)
	}

	if err := pred.Validate(); err != nil {
		return nil, fmt.Errorf("verify: %s: %w", s.Name, err)
	}

	return pred, nil
}

// judgeNames holds the declared expectation: required ∪ permitted is
// a CLOSED set, so a claim naming anything outside it is refused —
// a signed false dependency is worse than an omitted one — and every
// required name must appear, or the obligation is unmet.
//
// extras are the per-class half of the obligation (stele#122), taken
// for THIS artifact alone (stele#206): the names its own class owes on
// top of the universal set. validateDemand already proved them a
// subset of the closed set, so they extend only what is required,
// never what is allowed.
func judgeNames(e *policy.Enrichment, extras []string, pred *enrichment.Predicate, s Subject) error {
	allowed := make(map[string]bool, len(e.Required)+len(e.Permitted))
	for _, n := range e.Required {
		allowed[n] = true
	}

	for _, n := range e.Permitted {
		allowed[n] = true
	}

	claimed := make(map[string]bool, len(pred.ResolvedDependencies))

	for _, n := range pred.Names() {
		if !allowed[n] {
			return fmt.Errorf(
				"verify: %s: enrichment claims %q, which the policy neither requires nor permits — "+
					"the declared set is closed", s.Name, n)
		}

		claimed[n] = true
	}

	for _, n := range e.Required {
		if !claimed[n] {
			return fmt.Errorf("verify: %s: enrichment claims no %q, which the policy requires", s.Name, n)
		}
	}

	for _, n := range extras {
		if !claimed[n] {
			return fmt.Errorf(
				"verify: %s: enrichment claims no %q, which this release's evidence classes require of it",
				s.Name, n)
		}
	}

	return nil
}
