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

	"github.com/monumental-archive/stele/internal/enrichment"
	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
)

// judgeEnrichment proves one subject's enrichment claim. Exactly one
// claim per subject: none means the declared obligation is unmet,
// and two are two answers rather than more evidence — the same rule
// the decision-bearing SBOM selection already takes.
func judgeEnrichment(
	p *policy.Policy, c Coords, s Subject, found []StoredBundle, root verdictRoot, resource string,
	bv BundleVerifier,
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

	if err := judgeNames(p.Build.Enrichment, pred, s); err != nil {
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
// The per-class half of this obligation (stele#86: names a specific
// evidence class owes, declared where the class declaration already
// lives) extends the required set here, at this one place.
func judgeNames(e *policy.Enrichment, pred *enrichment.Predicate, s Subject) error {
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

	return nil
}
