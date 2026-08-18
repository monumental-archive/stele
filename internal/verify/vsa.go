// VSA verification: the consumer's read of a published verdict,
// implementing the VSA spec's seven-step procedure against the
// policy's expectations. The verdict identity is the org's second
// root of trust; releases the policy grandfathers verify under their
// enumerated legacy root, never under whichever root happens to work.

package verify

import (
	"errors"
	"fmt"
	"slices"

	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/vsa"
)

// VSAVerdict is the proof that a published verdict verified for
// every subject. Constructor: VSA, alone.
type VSAVerdict struct {
	levels   []string
	subjects int
}

// Levels reports the verified levels the VSA claimed — already
// checked to contain the policy's target.
func (v *VSAVerdict) Levels() []string {
	out := make([]string, len(v.levels))
	copy(out, v.levels)

	return out
}

// VSA verifies the published verdict over every subject of one
// release: for each subject, at least one VSA bundle must verify
// under the verdict identity with that subject's digest, name the
// expected resource, report PASSED, and claim the target level.
func VSA(
	p *policy.Policy, c Coords, subjects []Subject, pins Pins,
	store Store, bv BundleVerifier, log Logf,
) (*VSAVerdict, error) {
	switch {
	case p.Trust.Verdict == nil:
		return nil, errors.New("verify: the policy declares no trust.verdict — vsa verification needs one")
	case p.Build == nil:
		return nil, errors.New("verify: the policy declares no build section — vsa verification needs one")
	}

	if err := validateInputs(c, subjects, pins); err != nil {
		return nil, err
	}

	root := verdictIdentity(p, c, pins)
	resource := expand(*p.Build.ResourceURI, c)

	var levels []string

	for _, s := range subjects {
		got, err := vsaForSubject(p, c.Slug(), s, root, resource, store, bv)
		if err != nil {
			return nil, err
		}

		levels = got
	}

	log("verify: vsa %s@%s: verdict verified over %d subject(s), levels %v", c.Slug(), c.Tag, len(subjects), levels)

	return &VSAVerdict{levels: levels, subjects: len(subjects)}, nil
}

// verdictIdentity resolves which root of trust this release's
// verdict verifies under: the current verifier, or — for a release
// the policy enumerates as grandfathered history — its named legacy
// signer. A release absent from the list verifies under the current
// root or refuses, loudly; try-each is unrepresentable.
func verdictIdentity(p *policy.Policy, c Coords, pins Pins) verdictRoot {
	workflow, pin := expandWorkflow(*p.Trust.Verdict.VerifierWorkflow, c), pins.Machinery

	for _, lv := range p.Trust.Verdict.LegacyVerdicts {
		if *lv.Repository == c.Slug() && *lv.Tag == c.Tag {
			workflow, pin = expandWorkflow(*lv.SignerWorkflow, c), pins.Signer

			break
		}
	}

	// The claimed verifier is the org verifier in BOTH epochs: the
	// grandfathered verdicts were signed by the org signer on the
	// verifier's behalf, and their predicates already named
	// verify-release as verifier.id. Only the signing identity and
	// its pin switch on the legacy lookup — shadow mode on the real
	// pre-v1.14.0 releases (.github v1.13.0, release-lab v0.20.1) is
	// the proof of this shape.
	return verdictRoot{
		id:  trust.Identity{SAN: workflowSAN(workflow, identityRef(workflow, c, pin)), Issuer: *p.Issuer},
		pin: pin,
		uri: serverURL + "/" + expandWorkflow(*p.Trust.Verdict.VerifierWorkflow, c),
	}
}

// verdictRoot pairs the trust identity a verdict must verify under,
// the commit pin its certificate must carry, and the verifier URI
// its predicate must claim — the first two switch together on the
// legacy lookup, the claim never does.
type verdictRoot struct {
	id  trust.Identity
	pin string
	uri string
}

// vsaForSubject finds and proves one subject's verdict, returning
// the verified levels. A VSA-typed bundle that fails verification is
// a refusal, never a pass-over.
func vsaForSubject(
	p *policy.Policy, slug string, s Subject, root verdictRoot, resource string,
	store Store, bv BundleVerifier,
) ([]string, error) {
	bundles, err := store.Bundles(slug, s.SHA256)
	if err != nil {
		return nil, fmt.Errorf("verify: %s: no attestation retrievable: %w", s.Name, err)
	}

	for _, sb := range bundles {
		stmtPeek, err := bv.Peek(sb.Bundle)
		if err != nil {
			return nil, fmt.Errorf("verify: %s: unreadable bundle in the store: %w", s.Name, err)
		}

		peek, err := jsonx.DecodeBytes[intoto.Statement](stmtPeek)
		if err != nil {
			return nil, fmt.Errorf("verify: %s: bundle payload is not a statement: %w", s.Name, err)
		}

		if peek.PredicateType == nil || *peek.PredicateType != vsa.PredicateType {
			continue
		}

		return judgeVSA(p, s, sb, root, resource, bv)
	}

	return nil, fmt.Errorf("verify: %s: no verdict found for this subject", s.Name)
}

// judgeVSA runs the spec's steps over one bundle: signature and
// subject digest (the trust layer binds both), predicate type,
// verifier identity as a tautology with the certificate, resource,
// result, and levels.
func judgeVSA(
	p *policy.Policy, s Subject, sb StoredBundle, root verdictRoot, resource string,
	bv BundleVerifier,
) ([]string, error) {
	verified, err := bv.Attestation(sb.Bundle, root.id, s.SHA256)
	if err != nil {
		return nil, fmt.Errorf("verify: %s: verdict bundle refused: %w", s.Name, err)
	}

	// The commit-level binding, independent of how the SAN spells the
	// ref: the workflow tree that signed must BE the pinned one.
	if got := verified.Extensions.BuildSignerDigest; got != root.pin {
		return nil, fmt.Errorf("verify: %s: verdict signed at %q, pin is %q", s.Name, got, root.pin)
	}

	stmt, err := jsonx.DecodeBytes[intoto.Statement](verified.Payload)
	if err != nil {
		return nil, fmt.Errorf("verify: %s: verified payload is not a statement: %w", s.Name, err)
	}

	if verr := stmt.Validate(); verr != nil {
		return nil, fmt.Errorf("verify: %s: %w", s.Name, verr)
	}

	if *stmt.PredicateType != vsa.PredicateType {
		return nil, fmt.Errorf("verify: %s: verified payload is not a verification summary", s.Name)
	}

	pred, err := jsonx.DecodeBytes[vsa.Predicate](stmt.Predicate)
	if err != nil {
		return nil, fmt.Errorf("verify: %s: vsa predicate: %w", s.Name, err)
	}

	if err := pred.Validate(); err != nil {
		return nil, fmt.Errorf("verify: %s: %w", s.Name, err)
	}

	// The spec's step 4, and the org's #264 design: verifier.id must
	// BE the identity that signed — asserted, not taken on faith.
	if *pred.Verifier.ID != root.uri {
		return nil, fmt.Errorf("verify: %s: verifier.id %q is not the signing identity %q",
			s.Name, *pred.Verifier.ID, root.uri)
	}

	if *pred.ResourceURI != resource {
		return nil, fmt.Errorf(
			"verify: %s: verdict names resource %q, expected %q — a VSA naming another resource is rejected",
			s.Name, *pred.ResourceURI, resource)
	}

	if *pred.VerificationResult != vsa.ResultPassed {
		return nil, fmt.Errorf("verify: %s: verificationResult is %q, not %s",
			s.Name, *pred.VerificationResult, vsa.ResultPassed)
	}

	// The spec's step 7 verbatim: verifiedLevels contains the
	// expected value. The one-per-track rule already held above, so
	// containment cannot be a lower level smuggled beside a higher.
	want := *p.Build.TargetLevel
	if !slices.Contains(pred.VerifiedLevels, want) {
		return nil, fmt.Errorf("verify: %s: verifiedLevels does not claim %s", s.Name, want)
	}

	return pred.VerifiedLevels, nil
}
