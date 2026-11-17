// This file: the judgment of one first-party base under a scope that
// claims it by prefix — the ONE definition per kind that the corpus
// walk (assert evidence) and the build-time gate (`stele verify base`)
// both apply, so the two cannot come to disagree about what approves a
// base.

package assert

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/monumental-archive/stele/internal/baseimage"
)

// FirstPartyRunner is the runner environment a shared-signer base must
// have been built on: GitHub's hosted runners, the Fulcio extension's
// own value. A base built on a self-hosted runner is refused — the
// mechanism's decided stance (stele#402), as the canon's shell held it.
const FirstPartyRunner = "github-hosted"

// Approval is what approved one first-party base, named by the fact
// its kind established: the source ref a shared-signer base was
// produced at, or the identity a provenance-verified base's provenance
// verified under. The zero Approval approved nothing.
type Approval struct {
	Fact  string
	Value string
}

// The facts an approval rests on.
const (
	approvalProduced = "produced"
	approvalIdentity = "identity"
)

// Approved reports whether anything approved the base.
func (a Approval) Approved() bool { return a.Value != "" }

// String renders the approval for a log line.
func (a Approval) String() string {
	if a.Fact == approvalProduced {
		return "produced at " + a.Value
	}

	return "under " + a.Value
}

// JudgeBase judges one reference under this scope, by the scope's
// kind. diverge records what is wrong with the base; the Approval says
// what approved it, zero when nothing did; the error is a read this
// run could not make — the walk's blind, never a finding.
//
// The caller has already decided the reference is under the scope's
// prefix; a reference outside it is another judgment's, or none. A
// pin-file scope judges no single reference: its subjects are its pin
// file's, read whole by the walk.
func (s *BaseImageScope) JudgeBase(ref string, att Attestor, diverge func(string)) (Approval, error) {
	switch *s.Mechanism {
	case MechanismProvenanceVerified:
		return s.judgeProvenance(ref, att, diverge)
	case MechanismSharedSigner:
		return s.judgeSharedSigner(ref, att, diverge)
	case MechanismPinFile:
	}

	return Approval{}, fmt.Errorf("assert: base scope %s: the %s mechanism judges no single reference",
		*s.Name, *s.Mechanism)
}

// judgeProvenance proves a base carries provenance from the identity
// its own pin implies. Nothing here is a literal: the expected
// identity is expanded out of the reference, so the identity demanded
// travels with the pin that names it. The publishing repository is
// read off the reference path after the prefix.
func (s *BaseImageScope) judgeProvenance(ref string, att Attestor, diverge func(string)) (Approval, error) {
	// Compiled here rather than assumed: policy load already refused
	// an unparsable pattern, and a walk that PANICS on one instead of
	// refusing would be the wrong failure at the wrong altitude.
	re, err := regexp.Compile(*s.PinPattern)
	if err != nil {
		return Approval{}, fmt.Errorf("assert: base scope %s pinPattern: %w", *s.Name, err)
	}

	idx := re.FindStringSubmatchIndex(ref)
	if idx == nil {
		// The identity is derived from the pin, so a pin the
		// pattern cannot read leaves nothing to demand. Fail
		// closed: an unreadable pin is not an approved one.
		diverge("the pinned reference does not match this scope's pinPattern," +
			" so the identity that should have published it cannot be derived")

		return Approval{}, nil
	}

	identity := string(re.ExpandString(nil, *s.Identity, ref, idx))
	if identity == "" {
		diverge("this scope's identity template expands to nothing for the pinned reference")

		return Approval{}, nil
	}

	if verr := att.Verify(
		publisherOwner(*s.RegistryPrefix), publisherRepo(ref, *s.RegistryPrefix), refDigest(ref),
		[]Candidate{{Identity: identity}}, *s.PredicateType,
	); verr != nil {
		if unseen(verr) {
			return Approval{}, blind(scopeAssertion(s), ref, "provenance attestations", verr)
		}

		diverge(fmt.Sprintf("no %s attestation verifies for this base under %s: %v", *s.PredicateType, identity, verr))

		return Approval{}, nil
	}

	return Approval{Fact: approvalIdentity, Value: identity}, nil
}

// judgeSharedSigner judges one reference under a shared-signer scope:
// the pin read (a tag and a digest, both required), the source ref
// derived from the tag by the scope's rules, and the provenance
// verified under the scope's signer workflow at that ref, from the
// owner the prefix names, on a hosted runner.
func (s *BaseImageScope) judgeSharedSigner(ref string, att Attestor, diverge func(string)) (Approval, error) {
	rules, err := s.RefRules()
	if err != nil {
		return Approval{}, fmt.Errorf("assert: base scope %s %w", *s.Name, err)
	}

	pin, err := baseimage.ParsePin(ref)
	if err != nil {
		diverge(err.Error())

		return Approval{}, nil
	}

	produced, err := baseimage.DeriveRef(pin, rules)
	if err != nil {
		diverge(err.Error())

		return Approval{}, nil
	}

	owner := publisherOwner(*s.RegistryPrefix)
	candidate := Candidate{Workflow: &WorkflowCandidate{
		Workflow: serverURL + "/" + *s.SignerWorkflow,
		Owner:    owner,
		Ref:      produced,
		Runner:   FirstPartyRunner,
	}}

	// The owner's whole store: an image is not named after the
	// repository that built it, and the candidate anchors the owner
	// and the ref rather than trusting a name to say whose it is.
	verr := att.Verify(owner, "", pin.Digest, []Candidate{candidate}, *s.PredicateType)

	switch {
	case verr == nil:
		return Approval{Fact: approvalProduced, Value: produced}, nil
	case unseen(verr):
		return Approval{}, blind(scopeAssertion(s), ref, "provenance attestations", verr)
	}

	// Verified BEFORE it is instantiated: a pin proves the bytes did
	// not change, and only this proves they are the right bytes (the
	// canon's .github#715).
	diverge(fmt.Sprintf("no %s attestation verifies for these bytes at %s — a first-party base is verified"+
		" before it is instantiated: %v", *s.PredicateType, produced, verr))

	return Approval{}, nil
}

// RefRules compiles the scope's tag-to-ref convention, refusing a rule
// that cannot be applied: a pattern that does not compile, or is not
// anchored at both ends (an unanchored pattern matches inside a tag it
// was never written for), a ref that is not fully qualified, or a ref
// template naming a group its pattern does not capture.
func (s *BaseImageScope) RefRules() ([]baseimage.RefRule, error) {
	rules := make([]baseimage.RefRule, 0, len(s.Refs))

	for i, r := range s.Refs {
		field := fmt.Sprintf("refs[%d]", i)

		if r.Tag == nil || r.Ref == nil {
			return nil, fmt.Errorf("%s needs a tag and a ref", field)
		}

		if !strings.HasPrefix(*r.Tag, "^") || !strings.HasSuffix(*r.Tag, "$") {
			return nil, fmt.Errorf("%s.tag %q is not anchored (^…$) — an unanchored pattern matches inside a"+
				" tag it was never written for", field, *r.Tag)
		}

		re, err := regexp.Compile(*r.Tag)
		if err != nil {
			return nil, fmt.Errorf("%s.tag: %w", field, err)
		}

		if !strings.HasPrefix(*r.Ref, "refs/") {
			return nil, fmt.Errorf("%s.ref %q is not a fully qualified ref (refs/…)", field, *r.Ref)
		}

		if err := templateNamesGroups(*r.Ref, re); err != nil {
			return nil, fmt.Errorf("%s.ref %w", field, err)
		}

		rules = append(rules, baseimage.RefRule{Tag: re, Ref: *r.Ref})
	}

	return rules, nil
}

// Assertion names the judgment a scope records a reference under: one
// name, shared by the corpus walk and the build-time gate.
func (s *BaseImageScope) Assertion() string { return scopeAssertion(s) }

// Covers reports whether a reference is under this scope's prefix.
func (s *BaseImageScope) Covers(ref string) bool {
	return s.RegistryPrefix != nil && strings.HasPrefix(ref, *s.RegistryPrefix)
}

// Claimant is the first-party scope whose prefix covers a reference,
// nil when none does. Load refuses two scopes declaring one prefix, so
// at most one claims any reference: one reference, one judgment.
func (b *BaseImagesPolicy) Claimant(ref string) *BaseImageScope {
	for i := range b.Scopes {
		if s := &b.Scopes[i]; s.Covers(ref) {
			return s
		}
	}

	return nil
}

// UpstreamFor is the upstream entry naming a reference's image, nil
// when none does. Load refuses one image declared twice, and an image
// under a scope's prefix, so a reference has at most one claimant
// across both lists.
func (b *BaseImagesPolicy) UpstreamFor(ref string) *UpstreamBase {
	for i := range b.Upstream {
		if u := &b.Upstream[i]; u.Covers(ref) {
			return u
		}
	}

	return nil
}
