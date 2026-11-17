// This file: the provenance-verified judgment of one first-party base
// (stele#402) — the ONE definition the corpus walk (assert evidence)
// and the build-time gate (`stele verify base`) both apply, so the two
// cannot come to disagree about what approves a base.

package assert

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/monumental-archive/stele/internal/baseimage"
)

// FirstPartyRunner is the runner environment a first-party base must
// have been built on: GitHub's hosted runners, the Fulcio extension's
// own value. A base built on a self-hosted runner is refused — the
// mechanism's decided stance (stele#402), as the canon's shell held it.
const FirstPartyRunner = "github-hosted"

// JudgeFirstParty judges one reference under this provenance-verified
// scope: the pin read (a tag and a digest, both required), the source
// ref derived from the tag by the scope's rules, and the provenance
// verified under the scope's signer workflow at that ref, from the
// owner the prefix names, on a hosted runner. diverge records what is
// wrong with the base; the returned ref is where the base was produced
// ("" when it was not approved), and the error is a read this run
// could not make — the walk's blind, never a finding.
//
// The caller has already decided the reference is under the scope's
// prefix; a reference outside it is another judgment's, or none.
func (s *BaseImageScope) JudgeFirstParty(ref string, att Attestor, diverge func(string)) (string, error) {
	rules, err := s.RefRules()
	if err != nil {
		return "", fmt.Errorf("assert: base scope %s %w", *s.Name, err)
	}

	pin, err := baseimage.ParsePin(ref)
	if err != nil {
		diverge(err.Error())

		return "", nil
	}

	produced, err := baseimage.DeriveRef(pin, rules)
	if err != nil {
		diverge(err.Error())

		return "", nil
	}

	candidate := Candidate{Workflow: &WorkflowCandidate{
		Workflow: serverURL + "/" + *s.SignerWorkflow,
		Owner:    publisherOwner(*s.RegistryPrefix),
		Ref:      produced,
		Runner:   FirstPartyRunner,
	}}

	verr := att.Verify(publisherOwner(*s.RegistryPrefix), publisherRepo(ref, *s.RegistryPrefix),
		pin.Digest, []Candidate{candidate}, *s.PredicateType)

	switch {
	case verr == nil:
		return produced, nil
	case unseen(verr):
		return "", blind(scopeAssertion(s), ref, "provenance attestations", verr)
	}

	diverge(fmt.Sprintf("no %s attestation verifies for these bytes at %s — a first-party base is verified"+
		" before it is instantiated (.github#715): %v", *s.PredicateType, produced, verr))

	return "", nil
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

// Covers reports whether a reference is under this scope's prefix.
func (s *BaseImageScope) Covers(ref string) bool {
	return s.RegistryPrefix != nil && strings.HasPrefix(ref, *s.RegistryPrefix)
}
