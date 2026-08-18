// Package enrichment is the build-enrichment predicate: the build
// facts a platform's own provenance leaves best-effort — the toolbelt
// lock every tool version and checksum derives from, base-image
// digests, the released repository's lockfiles at the attested source
// revision — computed entirely in the verification control plane and
// signed by the identity that computed every byte of them.
//
// SLSA makes resolvedDependencies completeness a SHOULD at every
// level and requires L3 provenance fields to be generated or verified
// by the control plane. That is why these facts live in a COMPANION
// predicate rather than as tenant-generated fields inside the
// platform's envelope: the stock provenance stays unforgeable, and
// the companion carries the identity of whoever computed it.
//
// The predicate TYPE is an org URI and lives in the verify policy;
// this file carries the SHAPE, so the emitter and the verifier cannot
// disagree about what one is. Every identified thing here is an
// in-toto ResourceDescriptor — one vocabulary, so one digest rule
// judges all of them.
package enrichment

import (
	"errors"
	"fmt"

	"github.com/monumental-archive/stele/internal/intoto"
)

// Predicate is one build-enrichment claim.
type Predicate struct {
	// ResourceURI names the artifact set these facts describe — the
	// same resource the verdict beside them names.
	ResourceURI *string `json:"resourceUri"`
	// SourceRevision is the commit the enriched build's source was
	// at: uri names the repository, digest carries gitCommit.
	SourceRevision *intoto.ResourceDescriptor `json:"sourceRevision"`
	// Policy is the policy tree these facts were read from, by uri
	// and digest — what makes the claim independently re-derivable.
	Policy *intoto.ResourceDescriptor `json:"policy"`
	// ResolvedDependencies are the claimed build inputs, each named
	// and addressed so a stranger can fetch and re-hash it.
	ResolvedDependencies []intoto.ResourceDescriptor `json:"resolvedDependencies"`
}

// Validate refuses a predicate that cannot be judged at all. It is
// the shape's own rule and knows nothing of any org's expectations —
// which names are owed is the verify policy's declaration, checked
// against a predicate that already passed this.
func (p *Predicate) Validate() error {
	if p.ResourceURI == nil || *p.ResourceURI == "" {
		return errors.New("enrichment: resourceUri is absent — the claim names no artifact")
	}

	if err := validateRevision(p.SourceRevision); err != nil {
		return err
	}

	if err := validateTree(p.Policy); err != nil {
		return err
	}

	// The empty claim is the failure this predicate exists to make
	// impossible: a signed document resolving nothing is decoration
	// with a signature on it.
	if len(p.ResolvedDependencies) == 0 {
		return errors.New("enrichment: resolvedDependencies is empty — an enrichment resolving nothing claims nothing")
	}

	for i := range p.ResolvedDependencies {
		if err := validateDependency(&p.ResolvedDependencies[i]); err != nil {
			return fmt.Errorf("enrichment: resolvedDependencies[%d]: %w", i, err)
		}
	}

	return nil
}

// validateRevision holds the binding that makes every other fact
// mean something: which commit these inputs were resolved at.
func validateRevision(rd *intoto.ResourceDescriptor) error {
	if rd == nil {
		return errors.New("enrichment: sourceRevision is absent — facts unbound to a commit describe no build")
	}

	if rd.URI == nil || *rd.URI == "" {
		return errors.New("enrichment: sourceRevision.uri is absent — the commit belongs to no named repository")
	}

	if rd.Digest[intoto.AlgGitCommit] == "" {
		return errors.New("enrichment: sourceRevision carries no gitCommit digest — a branch name is not a revision")
	}

	if err := intoto.ValidateDigest(rd.Digest); err != nil {
		return fmt.Errorf("enrichment: sourceRevision: %w", err)
	}

	return nil
}

// validateTree holds the policy pin: uri and digest both, because a
// ref alone moves and a digest alone cannot be fetched.
func validateTree(rd *intoto.ResourceDescriptor) error {
	if rd == nil {
		return errors.New("enrichment: policy is absent — a claim that cannot say what it was rendered under is unauditable")
	}

	if rd.URI == nil || *rd.URI == "" {
		return errors.New("enrichment: policy.uri is absent")
	}

	if rd.Digest[intoto.AlgSHA256] == "" {
		return errors.New("enrichment: policy carries no sha256 digest — a moving ref pins nothing")
	}

	if err := intoto.ValidateDigest(rd.Digest); err != nil {
		return fmt.Errorf("enrichment: policy: %w", err)
	}

	return nil
}

// validateDependency requires a name and an address. The name is what
// a policy declares expectations against; the uri is what makes the
// claim checkable by someone who trusts none of this. A digest is
// optional by design — an entry may be identified by uri alone when
// its immutability rests on another entry in the same predicate (a
// digested mapping file naming an image), and whether that is good
// enough is the org's call, not the shape's.
func validateDependency(rd *intoto.ResourceDescriptor) error {
	if rd.Name == nil || *rd.Name == "" {
		return errors.New("name is absent — an unnamed claim cannot be declared or missed")
	}

	if rd.URI == nil || *rd.URI == "" {
		return errors.New("uri is absent — a claim nobody can fetch is not evidence")
	}

	if err := intoto.ValidateDigest(rd.Digest); err != nil {
		return err
	}

	return nil
}

// Revision is the commit this enrichment's inputs were resolved at.
// Safe after Validate, which is the only way one of these is judged.
func (p *Predicate) Revision() string { return p.SourceRevision.Digest[intoto.AlgGitCommit] }

// Names lists the claimed dependency names in claim order — what a
// policy's declared expectations are judged against.
func (p *Predicate) Names() []string {
	out := make([]string, 0, len(p.ResolvedDependencies))
	for i := range p.ResolvedDependencies {
		out = append(out, *p.ResolvedDependencies[i].Name)
	}

	return out
}
