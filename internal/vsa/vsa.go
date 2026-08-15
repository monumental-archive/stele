// Package vsa implements the SLSA Verification Summary Attestation
// predicate — the verdict this tool both verifies (a consumer's read)
// and, on the emit side, renders. Spec: slsa.dev/verification_summary
// (v1, read against SLSA v1.2). Format rules the spec fixes live
// here; which values are acceptable is the policy's business.
package vsa

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/intoto"
)

// PredicateType is the spec's predicate type URI.
const PredicateType = "https://slsa.dev/verification_summary/v1"

// The two verification results the spec admits.
const (
	ResultPassed = "PASSED"
	ResultFailed = "FAILED"
)

// SpecVersion is the SLSA version this tool's emitted verdicts claim
// — pinned once, in the package that owns the predicate.
const SpecVersion = "1.2"

// Predicate is the VSA predicate — decoded strictly, and also the
// shape both of the org's VSA kinds are EMITTED through (the one
// assembler: New below). One type owning the field set is what makes
// a field added for one kind structurally present in the other.
// omitempty is encode-side only: optional absent fields are absent,
// never null.
type Predicate struct {
	Verifier           *Verifier                   `json:"verifier"`
	TimeVerified       *string                     `json:"timeVerified,omitempty"`
	ResourceURI        *string                     `json:"resourceUri"`
	Policy             *intoto.ResourceDescriptor  `json:"policy"`
	InputAttestations  []intoto.ResourceDescriptor `json:"inputAttestations,omitempty"`
	VerificationResult *string                     `json:"verificationResult"`
	VerifiedLevels     []string                    `json:"verifiedLevels"`
	DependencyLevels   map[string]int              `json:"dependencyLevels,omitempty"`
	SlsaVersion        *string                     `json:"slsaVersion,omitempty"`
}

// Verifier identifies who computed the verdict. ID is required; in
// this org it is a tautology with the signing certificate (the
// second root of trust), and the trust code asserts that equality.
type Verifier struct {
	ID      *string           `json:"id"`
	Version map[string]string `json:"version,omitempty"`
}

// New assembles a predicate this tool vouches for: verifier, time,
// resource, a policy pinned by uri AND commit digest, the result and
// levels, slsaVersion pinned to SpecVersion — validated before it is
// returned, so an emitted predicate that would fail this package's
// own consumer read is unrepresentable. Track-specific extras
// (inputAttestations) are set by the caller on the result.
func New(
	verifierID, timeVerified, resourceURI, policyURI, policyGitCommit, result string, levels []string,
) (*Predicate, error) {
	if !gitCommitRE.MatchString(policyGitCommit) {
		return nil, fmt.Errorf("vsa: policy digest %q is not a full commit digest — the spec's policy pin", policyGitCommit)
	}

	if _, err := time.Parse(time.RFC3339, timeVerified); err != nil {
		return nil, fmt.Errorf("vsa: timeVerified: %w", err)
	}

	pin := intoto.ResourceDescriptor{URI: &policyURI, Digest: map[string]string{intoto.AlgGitCommit: policyGitCommit}}
	p := &Predicate{
		Verifier:           &Verifier{ID: &verifierID},
		TimeVerified:       &timeVerified,
		ResourceURI:        &resourceURI,
		Policy:             &pin,
		VerificationResult: &result,
		VerifiedLevels:     levels,
	}
	ver := SpecVersion
	p.SlsaVersion = &ver

	if err := p.Validate(); err != nil {
		return nil, err
	}

	return p, nil
}

// gitCommitRE is the policy pin's shape — a full commit digest.
var gitCommitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// slsaLevelRE is the spec's SlsaResult syntax for SLSA-prefixed
// values; anything not SLSA_-prefixed is a custom value and legal.
var slsaLevelRE = regexp.MustCompile(`^SLSA_([A-Z]+)_LEVEL_(\d+|UNEVALUATED)$`)

// versionRE is the spec's <MAJOR>.<MINOR> for slsaVersion.
var versionRE = regexp.MustCompile(`^\d+\.\d+$`)

// Validate refuses a predicate that breaks the spec's format rules:
// required fields absent, a verificationResult outside the two
// admitted values, malformed SLSA_ level syntax, more than one level
// for the same track, or a malformed slsaVersion. Whether the values
// are the EXPECTED ones is the caller's policy comparison, not this.
func (p *Predicate) Validate() error {
	if p.Verifier == nil || p.Verifier.ID == nil || *p.Verifier.ID == "" {
		return errors.New("vsa: verifier.id is absent or empty")
	}

	if p.ResourceURI == nil || *p.ResourceURI == "" {
		return errors.New("vsa: resourceUri is absent or empty")
	}

	if p.Policy == nil || p.Policy.URI == nil || *p.Policy.URI == "" {
		return errors.New("vsa: policy.uri is absent or empty")
	}

	switch {
	case p.VerificationResult == nil:
		return errors.New("vsa: verificationResult is absent")
	case *p.VerificationResult != ResultPassed && *p.VerificationResult != ResultFailed:
		return fmt.Errorf("vsa: verificationResult %q is neither %s nor %s",
			*p.VerificationResult, ResultPassed, ResultFailed)
	}

	if p.VerifiedLevels == nil {
		return errors.New("vsa: verifiedLevels is absent")
	}

	if err := validateLevels(p.VerifiedLevels); err != nil {
		return err
	}

	if p.SlsaVersion != nil && !versionRE.MatchString(*p.SlsaVersion) {
		return fmt.Errorf("vsa: slsaVersion %q is not <MAJOR>.<MINOR>", *p.SlsaVersion)
	}

	return nil
}

// validateLevels enforces the SlsaResult rules: SLSA_-prefixed values
// carry the exact track/level syntax and each track appears at most
// once (a level implies all lower ones, so two claims for one track
// are a contradiction, not emphasis). Custom values pass untouched.
func validateLevels(levels []string) error {
	tracks := make(map[string]bool, len(levels))

	for _, l := range levels {
		if !strings.HasPrefix(l, "SLSA_") {
			if l == "" {
				return errors.New("vsa: verifiedLevels carries an empty value")
			}

			continue
		}

		m := slsaLevelRE.FindStringSubmatch(l)
		if m == nil {
			return fmt.Errorf("vsa: verifiedLevels value %q is not SLSA_<TRACK>_LEVEL_<N|UNEVALUATED>", l)
		}

		if tracks[m[1]] {
			return fmt.Errorf("vsa: verifiedLevels claims track %s more than once", m[1])
		}

		tracks[m[1]] = true
	}

	return nil
}

// Level reports the SLSA level claimed for one track (for example
// "BUILD" or "SOURCE"), or absence. Validate first; this assumes the
// one-per-track rule already holds.
func (p *Predicate) Level(track string) (string, bool) {
	prefix := "SLSA_" + track + "_LEVEL_"
	for _, l := range p.VerifiedLevels {
		if strings.HasPrefix(l, prefix) {
			return l, true
		}
	}

	return "", false
}
