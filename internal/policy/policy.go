// Package policy decodes and validates the committed verify policy —
// the universality boundary docs/policy-schema.md defines: everything
// org-shaped lives in the policy file, zero org names in this code.
// Every must-be-present field is a pointer so absent and zero never
// conflate (the jsonx contract), and validation refuses nil
// explicitly: a policy field taken on faith would be a verdict input
// taken on faith.
package policy

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// Schema is the one schema version this implementation reads. A newer
// policy is refused, never best-efforted.
const Schema = 1

// Policy is the decoded document. Field semantics live in
// docs/policy-schema.md; this type carries exactly that shape.
type Policy struct {
	Schema *int    `json:"schema"`
	Issuer *string `json:"issuer"`
	Trust  *Trust  `json:"trust"`
	Build  *Build  `json:"build"`
	Source *Source `json:"source"`
}

// Trust names the roots of trust.
type Trust struct {
	Provenance *ProvenanceTrust `json:"provenance"`
	Verdict    *VerdictTrust    `json:"verdict"`
	Decision   *DecisionTrust   `json:"decision"`
}

// ProvenanceTrust is the identity build provenance verifies against.
// The commit-level pin is deliberately not here — it is derived from
// the consuming tree at invocation (docs/policy-schema.md).
type ProvenanceTrust struct {
	SignerWorkflow *string `json:"signerWorkflow"`
}

// VerdictTrust is the identity VSAs verify against, plus the closed
// list of grandfathered releases signed under an earlier root.
type VerdictTrust struct {
	VerifierWorkflow *string         `json:"verifierWorkflow"`
	LegacyVerdicts   []LegacyVerdict `json:"legacyVerdicts"`
}

// LegacyVerdict grandfathers one release whose verdict predates the
// current root. The set is closed history: enumerated, never derived.
type LegacyVerdict struct {
	Repository     *string `json:"repository"`
	Tag            *string `json:"tag"`
	SignerWorkflow *string `json:"signerWorkflow"`
}

// DecisionTrust is the release-decision gate.
type DecisionTrust struct {
	SignerWorkflow     *string `json:"signerWorkflow"`
	PredicateType      *string `json:"predicateType"`
	RequiredConclusion *string `json:"requiredConclusion"`
}

// Build carries the build-track expectations — all four of
// verifying-artifacts' comparisons are named here or in Trust.
type Build struct {
	BuildTypes            map[string]BuildType `json:"buildTypes"`
	ResourceURI           *string              `json:"resourceUri"`
	SourceRepository      *string              `json:"sourceRepository"`
	TargetLevel           *string              `json:"targetLevel"`
	DenySelfHostedRunners *bool                `json:"denySelfHostedRunners"`
}

// BuildType is one accepted buildType's expectations. An empty key
// list rejects every externalParameter; allow-all is unrepresentable.
type BuildType struct {
	ExternalParameterKeys []string `json:"externalParameterKeys"`
}

// Source carries the source-track policy.
type Source struct {
	Identity                *string           `json:"identity"`
	NotesRef                *string           `json:"notesRef"`
	ProvenancePredicateType *string           `json:"provenancePredicateType"`
	PropertyPrefix          *string           `json:"propertyPrefix"`
	ResourceURI             *string           `json:"resourceUri"`
	ProtectedBranches       []ProtectedBranch `json:"protectedBranches"`
	HealedContinuity        *bool             `json:"healedContinuity"`
	UnderclaimLevel         *string           `json:"underclaimLevel"`
	LegacyLeaves            []LegacyLeaf      `json:"legacyLeaves"`
}

// ProtectedBranch is one branch's target level and the properties
// required to claim it.
type ProtectedBranch struct {
	Name               *string            `json:"name"`
	TargetLevel        *string            `json:"targetLevel"`
	RequiredProperties []RequiredProperty `json:"requiredProperties"`
}

// RequiredProperty is one control property and its continuity start.
type RequiredProperty struct {
	Name  *string `json:"name"`
	Since *string `json:"since"`
}

// LegacyLeaf is one ledger member accepted as known history. The
// revision is the full 40-hex identifier — an exception to a
// cryptographic walk is itself named cryptographically.
type LegacyLeaf struct {
	Repository *string `json:"repository"`
	Revision   *string `json:"revision"`
	Reason     *string `json:"reason"`
}

var (
	levelRE    = regexp.MustCompile(`^SLSA_[A-Z]+_LEVEL_\d+$`)
	revisionRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	repoRE     = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
	// workflowRE is owner/repo/path-to-workflow — the identity shape
	// every root of trust names.
	workflowRE    = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+\.ya?ml$`)
	placeholderRE = regexp.MustCompile(`\{[^{}]*\}`)
)

// knownPlaceholder reports membership in the closed template
// vocabulary. A placeholder outside it is a typo that would
// substitute to nothing and then exact-match compare — refused at
// load, not discovered at verify.
func knownPlaceholder(ph string) bool {
	switch ph {
	case "{owner}", "{repo}", "{tag}", "{version}":
		return true
	default:
		return false
	}
}

// Load decodes and validates one policy document. Everything it
// refuses is refused here, before any verification consumes a field.
func Load(r io.Reader) (*Policy, error) {
	p, err := jsonx.Decode[Policy](r)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}

	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}

	return p, nil
}

func (p *Policy) validate() error {
	switch {
	case p.Schema == nil:
		return errors.New("schema is absent")
	case *p.Schema != Schema:
		return fmt.Errorf("schema %d is not the implemented schema %d", *p.Schema, Schema)
	}

	if p.Issuer == nil || !strings.HasPrefix(*p.Issuer, "https://") {
		return errors.New("issuer must be present and https")
	}

	if err := p.validateTrust(); err != nil {
		return err
	}

	if err := p.validateBuild(); err != nil {
		return err
	}

	return p.validateSource()
}

func (p *Policy) validateTrust() error {
	if p.Trust == nil {
		return errors.New("trust is absent")
	}

	if p.Trust.Provenance == nil {
		return errors.New("trust.provenance is absent")
	}

	if err := workflowField("trust.provenance.signerWorkflow", p.Trust.Provenance.SignerWorkflow); err != nil {
		return err
	}

	if p.Trust.Verdict == nil {
		return errors.New("trust.verdict is absent")
	}

	if err := workflowField("trust.verdict.verifierWorkflow", p.Trust.Verdict.VerifierWorkflow); err != nil {
		return err
	}

	for i, lv := range p.Trust.Verdict.LegacyVerdicts {
		if lv.Repository == nil || !repoRE.MatchString(*lv.Repository) {
			return fmt.Errorf("trust.verdict.legacyVerdicts[%d].repository must be owner/repo", i)
		}

		if lv.Tag == nil || *lv.Tag == "" {
			return fmt.Errorf("trust.verdict.legacyVerdicts[%d].tag is absent or empty", i)
		}

		field := fmt.Sprintf("trust.verdict.legacyVerdicts[%d].signerWorkflow", i)
		if err := workflowField(field, lv.SignerWorkflow); err != nil {
			return err
		}
	}

	if p.Trust.Decision == nil {
		return errors.New("trust.decision is absent")
	}

	if err := workflowField("trust.decision.signerWorkflow", p.Trust.Decision.SignerWorkflow); err != nil {
		return err
	}

	if p.Trust.Decision.PredicateType == nil || !strings.HasPrefix(*p.Trust.Decision.PredicateType, "https://") {
		return errors.New("trust.decision.predicateType must be present and an https URI")
	}

	if p.Trust.Decision.RequiredConclusion == nil || *p.Trust.Decision.RequiredConclusion == "" {
		return errors.New("trust.decision.requiredConclusion is absent or empty")
	}

	return nil
}

func (p *Policy) validateBuild() error {
	if p.Build == nil {
		return errors.New("build is absent")
	}

	if len(p.Build.BuildTypes) == 0 {
		return errors.New("build.buildTypes is absent or empty — a verifier accepting no buildType verifies nothing")
	}

	for uri, bt := range p.Build.BuildTypes {
		if !strings.HasPrefix(uri, "https://") {
			return fmt.Errorf("build.buildTypes key %q is not an https URI", uri)
		}

		// nil and empty are different answers here: empty is the
		// explicit reject-all, nil is a question never answered.
		if bt.ExternalParameterKeys == nil {
			return fmt.Errorf("build.buildTypes[%q].externalParameterKeys is absent", uri)
		}
	}

	if err := templateField("build.resourceUri", p.Build.ResourceURI); err != nil {
		return err
	}

	if err := templateField("build.sourceRepository", p.Build.SourceRepository); err != nil {
		return err
	}

	if err := levelField("build.targetLevel", p.Build.TargetLevel); err != nil {
		return err
	}

	if p.Build.DenySelfHostedRunners == nil {
		return errors.New("build.denySelfHostedRunners is absent — the stance is declared, never defaulted")
	}

	return nil
}

func (p *Policy) validateSource() error {
	s := p.Source
	if s == nil {
		return errors.New("source is absent")
	}

	if err := templateField("source.identity", s.Identity); err != nil {
		return err
	}

	if s.NotesRef == nil || !strings.HasPrefix(*s.NotesRef, "refs/") {
		return errors.New("source.notesRef must be present and fully qualified (refs/...)")
	}

	if s.ProvenancePredicateType == nil || !strings.HasPrefix(*s.ProvenancePredicateType, "https://") {
		return errors.New("source.provenancePredicateType must be present and an https URI")
	}

	if s.PropertyPrefix == nil || *s.PropertyPrefix == "" {
		return errors.New("source.propertyPrefix is absent or empty")
	}

	if err := templateField("source.resourceUri", s.ResourceURI); err != nil {
		return err
	}

	if len(s.ProtectedBranches) == 0 {
		return errors.New("source.protectedBranches is absent or empty — a source policy protecting nothing polices nothing")
	}

	for i, b := range s.ProtectedBranches {
		if err := p.validateBranch(i, b); err != nil {
			return err
		}
	}

	if s.HealedContinuity == nil {
		return errors.New("source.healedContinuity is absent — the stance is declared, never defaulted")
	}

	if err := levelField("source.underclaimLevel", s.UnderclaimLevel); err != nil {
		return err
	}

	for i, l := range s.LegacyLeaves {
		if l.Repository == nil || !repoRE.MatchString(*l.Repository) {
			return fmt.Errorf("source.legacyLeaves[%d].repository must be owner/repo", i)
		}

		if l.Revision == nil || !revisionRE.MatchString(*l.Revision) {
			return fmt.Errorf("source.legacyLeaves[%d].revision must be the full 40-hex identifier", i)
		}

		if l.Reason == nil || *l.Reason == "" {
			return fmt.Errorf("source.legacyLeaves[%d].reason is absent or empty — a silent exception is silence", i)
		}
	}

	return nil
}

func (p *Policy) validateBranch(i int, b ProtectedBranch) error {
	if b.Name == nil || *b.Name == "" {
		return fmt.Errorf("source.protectedBranches[%d].name is absent or empty", i)
	}

	if err := levelField(fmt.Sprintf("source.protectedBranches[%d].targetLevel", i), b.TargetLevel); err != nil {
		return err
	}

	if len(b.RequiredProperties) == 0 {
		return fmt.Errorf(
			"source.protectedBranches[%d].requiredProperties is absent or empty"+
				" — a level required by nothing is claimed by anything", i)
	}

	for j, rp := range b.RequiredProperties {
		if rp.Name == nil || !strings.HasPrefix(*rp.Name, *p.Source.PropertyPrefix) {
			return fmt.Errorf("source.protectedBranches[%d].requiredProperties[%d].name must carry the property prefix", i, j)
		}

		if rp.Since == nil {
			return fmt.Errorf("source.protectedBranches[%d].requiredProperties[%d].since is absent", i, j)
		}

		if _, err := time.Parse(time.RFC3339, *rp.Since); err != nil {
			return fmt.Errorf("source.protectedBranches[%d].requiredProperties[%d].since is not RFC 3339: %w", i, j, err)
		}
	}

	return nil
}

// workflowField refuses an absent or malformed workflow identity.
func workflowField(name string, v *string) error {
	if v == nil || !workflowRE.MatchString(*v) {
		return fmt.Errorf("%s must be present and owner/repo/path-to-workflow", name)
	}

	return nil
}

// levelField refuses an absent or malformed SLSA level.
func levelField(name string, v *string) error {
	if v == nil || !levelRE.MatchString(*v) {
		return fmt.Errorf("%s must be present and SLSA_<TRACK>_LEVEL_<N>", name)
	}

	return nil
}

// templateField refuses an absent template or one carrying a
// placeholder outside the closed vocabulary — an unknown placeholder
// would substitute to nothing and then exact-match compare, which is
// a verification passing against a typo.
func templateField(name string, v *string) error {
	if v == nil || *v == "" {
		return fmt.Errorf("%s is absent or empty", name)
	}

	for _, ph := range placeholderRE.FindAllString(*v, -1) {
		if !knownPlaceholder(ph) {
			return fmt.Errorf("%s carries unknown placeholder %s", name, ph)
		}
	}

	return nil
}
