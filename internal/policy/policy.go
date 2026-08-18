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
	"strconv"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/claims"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// Schema is the document epoch this implementation reads — any other
// is refused, never best-efforted. It is ONE number across every
// live-read stele document (both policies and the report), because
// there are no dual readers: per-document numbers would buy no
// tolerance a reader can use, and would drift the moment a human
// bumped one and forgot another, which is what stele#107 found.
// The number is defined once, at the version gate (jsonx.Epoch).
// Identifiers written into history keep their own numbers — see
// docs/versioning.md.
const Schema = jsonx.Epoch

// Policy is the decoded document. Field semantics live in
// docs/policy-schema.md; this type carries exactly that shape.
type Policy struct {
	Schema *int    `json:"schema"`
	Issuer *string `json:"issuer"`
	Trust  *Trust  `json:"trust"`
	Build  *Build  `json:"build"`
	Source *Source `json:"source"`
	// SLSARootsOfTrust is the spec's own root-of-trust map: which
	// attesters this verifier vouches for, and up to which level per
	// track. It bounds what `verify` will ACCEPT; it is deliberately
	// not read by `stele level`, which measures rather than gates and
	// must not be handed the answer it is computing.
	SLSARootsOfTrust []RootOfTrust `json:"slsaRootsOfTrust,omitempty"`
}

// RootOfTrust is one attester and the maximum level per track this
// verifier trusts it to. The spec keys this map on the PAIR (signer
// key identity, attester id) — here the pair collapses to the
// attester id alone, because the engine already asserts the
// tautology the pair exists to prevent: a verdict's verifier.id must
// BE the identity whose certificate signed it (verify/vsa.go, the
// spec's step 4). Keying on a value that has been proven equal to
// the signing identity is keying on the signing identity.
type RootOfTrust struct {
	// AttesterID is the provenance's builder.id or the summary's
	// verifier.id — the role-neutral name for the same field.
	AttesterID *string `json:"attesterId"`
	// MaxLevels is one SLSA_<TRACK>_LEVEL_<N> per track, at most one
	// per track: a level implies every level below it, so two entries
	// for one track are a contradiction, not emphasis.
	MaxLevels []string `json:"maxLevels"`
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
	Enrichment            *Enrichment          `json:"enrichment"`
}

// Enrichment is the OPTIONAL build-enrichment obligation: which
// resolved dependencies a signed enrichment claim must carry, and
// which it may. Absent means the org signs no enrichment and none is
// demanded; declared means a verdict is not proven until the claim
// beside it is. The two name lists are a CLOSED set — a claim naming
// anything outside them is refused, because a signed false dependency
// is worse than an omitted one.
type Enrichment struct {
	PredicateType *string  `json:"predicateType"`
	Required      []string `json:"required"`
	Permitted     []string `json:"permitted"`
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
	// Claims is the frozen control table: what makes each property
	// live. An obligation like every other section — absent means the
	// org does not derive claims with this tool. Declared, it is
	// cross-checked against RequiredProperties below.
	Claims *claims.Table `json:"claims,omitempty"`
}

// ProtectedBranch is one branch's target level and the per-level
// claims that establish it.
type ProtectedBranch struct {
	Name        *string `json:"name"`
	TargetLevel *string `json:"targetLevel"`
	// Levels declares, per level, what establishes it. The judge reads
	// this rather than fixing requirements to rungs in code: WHICH
	// level an organization's technical controls establish is that
	// organization's claim, and a tool that pinned it would make every
	// other shape unclaimable (CLAUDE.md's first rule).
	//
	// Levels the spec makes structurally judgeable from evidence this
	// tool already holds — a verifying source VSA, continuous coverage
	// — are judged from that evidence and need no entry here. A level
	// with no entry and no structural judgment is UNCLAIMED: the
	// policy said nothing, which is not the same as the judge deciding
	// nobody could.
	Levels []LevelClaim `json:"levels"`
}

// LevelClaim is one level an organization claims, and the properties
// that establish it at that level.
type LevelClaim struct {
	Level              *string            `json:"level"`
	RequiredProperties []RequiredProperty `json:"requiredProperties"`
}

// RequiredProperty is one control property and its continuity start.
type RequiredProperty struct {
	Name  *string `json:"name"`
	Since *string `json:"since"`
	// Evaluator optionally names the built-in that PROVES this
	// property from evidence anyone holds, rather than accepting the
	// SCS's signed claim at face value. The name vocabulary belongs
	// to internal/level, which refuses an unknown one at use: this
	// package would have to import the judge to check it here, and a
	// policy that imports its consumer is a cycle.
	Evaluator *string `json:"evaluator,omitempty"`
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
	levelRE      = regexp.MustCompile(`^SLSA_[A-Z]+_LEVEL_\d+$`)
	levelParseRE = regexp.MustCompile(`^SLSA_([A-Z]+)_LEVEL_(\d+)$`)
	revisionRE   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	repoRE       = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
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

// MaxLevel reports the maximum level the policy trusts one attester
// to on one track, and whether the attester is in the map at all.
// Absence is an ANSWER — the spec's step 1 defaults an unmapped
// attester to the track's floor — so the caller distinguishes the two
// and never conflates "trusted to zero" with "not declared".
func (p *Policy) MaxLevel(attesterID, track string) (int, bool) {
	for _, r := range p.SLSARootsOfTrust {
		if r.AttesterID != nil && *r.AttesterID == attesterID {
			return r.trustedTo(track)
		}
	}

	return 0, false
}

// ParseLevel splits a SlsaResult level value into its track and
// number. The UNEVALUATED and FAILED values are deliberately not
// levels: they are answers about the absence of one.
//
//nolint:nonamedreturns // the results are three unrelated values; naming them IS the doc
func ParseLevel(s string) (track string, n int, ok bool) {
	m := levelParseRE.FindStringSubmatch(s)
	if m == nil {
		return "", 0, false
	}

	num, err := strconv.Atoi(m[2])
	if err != nil {
		return "", 0, false
	}

	return m[1], num, true
}

// Load decodes and validates one policy document. Everything it
// refuses is refused here, before any verification consumes a field.
// The schema gate fires inside DecodeVersioned, BEFORE strict
// decoding — so a policy from another schema refuses with a version
// error, never incidentally with an unknown-field error (stele#107).
func Load(r io.Reader) (*Policy, error) {
	p, err := jsonx.DecodeVersioned[Policy](r, Schema)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}

	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}

	return p, nil
}

// validate holds the universality principle (#79/#82): obligations
// are declared; identities are roles; only provenance is intrinsic.
// The minimal valid policy is schema + issuer + a provenance
// identity (possibly templated to the repo itself). Every other
// section — verdicts, decisions, the build and source tracks — is an
// obligation an org declares when it builds the mechanism: absent
// means the obligation does not exist; declared means every field of
// it, validated strictly. The verbs refuse at USE when the section
// they need is undeclared.
func (p *Policy) validate() error {
	if p.Issuer == nil || !strings.HasPrefix(*p.Issuer, "https://") {
		return errors.New("issuer must be present and https")
	}

	if err := p.validateTrust(); err != nil {
		return err
	}

	if err := p.validateRoots(); err != nil {
		return err
	}

	if p.Build != nil {
		if err := p.validateBuild(); err != nil {
			return err
		}
	}

	if p.Source != nil {
		if err := p.validateSource(); err != nil {
			return err
		}
	}

	return p.validateReachable()
}

// validateRoots validates the OPTIONAL root-of-trust map. Declared
// means every field, strictly: an attester named without a level, or
// a track claimed twice, is a map that cannot answer the one question
// it exists to answer.
func (p *Policy) validateRoots() error {
	seenAttester := map[string]bool{}

	for i, r := range p.SLSARootsOfTrust {
		if r.AttesterID == nil || !strings.HasPrefix(*r.AttesterID, "https://") {
			return fmt.Errorf("slsaRootsOfTrust[%d].attesterId must be present and an https URI", i)
		}

		if seenAttester[*r.AttesterID] {
			return fmt.Errorf(
				"slsaRootsOfTrust[%d] names attester %s twice — two entries for one attester are two answers",
				i, *r.AttesterID)
		}

		seenAttester[*r.AttesterID] = true

		if len(r.MaxLevels) == 0 {
			return fmt.Errorf(
				"slsaRootsOfTrust[%d].maxLevels is absent or empty — an attester trusted to nothing is not a root of trust", i)
		}

		tracks := map[string]bool{}

		for j, l := range r.MaxLevels {
			track, _, ok := ParseLevel(l)
			if !ok {
				return fmt.Errorf("slsaRootsOfTrust[%d].maxLevels[%d] must be SLSA_<TRACK>_LEVEL_<N>", i, j)
			}

			if tracks[track] {
				return fmt.Errorf(
					"slsaRootsOfTrust[%d].maxLevels claims track %s more than once — a level implies those below it",
					i, track)
			}

			tracks[track] = true
		}
	}

	return nil
}

// validateReachable refuses a policy that demands more than it
// vouches for. A target level no declared attester reaches is
// unsatisfiable by construction: the judgment would cap below the
// demand on every run, so the disagreement is in the file, not in the
// evidence. Refused at load rather than reported every night.
func (p *Policy) validateReachable() error {
	if len(p.SLSARootsOfTrust) == 0 {
		return nil // no map declared: the spec default applies, nothing to contradict
	}

	if p.Build != nil {
		if err := p.reachable("build.targetLevel", *p.Build.TargetLevel); err != nil {
			return err
		}
	}

	if p.Source == nil {
		return nil
	}

	for i, b := range p.Source.ProtectedBranches {
		field := fmt.Sprintf("source.protectedBranches[%d].targetLevel", i)
		if err := p.reachable(field, *b.TargetLevel); err != nil {
			return err
		}
	}

	return nil
}

// reachable reports whether some declared attester is trusted to at
// least the demanded level on that level's track.
func (p *Policy) reachable(field, want string) error {
	track, n, ok := ParseLevel(want)
	if !ok {
		return fmt.Errorf("%s must be SLSA_<TRACK>_LEVEL_<N>", field)
	}

	for _, r := range p.SLSARootsOfTrust {
		if trusted, found := r.trustedTo(track); found && trusted >= n {
			return nil
		}
	}

	return fmt.Errorf(
		"%s demands %s but no slsaRootsOfTrust entry is trusted that far on the %s track",
		field, want, track)
}

// max reports this attester's maximum level on one track.
func (r RootOfTrust) trustedTo(track string) (int, bool) {
	for _, l := range r.MaxLevels {
		if t, n, ok := ParseLevel(l); ok && t == track {
			return n, true
		}
	}

	return 0, false
}

func (p *Policy) validateTrust() error {
	if p.Trust == nil {
		return errors.New("trust is absent")
	}

	if p.Trust.Provenance == nil {
		return errors.New("trust.provenance is absent — provenance is the one intrinsic obligation")
	}

	if err := workflowField("trust.provenance.signerWorkflow", p.Trust.Provenance.SignerWorkflow); err != nil {
		return err
	}

	if err := p.validateVerdict(); err != nil {
		return err
	}

	return p.validateDecision()
}

// validateVerdict validates the OPTIONAL verdict section: an adopter
// who never emits VSAs cannot be forced to name a verifier. Declared
// means every field, strictly.
func (p *Policy) validateVerdict() error {
	if p.Trust.Verdict == nil {
		return nil
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

	return nil
}

// validateDecision validates the OPTIONAL decision section — a
// release decision is an obligation an org declares, not a
// precondition of using the verifier.
func (p *Policy) validateDecision() error {
	if p.Trust.Decision == nil {
		return nil
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

	return p.validateEnrichment()
}

// validateEnrichment validates the OPTIONAL enrichment section.
//
// Its one cross-section rule is the exception that proves #82's:
// absent sections refuse at USE, but a DECLARED obligation whose
// proof needs an identity nobody declared is unprovable by
// construction — a malformed policy, not a missing one — so it
// refuses at LOAD. The enrichment is signed by the verdict identity;
// without trust.verdict there is nothing to verify it against.
func (p *Policy) validateEnrichment() error {
	e := p.Build.Enrichment
	if e == nil {
		return nil
	}

	if p.Trust.Verdict == nil {
		return errors.New(
			"build.enrichment is declared but trust.verdict is not — " +
				"the enrichment verifies under the verdict identity, so the obligation could never be proven")
	}

	if e.PredicateType == nil || !strings.HasPrefix(*e.PredicateType, "https://") {
		return errors.New("build.enrichment.predicateType must be present and an https URI")
	}

	// An obligation requiring nothing would let an enrichment
	// claiming nothing pass, which is the decoration this section
	// exists to end.
	if len(e.Required) == 0 {
		return errors.New(
			"build.enrichment.required is absent or empty — an obligation requiring nothing is not an obligation")
	}

	seen := map[string]bool{}

	for _, list := range [][]string{e.Required, e.Permitted} {
		for _, name := range list {
			switch {
			case name == "":
				return errors.New("build.enrichment names an empty dependency name")
			case seen[name]:
				return fmt.Errorf(
					"build.enrichment names %q twice — required and permitted are one closed set, and a name is in it once",
					name)
			}

			seen[name] = true
		}
	}

	return nil
}

func (p *Policy) validateSource() error {
	s := p.Source

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

	if err := p.validateClaims(); err != nil {
		return err
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

// validateClaims holds the control table and the cross-check that is
// this section's reason for existing. A property a branch REQUIRES
// but the table cannot derive is unclaimable, so that branch can
// never reach its target level — a permanent silent under-claim,
// discoverable today only by reading the policy, the org's docs and a
// shell script together. Here it refuses at load.
//
// The converse is deliberately allowed: a property may be derived
// without being required. Claiming more than the target needs is
// honest, and an org tightening its policy should not have to
// choreograph two files in one commit.
func (p *Policy) validateClaims() error {
	table := p.Source.Claims
	if table == nil {
		return nil
	}

	if err := table.Validate(); err != nil {
		return fmt.Errorf("source.%w", err)
	}

	for i, b := range p.Source.ProtectedBranches {
		for j, lc := range b.Levels {
			for k, rp := range lc.RequiredProperties {
				if !table.Declares(*rp.Name) {
					return fmt.Errorf(
						"source.protectedBranches[%d].levels[%d].requiredProperties[%d] requires %q, which"+
							" source.claims does not declare — the branch could never reach %s",
						i, j, k, *rp.Name, *lc.Level)
				}
			}
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

	if len(b.Levels) == 0 {
		return fmt.Errorf(
			"source.protectedBranches[%d].levels is absent or empty"+
				" — a level established by nothing is claimed by anything", i)
	}

	return validateLevelClaims(
		fmt.Sprintf("source.protectedBranches[%d]", i), b.Levels, p.Source.PropertyPrefix)
}

// validateLevelClaims validates one track's per-level claims. prefix
// is the property namespace when the track enforces one (the source
// track's SCS-enforced ORG_SOURCE_ rule); nil where no namespace is
// specified, because a namespace is a track's rule and not this
// validator's opinion.
func validateLevelClaims(field string, levels []LevelClaim, prefix *string) error {
	seen := map[string]bool{}

	for i, lc := range levels {
		if err := levelField(fmt.Sprintf("%s.levels[%d].level", field, i), lc.Level); err != nil {
			return err
		}

		if seen[*lc.Level] {
			return fmt.Errorf("%s.levels declares %s more than once — one level, one claim", field, *lc.Level)
		}

		seen[*lc.Level] = true

		if len(lc.RequiredProperties) == 0 {
			return fmt.Errorf(
				"%s.levels[%d].requiredProperties is absent or empty"+
					" — a level required by nothing is claimed by anything", field, i)
		}

		for j, rp := range lc.RequiredProperties {
			where := fmt.Sprintf("%s.levels[%d].requiredProperties[%d]", field, i, j)

			if rp.Name == nil || *rp.Name == "" {
				return fmt.Errorf("%s.name is absent or empty", where)
			}

			if prefix != nil && !strings.HasPrefix(*rp.Name, *prefix) {
				return fmt.Errorf("%s.name must carry the property prefix", where)
			}

			if rp.Since == nil {
				return fmt.Errorf("%s.since is absent", where)
			}

			if _, err := time.Parse(time.RFC3339, *rp.Since); err != nil {
				return fmt.Errorf("%s.since is not RFC 3339: %w", where, err)
			}
		}
	}

	return nil
}

// workflowField refuses an absent or malformed workflow identity.
// The identity is a ROLE (#82): `{owner}` and `{repo}` are accepted
// so "each repository signs for itself" is expressible — a
// self-attesting repository's certificate names its own workflow.
// Only those two placeholders: a workflow path templated on tag or
// version would move the identity per release, which is not a role
// but a wildcard.
func workflowField(name string, v *string) error {
	if v == nil {
		return fmt.Errorf("%s must be present and owner/repo/path-to-workflow", name)
	}

	shape := *v

	for _, ph := range placeholderRE.FindAllString(shape, -1) {
		if ph != "{owner}" && ph != "{repo}" {
			return fmt.Errorf("%s carries placeholder %s — workflow identities admit only {owner} and {repo}", name, ph)
		}
	}

	// Substitute a well-formed dummy so the shape check judges the
	// template's own syntax, not the placeholders.
	shape = strings.NewReplacer("{owner}", "o", "{repo}", "r").Replace(shape)
	if !workflowRE.MatchString(shape) {
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
