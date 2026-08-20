// The assert policy: everything org-shaped the evidence walk needs,
// as committed data — class names, their bundle assets, the store-VSA
// epoch, the debt file, the population expectation. Zero org names in
// code; the schema is docs/assert-policy-schema.md, written first.
// Decode contract: pointer fields, strict decode, explicit nil
// rejection (the jsonx law).

package assert

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/population"
)

// PolicySchema is the document epoch this implementation reads — any
// other is refused, never best-efforted. It is the SAME number the
// verify policy and the report carry: one epoch across every
// live-read stele document (docs/versioning.md), defined once at the
// version gate (jsonx.Epoch), so a bump can never land on one
// document and miss another, which is the drift stele#107 found. The
// pre-#84 vocabulary (`storeVsaFromCanon` and kin) is refused here
// as a version, not as a field typo.
const PolicySchema = jsonx.Epoch

// Policy is the committed assert policy. Constructor: LoadPolicy.
type Policy struct {
	Schema *int `json:"schema"`
	// Issuer is the OIDC issuer every store-resident attestation this
	// walk verifies must carry — the same value the verify policy
	// names, repeated here so this file stands alone.
	Issuer *string `json:"issuer,omitempty"`
	// DebtFile is the committed exceptions file (repo-relative in the
	// policy repo's checkout) holding human-asserted debt. It sits at
	// the ROOT because every target reads it (#147): excusability is a
	// property of judgment, not of one walk, and a key named for one
	// consumer among six would be a second source of truth about what
	// the file is. Absent means the org declares no exceptions —
	// validate by declared obligation, so nothing is excusable and
	// every finding stands.
	DebtFile *string `json:"debtFile,omitempty"`
	// Population is the organisation's own statement of which
	// repositories bear evidence, and on which tracks (stele#153). It
	// sits at the ROOT beside debtFile and for the same reason: every
	// target enumerates through it, and a population declared inside
	// one walk's section would be a second population for the other
	// five. Absent means the default predicate — archived repositories
	// and forks out, everything else in, on every track.
	Population  *population.Declaration `json:"population,omitempty"`
	Evidence    *EvidencePolicy         `json:"evidence"`
	BlastRadius *BlastRadiusPolicy      `json:"blastRadius,omitempty"`
	Tags        *TagsPolicy             `json:"tags,omitempty"`
	Chains      *ChainsPolicy           `json:"chains,omitempty"`
	Permissions *PermissionsPolicy      `json:"permissions,omitempty"`
}

// ChainsPolicy parameterises the chain-coverage audit (stele#94).
// Where the ledger lives and which branches it covers come from the
// verify policy's source section — the one declaration — so the only
// content here is the exception list. The section's PRESENCE is the
// declared obligation: an org that declares it audits every
// population member.
type ChainsPolicy struct {
	// Exceptions are the declared opt-outs: repositories the walk may
	// report unactivated without going red, each with a written
	// reason. The list may be empty — an org with every repository
	// activated excuses nothing — and an entry whose repository has
	// since founded its chain is reported stale by the report engine,
	// which is the removal condition made structural.
	Exceptions []ChainException `json:"exceptions,omitempty"`
}

// ChainException is one declared opt-out: the repository name within
// the population's owner, and the reason a human wrote down.
type ChainException struct {
	Repo   *string `json:"repo"`
	Reason *string `json:"reason"`
}

func (cp *ChainsPolicy) validate() error {
	seen := map[string]bool{}

	for i, e := range cp.Exceptions {
		if e.Repo == nil || *e.Repo == "" {
			return fmt.Errorf("chains.exceptions[%d].repo is absent or empty", i)
		}

		if seen[*e.Repo] {
			return fmt.Errorf("chains.exceptions[%d] names %s twice — one repository, one excuse", i, *e.Repo)
		}

		seen[*e.Repo] = true

		if e.Reason == nil || *e.Reason == "" {
			return fmt.Errorf("chains.exceptions[%d].reason is absent or empty — a silent exception is silence", i)
		}
	}

	return nil
}

// PermissionsPolicy parameterises the caller/callee permissions join
// (stele#148). The platform makes `permissions:` caller-owned — a
// reusable workflow inherits its caller's grant and can only narrow
// it — so a callee that gains a capability breaks every caller,
// enforced at run time as a startup failure with no jobs and no log.
// The requirement is nevertheless statically computable, which is
// what this section points the join at.
//
// Everything here is a CONVENTION, and every convention is declared:
// which repository holds the shared workflows, where its files sit in
// the checkout the run is handed, and which directories of the
// caller's tree hold callers. The Python this replaces carried all
// three as literals, which is why a tree shaped differently could not
// express its own join without editing the tool.
type PermissionsPolicy struct {
	// Reusable declares the shared-workflow tree this run holds and
	// the reference spelling that names it. Absent is meaningful: an
	// adopter whose reusable workflows all live beside their callers
	// declares no remote tree, and the join then covers local calls
	// alone.
	Reusable *ReusableTree `json:"reusable,omitempty"`
	// CallerDirs are the checkout-relative directories whose workflow
	// files are read as callers. More than one because a tree may hold
	// callers it does not run — an org's workflow templates are stubs
	// destined for other repositories, and a stub's grant is exactly
	// as breakable as a live caller's.
	CallerDirs []string `json:"callerDirs"`
}

// ReusableTree declares one shared-workflow tree: the owner/name a
// caller spells in `uses:`, and the directory its files occupy in the
// checkout the run is pointed at. Both halves are needed and neither
// implies the other — the reference is how callers name the tree, the
// directory is where this run can read it.
type ReusableTree struct {
	Repo *string `json:"repo"`
	Dir  *string `json:"dir"`
}

func (pp *PermissionsPolicy) validate() error {
	if len(pp.CallerDirs) == 0 {
		return errors.New("permissions.callerDirs is absent or empty — a join with no callers judges nothing")
	}

	seen := map[string]bool{}

	for i, dir := range pp.CallerDirs {
		if err := relativeDir(dir); err != nil {
			return fmt.Errorf("permissions.callerDirs[%d]: %w", i, err)
		}

		if seen[dir] {
			return fmt.Errorf("permissions.callerDirs[%d] names %q twice — the caller directories are a set", i, dir)
		}

		seen[dir] = true
	}

	if pp.Reusable == nil {
		return nil
	}

	return pp.Reusable.validate()
}

func (rt *ReusableTree) validate() error {
	if rt.Repo == nil || *rt.Repo == "" {
		return errors.New("permissions.reusable.repo is absent or empty")
	}

	owner, name, ok := strings.Cut(*rt.Repo, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return fmt.Errorf("permissions.reusable.repo %q is not owner/name", *rt.Repo)
	}

	if rt.Dir == nil || *rt.Dir == "" {
		return errors.New("permissions.reusable.dir is absent or empty")
	}

	if err := relativeDir(*rt.Dir); err != nil {
		return fmt.Errorf("permissions.reusable.dir: %w", err)
	}

	return nil
}

// relativeDir refuses a declared directory that could reach outside
// the checkout it is resolved against. A policy is reviewed data, not
// a trusted path: the run joins these onto an operator-supplied root,
// and a policy that can escape it turns a reviewed declaration into a
// file-system reach.
func relativeDir(dir string) error {
	switch {
	case dir == "":
		return errors.New("the directory is empty")
	case strings.HasPrefix(dir, "/"):
		return fmt.Errorf("%q is absolute — declared directories are checkout-relative", dir)
	}

	for part := range strings.SplitSeq(dir, "/") {
		if part == ".." {
			return fmt.Errorf("%q climbs out of the checkout", dir)
		}
	}

	return nil
}

// EpochPending is the declared-unsigned epoch value: the repository
// releases tags and says so, but has not begun signing them.
const EpochPending = "pending"

// TagsPolicy parameterises the tag audit (stele#83). Tag signing is
// a DECLARED obligation: the whole section is absent for orgs that
// do not sign tags, never a precondition.
type TagsPolicy struct {
	// TagPattern selects the release tags among all tag refs.
	TagPattern *string `json:"tagPattern"`
	// TaggerName is the minting role's tagger name — an identity from
	// policy, never a literal in code.
	TaggerName *string `json:"taggerName"`
	// IdentityPattern is the regular expression the signing
	// certificate's SAN must match.
	IdentityPattern *string `json:"identityPattern"`
	// ProofFloor is the floor of proof the org requires of a tag
	// signature (stele#173) — how much countersigned evidence is
	// enough is the ORG's declaration, never the tool's decision.
	// "certificate-transparency": the signing certificate's issuance
	// countersigned by a trusted CT log — what any Fulcio-minted
	// signature can prove offline, receipts or not. Or
	// "observer-timestamp": additionally a transparency-log entry and
	// an observer timestamp over the signature itself, which only a
	// mint that embeds its receipts can meet.
	ProofFloor *string `json:"proofFloor"`
	// NotesRef is the source chain's notes ref, fully qualified.
	NotesRef *string `json:"notesRef"`
	// Epochs maps each releasing repository to the first tag that
	// owes a signature, or EpochPending for declared-unsigned. A
	// repository that releases tags without a line here is a finding:
	// an undeclared population member is unchecked, not clean.
	Epochs map[string]string `json:"epochs"`
}

func (tp *TagsPolicy) validate() error {
	for name, f := range map[string]*string{
		"tagPattern": tp.TagPattern, "taggerName": tp.TaggerName,
		"identityPattern": tp.IdentityPattern, "notesRef": tp.NotesRef,
	} {
		if f == nil || *f == "" {
			return fmt.Errorf("tags.%s is absent or empty", name)
		}
	}

	for _, field := range []string{*tp.TagPattern, *tp.IdentityPattern} {
		if _, err := regexp.Compile(field); err != nil {
			return fmt.Errorf("tags pattern: %w", err)
		}
	}

	if tp.ProofFloor == nil || *tp.ProofFloor == "" {
		return errors.New(
			"tags.proofFloor is absent or empty — the org declares how much proof is enough, the tool never does")
	}

	if *tp.ProofFloor != "certificate-transparency" && *tp.ProofFloor != "observer-timestamp" {
		return fmt.Errorf(
			"tags.proofFloor %q is not a floor this verifier judges (certificate-transparency, observer-timestamp)",
			*tp.ProofFloor)
	}

	if !strings.HasPrefix(*tp.NotesRef, "refs/") {
		return errors.New("tags.notesRef must be fully qualified (refs/...)")
	}

	if len(tp.Epochs) == 0 {
		return errors.New("tags.epochs is absent or empty — a tag policy covering no repository audits nothing")
	}

	for repo, epoch := range tp.Epochs {
		if epoch == EpochPending {
			continue
		}

		if _, err := semver.NewVersion(strings.TrimPrefix(epoch, "v")); err != nil {
			return fmt.Errorf("tags.epochs[%s]: %w", repo, err)
		}
	}

	return nil
}

// EvidencePolicy parameterises the evidence walk.
type EvidencePolicy struct {
	// SBOMSuffix names the release's SBOM asset by suffix.
	SBOMSuffix *string `json:"sbomSuffix"`
	// Checksums is the checksum manifest asset every release carries.
	Checksums *string `json:"checksums"`
	// UmbrellaBundle is the single-bundle name a release may truthfully
	// use when one bundle covers the whole release.
	UmbrellaBundle *string `json:"umbrellaBundle"`
	// ManifestAsset names the release's own evidence manifest — the
	// declared contract; releases without one fall back to the
	// workflow adapter, and releases with neither are legacy.
	ManifestAsset *string `json:"manifestAsset"`
	// Classes maps each evidence class to its required assets.
	Classes map[string]ClassPolicy `json:"classes"`
	// StoreVSAFromVersion is the machinery version (inclusive) from
	// which verdicts are store-resident; before it the legacy VSA
	// bundles ride as release assets. The machinery version is the
	// version of the shared release machinery the release pinned at
	// its tag; a repository carrying its own machinery uses its own
	// version (docs/assert-policy-schema.md defines it once).
	StoreVSAFromVersion *string `json:"storeVsaFromVersion"`
	// Continuous, when set, adds the continuous-digest half: repos
	// whose stub calls the org's continuous workflow publish rolling
	// digests whose evidence lives ONLY in the attestation store.
	Continuous *ContinuousPolicy `json:"continuous,omitempty"`
	// BaseImages, when set, adds the base-approval half: every pinned
	// base digest carries its approval attestation, so a dependency
	// roll that outran the approval run surfaces here rather than at
	// the next release.
	BaseImages *BaseImagesPolicy `json:"baseImages,omitempty"`
	// DecisionFromVersion is the machinery version (inclusive) from
	// which a release owes a VERIFIABLE release decision — the same
	// epoch semantics as StoreVSAFromVersion. Absent means always. An
	// unparsable pin fails toward the stricter obligation.
	DecisionFromVersion *string `json:"decisionFromVersion,omitempty"`
	// EnrichmentFromVersion is the machinery version (inclusive) from
	// which a release owes a build-enrichment claim (stele#109) — the
	// same epoch semantics again, defined once in owedFrom. The epoch
	// lives HERE, not in the verify policy: verify judges the single
	// release it is pointed at and stays epoch-free; whether history
	// owes the obligation is the corpus walk's question, and the
	// corpus walk is assert's — which already derives the machinery
	// version this field is compared against.
	EnrichmentFromVersion *string `json:"enrichmentFromVersion,omitempty"`
	// EvidenceSuffixes are additional asset-name suffixes that mark a
	// checksum entry as an evidence document rather than an artifact
	// (the org's per-release VEX documents, for one) — excluded from
	// the full-depth provenance subject set, because a document about
	// the release is not a subject of its build.
	EvidenceSuffixes []string `json:"evidenceSuffixes,omitempty"`
	// PublishWorkflows names the workflows whose failure can burn a
	// release (#378). Absent means ANY failed run on the tag counts —
	// the bash's semantics, and too broad: an unrelated flaky workflow
	// would then excuse a genuinely missing verdict, which is the mute
	// button the burned category must never become. Naming them is a
	// narrowing, so it is data, not code.
	PublishWorkflows []string `json:"publishWorkflows,omitempty"`
}

// ContinuousPolicy parameterises the continuous-digest half. Every
// field is an org convention: which stub marks a publishing repo,
// where its images live, and which workflow's identity signs them.
type ContinuousPolicy struct {
	// StubPath is the caller stub whose presence marks a repo as
	// publishing continuous digests.
	StubPath *string `json:"stubPath"`
	// StubUses is the substring the stub must call for the repo to
	// count — the org's own reusable workflow.
	StubUses *string `json:"stubUses"`
	// Registry and Tag address the rolling image.
	Registry *string `json:"registry"`
	Tag      *string `json:"tag"`
	// SignerWorkflow is the signer's workflow PATH (owner/repo/path);
	// the certificate identity is that path at the pin, because the
	// signer is reached through a commit-pinned uses: and the pin is
	// the certificate's ref. SignerPinPattern finds the pins the
	// producing repo's own workflows declare, so the expected
	// identity is DERIVED from the consuming tree, never a literal.
	SignerWorkflow   *string `json:"signerWorkflow"`
	SignerPinPattern *string `json:"signerPinPattern"`
}

// BaseImagesPolicy parameterises the base-approval half.
type BaseImagesPolicy struct {
	// PinFile is the committed file carrying pinned base references;
	// absent from the checkout means this org pins no base images.
	PinFile *string `json:"pinFile"`
	// AttestorRepo holds the approval attestations; AttestorIdentity
	// is the certificate identity they must verify under.
	AttestorRepo     *string `json:"attestorRepo"`
	AttestorIdentity *string `json:"attestorIdentity"`
	// PredicateType is the approval predicate the attestation carries.
	PredicateType *string `json:"predicateType"`
}

func (c *ContinuousPolicy) validate() error {
	for name, f := range map[string]*string{
		"stubPath": c.StubPath, "stubUses": c.StubUses, "registry": c.Registry,
		"tag": c.Tag, "signerWorkflow": c.SignerWorkflow, "signerPinPattern": c.SignerPinPattern,
	} {
		if f == nil || *f == "" {
			return fmt.Errorf("evidence.continuous.%s is absent or empty", name)
		}
	}

	if _, err := regexp.Compile(*c.SignerPinPattern); err != nil {
		return fmt.Errorf("evidence.continuous.signerPinPattern: %w", err)
	}

	return nil
}

func (b *BaseImagesPolicy) validate() error {
	for name, f := range map[string]*string{
		"pinFile": b.PinFile, "attestorRepo": b.AttestorRepo,
		"attestorIdentity": b.AttestorIdentity, "predicateType": b.PredicateType,
	} {
		if f == nil || *f == "" {
			return fmt.Errorf("evidence.baseImages.%s is absent or empty", name)
		}
	}

	return nil
}

// AssetObligation is one non-bundle asset a class requires, matched
// by prefix on the release's asset names.
type AssetObligation struct {
	// Prefix matches the required asset by name prefix.
	Prefix *string `json:"prefix"`
	// OwedFrom, when set, is the machinery version (inclusive) from
	// which the obligation holds — the shared owedFrom semantics
	// (stele#128). Class obligations apply to every release of the
	// class, and an asset the machinery only began publishing at some
	// release would otherwise red all of history — the exact failure
	// the top-level epochs exist to prevent. The epoch rides on the
	// entry, not beside the class map, because each obligation comes
	// online at its own machinery release and the field stays free of
	// any one asset's vocabulary. Absent means always owed, which
	// stays correct for fresh adopters.
	OwedFrom *string `json:"owedFrom,omitempty"`
	// Planned declares this asset's fulfillment channel: the document
	// is derived from a build-leg inventory plan, so the pre-publish
	// plans judgment (`assert plans`) demands a plan naming a document
	// under this prefix before anything ships. Declared, never
	// inferred from the prefix's spelling: which obligations plans
	// fulfil is an org fact, and one class can owe both a planned
	// inventory and an unplanned attestation asset.
	Planned bool `json:"planned,omitempty"`
}

// ClassPolicy is one evidence class's asset obligations.
type ClassPolicy struct {
	// Bundles are the attestation bundle assets the class requires.
	Bundles []string `json:"bundles"`
	// LegacyVSABundles are additionally required BEFORE the store-VSA
	// epoch.
	LegacyVSABundles []string `json:"legacyVsaBundles,omitempty"`
	// AssetPrefixes are non-bundle assets required by prefix match,
	// each obligation carrying its own epoch.
	AssetPrefixes []AssetObligation `json:"assetPrefixes,omitempty"`
	// Enrichment names the dependency claims a release declaring this
	// class owes ON TOP of the verify policy's universal required set
	// (stele#122). Names must live inside that policy's required ∪
	// permitted — one vocabulary, no second truth; the verify engine
	// refuses a demand that steps outside it, because this file
	// cannot see the other document.
	Enrichment []string `json:"enrichment,omitempty"`
}

// validateClasses holds the per-class guards: a class must require
// something, and its enrichment names — what a release declaring it
// owes its build-enrichment claim, on top of the verify policy's
// universal set — form a set, so empty and repeated names refuse.
func validateClasses(classes map[string]ClassPolicy) error {
	if len(classes) == 0 {
		return errors.New("evidence.classes is empty — a walk with no classes asserts nothing")
	}

	for name, c := range classes {
		if len(c.Bundles) == 0 && len(c.AssetPrefixes) == 0 {
			return fmt.Errorf("evidence.classes.%s requires nothing — an empty class asserts nothing", name)
		}

		prefixes := map[string]bool{}

		for _, ob := range c.AssetPrefixes {
			switch {
			case ob.Prefix == nil || *ob.Prefix == "":
				return fmt.Errorf("evidence.classes.%s.assetPrefixes carries an entry with no prefix — "+
					"an obligation that matches everything obliges nothing", name)
			case prefixes[*ob.Prefix]:
				return fmt.Errorf("evidence.classes.%s.assetPrefixes names %q twice — obligations are a set",
					name, *ob.Prefix)
			}

			prefixes[*ob.Prefix] = true

			// Refused at load for the same reason as validateEpochs:
			// the epoch feeds MustParse at judgment time, so an
			// unparsable one must never reach the walk.
			if ob.OwedFrom != nil {
				if _, err := semver.NewVersion(*ob.OwedFrom); err != nil {
					return fmt.Errorf("evidence.classes.%s.assetPrefixes[%s].owedFrom: %w", name, *ob.Prefix, err)
				}
			}
		}

		seen := map[string]bool{}

		for _, n := range c.Enrichment {
			switch {
			case n == "":
				return fmt.Errorf("evidence.classes.%s.enrichment names an empty dependency name", name)
			case seen[n]:
				return fmt.Errorf(
					"evidence.classes.%s.enrichment names %q twice — what a class owes is a set, and a name is in it once",
					name, n)
			}

			seen[n] = true
		}
	}

	return nil
}

// LoadPolicy reads and validates the committed assert policy. The
// schema gate fires inside DecodeVersioned, BEFORE strict decoding —
// so a policy from another schema refuses with a version error,
// never incidentally with an unknown-field error (stele#107).
func LoadPolicy(r io.Reader) (*Policy, error) {
	p, err := jsonx.DecodeVersioned[Policy](r, PolicySchema)
	if err != nil {
		return nil, fmt.Errorf("assert: policy: %w", err)
	}

	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("assert: policy: %w", err)
	}

	return p, nil
}

func (p *Policy) validate() error {
	e := p.Evidence
	if e == nil {
		return errors.New("evidence is absent")
	}

	for name, field := range map[string]*string{
		"evidence.sbomSuffix":     e.SBOMSuffix,
		"evidence.checksums":      e.Checksums,
		"evidence.umbrellaBundle": e.UmbrellaBundle,
		"evidence.manifestAsset":  e.ManifestAsset,
	} {
		if field == nil || *field == "" {
			return fmt.Errorf("%s is absent or empty", name)
		}
	}

	if err := validateClasses(e.Classes); err != nil {
		return err
	}

	if err := e.validateEpochs(); err != nil {
		return err
	}

	if (e.Continuous != nil || e.BaseImages != nil) && (p.Issuer == nil || *p.Issuer == "") {
		return errors.New("issuer is required when evidence.continuous or evidence.baseImages is declared")
	}

	if e.Continuous != nil {
		if err := e.Continuous.validate(); err != nil {
			return err
		}
	}

	if e.BaseImages != nil {
		if err := e.BaseImages.validate(); err != nil {
			return err
		}
	}

	if p.BlastRadius != nil {
		if err := p.BlastRadius.validate(); err != nil {
			return err
		}
	}

	if err := p.Population.Validate(); err != nil {
		return err
	}

	if p.Chains != nil {
		if err := p.Chains.validate(); err != nil {
			return err
		}
	}

	if p.Permissions != nil {
		if err := p.Permissions.validate(); err != nil {
			return err
		}
	}

	return p.validateTags()
}

// validateTags validates the OPTIONAL tags section; declared means
// every field, and the issuer beside it.
func (p *Policy) validateTags() error {
	if p.Tags == nil {
		return nil
	}

	if p.Issuer == nil || *p.Issuer == "" {
		return errors.New("issuer is required when tags is declared")
	}

	return p.Tags.validate()
}

// validateEpochs refuses unparsable epochs — both epoch fields feed
// MustParse downstream, so an epoch validate admits but the walk
// panics on would turn a reviewed policy into a crash mid-walk.
func (e *EvidencePolicy) validateEpochs() error {
	if e.StoreVSAFromVersion != nil {
		if _, err := semver.NewVersion(*e.StoreVSAFromVersion); err != nil {
			return fmt.Errorf("evidence.storeVsaFromVersion: %w", err)
		}
	}

	if e.DecisionFromVersion != nil {
		if _, err := semver.NewVersion(*e.DecisionFromVersion); err != nil {
			return fmt.Errorf("evidence.decisionFromVersion: %w", err)
		}
	}

	if e.EnrichmentFromVersion != nil {
		if _, err := semver.NewVersion(*e.EnrichmentFromVersion); err != nil {
			return fmt.Errorf("evidence.enrichmentFromVersion: %w", err)
		}
	}

	return nil
}

// owedFrom is the ONE epoch semantics every from-version field gets —
// the definition is shared so a fourth epoch cannot drift from the
// first three (stele#109). No epoch configured means the obligation
// always held; an unparsable machinery pin cannot prove the pre-epoch
// exemption, so it fails toward the stricter obligation.
func owedFrom(fromVersion *string, machineryVersion string) bool {
	if fromVersion == nil {
		return true
	}

	epoch := semver.MustParse(*fromVersion)

	v, err := semver.NewVersion(machineryVersion)
	if err != nil {
		return true
	}

	return !v.LessThan(epoch)
}

// storeVSA reports whether a release under the given machinery
// version keeps its verdicts in the attestation store.
func (e *EvidencePolicy) storeVSA(machineryVersion string) bool {
	return owedFrom(e.StoreVSAFromVersion, machineryVersion)
}

// decision reports whether a release under the given machinery
// version owes a verifiable release decision.
func (e *EvidencePolicy) decision(machineryVersion string) bool {
	return owedFrom(e.DecisionFromVersion, machineryVersion)
}

// enrichment reports whether a release under the given machinery
// version owes a build-enrichment claim (stele#109). Both contract
// sources answer it onto Contract.Enrichment; the verify leg that
// consumes the answer lands with #86.
func (e *EvidencePolicy) enrichment(machineryVersion string) bool {
	return owedFrom(e.EnrichmentFromVersion, machineryVersion)
}

// owedPlannedPrefixes returns the plan-fulfilled prefix obligations a
// release under the given machinery version owes from this class —
// the subset of owedPrefixes the pre-publish plans judgment demands
// of the build legs' plans. One filter over the one obligation list:
// the pre-publish and post-publish legs cannot disagree about what is
// owed, only about when they look.
func (c *ClassPolicy) owedPlannedPrefixes(machineryVersion string) []string {
	var out []string

	for _, ob := range c.AssetPrefixes {
		if ob.Planned && owedFrom(ob.OwedFrom, machineryVersion) {
			out = append(out, *ob.Prefix)
		}
	}

	return out
}

// plannedPrefixes returns every plan-fulfilled prefix this class
// DECLARES, with no epoch in sight — the class's plan vocabulary.
// Vocabulary membership is a naming question, not a time question
// (stele#143): a prefix owed only from some future machinery version
// is still a name the class could owe, so a pre-epoch plan under it
// is correct, never an orphan.
func (c *ClassPolicy) plannedPrefixes() []string {
	var out []string

	for _, ob := range c.AssetPrefixes {
		if ob.Planned {
			out = append(out, *ob.Prefix)
		}
	}

	return out
}

// owedPrefixes returns the prefix obligations a release under the
// given machinery version owes from this class — each entry judged
// through the one owedFrom semantics (stele#128). Judged here rather
// than precomputed onto the contract because the obligations are
// per-class, and the class list joins the policy only in the walk.
func (c *ClassPolicy) owedPrefixes(machineryVersion string) []string {
	var out []string

	for _, ob := range c.AssetPrefixes {
		if owedFrom(ob.OwedFrom, machineryVersion) {
			out = append(out, *ob.Prefix)
		}
	}

	return out
}
