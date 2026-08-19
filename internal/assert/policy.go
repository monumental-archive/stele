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
	Issuer      *string            `json:"issuer,omitempty"`
	Evidence    *EvidencePolicy    `json:"evidence"`
	BlastRadius *BlastRadiusPolicy `json:"blastRadius,omitempty"`
	Tags        *TagsPolicy        `json:"tags,omitempty"`
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
	// DebtFile is the committed exceptions file (repo-relative in the
	// policy repo's checkout) holding human-asserted evidence debt.
	DebtFile *string `json:"debtFile"`
	// ExpectedRepos, when set, is the declared org population — a
	// listing that sees a different count cannot judge.
	ExpectedRepos *int `json:"expectedRepos,omitempty"`
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
		"evidence.debtFile":       e.DebtFile,
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

	if e.ExpectedRepos != nil && *e.ExpectedRepos <= 0 {
		return errors.New("evidence.expectedRepos must be positive when set")
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
