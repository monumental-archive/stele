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
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
	ociname "github.com/google/go-containerregistry/pkg/name"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/population"
	"github.com/monumental-archive/stele/internal/release"
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
	// SignerCertificates declares the signer-certificate watch
	// (stele#387): the certificate transparency log to read, and the
	// signing workflows whose every certificate must reconcile against
	// a signing the population performed. Its presence is the declared
	// obligation; the identity's issuer is the top-level Issuer.
	SignerCertificates *SignerCertificatesPolicy `json:"signerCertificates,omitempty"`
	// Published declares where a release's file subjects are served,
	// for the published-bytes proof (stele#392): the registries, each
	// claiming subjects by extension and serving them at a URL
	// template. Its presence is what `assert published` needs.
	Published *PublishedPolicy `json:"published,omitempty"`
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

// SignerCertificatesPolicy parameterises the signer-certificate watch
// (stele#387). Everything org-shaped about it is here: which log, which
// signing workflows, and which repositories each lets call it. No
// organisation, repository or log is named in code.
type SignerCertificatesPolicy struct {
	// Log is the certificate transparency log's base URL, spelled
	// exactly as the trusted root spells it: the root is what vouches
	// for the log's key, so a URL it does not name has no key.
	Log *string `json:"log"`
	// Signers are the signing workflows watched. A list from the start
	// — how many signing workflows an organisation runs is policy, and
	// each has its own callers (stele#387, amended in triage).
	Signers []SignerPolicy `json:"signers"`
}

// SignerPolicy is one signing workflow and the repositories whose
// workflows may call it.
type SignerPolicy struct {
	// Workflow is the signing workflow as a caller names it in `uses:`,
	// without the ref: owner/repo/path.
	Workflow *string `json:"workflow"`
	// Callers are the owner/name repositories whose workflows may call
	// the signer. A run outside them must reach the signer through one
	// of their workflows, never directly.
	Callers []string `json:"callers"`
}

// minWorkflowSegments is the least a workflow reference carries: an
// owner, a repository and a path.
const minWorkflowSegments = 3

func (sp *SignerCertificatesPolicy) validate() error {
	if err := validateLogURL(sp.Log); err != nil {
		return err
	}

	if len(sp.Signers) == 0 {
		return errors.New("signerCertificates.signers is absent or empty — a watch over no signer watches nothing")
	}

	seen := map[string]bool{}

	for i, s := range sp.Signers {
		where := fmt.Sprintf("signerCertificates.signers[%d]", i)

		if s.Workflow == nil || *s.Workflow == "" {
			return fmt.Errorf("%s.workflow is absent or empty", where)
		}

		parts := strings.Split(*s.Workflow, "/")
		if len(parts) < minWorkflowSegments || slices.Contains(parts, "") || strings.Contains(*s.Workflow, "@") {
			return fmt.Errorf("%s.workflow %q is not owner/repo/path without a ref", where, *s.Workflow)
		}

		if seen[*s.Workflow] {
			return fmt.Errorf("%s names %s twice — a certificate must match exactly one signer", where, *s.Workflow)
		}

		seen[*s.Workflow] = true

		if err := validateCallers(where, s.Callers); err != nil {
			return err
		}
	}

	return nil
}

// validateLogURL refuses a log address the reader could not use as
// written: not https — get-entries content is not proven entry by
// entry, so the transport is what keeps an entry from being dropped in
// flight — or carrying anything past the path, which the trusted
// root's spelling never does.
func validateLogURL(log *string) error {
	if log == nil || *log == "" {
		return errors.New("signerCertificates.log is absent or empty")
	}

	u, err := url.Parse(*log)

	switch {
	case err != nil:
		return fmt.Errorf("signerCertificates.log %q does not parse: %w", *log, err)
	case u.Scheme != "https" || u.Host == "":
		return fmt.Errorf("signerCertificates.log %q is not an https URL", *log)
	case u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(*log, "/"):
		return fmt.Errorf("signerCertificates.log %q carries more than a base URL — spell it as the trusted root does", *log)
	}

	return nil
}

func validateCallers(where string, callers []string) error {
	if len(callers) == 0 {
		return fmt.Errorf("%s.callers is absent or empty — a signer nobody may call reconciles no certificate", where)
	}

	seen := map[string]bool{}

	for j, c := range callers {
		owner, name, ok := strings.Cut(c, "/")
		if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
			return fmt.Errorf("%s.callers[%d] %q is not owner/name", where, j, c)
		}

		if seen[c] {
			return fmt.Errorf("%s.callers[%d] names %s twice — the callers are a set", where, j, c)
		}

		seen[c] = true
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
	// ProofFloor is how much countersigned proof the org requires of a
	// tag signature, and from which tag (stele#173, stele#186).
	ProofFloor *TagProofFloor `json:"proofFloor"`
	// NotesRef is the source chain's notes ref, fully qualified.
	NotesRef *string `json:"notesRef"`
	// Epochs maps each releasing repository to the first tag that
	// owes a signature, or EpochPending for declared-unsigned. A
	// repository that releases tags without a line here is a finding:
	// an undeclared population member is unchecked, not clean.
	Epochs map[string]string `json:"epochs"`
}

// SignsTag reports whether one tag of one repository owes a
// signature under this section: the repository declares a signing
// epoch (not pending) and the tag sits at or after it — the same one
// reading of the epoch the tag audit's population is drawn from.
func (tp *TagsPolicy) SignsTag(repo, tag string) bool {
	epoch, declared := tp.Epochs[repo]

	return declared && epoch != EpochPending && tagAtOrAfter(tag, epoch)
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

	if tp.ProofFloor == nil {
		return errors.New(
			"tags.proofFloor is absent — the org declares how much proof is enough, the tool never does",
		)
	}

	if err := tp.ProofFloor.validate(); err != nil {
		return err
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

	return tp.ProofFloor.validateAgainst(tp.Epochs)
}

// The floors this verifier judges, named once. A floor the policy may
// declare is a floor the tool must be able to reach, so the set lives
// beside the declaration it validates rather than being restated at
// each use.
const (
	tagFloorCertificateTransparency = "certificate-transparency"
	tagFloorObserverTimestamp       = "observer-timestamp"
)

func knownTagFloor(floor string) bool {
	return floor == tagFloorCertificateTransparency || floor == tagFloorObserverTimestamp
}

// TagProofFloor declares how much countersigned proof a tag signature
// owes — and, when a repository's mint gained the capability to prove
// more partway through its history, the tag from which the heavier
// obligation binds.
//
// The floor and the point it binds from are ONE declaration, never a
// second epoch map beside tags.epochs (stele#186). They answer
// different questions about the same tags: `epochs` says when a
// repository began signing at all, this says when its floor rose. A
// floor raised globally instead would redden every tag minted before
// the mint could meet it — the #128/#109 failure the epoch vocabulary
// exists to prevent — and those tags are not defective.
//
// Universality: an org whose floor never rose declares `floor` alone;
// an org that never minted without receipts declares `from` at its
// first tag. Neither has to edit this tool.
type TagProofFloor struct {
	// Floor is the floor owed from a repository's `from` tag onward,
	// or by every tag when no `from` is declared.
	// "certificate-transparency": the signing certificate's issuance
	// countersigned by a trusted CT log — what any Fulcio-minted
	// signature can prove offline, receipts or not.
	// "observer-timestamp": additionally a transparency-log entry and
	// an observer timestamp over the signature itself, which only a
	// mint that embeds its receipts can meet.
	Floor *string `json:"floor"`
	// From maps a repository to the first tag owing Floor. A
	// repository absent from a declared map has not raised its floor
	// and every one of its tags owes Before — the correct reading for
	// a rollout partway through a population. Absent entirely means
	// Floor binds everywhere.
	From map[string]string `json:"from"`
	// Before is what tags earlier than the `from` tag owe. Declared
	// with From or not at all: a rise with nothing beneath it leaves
	// the tags it does not reach owing nothing at all.
	Before *string `json:"before"`
}

// Raised reports whether any repository's floor rises — what a caller
// needs to know to say which regimes one run covered.
func (f *TagProofFloor) Raised() bool { return len(f.From) > 0 }

// FloorFor is the floor one tag of one repository owes — the one
// reading of the declaration, shared by the tag audit and the source
// verdict's tag check (stele#391), so the two cannot owe different
// floors for the same tag.
func (f *TagProofFloor) FloorFor(repo, tag string) string {
	if len(f.From) == 0 {
		return *f.Floor
	}

	from, raised := f.From[repo]
	if !raised {
		return *f.Before
	}

	if tagAtOrAfter(tag, from) {
		return *f.Floor
	}

	return *f.Before
}

func (f *TagProofFloor) validate() error {
	if f.Floor == nil || *f.Floor == "" {
		return errors.New(
			"tags.proofFloor.floor is absent or empty — the org declares how much proof is enough, " +
				"the tool never does",
		)
	}

	if !knownTagFloor(*f.Floor) {
		return fmt.Errorf(
			"tags.proofFloor.floor %q is not a floor this verifier judges (%s, %s)",
			*f.Floor, tagFloorCertificateTransparency, tagFloorObserverTimestamp,
		)
	}

	if (len(f.From) == 0) != (f.Before == nil) {
		return errors.New(
			"tags.proofFloor declares `from` and `before` together or not at all — " +
				"a floor that rises from a point says nothing about the tags before it, " +
				"and a floor for tags before a point that is never named binds nothing",
		)
	}

	if f.Before == nil {
		return nil
	}

	if !knownTagFloor(*f.Before) {
		return fmt.Errorf(
			"tags.proofFloor.before %q is not a floor this verifier judges (%s, %s)",
			*f.Before, tagFloorCertificateTransparency, tagFloorObserverTimestamp,
		)
	}

	// Equal floors are refused; unequal ones are not ordered here. A
	// mint that REGRESSED is a real thing an org must be able to
	// declare honestly, and a tool that only permits rises decides a
	// policy fact. What no org can mean is a boundary with the same
	// floor on both sides.
	if *f.Before == *f.Floor {
		return fmt.Errorf(
			"tags.proofFloor.before is %q, the floor it is already — a boundary with one floor on both sides "+
				"declares nothing", *f.Before,
		)
	}

	for repo, from := range f.From {
		if _, err := semver.NewVersion(strings.TrimPrefix(from, "v")); err != nil {
			return fmt.Errorf("tags.proofFloor.from[%s]: %w", repo, err)
		}
	}

	return nil
}

// validateAgainst holds the declared boundaries against the signing
// epochs: a floor cannot rise for a repository that owes no signature
// at all, nor at a tag minted before that repository began signing.
func (f *TagProofFloor) validateAgainst(epochs map[string]string) error {
	for repo, from := range f.From {
		epoch, declared := epochs[repo]

		switch {
		case !declared:
			return fmt.Errorf(
				"tags.proofFloor.from[%s] raises the floor for a repository tags.epochs does not name — "+
					"a heavier obligation on tags that owe no signature at all", repo,
			)

		case epoch == EpochPending:
			return fmt.Errorf(
				"tags.proofFloor.from[%s] raises the floor for a repository declared unsigned — "+
					"tags.epochs says it has not begun signing", repo,
			)

		case !tagAtOrAfter(from, epoch):
			return fmt.Errorf(
				"tags.proofFloor.from[%s] is %s, before the signing epoch %s — "+
					"the floor cannot rise for tags that owe no signature", repo, from, epoch,
			)
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
	// whose stub calls the declared continuous workflow publish
	// rolling digests whose evidence lives ONLY in the attestation
	// store.
	Continuous *ContinuousPolicy `json:"continuous,omitempty"`
	// BaseImages, when set, adds the base-approval half: every base
	// this org builds on carries its approval, so a dependency roll
	// that outran the approval run surfaces here rather than at the
	// next release. What "carries its approval" MEANS is the scope's
	// declared mechanism — there is more than one in the world, and
	// the section holds as many as the adopter has.
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
	// ManifestSchemaFromVersion is the machinery version (inclusive)
	// from which a release owes a manifest at the schema this build
	// writes — the same epoch semantics once more, and the only one
	// that governs a DOCUMENT'S OWN FORMAT rather than an obligation
	// it carries. A manifest below the current schema published by
	// machinery at or after this version is refused: the epoch excuses
	// history, never the present. Before it, the manifest is read for
	// exactly what its own schema promised, and whatever it could not
	// say the walk derives from the vocabulary this policy already
	// declares (Classify).
	//
	// Absent means every manifest owes the current schema — correct
	// for an adopter with no history, and the reason an org that has
	// published older manifests must declare the version its own
	// machinery moved at (stele#185).
	ManifestSchemaFromVersion *string `json:"manifestSchemaFromVersion,omitempty"`
	// SourceVerdictFromVersion is the machinery version (inclusive)
	// from which a tagged release owes a source verdict for its tag
	// (stele#391): the tag bound to its commit and the commit's chain
	// level, signed by the verdict identity. The same epoch semantics
	// as every sibling, defined once in owedFrom. Absent means the
	// release machinery emits no source verdict and none is owed —
	// unlike its siblings, because emitting one needs the `tags`
	// section beside it, and an adopter who signs no tags has nothing
	// for the verdict to bind.
	SourceVerdictFromVersion *string `json:"sourceVerdictFromVersion,omitempty"`
	// SourceVerdictBundle names the release asset the source verdict
	// is published as — a release asset because its subject is a
	// commit, which the attestation store's sha256-keyed lookup cannot
	// address. Declared with SourceVerdictFromVersion or not at all.
	SourceVerdictBundle *string `json:"sourceVerdictBundle,omitempty"`
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
// field is the adopter's declared convention — which stub marks a
// publishing repo, where its images live, and which workflow's
// identity signs them — never a shape this engine assumes.
type ContinuousPolicy struct {
	// StubPath is the caller stub whose presence marks a repo as
	// publishing continuous digests.
	StubPath *string `json:"stubPath"`
	// StubUses is the substring the stub must call for the repo to
	// count — the adopter's declared reusable workflow.
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

// BaseImagesPolicy parameterises the base-approval half as a list of
// typed approval scopes. Plurality is the ADOPTER'S: an org may
// approve its bases by one mechanism, by two, or twice over by the
// same one — two pin files is a valid world. What this engine owns is
// the set of mechanism KINDS, because each kind names a judgment the
// walk knows how to compute; how many scopes a policy declares, and
// with which parameters, is policy and never code (stele#247).
type BaseImagesPolicy struct {
	// Scopes are the declared approval scopes; their names form a set.
	// A section declaring neither a scope nor an upstream entry
	// approves nothing, and is refused.
	Scopes []BaseImageScope `json:"scopes,omitempty"`
	// Upstream declares, per official image a build consumes, the
	// source its published provenance must name (stele#402). A sibling
	// of the scopes rather than a kind among them: a kind names a
	// judgment the corpus walk computes, and the walk has no reference
	// to enumerate here — the build that instantiates the image passes
	// it to `stele verify base`, which alone reads this list.
	Upstream []UpstreamBase `json:"upstream,omitempty"`
}

// UpstreamBase is one official image and the source its provenance
// must name: the repository its BuildKit config source points at, and
// the directory within it, expanded from the pinned tag.
type UpstreamBase struct {
	// Image is the untagged reference the entry covers.
	Image *string `json:"image"`
	// TagPattern reads the pinned tag; its named groups are what Path
	// expands from, and what a caller may bind to cross-check.
	TagPattern *string `json:"tagPattern"`
	// Source is the repository URL the provenance's config source
	// must name, as BuildKit spells it (the part before `#`).
	Source *string `json:"source"`
	// Path is the directory within Source, a template over the tag
	// pattern's named groups (${major}/${suite}).
	Path *string `json:"path"`
}

// RefRule is one tag-to-ref convention of a shared-signer scope: a
// tag pattern, and the ref its named groups expand into.
type RefRule struct {
	Tag *string `json:"tag"`
	Ref *string `json:"ref"`
}

// BaseImageMechanism names one base-approval mechanism this engine
// implements. The kinds are code and their parameters are policy —
// the standard/convention split, not a shortage of vocabulary. A kind
// this version does not implement is refused AT LOAD, by name: a new
// mechanism is additive engine work, never a policy contortion and
// never a key that loads and computes nothing.
type BaseImageMechanism string

const (
	// MechanismPinFile approves the digest-pinned base references a
	// committed file carries, each by an approval attestation from a
	// declared attestor under a declared predicate.
	MechanismPinFile BaseImageMechanism = "pin-file"
	// MechanismProvenanceVerified approves the digest-pinned bases a
	// population repository's own build file names under a declared
	// registry prefix, each against the provenance of the identity
	// the pinned reference itself implies — so the approval demanded
	// cannot drift from the pin that names it.
	MechanismProvenanceVerified BaseImageMechanism = "provenance-verified"
	// MechanismSharedSigner approves the digest-pinned bases under a
	// declared registry prefix against the provenance ONE declared
	// signer workflow minted, at whatever signer commit, from the
	// prefix's owner, at the source ref the pin's tag implies by a
	// declared convention (stele#402). It is the shape of an owner
	// whose repositories all sign through one shared signer, which a
	// per-pin identity cannot say: the signer's commit is the
	// publishing release's to pin, and an image's name is not its
	// repository's.
	MechanismSharedSigner BaseImageMechanism = "shared-signer"
)

// BaseImageScope is one approval scope: a name, the mechanism that
// judges it, and that mechanism's parameters. The parameters sit flat
// in the scope rather than nested under the kind because a scope IS
// one mechanism's declaration — and validate refuses a parameter the
// declared mechanism does not read, so a key that means nothing where
// it sits is a load refusal rather than a silent no-op.
type BaseImageScope struct {
	// Name distinguishes this scope in findings and in the pin-file
	// override; names form a set across the section.
	Name *string `json:"name"`
	// Mechanism selects the judgment. A scope that will not say how
	// its bases are approved cannot be computed at all.
	Mechanism *BaseImageMechanism `json:"mechanism"`
	// PinFile is the committed file carrying pinned base references
	// (pin-file).
	PinFile *string `json:"pinFile,omitempty"`
	// AttestorRepo holds the approval attestations; AttestorIdentity
	// is the certificate identity they must verify under (pin-file).
	AttestorRepo     *string `json:"attestorRepo,omitempty"`
	AttestorIdentity *string `json:"attestorIdentity,omitempty"`
	// FromFile is the build file read from every population
	// repository at its default branch; the digest-pinned references
	// it carries are this scope's candidate subjects
	// (provenance-verified, shared-signer).
	FromFile *string `json:"fromFile,omitempty"`
	// RegistryPrefix selects which of those references this scope
	// judges. It ends at the OWNER boundary (`<host>/<owner>/`):
	// provenance-verified reads the publishing repository off the
	// path that follows it, and shared-signer reads the owner whose
	// attestation store it asks off its last segment — derivations
	// whose precondition validate enforces rather than assumes.
	// References outside the prefix are out of scope, not findings:
	// whose bases those are is another mechanism's question
	// (provenance-verified, shared-signer).
	RegistryPrefix *string `json:"registryPrefix,omitempty"`
	// PinPattern parses the pinned reference and Identity is built
	// from its capture groups, so the expected signer is DERIVED FROM
	// THE PIN and the two can never disagree — the shape the org
	// applies wherever an identity could otherwise be restated as a
	// literal. Every group the template names must exist in the
	// pattern, which validate checks (provenance-verified).
	PinPattern *string `json:"pinPattern,omitempty"`
	Identity   *string `json:"identity,omitempty"`
	// SignerWorkflow is the one workflow that signs every base's
	// provenance, owner/repo/path. Its ref is free: a published base
	// is signed at whatever signer commit its own release pinned
	// (trust.WorkflowIdentity) (shared-signer).
	SignerWorkflow *string `json:"signerWorkflow,omitempty"`
	// Refs is the ordered tag-to-ref convention: the first rule whose
	// tag pattern matches the pin's tag names the source ref the base
	// was built at, which the provenance must carry. A tag no rule
	// matches is refused by name (shared-signer).
	Refs []RefRule `json:"refs,omitempty"`
	// PredicateType is the predicate the approving attestation must
	// carry. Every mechanism declares one, because a predicate URI is
	// policy data and never a literal in this engine
	// (docs/versioning.md).
	PredicateType *string `json:"predicateType,omitempty"`
}

func (c *ContinuousPolicy) validate() error {
	for name, f := range map[string]*string{
		"stubPath": c.StubPath, "stubUses": c.StubUses, "registry": c.Registry,
		"tag": c.Tag, paramSignerWorkflow: c.SignerWorkflow, "signerPinPattern": c.SignerPinPattern,
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
	if len(b.Scopes) == 0 && len(b.Upstream) == 0 {
		return errors.New("evidence.baseImages declares no scope and no upstream entry — a base-approval" +
			" section that approves nothing is not one")
	}

	if err := b.validateUpstream(); err != nil {
		return err
	}

	names, prefixes := map[string]bool{}, map[string]string{}

	for i := range b.Scopes {
		s := &b.Scopes[i]

		switch {
		case s.Name == nil || *s.Name == "":
			return fmt.Errorf("evidence.baseImages.scopes[%d].name is absent or empty", i)
		case names[*s.Name]:
			return fmt.Errorf("evidence.baseImages.scopes names %q twice — scope names are a set", *s.Name)
		}

		names[*s.Name] = true

		if err := s.validate(); err != nil {
			return err
		}

		// A prefix ends at the owner boundary (ownerBoundary), so
		// two prefixes overlap only by being equal.
		if p := s.RegistryPrefix; p != nil {
			if other, dup := prefixes[*p]; dup {
				return fmt.Errorf("evidence.baseImages.scopes %s and %s both declare registryPrefix %q — one"+
					" reference, one judgment", other, *s.Name, *p)
			}

			prefixes[*p] = *s.Name
		}
	}

	return nil
}

// validateUpstream holds each upstream entry to its grammar: an
// untagged image named once, an anchored tag pattern, an https source,
// and a path that names only groups the pattern captures. An image
// under a first-party prefix is refused: one reference, one judgment.
func (b *BaseImagesPolicy) validateUpstream() error {
	seen := map[string]bool{}

	for i, u := range b.Upstream {
		field := fmt.Sprintf("evidence.baseImages.upstream[%d]", i)

		for name, v := range map[string]*string{
			"image": u.Image, "tagPattern": u.TagPattern, "source": u.Source, "path": u.Path,
		} {
			if v == nil || *v == "" {
				return fmt.Errorf("%s.%s is absent or empty", field, name)
			}
		}

		repo, err := ociname.NewRepository(*u.Image)
		if err != nil || strings.ContainsAny(*u.Image, ":@") {
			return fmt.Errorf("%s.image %q is not an untagged image reference", field, *u.Image)
		}

		if seen[repo.Name()] {
			return fmt.Errorf("%s.image %q is declared twice — one image, one expected source", field, *u.Image)
		}

		seen[repo.Name()] = true

		if _, err := u.Pattern(); err != nil {
			return fmt.Errorf("%s.%w", field, err)
		}

		if !strings.HasPrefix(*u.Source, "https://") || strings.Contains(*u.Source, "#") {
			return fmt.Errorf("%s.source %q is not an https repository URL", field, *u.Source)
		}

		for j := range b.Scopes {
			if p := b.Scopes[j].RegistryPrefix; p != nil && strings.HasPrefix(*u.Image, *p) {
				return fmt.Errorf("%s.image %q is under scope %s's prefix — one reference, one judgment",
					field, *u.Image, *b.Scopes[j].Name)
			}
		}
	}

	return nil
}

// Pattern compiles the entry's tag pattern, refusing one that is not
// anchored, and a path naming a group the pattern does not capture.
func (u *UpstreamBase) Pattern() (*regexp.Regexp, error) {
	if !strings.HasPrefix(*u.TagPattern, "^") || !strings.HasSuffix(*u.TagPattern, "$") {
		return nil, fmt.Errorf("tagPattern %q is not anchored (^…$) — an unanchored pattern matches inside a"+
			" tag it was never written for", *u.TagPattern)
	}

	re, err := regexp.Compile(*u.TagPattern)
	if err != nil {
		return nil, fmt.Errorf("tagPattern: %w", err)
	}

	if err := templateNamesGroups(*u.Path, re); err != nil {
		return nil, fmt.Errorf("path %w", err)
	}

	return re, nil
}

// paramPredicateType is the one parameter every mechanism owns: a
// predicate URI is policy data whichever way a base is approved.
const paramPredicateType = "predicateType"

// paramSignerWorkflow names the signer both the continuous leg and a
// shared-signer scope declare.
const paramSignerWorkflow = "signerWorkflow"

// paramFromFile and paramRegistryPrefix name the parameters both
// prefix mechanisms — provenance-verified and shared-signer — own.
const (
	paramFromFile       = "fromFile"
	paramRegistryPrefix = "registryPrefix"
)

// paramRefs is the one parameter that is a list rather than a string:
// the ordered tag-to-ref rules. params cannot carry it, so validate
// reads it beside the table — the same two questions, owned and
// declared, asked of it.
const paramRefs = "refs"

// params is every parameter this engine knows how to read off a
// scope, whichever mechanism owns it. One table, so "required by my
// kind" and "read by nobody here" are answered from the same list and
// cannot drift apart.
func (s *BaseImageScope) params() map[string]*string {
	return map[string]*string{
		"pinFile":           s.PinFile,
		"attestorRepo":      s.AttestorRepo,
		"attestorIdentity":  s.AttestorIdentity,
		paramFromFile:       s.FromFile,
		paramRegistryPrefix: s.RegistryPrefix,
		"pinPattern":        s.PinPattern,
		"identity":          s.Identity,
		paramSignerWorkflow: s.SignerWorkflow,
		paramPredicateType:  s.PredicateType,
	}
}

// owns names the parameters one mechanism reads, in the order its
// refusals report them. A kind absent from this switch is a kind this
// engine does not implement — the one place that fact is written.
func owns(m BaseImageMechanism) []string {
	switch m {
	case MechanismPinFile:
		return []string{"pinFile", "attestorRepo", "attestorIdentity", paramPredicateType}
	case MechanismProvenanceVerified:
		return []string{paramFromFile, paramRegistryPrefix, "pinPattern", "identity", paramPredicateType}
	case MechanismSharedSigner:
		return []string{paramFromFile, paramRegistryPrefix, paramSignerWorkflow, paramRefs, paramPredicateType}
	default:
		return nil
	}
}

// validate holds one scope to exactly its mechanism's parameters:
// each one it owns declared, and none it does not. Declaring a
// parameter the mechanism never reads is refused as firmly as
// omitting one it needs — a key nothing computes is the descriptive
// half this section exists to refuse.
func (s *BaseImageScope) validate() error {
	where := "evidence.baseImages.scopes[" + *s.Name + "]"

	if s.Mechanism == nil || *s.Mechanism == "" {
		return fmt.Errorf("%s.mechanism is absent or empty", where)
	}

	owned := owns(*s.Mechanism)
	if owned == nil {
		return fmt.Errorf(
			"%s.mechanism %q is not a base-approval mechanism this stele implements", where, *s.Mechanism,
		)
	}

	declared := s.params()

	for _, name := range owned {
		missing := name == paramRefs && len(s.Refs) == 0
		if f, isString := declared[name]; isString && (f == nil || *f == "") {
			missing = true
		}

		if missing {
			return fmt.Errorf("%s.%s is absent or empty — the %s mechanism requires it",
				where, name, *s.Mechanism)
		}
	}

	for _, name := range slices.Sorted(maps.Keys(declared)) {
		if f := declared[name]; f != nil && *f != "" && !slices.Contains(owned, name) {
			return fmt.Errorf("%s.%s is declared but the %s mechanism does not read it",
				where, name, *s.Mechanism)
		}
	}

	if len(s.Refs) > 0 && !slices.Contains(owned, paramRefs) {
		return fmt.Errorf("%s.%s is declared but the %s mechanism does not read it", where, paramRefs, *s.Mechanism)
	}

	switch *s.Mechanism {
	case MechanismProvenanceVerified:
		return s.validateProvenance(where)
	case MechanismSharedSigner:
		return s.validateSharedSigner(where)
	case MechanismPinFile:
	}

	return nil
}

// validateProvenance checks the two preconditions the
// provenance-verified judgment would otherwise assume: that the
// prefix stops where the owner does, and that the identity template
// names only groups the pattern actually captures.
func (s *BaseImageScope) validateProvenance(where string) error {
	// The publishing repository is read off the reference path
	// immediately after the prefix, so the prefix must end where the
	// owner does. A prefix reaching further would swallow the
	// repository segment and the derivation would address the wrong
	// repository — silently, and in the direction of a pass.
	if !ownerBoundary(*s.RegistryPrefix) {
		return fmt.Errorf(
			"%s.registryPrefix %q does not end at the owner boundary — it must spell <host>/<owner>/, "+
				"because the publishing repository is derived from the reference path that follows it",
			where, *s.RegistryPrefix,
		)
	}

	re, err := regexp.Compile(*s.PinPattern)
	if err != nil {
		return fmt.Errorf("%s.pinPattern: %w", where, err)
	}

	for _, g := range identityGroups(*s.Identity) {
		if !slices.Contains(re.SubexpNames(), g) {
			return fmt.Errorf(
				"%s.identity names the capture group %q, which pinPattern does not define — "+
					"the expansion would silently drop that segment and demand the wrong identity", where, g,
			)
		}
	}

	return nil
}

// validateSharedSigner checks the preconditions the shared-signer
// judgment would otherwise assume: that the prefix stops where the
// owner does, that the signer is a workflow, and that every tag rule
// reads and expands.
func (s *BaseImageScope) validateSharedSigner(where string) error {
	// The owner whose store is asked is the prefix's last segment, so
	// the prefix must end there: one reaching into a repository would
	// name a store nobody keeps.
	if !ownerBoundary(*s.RegistryPrefix) {
		return fmt.Errorf(
			"%s.registryPrefix %q does not end at the owner boundary — it must spell <host>/<owner>/, "+
				"because the owner whose attestation store is read is its last segment",
			where, *s.RegistryPrefix,
		)
	}

	if !signerWorkflowRE.MatchString(*s.SignerWorkflow) {
		return fmt.Errorf("%s.signerWorkflow %q is not owner/repo/path-to-workflow", where, *s.SignerWorkflow)
	}

	_, err := s.RefRules()
	if err != nil {
		return fmt.Errorf("%s.%w", where, err)
	}

	return nil
}

// ownerBoundary reports whether a registry prefix spells exactly
// `<host>/<owner>/`.
func ownerBoundary(prefix string) bool {
	trimmed, slashed := strings.CutSuffix(prefix, "/")

	return slashed && strings.Count(trimmed, "/") == 1 && !strings.HasSuffix(trimmed, "/")
}

// signerWorkflowRE is a workflow named by its repository and path.
var signerWorkflowRE = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+\.ya?ml$`)

// templateNamesGroups refuses a template naming a capture group the
// pattern does not define: the expansion would silently drop that
// segment and demand the wrong value.
func templateNamesGroups(template string, re *regexp.Regexp) error {
	for _, g := range identityGroups(template) {
		if !slices.Contains(re.SubexpNames(), g) {
			return fmt.Errorf("names the capture group %q, which its pattern does not define — the expansion"+
				" would silently drop that segment and demand the wrong value", g)
		}
	}

	return nil
}

// identityVarRE finds the variables an expansion template names, in
// regexp.Expand's own vocabulary: $name, ${name}, and $$ for a
// literal dollar.
var identityVarRE = regexp.MustCompile(`\$(\$|\{([A-Za-z0-9_]+)\}|([A-Za-z0-9_]+))`)

// identityGroups lists the capture groups an identity template names.
// Only NAMED groups are reported: a numbered reference is expanded by
// position, which no policy should depend on and which SubexpNames
// cannot vouch for either way, so it is left to the pattern.
func identityGroups(template string) []string {
	var out []string

	for _, m := range identityVarRE.FindAllStringSubmatch(template, -1) {
		const (
			whole = 1
			brace = 2
			bare  = 3
		)

		if m[whole] == "$" {
			continue // $$ is a literal dollar, not a group
		}

		name := m[brace]
		if name == "" {
			name = m[bare]
		}

		// A numbered reference names a position, not a name; only the
		// pattern can say whether the position exists.
		if name != "" && strings.Trim(name, "0123456789") != "" {
			out = append(out, name)
		}
	}

	return out
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
	// Subjects declares what one planned build leg of this class
	// leaves behind — the shape `stele derive subjects` judges
	// (stele#442). The kinds are the engine's and their parameters
	// the policy's; absent, the class has no subject manifest.
	Subjects *release.SubjectShape `json:"subjects,omitempty"`
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
					name, n,
				)
			}

			seen[n] = true
		}

		// Compiled at load, so a shape the derive leg could not run is
		// refused with the rest of the policy, never mid-release.
		if c.Subjects != nil {
			if _, err := c.Subjects.Compile(name); err != nil {
				return err
			}
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

	// A source verdict binds a SIGNED tag to its commit: owing one
	// from a version while declaring no tag obligation is an
	// obligation nothing can ever meet, and the corpus walk would red
	// every release past it for a reason the policy wrote itself.
	if err := p.validateSourceVerdict(); err != nil {
		return err
	}

	// Only an attestation has an issuer: an upstream entry judges
	// unsigned provenance, so a section declaring only those owes none.
	if (e.Continuous != nil || e.BaseImages != nil && len(e.BaseImages.Scopes) > 0) &&
		(p.Issuer == nil || *p.Issuer == "") {
		return errors.New("issuer is required when evidence.continuous or an evidence.baseImages scope is declared")
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

	if err := p.validateSignerCertificates(); err != nil {
		return err
	}

	if err := p.Published.validate(); err != nil {
		return err
	}

	return p.validateTags()
}

// validateSignerCertificates validates the OPTIONAL signer-certificate
// section; declared means the issuer beside it, because a signer
// identity is a subject AND the issuer that vouched for it.
func (p *Policy) validateSignerCertificates() error {
	if p.SignerCertificates == nil {
		return nil
	}

	if p.Issuer == nil || *p.Issuer == "" {
		return errors.New("issuer is required when signerCertificates is declared")
	}

	return p.SignerCertificates.validate()
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

// validateSourceVerdict refuses half a source-verdict declaration:
// the epoch and the asset name are one obligation (when it is owed,
// and where it is read), and the tag obligation it binds must exist.
func (p *Policy) validateSourceVerdict() error {
	e := p.Evidence

	switch {
	case e.SourceVerdictFromVersion != nil && e.SourceVerdictBundle == nil:
		return errors.New("evidence.sourceVerdictFromVersion is declared without evidence.sourceVerdictBundle — " +
			"an owed verdict needs the asset it is read from")
	case e.SourceVerdictBundle != nil && e.SourceVerdictFromVersion == nil:
		return errors.New("evidence.sourceVerdictBundle is declared without evidence.sourceVerdictFromVersion — " +
			"an asset name owes nothing until an epoch says from when")
	case e.SourceVerdictBundle != nil && *e.SourceVerdictBundle == "":
		return errors.New("evidence.sourceVerdictBundle is empty")
	case e.SourceVerdictFromVersion != nil && p.Tags == nil:
		return errors.New("evidence.sourceVerdictFromVersion is declared but the policy declares no tags section — " +
			"a source verdict binds a signed tag, and this policy owes none")
	}

	return nil
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

	if e.ManifestSchemaFromVersion != nil {
		if _, err := semver.NewVersion(*e.ManifestSchemaFromVersion); err != nil {
			return fmt.Errorf("evidence.manifestSchemaFromVersion: %w", err)
		}
	}

	if e.SourceVerdictFromVersion != nil {
		if _, err := semver.NewVersion(*e.SourceVerdictFromVersion); err != nil {
			return fmt.Errorf("evidence.sourceVerdictFromVersion: %w", err)
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

// sourceVerdict reports whether a release under the given machinery
// version owes a source verdict for its tag (stele#391). Through the
// one owedFrom definition — with the one difference its declaration
// carries: absent means never, because the verdict binds a signed tag
// and an adopter who declares no epoch has said it emits none.
func (e *EvidencePolicy) sourceVerdict(machineryVersion string) bool {
	return e.SourceVerdictFromVersion != nil && owedFrom(e.SourceVerdictFromVersion, machineryVersion)
}

// manifestSchema reports whether a release under the given machinery
// version owes an evidence manifest at the schema this build writes
// (stele#185). The obligation shape is the same as every other epoch,
// which is exactly why it is spelled through the same definition: a
// schema retirement decided by a second reading here would be a
// behaviour of the reader rather than a fact the org declared.
func (e *EvidencePolicy) manifestSchema(machineryVersion string) bool {
	return owedFrom(e.ManifestSchemaFromVersion, machineryVersion)
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
