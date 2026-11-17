// The full-depth leg (#4): the same evidence walk with every covered
// release re-verified through the verify engine — corpus
// re-verification as a flag on the walk, never a second walk. The
// engine is the verify verb's own (single-engine law); this file only
// derives its inputs and maps refusals into the report taxonomy.
//
// Pins are derived per release from the consuming tree, never policy
// literals: a foreign repository reaches the machinery repo through the
// commit-pinned uses: on its own publish workflow at the tag, and the
// machinery repo's releases run their verifier at the tag itself. The
// signer pin is read from the machinery publish workflow at that pin —
// the two-hop resolution a stranger performs.
//
// That derivation has two callers (stele#447): this walk, and `stele
// verify` run for a published release with no pins or subjects given.
// So the reading lives in receiver-free helpers both reach —
// PinRoots.Resolve for the pins, DeriveRelease for the subjects — and
// the walk keeps only what is its own: the findings it records and the
// order it records them in. One derivation, never a copy.

package assert

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/monumental-archive/stele/internal/evidence"
	"github.com/monumental-archive/stele/internal/provenance"
	"github.com/monumental-archive/stele/internal/verify"
)

// DeepVerifier runs the verify engine over one release — interface-
// shaped so every guard in the walk stays table-tested; the CLI wires
// the real engine (single-engine law: assert re-verifies through the
// same code path a stranger runs).
type DeepVerifier interface {
	// Release proves the release; decision=false runs the provenance
	// half alone (pre-decision-epoch history verifies what it can).
	Release(c verify.Coords, subjects []verify.Subject, sboms verify.SBOMs, pins verify.Pins, decision bool) error
	// VSA proves the store-resident verdict over every subject;
	// a nil demand leaves a declared enrichment obligation unasked
	// (pre-enrichment-epoch history proves what it can), and a
	// non-nil one carries the class-keyed names this release owes on
	// top of the universal set.
	VSA(c verify.Coords, subjects []verify.Subject, pins verify.Pins, demand *verify.EnrichmentDemand) error
	// SourceVSA proves one release tag's source verdict (stele#391)
	// from the asset's bytes: the read `verify source-vsa` runs.
	SourceVSA(c verify.Coords, envelope []byte, pins verify.Pins) error
}

// uses40RE finds the machinery pin on a caller's publish workflow:
// the full-commit uses: reference to the machinery repo's publish or release
// workflow. The 40-hex capture is the certificate-grade binding; the
// version comment beside it is presentation.
// The two halves of the deep leg, as an unseen read names them.
const (
	deepRelease = "deep release check"
	deepVerdict = "deep verdict check"
	// deepSourceVerdict is the source-verdict half (stele#391).
	deepSourceVerdict = "deep source verdict check"
)

var uses40RE = regexp.MustCompile(`uses:\s*\S*/(?:publish|release)\.ya?ml@([0-9a-f]{40})`)

// fullDepth re-verifies one release through the engine. Refusals land
// in the taxonomy the walk already has: verdict refusals carry a
// vsa-prefixed assertion so the burned derivation and vsa debt lines
// apply to them exactly as to presence findings; everything else is
// the release engine's own refusal under the "deep" assertion,
// excusable only by a written debt line naming it.
func (w *evidenceWalk) fullDepth(repo, tag string, contract *Contract, bundles []string) error {
	subject := repo + "@" + tag

	// One check for the deep release leg, taken before its outcome is
	// known: the three ways it can fail are one obligation.
	deep := w.check(subject, "deep")

	pinned, err := w.checksumPins(repo, tag)
	if err != nil {
		if unseen(err) {
			return blind(deepRelease, subject, "checksum manifest", err)
		}

		deep.Diverged(err.Error())

		return nil
	}

	files, sboms := w.checksumSubjects(pinned)

	// What the release published somewhere other than its assets
	// (stele#329): no checksum manifest can name it, so it is read
	// from the document that can.
	registry, unplaced, err := w.registrySubjects(repo, tag, contract, files, bundles)
	if err != nil {
		if unseen(err) {
			return blind(deepRelease, subject, "class bundles", err)
		}

		deep.Diverged(err.Error())

		return nil
	}

	subjects := slices.Concat(files, registry)
	if len(subjects) == 0 {
		deep.Diverged(w.pol.namesNoSubjects(contract))

		return nil
	}

	// Both pinning documents are in hand exactly here, and nowhere
	// else in the walk (stele#219). Taken after the subject
	// derivation succeeds: an unreadable checksum manifest is one
	// cause, and `deep` has already spoken for it.
	w.checksumAgreement(subject, contract, pinned)

	pins, err := w.resolvePins(repo, tag)
	if err != nil {
		if unseen(err) {
			return blind(deepRelease, subject, "signing pins", err)
		}

		deep.Diverged(err.Error())

		return nil
	}

	c := verify.Coords{Owner: w.org, Repo: repo, Tag: tag}

	if !contract.Decision {
		w.log("assert: evidence: %s predates the decision epoch — deep release check bounded to provenance", subject)
	}

	// The plan as the decision's denominator (stele#158): what this
	// release planned to inventory, recovered from the obligations its
	// classes owed at its own machinery version — derived once, beside
	// the vocabulary it reads, never re-spelled here.
	planned := w.pol.PlannedInventories(contract, sboms)

	if rerr := w.full.Verifier.Release(
		c, subjects, verify.SBOMs{Assets: sboms, Planned: planned}, pins, contract.Decision,
	); rerr != nil {
		if unseen(rerr) {
			return blind(deepRelease, subject, "release attestations", rerr)
		}

		deep.Diverged(rerr.Error())
	}

	if !contract.StoreVSA {
		// Pre-store verdicts are release assets under the policy's
		// enumerated legacy roots — grandfathered history, held to
		// presence depth. Logged, never silent.
		w.log("assert: evidence: %s predates store verdicts — deep verdict check bounded to presence", subject)

		return nil
	}

	if !w.full.VerdictDeclared {
		// No verdict obligation exists in the trust authority: the
		// deep verdict half cannot run, and saying so is the honest
		// output — a skip that logs is a bounded walk, a skip that
		// does not is a green lie.
		w.log("assert: evidence: %s — the verify policy declares no trust.verdict; deep verdict check skipped", subject)

		return nil
	}

	if len(w.vsaFindings(subject)) > 0 {
		// Presence already found verdicts missing, and the burned
		// derivation has judged those findings. A deep check here
		// would re-red what the taxonomy has spoken for; a deep VSA
		// failure must mean present-but-refusing — a distinct defect
		// no burn excuses.
		w.log("assert: evidence: %s has presence-level verdict findings — deep verdict check yields to them", subject)

		return nil
	}

	demand := w.enrichmentDemand(subject, contract, slices.Concat(files, placed(registry, unplaced)), unplaced)

	vc := w.check(subject, "vsa:deep")
	if verr := w.full.Verifier.VSA(c, subjects, pins, demand); verr != nil {
		if unseen(verr) {
			return blind(deepVerdict, subject, "verification summaries", verr)
		}

		vc.Diverged(verr.Error())
	}

	w.log("assert: evidence: %s re-verified at full depth", subject)

	return nil
}

// enrichmentDemand derives what this release's artifacts owe their
// enrichment claims and states everything the derivation had to say
// (stele#206).
//
// The two things it says are different in kind, so they are said
// differently. A NARROWING — an artifact whose class no manifest can
// state — is not a defect in the release: it is this walk declining to
// overclaim, and it is logged per artifact with the names it did not
// ask for, because a narrowing nobody can read is indistinguishable
// from a walk that never noticed. A DEFECT — a manifest that could
// attribute and did not — is a finding, because post-epoch attribution
// is owed, and letting omission narrow anything would hand a broken
// manifest the leniency that only structural silence earns.
//
// The attribution obligation is judged only where the manifest could
// meet it: recording the check for a release whose schema predates
// attribution would put a permanently unmeetable obligation in the
// journal, and an exception written against it would read as stale
// forever.
func (w *evidenceWalk) enrichmentDemand(
	subject string, contract *Contract, subjects, unplaced []verify.Subject,
) *verify.EnrichmentDemand {
	ad := w.pol.EnrichmentDemand(contract, subjects, unplaced)

	for _, n := range ad.Excused {
		w.log("assert: evidence: %s: %s: %s", subject, n.Artifact, n.Detail)
	}

	if contract.Attributed {
		if c := w.check(subject, "manifest:attribution"); len(ad.Defects) > 0 {
			details := make([]string, 0, len(ad.Defects))
			for _, n := range ad.Defects {
				details = append(details, n.Artifact+": "+n.Detail)
			}

			c.Diverged(strings.Join(details, "; "))
		}
	}

	return ad.Demand
}

// checksumPins reads the release's checksum manifest as what it is:
// every name it pins and the bytes it pins for it, in file order.
//
// It is the ONE reading of that document (stele#219). The subject
// derivation below classifies on top of this slice and the
// cross-check compares against it, so the two legs cannot come to
// different conclusions about what the checksum manifest says — the
// same share-the-definition rule that put one SHA256Hex across emit
// and verify. Lines that pin nothing (blank, commentary, a digest
// that is not one) are not part of the document's claim and are
// skipped once, here.
func (w *evidenceWalk) checksumPins(repo, tag string) ([]verify.Subject, error) {
	return w.pol.readChecksumPins(w.forge, w.org, repo, tag)
}

// readChecksumPins is checksumPins' reading, reachable without a walk.
func (e *EvidencePolicy) readChecksumPins(f AssetReader, owner, repo, tag string) ([]verify.Subject, error) {
	raw, err := f.Asset(owner, repo, tag, *e.Checksums)
	if err != nil {
		return nil, fmt.Errorf("the checksum manifest is unreadable: %w", err)
	}

	var pins []verify.Subject

	for line := range strings.SplitSeq(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || !hex64OnlyRE.MatchString(fields[0]) {
			continue
		}

		pins = append(pins, verify.Subject{Name: fields[1], SHA256: fields[0]})
	}

	return pins, nil
}

// checksumAgreement asks the one question no per-document check can:
// whether the release's two pinning documents describe the same bytes
// (stele#219). Each is internally consistent, and a name carrying one
// digest in the checksum manifest and another in the evidence
// manifest passes both — two pinning documents for one release that
// can silently disagree.
//
// Only the INTERSECTION of names is judged. A name in one document
// and not the other is sound and owned elsewhere: the evidence
// manifest cannot pin itself, the checksum manifest does pin it, and
// asset presence is the presence leg's obligation. Re-judging it here
// would red a release for the documents' own shapes.
//
// The check is recorded only where the source could meet it. A
// contract that cannot pin at all — a manifest schema below entries,
// or no manifest speaking for the release — is a narrowing, logged
// loudly and never recorded: an obligation the release could never
// meet would sit in the journal forever, and any exception written
// against it would read as stale from the day it was written.
func (w *evidenceWalk) checksumAgreement(subject string, contract *Contract, pinned []verify.Subject) {
	if !contract.Pinned {
		w.log("assert: evidence: %s: the contract pins no assets (%s) — the checksum cross-check is not asked",
			subject, contract.Origin)

		return
	}

	details := w.pol.checksumDisagreement(contract, pinned)

	// One check for one obligation — the two documents agree or they
	// do not — taken whether it holds or not, so an excuse for a
	// cross-check this run never performed cannot read as stale.
	if c := w.check(subject, "manifest:checksums"); len(details) > 0 {
		c.Diverged(strings.Join(details, "; "))
	}
}

// checksumDisagreement names every name the two pinning documents pin
// to different bytes — the comparison itself, which the walk records
// as a finding and the verb refuses on. A contract that pins nothing
// disagrees with nothing.
func (e *EvidencePolicy) checksumDisagreement(contract *Contract, pinned []verify.Subject) []string {
	var details []string

	for _, s := range pinned {
		declared, both := contract.Pins[s.Name]
		if !both || declared == s.SHA256 {
			continue
		}

		details = append(details, fmt.Sprintf("%s: %s pins %s, the evidence manifest pins %s",
			s.Name, *e.Checksums, s.SHA256, declared))
	}

	return details
}

// checksumSubjects classifies the checksum manifest's pins into the
// verify engine's subject list — the same manifest a stranger pins
// bytes against. SBOM candidates are the subset carrying the policy's
// SBOM suffix.
//
// It answers for the release's ASSETS and nothing else, so an empty
// answer is not a refusal here: a release whose every artifact lives
// in a registry pins only documents, correctly (stele#329). Whether
// the release names any subject at all is asked once, by the caller,
// with both halves in hand.
//
//nolint:gocritic // unnamedResult: subjects then sboms, documented above
func (w *evidenceWalk) checksumSubjects(pinned []verify.Subject) ([]verify.Subject, []verify.Subject) {
	return w.pol.splitChecksumPins(pinned)
}

// splitChecksumPins is checksumSubjects' classification, reachable
// without a walk.
//
//nolint:gocritic // unnamedResult: subjects then sboms, as checksumSubjects documents
func (e *EvidencePolicy) splitChecksumPins(pinned []verify.Subject) ([]verify.Subject, []verify.Subject) {
	var subjects, sboms []verify.Subject

	for _, s := range pinned {
		// The checksum manifest pins evidence documents beside the
		// artifacts, and a document about the release is not a subject
		// of its build (measured on v0.5.0: provenance covers exactly
		// the artifacts — a bundle cannot vouch for itself). Documents
		// are excluded from the provenance subject set; SBOMs travel
		// separately as the decision candidates, which is why they are
		// taken FIRST: the shared classifier calls an SBOM a document,
		// and this walk needs the subset by name.
		switch {
		case strings.HasSuffix(s.Name, *e.SBOMSuffix):
			sboms = append(sboms, s)
		case e.Classify(s.Name) == evidence.TypeEvidence:
		default:
			subjects = append(subjects, s)
		}
	}

	return subjects, sboms
}

// registrySubjects answers what the release published somewhere other
// than its assets — a container image, a registry package — as the
// verify engine names a subject (stele#329).
//
// Where the contract can say, the contract is READ, and the release's
// own provenance is held against it: a subject a class bundle attests
// that neither pinning document names is a release whose claim and
// whose evidence disagree about what it shipped, and that is the
// `manifest:subjects` finding. The claim comes first on purpose. A
// list read back out of the proofs can only ever say that the proofs
// which exist are sound; an artifact published with no proof at all is
// invisible to it, and visible to a list the release wrote.
//
// Where the contract cannot say — a manifest whose schema predates
// registry entries, or no manifest at all — the bundles are the only
// document that names these subjects, so they are read from there, and
// the walk says so per release. That is history proving what it CAN
// prove: an immutable manifest cannot be re-emitted, and refusing the
// release would red it forever for a format it was never offered. The
// second return names those subjects, because nothing attributed them
// to a class and the demand derivation must narrow rather than accuse.
//
//nolint:gocritic // unnamedResult: the registry subjects, then the ones no source placed — named above
func (w *evidenceWalk) registrySubjects(
	repo, tag string, contract *Contract, files []verify.Subject, bundles []string,
) ([]verify.Subject, []verify.Subject, error) {
	subject := repo + "@" + tag

	attested, err := w.provenanceSubjects(repo, tag, bundles)
	if err != nil && unseen(err) {
		// A bundle the run could not read is not a cross-check that
		// failed: the release's claim was never held against anything.
		return nil, nil, err
	}

	if contract.Registered {
		claimed := subjectSet(slices.Concat(files, contract.RegistrySubjects))

		// One check for one obligation, taken whether it holds or not —
		// an excuse for a cross-check this run never performed must not
		// read as stale.
		switch c := w.check(subject, "manifest:subjects"); {
		case err != nil:
			c.Diverged(err.Error())
		default:
			if stray := unclaimed(attested, claimed); len(stray) > 0 {
				c.Diverged(w.pol.strayMessage(stray))
			}
		}

		return contract.RegistrySubjects, nil, nil
	}

	if err != nil {
		return nil, nil, err
	}

	derived := derivedRegistry(files, attested)

	if len(derived) > 0 {
		w.log("assert: evidence: %s: %s names no registry subject — %d read from the release's own provenance",
			subject, registrySource(contract), len(derived))
	}

	return derived, derived, nil
}

// derivedRegistry is what the release's provenance attests beyond the
// assets its checksum manifest pins — the registry subjects of a
// release whose contract cannot name them, in attestation order, each
// once.
func derivedRegistry(files, attested []verify.Subject) []verify.Subject {
	var derived []verify.Subject

	claimed := subjectSet(files)

	for _, s := range attested {
		if line := s.SHA256 + "  " + s.Name; !claimed[line] {
			claimed[line] = true

			derived = append(derived, s)
		}
	}

	return derived
}

// strayMessage is the one spelling of a release whose provenance
// attests subjects its claim does not name.
func (e *EvidencePolicy) strayMessage(stray []string) string {
	return "provenance attests subject(s) neither " + *e.Checksums +
		" nor the evidence manifest names: " + strings.Join(stray, "; ")
}

// namesNoSubjects is the one spelling of a release that claims no
// artifact at all.
func (e *EvidencePolicy) namesNoSubjects(contract *Contract) string {
	return fmt.Sprintf(
		"the release names no artifact subjects — %s pins no artifact and %s names none: a release that"+
			" claims nothing verifies nothing", *e.Checksums, registrySource(contract),
	)
}

// registrySource names the document that did, or could not, say what
// the release published outside its assets.
func registrySource(contract *Contract) string {
	if contract.ManifestSchema == 0 {
		return "the contract (" + contract.Origin + ")"
	}

	return fmt.Sprintf("the evidence manifest (schema %d)", contract.ManifestSchema)
}

// subjectSet keys subjects the way the verify engine does: digest and
// name together, because two artifacts may share either one alone.
func subjectSet(subjects []verify.Subject) map[string]bool {
	out := make(map[string]bool, len(subjects))
	for _, s := range subjects {
		out[s.SHA256+"  "+s.Name] = true
	}

	return out
}

// unclaimed lists the attested subjects the claim does not name.
func unclaimed(attested []verify.Subject, claimed map[string]bool) []string {
	var out []string

	for _, s := range attested {
		if line := s.SHA256 + "  " + s.Name; !claimed[line] {
			claimed[line] = true

			out = append(out, s.Name+" (sha256:"+s.SHA256+")")
		}
	}

	return out
}

// placed is the registry subjects a source attributed: all of them
// where the contract named them, none where they were read back out of
// the bundles.
func placed(registry, unplaced []verify.Subject) []verify.Subject {
	if len(unplaced) > 0 {
		return nil
	}

	return registry
}

// provenanceSubjects reads every subject the release's present class
// bundles attest PROVENANCE over, named and digested. Provenance only:
// its subjects are the artifacts of the build by definition, while a
// verdict or a triage statement riding the same asset is a claim about
// them and names nothing new.
//
// The bundles are the ones the presence leg already judged — the same
// list, so the two legs cannot disagree about which assets carry the
// release's evidence.
func (w *evidenceWalk) provenanceSubjects(repo, tag string, bundles []string) ([]verify.Subject, error) {
	return readProvenanceSubjects(w.forge, w.org, repo, tag, bundles)
}

// readProvenanceSubjects is provenanceSubjects' reading, reachable
// without a walk.
func readProvenanceSubjects(f AssetReader, owner, repo, tag string, bundles []string) ([]verify.Subject, error) {
	var out []verify.Subject

	for _, asset := range bundles {
		raw, err := f.Asset(owner, repo, tag, asset)
		if err != nil {
			return nil, fmt.Errorf("%s is unreadable: %w", asset, err)
		}

		subjects, err := bundleSubjects(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", asset, err)
		}

		out = append(out, subjects...)
	}

	return out, nil
}

// bundleSubjects reads the provenance subjects out of one bundle
// asset. A provenance subject with no name or no sha256 digest is a
// refusal, not a skip: the verify engine asks for a subject by both,
// and one this walk dropped would be an artifact nobody verified.
func bundleSubjects(raw []byte) ([]verify.Subject, error) {
	var out []verify.Subject

	err := eachStatement(raw, func(line int, stmt *stmtSubjects) error {
		if stmt.PredicateType == nil || *stmt.PredicateType != provenance.PredicateType {
			return nil
		}

		for _, s := range stmt.Subject {
			d, ok := s.Digest["sha256"]
			if s.Name == nil || *s.Name == "" || !ok || !hex64OnlyRE.MatchString(d) {
				return fmt.Errorf("bundle line %d: a provenance subject carries no name or no sha256 digest", line)
			}

			out = append(out, verify.Subject{Name: *s.Name, SHA256: d})
		}

		return nil
	})

	return out, err
}

// resolvePins derives the machinery and signer pins for one release —
// the walk's call into the one derivation.
func (w *evidenceWalk) resolvePins(repo, tag string) (verify.Pins, error) {
	return w.full.Resolve(w.forge, w.org, repo, tag)
}

// FileReader is the one forge read pin resolution makes: a workflow
// file at a ref. found=false is the forge's 404 — an answer.
type FileReader interface {
	FileAt(owner, repo, path, ref string) (content []byte, found bool, err error)
}

// AssetReader is the one forge read subject derivation makes per
// document: a release asset's bytes.
type AssetReader interface {
	Asset(owner, repo, tag, name string) ([]byte, error)
}

// PinRoots is what resolving a release's signing pins needs: the tag
// resolver and the roots the verify policy's trust identities name.
// Built by NewPinRoots, so the walk and the verb derive the roots from
// the identities one way (stele#447).
type PinRoots struct {
	// Tags resolves a release tag to its commit — read through git, by
	// the same resolution the tag audit uses (stele#384).
	Tags                          TagResolver
	MachineryOwner, MachineryRepo string
	SignerWorkflow                string
	// SelfSigned marks the self-attesting topology: the signer
	// identity is templated to the repository under verification, so
	// pins derive from each release's own tag, no machinery hop.
	SelfSigned bool
}

// NewPinRoots derives the pin-resolution roots from the verify policy's
// trust identities. verifierWorkflow is empty when the policy declares
// no verdict obligation; the machinery repository is then unknown, and
// only the self-attesting topology resolves.
func NewPinRoots(tags TagResolver, verifierWorkflow, signerWorkflow string) (PinRoots, error) {
	const ownerRepoPath = 3

	if tags == nil {
		return PinRoots{}, errors.New("pin resolution needs a tag resolver: the pins are read through git")
	}

	roots := PinRoots{
		Tags:           tags,
		SignerWorkflow: signerWorkflow,
		SelfSigned:     strings.Contains(signerWorkflow, "{"),
	}

	if verifierWorkflow == "" {
		return roots, nil
	}

	parts := strings.SplitN(verifierWorkflow, "/", ownerRepoPath)
	if len(parts) < ownerRepoPath {
		return PinRoots{}, fmt.Errorf("verifier workflow %q does not name owner/repo/path", verifierWorkflow)
	}

	roots.MachineryOwner, roots.MachineryRepo = parts[0], parts[1]

	return roots, nil
}

// Resolve derives the machinery and signer pins for one release from
// the trees a stranger can read: the caller's publish workflow at the
// tag carries the machinery pin; the machinery publish workflow at that
// pin carries the signer pin. The machinery repo's own releases run at
// the tag.
func (r PinRoots) Resolve(f FileReader, owner, repo, tag string) (verify.Pins, error) {
	machineryOwner, machineryRepo := r.MachineryOwner, r.MachineryRepo
	signerWorkflow := r.SignerWorkflow

	// The self-attesting topology (#82): a templated signer identity
	// means every repository signs for itself — there is no foreign
	// machinery tree to hop through, and both pins ARE the release
	// commit: the certificate names the repo's own workflow at the
	// tag, and its signer digest is the tag's commit.
	if r.SelfSigned {
		sha, err := r.Tags.TagCommit(owner, repo, tag)
		if err != nil {
			return verify.Pins{}, fmt.Errorf("the tag's commit is unreadable: %w", err)
		}

		return verify.Pins{Machinery: sha, Signer: sha}, nil
	}

	if machineryOwner == "" {
		return verify.Pins{}, errors.New(
			"the verify policy names no machinery repository (no trust.verdict) and the signer identity is not" +
				" templated — pins cannot be derived; declare one or the other",
		)
	}

	var machineryPin string

	if owner == machineryOwner && repo == machineryRepo {
		sha, err := r.Tags.TagCommit(owner, repo, tag)
		if err != nil {
			return verify.Pins{}, fmt.Errorf("the tag's commit is unreadable: %w", err)
		}

		machineryPin = sha
	} else {
		wf, ok, err := f.FileAt(owner, repo, ".github/workflows/publish.yml", tag)
		if err != nil {
			return verify.Pins{}, fmt.Errorf("the publish workflow at the tag is unreadable: %w", err)
		}

		m := uses40RE.FindSubmatch(wf)
		if !ok || m == nil {
			return verify.Pins{}, fmt.Errorf(
				"no full-commit machinery pin on the publish workflow at %s — the verifier identity cannot be derived", tag,
			)
		}

		machineryPin = string(m[1])
	}

	machineryPublish, ok, err := f.FileAt(
		machineryOwner, machineryRepo, ".github/workflows/publish.yml", machineryPin,
	)
	if err != nil {
		return verify.Pins{}, fmt.Errorf(
			"the machinery publish workflow at %.12s is unreadable: %w", machineryPin, err,
		)
	}

	if !ok {
		return verify.Pins{}, fmt.Errorf("the machinery repository carries no publish workflow at %.12s", machineryPin)
	}

	signerRE, err := regexp.Compile(regexp.QuoteMeta(signerWorkflow) + `@([0-9a-f]{40})`)
	if err != nil {
		return verify.Pins{}, fmt.Errorf("the signer pin pattern does not compile: %w", err)
	}

	sm := signerRE.FindSubmatch(machineryPublish)
	if sm == nil {
		return verify.Pins{}, fmt.Errorf(
			"the machinery repository at %.12s declares no signer pin for %s — the provenance identity cannot be derived",
			machineryPin, signerWorkflow,
		)
	}

	return verify.Pins{Machinery: machineryPin, Signer: string(sm[1])}, nil
}

// FullDepth is everything the full-depth leg needs beyond the walk:
// the engine (behind the seam) and the pin-resolution roots derived
// from the VERIFY policy — the machinery repository is the verifier
// workflow's own, a fact of the identity, not a second declaration.
type FullDepth struct {
	// PinRoots resolves each release's pins — the one derivation the
	// verb shares (stele#447).
	PinRoots

	Verifier DeepVerifier
	// VerdictDeclared reports whether the verify policy declares a
	// trust.verdict — undeclared, the deep verdict half skips with a
	// log line, never a silent pass and never a refusal of the walk.
	VerdictDeclared bool
}

// NewFullDepth derives the pin-resolution roots from the verify
// policy's trust identities. verifierWorkflow is empty when the
// policy declares no verdict obligation.
func NewFullDepth(v DeepVerifier, tags TagResolver, verifierWorkflow, signerWorkflow string) (*FullDepth, error) {
	if tags == nil {
		return nil, errors.New("full depth needs a tag resolver: the pins are read through git")
	}

	roots, err := NewPinRoots(tags, verifierWorkflow, signerWorkflow)
	if err != nil {
		return nil, err
	}

	return &FullDepth{Verifier: v, PinRoots: roots, VerdictDeclared: verifierWorkflow != ""}, nil
}

// SBOMSuffix reports the policy's SBOM asset suffix — the naming
// convention an inventory is published under, which is org data and
// therefore never a literal in a judge.
func (p *Policy) SBOMSuffix() string {
	if p.Evidence == nil || p.Evidence.SBOMSuffix == nil {
		return ""
	}

	return *p.Evidence.SBOMSuffix
}

// ReleaseForge is what deriving one release's verify inputs reads: the
// release's asset listing and each asset's bytes.
type ReleaseForge interface {
	AssetReader
	ReleaseAssets(owner, repo, tag string) ([]string, error)
}

// ReleaseInputs is what one published release states about itself, as
// the verify engine takes it: the artifact subjects, and the SBOM
// assets with the inventory plan they are the denominator of.
type ReleaseInputs struct {
	Subjects []verify.Subject
	SBOMs    verify.SBOMs
}

// DeriveRelease reads the subjects, SBOM assets and inventory plan one
// release's own published evidence states — the deep walk's reading,
// composed for a caller that holds no walk (stele#447: `stele verify`
// run with no --subjects). Every step is the helper the walk calls;
// what differs is only what a failure is. The walk records a finding
// and carries on judging; this derivation has no journal, so each of
// the walk's findings about the release's claim is a refusal here,
// spelled as the walk spells it. A refused derivation is never a
// narrower list: a subject list a verifier was handed short is a
// verdict about less than the release shipped.
//
// The one exception is an owed class bundle the release does not
// carry. The walk records its absence and reads the bundles that are
// present; so does this, logged, because the bundles here only
// cross-check the claim — the attestations themselves are the
// engine's to fetch and prove, from the store.
func (e *EvidencePolicy) DeriveRelease(
	f ReleaseForge, src ContractSource, owner, repo, tag string, log Logf,
) (*ReleaseInputs, error) {
	subject := owner + "/" + repo + "@" + tag

	contract, ok, err := src.Contract(owner, repo, tag)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("no evidence contract speaks for %s — neither %s nor a publish workflow"+
			" at the tag says what the release shipped", subject, *e.ManifestAsset)
	}

	assets, err := f.ReleaseAssets(owner, repo, tag)
	if err != nil {
		return nil, fmt.Errorf("the assets of %s are unreadable: %w", subject, err)
	}

	have := make(map[string]bool, len(assets))
	for _, a := range assets {
		have[a] = true
	}

	present, absent := e.presentBundles(e.owedBundles(contract), have)
	for _, b := range slices.Sorted(maps.Keys(absent)) {
		log("%s: the owed class bundle %s is absent — the claim is cross-checked against the bundles present",
			subject, b)
	}

	pinned, err := e.readChecksumPins(f, owner, repo, tag)
	if err != nil {
		return nil, err
	}

	files, sboms := e.splitChecksumPins(pinned)

	if contract.Pinned {
		if details := e.checksumDisagreement(contract, pinned); len(details) > 0 {
			return nil, errors.New(strings.Join(details, "; "))
		}
	}

	attested, err := readProvenanceSubjects(f, owner, repo, tag, present)
	if err != nil {
		return nil, err
	}

	registry := derivedRegistry(files, attested)

	if contract.Registered {
		claimed := subjectSet(slices.Concat(files, contract.RegistrySubjects))
		if stray := unclaimed(attested, claimed); len(stray) > 0 {
			return nil, errors.New(e.strayMessage(stray))
		}

		registry = contract.RegistrySubjects
	}

	subjects := slices.Concat(files, registry)
	if len(subjects) == 0 {
		return nil, errors.New(e.namesNoSubjects(contract))
	}

	return &ReleaseInputs{
		Subjects: subjects,
		SBOMs:    verify.SBOMs{Assets: sboms, Planned: e.PlannedInventories(contract, sboms)},
	}, nil
}
