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

package assert

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/monumental-archive/stele/internal/evidence"
	"github.com/monumental-archive/stele/internal/gh"
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
}

// uses40RE finds the machinery pin on a caller's publish workflow:
// the full-commit uses: reference to the machinery repo's publish or release
// workflow. The 40-hex capture is the certificate-grade binding; the
// version comment beside it is presentation.
var uses40RE = regexp.MustCompile(`uses:\s*\S*/(?:publish|release)\.ya?ml@([0-9a-f]{40})`)

// fullDepth re-verifies one release through the engine. Refusals land
// in the taxonomy the walk already has: verdict refusals carry a
// vsa-prefixed assertion so the burned derivation and vsa debt lines
// apply to them exactly as to presence findings; everything else is
// the release engine's own refusal under the "deep" assertion,
// excusable only by a written debt line naming it.
func (w *evidenceWalk) fullDepth(repo, tag string, contract *Contract) error {
	subject := repo + "@" + tag

	// One check for the deep release leg, taken before its outcome is
	// known: the three ways it can fail are one obligation.
	deep := w.check(subject, "deep")

	subjects, sboms, err := w.checksumSubjects(repo, tag)
	if err != nil {
		deep.Diverged(err.Error())

		return nil
	}

	pins, err := w.resolvePins(repo, tag)
	if err != nil {
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

	demand := w.enrichmentDemand(subject, contract, subjects)

	vc := w.check(subject, "vsa:deep")
	if verr := w.full.Verifier.VSA(c, subjects, pins, demand); verr != nil {
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
	subject string, contract *Contract, subjects []verify.Subject,
) *verify.EnrichmentDemand {
	ad := w.pol.EnrichmentDemand(contract, subjects)

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

// checksumSubjects reads the release's checksum manifest into the
// verify engine's subject list — the same manifest a stranger pins
// bytes against. SBOM candidates are the subset carrying the policy's
// SBOM suffix.
//
//nolint:gocritic // unnamedResult: subjects then sboms, documented above
func (w *evidenceWalk) checksumSubjects(repo, tag string) ([]verify.Subject, []verify.Subject, error) {
	raw, err := w.forge.Asset(w.org, repo, tag, *w.pol.Checksums)
	if err != nil {
		return nil, nil, fmt.Errorf("the checksum manifest is unreadable: %w", err)
	}

	var subjects, sboms []verify.Subject

	for line := range strings.SplitSeq(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || !hex64OnlyRE.MatchString(fields[0]) {
			continue
		}

		s := verify.Subject{Name: fields[1], SHA256: fields[0]}

		// The checksum manifest pins evidence documents beside the
		// artifacts, and a document about the release is not a subject
		// of its build (measured on v0.5.0: provenance covers exactly
		// the artifacts — a bundle cannot vouch for itself). Documents
		// are excluded from the provenance subject set; SBOMs travel
		// separately as the decision candidates, which is why they are
		// taken FIRST: the shared classifier calls an SBOM a document,
		// and this walk needs the subset by name.
		switch {
		case strings.HasSuffix(s.Name, *w.pol.SBOMSuffix):
			sboms = append(sboms, s)
		case w.pol.Classify(s.Name) == evidence.TypeEvidence:
		default:
			subjects = append(subjects, s)
		}
	}

	if len(subjects) == 0 {
		return nil, nil, fmt.Errorf(
			"%s names no artifact subjects — a manifest that pins nothing verifies nothing", *w.pol.Checksums)
	}

	return subjects, sboms, nil
}

// resolvePins derives the machinery and signer pins for one release from
// the trees a stranger can read: the caller's publish workflow at the
// tag carries the machinery pin; the machinery publish workflow at that
// pin carries the signer pin. The machinery repo's own releases run at
// the tag.
func (w *evidenceWalk) resolvePins(repo, tag string) (verify.Pins, error) {
	machineryOwner, machineryRepo := w.full.MachineryOwner, w.full.MachineryRepo
	signerWorkflow := w.full.SignerWorkflow

	// The self-attesting topology (#82): a templated signer identity
	// means every repository signs for itself — there is no foreign
	// machinery tree to hop through, and both pins ARE the release
	// commit: the certificate names the repo's own workflow at the
	// tag, and its signer digest is the tag's commit.
	if w.full.SelfSigned {
		sha, err := w.forge.TagCommit(w.org, repo, tag)
		if err != nil {
			return verify.Pins{}, fmt.Errorf("the tag's commit is unreadable: %w", err)
		}

		return verify.Pins{Machinery: sha, Signer: sha}, nil
	}

	if machineryOwner == "" {
		return verify.Pins{}, errors.New(
			"the verify policy names no machinery repository (no trust.verdict) and the signer identity is not" +
				" templated — pins cannot be derived; declare one or the other")
	}

	var machineryPin string

	if w.org == machineryOwner && repo == machineryRepo {
		sha, err := w.forge.TagCommit(w.org, repo, tag)
		if err != nil {
			return verify.Pins{}, fmt.Errorf("the tag's commit is unreadable: %w", err)
		}

		machineryPin = sha
	} else {
		wf, ok, err := w.forge.FileAt(w.org, repo, ".github/workflows/publish.yml", tag)
		if err != nil {
			return verify.Pins{}, fmt.Errorf("the publish workflow at the tag is unreadable: %w", err)
		}

		m := uses40RE.FindSubmatch(wf)
		if !ok || m == nil {
			return verify.Pins{}, fmt.Errorf(
				"no full-commit machinery pin on the publish workflow at %s — the verifier identity cannot be derived", tag)
		}

		machineryPin = string(m[1])
	}

	machineryPublish, ok, err := w.forge.FileAt(
		machineryOwner, machineryRepo, ".github/workflows/publish.yml", machineryPin)
	if err != nil {
		return verify.Pins{}, fmt.Errorf(
			"the machinery publish workflow at %.12s is unreadable: %w", machineryPin, err)
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
			machineryPin, signerWorkflow)
	}

	return verify.Pins{Machinery: machineryPin, Signer: string(sm[1])}, nil
}

// FullDepth is everything the full-depth leg needs beyond the walk:
// the engine (behind the seam) and the pin-resolution roots derived
// from the VERIFY policy — the machinery repository is the verifier
// workflow's own, a fact of the identity, not a second declaration.
type FullDepth struct {
	Verifier                      DeepVerifier
	MachineryOwner, MachineryRepo string
	SignerWorkflow                string
	// SelfSigned marks the self-attesting topology: the signer
	// identity is templated to the repository under verification, so
	// pins derive from each release's own tag, no machinery hop.
	SelfSigned bool
	// VerdictDeclared reports whether the verify policy declares a
	// trust.verdict — undeclared, the deep verdict half skips with a
	// log line, never a silent pass and never a refusal of the walk.
	VerdictDeclared bool
}

// NewFullDepth derives the pin-resolution roots from the verify
// policy's trust identities. verifierWorkflow is empty when the
// policy declares no verdict obligation.
func NewFullDepth(v DeepVerifier, verifierWorkflow, signerWorkflow string) (*FullDepth, error) {
	const ownerRepoPath = 3

	fd := &FullDepth{
		Verifier:        v,
		SignerWorkflow:  signerWorkflow,
		SelfSigned:      strings.Contains(signerWorkflow, "{"),
		VerdictDeclared: verifierWorkflow != "",
	}

	if !fd.VerdictDeclared {
		return fd, nil
	}

	parts := strings.SplitN(verifierWorkflow, "/", ownerRepoPath)
	if len(parts) < ownerRepoPath {
		return nil, fmt.Errorf("verifier workflow %q does not name owner/repo/path", verifierWorkflow)
	}

	fd.MachineryOwner, fd.MachineryRepo = parts[0], parts[1]

	return fd, nil
}

// ReleaseInputs derives the verify engine's inputs for one release
// from the forge alone: the subjects its checksum manifest pins, the
// SBOM candidates beside them, and the two commit pins its identities
// are bound at.
//
// Exported for `stele level`, which asks the same question the deep
// leg asks — "what did this release actually ship, and under which
// pins" — and must not answer it a second way. A second derivation of
// a subject set is a second answer waiting to disagree.
//
//nolint:gocritic // unnamedResult: subjects, sboms, pins — named in the doc
func ReleaseInputs(
	pol *Policy, full *FullDepth, forge gh.Forge, owner, repo, tag string,
) ([]verify.Subject, []verify.Subject, verify.Pins, error) {
	if pol.Evidence == nil {
		return nil, nil, verify.Pins{}, errors.New("assert: the policy declares no evidence section")
	}

	w := &evidenceWalk{pol: pol.Evidence, org: owner, forge: forge, full: full}

	subjects, sboms, err := w.checksumSubjects(repo, tag)
	if err != nil {
		return nil, nil, verify.Pins{}, fmt.Errorf("assert: %s/%s@%s: %w", owner, repo, tag, err)
	}

	pins, err := w.resolvePins(repo, tag)
	if err != nil {
		return nil, nil, verify.Pins{}, fmt.Errorf("assert: %s/%s@%s: %w", owner, repo, tag, err)
	}

	return subjects, sboms, pins, nil
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
