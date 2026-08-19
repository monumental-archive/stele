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
	"slices"
	"strings"

	"github.com/monumental-archive/stele/internal/verify"
)

// DeepVerifier runs the verify engine over one release — interface-
// shaped so every guard in the walk stays table-tested; the CLI wires
// the real engine (single-engine law: assert re-verifies through the
// same code path a stranger runs).
type DeepVerifier interface {
	// Release proves the release; decision=false runs the provenance
	// half alone (pre-decision-epoch history verifies what it can).
	Release(c verify.Coords, subjects, sboms []verify.Subject, pins verify.Pins, decision bool) error
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

	subjects, sboms, err := w.checksumSubjects(repo, tag)
	if err != nil {
		w.finding(subject, "deep", err.Error())

		return nil
	}

	pins, err := w.resolvePins(repo, tag)
	if err != nil {
		w.finding(subject, "deep", err.Error())

		return nil
	}

	c := verify.Coords{Owner: w.org, Repo: repo, Tag: tag}

	if !contract.Decision {
		w.log("assert: evidence: %s predates the decision epoch — deep release check bounded to provenance", subject)
	}

	if rerr := w.full.Verifier.Release(c, subjects, sboms, pins, contract.Decision); rerr != nil {
		w.finding(subject, "deep", rerr.Error())
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

	if verr := w.full.Verifier.VSA(c, subjects, pins, w.pol.EnrichmentDemand(contract)); verr != nil {
		w.finding(subject, "vsa:deep", verr.Error())
	}

	w.log("assert: evidence: %s re-verified at full depth", subject)

	return nil
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
		// separately as the decision candidates.
		switch {
		case strings.HasSuffix(s.Name, *w.pol.SBOMSuffix):
			sboms = append(sboms, s)
		case w.evidenceDocument(s.Name):
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

// evidenceDocument reports whether a checksum entry is one of the
// release's own evidence documents rather than an artifact: the
// policy-known bundles, the umbrella, the contract manifest, and any
// declared evidence suffixes (the org's VEX documents, for one).
func (w *evidenceWalk) evidenceDocument(name string) bool {
	if name == *w.pol.Checksums || name == *w.pol.UmbrellaBundle || name == *w.pol.ManifestAsset {
		return true
	}

	for _, cp := range w.pol.Classes {
		if slices.Contains(cp.Bundles, name) || slices.Contains(cp.LegacyVSABundles, name) {
			return true
		}

		// Deliberately epoch-free: whether an obligation is OWED is a
		// per-release question, but a shipped document is a document —
		// a pre-epoch release that published the asset anyway must not
		// have it counted as a build subject.
		for _, ob := range cp.AssetPrefixes {
			if strings.HasPrefix(name, *ob.Prefix) {
				return true
			}
		}
	}

	for _, suffix := range w.pol.EvidenceSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}

	return false
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
