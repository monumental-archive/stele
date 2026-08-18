// The full-depth leg (#4): the same evidence walk with every covered
// release re-verified through the verify engine — corpus
// re-verification as a flag on the walk, never a second walk. The
// engine is the verify verb's own (single-engine law); this file only
// derives its inputs and maps refusals into the report taxonomy.
//
// Pins are derived per release from the consuming tree, never policy
// literals: a foreign repository reaches the canon through the
// commit-pinned uses: on its own publish workflow at the tag, and the
// canon's releases run their verifier at the tag itself. The signer
// pin is read from the canon's publish workflow at that same pin —
// the two-hop resolution a stranger performs.

package assert

import (
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
	// VSA proves the store-resident verdict over every subject.
	VSA(c verify.Coords, subjects []verify.Subject, pins verify.Pins) error
}

// uses40RE finds the canon pin on a caller's publish workflow: the
// full-commit uses: reference to the canon's publish or release
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

	if len(w.vsaFindings(subject)) > 0 {
		// Presence already found verdicts missing, and the burned
		// derivation has judged those findings. A deep check here
		// would re-red what the taxonomy has spoken for; a deep VSA
		// failure must mean present-but-refusing — a distinct defect
		// no burn excuses.
		w.log("assert: evidence: %s has presence-level verdict findings — deep verdict check yields to them", subject)

		return nil
	}

	if verr := w.full.Verifier.VSA(c, subjects, pins); verr != nil {
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

		for _, prefix := range cp.AssetPrefixes {
			if strings.HasPrefix(name, prefix) {
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

// resolvePins derives the canon and signer pins for one release from
// the trees a stranger can read: the caller's publish workflow at the
// tag carries the canon pin; the canon's publish workflow at that pin
// carries the signer pin. The canon's own releases run at the tag.
func (w *evidenceWalk) resolvePins(repo, tag string) (verify.Pins, error) {
	canonOwner, canonRepo := w.full.CanonOwner, w.full.CanonRepo
	signerWorkflow := w.full.SignerWorkflow

	var canonPin string

	if w.org == canonOwner && repo == canonRepo {
		sha, err := w.forge.TagCommit(w.org, repo, tag)
		if err != nil {
			return verify.Pins{}, fmt.Errorf("the tag's commit is unreadable: %w", err)
		}

		canonPin = sha
	} else {
		wf, ok, err := w.forge.FileAt(w.org, repo, ".github/workflows/publish.yml", tag)
		if err != nil {
			return verify.Pins{}, fmt.Errorf("the publish workflow at the tag is unreadable: %w", err)
		}

		m := uses40RE.FindSubmatch(wf)
		if !ok || m == nil {
			return verify.Pins{}, fmt.Errorf(
				"no full-commit canon pin on the publish workflow at %s — the verifier identity cannot be derived", tag)
		}

		canonPin = string(m[1])
	}

	canonPublish, ok, err := w.forge.FileAt(canonOwner, canonRepo, ".github/workflows/publish.yml", canonPin)
	if err != nil {
		return verify.Pins{}, fmt.Errorf("the canon publish workflow at %.12s is unreadable: %w", canonPin, err)
	}

	if !ok {
		return verify.Pins{}, fmt.Errorf("the canon carries no publish workflow at %.12s", canonPin)
	}

	signerRE, err := regexp.Compile(regexp.QuoteMeta(signerWorkflow) + `@([0-9a-f]{40})`)
	if err != nil {
		return verify.Pins{}, fmt.Errorf("the signer pin pattern does not compile: %w", err)
	}

	sm := signerRE.FindSubmatch(canonPublish)
	if sm == nil {
		return verify.Pins{}, fmt.Errorf(
			"the canon at %.12s declares no signer pin for %s — the provenance identity cannot be derived",
			canonPin, signerWorkflow)
	}

	return verify.Pins{Canon: canonPin, Signer: string(sm[1])}, nil
}

// FullDepth is everything the full-depth leg needs beyond the walk:
// the engine (behind the seam) and the pin-resolution roots derived
// from the VERIFY policy — the canon repository is the verifier
// workflow's own, a fact of the identity, not a second declaration.
type FullDepth struct {
	Verifier              DeepVerifier
	CanonOwner, CanonRepo string
	SignerWorkflow        string
}

// NewFullDepth derives the pin-resolution roots from the verify
// policy's trust identities.
func NewFullDepth(v DeepVerifier, verifierWorkflow, signerWorkflow string) (*FullDepth, error) {
	const ownerRepoPath = 3

	parts := strings.SplitN(verifierWorkflow, "/", ownerRepoPath)
	if len(parts) < ownerRepoPath {
		return nil, fmt.Errorf("verifier workflow %q does not name owner/repo/path", verifierWorkflow)
	}

	return &FullDepth{
		Verifier: v, CanonOwner: parts[0], CanonRepo: parts[1], SignerWorkflow: signerWorkflow,
	}, nil
}
