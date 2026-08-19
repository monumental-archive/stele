// The ONE definition of what a released asset IS (stele#156): a build
// subject, or one of the release's own evidence documents.
//
// Three legs asked this question and each answered it separately —
// the full-depth evidence walk had one derivation, the canon's
// reproducibility audit grew a second in workflow bash, and the
// publish machinery's resume guard had none and diffed everything.
// One question with three answers is agreement maintained by memory,
// so the derivation lives here, once, and is called from every leg
// that needs it.
//
// The classifier's jobs are deliberately narrow. It STAMPS the type
// onto every entry when `stele emit manifest` writes a release's
// manifest — the one moment the knowledge exists natively — and it
// classifies a manifest that arrives UNTYPED: a release published
// before the typing existed, or a foreign one this org never wrote.
// A typed manifest is READ; re-deriving its typing would resurrect
// the second answer.
//
// Everything it knows comes from the org's declared vocabulary. No
// asset name is spelled in this file, because which names mark a
// document is an org fact and a stranger's release says it
// differently.

package assert

import (
	"slices"
	"strings"

	"github.com/monumental-archive/stele/internal/evidence"
)

// Classify reports whether a released asset is an artifact OF the
// build or a document ABOUT it, from the policy alone: the checksum
// manifest, the contract manifest, the umbrella bundle, each class's
// bundles and legacy VSA bundles, the SBOM suffix, any declared
// evidence suffixes, and each class's prefixed assets.
//
// The answer is total by construction — an asset the vocabulary does
// not name is an artifact — because the vocabulary describes the
// documents a release publishes about itself, and it is the publisher
// who declares it. That totality is what lets `emit manifest` stamp
// every entry, and it is why an UNTYPED name never reaches a walk
// unclassified.
func (e *EvidencePolicy) Classify(name string) string {
	if name == *e.Checksums || name == *e.UmbrellaBundle || name == *e.ManifestAsset {
		return evidence.TypeEvidence
	}

	if strings.HasSuffix(name, *e.SBOMSuffix) {
		return evidence.TypeEvidence
	}

	for _, suffix := range e.EvidenceSuffixes {
		if strings.HasSuffix(name, suffix) {
			return evidence.TypeEvidence
		}
	}

	for _, cp := range e.Classes {
		if slices.Contains(cp.Bundles, name) || slices.Contains(cp.LegacyVSABundles, name) {
			return evidence.TypeEvidence
		}

		// Deliberately epoch-free: whether an obligation is OWED is a
		// per-release question, but a shipped document is a document —
		// a pre-epoch release that published the asset anyway must not
		// have it counted as a build subject.
		for _, ob := range cp.AssetPrefixes {
			if strings.HasPrefix(name, *ob.Prefix) {
				return evidence.TypeEvidence
			}
		}
	}

	return evidence.TypeBuildSubject
}
