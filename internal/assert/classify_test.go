// The one classifier, measured on real release shapes (stele#156).
//
// The rows are asset LISTS, not hand-picked names: the question a
// release actually asks is "of everything I published, what did I
// build?", and a classifier tested one name at a time can pass while
// getting a whole release wrong — which is how the reproducibility
// audit came to report a signature bundle as an unreproduced artifact.

package assert_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/evidence"
)

// classifyPolicyJSON carries the whole evidence vocabulary a release
// can be judged against: the three exact names, the SBOM suffix, a
// declared evidence suffix, per-class bundles, a legacy VSA bundle,
// and a prefixed asset.
const classifyPolicyJSON = `{
  "schema": 4,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "storeVsaFromVersion": "1.13.0",
    "evidenceSuffixes": [".openvex.json"],
    "debtFile": "security/attestation-debt.txt",
    "classes": {
      "rust-binary": {"bundles": ["attestations-binaries.intoto.jsonl"]},
      "wasm-npm": {
        "bundles": ["attestations-npm.intoto.jsonl"],
        "legacyVsaBundles": ["attestations-vsa-npm.intoto.jsonl"]
      },
      "pgrx-extension": {
        "bundles": ["attestations-extensions.intoto.jsonl"],
        "assetPrefixes": [{"prefix": "attestations-extimg-pg"}]
      }
    }
  }
}`

func classifyPolicy(t *testing.T) *assert.EvidencePolicy {
	t.Helper()

	p, err := assert.LoadPolicy(strings.NewReader(classifyPolicyJSON))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	return p.Evidence
}

func TestClassifyWholeReleases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		assets   []string
		subjects []string
	}{
		{
			// The shape that exposed the defect: one real build
			// artifact, reproduced bit-for-bit, and a walk that
			// counted the bundle, the manifest and the SBOM as
			// absent from the rebuild. None of them CAN reproduce —
			// a Sigstore signature embeds a fresh timestamp, and
			// that is a security property.
			"a single-artifact release",
			[]string{
				"attestations.intoto.jsonl", "checksums.txt", "evidence-manifest.json",
				"github-1.44.1.spdx.json", "github-1.44.1.tar.gz",
			},
			[]string{"github-1.44.1.tar.gz"},
		},
		{
			// The wide shape: per-class SBOMs, extension-image
			// bundles by prefix, a VEX document by declared suffix.
			"a multi-class release",
			[]string{
				"attestations-binaries.intoto.jsonl", "attestations-npm.intoto.jsonl",
				"attestations-vsa-npm.intoto.jsonl", "attestations-extensions.intoto.jsonl",
				"attestations-extimg-pg17.intoto.jsonl", "attestations-extimg-pg18.intoto.jsonl",
				"checksums.txt", "evidence-manifest.json",
				"sbom-cargo-lab-cli-0.25.3.spdx.json", "sbom-npm-lab-0.25.3.spdx.json",
				"release-lab-0.25.3.vex.openvex.json",
				"release-lab-0.25.3-x86_64-unknown-linux-musl.tar.gz",
				"lab-wasm-0.25.3.tgz",
			},
			[]string{
				"release-lab-0.25.3-x86_64-unknown-linux-musl.tar.gz",
				"lab-wasm-0.25.3.tgz",
			},
		},
		{
			// An adopter whose policy names documents this release
			// never published: the vocabulary narrows nothing it
			// does not match, so every asset is an artifact.
			"a release of artifacts alone",
			[]string{"a.tar.gz", "b.zip"},
			[]string{"a.tar.gz", "b.zip"},
		},
	}

	pol := classifyPolicy(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got []string

			for _, a := range tt.assets {
				switch kind := pol.Classify(a); kind {
				case evidence.TypeBuildSubject:
					got = append(got, a)
				case evidence.TypeEvidence:
				default:
					t.Fatalf("Classify(%q) = %q, outside the manifest's vocabulary", a, kind)
				}
			}

			if !slices.Equal(got, tt.subjects) {
				t.Fatalf("build subjects = %v, want %v", got, tt.subjects)
			}
		})
	}
}

// Each rule kind gets its own row: a vocabulary half the classifier
// stopped reading would show up as a document quietly rejoining the
// build population, which is the failure this file exists to prevent.
func TestClassifyReadsEveryRuleKind(t *testing.T) {
	t.Parallel()

	pol := classifyPolicy(t)

	for _, tt := range []struct {
		rule  string
		asset string
	}{
		{"checksums", "checksums.txt"},
		{"manifestAsset", "evidence-manifest.json"},
		{"umbrellaBundle", "attestations.intoto.jsonl"},
		{"sbomSuffix", "anything-at-all.spdx.json"},
		{"evidenceSuffixes", "decisions.openvex.json"},
		{"class bundles", "attestations-binaries.intoto.jsonl"},
		{"class legacyVsaBundles", "attestations-vsa-npm.intoto.jsonl"},
		{"class assetPrefixes", "attestations-extimg-pg18.intoto.jsonl"},
	} {
		t.Run(tt.rule, func(t *testing.T) {
			t.Parallel()

			if got := pol.Classify(tt.asset); got != evidence.TypeEvidence {
				t.Fatalf("Classify(%q) = %q, want %q — the %s rule went unread",
					tt.asset, got, evidence.TypeEvidence, tt.rule)
			}
		})
	}
}

// A prefixed asset is a document whether or not the release's own
// machinery version owed it: whether an obligation is OWED is a
// per-release question, but a shipped document is a document.
func TestClassifyIsEpochFree(t *testing.T) {
	t.Parallel()

	pol := classifyPolicy(t)
	for _, cp := range pol.Classes {
		for _, ob := range cp.AssetPrefixes {
			if ob.OwedFrom != nil {
				t.Fatalf("this fixture declares an epoch; the row below would then prove nothing")
			}
		}
	}

	if got := pol.Classify("attestations-extimg-pg14.intoto.jsonl"); got != evidence.TypeEvidence {
		t.Fatalf("Classify = %q, want %q", got, evidence.TypeEvidence)
	}
}
