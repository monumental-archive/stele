// The store halves' guard branches. Both exist to catch artifacts
// nobody else checks, so every way they could quietly pass is a row:
// a publishing repo with no image, a repo whose tree declares no
// signer pin, an attestation that refuses, a pin file that pins
// nothing.

package assert_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/workflow"
)

const storePolicyJSON = `{
  "schema": 6,
  "issuer": "https://token.actions.githubusercontent.com",
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}},
    "continuous": {
      "stubPath": ".github/workflows/continuous.yml",
      "stubUses": "acme/.github/",
      "registry": "ghcr.io",
      "tag": "latest",
      "signerWorkflow": "acme/signer/.github/workflows/sign.yml",
      "signerPinPattern": "acme/signer/.github/workflows/sign\\.yml@([0-9a-f]{40})"
    },
    "baseImages": {
      "pinFile": "docker/base-images.toml",
      "attestorRepo": ".github",
      "attestorIdentity": "https://github.com/acme/.github/.github/workflows/base-attest.yml@refs/heads/main",
      "predicateType": "https://acme.example/attestations/base-image-approval/v1"
    }
  }
}`

// The single-half variants: each half is declared only where it is
// under test, so a red from the other half cannot masquerade as the
// row's own verdict.
var (
	continuousOnlyPolicyJSON = strings.Replace(storePolicyJSON, `,
    "baseImages": {
      "pinFile": "docker/base-images.toml",
      "attestorRepo": ".github",
      "attestorIdentity": "https://github.com/acme/.github/.github/workflows/base-attest.yml@refs/heads/main",
      "predicateType": "https://acme.example/attestations/base-image-approval/v1"
    }`, "", 1)

	baseOnlyPolicyJSON = strings.Replace(storePolicyJSON, `"continuous": {
      "stubPath": ".github/workflows/continuous.yml",
      "stubUses": "acme/.github/",
      "registry": "ghcr.io",
      "tag": "latest",
      "signerWorkflow": "acme/signer/.github/workflows/sign.yml",
      "signerPinPattern": "acme/signer/.github/workflows/sign\\.yml@([0-9a-f]{40})"
    },
    `, "", 1)
)

const (
	contDigest = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
	baseDigest = "sha256:8888888888888888888888888888888888888888888888888888888888888888"
	signerPin  = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
	// decoyPin is the pin an UNRELATED workflow in the consumer's own
	// tree names — the shape that made the walk demand an identity no
	// release could have signed under (.github#645). It must never
	// reach a candidate.
	decoyPin = "1111111111111111111111111111111111111111"
	// sharedPin is the commit the consumer's stub pins the shared
	// repository's reusable workflow at: the released tree, and the
	// only tree the signer pin may come from.
	sharedPin = "2222222222222222222222222222222222222222"

	contStubPath   = "widget:HEAD:.github/workflows/continuous.yml"
	contSharedPath = ".github:" + sharedPin + ":.github/workflows/continuous.yml"
)

// continuousForge scripts one repo that publishes continuous digests:
// a stub pinning the shared repository's reusable workflow, that
// RELEASED tree naming the signer pin, and — deliberately — a decoy
// signer ref in the consumer's own workflows that the derivation must
// not read.
func continuousForge() *fakeForge {
	f := completeRelease()
	f.files = map[string]string{
		contStubPath: "jobs:\n  publish:\n" +
			"    uses: acme/.github/.github/workflows/continuous.yml@" + sharedPin + " # v1.0.0\n",
		contSharedPath: "jobs:\n  sign:\n" +
			"    uses: acme/signer/.github/workflows/sign.yml@" + signerPin + " # main\n",
	}
	f.pkgDigest = map[string]string{"widget": contDigest}
	f.workflows = map[string][]workflow.File{
		"widget": {{
			Name:    "exercise-sign.yml",
			Content: []byte("uses: acme/signer/.github/workflows/sign.yml@" + decoyPin + "\n"),
		}},
	}

	return f
}

func runStoreWalk(t *testing.T, policyJSON string, f *fakeForge, att assert.Attestor, pinFile []byte) *report.Report {
	t.Helper()

	pol, err := assert.LoadPolicy(strings.NewReader(policyJSON))
	if err != nil {
		t.Fatal(err)
	}

	src := assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}

	rep, err := assert.Evidence(pol, orgPop(t, f, nil), f, src, att,
		report.NewJournal(), pinFile, nil, func(string, ...any) {})
	if err != nil {
		t.Fatalf("Evidence: %v", err)
	}

	return rep
}

func TestContinuousHalf(t *testing.T) {
	t.Parallel()

	t.Run("a verifying digest passes and is the digest asked about", func(t *testing.T) {
		t.Parallel()

		att := &fakeAttestor{}

		rep := runStoreWalk(t, continuousOnlyPolicyJSON, continuousForge(), att, nil)
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		if len(att.seen) != 1 || att.seen[0] != contDigest {
			t.Fatalf("attestor saw %v, want exactly the rolling digest", att.seen)
		}

		if len(att.candidates) != 1 || att.candidates[0].SignerPin != signerPin {
			t.Fatalf("candidates = %+v, want exactly the released tree's pin %s", att.candidates, signerPin)
		}
	})

	t.Run("no signer pin in the released tree fails closed", func(t *testing.T) {
		t.Parallel()

		f := continuousForge()
		f.files[contSharedPath] = "jobs:\n  sign:\n    uses: acme/other/.github/workflows/thing.yml@" + signerPin + "\n"

		att := &fakeAttestor{}

		rep := runStoreWalk(t, continuousOnlyPolicyJSON, f, att, nil)
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — an image the signer cannot be derived for must not pass", rep.Verdict())
		}

		if len(att.seen) != 0 {
			t.Fatal("the attestor was asked despite no derivable pin — the guard must refuse first")
		}
	})

	t.Run("a repo whose stub calls elsewhere is not a publisher", func(t *testing.T) {
		t.Parallel()

		f := continuousForge()
		f.files = map[string]string{
			"widget:HEAD:.github/workflows/continuous.yml": "jobs:\n  publish:\n    uses: mallory/other@abc\n",
		}

		att := &fakeAttestor{}

		rep := runStoreWalk(t, continuousOnlyPolicyJSON, f, att, nil)
		if rep.Verdict() != report.VerdictPass || len(att.seen) != 0 {
			t.Fatalf("verdict = %s, seen = %v — a foreign stub is an answer, not a subject", rep.Verdict(), att.seen)
		}
	})
}

// TestContinuousPinDerivation walks the two-hop derivation itself: the
// stub's pin names the released tree, and that tree alone names the
// signer. Every way the derivation could read the wrong tree, or
// derive from no tree at all, is a row (#230).
func TestContinuousPinDerivation(t *testing.T) {
	t.Parallel()

	// The defect .github#645 measured: the consumer's own tree carries
	// an unrelated signer ref that moves on ITS main, while the signing
	// runs from the tree the stub's pin names. Reading the decoy demands
	// an identity no release could have signed under.
	t.Run("the consumer's own decoy signer ref is never read", func(t *testing.T) {
		t.Parallel()

		att := &fakeAttestor{}

		rep := runStoreWalk(t, continuousOnlyPolicyJSON, continuousForge(), att, nil)
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		for _, c := range att.candidates {
			if c.SignerPin == decoyPin || strings.Contains(c.Identity, decoyPin) {
				t.Fatalf("candidate %+v carries the consumer tree's decoy pin", c)
			}
		}
	})

	t.Run("every pin the released tree declares is a candidate", func(t *testing.T) {
		t.Parallel()

		const second = "3333333333333333333333333333333333333333"

		f := continuousForge()
		f.files[contSharedPath] += "    uses: acme/signer/.github/workflows/sign.yml@" + second + "\n"

		att := &fakeAttestor{}

		rep := runStoreWalk(t, continuousOnlyPolicyJSON, f, att, nil)
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		if len(att.candidates) != 2 {
			t.Fatalf("candidates = %+v, want both pins the released tree declares", att.candidates)
		}
	})

	t.Run("a stub with no commit-pinned call fails closed", func(t *testing.T) {
		t.Parallel()

		f := continuousForge()
		f.files[contStubPath] = "jobs:\n  publish:\n    uses: acme/.github/.github/workflows/continuous.yml@main\n"

		att := &fakeAttestor{}

		rep := runStoreWalk(t, continuousOnlyPolicyJSON, f, att, nil)
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — an unpinned stub names no released tree to derive from", rep.Verdict())
		}

		if len(att.seen) != 0 {
			t.Fatal("the attestor was asked despite no derivable pin — the guard must refuse first")
		}
	})

	t.Run("an unreadable released tree fails closed", func(t *testing.T) {
		t.Parallel()

		f := continuousForge()
		delete(f.files, contSharedPath)

		att := &fakeAttestor{}

		rep := runStoreWalk(t, continuousOnlyPolicyJSON, f, att, nil)
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — a tree the walk cannot read derives no identity", rep.Verdict())
		}

		if len(att.seen) != 0 {
			t.Fatal("the attestor was asked despite no derivable pin — the guard must refuse first")
		}
	})

	t.Run("a refusing attestation reddens", func(t *testing.T) {
		t.Parallel()

		att := &fakeAttestor{refuse: map[string]error{contDigest: errors.New("signed at another pin")}}

		rep := runStoreWalk(t, continuousOnlyPolicyJSON, continuousForge(), att, nil)
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s, want FAIL", rep.Verdict())
		}
	})

	t.Run("a publishing repo with no rolling image reddens", func(t *testing.T) {
		t.Parallel()

		f := continuousForge()
		f.pkgDigest = nil

		rep := runStoreWalk(t, continuousOnlyPolicyJSON, f, &fakeAttestor{}, nil)
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — a stub that publishes nothing is a gap, not a skip", rep.Verdict())
		}
	})
}

func TestBaseImagesHalf(t *testing.T) {
	t.Parallel()

	pins := []byte("images = [\n  \"docker.io/library/debian:trixie@" + baseDigest + "\",\n]\n")

	t.Run("an approved base pin passes", func(t *testing.T) {
		t.Parallel()

		att := &fakeAttestor{}

		rep := runStoreWalk(t, baseOnlyPolicyJSON, completeRelease(), att, pins)
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		if len(att.seen) != 1 || att.seen[0] != baseDigest {
			t.Fatalf("attestor saw %v, want the base digest", att.seen)
		}
	})

	t.Run("an unapproved base pin reddens", func(t *testing.T) {
		t.Parallel()

		att := &fakeAttestor{refuse: map[string]error{baseDigest: errors.New("no approval")}}

		rep := runStoreWalk(t, baseOnlyPolicyJSON, completeRelease(), att, pins)
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — a base the approver never vouched for must not pass", rep.Verdict())
		}
	})

	t.Run("a pin file that pins nothing reddens", func(t *testing.T) {
		t.Parallel()

		rep := runStoreWalk(t, baseOnlyPolicyJSON, completeRelease(), &fakeAttestor{}, []byte("images = []\n"))
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — a pin file checking nothing is a defect, not a clean answer", rep.Verdict())
		}
	})

	t.Run("a declared half handed no pin file reddens", func(t *testing.T) {
		t.Parallel()

		att := &fakeAttestor{}

		rep := runStoreWalk(t, baseOnlyPolicyJSON, completeRelease(), att, nil)
		if rep.Verdict() != report.VerdictFail || len(att.seen) != 0 {
			t.Fatalf("verdict = %s, seen = %v — a declared half checking nothing may never look like PASS",
				rep.Verdict(), att.seen)
		}
	})
}

// TestStorePolicyRefusals pins the schema guards: the halves cannot be
// declared without the issuer that makes them verifiable.
func TestStorePolicyRefusals(t *testing.T) {
	t.Parallel()

	noIssuer := strings.Replace(storePolicyJSON,
		`"issuer": "https://token.actions.githubusercontent.com",`, "", 1)
	if _, err := assert.LoadPolicy(strings.NewReader(noIssuer)); err == nil ||
		!strings.Contains(err.Error(), "issuer") {
		t.Fatalf("error = %v, want the issuer refusal", err)
	}

	badPattern := strings.Replace(storePolicyJSON, `sign\\.yml@([0-9a-f]{40})`, `sign(`, 1)
	if _, err := assert.LoadPolicy(strings.NewReader(badPattern)); err == nil ||
		!strings.Contains(err.Error(), "signerPinPattern") {
		t.Fatalf("error = %v, want the pattern refusal", err)
	}

	missing := strings.Replace(storePolicyJSON, `"registry": "ghcr.io",`, "", 1)
	if _, err := assert.LoadPolicy(strings.NewReader(missing)); err == nil ||
		!strings.Contains(err.Error(), "registry") {
		t.Fatalf("error = %v, want the missing-field refusal", err)
	}
}
