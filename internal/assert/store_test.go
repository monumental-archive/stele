// The store halves' guard branches. Both exist to catch artifacts
// nobody else checks, so every way they could quietly pass is a row:
// a publishing repo with no image, a repo whose tree declares no
// signer pin, an attestation that refuses, a pin file that pins
// nothing.

package assert_test

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/workflow"
)

// The evidence sections the rows compose from. Each is declared only
// where it is under test, so a red from a section the row is not about
// cannot masquerade as its verdict.
const (
	continuousSection = `"continuous": {
      "stubPath": ".github/workflows/continuous.yml",
      "stubUses": "acme/.github/",
      "registry": "ghcr.io",
      "tag": "latest",
      "signerWorkflow": "acme/signer/.github/workflows/sign.yml",
      "signerPinPattern": "acme/signer/.github/workflows/sign\\.yml@([0-9a-f]{40})"
    }`
)

// field is one declared key of a scope. The scopes are built from
// ordered pairs rather than written as text so a row can drop exactly
// one key and produce the ABSENT shape — which is what a pointer
// field exists to tell apart from the empty one.
type field struct{ key, value string }

// pinFileFields is the mechanism the org shipped first: a committed
// file of pins, each approved by one attestor under one predicate.
func pinFileFields() []field {
	return []field{
		{"name", `"pgrx-bases"`},
		{"mechanism", `"pin-file"`},
		{"pinFile", `"docker/base-images.toml"`},
		{"attestorRepo", `".github"`},
		{"attestorIdentity", `"https://github.com/acme/.github/.github/workflows/base-attest.yml@refs/heads/main"`},
		{"predicateType", `"https://acme.example/attestations/base-image-approval/v1"`},
	}
}

// provenanceFields is the second mechanism, the one the closed
// four-field block could not say at any value: first-party bases
// verified against the provenance of the identity their own pin
// implies.
func provenanceFields() []field {
	return []field{
		{"name", `"org-bases"`},
		{"mechanism", `"provenance-verified"`},
		{"fromFile", `"Dockerfile"`},
		{"registryPrefix", `"ghcr.io/acme/"`},
		{
			"pinPattern",
			`"^ghcr\\.io/acme/(?P<repo>[a-z-]+):(?P<version>[0-9]+\\.[0-9]+\\.[0-9]+)[^@]*@sha256:[0-9a-f]{64}$"`,
		},
		{"identity", `"https://github.com/acme/${repo}/.github/workflows/publish.yml@refs/tags/v${version}"`},
		{"predicateType", `"https://slsa.dev/provenance/v1"`},
	}
}

// orgRefs is the canon's tag convention as declared rules: `latest`
// is the continuous stream, built from the default branch; a version,
// optionally class-decorated (1.2.3-pg18), names its tag.
const orgRefs = `[{"tag": "^latest$", "ref": "refs/heads/main"},` +
	` {"tag": "^(?P<version>[0-9]+\\.[0-9]+\\.[0-9]+)(-.*)?$", "ref": "refs/tags/v${version}"}]`

// sharedSignerFields is the third mechanism (stele#402): first-party
// bases verified against the provenance one declared signer minted, at
// any signer commit, at the ref the pin's tag implies — the org whose
// repositories all sign through one shared signer, which a per-pin
// identity cannot say.
func sharedSignerFields() []field {
	return []field{
		{"name", `"shared-bases"`},
		{"mechanism", `"shared-signer"`},
		{"fromFile", `"Dockerfile"`},
		{"registryPrefix", `"ghcr.io/acme/"`},
		{"signerWorkflow", `"acme/signer/.github/workflows/sign.yml"`},
		{"refs", orgRefs},
		{"runnerEnvironment", `"github-hosted"`},
		{"predicateType", `"https://slsa.dev/provenance/v1"`},
	}
}

// scope renders declared fields as one scope object.
func scope(fields []field) string {
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		parts = append(parts, `"`+f.key+`": `+f.value)
	}

	return "{" + strings.Join(parts, ", ") + "}"
}

// dropping renders the scope with one key ABSENT — not empty, absent.
func dropping(fields []field, key string) string {
	kept := make([]field, 0, len(fields))

	for _, f := range fields {
		if f.key != key {
			kept = append(kept, f)
		}
	}

	return scope(kept)
}

// setting renders the scope with each named key's value replaced,
// adding a key the mechanism does not already declare. Pairs are
// key, value, key, value — a row usually changes one, and the rows
// that need two say so in one call.
func setting(fields []field, pairs ...string) string {
	out := append([]field{}, fields...)

	for i := 0; i+1 < len(pairs); i += 2 {
		key, value, replaced := pairs[i], pairs[i+1], false

		for j := range out {
			if out[j].key == key {
				out[j].value, replaced = value, true

				break
			}
		}

		if !replaced {
			out = append(out, field{key, value})
		}
	}

	return scope(out)
}

var (
	pinFileScopeJSON      = scope(pinFileFields())
	provenanceScopeJSON   = scope(provenanceFields())
	sharedSignerScopeJSON = scope(sharedSignerFields())
)

// storePolicy composes a policy declaring exactly the evidence
// sections a row is about.
func storePolicy(sections ...string) string {
	return `{
  "schema": 9,
  "issuer": "https://token.actions.githubusercontent.com",
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}` +
		strings.Join(append([]string{""}, sections...), ",\n    ") + `
  }
}`
}

// baseImages wraps scopes into the section. Plurality is the caller's
// — which is the whole point of the shape.
func baseImages(scopes ...string) string {
	return `"baseImages": {"scopes": [` + strings.Join(scopes, ",") + `]}`
}

var (
	storePolicyJSON          = storePolicy(continuousSection, baseImages(pinFileScopeJSON))
	continuousOnlyPolicyJSON = storePolicy(continuousSection)
	baseOnlyPolicyJSON       = storePolicy(baseImages(pinFileScopeJSON))
	provenanceOnlyPolicyJSON = storePolicy(baseImages(provenanceScopeJSON))
	bothKindsPolicyJSON      = storePolicy(baseImages(pinFileScopeJSON, provenanceScopeJSON))
	sharedOnlyPolicyJSON     = storePolicy(baseImages(sharedSignerScopeJSON))
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

func runStoreWalk(
	t *testing.T, policyJSON string, f *fakeForge, att assert.Attestor, pinFiles map[string][]byte,
) *report.Report {
	t.Helper()

	pol, err := assert.LoadPolicy(strings.NewReader(policyJSON))
	if err != nil {
		t.Fatal(err)
	}

	src := assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}

	rep, err := assert.Evidence(pol, orgPop(t, f, nil), f, src, att,
		report.NewJournal(), pinFiles, nil, func(string, ...any) {})
	if err != nil {
		t.Fatalf("Evidence: %v", err)
	}

	return rep
}

// pinsFor keys a pin file by the scope that declared it, which is how
// the walk now receives them.
func pinsFor(content []byte) map[string][]byte {
	return map[string][]byte{"pgrx-bases": content}
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

	pins := pinsFor([]byte("images = [\n  \"docker.io/library/debian:trixie@" + baseDigest + "\",\n]\n"))

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

		rep := runStoreWalk(t, baseOnlyPolicyJSON, completeRelease(), &fakeAttestor{},
			pinsFor([]byte("images = []\n")))
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — a pin file checking nothing is a defect, not a clean answer", rep.Verdict())
		}
	})

	t.Run("a declared scope handed no pin file reddens", func(t *testing.T) {
		t.Parallel()

		att := &fakeAttestor{}

		rep := runStoreWalk(t, baseOnlyPolicyJSON, completeRelease(), att, nil)
		if rep.Verdict() != report.VerdictFail || len(att.seen) != 0 {
			t.Fatalf("verdict = %s, seen = %v — a declared scope checking nothing may never look like PASS",
				rep.Verdict(), att.seen)
		}
	})
}

// orgBaseRef is a first-party base under the scope's registry prefix:
// the shape whose approval the pin-file mechanism could not express.
const orgBaseRef = "ghcr.io/acme/edtf-postgres:1.2.3-pg18@" + baseDigest

// provenanceForge scripts one repository building on a first-party
// base, plus a foreign base in the same file that the scope's prefix
// excludes.
func provenanceForge() *fakeForge {
	f := completeRelease()
	f.files = map[string]string{
		"widget:HEAD:Dockerfile": "FROM --platform=linux/amd64 " + orgBaseRef + " AS base\n" +
			"FROM docker.io/library/debian:trixie@" + contDigest + "\n",
	}

	return f
}

// TestProvenanceVerifiedScope walks the second mechanism. Every way it
// could quietly pass is a row: a base whose pin the pattern cannot
// read, an identity template that expands to nothing, a repository
// that builds no image at all, and a foreign base that must produce no
// finding rather than a green one.
func TestProvenanceVerifiedScope(t *testing.T) {
	t.Parallel()

	const wantIdentity = "https://github.com/acme/edtf-postgres/.github/workflows/publish.yml@refs/tags/v1.2.3"

	t.Run("a base with the provenance its pin implies passes", func(t *testing.T) {
		t.Parallel()

		att := &fakeAttestor{}

		rep := runStoreWalk(t, provenanceOnlyPolicyJSON, provenanceForge(), att, nil)
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		// The foreign base in the same file is out of scope: an
		// exclusion produces nothing, so exactly one subject is asked
		// about.
		if len(att.seen) != 1 || att.seen[0] != baseDigest {
			t.Fatalf("attestor saw %v, want only the first-party base", att.seen)
		}

		if len(att.candidates) != 1 || att.candidates[0].Identity != wantIdentity {
			t.Fatalf("candidates = %+v, want the identity expanded from the pin (%s)", att.candidates, wantIdentity)
		}

		// The publishing repository is read off the reference path
		// after the prefix — the one derivation this mechanism keeps.
		if len(att.asked) != 1 || att.asked[0] != "acme/edtf-postgres" {
			t.Fatalf("asked = %v, want the publisher derived from the reference", att.asked)
		}
	})

	t.Run("a base the declared signer never published reddens", func(t *testing.T) {
		t.Parallel()

		att := &fakeAttestor{refuse: map[string]error{baseDigest: errors.New("minted by another workflow")}}

		rep := runStoreWalk(t, provenanceOnlyPolicyJSON, provenanceForge(), att, nil)
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — a base nobody vouched for must not pass", rep.Verdict())
		}
	})

	t.Run("a pin the pattern cannot read fails closed", func(t *testing.T) {
		t.Parallel()

		f := provenanceForge()
		f.files["widget:HEAD:Dockerfile"] = "FROM ghcr.io/acme/edtf-postgres:nightly@" + baseDigest + "\n"

		att := &fakeAttestor{}

		rep := runStoreWalk(t, provenanceOnlyPolicyJSON, f, att, nil)
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — a pin naming no derivable identity is not an approved one", rep.Verdict())
		}

		if len(att.seen) != 0 {
			t.Fatal("the attestor was asked despite no derivable identity — the guard must refuse first")
		}
	})

	t.Run("a repository that builds no image is not a subject", func(t *testing.T) {
		t.Parallel()

		f := provenanceForge()
		delete(f.files, "widget:HEAD:Dockerfile")

		att := &fakeAttestor{}

		rep := runStoreWalk(t, provenanceOnlyPolicyJSON, f, att, nil)
		if rep.Verdict() != report.VerdictPass || len(att.seen) != 0 {
			t.Fatalf("verdict = %s, seen = %v — no build file is an answer, not a gap", rep.Verdict(), att.seen)
		}
	})

	t.Run("a build file naming only foreign bases produces no finding", func(t *testing.T) {
		t.Parallel()

		f := provenanceForge()
		f.files["widget:HEAD:Dockerfile"] = "FROM docker.io/library/debian:trixie@" + contDigest + "\n"

		att := &fakeAttestor{}

		rep := runStoreWalk(t, provenanceOnlyPolicyJSON, f, att, nil)
		if rep.Verdict() != report.VerdictPass || len(att.seen) != 0 {
			t.Fatalf("verdict = %s, seen = %v — whose bases those are is another mechanism's question",
				rep.Verdict(), att.seen)
		}
	})

	// The template validates — every group it names the pattern
	// defines — and still expands to nothing, because the group it
	// names captured nothing. Demanding an empty identity would ask
	// the store to vouch for anything at all.
	t.Run("an identity that expands to nothing fails closed", func(t *testing.T) {
		t.Parallel()

		fields := setting(provenanceFields(),
			"pinPattern", `"^ghcr\\.io/acme/edtf-postgres:[^@]*@sha256:[0-9a-f]{64}(?P<tail>)$"`,
			"identity", `"${tail}"`)

		att := &fakeAttestor{}

		rep := runStoreWalk(t, storePolicy(baseImages(fields)), provenanceForge(), att, nil)
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — an empty identity demands nothing of anybody", rep.Verdict())
		}

		if len(att.seen) != 0 {
			t.Fatal("the attestor was asked under an empty identity — the guard must refuse first")
		}
	})
}

// TestAPassingPinIsStillRecorded: Journal.Check RECORDS a performed
// check, and that record is what says this run was in a position to
// see one (subject, assertion) — the question a declared exception's
// staleness rests on. Register it only when the attestation refuses
// and every APPROVED pin goes unseen, so a committed excuse for one
// reports "this run has nothing to say" from a run that checked it
// clean. The two buckets are the assertion: exercised-and-unmatched
// is stale (retire the excuse), unexercised is not.
func TestAPassingPinIsStillRecorded(t *testing.T) {
	t.Parallel()

	ref := "docker.io/library/debian:trixie@" + baseDigest

	pol, err := assert.LoadPolicy(strings.NewReader(baseOnlyPolicyJSON))
	if err != nil {
		t.Fatal(err)
	}

	f := completeRelease()
	src := assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}
	j := report.NewJournal(report.Declared(ref, "base-image-approval:pgrx-bases", "debt.toml"))

	rep, err := assert.Evidence(pol, orgPop(t, f, nil), f, src, &fakeAttestor{}, j,
		pinsFor([]byte(`images = ["`+ref+`"]`)), nil, func(string, ...any) {})
	if err != nil {
		t.Fatalf("Evidence: %v", err)
	}

	var buf bytes.Buffer
	if encErr := rep.Encode(&buf); encErr != nil {
		t.Fatal(encErr)
	}

	if strings.Contains(buf.String(), "unexercisedExceptions") {
		t.Fatalf("the approved pin was not recorded as checked:\n%s", buf.String())
	}

	if !strings.Contains(buf.String(), "staleExceptions") {
		t.Fatalf("an excuse for a clean check must be reported stale:\n%s", buf.String())
	}
}

// TestProvenanceScopeRefusesAnUnparsablePattern: LoadPolicy refuses an
// unparsable pinPattern, so the walk's own compile is reachable only
// through a hand-built Policy — and it must REFUSE there rather than
// panic, because a walk that dies mid-population reports nothing at
// all, which is the one outcome worse than a finding.
func TestProvenanceScopeRefusesAnUnparsablePattern(t *testing.T) {
	t.Parallel()

	pol, err := assert.LoadPolicy(strings.NewReader(provenanceOnlyPolicyJSON))
	if err != nil {
		t.Fatal(err)
	}

	bad := "ghcr("
	pol.Evidence.BaseImages.Scopes[0].PinPattern = &bad

	f := provenanceForge()
	src := assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}

	_, err = assert.Evidence(pol, orgPop(t, f, nil), f, src, &fakeAttestor{},
		report.NewJournal(), nil, nil, func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "pinPattern") {
		t.Fatalf("Evidence = %v, want the walk to refuse by name", err)
	}
}

// TestSharedSignerScope walks the third mechanism (stele#402). The
// candidate is the declared signer at any commit, anchored to the
// owner and to the ref the pin's tag implies, and the owner's whole
// store is asked; every way it could quietly pass is a row.
func TestSharedSignerScope(t *testing.T) {
	t.Parallel()

	wantCandidate := assert.WorkflowCandidate{
		Workflow: "https://github.com/acme/signer/.github/workflows/sign.yml",
		Owner:    "acme",
		Ref:      "refs/tags/v1.2.3",
		Runner:   "github-hosted",
	}

	t.Run("a base with the provenance its tag implies passes", func(t *testing.T) {
		t.Parallel()

		att := &fakeAttestor{}

		rep := runStoreWalk(t, sharedOnlyPolicyJSON, provenanceForge(), att, nil)
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		if len(att.seen) != 1 || att.seen[0] != baseDigest {
			t.Fatalf("attestor saw %v, want only the first-party base", att.seen)
		}

		// The ref is derived from the pin's decorated tag (1.2.3-pg18 →
		// refs/tags/v1.2.3) and the signer is the scope's, at any ref.
		if len(att.candidates) != 1 || att.candidates[0].Workflow == nil ||
			*att.candidates[0].Workflow != wantCandidate || att.candidates[0].Identity != "" {
			t.Fatalf("candidates = %+v, want the workflow candidate %+v", att.candidates, wantCandidate)
		}

		// The owner's whole store is asked, never a repository read
		// off the image name: an image is not named after the
		// repository that built it (edtf-postgres is edtf's).
		if len(att.asked) != 1 || att.asked[0] != "acme/" {
			t.Fatalf("asked = %v, want the owner's store", att.asked)
		}
	})

	t.Run("a base with no verifying attestation fails", func(t *testing.T) {
		t.Parallel()

		att := &fakeAttestor{refuse: map[string]error{baseDigest: errors.New("no bundle verifies")}}

		rep := runStoreWalk(t, sharedOnlyPolicyJSON, provenanceForge(), att, nil)
		if got := rep.Findings(); rep.Verdict() != report.VerdictFail || len(got) != 1 ||
			!strings.Contains(got[0].Detail, "no https://slsa.dev/provenance/v1 attestation verifies for these bytes"+
				" at refs/tags/v1.2.3 — a first-party base is verified before it is instantiated: no bundle verifies") {
			t.Fatalf("verdict = %s, findings = %+v", rep.Verdict(), got)
		}
	})

	t.Run("a tag no rule decodes fails closed", func(t *testing.T) {
		t.Parallel()

		f := provenanceForge()
		f.files["widget:HEAD:Dockerfile"] = "FROM ghcr.io/acme/edtf-postgres:nightly@" + baseDigest + "\n"

		att := &fakeAttestor{}

		rep := runStoreWalk(t, sharedOnlyPolicyJSON, f, att, nil)
		if got := rep.Findings(); rep.Verdict() != report.VerdictFail || len(got) != 1 ||
			!strings.Contains(got[0].Detail, "cannot derive the ref that produced it from tag 'nightly'") {
			t.Fatalf("verdict = %s, findings = %+v — a pin naming no derivable ref is not an approved one",
				rep.Verdict(), got)
		}

		if len(att.seen) != 0 {
			t.Fatal("the attestor was asked despite no derivable ref — the guard must refuse first")
		}
	})

	t.Run("a base pinned with no tag fails closed", func(t *testing.T) {
		t.Parallel()

		f := provenanceForge()
		f.files["widget:HEAD:Dockerfile"] = "FROM ghcr.io/acme/edtf-postgres@" + baseDigest + "\n"

		att := &fakeAttestor{}

		rep := runStoreWalk(t, sharedOnlyPolicyJSON, f, att, nil)
		if got := rep.Findings(); rep.Verdict() != report.VerdictFail || len(got) != 1 ||
			!strings.Contains(got[0].Detail, "carries a digest but no tag") || len(att.seen) != 0 {
			t.Fatalf("verdict = %s, findings = %+v, seen = %v — a tagless pin derives no ref",
				rep.Verdict(), got, att.seen)
		}
	})

	t.Run("a build file naming only foreign bases produces no finding", func(t *testing.T) {
		t.Parallel()

		f := provenanceForge()
		f.files["widget:HEAD:Dockerfile"] = "FROM docker.io/library/debian:trixie@" + contDigest + "\n"

		att := &fakeAttestor{}

		rep := runStoreWalk(t, sharedOnlyPolicyJSON, f, att, nil)
		if rep.Verdict() != report.VerdictPass || len(att.seen) != 0 {
			t.Fatalf("verdict = %s, seen = %v — whose bases those are is another mechanism's question",
				rep.Verdict(), att.seen)
		}
	})
}

// TestSharedSignerScopeRefusesAnUnparsableRule: LoadPolicy refuses a
// ref rule that does not compile, so the walk's own compile is
// reachable only through a hand-built Policy — and it must REFUSE there
// rather than panic.
func TestSharedSignerScopeRefusesAnUnparsableRule(t *testing.T) {
	t.Parallel()

	pol, err := assert.LoadPolicy(strings.NewReader(sharedOnlyPolicyJSON))
	if err != nil {
		t.Fatal(err)
	}

	bad := "^ghcr($"
	pol.Evidence.BaseImages.Scopes[0].Refs[0].Tag = &bad

	f := provenanceForge()
	src := assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}

	_, err = assert.Evidence(pol, orgPop(t, f, nil), f, src, &fakeAttestor{},
		report.NewJournal(), nil, nil, func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "assert: base scope shared-bases refs[0].tag") {
		t.Fatalf("Evidence = %v, want the walk to refuse by name", err)
	}
}

// TestJudgeBaseRefusesAPinFileScope: a pin-file scope judges no single
// reference — its subjects are its pin file's — so a caller handing it
// one is refused rather than answered.
func TestJudgeBaseRefusesAPinFileScope(t *testing.T) {
	t.Parallel()

	pol, err := assert.LoadPolicy(strings.NewReader(baseOnlyPolicyJSON))
	if err != nil {
		t.Fatal(err)
	}

	_, err = pol.Evidence.BaseImages.Scopes[0].JudgeBase(orgBaseRef, &fakeAttestor{},
		func(string) { t.Fatal("a refusal was recorded as a finding") })
	if err == nil || err.Error() != "assert: base scope pgrx-bases: the pin-file mechanism judges no single reference" {
		t.Fatalf("JudgeBase = %v", err)
	}
}

// TestTwoScopesOfOneKind: plurality of MECHANISM is policy, and so is
// plurality WITHIN a mechanism. Two pin files is a valid world, and
// each scope is judged against its own file, attestor and predicate.
func TestTwoScopesOfOneKind(t *testing.T) {
	t.Parallel()

	second := setting(pinFileFields(),
		"name", `"vendor-bases"`,
		"pinFile", `"docker/vendor-images.toml"`,
		"attestorRepo", `"infra"`)

	att := &fakeAttestor{}

	rep := runStoreWalk(t, storePolicy(baseImages(pinFileScopeJSON, second)), completeRelease(), att,
		map[string][]byte{
			"pgrx-bases":   []byte(`images = ["docker.io/library/debian:trixie@` + baseDigest + `"]`),
			"vendor-bases": []byte(`images = ["docker.io/library/alpine:3.21@` + contDigest + `"]`),
		})
	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
	}

	if len(att.seen) != 2 || !slices.Contains(att.seen, baseDigest) || !slices.Contains(att.seen, contDigest) {
		t.Fatalf("attestor saw %v, want one subject from each declared pin file", att.seen)
	}

	if !slices.Contains(att.asked, "acme/.github") || !slices.Contains(att.asked, "acme/infra") {
		t.Fatalf("asked = %v, want each scope held to its own attestor repository", att.asked)
	}
}

// TestBothScopeKinds is the issue's first done-when: a policy naming
// both mechanisms loads and BOTH reach judgment in the same walk —
// each against its own subjects, its own attestor and its own
// predicate.
func TestBothScopeKinds(t *testing.T) {
	t.Parallel()

	f := provenanceForge()
	f.files["widget:HEAD:docker/base-images.toml"] = ""

	att := &fakeAttestor{}

	pins := pinsFor([]byte("images = [\n  \"docker.io/library/debian:trixie@" + contDigest + "\",\n]\n"))

	rep := runStoreWalk(t, bothKindsPolicyJSON, f, att, pins)
	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
	}

	// One subject per scope, and they are different subjects: the two
	// mechanisms judge different bases under different predicates.
	if len(att.seen) != 2 {
		t.Fatalf("attestor saw %v, want one subject from each declared scope", att.seen)
	}

	if !slices.Contains(att.seen, baseDigest) || !slices.Contains(att.seen, contDigest) {
		t.Fatalf("attestor saw %v, want both the first-party base and the pinned one", att.seen)
	}

	if !slices.Contains(att.predicates, "https://slsa.dev/provenance/v1") ||
		!slices.Contains(att.predicates, "https://acme.example/attestations/base-image-approval/v1") {
		t.Fatalf("predicates = %v, want each scope's own", att.predicates)
	}
}

// TestStrangerScopedPolicy is the issue's stranger condition: a fresh
// single-repository adopter, different names throughout, one scope of
// its own choosing, and NO continuous section — expressed without
// touching this engine.
func TestStrangerScopedPolicy(t *testing.T) {
	t.Parallel()

	stranger := storePolicy(baseImages(`{
        "name": "vendor-images",
        "mechanism": "pin-file",
        "pinFile": "deps/images.lock",
        "attestorRepo": "infra",
        "attestorIdentity": "https://gitlab.example/stranger/infra/approve.yml@refs/heads/trunk",
        "predicateType": "https://stranger.example/base-ok/v2"
      }`))

	pol, err := assert.LoadPolicy(strings.NewReader(stranger))
	if err != nil {
		t.Fatalf("LoadPolicy: %v — a stranger's shape must not need this engine edited", err)
	}

	scopes := pol.Evidence.BaseImages.Scopes
	if len(scopes) != 1 || *scopes[0].Name != "vendor-images" ||
		*scopes[0].Mechanism != assert.MechanismPinFile {
		t.Fatalf("scopes = %+v, want the stranger's single declared scope", scopes)
	}
}

// TestStorePolicyRefusals pins the schema guards: the halves cannot be
// declared without the issuer that makes them verifiable.
func TestStorePolicyRefusals(t *testing.T) {
	t.Parallel()

	withoutIssuer := func(doc string) string {
		return strings.Replace(doc, `"issuer": "https://token.actions.githubusercontent.com",`, "", 1)
	}

	for _, doc := range []string{storePolicyJSON, provenanceOnlyPolicyJSON, sharedOnlyPolicyJSON} {
		if _, err := assert.LoadPolicy(strings.NewReader(withoutIssuer(doc))); err == nil || err.Error() !=
			"assert: policy: issuer is required when evidence.continuous or an evidence.baseImages scope is declared" {
			t.Fatalf("error = %v, want the issuer refusal", err)
		}
	}

	// Only an attestation has an issuer: a section of upstream entries
	// alone judges unsigned provenance, and owes none.
	upstreamOnly := withoutIssuer(storePolicy(`"baseImages": {"upstream": [` + pgEntry + `]}`))
	if _, err := assert.LoadPolicy(strings.NewReader(upstreamOnly)); err != nil {
		t.Fatalf("an upstream-only section without an issuer = %v, want it loaded", err)
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

// TestBaseImageScopeRefusals walks every way a declared approval scope
// can fail to be one. Each row breaks exactly one thing and names the
// refusal it must produce, and each required parameter appears twice —
// once ABSENT and once empty — because a pointer field exists to tell
// those apart and a guard that conflates them has never been asked.
func TestBaseImageScopeRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "a section declaring no scopes",
			doc:  storePolicy(`"baseImages": {"scopes": []}`),
			want: "evidence.baseImages declares no scope and no upstream entry",
		},
		{
			name: "a section whose scopes key is absent",
			doc:  storePolicy(`"baseImages": {}`),
			want: "evidence.baseImages declares no scope and no upstream entry",
		},
		{
			name: "a scope with no name",
			doc:  storePolicy(baseImages(dropping(pinFileFields(), "name"))),
			want: "evidence.baseImages.scopes[0].name is absent or empty",
		},
		{
			name: "a scope with an empty name",
			doc:  storePolicy(baseImages(setting(pinFileFields(), "name", `""`))),
			want: "evidence.baseImages.scopes[0].name is absent or empty",
		},
		{
			name: "two scopes sharing a name",
			doc:  storePolicy(baseImages(pinFileScopeJSON, pinFileScopeJSON)),
			want: `evidence.baseImages.scopes names "pgrx-bases" twice — scope names are a set`,
		},
		{
			// Of either kind: a reference both claimed would have two
			// judgments.
			name: "two scopes declaring one prefix",
			doc:  storePolicy(baseImages(provenanceScopeJSON, sharedSignerScopeJSON)),
			want: `evidence.baseImages.scopes org-bases and shared-bases both declare registryPrefix` +
				` "ghcr.io/acme/" — one reference, one judgment`,
		},
		{
			name: "a scope with no mechanism",
			doc:  storePolicy(baseImages(dropping(pinFileFields(), "mechanism"))),
			want: "evidence.baseImages.scopes[pgrx-bases].mechanism is absent or empty",
		},
		{
			name: "a scope with an empty mechanism",
			doc:  storePolicy(baseImages(setting(pinFileFields(), "mechanism", `""`))),
			want: "evidence.baseImages.scopes[pgrx-bases].mechanism is absent or empty",
		},
		{
			// Absent, not refused: a kind this engine has no judgment
			// for is named and refused at load, never ignored.
			name: "a mechanism this engine does not implement",
			doc:  storePolicy(baseImages(setting(pinFileFields(), "mechanism", `"notary-countersigned"`))),
			want: `mechanism "notary-countersigned" is not a base-approval mechanism this stele implements`,
		},
		{
			name: "a pin-file scope carrying a parameter of the other mechanism",
			doc:  storePolicy(baseImages(setting(pinFileFields(), "registryPrefix", `"ghcr.io/acme/"`))),
			want: "scopes[pgrx-bases].registryPrefix is declared but the pin-file mechanism does not read it",
		},
		{
			name: "a provenance scope carrying a parameter of the other mechanism",
			doc:  storePolicy(baseImages(setting(provenanceFields(), "pinFile", `"docker/base-images.toml"`))),
			want: "scopes[org-bases].pinFile is declared but the provenance-verified mechanism does not read it",
		},
		{
			name: "a prefix that stops before the owner",
			doc:  storePolicy(baseImages(setting(provenanceFields(), "registryPrefix", `"ghcr.io/"`))),
			want: "does not end at the owner boundary",
		},
		{
			name: "a prefix that reaches past the owner",
			doc:  storePolicy(baseImages(setting(provenanceFields(), "registryPrefix", `"ghcr.io/acme/team/"`))),
			want: "does not end at the owner boundary",
		},
		{
			name: "a prefix with no trailing separator",
			doc:  storePolicy(baseImages(setting(provenanceFields(), "registryPrefix", `"ghcr.io/acme"`))),
			want: "does not end at the owner boundary",
		},
		{
			name: "a pin pattern that does not compile",
			doc:  storePolicy(baseImages(setting(provenanceFields(), "pinPattern", `"ghcr("`))),
			want: "scopes[org-bases].pinPattern:",
		},
		{
			name: "an identity naming a group the pattern never captures",
			doc: storePolicy(baseImages(setting(provenanceFields(), "identity",
				`"https://github.com/acme/${repo}/.github/workflows/publish.yml@refs/tags/v${release}"`))),
			want: `identity names the capture group "release", which pinPattern does not define`,
		},
		{
			name: "a shared-signer prefix reaching past the owner",
			doc:  storePolicy(baseImages(setting(sharedSignerFields(), "registryPrefix", `"ghcr.io/acme/db/"`))),
			want: `scopes[shared-bases].registryPrefix "ghcr.io/acme/db/" does not end at the owner boundary — it` +
				` must spell <host>/<owner>/, because the owner whose attestation store is read is its last segment`,
		},
		{
			name: "a ref rule whose tag does not compile",
			doc: storePolicy(baseImages(setting(sharedSignerFields(), "refs",
				`[{"tag": "^ghcr($", "ref": "refs/x"}]`))),
			want: "scopes[shared-bases].refs[0].tag:",
		},
		{
			name: "a ref rule whose tag is not anchored",
			doc: storePolicy(baseImages(setting(sharedSignerFields(), "refs",
				`[{"tag": "latest", "ref": "refs/heads/main"}]`))),
			want: `scopes[shared-bases].refs[0].tag "latest" is not anchored (^…$)`,
		},
		{
			name: "a ref rule naming a ref that is not fully qualified",
			doc: storePolicy(baseImages(setting(sharedSignerFields(), "refs",
				`[{"tag": "^latest$", "ref": "main"}]`))),
			want: `scopes[shared-bases].refs[0].ref "main" is not a fully qualified ref`,
		},
		{
			name: "a ref template naming a group its tag never captures",
			doc: storePolicy(baseImages(setting(sharedSignerFields(), "refs",
				`[{"tag": "^(?P<version>[0-9.]+)$", "ref": "refs/tags/v${release}"}]`))),
			want: `scopes[shared-bases].refs[0].ref names the capture group "release", which its pattern does not define`,
		},
		{
			name: "a ref rule with no ref",
			doc:  storePolicy(baseImages(setting(sharedSignerFields(), "refs", `[{"tag": "^latest$"}]`))),
			want: "scopes[shared-bases].refs[0] needs a tag and a ref",
		},
		{
			name: "a ref rule with no tag",
			doc:  storePolicy(baseImages(setting(sharedSignerFields(), "refs", `[{"ref": "refs/heads/main"}]`))),
			want: "scopes[shared-bases].refs[0] needs a tag and a ref",
		},
		{
			name: "a signer that is no workflow",
			doc:  storePolicy(baseImages(setting(sharedSignerFields(), "signerWorkflow", `"acme/signer"`))),
			want: `scopes[shared-bases].signerWorkflow "acme/signer" is not owner/repo/path-to-workflow`,
		},
		{
			name: "a provenance-verified scope carrying the shared-signer mechanism's rules",
			doc:  storePolicy(baseImages(setting(provenanceFields(), "refs", orgRefs))),
			want: "scopes[org-bases].refs is declared but the provenance-verified mechanism does not read it",
		},
		{
			name: "a shared-signer scope carrying a per-pin identity",
			doc: storePolicy(baseImages(setting(sharedSignerFields(), "identity",
				`"https://github.com/acme/x/.github/workflows/publish.yml@refs/heads/main"`))),
			want: "scopes[shared-bases].identity is declared but the shared-signer mechanism does not read it",
		},
	}

	// Every required parameter, absent and empty, for both mechanisms.
	for _, m := range []struct {
		mechanism string
		fields    []field
		named     string
		required  []string
	}{
		{
			"pin-file", pinFileFields(), "pgrx-bases",
			[]string{"pinFile", "attestorRepo", "attestorIdentity", "predicateType"},
		},
		{
			"provenance-verified", provenanceFields(), "org-bases",
			[]string{"fromFile", "registryPrefix", "pinPattern", "identity", "predicateType"},
		},
		{
			"shared-signer", sharedSignerFields(), "shared-bases",
			[]string{"fromFile", "registryPrefix", "signerWorkflow", "refs", "runnerEnvironment", "predicateType"},
		},
	} {
		want := "scopes[" + m.named + "].%s is absent or empty — the " + m.mechanism + " mechanism requires it"

		for _, key := range m.required {
			// A list's empty value is the empty list.
			empty := `""`
			if key == "refs" {
				empty = `[]`
			}

			tests = append(tests,
				struct {
					name string
					doc  string
					want string
				}{
					name: "a " + m.mechanism + " scope with no " + key,
					doc:  storePolicy(baseImages(dropping(m.fields, key))),
					want: fmt.Sprintf(want, key),
				},
				struct {
					name string
					doc  string
					want string
				}{
					name: "a " + m.mechanism + " scope with an empty " + key,
					doc:  storePolicy(baseImages(setting(m.fields, key, empty))),
					want: fmt.Sprintf(want, key),
				},
			)
		}
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := assert.LoadPolicy(strings.NewReader(tc.doc))
			if err == nil {
				t.Fatalf("LoadPolicy accepted %s", tc.name)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadPolicy = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestBaseImagesEpochBothDirections is the issue's measurement: the
// OLD four-field block is refused at the new epoch with a cause that
// names what moved, and the scoped shape loads. Both directions,
// because a bump proven in one is a bump nobody has tested.
func TestBaseImagesEpochBothDirections(t *testing.T) {
	t.Parallel()

	oldShape := `"baseImages": {
      "pinFile": "docker/base-images.toml",
      "attestorRepo": ".github",
      "attestorIdentity": "https://github.com/acme/.github/.github/workflows/base-attest.yml@refs/heads/main",
      "predicateType": "https://acme.example/attestations/base-image-approval/v1"
    }`

	t.Run("the old block at the old epoch refuses as a version", func(t *testing.T) {
		t.Parallel()

		doc := strings.Replace(storePolicy(oldShape), `"schema": 9`, `"schema": 6`, 1)

		_, err := assert.LoadPolicy(strings.NewReader(doc))
		if err == nil || !strings.Contains(err.Error(), "schema 6 is not the implemented schema 9") {
			t.Fatalf("LoadPolicy = %v, want the version gate to fire first", err)
		}
	})

	t.Run("the old block at the new epoch names the key that moved", func(t *testing.T) {
		t.Parallel()

		_, err := assert.LoadPolicy(strings.NewReader(storePolicy(oldShape)))
		if err == nil {
			t.Fatal("LoadPolicy accepted the pre-scopes block at the new epoch")
		}

		if !strings.Contains(err.Error(), `unknown field "pinFile"`) {
			t.Fatalf("LoadPolicy = %v, want the refusal to name the key that is no longer read", err)
		}
	})

	t.Run("the scoped shape at the new epoch loads", func(t *testing.T) {
		t.Parallel()

		pol, err := assert.LoadPolicy(strings.NewReader(bothKindsPolicyJSON))
		if err != nil {
			t.Fatalf("LoadPolicy = %v, want the reshaped section to load", err)
		}

		if got := len(pol.Evidence.BaseImages.Scopes); got != 2 {
			t.Fatalf("scopes = %d, want both declared mechanisms", got)
		}
	})
}
