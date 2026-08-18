// The full-depth leg's guard branches: pin derivation (the two-hop
// stranger's read), the engine refusals mapping into the taxonomy,
// the presence-findings yield, and the pre-store bound. The engine
// itself is proven in internal/verify; here it is a scripted seam.

package assert_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/verify"
)

const (
	machineryPin40 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	signerPin40    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	tagSHA40       = "cccccccccccccccccccccccccccccccccccccccc"
)

// fakeDeep scripts the verify engine seam and records the pins each
// call received — the pin derivation is the logic under test.
type fakeDeep struct {
	releaseErr, vsaErr error
	releasePins        []verify.Pins
	decisions          []bool
	vsaPins            []verify.Pins
	subjects           int
}

func (d *fakeDeep) Release(_ verify.Coords, subjects, _ []verify.Subject, pins verify.Pins, decision bool) error {
	d.releasePins = append(d.releasePins, pins)
	d.subjects = len(subjects)
	d.decisions = append(d.decisions, decision)

	return d.releaseErr
}

func (d *fakeDeep) VSA(_ verify.Coords, _ []verify.Subject, pins verify.Pins) error {
	d.vsaPins = append(d.vsaPins, pins)

	return d.vsaErr
}

// deepForge is completeRelease plus what full depth reads: a checksum
// manifest with real subjects, the caller's publish workflow carrying
// the canon pin, and the canon's publish workflow carrying the signer
// pin.
func deepForge() *fakeForge {
	f := completeRelease()
	// Evidence documents ride the checksum manifest beside the
	// artifacts and must all be excluded from the subject set: the
	// umbrella, a class bundle, a legacy VSA bundle, a prefixed
	// asset, a declared-suffix document, and the contract manifest.
	f.assetBytes["widget@v1.0.0"]["checksums.txt"] = "" +
		subjectDigest + "  widget-v1.0.0.tar.gz\n" +
		strings.Repeat("d", 64) + "  app.spdx.json\n" +
		strings.Repeat("e", 64) + "  attestations.intoto.jsonl\n" +
		strings.Repeat("e", 64) + "  attestations-image.intoto.jsonl\n" +
		strings.Repeat("e", 64) + "  attestations-vsa-crates.intoto.jsonl\n" +
		strings.Repeat("e", 64) + "  attestations-extimg-pg17.tar.gz\n" +
		strings.Repeat("e", 64) + "  RUSTSEC-2021-0127.openvex.json\n" +
		strings.Repeat("e", 64) + "  evidence-manifest.json\n"
	f.files = map[string]string{
		"widget:v1.0.0:.github/workflows/publish.yml": "jobs:\n  publish:\n" +
			"    uses: acme/canon/.github/workflows/publish.yml@" + machineryPin40 + " # v1.2.3\n",
		"canon:" + machineryPin40 + ":.github/workflows/publish.yml": "jobs:\n  sign:\n" +
			"    uses: acme/signer/.github/workflows/sign.yml@" + signerPin40 + "\n",
	}

	return f
}

func runDeepWalk(t *testing.T, f *fakeForge, deep *fakeDeep) *report.Report {
	t.Helper()

	full, err := assert.NewFullDepth(deep,
		"acme/canon/.github/workflows/verify-release.yml", "acme/signer/.github/workflows/sign.yml")
	if err != nil {
		t.Fatal(err)
	}

	pol := loadTestPolicy(t)
	src := assert.Sources{assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"}}

	rep, err := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src, &fakeAttestor{}, nil, nil, full,
		func(string, ...any) {})
	if err != nil {
		t.Fatalf("Evidence: %v", err)
	}

	return rep
}

func TestDepthFull(t *testing.T) {
	t.Parallel()

	t.Run("a clean release passes with pins derived from the trees", func(t *testing.T) {
		t.Parallel()

		deep := &fakeDeep{}

		rep := runDeepWalk(t, deepForge(), deep)
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		want := verify.Pins{Machinery: machineryPin40, Signer: signerPin40}
		if len(deep.releasePins) != 1 || deep.releasePins[0] != want {
			t.Fatalf("release pins = %+v, want %+v — the two-hop derivation is the contract",
				deep.releasePins, want)
		}

		if len(deep.vsaPins) != 1 || deep.vsaPins[0] != want {
			t.Fatalf("vsa pins = %+v, want %+v", deep.vsaPins, want)
		}

		if deep.subjects != 1 {
			t.Fatalf("engine saw %d subjects, want the one artifact — the SBOM is a decision candidate",
				deep.subjects)
		}
	})

	t.Run("the canon's own release pins the tag commit", func(t *testing.T) {
		t.Parallel()

		f := deepForge()
		f.repos = []string{"canon"}
		f.tags = map[string][]string{"canon": {"v1.0.0"}}
		f.assets["canon@v1.0.0"] = f.assets["widget@v1.0.0"]
		f.assetBytes["canon@v1.0.0"] = f.assetBytes["widget@v1.0.0"]
		f.tagCommits = map[string]string{"v1.0.0": tagSHA40}
		canonWF := f.files["canon:"+machineryPin40+":.github/workflows/publish.yml"]
		f.files["canon:"+tagSHA40+":.github/workflows/publish.yml"] = canonWF

		deep := &fakeDeep{}

		rep := runDeepWalk(t, f, deep)
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		want := verify.Pins{Machinery: tagSHA40, Signer: signerPin40}
		if len(deep.releasePins) != 1 || deep.releasePins[0] != want {
			t.Fatalf("release pins = %+v, want the tag commit %+v", deep.releasePins, want)
		}
	})
}

func TestDepthFullRefusals(t *testing.T) {
	t.Parallel()

	t.Run("a release engine refusal reddens under deep", func(t *testing.T) {
		t.Parallel()

		deep := &fakeDeep{releaseErr: errors.New("provenance bundle refused")}

		rep := runDeepWalk(t, deepForge(), deep)
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s, want FAIL", rep.Verdict())
		}

		if got := rep.Findings(); len(got) != 1 || got[0].Assertion != "deep" {
			t.Fatalf("findings = %+v, want one deep finding", got)
		}
	})

	t.Run("a verdict engine refusal reddens under vsa:deep", func(t *testing.T) {
		t.Parallel()

		deep := &fakeDeep{vsaErr: errors.New("verdict bundle refused")}

		rep := runDeepWalk(t, deepForge(), deep)
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s, want FAIL", rep.Verdict())
		}

		if got := rep.Findings(); len(got) != 1 || got[0].Assertion != "vsa:deep" {
			t.Fatalf("findings = %+v, want one vsa:deep finding", got)
		}
	})

	t.Run("presence-level verdict findings silence the deep verdict check", func(t *testing.T) {
		t.Parallel()

		f := deepForge()
		f.store = nil // the store is empty: presence reds every subject digest

		deep := &fakeDeep{vsaErr: errors.New("would double-red")}

		rep := runDeepWalk(t, f, deep)
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s, want FAIL from presence", rep.Verdict())
		}

		if len(deep.vsaPins) != 0 {
			t.Fatal("the deep verdict check ran despite presence findings — it must yield to the taxonomy")
		}
	})

	t.Run("an unreadable checksum manifest is a deep finding, not a walk failure", func(t *testing.T) {
		t.Parallel()

		f := deepForge()
		delete(f.assetBytes["widget@v1.0.0"], "checksums.txt")

		rep := runDeepWalk(t, f, &fakeDeep{})
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s, want FAIL", rep.Verdict())
		}
	})

	t.Run("a manifest pinning nothing refuses to verify nothing", func(t *testing.T) {
		t.Parallel()

		f := deepForge()
		f.assetBytes["widget@v1.0.0"]["checksums.txt"] = "not a manifest\n"

		deep := &fakeDeep{}

		rep := runDeepWalk(t, f, deep)
		if rep.Verdict() != report.VerdictFail || len(deep.releasePins) != 0 {
			t.Fatalf("verdict = %s, engine calls = %d — an empty manifest must red before the engine",
				rep.Verdict(), len(deep.releasePins))
		}
	})

	t.Run("no canon pin on the publish workflow is a deep finding", func(t *testing.T) {
		t.Parallel()

		f := deepForge()
		f.files["widget:v1.0.0:.github/workflows/publish.yml"] = "jobs: {}\n"

		rep := runDeepWalk(t, f, &fakeDeep{})
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — an underivable identity must not pass", rep.Verdict())
		}
	})

	t.Run("no signer pin in the canon at the pin is a deep finding", func(t *testing.T) {
		t.Parallel()

		f := deepForge()
		f.files["canon:"+machineryPin40+":.github/workflows/publish.yml"] = "jobs: {}\n"

		rep := runDeepWalk(t, f, &fakeDeep{})
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — an underivable signer must not pass", rep.Verdict())
		}
	})
}

func TestDepthFullBounds(t *testing.T) {
	t.Parallel()

	t.Run("a pre-store release bounds the verdict check to presence", func(t *testing.T) {
		t.Parallel()

		f := deepForge()
		f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = manifestAsset([]string{"oci-image"}, false)
		f.assets["widget@v1.0.0"] = append(f.assets["widget@v1.0.0"], "attestations-vsa-image.intoto.jsonl")

		deep := &fakeDeep{vsaErr: errors.New("must never be asked")}

		rep := runDeepWalk(t, f, deep)
		if len(deep.vsaPins) != 0 {
			t.Fatal("the deep verdict check ran on a pre-store release — grandfathered history is presence-bounded")
		}

		if len(deep.releasePins) != 1 {
			t.Fatalf("release engine calls = %d — the provenance half still runs", len(deep.releasePins))
		}

		_ = rep
	})

	t.Run("a pre-decision-epoch release runs provenance-only", func(t *testing.T) {
		t.Parallel()

		// The workflow adapter carries the canon version; a pin older
		// than decisionFromVersion must reach the engine with the
		// decision obligation OFF — grandfathered history verifies
		// what it can prove, decided by policy data, never a try-each.
		polJSON := strings.Replace(testPolicyJSON,
			`"storeVsaFromVersion": "1.13.0",`,
			`"storeVsaFromVersion": "1.13.0", "decisionFromVersion": "1.23.1",`, 1)

		pol, err := assert.LoadPolicy(strings.NewReader(polJSON))
		if err != nil {
			t.Fatal(err)
		}

		f := deepForge()
		delete(f.assetBytes["widget@v1.0.0"], "evidence-manifest.json")
		f.files["widget:v1.0.0:.github/workflows/publish.yml"] = "jobs:\n  publish:\n" +
			"    with:\n      classes: oci-image\n" +
			"    uses: acme/canon/.github/workflows/publish.yml@" + machineryPin40 + " # v1.20.0\n"

		deep := &fakeDeep{}
		full, err := assert.NewFullDepth(deep,
			"acme/canon/.github/workflows/verify-release.yml", "acme/signer/.github/workflows/sign.yml")
		if err != nil {
			t.Fatal(err)
		}

		src := assert.Sources{assert.WorkflowSource{Forge: f, Policy: pol.Evidence}}

		rep, rerr := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src, &fakeAttestor{}, nil, nil, full,
			func(string, ...any) {})
		if rerr != nil {
			t.Fatal(rerr)
		}

		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		if len(deep.decisions) != 1 || deep.decisions[0] {
			t.Fatalf("decisions = %v — a v1.20.0 pin predates the 1.23.1 epoch", deep.decisions)
		}
	})

	t.Run("an unreadable tag commit on the canon's own release is a deep finding", func(t *testing.T) {
		t.Parallel()

		f := deepForge()
		f.repos = []string{"canon"}
		f.tags = map[string][]string{"canon": {"v1.0.0"}}
		f.assets["canon@v1.0.0"] = f.assets["widget@v1.0.0"]
		f.assetBytes["canon@v1.0.0"] = f.assetBytes["widget@v1.0.0"]
		f.tagCommits = nil

		rep := runDeepWalk(t, f, &fakeDeep{})
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — an unpinnable canon release must not pass", rep.Verdict())
		}
	})

	t.Run("a malformed verifier workflow refuses at construction", func(t *testing.T) {
		t.Parallel()

		if _, err := assert.NewFullDepth(&fakeDeep{}, "not-a-workflow", "s"); err == nil {
			t.Fatal("NewFullDepth accepted a workflow that names no owner/repo")
		}
	})
}

// TestDepthSelfAttesting covers the #82 topology on the full-depth
// leg: templated signer identity, verdict obligation undeclared.
func TestDepthSelfAttesting(t *testing.T) {
	t.Parallel()

	t.Run("the self-attesting topology pins both roots to the tag", func(t *testing.T) {
		t.Parallel()

		f := deepForge()
		f.tagCommits = map[string]string{"v1.0.0": tagSHA40}
		// No machinery hop exists to read: the publish-workflow files
		// disappear and the walk must not miss them.
		f.files = map[string]string{}

		deep := &fakeDeep{}

		full, err := assert.NewFullDepth(deep, "", "{owner}/{repo}/.github/workflows/release.yml")
		if err != nil {
			t.Fatal(err)
		}

		pol := loadTestPolicy(t)
		src := assert.Sources{assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"}}

		rep, rerr := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src, &fakeAttestor{}, nil, nil, full,
			func(string, ...any) {})
		if rerr != nil {
			t.Fatal(rerr)
		}

		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		want := verify.Pins{Machinery: tagSHA40, Signer: tagSHA40}
		if len(deep.releasePins) != 1 || deep.releasePins[0] != want {
			t.Fatalf("release pins = %+v, want %+v — self-attesting pins are the tag's own commit",
				deep.releasePins, want)
		}

		// The verify policy declared no verdict: the deep verdict half
		// skips, so the engine's VSA leg is never reached.
		if len(deep.vsaPins) != 0 {
			t.Fatalf("vsa pins = %+v — the deep verdict half must skip when no trust.verdict is declared",
				deep.vsaPins)
		}
	})

	t.Run("no verdict and no template refuses pin derivation", func(t *testing.T) {
		t.Parallel()

		f := deepForge()

		full, err := assert.NewFullDepth(&fakeDeep{}, "", "acme/signer/.github/workflows/sign.yml")
		if err != nil {
			t.Fatal(err)
		}

		pol := loadTestPolicy(t)
		src := assert.Sources{assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"}}

		rep, rerr := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src, &fakeAttestor{}, nil, nil, full,
			func(string, ...any) {})
		if rerr != nil {
			t.Fatal(rerr)
		}

		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — underivable pins must red, not pass silently", rep.Verdict())
		}
	})
}
