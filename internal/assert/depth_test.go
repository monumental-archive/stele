// The full-depth leg's guard branches: pin derivation (the two-hop
// stranger's read), the engine refusals mapping into the taxonomy,
// the presence-findings yield, and the pre-store bound. The engine
// itself is proven in internal/verify; here it is a scripted seam.

package assert_test

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/evidence"
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
	demands            []*verify.EnrichmentDemand
	subjects           int
	sboms              []verify.SBOMs
}

func (d *fakeDeep) Release(
	_ verify.Coords, subjects []verify.Subject, sboms verify.SBOMs, pins verify.Pins, decision bool,
) error {
	d.releasePins = append(d.releasePins, pins)
	d.subjects = len(subjects)
	d.decisions = append(d.decisions, decision)
	d.sboms = append(d.sboms, sboms)

	return d.releaseErr
}

func (d *fakeDeep) VSA(_ verify.Coords, _ []verify.Subject, pins verify.Pins, demand *verify.EnrichmentDemand) error {
	d.vsaPins = append(d.vsaPins, pins)
	d.demands = append(d.demands, demand)

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

	return runDeepWalkPolicy(t, f, deep, loadTestPolicy(t))
}

func runDeepWalkPolicy(t *testing.T, f *fakeForge, deep *fakeDeep, pol *assert.Policy) *report.Report {
	t.Helper()

	full, err := assert.NewFullDepth(deep,
		"acme/canon/.github/workflows/verify-release.yml", "acme/signer/.github/workflows/sign.yml")
	if err != nil {
		t.Fatal(err)
	}

	src := assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}

	rep, err := assert.Evidence(pol, orgPop(t, f, nil), f, src, &fakeAttestor{},
		report.NewJournal(), nil, full, func(string, ...any) {})
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
		// than an epoch must reach the engine with that obligation
		// OFF — grandfathered history verifies what it can prove,
		// decided by policy data, never a try-each. Both declared
		// epochs are exercised here because they travel the same
		// contract to two different engine entry points.
		polJSON := strings.Replace(testPolicyJSON,
			`"storeVsaFromVersion": "1.13.0",`,
			`"storeVsaFromVersion": "1.13.0", "decisionFromVersion": "1.23.1", `+
				`"enrichmentFromVersion": "1.30.0",`, 1)

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

		rep, rerr := assert.Evidence(pol, orgPop(t, f, nil), f, src, &fakeAttestor{},
			report.NewJournal(), nil, full,
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

		if len(deep.demands) != 1 || deep.demands[0] != nil {
			t.Fatalf("demands = %v — a v1.20.0 pin predates the 1.30.0 enrichment epoch, "+
				"so the claim must not be demanded of it", deep.demands)
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
// TestDepthClassDemand pins the wire (stele#122): class enrichment
// names reach the engine as the demand.
func TestDepthClassDemand(t *testing.T) {
	t.Parallel()

	// The class-keyed half (stele#122): the walk's demand carries
	// what the release's declared classes owe, derived from the
	// policy — never a boolean, never re-derived at the engine.
	polJSON := strings.Replace(testPolicyJSON,
		`"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}`,
		`"oci-image": {"bundles": ["attestations-image.intoto.jsonl"], "enrichment": ["base-images"]}`, 1)

	pol, err := assert.LoadPolicy(strings.NewReader(polJSON))
	if err != nil {
		t.Fatal(err)
	}

	f := deepForge()
	deep := &fakeDeep{}
	full, ferr := assert.NewFullDepth(deep,
		"acme/canon/.github/workflows/verify-release.yml", "acme/signer/.github/workflows/sign.yml")
	if ferr != nil {
		t.Fatal(ferr)
	}

	src := assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}

	rep, rerr := assert.Evidence(pol, orgPop(t, f, nil), f, src, &fakeAttestor{},
		report.NewJournal(), nil, full,
		func(string, ...any) {})
	if rerr != nil {
		t.Fatal(rerr)
	}

	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
	}

	// Keyed by artifact, not by release (stele#206): the demand names
	// the tarball the manifest attributed to oci-image, and nothing
	// else in the release is asked for that class's names.
	if len(deep.demands) != 1 || deep.demands[0] == nil ||
		!slices.Equal(deep.demands[0].ByArtifact["widget-v1.0.0.tar.gz"], []string{"base-images"}) {
		t.Fatalf("demands = %+v, want the oci-image class's base-images on the attributed artifact", deep.demands)
	}
}

// enrichedDeepPolicy is the deep-walk policy with an enrichment name
// on oci-image and the manifest-schema epoch pushed past the fixture's
// machinery version, so a pre-class-split manifest is admitted as the
// history it is rather than refused.
func enrichedDeepPolicy(t *testing.T) *assert.Policy {
	t.Helper()

	polJSON := strings.Replace(testPolicyJSON,
		`"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}`,
		`"oci-image": {"bundles": ["attestations-image.intoto.jsonl"], "enrichment": ["base-images"]}`, 1)
	polJSON = strings.Replace(polJSON,
		`"storeVsaFromVersion": "1.13.0"`,
		`"storeVsaFromVersion": "1.13.0", "manifestSchemaFromVersion": "10.0.0"`, 1)

	pol, err := assert.LoadPolicy(strings.NewReader(polJSON))
	if err != nil {
		t.Fatal(err)
	}

	return pol
}

// classlessManifest renders a pre-class-split manifest: typed entries
// that carry no class, which is everything schema 2 could say.
func classlessManifest() string {
	return `{"schema": 2, "classes": ["oci-image"], "storeVsa": true, "machineryVersion": "9.9.9",` +
		` "entries": [{"name": "widget-v1.0.0.tar.gz", "sha256": "` + subjectDigest +
		`", "type": "build-subject"}]}`
}

// runDeepDemand walks one release at full depth, returning the sealed
// report and everything the walk said out loud.
//
//nolint:gocritic // unnamedResult: the report, then its transcript — named in the doc
func runDeepDemand(t *testing.T, f *fakeForge, deep *fakeDeep, pol *assert.Policy, declared ...report.Exception,
) (*report.Report, string) {
	t.Helper()

	return runDeepDemandSource(t, f, deep, pol,
		assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}, declared...)
}

// runDeepSource walks one release at full depth through the given
// contract source — the seam the cross-check's not-owed rows need,
// where WHICH source speaks for the release is the fixture.
//
//nolint:gocritic // unnamedResult: the report, then its transcript — named in the doc
func runDeepSource(t *testing.T, f *fakeForge, pol *assert.Policy, src assert.ContractSource,
	declared ...report.Exception,
) (*report.Report, string) {
	t.Helper()

	return runDeepDemandSource(t, f, &fakeDeep{}, pol, src, declared...)
}

//nolint:gocritic // unnamedResult: the report, then its transcript — named in the doc
func runDeepDemandSource(t *testing.T, f *fakeForge, deep *fakeDeep, pol *assert.Policy,
	source assert.ContractSource, declared ...report.Exception,
) (*report.Report, string) {
	t.Helper()

	full, err := assert.NewFullDepth(deep,
		"acme/canon/.github/workflows/verify-release.yml", "acme/signer/.github/workflows/sign.yml")
	if err != nil {
		t.Fatal(err)
	}

	src := assert.Sources{source}

	var said strings.Builder

	rep, err := assert.Evidence(pol, orgPop(t, f, nil), f, src, &fakeAttestor{},
		report.NewJournal(declared...), nil, full,
		func(format string, args ...any) { fmt.Fprintf(&said, format+"\n", args...) })
	if err != nil {
		t.Fatalf("Evidence: %v", err)
	}

	return rep, said.String()
}

// encoded renders a sealed report as the document a consumer reads —
// the only place staleness and unexercised-ness are observable, and
// the difference between them is the whole point of judging the
// attribution obligation only where a manifest could meet it.
func encoded(t *testing.T, rep *report.Report) string {
	t.Helper()

	var doc strings.Builder
	if err := rep.Encode(&doc); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	return doc.String()
}

// TestDepthClasslessManifestNarrows is the stele#206 fix at the walk:
// a manifest that predates the class split cannot say which artifact
// belongs to which class, so every artifact is held to its
// class-independent obligations IN FULL and to no class-specific one —
// and the narrowing is stated per artifact, naming what it excused.
// The pre-fix behaviour held every artifact to the release's whole
// class set, which reds pre-epoch releases forever.
func TestDepthClasslessManifestNarrows(t *testing.T) {
	t.Parallel()

	pol := enrichedDeepPolicy(t)
	f := deepForge()
	f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = classlessManifest()

	deep := &fakeDeep{}
	rep, said := runDeepDemand(t, f, deep, pol,
		report.Declared("widget@v1.0.0", "manifest:attribution", "debt.txt:1"))

	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
	}

	if len(deep.demands) != 1 || deep.demands[0] == nil || len(deep.demands[0].ByArtifact) != 0 {
		t.Fatalf("demands = %+v, want nothing class-specific asked of an unattributable artifact", deep.demands)
	}

	want := "widget-v1.0.0.tar.gz: class unknowable under schema 2 — excused: base-images"
	if !strings.Contains(said, want) {
		t.Fatalf("the walk did not state the narrowing:\n%s\nwant substring %q", said, want)
	}

	// The obligation is not judged where the manifest could never meet
	// it, so an excuse written against it is unexercised — never stale,
	// which would claim this run watched it run clean.
	if doc := encoded(t, rep); !strings.Contains(doc, "unexercisedExceptions") ||
		strings.Contains(doc, "staleExceptions") {
		t.Fatalf("attribution was judged on a manifest that cannot attribute:\n%s", doc)
	}
}

// TestDepthAttributionDefects is ruling (a) on stele#206: post-epoch,
// attribution is OWED. A manifest that could attribute and did not is
// broken derived state — a finding, and the artifact stays held to the
// whole declared set, because narrowing there would let omission buy
// the leniency only structural silence earns.
func TestDepthAttributionDefects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		manifest string
		want     string
	}{
		{
			name: "an artifact the manifest does not list",
			manifest: `{"schema": ` + strconv.Itoa(evidence.Schema) + `, "classes": ["oci-image"], ` +
				`"storeVsa": true, "machineryVersion": "9.9.9", "entries": [` +
				manifestEntry("somewhere-else.tar.gz", "build-subject", "oci-image", "linux-amd64") + `]}`,
			want: "attributes every artifact to a class and this one to none",
		},
		{
			name: "an artifact attributed to a class the policy does not define",
			manifest: `{"schema": ` + strconv.Itoa(evidence.Schema) + `, "classes": ["conjured"], ` +
				`"storeVsa": true, "machineryVersion": "9.9.9", "entries": [` +
				manifestEntry("widget-v1.0.0.tar.gz", "build-subject", "conjured", "linux-amd64") + `]}`,
			want: `built by class "conjured", which the policy does not define`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pol := enrichedDeepPolicy(t)
			f := deepForge()
			f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = tt.manifest

			rep, said := runDeepDemand(t, f, &fakeDeep{}, pol)

			if rep.Verdict() != report.VerdictFail {
				t.Fatalf("verdict = %s, want a finding on a manifest that could attribute and did not", rep.Verdict())
			}

			found := rep.Findings()

			var got *report.Finding

			for i := range found {
				if found[i].Assertion == "manifest:attribution" {
					got = &found[i]

					break
				}
			}

			if got == nil {
				t.Fatalf("no manifest:attribution finding, findings: %+v", found)
			}

			if !strings.Contains(got.Detail, tt.want) || !strings.Contains(got.Detail, "widget-v1.0.0.tar.gz") {
				t.Fatalf("finding = %q, want it to name the artifact and %q", got.Detail, tt.want)
			}

			// A defect is never an excusal: the walk must not also have
			// told the reader it narrowed anything.
			if strings.Contains(said, "class unknowable") {
				t.Fatalf("a broken attribution was reported as a narrowing:\n%s", said)
			}
		})
	}
}

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
		src := assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}

		rep, rerr := assert.Evidence(pol, orgPop(t, f, nil), f, src, &fakeAttestor{},
			report.NewJournal(), nil, full,
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
		src := assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}

		rep, rerr := assert.Evidence(pol, orgPop(t, f, nil), f, src, &fakeAttestor{},
			report.NewJournal(), nil, full,
			func(string, ...any) {})
		if rerr != nil {
			t.Fatal(rerr)
		}

		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — underivable pins must red, not pass silently", rep.Verdict())
		}
	})
}

// TestDepthFullPlan pins the join the per-inventory decision rests on
// (stele#158): the walk hands the verify engine the release's
// SBOM assets AND, among them, the documents its classes' planned
// obligations owed at its own machinery version. The denominator is
// derived where the class list meets the policy — a caller restating
// it would be the second source of truth .github#544 was filed about.
func TestDepthFullPlan(t *testing.T) {
	t.Parallel()

	planned, err := assert.LoadPolicy(strings.NewReader(strings.Replace(testPolicyJSON,
		`"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]},`,
		`"oci-image": {"bundles": ["attestations-image.intoto.jsonl"],`+
			`"assetPrefixes": [{"prefix": "sbom-image-", "planned": true}]},`, 1)))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	f := deepForge()
	f.assets["widget@v1.0.0"] = append(f.assets["widget@v1.0.0"], "sbom-image-widget-1.0.0.spdx.json")
	f.assetBytes["widget@v1.0.0"]["checksums.txt"] += strings.Repeat("f", 64) +
		"  sbom-image-widget-1.0.0.spdx.json\n"

	deep := &fakeDeep{}

	rep := runDeepWalkPolicy(t, f, deep, planned)
	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
	}

	if len(deep.sboms) != 1 {
		t.Fatalf("release leg called %d time(s), want once", len(deep.sboms))
	}

	got := deep.sboms[0]
	if len(got.Assets) != 2 {
		t.Errorf("assets = %+v, want both SBOM documents as decision candidates", got.Assets)
	}

	if len(got.Planned) != 1 || got.Planned[0].Name != "sbom-image-widget-1.0.0.spdx.json" {
		t.Errorf("planned = %+v, want the one document the class's planned obligation claims", got.Planned)
	}
}
