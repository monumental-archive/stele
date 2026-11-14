// What a release published somewhere other than its assets
// (stele#329): a container image or a registry package has no file
// beside the manifest, so no checksum manifest can name it. These rows
// hold the deep walk to reading it from the document that can — the
// evidence manifest where its schema names registry subjects, the
// release's own provenance where it predates that — and to refusing
// only a release that names no subject of any kind.

package assert_test

import (
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/evidence"
	"github.com/monumental-archive/stele/internal/provenance"
	"github.com/monumental-archive/stele/internal/report"
)

const (
	imageName     = "ghcr.io/acme/widget"
	imageDigest   = "7777777777777777777777777777777777777777777777777777777777777777"
	documentBytes = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	// documentsOnly is the checksum manifest of a release whose every
	// artifact lives in a registry: it pins the documents about the
	// release and nothing else, correctly.
	documentsOnly = documentBytes + "  app.spdx.json\n" +
		documentBytes + "  attestations-image.intoto.jsonl\n" +
		documentBytes + "  evidence-manifest.json\n"
)

// statementLine renders one bundle line around a statement body.
func statementLine(subjects, predicateType string) string {
	stmt := `{"_type": "https://in-toto.io/Statement/v1", "subject": [` + subjects + `],` +
		`"predicateType": "` + predicateType + `", "predicate": {}}`

	return `{"dsseEnvelope": {"payload": "` + base64.StdEncoding.EncodeToString([]byte(stmt)) + `"}}`
}

// provenanceLine is a bundle line attesting provenance over one named
// subject — the only statement whose subjects are artifacts of the
// build by definition.
func provenanceLine(name, digest string) string {
	return statementLine(`{"name": "`+name+`", "digest": {"sha256": "`+digest+`"}}`, provenance.PredicateType)
}

// manifestAt renders a manifest at the given schema over the given
// entries, published by the fixture's machinery version.
func manifestAt(schema int, entries ...string) string {
	return `{"schema": ` + strconv.Itoa(schema) + `, "classes": ["oci-image"], "storeVsa": true,` +
		` "machineryVersion": "9.9.9", "entries": [` + strings.Join(entries, ", ") + `]}`
}

// theInventory is the one document every fixture manifest lists, at
// the bytes the checksum manifest pins for it.
func theInventory() string {
	return manifestEntryPinned("app.spdx.json", "evidence", "", "", documentBytes)
}

// imageEntry is the registry-subject entry naming the fixture image.
func imageEntry() string {
	return manifestEntryPinned(imageName, evidence.TypeRegistrySubject, "oci-image", "image", imageDigest)
}

// imageOnlyForge is a release that shipped one image and no file: the
// class bundle attests provenance over it, the store holds its
// verdict, and the manifest is the row's own.
func imageOnlyForge(manifest string) *fakeForge {
	f := deepForge()
	f.assetBytes["widget@v1.0.0"]["checksums.txt"] = documentsOnly
	f.assetBytes["widget@v1.0.0"]["attestations-image.intoto.jsonl"] = provenanceLine(imageName, imageDigest)
	f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = manifest
	f.store = map[string][]string{imageDigest: {bundleJSONL(vsaType)}}

	return f
}

// TestDepthImageOnlyRelease is the defect itself, measured on
// iiif-server v0.2.2 and release-lab v0.28.0 (.github#1168): both
// shipped an image alone, both were sound, and the deep walk refused
// both because their checksum manifest pinned only documents.
func TestDepthImageOnlyRelease(t *testing.T) {
	t.Parallel()

	t.Run("the manifest names the image, and the walk reads it", func(t *testing.T) {
		t.Parallel()

		deep := &fakeDeep{}

		rep, said := runDeepDemand(t, imageOnlyForge(manifestAt(evidence.Schema, theInventory(), imageEntry())),
			deep, enrichedDeepPolicy(t))
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		if !slices.Equal(deep.names, []string{imageName}) {
			t.Fatalf("the engine was handed %v, want the image alone", deep.names)
		}

		// The manifest attributed it, so it owes its class's names in
		// full — and nothing was read back out of the bundles.
		if got := deep.demands[0].ByArtifact[imageName]; !slices.Equal(got, []string{"base-images"}) {
			t.Fatalf("the image owes %v, want its class's enrichment", got)
		}

		if strings.Contains(said, "read from the release's own provenance") {
			t.Fatalf("a manifest that names its registry subjects was not read for them:\n%s", said)
		}
	})

	t.Run("a manifest that predates registry subjects is answered from the provenance", func(t *testing.T) {
		t.Parallel()

		deep := &fakeDeep{}

		rep, said := runDeepDemand(t, imageOnlyForge(manifestAt(4, theInventory())), deep, enrichedDeepPolicy(t))
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		if !slices.Equal(deep.names, []string{imageName}) {
			t.Fatalf("the engine was handed %v, want the image the bundle attests", deep.names)
		}

		for _, want := range []string{
			"widget@v1.0.0: the evidence manifest (schema 4) names no registry subject — 1 read from the" +
				" release's own provenance",
			imageName + ": class unknowable: schema 4 names no registry subject — excused: base-images",
		} {
			if !strings.Contains(said, want) {
				t.Fatalf("the walk did not say %q:\n%s", want, said)
			}
		}

		// Nothing attributed it, so nothing class-specific is asked of
		// it — and the manifest is not accused of an omission its
		// schema gave it no way to avoid.
		if got := deep.demands[0].ByArtifact; len(got) != 0 {
			t.Fatalf("demand = %v, want nothing class-specific asked of an unplaced subject", got)
		}
	})

	t.Run("a release no manifest speaks for is answered from the provenance too", func(t *testing.T) {
		t.Parallel()

		f := imageOnlyForge("")
		f.files["widget:v1.0.0:.github/workflows/publish.yml"] = "jobs:\n  publish:\n" +
			"    uses: acme/canon/.github/workflows/publish.yml@" + machineryPin40 + " # v1.20.0\n" +
			"    with:\n      classes: oci-image\n"

		pol := enrichedDeepPolicy(t)

		rep, said := runDeepSource(t, f, pol, assert.WorkflowSource{Forge: f, Policy: pol.Evidence})
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		want := "the contract (publish workflow at v1.0.0) names no registry subject — 1 read"
		if !strings.Contains(said, want) {
			t.Fatalf("the walk did not say %q:\n%s", want, said)
		}
	})
}

// TestDepthNoSubjectOfAnyKind: the refusal the image-only release used
// to trip is still owed by a release that genuinely claims nothing —
// asked once, with both halves in hand, and naming the document that
// had the chance to say otherwise.
func TestDepthNoSubjectOfAnyKind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		manifest string
		want     string
	}{
		{
			"a manifest that could name a registry subject and named none",
			manifestAt(evidence.Schema, theInventory()),
			"checksums.txt pins no artifact and the evidence manifest (schema 5) names none",
		},
		{
			"a manifest that could not, over bundles that attest no provenance",
			manifestAt(4, theInventory()),
			"checksums.txt pins no artifact and the evidence manifest (schema 4) names none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := imageOnlyForge(tt.manifest)
			// A verdict statement names the image; no provenance does.
			f.assetBytes["widget@v1.0.0"]["attestations-image.intoto.jsonl"] = statementLine(
				`{"name": "`+imageName+`", "digest": {"sha256": "`+imageDigest+`"}}`, vsaType,
			)

			deep := &fakeDeep{}

			rep, _ := runDeepDemand(t, f, deep, enrichedDeepPolicy(t))

			got := rep.Findings()
			if len(got) != 1 || got[0].Assertion != "deep" || !strings.Contains(got[0].Detail, tt.want) {
				t.Fatalf("findings = %+v, want one deep finding mentioning %q", got, tt.want)
			}

			if len(deep.releasePins) != 0 {
				t.Fatal("the engine ran over a release that names no subject")
			}
		})
	}
}

// TestDepthMixedRelease: the half of the defect nothing reported. A
// release shipping a file AND an image had the image dropped from the
// deep subject set in silence (measured on release-lab v0.28.1:
// fourteen tarballs verified, six images and a package never asked
// about). Both populations now reach the engine, each exactly once.
func TestDepthMixedRelease(t *testing.T) {
	t.Parallel()

	const artifact = "widget-v1.0.0.tar.gz"

	mixed := func(manifest string) *fakeForge {
		f := deepForge()
		f.assetBytes["widget@v1.0.0"]["attestations-image.intoto.jsonl"] = provenanceLine(artifact, subjectDigest) +
			"\n" + provenanceLine(imageName, imageDigest)
		f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = manifest
		f.store[imageDigest] = []string{bundleJSONL(vsaType)}

		return f
	}

	file := manifestEntryPinned(artifact, "build-subject", "oci-image", "linux-amd64", subjectDigest)

	t.Run("read from the manifest", func(t *testing.T) {
		t.Parallel()

		deep := &fakeDeep{}

		rep, _ := runDeepDemand(t, mixed(manifestAt(evidence.Schema, file, imageEntry())), deep, enrichedDeepPolicy(t))
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		if !slices.Equal(deep.names, []string{artifact, imageName}) {
			t.Fatalf("the engine was handed %v, want the file then the image", deep.names)
		}
	})

	t.Run("read from the provenance, the file not twice", func(t *testing.T) {
		t.Parallel()

		deep := &fakeDeep{}

		rep, said := runDeepDemand(t, mixed(manifestAt(4, file)), deep, enrichedDeepPolicy(t))
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		if !slices.Equal(deep.names, []string{artifact, imageName}) {
			t.Fatalf("the engine was handed %v, want the file once and the image", deep.names)
		}

		// The file is attributed by the manifest and owes its class in
		// full; only the subject nothing placed is narrowed.
		demand := deep.demands[0].ByArtifact
		if !slices.Equal(demand[artifact], []string{"base-images"}) || len(demand[imageName]) != 0 {
			t.Fatalf("demand = %v, want the file held and the image narrowed", demand)
		}

		if !strings.Contains(said, "1 read from the release's own provenance") {
			t.Fatalf("the walk did not count the one subject it read back:\n%s", said)
		}
	})
}

// TestDepthManifestSubjectsCrossCheck: where the manifest claims what
// the release published, the release's own provenance is held against
// the claim. A list read back out of the proofs can only say the
// proofs that exist are sound; this is the other direction — an
// artifact the evidence attests and neither pinning document names.
func TestDepthManifestSubjectsCrossCheck(t *testing.T) {
	t.Parallel()

	registered := manifestAt(evidence.Schema, theInventory(), imageEntry())

	t.Run("an attested subject the release does not claim", func(t *testing.T) {
		t.Parallel()

		const stray = "8888888888888888888888888888888888888888888888888888888888888888"

		f := imageOnlyForge(registered)
		f.assetBytes["widget@v1.0.0"]["attestations-image.intoto.jsonl"] = provenanceLine(imageName, imageDigest) +
			"\n" + provenanceLine(imageName, stray)
		f.store[stray] = []string{bundleJSONL(vsaType)}

		deep := &fakeDeep{}

		rep, _ := runDeepDemand(t, f, deep, enrichedDeepPolicy(t))

		got := rep.Findings()
		if len(got) != 1 || got[0].Assertion != "manifest:subjects" ||
			!strings.Contains(got[0].Detail, imageName+" (sha256:"+stray+")") {
			t.Fatalf("findings = %+v, want one manifest:subjects finding naming the stray digest", got)
		}

		// The claim is still what gets verified: the cross-check
		// reports the disagreement, it does not widen the subject set.
		if !slices.Equal(deep.names, []string{imageName}) {
			t.Fatalf("the engine was handed %v, want the claimed subject alone", deep.names)
		}
	})

	t.Run("a class bundle that cannot be read", func(t *testing.T) {
		t.Parallel()

		f := imageOnlyForge(registered)
		f.assetErr = map[string]error{
			"widget@v1.0.0/attestations-image.intoto.jsonl": errors.New("asset fetch failed"),
		}

		rep, _ := runDeepDemand(t, f, &fakeDeep{}, enrichedDeepPolicy(t))

		if !hasFinding(rep, "manifest:subjects", "attestations-image.intoto.jsonl is unreadable") {
			t.Fatalf("findings = %+v, want manifest:subjects to say it could not cross-check", rep.Findings())
		}
	})

	t.Run("a release that agrees with itself records the check and passes", func(t *testing.T) {
		t.Parallel()

		rep, _ := runDeepDemand(t, imageOnlyForge(registered), &fakeDeep{}, enrichedDeepPolicy(t),
			report.Declared("widget@v1.0.0", "manifest:subjects", "debt.txt:1"))

		// Judged and clean, so an excuse written against it is STALE —
		// which is how the journal proves the check ran.
		if doc := encoded(t, rep); !strings.Contains(doc, "staleExceptions") {
			t.Fatalf("manifest:subjects was not judged on a manifest that names registry subjects:\n%s", doc)
		}
	})

	t.Run("a manifest that could not claim is never judged against one", func(t *testing.T) {
		t.Parallel()

		rep, _ := runDeepDemand(t, imageOnlyForge(manifestAt(4, theInventory())), &fakeDeep{}, enrichedDeepPolicy(t),
			report.Declared("widget@v1.0.0", "manifest:subjects", "debt.txt:1"))

		if doc := encoded(t, rep); !strings.Contains(doc, "unexercisedExceptions") ||
			strings.Contains(doc, "staleExceptions") {
			t.Fatalf("manifest:subjects was judged on a manifest that names no registry subject:\n%s", doc)
		}
	})
}

// TestDepthProvenanceFallbackRefusals: the bundles are the only
// document that names a registry subject for a release whose manifest
// predates them, so a bundle the walk cannot read — or a provenance
// subject it cannot ask the engine for — is a refusal under `deep`,
// never a subject quietly left out.
func TestDepthProvenanceFallbackRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		corrupt func(f *fakeForge)
		want    string
	}{
		{
			"a class bundle that cannot be fetched",
			func(f *fakeForge) {
				f.assetErr = map[string]error{
					"widget@v1.0.0/attestations-image.intoto.jsonl": errors.New("asset fetch failed"),
				}
			},
			"attestations-image.intoto.jsonl is unreadable",
		},
		{
			"a provenance subject with no name",
			func(f *fakeForge) {
				f.assetBytes["widget@v1.0.0"]["attestations-image.intoto.jsonl"] = statementLine(
					`{"digest": {"sha256": "`+imageDigest+`"}}`, provenance.PredicateType,
				)
			},
			"a provenance subject carries no name or no sha256 digest",
		},
		{
			"a provenance subject with no sha256 digest",
			func(f *fakeForge) {
				f.assetBytes["widget@v1.0.0"]["attestations-image.intoto.jsonl"] = statementLine(
					`{"name": "`+imageName+`", "digest": {"sha512": "abc"}}`, provenance.PredicateType,
				)
			},
			"a provenance subject carries no name or no sha256 digest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := imageOnlyForge(manifestAt(4, theInventory()))
			tt.corrupt(f)

			deep := &fakeDeep{}

			rep, _ := runDeepDemand(t, f, deep, enrichedDeepPolicy(t))
			if !hasFinding(rep, "deep", tt.want) {
				t.Fatalf("findings = %+v, want a deep finding mentioning %q", rep.Findings(), tt.want)
			}

			if len(deep.releasePins) != 0 {
				t.Fatal("the engine ran over a subject set the walk could not derive")
			}
		})
	}
}

// hasFinding reports whether the report carries a finding under the
// assertion whose detail mentions the text.
func hasFinding(rep *report.Report, assertion, mention string) bool {
	for _, f := range rep.Findings() {
		if f.Assertion == assertion && strings.Contains(f.Detail, mention) {
			return true
		}
	}

	return false
}
