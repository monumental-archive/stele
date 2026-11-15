// A release whose artifacts live in a registry (stele#363).
//
// The level walk learns what a release published in one place,
// releaseSubjects, and that answer is the union of the files the
// digest manifest pins and the registry subjects the release's own
// evidence manifest names. Measured on iiif-server v0.2.4: the digest
// manifest names five evidence documents and nothing else, the image
// is named only by the evidence manifest, and a walk reading the
// digest manifest alone measured "0 artifact(s)" for a release whose
// evidence was complete.
//
// The fixture is that release's own published bytes, not a
// hand-written imitation: testdata/iiif-server-0.2.4 holds its
// checksums.txt and its evidence-manifest.json, the latter under a
// ".published" suffix so no formatter rewrites it — its identity IS
// its digest, and TestFixtureIsThePublishedBytes holds it to the pin
// the release's own checksums.txt carries.

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/trust"
)

// iiifImage is the registry subject iiif-server v0.2.4's evidence
// manifest names, joined to its digest the way the walk names it.
const (
	iiifImageDigest = "a5948d557955e2fbadd50aaaa91c7097b4a879eb3fc7332fab1d17a12f3a4bed"
	iiifImage       = "ghcr.io/monumental-archive/iiif-server@sha256:" + iiifImageDigest
)

// iiifRelease serves iiif-server v0.2.4's asset list: its real digest
// manifest and evidence manifest, and evidence documents whose bytes
// name themselves the way the real ones do. The inventories cover the
// image (they name a package URL).
func iiifRelease(t *testing.T) map[string][]byte {
	t.Helper()

	read := func(name string) []byte { return iiifFixture(t, name) }

	inventory := []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"externalRefs":[` +
		`{"referenceLocator":"pkg:cargo/axum@0.8.4"}]}]}`)

	return map[string][]byte{
		"attestations.intoto.jsonl":              []byte(`{"dsseEnvelope":{"payload":"e30="}}` + "\n"),
		"checksums.txt":                          read("checksums.txt"),
		"evidence-manifest.json":                 read("evidence-manifest.json.published"),
		"iiif-server-0.2.4-image.spdx.json":      inventory,
		"iiif-server-0.2.4.spdx.json":            inventory,
		"sbom-image-iiif-server-0.2.4.spdx.json": inventory,
	}
}

// iiifFixture reads one committed asset of iiif-server v0.2.4.
func iiifFixture(t *testing.T, name string) []byte {
	t.Helper()

	raw, err := fs.ReadFile(os.DirFS(filepath.Join("testdata", "iiif-server-0.2.4")), name)
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

// TestFixtureIsThePublishedBytes: the committed evidence manifest is
// the one iiif-server v0.2.4 published, byte for byte — its sha256 is
// the pin the release's own checksums.txt carries for it.
func TestFixtureIsThePublishedBytes(t *testing.T) {
	t.Parallel()

	sum := sha256.Sum256(iiifFixture(t, "evidence-manifest.json.published"))
	pins := parseDigestManifest(string(iiifFixture(t, "checksums.txt")))

	if got, want := hex.EncodeToString(sum[:]), pins["evidence-manifest.json"]; got != want {
		t.Errorf("the fixture is not the published manifest: sha256 %s, the release pins %s", got, want)
	}
}

// iiifAssets is the release's asset list in the forge's order.
func iiifAssets(files map[string][]byte) []string {
	out := make([]string, 0, len(files))
	for _, name := range []string{
		"attestations.intoto.jsonl", "checksums.txt", "evidence-manifest.json",
		"iiif-server-0.2.4-image.spdx.json", "iiif-server-0.2.4.spdx.json",
		"sbom-image-iiif-server-0.2.4.spdx.json",
	} {
		if _, ok := files[name]; ok {
			out = append(out, name)
		}
	}

	return out
}

// imageProvenance is build provenance for the image, as the store
// would serve it keyed by the image's digest.
const imageProvenance = `{"predicateType":"https://slsa.dev/provenance/v1","predicate":` +
	`{"buildDefinition":{"buildType":"https://actions.github.io/buildtypes/workflow/v1",` +
	`"externalParameters":{"workflow":{}}}}}`

// TestImageOnlyReleaseIsMeasured is the Done-when row: a release whose
// digest manifest names only evidence documents and whose evidence
// manifest names one registry subject with verifying provenance and a
// covering inventory. One artifact is measured, and both tracks
// establish their first requirement on it. Before stele#363 this
// release read "0 artifact(s) measured".
func TestImageOnlyReleaseIsMeasured(t *testing.T) {
	files := iiifRelease(t)
	bundle := jsonx.Raw("image provenance")

	for _, tt := range []struct {
		track string
		log   string
		want  string
	}{
		{
			track: "build",
			log:   "level: release v0.2.4: 1 artifact(s) measured (0 file, 1 registry)",
			want: `"build/provenance-exists","value":"HELD: all 1 published artifact(s)` +
				` carry provenance identifying them by digest"`,
		},
		{
			track: "dependency",
			log:   "level: release v0.2.4: 1 inventoried, 0 not",
			want:  `"dependency/inventory","value":"HELD: a published inventory covers all 1 published artifact(s)"`,
		},
	} {
		swapStreamSeams(t, &storeForgeStream{
			tags: []string{"v0.2.3", "v0.2.4"}, assets: iiifAssets(files), files: files,
			released: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC),
			bundles:  map[string][]jsonx.Raw{iiifImageDigest: {bundle}},
		}, scriptedOCI{}, map[string]*trust.Verified{
			string(bundle): {SAN: streamSAN, Payload: []byte(imageProvenance)},
		})

		var stdout, stderr bytes.Buffer

		Run([]string{"level", tt.track, "--repo", "monumental-archive/iiif-server", "--json"}, &stdout, &stderr)

		if !strings.Contains(stderr.String(), tt.log) {
			t.Errorf("%s: the walk did not log %q:\n%s", tt.track, tt.log, stderr.String())
		}

		if !strings.Contains(stdout.String(), tt.want) {
			t.Errorf("%s: the report does not carry %q:\n%s", tt.track, tt.want, stdout.String())
		}
	}
}

// TestRealManifestNamesTheImage: the committed iiif-server v0.2.4
// manifest, read through the level path, yields the image entry and
// nothing else — named by image and digest, measured with no
// provenance in the store, and so refuted by name rather than skipped.
func TestRealManifestNamesTheImage(t *testing.T) {
	files := iiifRelease(t)

	swapLevelSeams(t, &levelForge{tags: []string{"v0.2.4"}, assets: iiifAssets(files), files: files}, nil)

	var stdout, stderr bytes.Buffer

	Run([]string{"level", "build", "--repo", "monumental-archive/iiif-server", "--json"}, &stdout, &stderr)

	want := "1 of 1 published artifact(s) carry no provenance identifying them: [" + iiifImage + "]"
	if !strings.Contains(stdout.String(), want) {
		t.Errorf("the report does not carry %q:\n%s", want, stdout.String())
	}

	if !strings.Contains(stderr.String(), "1 artifact(s) measured (0 file, 1 registry)") {
		t.Errorf("the walk did not count the image:\n%s", stderr.String())
	}
}

// TestRegistrySubjectGuards holds every branch of the registry read to
// the account it owes. A release that cannot name a registry subject
// contributes none and says so by name; it is never answered out of
// the bundles, and a release with files still measures its files.
func TestRegistrySubjectGuards(t *testing.T) {
	const (
		fileDigest = "5555555555555555555555555555555555555555555555555555555555555555"
		noRegistry = "level: release v1.0.0 names no registry subjects (no manifest, or one that predates them)"
	)

	// The real manifest moved back to schema 4: the format before a
	// release could name a registry subject, carrying no such entry.
	published := iiifRelease(t)["evidence-manifest.json"]
	schema4 := bytes.Replace(published, []byte(`"schema":5`), []byte(`"schema":4`), 1)
	schema4 = bytes.Replace(schema4, []byte(`,{"name":"ghcr.io/monumental-archive/iiif-server",`+
		`"sha256":"`+iiifImageDigest+`","type":"registry-subject","class":"oci-image-crate","target":"image"}`),
		nil, 1)

	if bytes.Contains(schema4, []byte("registry-subject")) || !bytes.Contains(schema4, []byte(`"schema":4`)) {
		t.Fatalf("the schema-4 fixture was not derived:\n%s", schema4)
	}

	artifact := []byte("\x7fELF binary bytes")
	checksums := []byte(fileDigest + "  widget\n")

	// A schema-5 manifest naming the image beside a file artifact.
	mixed := bytes.Replace(published, []byte(`"entries":[`),
		[]byte(`"entries":[{"name":"widget","sha256":"`+fileDigest+
			`","type":"build-subject","class":"oci-image-crate","target":"image"},`), 1)

	manyAssets := []string{"checksums.txt", "widget"}
	manyFiles := map[string][]byte{"checksums.txt": checksums, "widget": artifact}

	for i := range maxManifestProbes {
		name := "z" + strings.Repeat("x", i)
		manyAssets = append(manyAssets, name)
		manyFiles[name] = artifact
	}

	// Named with no hint, so it is probed in listing order, last.
	manyAssets = append(manyAssets, "zz-release.json")
	manyFiles["zz-release.json"] = published

	for _, tt := range []struct {
		name     string
		assets   []string
		files    map[string][]byte
		logs     []string
		unlogged string
		report   string
	}{
		{
			name:   "no evidence manifest",
			assets: []string{"checksums.txt", "widget"},
			files:  map[string][]byte{"checksums.txt": checksums, "widget": artifact},
			logs:   []string{noRegistry, "1 artifact(s) measured (1 file, 0 registry)"},
			report: "carry no provenance identifying them: [widget]",
		},
		{
			name:   "a manifest that predates registry subjects",
			assets: []string{"checksums.txt", "evidence-manifest.json", "widget"},
			files: map[string][]byte{
				"checksums.txt": checksums, "evidence-manifest.json": schema4, "widget": artifact,
			},
			logs:   []string{noRegistry, "1 artifact(s) measured (1 file, 0 registry)"},
			report: "carry no provenance identifying them: [widget]",
		},
		{
			name:   "an asset claiming to be a manifest that does not parse",
			assets: []string{"checksums.txt", "evidence-manifest.json", "widget"},
			files: map[string][]byte{
				"checksums.txt": checksums, "evidence-manifest.json": []byte(`{"classes":[]}`), "widget": artifact,
			},
			logs:   []string{noRegistry, "1 artifact(s) measured (1 file, 0 registry)"},
			report: "carry no provenance identifying them: [widget]",
		},
		{
			name:   "the probe bound reached before the manifest",
			assets: manyAssets,
			files:  manyFiles,
			logs: []string{
				"level: release v1.0.0: stopped looking for an evidence manifest after 12 asset(s)",
			},
			// Unfinished, not absent (stele#373): the release surface is
			// unreached, and nothing is said about registry subjects
			// because nothing is known.
			unlogged: noRegistry,
			report: `"build/provenance-exists","value":"UNDETERMINED: 1 of the 1 surface(s)` +
				` this repository publishes on yielded no publish this run could see, so whatever they publish` +
				` has not been asked for provenance — release: release v1.0.0: stopped looking for an evidence` +
				` manifest after 12 of 15 asset(s), so whether the release carries one is unknown"`,
		},
		{
			name:   "a mixed release counts its image beside its file",
			assets: []string{"checksums.txt", "evidence-manifest.json", "widget"},
			files: map[string][]byte{
				"checksums.txt": checksums, "evidence-manifest.json": mixed, "widget": artifact,
			},
			logs:   []string{"2 artifact(s) measured (1 file, 1 registry)"},
			report: "2 of 2 published artifact(s) carry no provenance identifying them: [widget " + iiifImage + "]",
		},
		{
			name:   "registry subjects alone, with no digest manifest",
			assets: []string{"evidence-manifest.json"},
			files:  map[string][]byte{"evidence-manifest.json": published},
			logs:   []string{"1 artifact(s) measured (0 file, 1 registry)"},
			report: "1 of 1 published artifact(s) carry no provenance identifying them: [" + iiifImage + "]",
		},
		{
			name:   "neither a digest manifest nor a registry subject",
			assets: []string{"evidence-manifest.json", "widget"},
			files:  map[string][]byte{"evidence-manifest.json": schema4, "widget": artifact},
			logs: []string{
				noRegistry,
				"level: release v1.0.0: no asset lists artifact digests, so its artifacts cannot be located",
			},
			report: "has not been asked for provenance — release: release v1.0.0 publishes no asset listing" +
				" artifact digests, so its artifacts cannot be located",
		},
	} {
		swapLevelSeams(t, &levelForge{tags: []string{"v1.0.0"}, assets: tt.assets, files: tt.files}, nil)

		var stdout, stderr bytes.Buffer

		Run([]string{"level", "build", "--repo", "acme/widget", "--json"}, &stdout, &stderr)

		for _, want := range tt.logs {
			if !strings.Contains(stderr.String(), want) {
				t.Errorf("%s: the walk did not log %q:\n%s", tt.name, want, stderr.String())
			}
		}

		if tt.unlogged != "" && strings.Contains(stderr.String(), tt.unlogged) {
			t.Errorf("%s: the walk logged %q:\n%s", tt.name, tt.unlogged, stderr.String())
		}

		if !strings.Contains(stdout.String(), tt.report) {
			t.Errorf("%s: the report does not carry %q:\n%s", tt.name, tt.report, stdout.String())
		}
	}
}
