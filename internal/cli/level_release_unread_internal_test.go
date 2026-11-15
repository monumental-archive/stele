// A read error on the release surface is never evidence about an
// artifact (stele#370).
//
// The stream surface already kept "the store could not be read" apart
// from "the store answered with nothing" (#355). These rows hold the
// release surface to the same rule on both legs: a failed read leaves
// the surface unreached with the subject and the forge's own error
// named, and a partial population is not judged.

package cli

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/level"
	"github.com/monumental-archive/stele/internal/trust"
)

// unreadForge fails chosen store reads (by digest) and asset reads (by
// name), and serves everything else as its scripted release.
type unreadForge struct {
	storeForgeStream

	attErrs   map[string]error
	assetErrs map[string]error
}

func (f *unreadForge) Attestations(owner, repo, hex string) ([]jsonx.Raw, error) {
	if err, ok := f.attErrs[hex]; ok {
		return nil, err
	}

	return f.storeForgeStream.Attestations(owner, repo, hex)
}

func (f *unreadForge) Asset(owner, repo, tag, name string) ([]byte, error) {
	if err, ok := f.assetErrs[name]; ok {
		return nil, err
	}

	return f.levelForge.Asset(owner, repo, tag, name)
}

// The release these rows read: two binaries pinned by a digest
// manifest, and the iiif-server v0.2.4 evidence manifest naming one
// registry image beside them where a row needs it.
const (
	linuxDigest  = "6666666666666666666666666666666666666666666666666666666666666666"
	darwinDigest = "7777777777777777777777777777777777777777777777777777777777777777"
)

// unreadRelease builds the scripted release. withImage adds the real
// evidence manifest, so the release also names a registry subject.
func unreadRelease(t *testing.T, withImage bool) *unreadForge {
	t.Helper()

	f := &unreadForge{}
	f.tags = []string{"v1.0.0"}
	f.assets = []string{"checksums.txt", "widget_linux", "widget_darwin"}
	f.files = map[string][]byte{
		"checksums.txt": []byte(linuxDigest + "  widget_linux\n" + darwinDigest + "  widget_darwin\n"),
		"widget_linux":  []byte("\x7fELF linux bytes"),
		"widget_darwin": []byte("\xcf\xfa\xed\xfe darwin bytes"),
	}

	if withImage {
		f.assets = append(f.assets, "evidence-manifest.json")
		f.files["evidence-manifest.json"] = iiifFixture(t, "evidence-manifest.json.published")
	}

	return f
}

// TestBuildReleaseStoreUnreadable: a store read that failed for any
// subject leaves the release surface unreached, naming each failed
// subject and the forge's error, and judges none of them.
func TestBuildReleaseStoreUnreadable(t *testing.T) {
	throttled := errors.New("HTTP 403: API rate limit exceeded")
	prov := jsonx.Raw("release provenance")

	for _, tt := range []struct {
		name      string
		image     bool
		attErrs   map[string]error
		assetErrs map[string]error
		bundles   map[string][]jsonx.Raw
		want      []string
		subjects  int
		blind     bool
	}{
		{
			name:    "the store errors for one of two files",
			attErrs: map[string]error{darwinDigest: throttled},
			bundles: map[string][]jsonx.Raw{linuxDigest: {prov}},
			want: []string{"release: the attestation store could not be read for widget_darwin (" +
				darwinDigest + "): HTTP 403: API rate limit exceeded"},
			blind: true,
		},
		{
			name:    "the store errors for a registry subject",
			image:   true,
			attErrs: map[string]error{iiifImageDigest: throttled},
			bundles: map[string][]jsonx.Raw{linuxDigest: {prov}, darwinDigest: {prov}},
			want: []string{"release: the attestation store could not be read for " + iiifImage + " (" +
				iiifImageDigest + "): HTTP 403: API rate limit exceeded"},
			blind: true,
		},
		{
			name:    "every failed subject is named",
			attErrs: map[string]error{linuxDigest: throttled, darwinDigest: errors.New("HTTP 502")},
			want: []string{
				"the attestation store could not be read for widget_darwin (" + darwinDigest +
					"): HTTP 502; the attestation store could not be read for widget_linux (" + linuxDigest +
					"): HTTP 403: API rate limit exceeded",
			},
			blind: true,
		},
		{
			// stele#373: a file with no provenance that could not be
			// read to ask whether it is evidence about the release.
			name:      "an unreadable file subject with no provenance",
			assetErrs: map[string]error{"widget_darwin": throttled},
			bundles:   map[string][]jsonx.Raw{linuxDigest: {prov}},
			want: []string{"release: release v1.0.0: asset widget_darwin could not be read, so whether it is an" +
				" artifact or evidence about the release is unknown: HTTP 403: API rate limit exceeded"},
			blind: true,
		},
		{
			// Unchanged: a store that answered with nothing is a
			// measurement, and it refutes.
			name:     "every store read answered and none verified",
			subjects: 2,
			want: []string{`"build/provenance-exists","value":"REFUTED: 2 of 2 published artifact(s)` +
				` carry no provenance identifying them: [widget_darwin widget_linux]`},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := unreadRelease(t, tt.image)
			f.attErrs, f.assetErrs, f.bundles = tt.attErrs, tt.assetErrs, tt.bundles

			swapStreamSeams(t, f, scriptedOCI{}, map[string]*trust.Verified{
				"release provenance": {SAN: dbSAN, Payload: []byte(provenanceFor(t, "sha256:"+linuxDigest))},
			})

			la := &levelArgs{track: trackBuild, owner: "acme", name: "widget", repo: "acme/widget"}
			run := buildReport(t, la, f)

			if len(run.ev.Subjects) != tt.subjects {
				t.Errorf("%d subject(s) judged, want %d\n%s", len(run.ev.Subjects), tt.subjects, run.log)
			}

			checkBuildRun(t, run, subjectNames(run.ev), tt.want, tt.blind)
		})
	}
}

// subjectNames lists the subjects a run judged, in order.
func subjectNames(ev *level.Evidence) []string {
	names := make([]string, 0, len(ev.Subjects))
	for i := range ev.Subjects {
		names = append(names, ev.Subjects[i].Name)
	}

	return names
}

// TestDependencyReleaseAssetUnreadable: on the Dependency leg the
// release gather reads no store, but it reads assets — to find the
// inventory and to tell an artifact from evidence about the release.
// When no covering inventory was found, an asset it could not read
// might have been the inventory, or might be evidence rather than an
// uninventoried artifact; either way a read error is not "not
// inventoried", and the surface is unreached.
func TestDependencyReleaseAssetUnreadable(t *testing.T) {
	refused := errors.New("HTTP 403: API rate limit exceeded")
	inventory := []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"externalRefs":[` +
		`{"referenceLocator":"pkg:golang/example.com/dep@v1.0.0"}]}]}`)

	for _, tt := range []struct {
		name      string
		extra     map[string][]byte
		assetErrs map[string]error
		want      []string
		unwanted  string
	}{
		{
			name:      "an unreadable asset might have been the inventory",
			extra:     map[string][]byte{"widget.spdx.json": inventory},
			assetErrs: map[string]error{"widget.spdx.json": refused},
			want: []string{
				`"dependency/inventory","value":"UNDETERMINED: 1 of the 1 surface(s)`,
				"release: release v1.0.0: asset widget.spdx.json could not be read, so whether it is an" +
					" inventory is unknown: HTTP 403: API rate limit exceeded",
			},
		},
		{
			name:      "an unreadable artifact might have been evidence",
			assetErrs: map[string]error{"widget_darwin": refused},
			want: []string{
				`"dependency/inventory","value":"UNDETERMINED: 1 of the 1 surface(s)`,
				"release v1.0.0: asset widget_darwin could not be read, so whether it is an artifact or" +
					" evidence about the release is unknown: HTTP 403: API rate limit exceeded",
			},
		},
		{
			// A covering inventory answers for every artifact whatever
			// the unread asset was, so the read error changes nothing.
			name:      "a covering inventory makes an unread asset immaterial",
			extra:     map[string][]byte{"widget.spdx.json": inventory},
			assetErrs: map[string]error{"widget_darwin": refused},
			want: []string{`"dependency/inventory","value":"HELD: a published inventory covers all 2` +
				` published artifact(s)"`},
			unwanted: "could not be read",
		},
		{
			// Unchanged: every asset read and none is an inventory.
			name: "every asset read and no inventory",
			want: []string{`"dependency/inventory","value":"REFUTED: 2 of 2 published artifact(s) have no` +
				` published inventory: [widget_darwin widget_linux]`},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := unreadRelease(t, false)
			f.assetErrs = tt.assetErrs

			for name, raw := range tt.extra {
				f.assets = append(f.assets, name)
				f.files[name] = raw
			}

			swapStreamSeams(t, f, scriptedOCI{}, nil)

			ev := &level.Evidence{Owner: "acme", Repo: "widget"}
			la := &levelArgs{track: trackDependency, owner: "acme", name: "widget", repo: "acme/widget"}
			la.gatherDependency(ev, f, &latch{w: &bytes.Buffer{}})

			var doc bytes.Buffer
			if err := level.Assess(level.TrackDependency, ev).Report().Encode(&doc); err != nil {
				t.Fatalf("Encode = %v", err)
			}

			for _, want := range tt.want {
				if !strings.Contains(doc.String(), want) {
					t.Errorf("the report does not carry %q:\n%s", want, doc.String())
				}
			}

			if tt.unwanted != "" && strings.Contains(doc.String(), tt.unwanted) {
				t.Errorf("the report carries %q:\n%s", tt.unwanted, doc.String())
			}
		})
	}
}

// TestDependencyInventorySearchBound (stele#373): the search for an
// inventory is bounded so it cannot download a release of binaries,
// and a search the bound stopped is a look not finished. The release
// here carries the real iiif-server evidence manifest (found first, by
// its name hint) and a dozen-odd unhinted binaries.
func TestDependencyInventorySearchBound(t *testing.T) {
	inventory := []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"externalRefs":[` +
		`{"referenceLocator":"pkg:golang/example.com/dep@v1.0.0"}]}]}`)

	// release lists the digest manifest, the evidence manifest, the
	// artifact, fillers unhinted binaries and, where given, the
	// inventory under a name that carries no hint, at position at.
	release := func(fillers, at int) *unreadForge {
		f := &unreadForge{}
		f.tags = []string{"v1.0.0"}
		f.assets = []string{"checksums.txt", "evidence-manifest.json", "widget_linux"}
		f.files = map[string][]byte{
			"checksums.txt":          []byte(linuxDigest + "  widget_linux\n"),
			"evidence-manifest.json": iiifFixture(t, "evidence-manifest.json.published"),
			"widget_linux":           []byte("\x7fELF linux bytes"),
		}

		for i := range fillers {
			name := "part-" + string(rune('a'+i)) + ".bin"
			f.assets = append(f.assets, name)
			f.files[name] = []byte("\x7fELF part bytes")
		}

		if at >= 0 {
			f.assets = slices.Insert(f.assets, at, "deps.json")
			f.files["deps.json"] = inventory
		}

		return f
	}

	for _, tt := range []struct {
		name  string
		forge *unreadForge
		want  string
	}{
		{
			name:  "the inventory lies past the bound",
			forge: release(10, 13),
			want: `"dependency/inventory","value":"UNDETERMINED: 1 of the 1 surface(s) this repository` +
				` publishes on yielded no publish this run could see, so whatever they publish has not been` +
				` asked for an inventory — release: release v1.0.0: stopped looking for an inventory after` +
				` 12 of 14 asset(s), so whether the release carries one is unknown"`,
		},
		{
			name:  "the inventory lies within the bound",
			forge: release(10, 5),
			want:  `"dependency/inventory","value":"HELD: a published inventory covers all 2 published artifact(s)"`,
		},
		{
			// Every asset was read: absence is then a measurement.
			name:  "twelve assets and no inventory",
			forge: release(9, -1),
			want: `"dependency/inventory","value":"REFUTED: 2 of 2 published artifact(s) have no published` +
				` inventory: [widget_linux ` + iiifImage + `]`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			swapStreamSeams(t, tt.forge, scriptedOCI{}, nil)

			ev := &level.Evidence{Owner: "acme", Repo: "widget"}
			la := &levelArgs{track: trackDependency, owner: "acme", name: "widget", repo: "acme/widget"}
			la.gatherDependency(ev, tt.forge, &latch{w: &bytes.Buffer{}})

			var doc bytes.Buffer
			if err := level.Assess(level.TrackDependency, ev).Report().Encode(&doc); err != nil {
				t.Fatalf("Encode = %v", err)
			}

			if !strings.Contains(doc.String(), tt.want) {
				t.Errorf("the report does not carry %q:\n%s", tt.want, doc.String())
			}
		})
	}
}
