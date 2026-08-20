// The checksum cross-check (stele#219): a release's two pinning
// documents describe the same bytes, or the walk says so. Every guard
// branch is here, because the ways this check must stay SILENT — a
// name only one document carries, a manifest that cannot pin, a
// checksum manifest that would not read — are exactly the ways a
// cross-check turns into a second source of noise over sound
// releases.

package assert_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/report"
)

// otherDigest is bytes that are not the checksum manifest's — the
// disagreement itself.
const otherDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// pinningManifest renders a schema-3 manifest over the given entry
// JSON — the fixture's control over what the evidence manifest pins.
func pinningManifest(entries ...string) string {
	return `{"schema": 3, "classes": ["oci-image"], "storeVsa": true, "machineryVersion": "9.9.9",` +
		` "entries": [` + strings.Join(entries, ", ") + `]}`
}

// findingsFor narrows a sealed report's findings to one assertion.
func findingsFor(rep *report.Report, assertion string) []report.Finding {
	var out []report.Finding

	found := rep.Findings()
	for i := range found {
		if found[i].Assertion == assertion {
			out = append(out, found[i])
		}
	}

	return out
}

// TestChecksumAgreement is the cross-check's whole vocabulary: the
// disagreement is a finding, and everything that merely LOOKS like one
// is not.
func TestChecksumAgreement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// arrange mutates the fixture release.
		arrange func(*fakeForge)
		// want are substrings the finding's detail must carry; empty
		// means the cross-check must find nothing.
		want []string
	}{
		{
			name:    "the healthy release's two documents agree",
			arrange: func(*fakeForge) {},
		},
		{
			name: "one name carrying two digests is the finding",
			arrange: func(f *fakeForge) {
				f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = pinningManifest(
					manifestEntryPinned("widget-v1.0.0.tar.gz", "build-subject", "oci-image", otherDigest))
			},
			want: []string{"widget-v1.0.0.tar.gz", subjectDigest, otherDigest},
		},
		{
			name: "every disagreeing name is named, in one finding",
			arrange: func(f *fakeForge) {
				f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = pinningManifest(
					manifestEntryPinned("widget-v1.0.0.tar.gz", "build-subject", "oci-image", otherDigest),
					manifestEntryPinned("app.spdx.json", "evidence", "", otherDigest))
			},
			want: []string{"widget-v1.0.0.tar.gz", "app.spdx.json", strings.Repeat("d", 64)},
		},
		{
			// The evidence manifest cannot pin itself, and the checksum
			// manifest does pin it. Judging that as a disagreement would
			// red every healthy release for the documents' own shapes.
			name: "a name only the checksum manifest carries is not judged",
			arrange: func(f *fakeForge) {
				f.assetBytes["widget@v1.0.0"]["checksums.txt"] += otherDigest + "  unlisted-v1.0.0.tar.gz\n"
			},
		},
		{
			name: "a name only the evidence manifest carries is not judged",
			arrange: func(f *fakeForge) {
				f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = pinningManifest(
					manifestEntryPinned("widget-v1.0.0.tar.gz", "build-subject", "oci-image", subjectDigest),
					manifestEntryPinned("unshipped.json", "evidence", "", otherDigest))
			},
		},
		{
			// A line that pins nothing is not part of the checksum
			// manifest's claim, and reading one as a digest would
			// manufacture a disagreement out of commentary.
			name: "lines that pin nothing raise no disagreement",
			arrange: func(f *fakeForge) {
				f.assetBytes["widget@v1.0.0"]["checksums.txt"] += "not a manifest line\n" +
					strings.ToUpper(otherDigest) + "  widget-v1.0.0.tar.gz\n"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := deepForge()
			tt.arrange(f)

			rep, _ := runDeepDemand(t, f, &fakeDeep{}, enrichedDeepPolicy(t))

			got := findingsFor(rep, "manifest:checksums")

			if len(tt.want) == 0 {
				if len(got) != 0 {
					t.Fatalf("manifest:checksums findings = %+v, want none", got)
				}

				return
			}

			if len(got) != 1 {
				t.Fatalf("manifest:checksums findings = %+v, want exactly one", got)
			}

			for _, w := range tt.want {
				if !strings.Contains(got[0].Detail, w) {
					t.Fatalf("finding = %q, want it to carry %q", got[0].Detail, w)
				}
			}
		})
	}
}

// TestChecksumAgreementJudged proves the check is RECORDED on a
// release that can meet it: an excuse written against a check this run
// watched run clean is stale, which is the only observable difference
// between a check that held and a check nobody performed.
func TestChecksumAgreementJudged(t *testing.T) {
	t.Parallel()

	rep, _ := runDeepDemand(t, deepForge(), &fakeDeep{}, enrichedDeepPolicy(t),
		report.Declared("widget@v1.0.0", "manifest:checksums", "debt.txt:1"))

	if doc := encoded(t, rep); !strings.Contains(doc, "staleExceptions") {
		t.Fatalf("the cross-check was not recorded on a release that pins its assets:\n%s", doc)
	}
}

// TestChecksumAgreementNotOwed is the epoch floor and the missing
// document: a source that cannot pin at all is a NARROWING — stated
// out loud, and never recorded as a check, because an obligation the
// release could never meet would sit in the journal forever and any
// exception against it would read as stale from the day it was
// written.
func TestChecksumAgreementNotOwed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		arrange func(*fakeForge)
		src     func(*assert.Policy, *fakeForge) assert.ContractSource
	}{
		{
			name: "a manifest whose schema carries no entries",
			arrange: func(f *fakeForge) {
				const entryless = `{"schema": 1, "classes": ["oci-image"], "storeVsa": true,` +
					` "machineryVersion": "9.9.9"}`

				f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = entryless
			},
			src: func(pol *assert.Policy, f *fakeForge) assert.ContractSource {
				return assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}
			},
		},
		{
			name: "a release no manifest speaks for",
			arrange: func(f *fakeForge) {
				stub := "jobs:\n  publish:\n    with:\n      classes: oci-image\n" +
					"    uses: acme/canon/.github/workflows/publish.yml@" + machineryPin40 + " # v1.2.3\n"

				f.files["widget:v1.0.0:.github/workflows/publish.yml"] = stub
			},
			src: func(pol *assert.Policy, f *fakeForge) assert.ContractSource {
				return assert.WorkflowSource{Forge: f, Policy: pol.Evidence}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pol := enrichedDeepPolicy(t)
			f := deepForge()
			tt.arrange(f)

			rep, said := runDeepSource(t, f, pol, tt.src(pol, f),
				report.Declared("widget@v1.0.0", "manifest:checksums", "debt.txt:1"))

			if got := findingsFor(rep, "manifest:checksums"); len(got) != 0 {
				t.Fatalf("manifest:checksums findings = %+v, want none from a source that cannot pin", got)
			}

			if !strings.Contains(said, "the checksum cross-check is not asked") {
				t.Fatalf("the walk did not state the narrowing:\n%s", said)
			}

			if doc := encoded(t, rep); strings.Contains(doc, "staleExceptions") {
				t.Fatalf("a cross-check nobody could perform read as watched:\n%s", doc)
			}
		})
	}
}

// TestChecksumAgreementUnreadable: an unreadable checksum manifest is
// ONE cause, and `deep` has already spoken for it. A second red here
// would report one broken release as two defects.
func TestChecksumAgreementUnreadable(t *testing.T) {
	t.Parallel()

	f := deepForge()
	delete(f.assetBytes["widget@v1.0.0"], "checksums.txt")

	rep, _ := runDeepDemand(t, f, &fakeDeep{}, enrichedDeepPolicy(t))

	if got := findingsFor(rep, "manifest:checksums"); len(got) != 0 {
		t.Fatalf("manifest:checksums findings = %+v, want none where the document would not read", got)
	}

	if got := findingsFor(rep, "deep"); len(got) != 1 {
		t.Fatalf("deep findings = %+v, want the one cause reported once", got)
	}
}
