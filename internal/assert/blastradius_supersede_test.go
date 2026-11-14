// The supersession table: where only the newest release is supported,
// a finding on an older one is answered by the upgrade — and only
// where the newest release proves the upgrade remedies it. Every row
// varies one thing about the newest release and asserts what the old
// finding amounts to, by the finding left standing and never by the
// verdict alone: a row that goes red for the wrong reason must not
// pass for the right one.

package assert_test

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

// scriptedScanner answers per inventory: the report is chosen by the
// SBOM bytes handed in, so two releases of one repository can ship
// different things.
type scriptedScanner map[string]string

func (s scriptedScanner) Scan(sbom []byte) ([]byte, error) {
	out, ok := s[string(sbom)]
	if !ok {
		return []byte(`{"results": []}`), nil
	}

	return []byte(out), nil
}

const (
	oldSBOM = `{"spdxVersion": "SPDX-2.3", "name": "old"}`
	newSBOM = `{"spdxVersion": "SPDX-2.3", "name": "new"}`
	oldTag  = "v1.0.0"
	newTag  = "v1.1.0"
	// The old release's finding, spelled the way a report names it.
	oldFinding = canaryScan + ":serde_cbor@0.11.2"
)

func supersedingPolicy(t *testing.T) *assert.Policy {
	t.Helper()

	doc := strings.Replace(blastPolicyJSON,
		`"osEcosystems": ["debian", "alpine"],`,
		`"osEcosystems": ["debian", "alpine"], "supported": "latest-release",`, 1)

	pol, err := assert.LoadPolicy(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}

	return pol
}

// twoReleases scripts widget with an old release (the canary's, which
// always ships the canary advisory) and a newer one. The listing
// order is the caller's, because the newest release is chosen by
// version and a row must be able to prove it.
func twoReleases(tags ...string) *fakeForge {
	return &fakeForge{
		repos: []string{"widget"},
		tags:  map[string][]string{"widget": tags},
		assets: map[string][]string{
			"widget@" + oldTag: {"app.spdx.json"},
			"widget@" + newTag: {"app.spdx.json"},
		},
		assetBytes: map[string]map[string]string{
			"widget@" + oldTag: {"app.spdx.json": oldSBOM},
			"widget@" + newTag: {"app.spdx.json": newSBOM},
		},
		store: map[string][]string{
			chain.SHA256Hex([]byte(oldSBOM)): {`{"bundle": 1}`},
			chain.SHA256Hex([]byte(newSBOM)): {`{"bundle": 2}`},
		},
	}
}

func runSuperseding(
	t *testing.T, pol *assert.Policy, f *fakeForge, scans scriptedScanner, d *vexjoin.Decisions,
) *report.Report {
	t.Helper()

	rep, err := assert.BlastRadius(pol, orgPop(t, f, nil), f, scans, d,
		report.NewJournal(), func(string, ...any) {})
	if err != nil {
		t.Fatalf("BlastRadius: %v", err)
	}

	return rep
}

// standing renders the unexcused findings as "subject assertion", the
// form every row asserts against — sorted, because which release the
// forge listed first is not what a row is about.
func standing(rep *report.Report) []string {
	var out []string
	for _, f := range rep.Findings() {
		out = append(out, f.Subject+" "+f.Assertion)
	}

	sort.Strings(out)

	return out
}

func TestBlastRadiusSupersession(t *testing.T) {
	t.Parallel()

	oldScan := scanResult(canaryScan, "serde_cbor", "0.11.2", "crates.io", true)
	oldStands := "widget@" + oldTag + " " + oldFinding

	tests := []struct {
		name      string
		pol       func(*testing.T) *assert.Policy
		forge     func() *fakeForge
		newScan   string
		decisions *vexjoin.Decisions
		want      []string
	}{
		{
			name: "the newest release does not carry it: the old finding is superseded",
			pol:  supersedingPolicy, forge: func() *fakeForge { return twoReleases(newTag, oldTag) },
			newScan: `{"results": []}`, decisions: &vexjoin.Decisions{},
			want: nil,
		},
		{
			name: "no support window declared: every release still gates",
			pol:  loadBlastPolicy, forge: func() *fakeForge { return twoReleases(newTag, oldTag) },
			newScan: `{"results": []}`, decisions: &vexjoin.Decisions{},
			want: []string{oldStands},
		},
		{
			name: "the newest release is chosen by version, not by listing order",
			pol:  supersedingPolicy, forge: func() *fakeForge { return twoReleases(oldTag, newTag) },
			newScan: `{"results": []}`, decisions: &vexjoin.Decisions{},
			want: nil,
		},
		{
			name: "the newest release carries the same triple: both stand",
			pol:  supersedingPolicy, forge: func() *fakeForge { return twoReleases(newTag, oldTag) },
			newScan: oldScan, decisions: &vexjoin.Decisions{},
			want: []string{oldStands, "widget@" + newTag + " " + oldFinding},
		},
		{
			name: "the newest release carries the advisory at another version: the upgrade remedies nothing",
			pol:  supersedingPolicy, forge: func() *fakeForge { return twoReleases(newTag, oldTag) },
			newScan:   scanResult(canaryScan, "serde_cbor", "0.11.3", "crates.io", true),
			decisions: &vexjoin.Decisions{},
			want:      []string{oldStands, "widget@" + newTag + " " + canaryScan + ":serde_cbor@0.11.3"},
		},
		{
			name: "the newest release carries it at a version judged not affected: the upgrade is the remedy",
			pol:  supersedingPolicy, forge: func() *fakeForge { return twoReleases(newTag, oldTag) },
			newScan:   scanResult(canaryScan, "serde_cbor", "0.11.3", "crates.io", true),
			decisions: decided(t, canaryScan, "serde_cbor", "0.11.3"),
			want:      nil,
		},
		{
			name: "the newest release carries a different package's finding: the old one is still superseded",
			pol:  supersedingPolicy, forge: func() *fakeForge { return twoReleases(newTag, oldTag) },
			newScan:   scanResult(canaryScan, "other_pkg", "2.0.0", "crates.io", true),
			decisions: &vexjoin.Decisions{},
			want:      []string{"widget@" + newTag + " " + canaryScan + ":other_pkg@2.0.0"},
		},
		{
			name: "the newest release's SBOM is unattested: it proves nothing and supersedes nothing",
			pol:  supersedingPolicy,
			forge: func() *fakeForge {
				f := twoReleases(newTag, oldTag)
				delete(f.store, chain.SHA256Hex([]byte(newSBOM)))

				return f
			},
			newScan: `{"results": []}`, decisions: &vexjoin.Decisions{},
			want: []string{oldStands, "widget@" + newTag + " app.spdx.json:unattested"},
		},
		{
			name: "the newest release ships no SBOM: it proves nothing and supersedes nothing",
			pol:  supersedingPolicy,
			forge: func() *fakeForge {
				f := twoReleases(newTag, oldTag)
				f.assets["widget@"+newTag] = []string{"widget.tar.gz"}

				return f
			},
			newScan: `{"results": []}`, decisions: &vexjoin.Decisions{},
			want: []string{oldStands},
		},
		{
			name: "a newer prerelease is not the supported release",
			pol:  supersedingPolicy,
			forge: func() *fakeForge {
				f := twoReleases("v1.1.0-rc.1", oldTag)
				f.assets["widget@v1.1.0-rc.1"] = f.assets["widget@"+newTag]
				f.assetBytes["widget@v1.1.0-rc.1"] = f.assetBytes["widget@"+newTag]

				return f
			},
			newScan: `{"results": []}`, decisions: &vexjoin.Decisions{},
			want: []string{oldStands},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rep := runSuperseding(t, tt.pol(t), tt.forge(),
				scriptedScanner{oldSBOM: oldScan, newSBOM: tt.newScan}, tt.decisions)

			got := standing(rep)
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Fatalf("standing findings:\n  got  %q\n  want %q", got, tt.want)
			}

			wantVerdict := report.VerdictPass
			if len(tt.want) > 0 {
				wantVerdict = report.VerdictFail
			}

			if rep.Verdict() != wantVerdict {
				t.Fatalf("verdict = %s, want %s", rep.Verdict(), wantVerdict)
			}
		})
	}
}

// TestBlastRadiusSupersessionIsStated pins what a reader of the report
// is told: the exception names the release that answers the finding,
// and a repository whose newest release could not answer is named as
// withheld rather than silently gating.
func TestBlastRadiusSupersessionIsStated(t *testing.T) {
	t.Parallel()

	oldScan := scanResult(canaryScan, "serde_cbor", "0.11.2", "crates.io", true)

	t.Run("the exception names the supported release", func(t *testing.T) {
		t.Parallel()

		rep := runSuperseding(t, supersedingPolicy(t), twoReleases(newTag, oldTag),
			scriptedScanner{oldSBOM: oldScan}, &vexjoin.Decisions{})

		var buf bytes.Buffer
		if err := rep.Encode(&buf); err != nil {
			t.Fatalf("Encode: %v", err)
		}

		want := "superseded release: widget@" + newTag + " is the supported release and does not carry " +
			canaryScan + " in serde_cbor unexcused"
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("the report does not state the supersession:\n  want %q\n%s", want, buf.String())
		}
	})

	t.Run("a newest release not read whole is named as withheld", func(t *testing.T) {
		t.Parallel()

		f := twoReleases(newTag, oldTag)
		delete(f.store, chain.SHA256Hex([]byte(newSBOM)))

		rep := runSuperseding(t, supersedingPolicy(t), f,
			scriptedScanner{oldSBOM: oldScan}, &vexjoin.Decisions{})

		var buf bytes.Buffer
		if err := rep.Encode(&buf); err != nil {
			t.Fatalf("Encode: %v", err)
		}

		for _, want := range []string{"supersessionWithheld", "widget@" + newTag + "(not read whole)"} {
			if !strings.Contains(buf.String(), want) {
				t.Fatalf("the report does not carry %q:\n%s", want, buf.String())
			}
		}
	})

	t.Run("no tag that orders as a stable version is named as withheld", func(t *testing.T) {
		t.Parallel()

		f := twoReleases("nightly", oldTag+"-rc.1")
		f.assets["widget@nightly"] = f.assets["widget@"+newTag]
		f.assetBytes["widget@nightly"] = f.assetBytes["widget@"+newTag]
		f.assets["widget@"+oldTag+"-rc.1"] = f.assets["widget@"+oldTag]
		f.assetBytes["widget@"+oldTag+"-rc.1"] = f.assetBytes["widget@"+oldTag]

		pol := supersedingPolicy(t)
		pol.BlastRadius.Canary = nil

		rep := runSuperseding(t, pol, f, scriptedScanner{oldSBOM: oldScan}, &vexjoin.Decisions{})

		var buf bytes.Buffer
		if err := rep.Encode(&buf); err != nil {
			t.Fatalf("Encode: %v", err)
		}

		if !strings.Contains(buf.String(), "widget(no release tag orders as a stable version)") {
			t.Fatalf("the report does not name the unordered repository:\n%s", buf.String())
		}

		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s, want FAIL: nothing was superseded", rep.Verdict())
		}
	})
}

// TestBlastRadiusSupportedRefusal pins the vocabulary guard: a window
// this walk does not know is refused at load, never read as either
// everything or nothing.
func TestBlastRadiusSupportedRefusal(t *testing.T) {
	t.Parallel()

	doc := strings.Replace(blastPolicyJSON,
		`"osEcosystems": ["debian", "alpine"],`,
		`"osEcosystems": ["debian", "alpine"], "supported": "two-latest",`, 1)

	_, err := assert.LoadPolicy(strings.NewReader(doc))
	if err == nil || !strings.Contains(err.Error(), `blastRadius.supported is "two-latest"`) {
		t.Fatalf("error = %v, want the unknown-window refusal", err)
	}
}

// TestBlastRadiusStatesTheSupportWindow pins the two facts a release
// decision reads: which release answers for the repository, and
// whether that release is itself carrying an advisory nothing excuses.
// A consumer that derived either from finding subjects would be
// choosing the newest release a second way.
func TestBlastRadiusStatesTheSupportWindow(t *testing.T) {
	t.Parallel()

	oldScan := scanResult(canaryScan, "serde_cbor", "0.11.2", "crates.io", true)

	for _, tt := range []struct {
		name      string
		pol       func(*testing.T) *assert.Policy
		newScan   string
		decisions *vexjoin.Decisions
		supported string
		affected  string
	}{
		{
			"a clean newest release is supported and not affected",
			supersedingPolicy, `{"results": []}`, &vexjoin.Decisions{},
			`"supportedReleases","value":"widget@` + newTag + `"`, "",
		},
		{
			"a newest release carrying an undecided advisory is affected",
			supersedingPolicy, oldScan, &vexjoin.Decisions{},
			`"supportedReleases","value":"widget@` + newTag + `"`,
			`"supportedReleasesAffected","value":"widget@` + newTag + `"`,
		},
		{
			"a newest release whose only finding is decided is not affected",
			supersedingPolicy, oldScan, decided(t, canaryScan, "serde_cbor", "0.11.2"),
			`"supportedReleases","value":"widget@` + newTag + `"`, "",
		},
		{
			"no support window declared states neither",
			loadBlastPolicy, oldScan, &vexjoin.Decisions{},
			"", "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rep := runSuperseding(t, tt.pol(t), twoReleases(newTag, oldTag),
				scriptedScanner{oldSBOM: oldScan, newSBOM: tt.newScan}, tt.decisions)

			var buf bytes.Buffer
			if err := rep.Encode(&buf); err != nil {
				t.Fatalf("Encode: %v", err)
			}

			compact := strings.NewReplacer(" ", "", "\n", "").Replace(buf.String())

			for name, want := range map[string]string{
				"supportedReleases": tt.supported, "supportedReleasesAffected": tt.affected,
			} {
				if want == "" {
					if strings.Contains(compact, `"`+name+`"`) {
						t.Fatalf("the report states %s and should not:\n%s", name, buf.String())
					}

					continue
				}

				if !strings.Contains(compact, want) {
					t.Fatalf("the report lacks %s:\n%s", want, buf.String())
				}
			}
		})
	}
}
