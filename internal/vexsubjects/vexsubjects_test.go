// The affected-release derivation's table: the join that decides a
// release is reached, the subjects a reached release contributes, and
// every way the walk can fail to answer. The join itself is
// triage.Join — the same one blast-radius runs — so what is pinned
// here is the direction, never a second matcher.

package vexsubjects_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/triage"
	"github.com/monumental-archive/stele/internal/vexjoin"
	"github.com/monumental-archive/stele/internal/vexsubjects"
	"github.com/monumental-archive/stele/internal/workflow"
)

const (
	advisory = "RUSTSEC-2021-0127"
	pkgName  = "serde_cbor"
	pkgVer   = "0.11.2"
)

// decisionDoc is one recorded VEX decision over one dependency — the
// document shape security/vex/*.openvex.json carries.
func decisionDoc(version string) []byte {
	return []byte(`{
	  "@context": "https://openvex.dev/ns/v0.2.0",
	  "timestamp": "2026-01-01T00:00:00Z",
	  "statements": [{
	    "vulnerability": {"name": "` + advisory + `"},
	    "products": [{"@id": "pkg:cargo/` + pkgName + `@` + version + `"}],
	    "status": "not_affected",
	    "justification": "vulnerable_code_not_in_execute_path"
	  }]
	}`)
}

func decided(t *testing.T, doc []byte) *vexjoin.Decisions {
	t.Helper()

	d := &vexjoin.Decisions{}
	if err := vexjoin.Parse(d, doc, "security/vex/"+advisory+".openvex.json"); err != nil {
		t.Fatalf("vexjoin.Parse = %v", err)
	}

	return d
}

// scanResult renders one osv-scanner report naming one finding.
func scanResult(pkg, version string) string {
	return `{"results": [{"packages": [{
	  "package": {"name": "` + pkg + `", "version": "` + version + `", "ecosystem": "crates.io"},
	  "vulnerabilities": [{"id": "` + advisory + `", "affected": [{"ranges": [{"events": [{"fixed": "9.9.9"}]}]}]}]
	}]}]}`
}

// fakeForge scripts one org's published releases.
type fakeForge struct {
	tags     map[string][]string
	assets   map[string][]string
	bytes    map[string]string
	unstored map[string]bool
	scanFor  map[string]string
	scanZero map[string]bool
}

func (f *fakeForge) Repos(string) ([]string, error) { return []string{"widget"}, nil }

func (f *fakeForge) ReleaseTags(_, repo string) ([]string, error) { return f.tags[repo], nil }

func (f *fakeForge) ReleaseAssets(_, repo, tag string) ([]string, error) {
	return f.assets[repo+"@"+tag], nil
}

func (f *fakeForge) Asset(_, repo, tag, name string) ([]byte, error) {
	key := repo + "@" + tag + "/" + name

	content, ok := f.bytes[key]
	if !ok {
		return nil, errors.New("no such asset: " + key)
	}

	return []byte(content), nil
}

func (f *fakeForge) Attestations(_, _, digest string) ([]jsonx.Raw, error) {
	if f.unstored[digest] {
		return nil, nil
	}

	return []jsonx.Raw{jsonx.Raw(`{"bundle": true}`)}, nil
}

func (f *fakeForge) ReleaseDate(_, _, _ string) (time.Time, error) {
	return time.Time{}, errors.New("this fixture serves no release date")
}

func (f *fakeForge) TagCommit(_, _, _ string) (string, error) {
	return "", errors.New("this fixture serves no tag commit")
}

//nolint:gocritic // unnamedResult: the Forge interface documents the results
func (f *fakeForge) FileAt(_, _, _, _ string) ([]byte, bool, error) { return nil, false, nil }

func (f *fakeForge) PackageVersionDigest(_, _, _ string) (string, error) { return "", nil }

func (f *fakeForge) WorkflowContents(_, _ string) ([][]byte, error) { return nil, nil }

func (f *fakeForge) Workflows(_, _ string) ([]workflow.File, error) { return nil, nil }

func (f *fakeForge) FailedRuns(_, _, _ string) ([]string, error) { return nil, nil }

// scanner answers per SBOM CONTENT, so a fixture can ship one release
// whose inventory names the package and another whose does not.
type scanner struct{ f *fakeForge }

func (s scanner) Scan(sbom []byte) ([]byte, error) {
	if s.f.scanZero[string(sbom)] {
		return nil, osv.ErrZeroPackages
	}

	out, ok := s.f.scanFor[string(sbom)]
	if !ok {
		return []byte(`{"results": []}`), nil
	}

	return []byte(out), nil
}

// twoReleases is the clean world: v1.0.0 ships an inventory naming
// the decided package, v0.9.0 ships one that does not, and both ship
// a checksum manifest.
func twoReleases() *fakeForge {
	hit, miss := "inventory with serde_cbor", "inventory without it"

	return &fakeForge{
		tags: map[string][]string{"widget": {"v1.0.0", "v0.9.0"}},
		assets: map[string][]string{
			"widget@v1.0.0": {"app.spdx.json", "checksums.txt"},
			"widget@v0.9.0": {"app.spdx.json", "checksums.txt"},
		},
		bytes: map[string]string{
			"widget@v1.0.0/app.spdx.json": hit,
			"widget@v0.9.0/app.spdx.json": miss,
			"widget@v1.0.0/checksums.txt": strings.Repeat("a", 64) + "  widget-1.0.0.tar.gz\n" +
				strings.Repeat("b", 64) + "  app.spdx.json\n",
			"widget@v0.9.0/checksums.txt": strings.Repeat("c", 64) + "  widget-0.9.0.tar.gz\n",
		},
		scanFor: map[string]string{hit: scanResult(pkgName, pkgVer)},
	}
}

func deriverOver(f *fakeForge) *vexsubjects.Deriver {
	return &vexsubjects.Deriver{
		Org:        "acme",
		SBOMSuffix: ".spdx.json",
		Checksums:  "checksums.txt",
		Triage:     &triage.Policy{BaseEcosystems: []string{"debian", "alpine"}},
		Forge:      f,
		Scanner:    scanner{f: f},
	}
}

// TestAffected is the whole point: the releases a decision reaches
// are derived from what they SHIP, and only those contribute
// subjects.
func TestAffected(t *testing.T) {
	t.Parallel()

	f := twoReleases()

	doc, err := deriverOver(f).Affected([]string{"widget"}, decided(t, decisionDoc(pkgVer)),
		"security/vex/"+advisory+".openvex.json")
	if err != nil {
		t.Fatalf("Affected = %v", err)
	}

	if len(doc.Releases) != 1 || doc.Releases[0].Subject() != "widget@v1.0.0" {
		t.Fatalf("releases = %+v, want the one shipping the decided package", doc.Releases)
	}

	if got := doc.Releases[0].Advisories; len(got) != 1 || got[0] != advisory {
		t.Errorf("advisories = %v, want the advisory that reached it", got)
	}

	// The reached release's manifest, whole — the claim is bound to
	// every byte that release publishes, not to the inventory alone.
	if len(doc.Subjects) != 2 {
		t.Fatalf("subjects = %+v, want the affected release's whole manifest", doc.Subjects)
	}

	if doc.Subjects[0].Name != "widget-1.0.0.tar.gz" || doc.Subjects[0].SHA256 != strings.Repeat("a", 64) {
		t.Errorf("subject[0] = %+v, want the manifest's first line", doc.Subjects[0])
	}

	if doc.Decision != "security/vex/"+advisory+".openvex.json" {
		t.Errorf("decision = %q, want the document it was derived for", doc.Decision)
	}
}

// TestAffectedJoinsOnTheExactTriple pins that this is the SAME join
// blast-radius runs: a decision on another version of the same
// package reaches nothing, which is how a bumped dependency surfaces
// for a fresh judgment instead of inheriting the old one.
func TestAffectedJoinsOnTheExactTriple(t *testing.T) {
	t.Parallel()

	f := twoReleases()

	_, err := deriverOver(f).Affected([]string{"widget"}, decided(t, decisionDoc("0.11.1")),
		"security/vex/"+advisory+".openvex.json")
	if err == nil || !strings.Contains(err.Error(), "no published release ships a package") {
		t.Fatalf("error = %v, want the bound-to-nothing refusal", err)
	}
}

// TestAffectedOneReleaseManyInventories pins the per-artifact
// inventory shape (.github#492): a release carrying several
// inventories is named once, with every advisory that reached it.
func TestAffectedOneReleaseManyInventories(t *testing.T) {
	t.Parallel()

	f := twoReleases()
	f.assets["widget@v1.0.0"] = []string{"sbom-npm-app.spdx.json", "app.spdx.json", "checksums.txt"}
	f.bytes["widget@v1.0.0/sbom-npm-app.spdx.json"] = "second inventory with serde_cbor"
	f.scanFor["second inventory with serde_cbor"] = scanResult(pkgName, pkgVer)

	doc, err := deriverOver(f).Affected([]string{"widget"}, decided(t, decisionDoc(pkgVer)),
		"security/vex/"+advisory+".openvex.json")
	if err != nil {
		t.Fatalf("Affected = %v", err)
	}

	if len(doc.Releases) != 1 {
		t.Fatalf("releases = %+v, want the release named once", doc.Releases)
	}

	if len(doc.Releases[0].Advisories) != 1 {
		t.Errorf("advisories = %v, want the advisory named once", doc.Releases[0].Advisories)
	}

	if len(doc.Subjects) != 2 {
		t.Errorf("subjects = %+v, want the manifest read once", doc.Subjects)
	}
}

// TestAffectedRefusals is the guard table: everything that must stop
// the derivation rather than quietly shrink the subject set.
func TestAffectedRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		world     func(f *fakeForge)
		decisions func(t *testing.T) *vexjoin.Decisions
		want      string
	}{
		{
			"an inventory the store does not vouch for",
			func(f *fakeForge) {
				f.unstored = map[string]bool{chain.SHA256Hex([]byte("inventory with serde_cbor")): true}
			},
			nil, "not vouched for by the attestation store",
		},
		{
			"an inventory that parsed to zero packages",
			func(f *fakeForge) { f.scanZero = map[string]bool{"inventory with serde_cbor": true} },
			nil, "parsed to zero packages",
		},
		{
			"an affected release with no checksum manifest",
			func(f *fakeForge) { delete(f.bytes, "widget@v1.0.0/checksums.txt") },
			nil, "ships a named package but its checksums.txt is unreadable",
		},
		{
			"an affected release whose manifest pins nothing",
			func(f *fakeForge) { f.bytes["widget@v1.0.0/checksums.txt"] = "\n# nothing here\n" },
			nil, "pins nothing",
		},
		{
			"a decision document naming no versioned product",
			func(*fakeForge) {},
			func(t *testing.T) *vexjoin.Decisions {
				t.Helper()

				return &vexjoin.Decisions{}
			},
			"decides nothing",
		},
		{
			"a scanner report that does not decode",
			func(f *fakeForge) { f.scanFor["inventory with serde_cbor"] = "not a report" },
			nil, "scanner report",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := twoReleases()
			tt.world(f)

			decisions := decided(t, decisionDoc(pkgVer))
			if tt.decisions != nil {
				decisions = tt.decisions(t)
			}

			_, err := deriverOver(f).Affected([]string{"widget"}, decisions, "security/vex/d.openvex.json")
			if err == nil {
				t.Fatal("the derivation accepted what it must refuse")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestAffectedWithoutChecksumsDeclared pins the caller-side guard: a
// derivation with no manifest name has no source for its subjects,
// and guessing one would put this package's opinion into signed
// evidence.
func TestAffectedWithoutChecksumsDeclared(t *testing.T) {
	t.Parallel()

	d := deriverOver(twoReleases())
	d.Checksums = ""

	_, err := d.Affected([]string{"widget"}, decided(t, decisionDoc(pkgVer)), "security/vex/d.openvex.json")
	if err == nil || !strings.Contains(err.Error(), "no checksum manifest declared") {
		t.Fatalf("error = %v, want the undeclared-manifest refusal", err)
	}
}

// TestAffectedSkipsReleasesWithoutInventories pins the absence rule:
// a release predating the inventory obligation is skipped, never
// failed — whether that absence is owed is the evidence walk's
// question, not this one's.
func TestAffectedSkipsReleasesWithoutInventories(t *testing.T) {
	t.Parallel()

	f := twoReleases()
	f.assets["widget@v0.9.0"] = []string{"widget-0.9.0.tar.gz"}

	doc, err := deriverOver(f).Affected([]string{"widget"}, decided(t, decisionDoc(pkgVer)),
		"security/vex/d.openvex.json")
	if err != nil {
		t.Fatalf("Affected = %v", err)
	}

	if len(doc.Releases) != 1 || doc.Releases[0].Tag != "v1.0.0" {
		t.Errorf("releases = %+v, want only the one with an inventory", doc.Releases)
	}
}

// TestAffectedLogsProgress pins that the derivation says what it
// found: a caller wiring no log must not change the answer, and one
// wiring a log must be told which release was reached.
func TestAffectedLogsProgress(t *testing.T) {
	t.Parallel()

	var lines []string

	d := deriverOver(twoReleases())
	d.Log = func(format string, args ...any) {
		lines = append(lines, format)
		_ = args
	}

	if _, err := d.Affected([]string{"widget"}, decided(t, decisionDoc(pkgVer)),
		"security/vex/d.openvex.json"); err != nil {
		t.Fatalf("Affected = %v", err)
	}

	if len(lines) != 1 {
		t.Errorf("logged %d line(s), want one per reached inventory", len(lines))
	}
}
