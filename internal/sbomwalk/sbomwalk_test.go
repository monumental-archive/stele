// The shared traversal's table: every defect the walk can report,
// every read that can tear, and the order it visits in. The walk
// judges nothing, so what is pinned here is exactly what it hands a
// visitor — two callers depend on that being the same thing.

package sbomwalk_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/sbomwalk"
	"github.com/monumental-archive/stele/internal/workflow"
)

// fakeForge scripts one org's releases. A read it was not given
// scripted content for answers empty, which is the forge's own shape;
// torn names the ONE read that fails, because which read tears
// decides which refusal a caller sees.
type fakeForge struct {
	tags   map[string][]string
	assets map[string][]string
	bytes  map[string]string
	store  map[string]bool
	torn   map[string]error
}

func (f *fakeForge) Repos(string) ([]string, error) { return nil, f.torn["Repos"] }

func (f *fakeForge) ReleaseTags(_, repo string) ([]string, error) {
	return f.tags[repo], f.torn["ReleaseTags"]
}

func (f *fakeForge) ReleaseAssets(_, repo, tag string) ([]string, error) {
	return f.assets[repo+"@"+tag], f.torn["ReleaseAssets"]
}

func (f *fakeForge) Asset(_, repo, tag, name string) ([]byte, error) {
	if err := f.torn["Asset"]; err != nil {
		return nil, err
	}

	return []byte(f.bytes[repo+"@"+tag+"/"+name]), nil
}

func (f *fakeForge) Attestations(_, _, digest string) ([]jsonx.Raw, error) {
	if err := f.torn["Attestations"]; err != nil {
		return nil, err
	}

	if !f.store[digest] {
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

// fakeScanner answers every scan the same way — the walk does not
// read the report, so its content is only ever passed through.
type fakeScanner struct {
	out string
	err error
}

func (s fakeScanner) Scan([]byte) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}

	return []byte(s.out), nil
}

// oneRelease is a repository with one release shipping one attested
// inventory — the clean world every row mutates.
func oneRelease() *fakeForge {
	sbom := "the inventory bytes"

	return &fakeForge{
		tags:   map[string][]string{"widget": {"v1.0.0"}},
		assets: map[string][]string{"widget@v1.0.0": {"app.tar.gz", "app.spdx.json"}},
		bytes:  map[string]string{"widget@v1.0.0/app.spdx.json": sbom},
		store:  map[string]bool{chain.SHA256Hex([]byte(sbom)): true},
	}
}

func TestWalkScansEveryInventory(t *testing.T) {
	t.Parallel()

	f := oneRelease()
	f.assets["widget@v1.0.0"] = append(f.assets["widget@v1.0.0"], "sbom-npm-app.spdx.json")
	f.bytes["widget@v1.0.0/sbom-npm-app.spdx.json"] = "second inventory"
	f.store[chain.SHA256Hex([]byte("second inventory"))] = true

	var seen []sbomwalk.Inventory

	w := &sbomwalk.Walk{Org: "acme", SBOMSuffix: ".spdx.json", Forge: f, Scanner: fakeScanner{out: `{"results":[]}`}}

	if err := w.Releases([]string{"widget"}, func(inv *sbomwalk.Inventory) error {
		seen = append(seen, *inv)

		return nil
	}); err != nil {
		t.Fatalf("Releases = %v", err)
	}

	if len(seen) != 2 {
		t.Fatalf("visited %d inventories, want both: %+v", len(seen), seen)
	}

	// Listing order, not sorted order: a walk that reordered would
	// report a traversal it did not perform.
	if seen[0].Asset != "app.spdx.json" || seen[1].Asset != "sbom-npm-app.spdx.json" {
		t.Errorf("order = %s, %s — want the forge's listing order", seen[0].Asset, seen[1].Asset)
	}

	for _, inv := range seen {
		if inv.Defect != sbomwalk.DefectNone || string(inv.Report) != `{"results":[]}` {
			t.Errorf("inventory %+v: want a clean scan carrying the report", inv)
		}

		if inv.Subject() != "widget@v1.0.0" {
			t.Errorf("subject = %q, want widget@v1.0.0", inv.Subject())
		}
	}
}

// TestWalkDefects pins what the walk REPORTS rather than what it
// decides: each row is a world, and the defect handed to the visitor
// is the whole answer.
func TestWalkDefects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		world     func() (*fakeForge, osv.Scanner)
		want      sbomwalk.Defect
		wantAsset string
	}{
		{
			"a release shipping no inventory at all",
			func() (*fakeForge, osv.Scanner) {
				f := oneRelease()
				f.assets["widget@v1.0.0"] = []string{"app.tar.gz"}

				return f, fakeScanner{out: "{}"}
			},
			sbomwalk.DefectNoInventory, "",
		},
		{
			"an inventory the store does not vouch for",
			func() (*fakeForge, osv.Scanner) {
				f := oneRelease()
				f.store = nil

				return f, fakeScanner{out: "{}"}
			},
			sbomwalk.DefectUnattested, "app.spdx.json",
		},
		{
			"an inventory that parsed to zero packages",
			func() (*fakeForge, osv.Scanner) {
				return oneRelease(), fakeScanner{err: osv.ErrZeroPackages}
			},
			sbomwalk.DefectZeroPackages, "app.spdx.json",
		},
		{
			"an inventory fetched, trusted and scanned",
			func() (*fakeForge, osv.Scanner) { return oneRelease(), fakeScanner{out: "{}"} },
			sbomwalk.DefectNone, "app.spdx.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f, scanner := tt.world()

			var seen []sbomwalk.Inventory

			w := &sbomwalk.Walk{Org: "acme", SBOMSuffix: ".spdx.json", Forge: f, Scanner: scanner}

			if err := w.Releases([]string{"widget"}, func(inv *sbomwalk.Inventory) error {
				seen = append(seen, *inv)

				return nil
			}); err != nil {
				t.Fatalf("Releases = %v", err)
			}

			if len(seen) != 1 {
				t.Fatalf("visited %d, want one: %+v", len(seen), seen)
			}

			if seen[0].Defect != tt.want {
				t.Errorf("defect = %q, want %q", seen[0].Defect, tt.want)
			}

			if seen[0].Asset != tt.wantAsset {
				t.Errorf("asset = %q, want %q", seen[0].Asset, tt.wantAsset)
			}

			if tt.want != sbomwalk.DefectNone && seen[0].Report != nil {
				t.Error("a defect carried a report — a caller must not reach a judgment through bytes never obtained")
			}
		})
	}
}

// TestWalkTornReads pins the degraded forge: every read the walk
// makes can fail, and each one must stop the walk by name rather than
// read as an org with nothing published.
func TestWalkTornReads(t *testing.T) {
	t.Parallel()

	tests := []struct {
		read string
		want string
	}{
		{"ReleaseTags", "releases of acme/widget"},
		{"ReleaseAssets", "assets of acme/widget@v1.0.0"},
		{"Asset", "app.spdx.json of acme/widget@v1.0.0"},
		{"Attestations", "store for app.spdx.json of acme/widget@v1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.read, func(t *testing.T) {
			t.Parallel()

			f := oneRelease()
			f.torn = map[string]error{tt.read: errors.New("the forge is degraded")}

			w := &sbomwalk.Walk{Org: "acme", SBOMSuffix: ".spdx.json", Forge: f, Scanner: fakeScanner{out: "{}"}}

			err := w.Releases([]string{"widget"}, func(*sbomwalk.Inventory) error { return nil })
			if err == nil {
				t.Fatal("a torn read walked clean")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestWalkScannerFailure pins the difference between the scanner
// answering "nothing here" and the scanner failing: one is a defect
// the visitor judges, the other stops the walk.
func TestWalkScannerFailure(t *testing.T) {
	t.Parallel()

	w := &sbomwalk.Walk{
		Org: "acme", SBOMSuffix: ".spdx.json", Forge: oneRelease(),
		Scanner: fakeScanner{err: errors.New("the scanner died")},
	}

	err := w.Releases([]string{"widget"}, func(*sbomwalk.Inventory) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "scanning app.spdx.json") {
		t.Fatalf("error = %v, want the scan failure named", err)
	}
}

// TestWalkVisitorStops pins the visitor's own veto: a caller that
// treats a defect as fatal returns, and the walk stops there.
func TestWalkVisitorStops(t *testing.T) {
	t.Parallel()

	f := oneRelease()
	f.tags["widget"] = []string{"v1.0.0", "v1.1.0"}
	f.assets["widget@v1.1.0"] = []string{"app.spdx.json"}

	w := &sbomwalk.Walk{Org: "acme", SBOMSuffix: ".spdx.json", Forge: f, Scanner: fakeScanner{out: "{}"}}
	stop := errors.New("the caller refuses")

	visits := 0

	err := w.Releases([]string{"widget"}, func(*sbomwalk.Inventory) error {
		visits++

		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("error = %v, want the visitor's own refusal", err)
	}

	if visits != 1 {
		t.Errorf("visited %d times after a refusal, want one", visits)
	}
}

// TestWalkWithoutSuffix pins the guard on the org's own declaration:
// with no inventory suffix declared, every asset or none would be an
// inventory, and guessing which is not this package's to do.
func TestWalkWithoutSuffix(t *testing.T) {
	t.Parallel()

	w := &sbomwalk.Walk{Org: "acme", Forge: oneRelease(), Scanner: fakeScanner{out: "{}"}}

	err := w.Releases([]string{"widget"}, func(*sbomwalk.Inventory) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "no SBOM suffix declared") {
		t.Fatalf("error = %v, want the undeclared-suffix refusal", err)
	}
}
