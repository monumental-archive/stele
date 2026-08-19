// The union view.
//
// The row that matters most is the divergence one: two artifacts
// resolving different versions of one package. The union records
// BOTH, each naming who ships it, and the accompanying row proves
// that divergence is not silently demoted to a fact nobody reads —
// it is visible in the document itself, which is what a consumer and
// an evidence walk both key off.

package sbom_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/sbom"
)

// doc builds a per-artifact document: a root naming the artifact,
// declared through a DESCRIBES relationship the way SPDX says which
// package IS the artifact, then its packages.
func doc(artifact string, deps ...[2]string) *sbom.Document {
	d := &sbom.Document{
		SPDXID:   "SPDXRef-DOCUMENT",
		Packages: []sbom.Package{{SPDXID: "SPDXRef-Package-0", Name: artifact, PrimaryPurpose: "APPLICATION"}},
		Relationships: []sbom.Relationship{{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelatedSPDXElement: "SPDXRef-Package-0",
			RelationshipType:   "DESCRIBES",
		}},
	}

	for i, dep := range deps {
		d.Packages = append(d.Packages, sbom.Package{
			SPDXID:      "SPDXRef-Package-" + string(rune('1'+i)),
			Name:        dep[0],
			VersionInfo: dep[1],
			// An input's own SourceInfo describes ITS platform legs and
			// must not leak into the view.
			SourceInfo:     "linked into: linux/amd64",
			PrimaryPurpose: "LIBRARY",
		})
	}

	return d
}

const released = "2026-08-18T12:00:00Z"

// pkgVersions maps a rendered document's package names to the
// versions it carries, so a row can assert both entries survive.
func pkgVersions(d *sbom.Document) map[string][]string {
	out := map[string][]string{}
	for _, p := range d.Packages[1:] {
		out[p.Name] = append(out[p.Name], p.VersionInfo)
	}

	return out
}

func sourceInfoFor(d *sbom.Document, name, version string) string {
	for _, p := range d.Packages[1:] {
		if p.Name == name && p.VersionInfo == version {
			return p.SourceInfo
		}
	}

	return "<absent>"
}

func TestUnionAggregates(t *testing.T) {
	t.Parallel()

	got, err := sbom.Union("widget@1.0.0", released, "stele-test", []*sbom.Document{
		doc("widget-cli", [2]string{"shared", "1.0.0"}, [2]string{"only-cli", "2.0.0"}),
		doc("widget-npm", [2]string{"shared", "1.0.0"}),
	})
	if err != nil {
		t.Fatalf("Union = %v", err)
	}

	if got.Packages[0].Name != "widget@1.0.0" {
		t.Errorf("root = %q", got.Packages[0].Name)
	}

	if !strings.Contains(got.Packages[0].SourceInfo, "aggregated from widget-cli, widget-npm") {
		t.Errorf("the root does not say what it aggregates: %q", got.Packages[0].SourceInfo)
	}

	// A package every artifact ships needs no qualifier; one only some
	// ship must name them, or the view over-claims exactly the way the
	// per-release document did before it became a view.
	if s := sourceInfoFor(got, "shared", "1.0.0"); s != "" {
		t.Errorf("a universally shipped package was qualified: %q", s)
	}

	if s := sourceInfoFor(got, "only-cli", "2.0.0"); s != "shipped in: widget-cli" {
		t.Errorf("only-cli sourceInfo = %q", s)
	}
}

// The root is whatever the document's DESCRIBES relationship names,
// wherever it sits in the package list. SPDX does not order packages,
// and a foreign generator (or a re-sort in transit) can put the root
// anywhere; a positional read here would silently promote a
// dependency to artifact.
func TestUnionFindsTheRootByDescribesNotPosition(t *testing.T) {
	t.Parallel()

	d := doc("widget-cli", [2]string{"aardvark", "1.0.0"})
	d.Packages[0], d.Packages[1] = d.Packages[1], d.Packages[0]

	got, err := sbom.Union("w", released, "t", []*sbom.Document{d})
	if err != nil {
		t.Fatalf("Union = %v", err)
	}

	if s := sourceInfoFor(got, "aardvark", "1.0.0"); s != "" {
		t.Errorf("aardvark was qualified as %q — the root was misread from position", s)
	}

	if !strings.Contains(got.Packages[0].SourceInfo, "aggregated from widget-cli") {
		t.Errorf("the view does not name widget-cli as the artifact: %q", got.Packages[0].SourceInfo)
	}
}

// Cross-artifact version divergence is ORDINARY — a Rust binary and
// an npm package legitimately resolve different versions of a shared
// dependency — so the union records both rather than choosing a
// winner. Choosing one would make the view assert a dependency
// version half its artifacts do not have.
func TestUnionKeepsBothSidesOfADivergence(t *testing.T) {
	t.Parallel()

	got, err := sbom.Union("widget@1.0.0", released, "stele-test", []*sbom.Document{
		doc("widget-cli", [2]string{"shared", "1.0.0"}),
		doc("widget-npm", [2]string{"shared", "2.0.0"}),
	})
	if err != nil {
		t.Fatalf("Union = %v", err)
	}

	versions := pkgVersions(got)["shared"]
	if len(versions) != 2 {
		t.Fatalf("shared appears %d time(s) (%v), want both versions", len(versions), versions)
	}

	// And each names who ships it: a divergence recorded without
	// attribution is a document a reader cannot act on.
	for version, want := range map[string]string{
		"1.0.0": "shipped in: widget-cli",
		"2.0.0": "shipped in: widget-npm",
	} {
		if s := sourceInfoFor(got, "shared", version); s != want {
			t.Errorf("shared@%s sourceInfo = %q, want %q", version, s, want)
		}
	}
}

// The divergence must be VISIBLE, not merely stored. This is the
// property that keeps it from being demoted to a fact nobody reads:
// the rendered document names both versions and both carriers, which
// is what a consumer greps and what an evidence walk scans.
func TestDivergenceIsVisibleInTheDocument(t *testing.T) {
	t.Parallel()

	got, err := sbom.Union("widget@1.0.0", released, "stele-test", []*sbom.Document{
		doc("widget-cli", [2]string{"shared", "1.0.0"}),
		doc("widget-npm", [2]string{"shared", "2.0.0"}),
	})
	if err != nil {
		t.Fatalf("Union = %v", err)
	}

	for _, want := range []string{"1.0.0", "2.0.0", "widget-cli", "widget-npm"} {
		found := false

		for _, p := range got.Packages {
			if strings.Contains(p.VersionInfo, want) || strings.Contains(p.SourceInfo, want) {
				found = true

				break
			}
		}

		if !found {
			t.Errorf("the rendered document hides %q", want)
		}
	}
}

// An input's own SourceInfo describes its platform legs and says
// nothing about which artifacts ship it. Carrying it through would
// make the view claim a scope it never computed.
func TestUnionRebuildsSourceInfo(t *testing.T) {
	t.Parallel()

	got, err := sbom.Union("widget@1.0.0", released, "stele-test", []*sbom.Document{
		doc("widget-cli", [2]string{"shared", "1.0.0"}),
		doc("widget-npm", [2]string{"shared", "1.0.0"}),
	})
	if err != nil {
		t.Fatalf("Union = %v", err)
	}

	for _, p := range got.Packages {
		if strings.Contains(p.SourceInfo, "linked into") {
			t.Errorf("an input's platform scope leaked into the view: %q", p.SourceInfo)
		}
	}
}

// One set of inputs renders one document, whatever order they arrive
// in — the view is attested, so it has to be reproducible.
func TestUnionIsOrderIndependent(t *testing.T) {
	t.Parallel()

	a := doc("widget-cli", [2]string{"z", "1"}, [2]string{"a", "1"})
	b := doc("widget-npm", [2]string{"m", "1"})

	forward, err := sbom.Union("w", released, "t", []*sbom.Document{a, b})
	if err != nil {
		t.Fatal(err)
	}

	reversed, err := sbom.Union("w", released, "t", []*sbom.Document{b, a})
	if err != nil {
		t.Fatal(err)
	}

	if len(forward.Packages) != len(reversed.Packages) {
		t.Fatalf("package counts differ: %d vs %d", len(forward.Packages), len(reversed.Packages))
	}

	for i := range forward.Packages {
		if forward.Packages[i].Name != reversed.Packages[i].Name {
			t.Fatalf("package %d differs: %q vs %q", i, forward.Packages[i].Name, reversed.Packages[i].Name)
		}
	}
}

func TestUnionRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		created  string
		docs     []*sbom.Document
		wantText string
	}{
		{"nothing to aggregate", released, nil, "no documents"},
		{"no release instant", "", []*sbom.Document{doc("a")}, "release instant"},
		{"a nil document", released, []*sbom.Document{nil}, "describes nothing"},
		{"a document with no packages", released, []*sbom.Document{{}}, "describes nothing"},
		{
			"a document with no DESCRIBES", released,
			[]*sbom.Document{{Packages: []sbom.Package{{SPDXID: "SPDXRef-Package-0", Name: "a"}}}},
			"no DESCRIBES relationship",
		},
		{
			"a document describing two artifacts", released,
			[]*sbom.Document{func() *sbom.Document {
				d := doc("a", [2]string{"b", "1"})
				d.Relationships = append(d.Relationships, sbom.Relationship{
					SPDXElementID: "SPDXRef-DOCUMENT", RelatedSPDXElement: "SPDXRef-Package-1",
					RelationshipType: "DESCRIBES",
				})

				return d
			}()},
			"more than one DESCRIBES",
		},
		{
			"a DESCRIBES naming a package that is not there", released,
			[]*sbom.Document{func() *sbom.Document {
				d := doc("a")
				d.Relationships[0].RelatedSPDXElement = "SPDXRef-Package-99"

				return d
			}()},
			"not among its packages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := sbom.Union("w", tt.created, "t", tt.docs)
			if err == nil || !strings.Contains(err.Error(), tt.wantText) {
				t.Fatalf("Union = %v, want it to mention %q", err, tt.wantText)
			}
		})
	}
}

// An artifact shipping nothing is legal: the view records it as a
// carrier of no packages rather than refusing a release that
// genuinely has one.
func TestUnionAcceptsAnEmptyArtifact(t *testing.T) {
	t.Parallel()

	got, err := sbom.Union("w", released, "t", []*sbom.Document{
		doc("empty"), doc("full", [2]string{"a", "1"}),
	})
	if err != nil {
		t.Fatalf("Union = %v", err)
	}

	if s := sourceInfoFor(got, "a", "1"); s != "shipped in: full" {
		t.Errorf("sourceInfo = %q", s)
	}
}
