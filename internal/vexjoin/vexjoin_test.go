// The join's empty-set laws, tested by name: an empty decided set
// decides nothing (never everything — the grep -f landmine), the
// join key is the exact triple (a version bump misses), and a
// statement missing what the join needs refuses.

package vexjoin_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/vexjoin"
)

const vexDoc = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "timestamp": "2026-01-01T00:00:00Z",
  "statements": [
    {
      "vulnerability": {"name": "RUSTSEC-2021-0127"},
      "products": [{"@id": "pkg:cargo/serde_cbor@0.11.2"}],
      "status": "not_affected"
    }
  ]
}`

func TestParseAndJoin(t *testing.T) {
	t.Parallel()

	d := &vexjoin.Decisions{}
	if err := vexjoin.Parse(d, []byte(vexDoc), "serde_cbor.openvex.json"); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if d.Len() != 1 {
		t.Fatalf("Len = %d, want 1", d.Len())
	}

	exact := vexjoin.Key{Advisory: "RUSTSEC-2021-0127", Package: "serde_cbor", Version: "0.11.2"}
	if !d.Has(exact) {
		t.Fatal("the exact triple is not decided")
	}

	// The per-version join is the drift guard by construction: a
	// bumped version matches no decision.
	bumped := exact
	bumped.Version = "0.11.3"

	if d.Has(bumped) {
		t.Fatal("a bumped version must not inherit the old judgment")
	}

	other := exact
	other.Advisory = "RUSTSEC-2099-9999"

	if d.Has(other) {
		t.Fatal("another advisory must not match")
	}
}

func TestEmptySetDecidesNothing(t *testing.T) {
	t.Parallel()

	var d *vexjoin.Decisions // nil: no VEX directory at all

	if d.Has(vexjoin.Key{Advisory: "X", Package: "p", Version: "1"}) {
		t.Fatal("a nil decided set decided something")
	}

	empty := &vexjoin.Decisions{}
	if empty.Has(vexjoin.Key{Advisory: "X", Package: "p", Version: "1"}) || empty.Len() != 0 {
		t.Fatal("an empty decided set decided something")
	}
}

func TestParseRefusals(t *testing.T) {
	t.Parallel()

	d := &vexjoin.Decisions{}

	if err := vexjoin.Parse(d, []byte("not json"), "x"); err == nil {
		t.Fatal("non-JSON did not refuse")
	}

	noVuln := `{"timestamp": "2026-01-01T00:00:00Z",
	  "statements": [{"products": [{"@id": "pkg:cargo/a@1"}], "status": "not_affected"}]}`
	if err := vexjoin.Parse(d, []byte(noVuln), "x"); err == nil {
		t.Fatal("a statement naming no vulnerability did not refuse")
	}
}

func TestUnversionedProductCannotJoin(t *testing.T) {
	t.Parallel()

	d := &vexjoin.Decisions{}
	doc := `{"timestamp": "2026-01-01T00:00:00Z",
	  "statements": [{"vulnerability": {"name": "X"}, "status": "not_affected",
	   "products": [{"@id": "pkg:cargo/noversion"}], "status": "not_affected"}]}`

	if err := vexjoin.Parse(d, []byte(doc), "x"); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if d.Len() != 0 {
		t.Fatal("an unversioned product joined — the key is the exact triple")
	}
}

func TestAllAndLen(t *testing.T) {
	t.Parallel()

	var nilSet *vexjoin.Decisions
	if nilSet.All() != nil || nilSet.Len() != 0 {
		t.Fatal("a nil set must enumerate nothing")
	}

	d := &vexjoin.Decisions{}
	if err := vexjoin.Parse(d, []byte(vexDoc), "origin.json"); err != nil {
		t.Fatal(err)
	}

	all := d.All()
	if len(all) != 1 || all[0].Origin != "origin.json" {
		t.Fatalf("All = %+v, want the one decision with its origin", all)
	}
}

// TestParseSkipsProductsWithoutID pins the product-side tolerance: a
// statement whose product carries no "@id" names nothing to join, so
// it contributes no decision — and must not abort the document,
// whose other products are still real triage.
func TestParseSkipsProductsWithoutID(t *testing.T) {
	t.Parallel()

	var d vexjoin.Decisions

	doc := []byte(`{"timestamp": "2026-01-01T00:00:00Z",
	  "statements": [{"vulnerability": {"name": "CVE-2026-0001"}, "status": "not_affected",
	  "products": [{}, {"@id": "pkg:cargo/serde_cbor@0.11.2"}]}]}`)

	if err := vexjoin.Parse(&d, doc, "vex.json"); err != nil {
		t.Fatalf("Parse = %v — an id-less product is not a document fault", err)
	}

	sibling := vexjoin.Key{Advisory: "CVE-2026-0001", Package: "serde_cbor", Version: "0.11.2"}
	if !d.Has(sibling) {
		t.Fatal("the sibling product with an @id did not join")
	}

	if n := d.Len(); n != 1 {
		t.Fatalf("Len = %d, want 1 — the id-less product joined nothing", n)
	}
}

// Two decisions for one triple would let directory order pick which
// judgment enters signed evidence; the parse refuses and names both
// origins so a human retires one.
func TestParseRefusesADuplicateDecision(t *testing.T) {
	t.Parallel()

	d := &vexjoin.Decisions{}
	if err := vexjoin.Parse(d, []byte(vexDoc), "first.openvex.json"); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	err := vexjoin.Parse(d, []byte(vexDoc), "second.openvex.json")
	if err == nil {
		t.Fatal("a second decision for the same triple was silently accepted")
	}

	for _, want := range []string{"first.openvex.json", "second.openvex.json", "one finding, one decision"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// TestProductNamesKeepTheirNamespace is the regression for a join that
// silently missed.
//
// The purl name is namespace AND name. Keying on the last path segment
// alone made pkg:golang/example.com/dep decide as "dep", so a decision
// written for a Go module never matched the finding the scanner
// reported for it — every advisory in a Go dependency read as
// undecided, and a blast-radius run would have gone red with no
// explanation a reader could act on. Single-segment ecosystems were
// unaffected, which is why it survived: the org's own decisions are
// Cargo purls, and those key the same either way.
func TestProductNamesKeepTheirNamespace(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		purl    string
		pkg     string
		version string
		joins   bool
	}{
		{
			purl: "pkg:golang/example.com/dep@v1.0.0",
			pkg:  "example.com/dep", version: "v1.0.0", joins: true,
		},
		{
			purl: "pkg:golang/github.com/Masterminds/semver/v3@v3.5.0",
			pkg:  "github.com/Masterminds/semver/v3", version: "v3.5.0", joins: true,
		},
		{
			// The shape the org's own decisions use: one segment, so
			// the narrower reading gave the same answer.
			purl: "pkg:cargo/serde_cbor@0.11.2",
			pkg:  "serde_cbor", version: "0.11.2", joins: true,
		},
		{
			// An npm scoped name opens with @, so cutting at the FIRST
			// one would split the name in half.
			purl: "pkg:npm/%40scope/pkg@1.0.0",
			pkg:  "@scope/pkg", version: "1.0.0", joins: true,
		},
		{
			// Qualifiers and subpath are not part of the identity.
			purl: "pkg:golang/example.com/dep@v1.0.0?type=module#sub",
			pkg:  "example.com/dep", version: "v1.0.0", joins: true,
		},
		{purl: "pkg:golang/example.com/dep", joins: false},
		{purl: "example.com/dep@v1.0.0", joins: false},
		{purl: "pkg:golang/@v1.0.0", joins: false},
	} {
		d := &vexjoin.Decisions{}

		// #124 made a decision carry its timestamp and justification;
		// this document is the shape that parse now demands.
		doc := `{"@context":"https://openvex.dev/ns/v0.2.0","timestamp":"2026-08-12T00:00:00Z",` +
			`"statements":[{"vulnerability":{"name":"GHSA-xxxx"},` +
			`"products":[{"@id":"` + tt.purl + `"}],"status":"not_affected",` +
			`"justification":"vulnerable_code_not_present"}]}`

		if err := vexjoin.Parse(d, []byte(doc), "decisions.openvex.json"); err != nil {
			t.Fatalf("%s: Parse = %v", tt.purl, err)
		}

		got := d.Has(vexjoin.Key{Advisory: "GHSA-xxxx", Package: tt.pkg, Version: tt.version})
		if got != tt.joins {
			t.Errorf("%s: decided(%q, %q) = %v, want %v", tt.purl, tt.pkg, tt.version, got, tt.joins)
		}

		if !tt.joins && d.Len() != 0 {
			t.Errorf("%s: an unjoinable product decided something: %d", tt.purl, d.Len())
		}
	}
}
