// The join's empty-set laws, tested by name: an empty decided set
// decides nothing (never everything — the grep -f landmine), the
// join key is the exact triple (a version bump misses), and a
// statement missing what the join needs refuses.

package vexjoin_test

import (
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
