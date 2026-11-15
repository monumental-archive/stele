// The published reading (stele#356): a release's VEX names the shipped
// artifact as its product and decides the dependency inside it, so the
// join reads the component each statement DECIDES — the subcomponent
// when the product carries any, the product when it carries none
// (docs/vex-join.md, rule 1).
//
// The fixture is edtf v1.3.4's published asset
// edtf-1.3.4.vex.openvex.json, byte for byte as the release carries it
// — not a hand-written approximation of its shape. It is one JSON value
// and a newline, so it carries the .jsonl extension: evidence is kept
// out of the formatter, which would rewrite it (the seed-corpus rule).

package vexjoin_test

import (
	_ "embed"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/vexjoin"
)

//go:embed testdata/edtf-1.3.4.vex.openvex.jsonl
var edtfPublished []byte

const edtfOrigin = "edtf-1.3.4.vex.openvex.json"

// serdeFinding is the key the scanner mints for the finding edtf's
// release decides: OSV reports the crate under "crates.io".
func serdeFinding() vexjoin.Key {
	return vexjoin.KeyFromFinding("RUSTSEC-2021-0127", "crates.io", "serde_cbor", "0.11.2")
}

// TestPublishedReadingDecidesTheSubcomponent: the real published
// document, six statements repeating one decision once per shipped
// product, decides the one triple it was written for — without error
// and with nothing it could not read.
func TestPublishedReadingDecidesTheSubcomponent(t *testing.T) {
	t.Parallel()

	d := &vexjoin.Decisions{}

	unjoinable, err := vexjoin.ParsePublished(d, edtfPublished, edtfOrigin)
	if err != nil {
		t.Fatalf("ParsePublished = %v — one triple stated six times is one decided triple", err)
	}

	if len(unjoinable) != 0 {
		t.Fatalf("unjoinable = %v, want none: every statement decides a versioned purl", unjoinable)
	}

	if !d.Has(serdeFinding()) {
		t.Fatal("the published document does not decide RUSTSEC-2021-0127 on serde_cbor@0.11.2")
	}

	if d.Len() != 1 {
		t.Fatalf("Len = %d, want 1 — the products are shipped artifacts, not decided components", d.Len())
	}

	got, _ := d.Get(serdeFinding())
	if got.Purl != "pkg:cargo/serde_cbor@0.11.2" || got.Origin != edtfOrigin || got.PurlType() != "cargo" {
		t.Errorf("decision = purl %q origin %q type %q, want the subcomponent's purl from %s",
			got.Purl, got.Origin, got.PurlType(), edtfOrigin)
	}

	// A second document stating the same triple — the same decisions
	// attested over another digest of one publish — is still one
	// decided triple, not a contradiction.
	if _, err := vexjoin.ParsePublished(d, edtfPublished, "again.openvex.json"); err != nil {
		t.Fatalf("a second published document repeating the triple refused: %v", err)
	}

	if again, _ := d.Get(serdeFinding()); again.Origin != edtfOrigin {
		t.Errorf("origin = %q, want the first document's: a repeat decides nothing new", again.Origin)
	}
}

// TestSourceParseStaysStrictOnThePublishedShape: the source reading
// applies the same rule, so it now SEES the six repeated statements —
// and as source decisions they are six judgments on one finding, which
// it refuses as it always has.
func TestSourceParseStaysStrictOnThePublishedShape(t *testing.T) {
	t.Parallel()

	err := vexjoin.Parse(&vexjoin.Decisions{}, edtfPublished, edtfOrigin)
	if err == nil {
		t.Fatal("Parse accepted one triple decided six times — source decisions are one finding, one decision")
	}

	want := "vexjoin: " + edtfOrigin + " and " + edtfOrigin + " both decide RUSTSEC-2021-0127 on" +
		" serde_cbor@0.11.2 — one finding, one decision; retire one"
	if err.Error() != want {
		t.Errorf("Parse = %q\nwant      %q", err, want)
	}
}

// TestSourceShapeReadsAsPublished: a document whose product IS the
// dependency (no subcomponents) — the hand-written source shape —
// decides its triple through the published reading too.
func TestSourceShapeReadsAsPublished(t *testing.T) {
	t.Parallel()

	d := &vexjoin.Decisions{}

	unjoinable, err := vexjoin.ParsePublished(d, []byte(vexDoc), "serde_cbor.openvex.json")
	if err != nil || len(unjoinable) != 0 {
		t.Fatalf("ParsePublished = %v, unjoinable %v", err, unjoinable)
	}

	if !d.Has(serdeFinding()) {
		t.Fatal("a product with no subcomponents did not decide its own triple")
	}
}

// statementDoc renders one document with one statement whose product
// is given as raw JSON, so each row can shape products freely.
func statementDoc(products string) []byte {
	return []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","timestamp":"2026-08-12T00:00:00Z",` +
		`"statements":[{"vulnerability":{"name":"RUSTSEC-2021-0127"},"status":"not_affected",` +
		`"products":` + products + `}]}`)
}

// TestRuleOneDecidesTheDecidingComponent is rule 1, row by row, through
// BOTH readings: they share it, so they must agree on every row. A
// third party's document in the same OpenVEX shape reads as one `derive
// vex` wrote, whatever its product ids look like.
func TestRuleOneDecidesTheDecidingComponent(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name     string
		products string
		decides  []vexjoin.Key
		misses   []vexjoin.Key
	}{
		{
			name:     "free-text product, purl subcomponent: the subcomponent",
			products: `[{"@id":"edtf-postgres-pg14@1.3.4","subcomponents":[{"@id":"pkg:cargo/serde_cbor@0.11.2"}]}]`,
			decides:  []vexjoin.Key{serdeFinding()},
		},
		{
			// A purl product with subcomponents is an artifact the
			// statement is ABOUT; it decides the subcomponent only.
			name: "purl product, purl subcomponent: the subcomponent, never the product",
			products: `[{"@id":"pkg:oci/widget@sha256%3Aabc","subcomponents":` +
				`[{"@id":"pkg:cargo/serde_cbor@0.11.2"}]}]`,
			decides: []vexjoin.Key{serdeFinding()},
			misses: []vexjoin.Key{
				vexjoin.KeyFromFinding("RUSTSEC-2021-0127", "oci", "widget", "sha256%3Aabc"),
			},
		},
		{
			name:     "product with no @id still decides its subcomponents",
			products: `[{"subcomponents":[{"@id":"pkg:cargo/serde_cbor@0.11.2"}]}]`,
			decides:  []vexjoin.Key{serdeFinding()},
		},
		{
			name: "several subcomponents: each one",
			products: `[{"@id":"app","subcomponents":[{"@id":"pkg:cargo/serde_cbor@0.11.2"},` +
				`{"@id":"pkg:cargo/half@1.8.2"}]}]`,
			decides: []vexjoin.Key{
				serdeFinding(),
				vexjoin.KeyFromFinding("RUSTSEC-2021-0127", "crates.io", "half", "1.8.2"),
			},
		},
		{
			name:     "an id-less subcomponent names nothing and decides nothing",
			products: `[{"@id":"app","subcomponents":[{}]}]`,
		},
	} {
		for _, reading := range []struct {
			name string
			read func(*vexjoin.Decisions, []byte) error
		}{
			{"source", func(d *vexjoin.Decisions, doc []byte) error { return vexjoin.Parse(d, doc, "x") }},
			{"published", func(d *vexjoin.Decisions, doc []byte) error {
				u, err := vexjoin.ParsePublished(d, doc, "x")
				if len(u) != 0 {
					t.Errorf("%s: unjoinable %v, want none", tt.name, u)
				}

				return err
			}},
		} {
			d := &vexjoin.Decisions{}
			if err := reading.read(d, statementDoc(tt.products)); err != nil {
				t.Fatalf("%s (%s): %v", tt.name, reading.name, err)
			}

			for _, k := range tt.decides {
				if !d.Has(k) {
					t.Errorf("%s (%s): %s not decided", tt.name, reading.name, k)
				}
			}

			for _, k := range tt.misses {
				if d.Has(k) {
					t.Errorf("%s (%s): %s decided — the product is not the deciding component",
						tt.name, reading.name, k)
				}
			}

			if d.Len() != len(tt.decides) {
				t.Errorf("%s (%s): Len = %d, want %d", tt.name, reading.name, d.Len(), len(tt.decides))
			}
		}
	}
}

// TestUnjoinableStatements: a deciding component that is not a
// versioned package URL is RETURNED by the published reading, which
// carries on, and REFUSED by the source reading, naming the statement
// index. Both messages asserted exactly.
func TestUnjoinableStatements(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name      string
		products  string
		logged    string
		refusal   string
		joinsElse bool
	}{
		{
			name:     "a free-text product with no subcomponents",
			products: `[{"@id":"edtf-postgres-pg14@1.3.4"}]`,
			logged:   "doc.json statement 1: product edtf-postgres-pg14@1.3.4 is not a versioned package URL",
			refusal: "vexjoin: doc.json: statement 1: product edtf-postgres-pg14@1.3.4 is not a versioned" +
				" package URL — a decision that joins nothing decides nothing",
		},
		{
			name:     "an unversioned purl product",
			products: `[{"@id":"pkg:cargo/noversion"}]`,
			logged:   "doc.json statement 1: product pkg:cargo/noversion is not a versioned package URL",
			refusal: "vexjoin: doc.json: statement 1: product pkg:cargo/noversion is not a versioned" +
				" package URL — a decision that joins nothing decides nothing",
		},
		{
			name:     "a subcomponent that is not a purl",
			products: `[{"@id":"app","subcomponents":[{"@id":"serde_cbor 0.11.2"}]}]`,
			logged:   "doc.json statement 1: subcomponent serde_cbor 0.11.2 is not a versioned package URL",
			refusal: "vexjoin: doc.json: statement 1: subcomponent serde_cbor 0.11.2 is not a versioned" +
				" package URL — a decision that joins nothing decides nothing",
		},
	} {
		// Statement 0 is joinable; statement 1 carries the row's
		// products, so the index is proven to be the statement's own.
		doc := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","timestamp":"2026-08-12T00:00:00Z",` +
			`"statements":[` +
			`{"vulnerability":{"name":"RUSTSEC-2021-0127"},"status":"not_affected",` +
			`"products":[{"@id":"pkg:cargo/serde_cbor@0.11.2"}]},` +
			`{"vulnerability":{"name":"RUSTSEC-2099-0001"},"status":"not_affected",` +
			`"products":` + tt.products + `}]}`)

		published := &vexjoin.Decisions{}

		unjoinable, err := vexjoin.ParsePublished(published, doc, "doc.json")
		if err != nil {
			t.Fatalf("%s: ParsePublished = %v — an unjoinable statement does not stop the read", tt.name, err)
		}

		if len(unjoinable) != 1 || unjoinable[0].String() != tt.logged {
			t.Errorf("%s: unjoinable = %v\nwant [%s]", tt.name, unjoinable, tt.logged)
		}

		if !published.Has(serdeFinding()) || published.Len() != 1 {
			t.Errorf("%s: the joinable sibling statement was not read (Len %d)", tt.name, published.Len())
		}

		err = vexjoin.Parse(&vexjoin.Decisions{}, doc, "doc.json")
		if err == nil || err.Error() != tt.refusal {
			t.Errorf("%s: Parse = %v\nwant      %s", tt.name, err, tt.refusal)
		}
	}
}

// TestPublishedReadingKeepsTheDocumentRefusals: what makes a statement
// not a decision at all — no vulnerability, no status, no moment — is
// still an error on the published reading; only the deciding
// component's shape is tolerated.
func TestPublishedReadingKeepsTheDocumentRefusals(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		doc  string
		want string
	}{
		{name: "not json", doc: "not json", want: "vexjoin: doc.json: "},
		{
			name: "no vulnerability",
			doc: `{"timestamp":"2026-01-01T00:00:00Z","statements":[{"status":"not_affected",` +
				`"products":[{"@id":"pkg:cargo/a@1"}]}]}`,
			want: "vexjoin: doc.json: statement 0 names no vulnerability",
		},
		{
			name: "no status",
			doc: `{"timestamp":"2026-01-01T00:00:00Z","statements":[{"vulnerability":{"name":"X"},` +
				`"products":[{"@id":"pkg:cargo/a@1"}]}]}`,
			want: "vexjoin: doc.json: statement 0 carries no status — a decision that decides nothing is not a decision",
		},
		{
			name: "no moment",
			doc: `{"statements":[{"vulnerability":{"name":"X"},"status":"not_affected",` +
				`"products":[{"@id":"pkg:cargo/a@1"}]}]}`,
			want: "vexjoin: doc.json: statement 0: no timestamp on the statement or its document",
		},
	} {
		unjoinable, err := vexjoin.ParsePublished(&vexjoin.Decisions{}, []byte(tt.doc), "doc.json")
		if err == nil || !strings.HasPrefix(err.Error(), tt.want) || unjoinable != nil {
			t.Errorf("%s: ParsePublished = %v, %v; want an error starting %q", tt.name, unjoinable, err, tt.want)
		}
	}
}
