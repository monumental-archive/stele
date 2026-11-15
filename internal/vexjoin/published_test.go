// The published reading (stele#356): a release's VEX names the shipped
// artifact as its product and decides the dependency inside it, so the
// level join must read the component each statement DECIDES.
//
// The fixture is edtf v1.3.4's published asset
// edtf-1.3.4.vex.openvex.json, byte for byte as the release carries it
// — not a hand-written approximation of its shape. It is one JSON value
// and a newline, so it carries the .jsonl extension: evidence is kept
// out of the formatter, which would rewrite it (the seed-corpus rule).

package vexjoin_test

import (
	_ "embed"
	"testing"

	"github.com/monumental-archive/stele/internal/vexjoin"
)

//go:embed testdata/edtf-1.3.4.vex.openvex.jsonl
var edtfPublished []byte

// serdeFinding is the key the scanner mints for the finding edtf's
// release decides: OSV reports the crate under "crates.io".
func serdeFinding() vexjoin.Key {
	return vexjoin.KeyFromFinding("RUSTSEC-2021-0127", "crates.io", "serde_cbor", "0.11.2")
}

// TestSourceParseMissesThePublishedShape records the defect as
// measured: through the source reading, the published document decides
// nothing for the finding it was written for.
func TestSourceParseMissesThePublishedShape(t *testing.T) {
	t.Parallel()

	d := &vexjoin.Decisions{}
	if err := vexjoin.Parse(d, edtfPublished, "edtf-1.3.4.vex.openvex.json"); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if d.Has(serdeFinding()) {
		t.Fatal("Has = true: the defect this test records is fixed — flip it to the published reading")
	}
}
