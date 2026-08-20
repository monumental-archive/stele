// The join's empty-set laws, tested by name: an empty decided set
// decides nothing (never everything — the grep -f landmine), the
// join key is the exact triple (a version bump misses), and a
// statement missing what the join needs refuses.
//
// And the case rule (docs/vex-join.md): a golang purl name compares
// case-insensitively, everything else compares as it arrived.

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

	if !d.Has(vexjoin.KeyFromFinding("RUSTSEC-2021-0127", "crates.io", "serde_cbor", "0.11.2")) {
		t.Fatal("the exact triple is not decided")
	}

	// The per-version join is the drift guard by construction: a
	// bumped version matches no decision.
	if d.Has(vexjoin.KeyFromFinding("RUSTSEC-2021-0127", "crates.io", "serde_cbor", "0.11.3")) {
		t.Fatal("a bumped version must not inherit the old judgment")
	}

	if d.Has(vexjoin.KeyFromFinding("RUSTSEC-2099-9999", "crates.io", "serde_cbor", "0.11.2")) {
		t.Fatal("another advisory must not match")
	}
}

func TestEmptySetDecidesNothing(t *testing.T) {
	t.Parallel()

	var d *vexjoin.Decisions // nil: no VEX directory at all

	if d.Has(vexjoin.KeyFromFinding("X", "crates.io", "p", "1")) {
		t.Fatal("a nil decided set decided something")
	}

	empty := &vexjoin.Decisions{}
	if empty.Has(vexjoin.KeyFromFinding("X", "crates.io", "p", "1")) || empty.Len() != 0 {
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

	sibling := vexjoin.KeyFromFinding("CVE-2026-0001", "crates.io", "serde_cbor", "0.11.2")
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
		purl      string
		ecosystem string
		pkg       string
		version   string
		joins     bool
	}{
		{
			purl: "pkg:golang/example.com/dep@v1.0.0", ecosystem: "Go",
			pkg: "example.com/dep", version: "v1.0.0", joins: true,
		},
		{
			purl: "pkg:golang/github.com/Masterminds/semver/v3@v3.5.0", ecosystem: "Go",
			pkg: "github.com/Masterminds/semver/v3", version: "v3.5.0", joins: true,
		},
		{
			// The shape the org's own decisions use: one segment, so
			// the narrower reading gave the same answer.
			purl: "pkg:cargo/serde_cbor@0.11.2", ecosystem: "crates.io",
			pkg: "serde_cbor", version: "0.11.2", joins: true,
		},
		{
			// An npm scoped name opens with @, so cutting at the FIRST
			// one would split the name in half.
			purl: "pkg:npm/%40scope/pkg@1.0.0", ecosystem: "npm",
			pkg: "@scope/pkg", version: "1.0.0", joins: true,
		},
		{
			// Qualifiers and subpath are not part of the identity.
			purl: "pkg:golang/example.com/dep@v1.0.0?type=module#sub", ecosystem: "Go",
			pkg: "example.com/dep", version: "v1.0.0", joins: true,
		},
		{purl: "pkg:golang/example.com/dep", ecosystem: "Go", joins: false},
		{purl: "example.com/dep@v1.0.0", ecosystem: "Go", joins: false},
		{purl: "pkg:golang/@v1.0.0", ecosystem: "Go", joins: false},
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

		got := d.Has(vexjoin.KeyFromFinding("GHSA-xxxx", tt.ecosystem, tt.pkg, tt.version))
		if got != tt.joins {
			t.Errorf("%s: decided(%q, %q) = %v, want %v", tt.purl, tt.pkg, tt.version, got, tt.joins)
		}

		if !tt.joins && d.Len() != 0 {
			t.Errorf("%s: an unjoinable product decided something: %d", tt.purl, d.Len())
		}
	}
}

// decide renders one OpenVEX document deciding a single product, the
// shape parse demands since #124 (a statement carries its judgment
// and the moment it was made).
func decide(purl string) []byte {
	return []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","timestamp":"2026-08-20T00:00:00Z",` +
		`"statements":[{"vulnerability":{"name":"GO-2026-0001"},` +
		`"products":[{"@id":"` + purl + `"}],"status":"not_affected",` +
		`"justification":"vulnerable_code_not_present"}]}`)
}

// TestGolangNamesCaseFold is the regression for a join that silently
// missed, the second of its kind on this key.
//
// The SBOM emitter mints golang purls in the purl type's canonical
// form — lowercased — while govulncheck reports the module path as
// written. A decision authored the natural way, by copying the
// product purl out of the published SBOM where the affected inventory
// is read, therefore carried a name the finding never matched: for a
// mixed-case module the decision excused nothing, silently. The
// producer is spec-conformant, so the join is what moves.
//
// The rows below are the real pairing, both directions: the purl a
// stele SBOM publishes for this repository's own mixed-case
// dependency, and the module path its scanner reports.
func TestGolangNamesCaseFold(t *testing.T) {
	t.Parallel()

	const (
		// Copied from the shape `derive sbom` emits for this
		// repository's own graph: github.com/Masterminds/semver/v3.
		published = "pkg:golang/github.com/masterminds/semver/v3@v3.5.0"
		module    = "github.com/Masterminds/semver/v3"
	)

	for _, tt := range []struct {
		name  string
		purl  string
		pkg   string
		joins bool
	}{
		{
			name: "the published purl joins the module path it was minted from",
			purl: published, pkg: module, joins: true,
		},
		{
			name: "a decision written in the module's own case still joins",
			purl: "pkg:golang/" + module + "@v3.5.0", pkg: module, joins: true,
		},
		{
			// The direction the org's graphs are in today, which is why
			// the defect was latent: nothing to fold, nothing to break.
			name: "an all-lowercase module is unchanged",
			purl: "pkg:golang/example.com/dep@v3.5.0", pkg: "example.com/dep", joins: true,
		},
		{
			name: "folding is the name's alone — a different module does not join",
			purl: published, pkg: "github.com/masterminds/semver/v4", joins: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := &vexjoin.Decisions{}
			if err := vexjoin.Parse(d, decide(tt.purl), "semver.openvex.json"); err != nil {
				t.Fatalf("Parse: %v", err)
			}

			if got := d.Has(vexjoin.KeyFromFinding("GO-2026-0001", "Go", tt.pkg, "v3.5.0")); got != tt.joins {
				t.Errorf("%s joined by %s = %v, want %v", tt.pkg, tt.purl, got, tt.joins)
			}
		})
	}
}

// TestVersionsAndOtherFieldsDoNotFold holds the rule's edges. Only the
// NAME folds, and only for a type whose spec declares it: a version
// is opaque to purl's case rules, and an advisory identifier is
// nobody's package name.
func TestVersionsAndOtherFieldsDoNotFold(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name      string
		purl      string
		ecosystem string
		pkg       string
		version   string
		joins     bool
	}{
		{
			// Go's own version vocabulary is case-sensitive: v1.0.0-RC1
			// and v1.0.0-rc1 are different prereleases of one module.
			name: "a golang version keeps its case",
			purl: "pkg:golang/example.com/dep@v1.0.0-RC1", ecosystem: "Go",
			pkg: "example.com/dep", version: "v1.0.0-rc1", joins: false,
		},
		{
			name: "the same version, unfolded, still joins",
			purl: "pkg:golang/example.com/dep@v1.0.0-RC1", ecosystem: "Go",
			pkg: "example.com/dep", version: "v1.0.0-RC1", joins: true,
		},
		{
			// purl declares names case-sensitive unless the type says
			// otherwise, and cargo does not. These are the org's own
			// decisions' type, so the narrow rule is load-bearing here
			// rather than hypothetical.
			name: "a cargo name does not fold",
			purl: "pkg:cargo/Serde_CBOR@0.11.2", ecosystem: "crates.io",
			pkg: "serde_cbor", version: "0.11.2", joins: false,
		},
		{
			name: "a cargo name matching exactly joins",
			purl: "pkg:cargo/serde_cbor@0.11.2", ecosystem: "crates.io",
			pkg: "serde_cbor", version: "0.11.2", joins: true,
		},
		{
			// The ecosystem label decides, not the name's shape: the
			// same string folds under Go and does not under cargo.
			name: "one name, two ecosystems, two answers",
			purl: "pkg:cargo/Mixed/Case@1.0", ecosystem: "crates.io",
			pkg: "mixed/case", version: "1.0", joins: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := &vexjoin.Decisions{}
			if err := vexjoin.Parse(d, decide(tt.purl), "x.openvex.json"); err != nil {
				t.Fatalf("Parse: %v", err)
			}

			got := d.Has(vexjoin.KeyFromFinding("GO-2026-0001", tt.ecosystem, tt.pkg, tt.version))
			if got != tt.joins {
				t.Errorf("decided(%q, %q, %q) = %v, want %v", tt.ecosystem, tt.pkg, tt.version, got, tt.joins)
			}
		})
	}
}

// TestFindingSideFoldsOnItsOwnVocabulary pins the alias the two sides
// need: a decision names the purl TYPE, a scanner finding names the
// OSV ECOSYSTEM, and one ecosystem answering to two labels must fold
// the same either way — otherwise the join agrees with itself only by
// accident of which side is asked.
func TestFindingSideFoldsOnItsOwnVocabulary(t *testing.T) {
	t.Parallel()

	d := &vexjoin.Decisions{}
	if err := vexjoin.Parse(d, decide("pkg:golang/example.com/Dep@v1.0.0"), "x.json"); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// "Go" is what OSV reports; "golang" is the purl type; a scanner
	// speaking either names the same ecosystem.
	for _, ecosystem := range []string{"Go", "go", "golang"} {
		if !d.Has(vexjoin.KeyFromFinding("GO-2026-0001", ecosystem, "example.com/dep", "v1.0.0")) {
			t.Errorf("ecosystem %q did not fold", ecosystem)
		}
	}

	// An ecosystem the rule does not name folds nothing — the safe
	// direction, and the reason an unread spec cannot quietly widen
	// the join. The finding's name is the one needing the fold here,
	// so an unfolded side cannot reach the decision's canonical form.
	if d.Has(vexjoin.KeyFromFinding("GO-2026-0001", "unheard-of", "example.com/Dep", "v1.0.0")) {
		t.Error("an ecosystem with no written rule folded anyway")
	}
}

// TestKeyRendersTheCanonicalName holds what a report ID means: the
// spelling a decision must use to join the finding, which is the
// purl name — so an ID read out of a report can be pasted into a
// decision. The module's own case is the FINDING's to carry, not the
// key's (internal/triage's Finding.Package).
func TestKeyRendersTheCanonicalName(t *testing.T) {
	t.Parallel()

	k := vexjoin.KeyFromFinding("GO-2026-0001", "Go", "github.com/Masterminds/semver/v3", "v3.5.0")

	if got, want := k.Package(), "github.com/masterminds/semver/v3"; got != want {
		t.Errorf("Package() = %q, want %q", got, want)
	}

	if got, want := k.String(), "GO-2026-0001:github.com/masterminds/semver/v3@v3.5.0"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	if got, want := k.Version(), "v3.5.0"; got != want {
		t.Errorf("Version() = %q, want %q", got, want)
	}
}

// TestDecisionsDifferingOnlyInCaseCollide is the fold's consequence
// for the duplicate law: two statements naming one module in two
// spellings are two judgments on ONE finding, so directory order
// would decide which enters signed evidence. Before the fold they
// were two triples and both were kept; now the parse refuses and
// names both origins.
func TestDecisionsDifferingOnlyInCaseCollide(t *testing.T) {
	t.Parallel()

	d := &vexjoin.Decisions{}
	if err := vexjoin.Parse(d, decide("pkg:golang/example.com/Dep@v1.0.0"), "first.openvex.json"); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	err := vexjoin.Parse(d, decide("pkg:golang/example.com/dep@v1.0.0"), "second.openvex.json")
	if err == nil {
		t.Fatal("two spellings of one module were both kept — one finding, one decision")
	}

	for _, want := range []string{"first.openvex.json", "second.openvex.json", "example.com/dep"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}
