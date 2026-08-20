// The renderer, row by row. The property that matters most has its
// own test: one set of inputs renders one set of BYTES, because the
// document is attested and an attested artifact nobody can reproduce
// cannot be checked by anyone.

package vex_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/vex"
)

func released() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) }
func decided() time.Time  { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }

func opts() vex.Options {
	return vex.Options{ID: "https://example.test/vex/widget-1.0.0", Author: "acme", Released: released()}
}

func coverage() []vex.Coverage {
	return []vex.Coverage{{
		Product:       "pkg:github/acme/widget@v1.0.0",
		Subcomponent:  "pkg:npm/left-pad@1.0.0",
		Advisory:      "CVE-1",
		Status:        "not_affected",
		Justification: "vulnerable_code_not_present",
		Decided:       decided(),
	}}
}

func render(t *testing.T, c []vex.Coverage) string {
	t.Helper()

	complete, err := vex.Cover(c, nil)
	if err != nil {
		t.Fatalf("Cover = %v", err)
	}

	doc, err := vex.Render(opts(), complete)
	if err != nil {
		t.Fatalf("Render = %v", err)
	}

	var buf bytes.Buffer
	if err := doc.Encode(&buf); err != nil {
		t.Fatalf("Encode = %v", err)
	}

	return buf.String()
}

func TestRender(t *testing.T) {
	t.Parallel()

	got := render(t, coverage())

	for _, want := range []string{
		`"@context":"` + vex.Context + `"`,
		`"@id":"https://example.test/vex/widget-1.0.0"`,
		`"author":"acme"`,
		`"version":1`,
		// The document is dated by the RELEASE it describes.
		`"timestamp":"2026-08-18T12:00:00Z"`,
		`"vulnerability":{"name":"CVE-1"}`,
		// The statement is dated by the JUDGMENT, not by this run.
		`"timestamp":"2026-01-02T03:04:05Z"`,
		`"@id":"pkg:github/acme/widget@v1.0.0"`,
		`"subcomponents":[{"@id":"pkg:npm/left-pad@1.0.0"}]`,
		`"status":"not_affected"`,
		`"justification":"vulnerable_code_not_present"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("document lacks %s:\n%s", want, got)
		}
	}

	// Absent optional statements are omitted rather than emitted empty.
	for _, absent := range []string{"impact_statement", "action_statement"} {
		if strings.Contains(got, absent) {
			t.Errorf("document carries an empty %s:\n%s", absent, got)
		}
	}
}

// The whole point of carrying the decision's own moment: the same
// inputs render the same bytes, every time.
func TestRenderIsReproducible(t *testing.T) {
	t.Parallel()

	first := render(t, coverage())

	time.Sleep(2 * time.Millisecond)

	if second := render(t, coverage()); first != second {
		t.Fatalf("two renders differ:\n%s\n%s", first, second)
	}
}

// Statement order is derived, not incidental: coverage arriving in any
// order renders one document.
func TestRenderOrdersAndDeduplicates(t *testing.T) {
	t.Parallel()

	a := vex.Coverage{
		Product: "pkg:github/acme/widget@v1", Subcomponent: "pkg:npm/a@1",
		Advisory: "CVE-1", Status: "not_affected", Decided: decided(),
	}
	b := vex.Coverage{
		Product: "pkg:github/acme/widget@v1", Subcomponent: "pkg:npm/b@1",
		Advisory: "CVE-2", Status: "affected", ActionStatement: "upgrade", Decided: decided(),
	}

	forward := render(t, []vex.Coverage{a, b})
	if reversed := render(t, []vex.Coverage{b, a, a}); forward != reversed {
		t.Fatalf("order or duplication changed the document:\n%s\n%s", forward, reversed)
	}

	if strings.Index(forward, "CVE-1") > strings.Index(forward, "CVE-2") {
		t.Errorf("statements are not ordered by advisory:\n%s", forward)
	}
}

// One advisory reaching several products is the ordinary shape, not a
// corner: a CVE in a shared dependency touches every artifact that
// links it, and each lands as its own statement. Advisory name alone
// therefore does not order the document — the product, and then the
// subcomponent, have to finish the job, or two statements stay
// interchangeable and the rendered bytes wander between runs.
func TestRenderOrdersStatementsSharingOneAdvisory(t *testing.T) {
	t.Parallel()

	// Deliberately supplied worst-first, and the two rows sharing a
	// product differ ONLY in subcomponent, so a comparator stopping at
	// the product leaves them tied.
	rows := []vex.Coverage{
		{
			Product: "pkg:github/acme/widget@v1", Subcomponent: "pkg:npm/zlib@1",
			Advisory: "CVE-1", Status: "not_affected", Decided: decided(),
		},
		{
			Product:  "pkg:github/acme/gadget@v1",
			Advisory: "CVE-1", Status: "affected", ActionStatement: "upgrade", Decided: decided(),
		},
		{
			Product: "pkg:github/acme/widget@v1", Subcomponent: "pkg:npm/apple@1",
			Advisory: "CVE-1", Status: "not_affected", Decided: decided(),
		},
	}

	got := render(t, rows)

	gadget := strings.Index(got, "gadget")
	apple := strings.Index(got, "apple")
	zlib := strings.Index(got, "zlib")

	if gadget >= apple || apple >= zlib {
		t.Errorf("statements sharing CVE-1 are not ordered by product then subcomponent:\n%s", got)
	}

	// And the order is a function of the inputs, not of their arrival.
	if reversed := render(t, []vex.Coverage{rows[2], rows[0], rows[1]}); reversed != got {
		t.Errorf("arrival order changed the document:\n%s\n%s", got, reversed)
	}
}

// TestEncodeWriteFailure: the document is written to a file the
// release depends on, and a write that half-succeeds must be reported.
// A truncated VEX document is a triage surface with statements
// silently missing from it.
func TestEncodeWriteFailure(t *testing.T) {
	t.Parallel()

	complete, err := vex.Cover(coverage(), nil)
	if err != nil {
		t.Fatalf("Cover = %v", err)
	}

	doc, err := vex.Render(opts(), complete)
	if err != nil {
		t.Fatalf("Render = %v", err)
	}

	if err := doc.Encode(failWriter{}); err == nil {
		t.Fatal("Encode to a failing writer succeeded, want error")
	}
}

// failWriter is a sink that always tears.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("sink closed") }

// A subcomponent-less coverage is legal: the judgment concerns the
// product itself.
func TestRenderWithoutSubcomponent(t *testing.T) {
	t.Parallel()

	c := coverage()
	c[0].Subcomponent = ""

	if got := render(t, c); strings.Contains(got, "subcomponents") {
		t.Errorf("an absent subcomponent was emitted:\n%s", got)
	}
}

// Nothing to say is the ordinary outcome, named so a caller can treat
// it as one rather than as a failure.
func TestNoCoverage(t *testing.T) {
	t.Parallel()

	empty, err := vex.Cover(nil, nil)
	if err != nil {
		t.Fatalf("Cover = %v", err)
	}

	if _, err := vex.Render(opts(), empty); !errors.Is(err, vex.ErrNoCoverage) {
		t.Fatalf("Render = %v, want ErrNoCoverage", err)
	}
}

// The refusal is a TYPE, not a branch: Render takes only a sealed
// set, so no caller — this one or a later one — can produce a
// coverage document beside untriaged findings.
func TestCoverRefusesUndecided(t *testing.T) {
	t.Parallel()

	_, err := vex.Cover(coverage(), []string{"CVE-9:x@1"})
	if err == nil {
		t.Fatal("Cover sealed a set with an undecided finding")
	}

	for _, want := range []string{"no recorded decision", "CVE-9:x@1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Cover = %v, want it to mention %q", err, want)
		}
	}

	if _, err := vex.Render(opts(), nil); err == nil {
		t.Fatal("Render accepted nothing sealed")
	}
}

func TestRenderRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*vex.Options)
		cover   func(*vex.Coverage)
		wantMsg string
	}{
		{
			name:    "no document id",
			mutate:  func(o *vex.Options) { o.ID = "" },
			wantMsg: "document id is required",
		},
		{
			name:    "no author",
			mutate:  func(o *vex.Options) { o.Author = "" },
			wantMsg: "an author is required",
		},
		{
			name:    "no release instant",
			mutate:  func(o *vex.Options) { o.Released = time.Time{} },
			wantMsg: "not reproducible",
		},
		{
			name:    "a statement naming no advisory",
			cover:   func(c *vex.Coverage) { c.Advisory = "" },
			wantMsg: "names no vulnerability",
		},
		{
			name:    "a statement naming no product",
			cover:   func(c *vex.Coverage) { c.Product = "" },
			wantMsg: "names no product",
		},
		{
			name:    "a statement carrying no status",
			cover:   func(c *vex.Coverage) { c.Status = "" },
			wantMsg: "carries no status",
		},
		{
			name:    "a statement with no decision moment",
			cover:   func(c *vex.Coverage) { c.Decided = time.Time{} },
			wantMsg: "asserts a judgment nobody made then",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			o := opts()
			if tt.mutate != nil {
				tt.mutate(&o)
			}

			c := coverage()
			if tt.cover != nil {
				tt.cover(&c[0])
			}

			complete, cerr := vex.Cover(c, nil)
			if cerr != nil {
				t.Fatalf("Cover = %v", cerr)
			}

			_, err := vex.Render(o, complete)
			if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("Render = %v, want it to mention %q", err, tt.wantMsg)
			}
		})
	}
}
