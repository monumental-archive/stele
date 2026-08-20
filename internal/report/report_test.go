// Seal is the org's entire green/red boundary in one function, so
// its table is exhaustive over the judgment axes: population state ×
// canary state × finding/exception matching. Every row states which
// law it pins.

package report_test

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/report"
)

func finding(subject, assertion string) report.Finding {
	return report.Finding{Subject: subject, Assertion: assertion, Detail: "detail"}
}

// journal replays a row's findings through the door a walk uses: each
// one is a check that diverged. Rows pinning the coverage rules build
// their own journals — this one is for the verdict axes, where what
// was checked beyond the findings does not bear on the answer.
func journal(findings []report.Finding, exceptions []report.Exception) *report.Journal {
	j := report.NewJournal(exceptions...)

	for _, f := range findings {
		j.Check(f.Subject, f.Assertion).DivergedFrom(f.Expected, f.Actual, f.Detail)
	}

	return j
}

func TestSealVerdicts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pop        report.Population
		findings   []report.Finding
		exceptions []report.Exception
		canary     report.Canary
		want       report.Verdict
	}{
		{
			"clean run over a real population passes",
			report.PopulationFromEvidence(3, "subjects"), nil, nil, report.NoCanary(),
			report.VerdictPass,
		},
		{
			"zero population cannot pass — the walk found nothing to check",
			report.PopulationFromEvidence(0, "subjects"), nil, nil, report.NoCanary(),
			report.VerdictCannotJudge,
		},
		{
			"negative population is a defect, judged as no coverage",
			report.PopulationFromEvidence(-1, "subjects"), nil, nil, report.NoCanary(),
			report.VerdictCannotJudge,
		},
		{
			"zero population with findings is still cannot-judge — partial sight is not a verdict",
			report.PopulationFromEvidence(0, "subjects"),
			[]report.Finding{finding("a", "x")},
			nil, report.NoCanary(),
			report.VerdictCannotJudge,
		},
		{
			"declared population matched passes",
			report.PopulationAgainstDeclared(4, 4, "repos"), nil, nil, report.NoCanary(),
			report.VerdictPass,
		},
		{
			"declared population short means an unseen subject is unchecked, not clean",
			report.PopulationAgainstDeclared(3, 4, "repos"), nil, nil, report.NoCanary(),
			report.VerdictCannotJudge,
		},
		{
			"declared population exceeded means the declaration is stale",
			report.PopulationAgainstDeclared(5, 4, "repos"), nil, nil, report.NoCanary(),
			report.VerdictCannotJudge,
		},
		{
			"listing population passes like evidence",
			report.PopulationFromListing(2, "org repos"), nil, nil, report.NoCanary(),
			report.VerdictPass,
		},
		{
			"an unexcused finding fails",
			report.PopulationFromEvidence(3, "subjects"),
			[]report.Finding{finding("a", "x")},
			nil, report.NoCanary(),
			report.VerdictFail,
		},
		{
			"a declared exception excuses its exact finding",
			report.PopulationFromEvidence(3, "subjects"),
			[]report.Finding{finding("a", "x")},
			[]report.Exception{report.Declared("a", "x", "debt.txt:3")},
			report.NoCanary(),
			report.VerdictPass,
		},
		{
			"a subject-wide exception excuses every assertion on the subject",
			report.PopulationFromEvidence(3, "subjects"),
			[]report.Finding{finding("a", "x"), finding("a", "y")},
			[]report.Exception{report.Declared("a", "", "debt.txt:3")},
			report.NoCanary(),
			report.VerdictPass,
		},
		{
			"an exception for another subject excuses nothing",
			report.PopulationFromEvidence(3, "subjects"),
			[]report.Finding{finding("a", "x")},
			[]report.Exception{report.Declared("b", "x", "debt.txt:3")},
			report.NoCanary(),
			report.VerdictFail,
		},
		{
			"an exception for another assertion excuses nothing",
			report.PopulationFromEvidence(3, "subjects"),
			[]report.Finding{finding("a", "x")},
			[]report.Exception{report.Declared("a", "y", "debt.txt:3")},
			report.NoCanary(),
			report.VerdictFail,
		},
		{
			"a derived exception excuses like a declared one",
			report.PopulationFromEvidence(3, "subjects"),
			[]report.Finding{finding("a", "x")},
			[]report.Exception{report.Derived("a", "x", "run history: publish failed")},
			report.NoCanary(),
			report.VerdictPass,
		},
		{
			"one exception cannot excuse two subjects",
			report.PopulationFromEvidence(3, "subjects"),
			[]report.Finding{finding("a", "x"), finding("b", "x")},
			[]report.Exception{report.Declared("a", "x", "debt.txt:3")},
			report.NoCanary(),
			report.VerdictFail,
		},
		{
			"a seen canary keeps a clean pass",
			report.PopulationFromEvidence(3, "subjects"), nil, nil, report.CanarySeen("RUSTSEC-2021-0127"),
			report.VerdictPass,
		},
		{
			"a missed canary means the walk cannot see — never pass",
			report.PopulationFromEvidence(3, "subjects"), nil, nil, report.CanaryMissed("RUSTSEC-2021-0127"),
			report.VerdictCannotJudge,
		},
		{
			"a missed canary outranks findings — cannot-judge, not fail",
			report.PopulationFromEvidence(3, "subjects"),
			[]report.Finding{finding("a", "x")},
			nil,
			report.CanaryMissed("RUSTSEC-2021-0127"),
			report.VerdictCannotJudge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := report.Seal("test", "acme/widget", tt.pop,
				journal(tt.findings, tt.exceptions), tt.canary, report.NoJudgedSet())
			if got := r.Verdict(); got != tt.want {
				t.Fatalf("verdict = %s, want %s", got, tt.want)
			}

			if r.Passed() != (tt.want == report.VerdictPass) {
				t.Fatalf("Passed() disagrees with verdict %s", tt.want)
			}
		})
	}
}

// TestSealSortsUnmatchedExceptionsByCoverage pins #147's rule: what
// an unmatched excuse is called follows from what the run could SEE.
// The check ran and was clean → stale, a retirement candidate. The
// check never ran here → unexercised, and this run says nothing about
// it. Calling the second one stale would be a retirement claim made
// without evidence — the population law's defect, one level down.
func TestSealSortsUnmatchedExceptionsByCoverage(t *testing.T) {
	t.Parallel()

	j := report.NewJournal(
		report.Declared("a", "x", "debt.txt:3"),       // matched below: excused
		report.Declared("a", "y", "debt.txt:5"),       // checked, clean: stale
		report.Declared("gone", "y", "debt.txt:9"),    // never checked: unexercised
		report.Declared("a", "", "debt.txt:11"),       // subject-wide: it too answers the a/x finding
		report.Declared("nowhere", "", "debt.txt:13"), // subject-wide over a subject nobody checked
	)

	j.Check("a", "x").Diverged("detail")
	j.Check("a", "y")

	r := report.Seal("test", "acme/widget", report.PopulationFromEvidence(2, "subjects"),
		j, report.NoCanary(), report.NoJudgedSet())

	if got := r.Verdict(); got != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS — neither bucket is a failure", got)
	}

	var buf bytes.Buffer
	if err := r.Encode(&buf); err != nil {
		t.Fatalf("encode: %v", err)
	}

	doc := decodeDoc(t, buf.Bytes())

	stale := origins(doc.Stale)
	if len(stale) != 1 || stale[0] != "debt.txt:5" {
		t.Fatalf("staleExceptions = %v, want the one whose check ran clean and matched nothing", stale)
	}

	unexercised := origins(doc.Unexercised)
	if len(unexercised) != 2 || unexercised[0] != "debt.txt:9" || unexercised[1] != "debt.txt:13" {
		t.Fatalf("unexercisedExceptions = %v, want the two this run never looked for", unexercised)
	}

	// Both lines that answer a/x are credited: the narrow one and the
	// subject-wide one. Crediting only the first would report the
	// other stale, which is a retirement claim about a line that did
	// its job this run (#220).
	if len(doc.Excused) != 2 ||
		doc.Excused[0].Exception.Origin != "debt.txt:3" || doc.Excused[1].Exception.Origin != "debt.txt:11" {
		t.Fatalf("excused = %+v, want both declared lines that matched the finding", doc.Excused)
	}
}

// A swept subject answers for every assertion on it: a discovery walk
// (the SBOM scan) enumerates what is there, so an excuse it did not
// meet was met by absence — stale, not unexercised. And a
// subject-agnostic excuse, which is the shape a triage decision has,
// is exercised by the sweep itself.
func TestSealStalenessFollowsASweep(t *testing.T) {
	t.Parallel()

	j := report.NewJournal(
		report.Declared("acme/widget@v1", "CVE-1:pkg@1", "vex/one.json"),
		report.Declared("", "CVE-2:pkg@2", "vex/two.json"),
	)

	j.Check("acme/widget@v1", "CVE-9:other@9").Diverged("affects")
	j.Swept("acme/widget@v1")

	r := report.Seal("test", "acme", report.PopulationFromEvidence(1, "SBOMs"), j, report.NoCanary(), report.NoJudgedSet())

	var buf bytes.Buffer
	if err := r.Encode(&buf); err != nil {
		t.Fatalf("encode: %v", err)
	}

	doc := decodeDoc(t, buf.Bytes())
	if len(doc.Stale) != 2 {
		t.Fatalf("staleExceptions = %+v, want both — the inventory was read whole", doc.Stale)
	}

	if len(doc.Unexercised) != 0 {
		t.Fatalf("unexercisedExceptions = %+v, want none after a sweep", doc.Unexercised)
	}
}

// Without a sweep, a subject-agnostic excuse is unexercised: nothing
// enumerated anything, so nothing observed its absence.
func TestSubjectAgnosticExceptionNeedsASweep(t *testing.T) {
	t.Parallel()

	j := report.NewJournal(report.Declared("", "CVE-2:pkg@2", "vex/two.json"))
	j.Check("acme/widget@v1", "sbom")

	r := report.Seal("test", "acme", report.PopulationFromEvidence(1, "subjects"),
		j, report.NoCanary(), report.NoJudgedSet())

	var buf bytes.Buffer
	if err := r.Encode(&buf); err != nil {
		t.Fatalf("encode: %v", err)
	}

	doc := decodeDoc(t, buf.Bytes())
	if len(doc.Unexercised) != 1 || len(doc.Stale) != 0 {
		t.Fatalf("stale = %+v, unexercised = %+v — a check is not a sweep", doc.Stale, doc.Unexercised)
	}
}

// A subject-agnostic exception excuses its assertion wherever it
// appears: the decision is about the package version, not about the
// release that happens to carry it.
func TestSubjectAgnosticExceptionExcusesEverySubject(t *testing.T) {
	t.Parallel()

	j := report.NewJournal(report.Declared("", "CVE-1:pkg@1", "vex/one.json"))
	j.Check("a@v1", "CVE-1:pkg@1").Diverged("affects")
	j.Check("b@v2", "CVE-1:pkg@1").Diverged("affects")

	r := report.Seal("test", "acme", report.PopulationFromEvidence(2, "SBOMs"), j, report.NoCanary(), report.NoJudgedSet())
	if got := r.Verdict(); got != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS — one decision covers the triple wherever it is found", got)
	}
}

// TestOverlappingExceptionsOverOneCoordinate pins stele#220 across
// the four arrangements a declared line and a derivation can take over
// one coordinate. The rules under test, in one place:
//
//   - every matching exception is credited, so a finding both answer
//     names both, and neither is left looking unmatched;
//   - stale keeps its #147 meaning exactly — this run performed the
//     check and found it CLEAN — so no exception whose coordinate
//     diverged is ever called stale;
//   - a derived exception is never stale and never unexercised in any
//     arrangement: both buckets speak to a human holding a committed
//     file, and nobody can retire engine logic.
//
// The redundancy signal for a debt line the machinery has outgrown is
// therefore the visible pairing — the line shown excused alongside a
// derivation — not a claim the report makes.
func TestOverlappingExceptionsOverOneCoordinate(t *testing.T) {
	t.Parallel()

	const (
		subject   = "widget@v1.1.0"
		assertion = "tag:link"
		debtLine  = "debt.txt:1"
		horizon   = "the ledger founds no chain reaching this tag"
	)

	tests := []struct {
		name        string
		declared    bool
		derived     bool
		diverged    bool
		excusedBy   []string
		stale       []string
		unexercised []string
		findings    int
	}{
		{
			name:      "declared alone",
			declared:  true,
			diverged:  true,
			excusedBy: []string{debtLine},
		},
		{
			name:      "derived alone",
			derived:   true,
			diverged:  true,
			excusedBy: []string{horizon},
		},
		{
			name:      "both over one coordinate",
			declared:  true,
			derived:   true,
			diverged:  true,
			excusedBy: []string{debtLine, horizon},
		},
		{
			// The clean check is the ONLY arrangement that retires a
			// line, and it retires the declared one alone.
			name:     "both, and the check ran clean",
			declared: true,
			derived:  true,
			stale:    []string{debtLine},
		},
		{
			name:     "declared alone, and the check ran clean",
			declared: true,
			stale:    []string{debtLine},
		},
		{
			name:    "derived alone, and the check ran clean",
			derived: true,
		},
		{
			name:     "neither, and the check diverged",
			diverged: true,
			findings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := sealOneCoordinate(subject, assertion, debtLine, horizon,
				tt.declared, tt.derived, tt.diverged)

			want := report.VerdictPass
			if tt.findings > 0 {
				want = report.VerdictFail
			}

			if got := r.Verdict(); got != want {
				t.Fatalf("verdict = %s, want %s", got, want)
			}

			var buf bytes.Buffer
			if err := r.Encode(&buf); err != nil {
				t.Fatalf("encode: %v", err)
			}

			doc := decodeDoc(t, buf.Bytes())

			if got := excusedOrigins(t, doc, subject, assertion); !slices.Equal(got, tt.excusedBy) {
				t.Errorf("excused by %v, want %v", got, tt.excusedBy)
			}

			if got := origins(doc.Stale); !slices.Equal(got, tt.stale) {
				t.Errorf("staleExceptions = %v, want %v", got, tt.stale)
			}

			if got := origins(doc.Unexercised); !slices.Equal(got, tt.unexercised) {
				t.Errorf("unexercisedExceptions = %v, want %v", got, tt.unexercised)
			}

			if len(doc.Findings) != tt.findings {
				t.Errorf("findings = %+v, want %d unexcused", doc.Findings, tt.findings)
			}
		})
	}
}

// sealOneCoordinate runs one arrangement of the overlap: the debt
// line, the derivation, or both, over a single checked coordinate that
// either diverged or ran clean.
func sealOneCoordinate(subject, assertion, debtLine, horizon string, declared, derived, diverged bool) *report.Report {
	var lines []report.Exception
	if declared {
		lines = append(lines, report.Declared(subject, assertion, debtLine))
	}

	j := report.NewJournal(lines...)
	if derived {
		j.Except(report.Derived(subject, assertion, horizon))
	}

	c := j.Check(subject, assertion)
	if diverged {
		c.Diverged("the tag names no link")
	}

	return report.Seal("test", "acme/widget", report.PopulationFromEvidence(1, "tags"),
		j, report.NoCanary(), report.NoJudgedSet())
}

// excusedOrigins lists what excused the findings, asserting on the
// way that every pairing names the one coordinate under test.
func excusedOrigins(t *testing.T, doc *encodedDoc, subject, assertion string) []string {
	t.Helper()

	out := make([]string, 0, len(doc.Excused))

	for i := range doc.Excused {
		if f := doc.Excused[i].Finding; f.Subject != subject || f.Assertion != assertion {
			t.Fatalf("excused pairs the wrong finding: %+v", f)
		}

		out = append(out, doc.Excused[i].Exception.Origin)
	}

	return out
}

// A derivation over a coordinate this run never checked is not
// reported either: unexercised is a statement to a human about a
// committed line, and there is no committed line to make it about.
func TestAnUncheckedDerivationIsNotReported(t *testing.T) {
	t.Parallel()

	j := report.NewJournal(report.Declared("elsewhere", "y", "debt.txt:4"))
	j.Except(report.Derived("widget@v1", "tag:link", "the ledger founds no chain"))
	j.Check("other@v2", "tag:link")

	r := report.Seal("test", "acme", report.PopulationFromEvidence(1, "tags"),
		j, report.NoCanary(), report.NoJudgedSet())

	var buf bytes.Buffer
	if err := r.Encode(&buf); err != nil {
		t.Fatalf("encode: %v", err)
	}

	doc := decodeDoc(t, buf.Bytes())
	if got := origins(doc.Unexercised); !slices.Equal(got, []string{"debt.txt:4"}) {
		t.Fatalf("unexercisedExceptions = %v, want the declared line alone", got)
	}

	if len(doc.Stale) != 0 {
		t.Fatalf("staleExceptions = %+v, want none", doc.Stale)
	}
}

// origins renders an exception list by the line that asserted it —
// the identity a debt file's reader cares about.
func origins(list []encodedExc) []string {
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, e.Origin)
	}

	return out
}

// encodedDoc mirrors the wire shape for test-side decoding — the
// package deliberately exports no decoder, so the test owns one.
type encodedDoc struct {
	Schema     *int             `json:"schema"`
	Target     *string          `json:"target"`
	Subject    *string          `json:"subject"`
	Verdict    *string          `json:"verdict"`
	Population *encodedPop      `json:"population"`
	Canary     *encodedCanary   `json:"canary"`
	Facts      []report.Fact    `json:"facts"`
	Findings   []report.Finding `json:"findings"`
	Excused    []struct {
		Finding   report.Finding `json:"finding"`
		Exception encodedExc     `json:"exception"`
	} `json:"excused"`
	Stale       []encodedExc `json:"staleExceptions"`
	Unexercised []encodedExc `json:"unexercisedExceptions"`
	Judged      jsonx.Raw    `json:"judged"`
}

type encodedPop struct {
	Size     *int    `json:"size"`
	Expected *int    `json:"expected"`
	Source   *string `json:"source"`
	Detail   *string `json:"detail"`
}

type encodedCanary struct {
	Key  *string `json:"key"`
	Seen *bool   `json:"seen"`
}

type encodedExc struct {
	Kind      string `json:"kind"`
	Subject   string `json:"subject"`
	Assertion string `json:"assertion"`
	Origin    string `json:"origin"`
}

func decodeDoc(t *testing.T, b []byte) *encodedDoc {
	t.Helper()

	doc, err := jsonx.DecodeBytes[encodedDoc](b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	return doc
}

// TestEncodeShape pins the wire document: verdict, provenance-bearing
// population, canary, facts and findings all present under their
// stable names — the schema assert and level will consume.
func TestEncodeShape(t *testing.T) {
	t.Parallel()

	r := report.Seal("verify vsa", "acme/widget@v1.2.3",
		report.PopulationAgainstDeclared(2, 4, "org repos"),
		journal([]report.Finding{
			{Subject: "a", Assertion: "digest", Expected: "aa", Actual: "bb", Detail: "drift"},
		}, nil),
		report.CanaryMissed("known-bug"),
		report.Judged(jsonx.Raw(`[{"doc":"sbom-npm-x"}]`)),
		report.Fact{Name: "levels", Value: "SLSA_BUILD_LEVEL_3"},
	)

	var buf bytes.Buffer
	if err := r.Encode(&buf); err != nil {
		t.Fatalf("encode: %v", err)
	}

	if !strings.HasSuffix(buf.String(), "\n") {
		t.Fatal("encoded report does not end in a newline")
	}

	doc := decodeDoc(t, buf.Bytes())

	switch {
	case doc.Schema == nil || *doc.Schema != report.Schema:
		t.Fatalf("schema = %v, want %d — every encoded report declares its version (stele#107)", doc.Schema, report.Schema)
	case doc.Verdict == nil || *doc.Verdict != string(report.VerdictCannotJudge):
		t.Fatalf("verdict = %v, want CANNOT_JUDGE", doc.Verdict)
	case doc.Target == nil || *doc.Target != "verify vsa":
		t.Fatalf("target = %v", doc.Target)
	case doc.Subject == nil || *doc.Subject != "acme/widget@v1.2.3":
		t.Fatalf("subject = %v", doc.Subject)
	case doc.Population == nil || doc.Population.Size == nil || *doc.Population.Size != 2:
		t.Fatalf("population = %+v", doc.Population)
	case doc.Population.Expected == nil || *doc.Population.Expected != 4:
		t.Fatalf("population.expected = %v", doc.Population.Expected)
	case doc.Population.Source == nil || *doc.Population.Source != "declared":
		t.Fatalf("population.source = %v", doc.Population.Source)
	case doc.Canary == nil || doc.Canary.Seen == nil || *doc.Canary.Seen || *doc.Canary.Key != "known-bug":
		t.Fatalf("canary = %+v", doc.Canary)
	case len(doc.Facts) != 1 || doc.Facts[0].Name != "levels":
		t.Fatalf("facts = %+v", doc.Facts)
	case len(doc.Findings) != 1 || doc.Findings[0].Expected != "aa":
		t.Fatalf("findings = %+v", doc.Findings)
	case string(doc.Judged) != `[{"doc":"sbom-npm-x"}]`:
		t.Fatalf("judged = %s, want the engine's own rendering, carried verbatim", doc.Judged)
	}
}

// TestJudgedSet pins the carrier's two halves: a run that declares no
// set encodes none and hands back none, and a run that declares one
// hands back a COPY of the same bytes the document carries — the file
// a caller writes beside the report and the report itself are one
// rendering, so they cannot disagree about what was judged
// (stele#151).
func TestJudgedSet(t *testing.T) {
	t.Parallel()

	none := report.Seal("test", "s", report.PopulationFromEvidence(1, "x"), report.NewJournal(),
		report.NoCanary(), report.NoJudgedSet())
	if got := none.Judged(); len(got) != 0 {
		t.Fatalf("Judged() = %s, want nothing — the run declared no set", got)
	}

	var buf bytes.Buffer
	if err := none.Encode(&buf); err != nil {
		t.Fatalf("encode: %v", err)
	}

	if strings.Contains(buf.String(), "judged") {
		t.Fatalf("document = %s, want no judged field for a run that declared none", buf.String())
	}

	set := `[{"class":"wasm-npm","doc":"sbom-npm-x"}]`

	r := report.Seal("test", "s", report.PopulationFromEvidence(1, "x"), report.NewJournal(),
		report.NoCanary(), report.Judged(jsonx.Raw(set)))

	got := r.Judged()
	if string(got) != set {
		t.Fatalf("Judged() = %s, want %s", got, set)
	}

	got[0] = 'X'

	if again := r.Judged(); string(again) != set {
		t.Fatalf("Judged() = %s after a caller mutated the copy — the sealed report moved", again)
	}
}

// TestEncodeUnsealed pins the sealed-only rule: the zero value
// carries no verdict and refuses to encode.
func TestEncodeUnsealed(t *testing.T) {
	t.Parallel()

	var r report.Report

	if err := r.Encode(&bytes.Buffer{}); err == nil {
		t.Fatal("encoding an unsealed report did not refuse")
	}
}

// failWriter fails on first write — the stream-failure guard.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errFail }

var errFail = &writeError{}

type writeError struct{}

func (*writeError) Error() string { return "write refused" }

// TestEncodeWriteFailure pins the latch contract: a failed write
// surfaces as an error, never a silent success.
func TestEncodeWriteFailure(t *testing.T) {
	t.Parallel()

	r := report.Seal("test", "s", report.PopulationFromEvidence(1, "x"),
		report.NewJournal(), report.NoCanary(), report.NoJudgedSet())
	if err := r.Encode(failWriter{}); err == nil {
		t.Fatal("a failed write did not surface")
	}
}

// TestFindingsAreTheUnexcusedOnes pins both halves of the accessor's
// contract: an excused finding is not a finding, and the slice handed
// out is a copy — a caller that mutates it cannot rewrite a sealed
// report.
func TestFindingsAreTheUnexcusedOnes(t *testing.T) {
	t.Parallel()

	r := report.Seal("target", "subject",
		report.PopulationFromEvidence(2, "subjects"),
		journal([]report.Finding{finding("a", "unexcused"), finding("b", "excused")},
			[]report.Exception{report.Declared("b", "excused", "debt.txt:1")}),
		report.NoCanary(),
		report.NoJudgedSet(),
	)

	got := r.Findings()
	if len(got) != 1 || got[0].Subject != "a" {
		t.Fatalf("Findings = %+v, want only the unexcused one", got)
	}

	got[0].Subject = "rewritten"

	if again := r.Findings(); again[0].Subject != "a" {
		t.Fatalf("Findings = %+v after a caller mutated the copy — the sealed report moved", again)
	}
}

// TestJudgedSetAbsentEncodesAsNoValue pins the nil contract: a report
// with no set hands back nothing that a caller could re-encode into
// bytes that are not a JSON value — the trap an empty-but-present
// slice would set for the leg writing the set beside the report.
func TestJudgedSetAbsentEncodesAsNoValue(t *testing.T) {
	t.Parallel()

	r := report.Seal("test", "s", report.PopulationFromEvidence(1, "x"), report.NewJournal(),
		report.NoCanary(), report.NoJudgedSet())

	if got := r.Judged(); got != nil {
		t.Fatalf("Judged() = %#v, want nil for a run that declared no set", got)
	}
}
