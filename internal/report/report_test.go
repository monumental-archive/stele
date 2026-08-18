// Seal is the org's entire green/red boundary in one function, so
// its table is exhaustive over the judgment axes: population state ×
// canary state × finding/exception matching. Every row states which
// law it pins.

package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/report"
)

func finding(subject, assertion string) report.Finding {
	return report.Finding{Subject: subject, Assertion: assertion, Detail: "detail"}
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

			r := report.Seal("test", "acme/widget", tt.pop, tt.findings, tt.exceptions, tt.canary)
			if got := r.Verdict(); got != tt.want {
				t.Fatalf("verdict = %s, want %s", got, tt.want)
			}

			if r.Passed() != (tt.want == report.VerdictPass) {
				t.Fatalf("Passed() disagrees with verdict %s", tt.want)
			}
		})
	}
}

// TestSealStaleExceptions pins the retirement rule: an exception
// matching no finding is carried in the document as stale — reported
// for retirement, never a failure and never silently dropped.
func TestSealStaleExceptions(t *testing.T) {
	t.Parallel()

	r := report.Seal("test", "acme/widget",
		report.PopulationFromEvidence(2, "subjects"),
		[]report.Finding{finding("a", "x")},
		[]report.Exception{
			report.Declared("a", "x", "debt.txt:3"),
			report.Declared("gone", "", "debt.txt:9"),
		},
		report.NoCanary(),
	)

	if got := r.Verdict(); got != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS", got)
	}

	var buf bytes.Buffer
	if err := r.Encode(&buf); err != nil {
		t.Fatalf("encode: %v", err)
	}

	doc := decodeDoc(t, buf.Bytes())
	if len(doc.Stale) != 1 || doc.Stale[0].Subject != "gone" {
		t.Fatalf("staleExceptions = %+v, want the unmatched one", doc.Stale)
	}

	if len(doc.Excused) != 1 || doc.Excused[0].Exception.Kind != "declared" {
		t.Fatalf("excused = %+v, want the matched declared exception", doc.Excused)
	}
}

// encodedDoc mirrors the wire shape for test-side decoding — the
// package deliberately exports no decoder, so the test owns one.
type encodedDoc struct {
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
	Stale []encodedExc `json:"staleExceptions"`
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
		[]report.Finding{{Subject: "a", Assertion: "digest", Expected: "aa", Actual: "bb", Detail: "drift"}},
		nil,
		report.CanaryMissed("known-bug"),
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

	r := report.Seal("test", "s", report.PopulationFromEvidence(1, "x"), nil, nil, report.NoCanary())
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
		[]report.Finding{finding("a", "unexcused"), finding("b", "excused")},
		[]report.Exception{report.Declared("b", "excused", "debt.txt:1")},
		report.NoCanary(),
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
