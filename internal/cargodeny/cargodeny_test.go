// What the stream says, and what it must never be read as saying.
//
// The load-bearing law is the summary: every failure mode of a check
// that did not finish — an empty file, a stream cut short, the output
// of some other tool — arrives as zero findings, and zero findings is
// the shape of a clean run. cargo-deny's exit status cannot tell them
// apart (it exits 1 for both), so the summary line is the only
// witness, and a reader that returned "clean" without it would report
// a check nobody completed.

package cargodeny_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/cargodeny"
)

// fixture is the stream cargo-deny 0.20.2 wrote to stderr for
// `cargo deny --format json check advisories` over iiif-server at
// a0d8fef9117b4aa4d5f869ad4f543523438c659f on 2026-11-21 — recorded
// from the real tool, not written from its documentation.
const fixture = "testdata/iiif-server-advisories.jsonl"

func readFixture(t *testing.T) string {
	t.Helper()

	b, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

// The recorded stream: two error diagnostics, one graph each, and a
// summary counting two errors — two findings, keyed by the crate
// version each graph names.
func TestReadsTheRecordedStream(t *testing.T) {
	t.Parallel()

	scan, err := cargodeny.Read(strings.NewReader(readFixture(t)))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	want := []cargodeny.Finding{
		{Advisory: "RUSTSEC-2026-0542", Code: "unmaintained", Crate: "humantime", Version: "2.4.0"},
		{Advisory: "RUSTSEC-2026-0543", Code: "unmaintained", Crate: "chrono", Version: "0.4.45"},
	}

	if len(scan.Findings) != len(want) {
		t.Fatalf("findings = %+v, want %+v", scan.Findings, want)
	}

	for i := range want {
		if scan.Findings[i] != want[i] {
			t.Errorf("finding %d = %+v, want %+v", i, scan.Findings[i], want[i])
		}
	}

	if scan.Severities[cargodeny.SeverityError] != 2 || len(scan.Severities) != 1 {
		t.Errorf("severities = %v, want two errors and nothing else", scan.Severities)
	}

	if got := scan.Findings[1].Purl(); got != "pkg:cargo/chrono@0.4.45" {
		t.Errorf("purl = %q", got)
	}
}

// diag renders one diagnostic line; graphs is the raw graphs array.
func diag(severity, advisory, graphs string) string {
	return `{"type":"diagnostic","fields":{"severity":"` + severity + `","code":"vulnerability",` +
		`"advisory":` + advisory + `,"graphs":` + graphs + `}}` + "\n"
}

func summary(errs string) string {
	return `{"type":"summary","fields":{"advisories":{"errors":` + errs +
		`,"helps":0,"notes":0,"warnings":0}}}` + "\n"
}

const (
	anAdvisory = `{"id":"RUSTSEC-2026-0001","package":"foo"}`
	oneGraph   = `[{"Krate":{"name":"foo","version":"1.0.0"},"parents":[]}]`
)

// Every row is a stream a reader must refuse, and each one is a real
// way this input arrives broken or ambiguous.
func TestRefusals(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		input string
		want  error
	}{
		{"an empty file", "", cargodeny.ErrNoSummary},
		{"another tool's JSON", `{"results":[]}`, cargodeny.ErrNoSummary},
		{
			"diagnostics with no summary — a check that stopped", diag("error", anAdvisory, oneGraph),
			cargodeny.ErrNoSummary,
		},
		{
			"a summary for another check", `{"type":"summary","fields":{"bans":{"errors":0}}}`,
			cargodeny.ErrNoSummary,
		},
		{
			"a summary with no error count", `{"type":"summary","fields":{"advisories":{"warnings":0}}}`,
			cargodeny.ErrNoSummary,
		},
		{"two summaries", summary("0") + summary("0"), cargodeny.ErrTwoSummaries},
		{
			"a summary counting more errors than the stream carries",
			diag("error", anAdvisory, oneGraph) + summary("2"), cargodeny.ErrCountMismatch,
		},
		{
			"a summary counting fewer", diag("error", anAdvisory, oneGraph) + summary("0"),
			cargodeny.ErrCountMismatch,
		},
		{
			"a diagnostic with no severity",
			`{"type":"diagnostic","fields":{"code":"x","graphs":` + oneGraph + `}}` + summary("0"),
			cargodeny.ErrNoSeverity,
		},
		{"an error with no graphs", diag("error", anAdvisory, `[]`) + summary("1"), cargodeny.ErrUnkeyed},
		{
			"an error whose graph names no crate", diag("error", anAdvisory, `[{"parents":[]}]`) + summary("1"),
			cargodeny.ErrUnkeyed,
		},
		{
			"an error whose crate has no version",
			diag("error", anAdvisory, `[{"Krate":{"name":"foo"}}]`) + summary("1"), cargodeny.ErrUnkeyed,
		},
		{
			"an advisory with no id", diag("error", `{"package":"foo"}`, oneGraph) + summary("1"),
			cargodeny.ErrUnkeyed,
		},
		{
			"no advisory and no code",
			`{"type":"diagnostic","fields":{"severity":"error","graphs":` + oneGraph + `}}` + summary("1"),
			cargodeny.ErrUnkeyed,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := cargodeny.Read(strings.NewReader(tt.input))
			if !errors.Is(err, tt.want) {
				t.Fatalf("Read = %v, want %v", err, tt.want)
			}
		})
	}
}

// A line that is not JSON is a producer that broke; the read fails
// whole rather than returning the lines before it.
func TestALineThatIsNotJSONFailsTheRead(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		readFixture(t) + "warning: something\n",
		"not json\n" + summary("0"),
		diag("error", anAdvisory, oneGraph)[:40],
	} {
		if _, err := cargodeny.Read(strings.NewReader(input)); err == nil {
			t.Errorf("Read(%q) = nil error, want a refusal", input)
		}
	}
}

// Severities below error are counted and gate nothing; lines of a type
// this reader does not know are skipped.
func TestOnlyErrorsAreFindings(t *testing.T) {
	t.Parallel()

	input := `{"type":"log","fields":{"level":"WARN","message":"x"}}` + "\n" +
		diag("warning", anAdvisory, oneGraph) + diag("note", "null", oneGraph) + diag("help", "null", `[]`) +
		summary("0")

	scan, err := cargodeny.Read(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if len(scan.Findings) != 0 {
		t.Errorf("findings = %+v, want none below error", scan.Findings)
	}

	for _, sev := range []string{"warning", "note", "help"} {
		if scan.Severities[sev] != 1 {
			t.Errorf("severities[%s] = %d, want 1", sev, scan.Severities[sev])
		}
	}
}

// An error with no advisory — a yanked crate — is still a finding,
// carried by its code; and one crate version reached by two graphs is
// one finding.
func TestAnErrorWithNoAdvisoryIsAFindingByItsCode(t *testing.T) {
	t.Parallel()

	twoGraphs := `[{"Krate":{"name":"foo","version":"1.0.0"}},{"Krate":{"name":"foo","version":"1.0.0"}}]`
	input := `{"type":"diagnostic","fields":{"severity":"error","code":"yanked","graphs":` + twoGraphs + `}}` +
		"\n" + summary("1")

	scan, err := cargodeny.Read(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	want := cargodeny.Finding{Code: "yanked", Crate: "foo", Version: "1.0.0"}
	if len(scan.Findings) != 1 || scan.Findings[0] != want {
		t.Fatalf("findings = %+v, want [%+v]", scan.Findings, want)
	}
}
