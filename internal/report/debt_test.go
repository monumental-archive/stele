// The debt file's parser: what a committed line may say, and what it
// may not. Both wildcards the engine can spell are refused here — a
// file that could vote itself wider than the line a human read would
// be an excuse nobody approved.

package report_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/report"
)

func TestParseDebt(t *testing.T) {
	t.Parallel()

	debt, err := report.ParseDebt([]byte("# reviewed in PR 9\n\nwidget@v1.0.0(sbom)\n"), "debt.txt")
	if err != nil {
		t.Fatalf("ParseDebt: %v", err)
	}

	if len(debt) != 1 {
		t.Fatalf("debt = %d entries, want 1", len(debt))
	}
}

func TestParseDebtRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		line string
	}{
		{"a line that is not subject(assertion)", "no-parens\n"},
		{"an empty assertion — a blanket excuse needs its own review", "widget@v1.0.0()\n"},
		{"an empty subject — the any-subject wildcard is engine vocabulary", "(sbom)\n"},
		{"an unclosed assertion", "widget@v1.0.0(sbom\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := report.ParseDebt([]byte(tt.line), "debt.txt")
			if err == nil {
				t.Fatalf("%q did not refuse", tt.line)
			}

			if !strings.Contains(err.Error(), "debt.txt:1") {
				t.Fatalf("refusal = %v, want it to name the reviewed line", err)
			}
		})
	}
}

// A parsed line excuses exactly its own coordinate: the origin points
// back at the review that approved it, which is what makes an excuse
// auditable rather than a mute button.
func TestParseDebtCarriesTheReviewedLine(t *testing.T) {
	t.Parallel()

	debt, err := report.ParseDebt([]byte("\n\nwidget@v1.0.0(sbom)\n"), "security/debt.txt")
	if err != nil {
		t.Fatalf("ParseDebt: %v", err)
	}

	j := report.NewJournal(debt...)
	j.Check("widget@v1.0.0", "sbom").Diverged("absent")

	rep := report.Seal("test", "acme", report.PopulationFromEvidence(1, "subjects"), j, report.NoCanary())
	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want the declared line to excuse its finding", rep.Verdict())
	}
}
