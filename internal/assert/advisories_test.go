// The advisories judgment, row by row.
//
// Two laws carry this file. Only a CALLED finding gates — everything
// weaker is the graph around it, excused as derived so it stays
// visible without a human writing a decision for a vulnerability
// nothing reaches. And only a DENYING decision excuses — a statement
// admitting the finding, or withholding judgment, or claiming a
// remediation the scan just disproved, is reported on the finding it
// fails to excuse rather than silently clearing it.

package assert_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/govulncheck"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

// The mixed-case fixture, stated as LITERALS on both sides.
//
// The purl is the one a published stele SBOM carries for this
// module, lowercased because that is the purl golang type's canonical
// form; the module path is what govulncheck reports. Neither is
// derived from the other — a fixture that built the purl by
// lowercasing the module path would agree with the code under test
// whatever the code did, which is the trap measured in the Python
// harness this target replaces (stele#221).
const (
	mixedModule    = "github.com/Masterminds/semver/v3"
	publishedPurl  = "pkg:golang/github.com/masterminds/semver/v3@v3.5.0"
	mixedVersion   = "v3.5.0"
	mixedAdvisory  = "GO-2026-9999"
	canonicalKeyID = "GO-2026-9999:github.com/masterminds/semver/v3@v3.5.0"
)

// scanWith renders one govulncheck scan holding a single finding.
func scanWith(module, version string, level govulncheck.Level) *govulncheck.Scan {
	return &govulncheck.Scan{
		Scanner: "govulncheck", Version: "v1.7.0",
		DB: "https://vuln.go.dev", DBTime: "2026-08-19T17:06:06Z", ScanLevel: "symbol",
		Findings: []govulncheck.Finding{
			{Advisory: mixedAdvisory, Module: module, Version: version, Level: level},
		},
	}
}

// decisionsFrom parses one decision document.
func decisionsFrom(t *testing.T, purl, status, origin string) *vexjoin.Decisions {
	t.Helper()

	doc := `{"@context":"https://openvex.dev/ns/v0.2.0","timestamp":"2026-08-20T00:00:00Z",` +
		`"statements":[{"vulnerability":{"name":"` + mixedAdvisory + `"},"status":"` + status + `",` +
		`"justification":"vulnerable_code_not_present","products":[{"@id":"` + purl + `"}]}]}`

	d := &vexjoin.Decisions{}
	if err := vexjoin.Parse(d, []byte(doc), origin); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	return d
}

func judge(scan *govulncheck.Scan, decisions *vexjoin.Decisions) *report.Report {
	return assert.Advisories("example.com/mod", scan, decisions, report.NewJournal(), func(string, ...any) {})
}

// TestAPublishedPurlExcusesACalledFinding is the target's reason to
// exist: a decision authored the natural way — the product purl
// copied out of the published SBOM — joins the finding govulncheck
// reports for the same module, whose path carries uppercase letters.
func TestAPublishedPurlExcusesACalledFinding(t *testing.T) {
	t.Parallel()

	rep := judge(
		scanWith(mixedModule, mixedVersion, govulncheck.LevelCalled),
		decisionsFrom(t, publishedPurl, "not_affected", "semver.openvex.json"),
	)

	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS: %+v", rep.Verdict(), rep.Findings())
	}
}

// Only a denial excuses. Each row is a decision that EXISTS for the
// exact triple and does not clear it — and the finding must say so,
// because a red finding whose reader cannot tell somebody already
// looked at it is how a decision gets written twice.
func TestOnlyADenyingDecisionExcuses(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		status  string
		excuses bool
	}{
		{"not_affected", true},
		{"false_positive", true},
		{"affected", false},
		{"under_investigation", false},
		{"fixed", false},
	} {
		t.Run(tt.status, func(t *testing.T) {
			t.Parallel()

			rep := judge(
				scanWith(mixedModule, mixedVersion, govulncheck.LevelCalled),
				decisionsFrom(t, publishedPurl, tt.status, "d.openvex.json"),
			)

			if tt.excuses {
				if rep.Verdict() != report.VerdictPass {
					t.Fatalf("verdict = %s, want PASS for a denying status", rep.Verdict())
				}

				return
			}

			if rep.Verdict() != report.VerdictFail {
				t.Fatalf("verdict = %s, want FAIL — %q is not a denial", rep.Verdict(), tt.status)
			}

			findings := rep.Findings()
			if len(findings) != 1 {
				t.Fatalf("findings = %+v, want the one unexcused finding", findings)
			}

			for _, want := range []string{tt.status, "does not excuse", "d.openvex.json"} {
				if !strings.Contains(findings[0].Detail, want) {
					t.Errorf("detail %q does not name %q", findings[0].Detail, want)
				}
			}
		})
	}
}

// A decision for another ecosystem is not a stale decision here and
// not a covered one — it is out of this run's world entirely. It must
// produce NOTHING: no exception, no finding, no staleness claim. The
// name in the org's shared directory is already lowercase, so a
// blanket fold would look correct here; the test is that it is out of
// SCOPE, not that it folds harmlessly.
func TestADecisionFromAnotherEcosystemProducesNothing(t *testing.T) {
	t.Parallel()

	cargo := `{"@context":"https://openvex.dev/ns/v0.2.0","timestamp":"2026-08-20T00:00:00Z",` +
		`"statements":[{"vulnerability":{"name":"RUSTSEC-2021-0127"},"status":"not_affected",` +
		`"products":[{"@id":"pkg:cargo/serde_cbor@0.11.2"}]}]}`

	d := &vexjoin.Decisions{}
	if err := vexjoin.Parse(d, []byte(cargo), "RUSTSEC-2021-0127.openvex.json"); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	rep := judge(scanWith("example.com/dep", "v1.0.0", govulncheck.LevelRequired), d)

	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS", rep.Verdict())
	}

	doc := encode(t, rep)

	if strings.Contains(doc, "serde_cbor") || strings.Contains(doc, "RUSTSEC") {
		t.Errorf("the cargo decision appears in a Go scan's report:\n%s", doc)
	}

	// It was READ, and the report says so — reading is not scope.
	if !strings.Contains(doc, `"decisionsRead"`) || !strings.Contains(doc, `"decisionsInScope"`) {
		t.Errorf("the report does not account for what it read:\n%s", doc)
	}
}

// Everything below CALLED is the graph around the finding: reported,
// excused as DERIVED so no human can widen it, and never a gate.
func TestOnlyCalledFindingsGate(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		level govulncheck.Level
		gates bool
	}{
		{govulncheck.LevelRequired, false},
		{govulncheck.LevelImported, false},
		{govulncheck.LevelCalled, true},
	} {
		t.Run(string(tt.level), func(t *testing.T) {
			t.Parallel()

			rep := judge(scanWith("example.com/dep", "v1.0.0", tt.level), &vexjoin.Decisions{})

			want := report.VerdictPass
			if tt.gates {
				want = report.VerdictFail
			}

			if rep.Verdict() != want {
				t.Fatalf("verdict = %s at level %s, want %s", rep.Verdict(), tt.level, want)
			}

			if !tt.gates && !strings.Contains(encode(t, rep), "derived") {
				t.Error("an unreachable finding was excused by something other than a derivation")
			}
		})
	}
}

// A module with nothing found is a PASS, not a run that could not
// see. The population is the scan — one was read — because sizing it
// by the findings would make every clean repository CANNOT_JUDGE.
func TestACleanScanPasses(t *testing.T) {
	t.Parallel()

	rep := judge(&govulncheck.Scan{Scanner: "govulncheck", Version: "v1.7.0"}, &vexjoin.Decisions{})
	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS over an empty finding set", rep.Verdict())
	}
}

// The finding's ID is the canonical join key — the name a decision
// must be written against — while the detail keeps the module path as
// govulncheck reported it. Both facts present, neither invented; the
// same split the SBOM makes between its purl and its SPDX name.
func TestTheIDIsCanonicalAndTheDetailIsVerbatim(t *testing.T) {
	t.Parallel()

	rep := judge(scanWith(mixedModule, mixedVersion, govulncheck.LevelCalled), &vexjoin.Decisions{})

	findings := rep.Findings()
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one", findings)
	}

	if findings[0].Assertion != canonicalKeyID {
		t.Errorf("assertion = %q, want the canonical key %q", findings[0].Assertion, canonicalKeyID)
	}

	if !strings.Contains(findings[0].Detail, mixedModule) {
		t.Errorf("detail = %q, want the module path as the scanner reported it", findings[0].Detail)
	}
}

// A decision this scan never met is NOT stale: this run enumerates
// one module's graph while the decisions cover every graph the org
// keeps. Saying "stale" would be a retirement claim the run has no
// standing to make, so the unmatched decision lands in the
// unexercised bucket instead.
func TestAnUnmetDecisionIsNotCalledStale(t *testing.T) {
	t.Parallel()

	rep := judge(
		scanWith("example.com/other", "v9.0.0", govulncheck.LevelRequired),
		decisionsFrom(t, publishedPurl, "not_affected", "semver.openvex.json"),
	)

	doc := encode(t, rep)
	if strings.Contains(doc, "staleExceptions") {
		t.Errorf("a decision this scan never looked for was called stale:\n%s", doc)
	}

	if !strings.Contains(doc, "unexercisedExceptions") {
		t.Errorf("the unmet decision was not carried as unexercised:\n%s", doc)
	}
}

// encode renders the report document for assertions about what it
// does and does not contain.
func encode(t *testing.T, rep *report.Report) string {
	t.Helper()

	var b strings.Builder
	if err := rep.Encode(&b); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	return b.String()
}

// A dependency that moved off a decided version is what the
// per-version join is FOR: the old judgment excuses nothing, and the
// finding says a judgment exists rather than leaving the reader to
// re-derive one that is already written down.
func TestAMovedVersionNamesTheDecisionItLeftBehind(t *testing.T) {
	t.Parallel()

	rep := judge(
		scanWith(mixedModule, "v3.6.0", govulncheck.LevelCalled),
		decisionsFrom(t, publishedPurl, "not_affected", "semver.openvex.json"),
	)

	if rep.Verdict() != report.VerdictFail {
		t.Fatalf("verdict = %s, want FAIL — a bumped version inherits no judgment", rep.Verdict())
	}

	findings := rep.Findings()
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one", findings)
	}

	for _, want := range []string{"semver.openvex.json", "v3.5.0", "v3.6.0", "fresh judgment"} {
		if !strings.Contains(findings[0].Detail, want) {
			t.Errorf("detail %q does not name %q", findings[0].Detail, want)
		}
	}
}

// A near miss is same-advisory AND same-package. Another package's
// decision for the same advisory is not a judgment about this
// finding, and naming it would send a reader to an unrelated
// statement.
func TestANearMissIsScopedToThePackage(t *testing.T) {
	t.Parallel()

	rep := judge(
		scanWith(mixedModule, mixedVersion, govulncheck.LevelCalled),
		decisionsFrom(t, "pkg:golang/example.com/elsewhere@v1.0.0", "not_affected", "other.openvex.json"),
	)

	findings := rep.Findings()
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one", findings)
	}

	if strings.Contains(findings[0].Detail, "other.openvex.json") {
		t.Errorf("detail %q cites a decision about another package", findings[0].Detail)
	}
}
