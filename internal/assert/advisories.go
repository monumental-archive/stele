// The advisories target: one scan of one subject's dependencies,
// judged against the recorded triage decisions.
//
// The join is internal/vexjoin's and nothing here reimplements it —
// the same sealed key, the same per-type fold, the same rule about
// which statuses excuse. That is the whole point of the target
// (stele#221): the org ran this judgment twice, in two languages, and
// a second derivation of one rule is the share-the-definition failure
// mode whatever language it is written in.
//
// Two readers feed it (stele#515): govulncheck's stream for a Go
// module and cargo-deny's for a Cargo lock. Each entry point below
// translates its scanner's findings into the one shape the judgment
// takes, and everything after that — the decisions in scope, the
// excuse rule, the near miss, the report — is one code path. The
// scanner decides only what a finding IS and whether it gates; it
// never decides what excuses it.

package assert

import (
	"fmt"
	"slices"
	"sort"
	"strconv"

	"github.com/monumental-archive/stele/internal/cargodeny"
	"github.com/monumental-archive/stele/internal/govulncheck"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

// scanned is one finding in the shape the judgment takes, whatever
// scanner produced it.
type scanned struct {
	// assertion is the finding's ID in the report. For a keyed finding
	// it is the join key's rendering, never the scanner's spelling.
	assertion string
	// keyed is false for a finding no decision can excuse — one naming
	// no advisory — and then key is the zero Key.
	keyed bool
	key   vexjoin.Key
	// advisory and version are the scanner's own words, for the near
	// miss line.
	advisory, version string
	// base is the detail line's opening: what the scan found, in the
	// scanner's spelling.
	base string
	// derived, when non-empty, excuses the finding as DERIVED: the
	// scanner's own answer that it does not gate.
	derived string
}

// Advisories judges one govulncheck scan. subject names the module
// the scan covers, so a report reads as being about something.
//
// Only a CALLED finding gates. The weaker levels are the graph around
// it — a vulnerable module nothing imports, or a package no
// vulnerable symbol of which is reached — and they are excused as
// DERIVED, so they stay visible in the document without a human
// having to write a decision for a vulnerability that is not reachable.
// That is govulncheck's own ranking, kept rather than reinterpreted.
//
// decisions must be non-nil; an empty set is the honest way to say
// nothing is decided, and it decides nothing.
func Advisories(
	subject string, scan *govulncheck.Scan, decisions *vexjoin.Decisions, j *report.Journal, log Logf,
) *report.Report {
	log("assert: advisories: %s: %s %s, db %s (%s), scan level %s",
		subject, scan.Scanner, scan.Version, scan.DB, scan.DBTime, scan.ScanLevel)

	levels := map[govulncheck.Level]int{}
	findings := make([]scanned, 0, len(scan.Findings))

	for i := range scan.Findings {
		f := scan.Findings[i]
		levels[f.Level]++

		// The assertion is the JOIN KEY's rendering, never the
		// scanner's own spelling of the module path. Exceptions match
		// findings by this string, and a decision's exception is keyed
		// by the canonical purl name — so using govulncheck's spelling
		// here would put two spellings of one module on the two sides
		// of the report's match and excuse nothing for any module with
		// an uppercase letter. That is stele#201's defect exactly,
		// one layer up, and it is invisible until such a module has a
		// decision. The true-case path stays in the detail, which is
		// where a reader wants it.
		key := vexjoin.KeyFromFinding(f.Advisory, govulncheck.PurlType, f.Module, f.Version)

		s := scanned{
			assertion: key.String(), keyed: true, key: key,
			advisory: f.Advisory, version: f.Version,
			base: fmt.Sprintf("%s affects %s@%s (%s)", f.Advisory, f.Module, f.Version, f.Level),
		}

		if !f.Called() {
			// DERIVED, so a human cannot widen it: the exception is the
			// scanner's own reachability answer, not a judgment anybody
			// recorded.
			s.derived = "govulncheck reached this only at level " + string(f.Level) +
				": no vulnerable symbol is called from this module"
		}

		findings = append(findings, s)
	}

	inScope := judgeAdvisories(subject, govulncheck.PurlType, findings, decisions, j)

	log("assert: advisories: %s: %d advisory(ies) in scope — %d called, %d imported, %d required",
		subject, len(scan.Findings), levels[govulncheck.LevelCalled],
		levels[govulncheck.LevelImported], levels[govulncheck.LevelRequired])

	return sealAdvisories(subject, "govulncheck scan read for "+subject, j,
		report.Fact{Name: "advisories", Value: strconv.Itoa(len(scan.Findings))},
		report.Fact{Name: "called", Value: strconv.Itoa(levels[govulncheck.LevelCalled])},
		report.Fact{Name: "decisionsRead", Value: strconv.Itoa(decisions.Len())},
		report.Fact{Name: "decisionsInScope", Value: strconv.Itoa(inScope)},
		report.Fact{Name: "scanner", Value: scan.Scanner + " " + scan.Version},
		report.Fact{Name: "db", Value: scan.DB + " " + scan.DBTime},
	)
}

// CargoAdvisories judges one cargo-deny advisories check. subject
// names the lock the check covers.
//
// Every finding gates: cargo-deny has no reachability levels, and the
// reader has already kept only the error diagnostics, so nothing here
// is excused as derived. A finding naming an advisory joins the
// decisions on its (advisory, crate, version) triple exactly as a Go
// finding does. A finding naming NO advisory — a yanked crate — is
// asserted by its code and the crate's purl, and no decision can
// excuse it, because a decision is keyed by the advisory it decides.
//
// The stream states no advisory database, so the report carries no
// db fact rather than an empty one. It carries the count of each
// severity read instead, which is what this scanner says about the
// diagnostics it did not gate on.
func CargoAdvisories(
	subject string, scan *cargodeny.Scan, decisions *vexjoin.Decisions, j *report.Journal, log Logf,
) *report.Report {
	log("assert: advisories: %s: %s", subject, cargodeny.Scanner)

	findings := make([]scanned, 0, len(scan.Findings))

	for i := range scan.Findings {
		f := scan.Findings[i]

		if f.Advisory == "" {
			findings = append(findings, scanned{
				assertion: f.Code + ":" + f.Purl(),
				base: fmt.Sprintf("%s@%s is %s, and names no advisory a decision could excuse",
					f.Crate, f.Version, f.Code),
			})

			continue
		}

		key := vexjoin.KeyFromFinding(f.Advisory, cargodeny.PurlType, f.Crate, f.Version)

		findings = append(findings, scanned{
			assertion: key.String(), keyed: true, key: key,
			advisory: f.Advisory, version: f.Version,
			base: fmt.Sprintf("%s affects %s@%s (%s)", f.Advisory, f.Crate, f.Version, f.Code),
		})
	}

	inScope := judgeAdvisories(subject, cargodeny.PurlType, findings, decisions, j)

	log("assert: advisories: %s: %d finding(s) gate", subject, len(scan.Findings))

	facts := []report.Fact{
		{Name: "advisories", Value: strconv.Itoa(len(scan.Findings))},
		{Name: "decisionsRead", Value: strconv.Itoa(decisions.Len())},
		{Name: "decisionsInScope", Value: strconv.Itoa(inScope)},
		{Name: "scanner", Value: cargodeny.Scanner},
	}

	return sealAdvisories(subject, "cargo-deny check read for "+subject, j,
		append(facts, severityFacts(scan.Severities)...)...)
}

// severityFacts renders the count of each severity read: the four
// cargo-deny's summary names always, so a zero is stated rather than
// absent, and any other a newer cargo-deny writes after them, sorted.
func severityFacts(sev cargodeny.Severities) []report.Fact {
	known := []string{cargodeny.SeverityError, "warning", "note", "help"}

	names := append([]string{}, known...)

	var extra []string

	for name := range sev {
		if !slices.Contains(known, name) {
			extra = append(extra, name)
		}
	}

	sort.Strings(extra)

	out := make([]report.Fact, 0, len(names)+len(extra))
	for _, name := range append(names, extra...) {
		out = append(out, report.Fact{Name: "diagnostics." + name, Value: strconv.Itoa(sev[name])})
	}

	return out
}

// judgeAdvisories is the one judgment both readers feed: the
// decisions in scope for the scanner's purl type entered, each finding
// checked with what was already written down about it, and each
// derived excuse recorded. It returns how many decisions were in
// scope.
func judgeAdvisories(
	subject, purlType string, findings []scanned, decisions *vexjoin.Decisions, j *report.Journal,
) int {
	inScope := enterDecisions(purlType, decisions, j)

	for i := range findings {
		f := &findings[i]

		j.Check(subject, f.assertion).Diverged(divergence(purlType, f, decisions))

		if f.derived != "" {
			j.Except(report.Derived(subject, f.assertion, f.derived))
		}
	}

	return inScope
}

// sealAdvisories seals the report the same way for every scanner.
func sealAdvisories(subject, evidence string, j *report.Journal, facts ...report.Fact) *report.Report {
	// The population is the scan, not the advisories in it: a clean
	// subject reports zero findings and that is a PASS, never a run
	// that could not see. Whether the scan happened at all is settled
	// before this point — a stream that did not finish is refused by
	// its reader, which is CANNOT_JUDGE at the surface.
	pop := report.PopulationFromEvidence(1, evidence)

	// No Swept: this run enumerates ONE subject's graph, while the
	// decisions it reads cover every graph the org keeps. A decision
	// this scan did not meet was not observed to be absent — it was
	// not looked for, and saying "stale" would be a retirement claim
	// this run has no standing to make.
	return report.Seal("assert advisories", subject, pop, j,
		report.NoCanary(), report.NoJudgedSet(), facts...)
}

// enterDecisions puts every decision this scan could meet, and that
// would excuse, into the judgment — and reports how many those were.
//
// Scope is by purl type. A cargo decision cannot match a Go module
// finding in any spelling, so it is not a stale decision here and not
// a covered one: it is out of this run's world entirely and produces
// NOTHING — no exception, no count, no line. A non-excusing decision
// is likewise not an exception; it is reported on the finding it
// fails to excuse, which is where a reader is looking.
func enterDecisions(purlType string, decisions *vexjoin.Decisions, j *report.Journal) int {
	all := decisions.All()

	scoped := 0

	for i := range all {
		if all[i].PurlType() != purlType {
			continue
		}

		scoped++

		if !all[i].Excuses() {
			continue
		}

		// Subject-agnostic, like every triage decision: it judges a
		// package version, not the subject whose scan happened to meet it.
		j.Except(report.Declared("", all[i].Key.String(), all[i].Origin))
	}

	return scoped
}

// divergence states what the scan found and what was already written
// down about it. A decision that was read and did not clear the
// finding must be visible either way: the alternative is a red line
// whose reader cannot tell that somebody already looked at this, which
// is how one advisory gets triaged twice.
//
// Two shapes of "already looked":
//
//   - a decision on the exact triple that does not DENY — reported
//     with its status, because the reader's next move is to revisit
//     that statement, not to write a new one;
//   - a decision for the same advisory on a DIFFERENT version — the
//     case the per-version join exists to create. The decision is
//     real and excuses nothing here, and the reader needs to know a
//     judgment exists before re-deriving it from scratch. The
//     predecessor this target replaces surfaced it as a stale
//     decision; naming it on the finding puts it where the reader
//     already is.
//
// A finding with no key has nothing to look up: nothing was or could
// be written down about it.
func divergence(purlType string, f *scanned, decisions *vexjoin.Decisions) string {
	if !f.keyed {
		return f.base
	}

	if dec, ok := decisions.Get(f.key); ok {
		if dec.Excuses() {
			return f.base
		}

		return fmt.Sprintf("%s — %s records status %q, which does not excuse it", f.base, dec.Origin, dec.Status)
	}

	if near := nearMiss(purlType, f, decisions); near != "" {
		return f.base + " — " + near
	}

	return f.base
}

// nearMiss names a decision for this advisory on another version of
// the same package: a judgment that was made and no longer applies,
// which is exactly what a per-version join is meant to expose when a
// dependency moves.
func nearMiss(purlType string, f *scanned, decisions *vexjoin.Decisions) string {
	all := decisions.All()

	for i := range all {
		d := &all[i]

		switch {
		case d.PurlType() != purlType:
			continue // another ecosystem's decision is not a near miss, it is a stranger
		case d.Key.Advisory() != f.key.Advisory() || d.Key.Package() != f.key.Package():
			continue
		case d.Key.Version() == f.key.Version():
			continue // the exact match is not a near miss; the caller handled it
		}

		return fmt.Sprintf("%s decides %s at %s, and this graph carries %s — a fresh judgment is owed",
			d.Origin, f.advisory, d.Key.Version(), f.version)
	}

	return ""
}
