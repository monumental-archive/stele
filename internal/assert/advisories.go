// The advisories target: one module's reachable-vulnerability scan,
// judged against the recorded triage decisions.
//
// The join is internal/vexjoin's and nothing here reimplements it —
// the same sealed key, the same per-type fold, the same rule about
// which statuses excuse. That is the whole point of the target
// (stele#221): the org ran this judgment twice, in two languages, and
// a second derivation of one rule is the share-the-definition failure
// mode whatever language it is written in.

package assert

import (
	"fmt"
	"strconv"

	"github.com/monumental-archive/stele/internal/govulncheck"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

// Advisories judges one scan. subject names the module the scan
// covers, so a report reads as being about something.
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

	inScope := enterDecisions(decisions, j)

	levels := map[govulncheck.Level]int{}

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

		j.Check(subject, key.String()).Diverged(divergence(f, key, decisions))

		if !f.Called() {
			// DERIVED, so a human cannot widen it: the exception is the
			// scanner's own reachability answer, not a judgment anybody
			// recorded.
			j.Except(report.Derived(subject, key.String(),
				"govulncheck reached this only at level "+string(f.Level)+
					": no vulnerable symbol is called from this module"))
		}
	}

	log("assert: advisories: %s: %d advisory(ies) in scope — %d called, %d imported, %d required",
		subject, len(scan.Findings), levels[govulncheck.LevelCalled],
		levels[govulncheck.LevelImported], levels[govulncheck.LevelRequired])

	facts := []report.Fact{
		{Name: "advisories", Value: strconv.Itoa(len(scan.Findings))},
		{Name: "called", Value: strconv.Itoa(levels[govulncheck.LevelCalled])},
		{Name: "decisionsRead", Value: strconv.Itoa(decisions.Len())},
		{Name: "decisionsInScope", Value: strconv.Itoa(inScope)},
		{Name: "scanner", Value: scan.Scanner + " " + scan.Version},
		{Name: "db", Value: scan.DB + " " + scan.DBTime},
	}

	// The population is the scan, not the advisories in it: a clean
	// module reports zero findings and that is a PASS, never a run
	// that could not see. Whether the scan happened at all is settled
	// before this point — a stream carrying no config message is
	// refused by the reader, which is CANNOT_JUDGE at the surface.
	pop := report.PopulationFromEvidence(1, "govulncheck scan read for "+subject)

	// No Swept: this run enumerates ONE module's graph, while the
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
func enterDecisions(decisions *vexjoin.Decisions, j *report.Journal) int {
	all := decisions.All()

	scoped := 0

	for i := range all {
		if all[i].PurlType() != govulncheck.PurlType {
			continue
		}

		scoped++

		if !all[i].Excuses() {
			continue
		}

		// Subject-agnostic, like every triage decision: it judges a
		// package version, not the module whose scan happened to meet it.
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
func divergence(f govulncheck.Finding, key vexjoin.Key, decisions *vexjoin.Decisions) string {
	base := fmt.Sprintf("%s affects %s@%s (%s)", f.Advisory, f.Module, f.Version, f.Level)

	if dec, ok := decisions.Get(key); ok {
		if dec.Excuses() {
			return base
		}

		return fmt.Sprintf("%s — %s records status %q, which does not excuse it", base, dec.Origin, dec.Status)
	}

	if near := nearMiss(f, key, decisions); near != "" {
		return base + " — " + near
	}

	return base
}

// nearMiss names a decision for this advisory on another version of
// the same package: a judgment that was made and no longer applies,
// which is exactly what a per-version join is meant to expose when a
// dependency moves.
func nearMiss(f govulncheck.Finding, key vexjoin.Key, decisions *vexjoin.Decisions) string {
	all := decisions.All()

	for i := range all {
		d := &all[i]

		switch {
		case d.PurlType() != govulncheck.PurlType:
			continue // another ecosystem's decision is not a near miss, it is a stranger
		case d.Key.Advisory() != key.Advisory() || d.Key.Package() != key.Package():
			continue
		case d.Key.Version() == key.Version():
			continue // the exact match is not a near miss; the caller handled it
		}

		return fmt.Sprintf("%s decides %s at %s, and this graph carries %s — a fresh judgment is owed",
			d.Origin, f.Advisory, d.Key.Version(), f.Version)
	}

	return ""
}
