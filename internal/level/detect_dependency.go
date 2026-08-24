// Dependency-track detectors, against the DRAFT track.
//
// SLSA v1.2 approves no dependency track. Judging it anyway is
// deliberate: organizations claim dependency levels today, and a claim
// nobody computes is a claim nobody has tested — a moving spec
// underneath makes that more likely to be wrong, not less. Every
// output carrying one of these levels marks it draft.
//
// The draft's own framing is what makes L1 and L2 detectable: it asks
// that an inventory EXIST and that findings be TRIAGED, not that a
// release be free of vulnerabilities. Both are properties of published
// artifacts.

package level

import (
	"strconv"
	"strings"
	"time"
)

//nolint:gochecknoinits // the registry is populated once, at load, by the detectors themselves
func init() {
	register(inventoryExists{})
	register(dependenciesScanned{})
	register(findingsTriaged{})
	register(producerControlled{})
	register(secureIngestion{})
}

type inventoryExists struct{}

func (inventoryExists) For() string { return "dependency/inventory" }

// Detect judges whether a published inventory covers what this
// repository published.
//
// The coverage question comes FIRST, before the artifacts are counted
// at all. A repository publishes on every surface it declares, so a
// surface this run could not see leaves artifacts nobody asked the
// inventory question about — and answering over the surfaces that did
// respond would seal a rung as established across a population this
// run knowingly did not cover. That is the population law at the
// artifact grain (stele#252), and skipping it is how a repository
// whose stream publishes nothing verifiable still reads as compliant
// on the strength of its releases.
func (inventoryExists) Detect(ev *Evidence) Outcome {
	if unseen := unreached(ev.PublishSurfaces, len(ev.Inventoried)+len(ev.Uninventoried)); unseen != "" {
		return Unevaluated("%s", unseen)
	}

	total := len(ev.Inventoried) + len(ev.Uninventoried)
	if total == 0 {
		// Every surface answered and none of them named an artifact:
		// not the same statement as a surface nobody could see, and a
		// reader told the wrong one of the two goes looking in the
		// wrong place.
		return Unevaluated("a publish was reached, but it named no artifact an inventory could cover")
	}

	if len(ev.Uninventoried) > 0 {
		return Contradicted("%d of %d published artifact(s) have no published inventory: %v",
			len(ev.Uninventoried), total, ev.Uninventoried)
	}

	return Established("a published inventory covers all %d published artifact(s)", total)
}

// unreached names every surface this run could not see and what was
// missing on each, or empty when it saw them all.
//
// The account is owed. "No inventory was found" over a repository
// that publishes one every hour reads as an accusation, and the
// producer cannot act on it without knowing which of the places this
// tool looked came back empty — which was exactly the shape of the
// defect that made every digest-publishing repository permanently
// unevaluated: the answer was correct about what it had looked at and
// never said what that was.
//
// One clause per surface, and inside a surface one per absence,
// because a producer clears them one at a time and the account should
// narrow as they do.
func unreached(surfaces []PublishSurface, reached int) string {
	if len(surfaces) == 0 {
		if reached > 0 {
			// Artifacts with no account of where they came from. The
			// gather always renders one, so this is a caller that
			// assembled evidence by hand — and the artifacts it did
			// reach are still artifacts. Judging them is right; it is
			// the COVERAGE claim that needs an account, and there is no
			// coverage claim to check against nothing.
			return ""
		}

		return "this run looked at no publish surface, so no inventory could be looked for"
	}

	var parts []string

	for _, s := range surfaces {
		if s.Reached() {
			continue
		}

		parts = append(parts, s.Name+": "+strings.Join(s.Missing, "; "))
	}

	if len(parts) == 0 {
		return ""
	}

	msg := strconv.Itoa(len(parts)) + " of the " + strconv.Itoa(len(surfaces)) +
		" surface(s) this repository publishes on yielded no publish this run could see, so whatever they" +
		" publish has not been asked for an inventory — " + strings.Join(parts, " | ")

	if reached > 0 {
		// The dangerous case, said out loud: some surface DID answer,
		// and a reader who stopped at its artifacts would take a
		// partial population for the whole one.
		msg += " — the " + strconv.Itoa(reached) + " artifact(s) another surface published are covered," +
			" which is not the same as this repository's published artifacts being covered"
	}

	return msg
}

type dependenciesScanned struct{}

func (dependenciesScanned) For() string { return "dependency/scanned" }

func (dependenciesScanned) Detect(ev *Evidence) Outcome {
	if !ev.Scanned {
		return Unevaluated("the inventories were not scanned against a vulnerability database in this run")
	}

	if len(ev.Inventoried) == 0 {
		return Contradicted("there was no inventory to scan")
	}

	return Established("the inventories covering %d published artifact(s) were scanned against a vulnerability database,"+
		" identifying %d finding(s)", len(ev.Inventoried), ev.Findings)
}

type findingsTriaged struct{}

func (findingsTriaged) For() string { return "dependency/triaged" }

func (findingsTriaged) Detect(ev *Evidence) Outcome {
	if !ev.Scanned {
		return Unevaluated("no scan ran, so there is no set of findings to have triaged")
	}

	if ev.Findings == 0 {
		// The draft asks that known vulnerabilities be triaged. None
		// known is that requirement met, not dodged.
		return Established("the scan identified no known vulnerability in the publish's inventories")
	}

	if undecided := ev.Findings - ev.Triaged; undecided > 0 {
		return Contradicted("%d of %d advisory finding(s) carry no published triage decision",
			undecided, ev.Findings)
	}

	return Established("all %d advisory finding(s) carry a published triage decision", ev.Findings)
}

type secureIngestion struct{}

func (secureIngestion) For() string { return "dependency/secure-ingestion" }

// Detect judges the draft's level 4 by the one consequence an
// ingestion policy cannot avoid leaving: the interval between a
// version appearing upstream and this producer shipping it.
//
// The asymmetry is the point. A floor of ZERO refutes — some version
// was consumed the moment it appeared, so no ingestion control stood
// between publication and use. But a POSITIVE floor establishes
// nothing: a producer who merely releases slowly leaves exactly the
// same interval as one running a real quarantine, and the two are
// indistinguishable from published artifacts. Holding this rung on a
// positive floor would hand level four to every infrequent releaser —
// a false-positive machine. So a positive floor is UNDETERMINED with
// the floor stated: the reader gets the measurement, never a verdict
// the measurement cannot carry.
func (secureIngestion) Detect(ev *Evidence) Outcome {
	if len(ev.IngestionIntervals) == 0 {
		return Unevaluated("no dependency's publication time was resolved, so the interval between a version" +
			" appearing upstream and this producer taking it is unknown")
	}

	var (
		floor   = time.Duration(1<<63 - 1)
		soonest string
	)

	for pkg, gap := range ev.IngestionIntervals {
		if gap < floor {
			floor, soonest = gap, pkg
		}
	}

	if floor <= 0 {
		return Contradicted("%s was taken at or before its publication time, so nothing stood between the"+
			" version appearing upstream and this producer consuming it", soonest)
	}

	return Unevaluated("no dependency shipped sooner than %s after it was published (%s was the soonest,"+
		" across %d resolved) — consistent with an ingestion control, but a slow release cadence leaves the"+
		" same interval, so the policy's enforcement is not established from this alone",
		floor.Round(time.Hour), soonest, len(ev.IngestionIntervals))
}

type producerControlled struct{}

func (producerControlled) For() string { return "dependency/producer-controlled" }

func (producerControlled) Detect(ev *Evidence) Outcome {
	if ev.DependencySources == nil {
		return Unevaluated("the publish's resolved dependency sources were not read, so where the build" +
			" fetched them from is unknown")
	}

	if len(ev.DependencySources) == 0 {
		return Unevaluated("no resolved dependency source was found to judge")
	}

	var upstream []string

	for src, producerOwned := range ev.DependencySources {
		if !producerOwned {
			upstream = append(upstream, src)
		}
	}

	if len(upstream) > 0 {
		return Contradicted("%d resolved dependency source(s) are upstream rather than producer-controlled: %v",
			len(upstream), upstream)
	}

	if len(ev.UnrecognisedSources) > 0 {
		return Unevaluated("%d dependency source(s) belong to a host this run cannot place — neither an"+
			" ecosystem's default registry nor inside the producer's own forge namespace: %v",
			len(ev.UnrecognisedSources), ev.UnrecognisedSources)
	}

	return Established("all %d resolved dependency source(s) are locations the producer controls",
		len(ev.DependencySources))
}
