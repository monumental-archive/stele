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

import "time"

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

func (inventoryExists) Detect(ev *Evidence) Outcome {
	total := len(ev.Inventoried) + len(ev.Uninventoried)
	if total == 0 {
		return Unevaluated("no released artifact was reached, so no inventory could be looked for")
	}

	if len(ev.Uninventoried) > 0 {
		return Contradicted("%d of %d released artifact(s) have no published inventory: %v",
			len(ev.Uninventoried), total, ev.Uninventoried)
	}

	return Established("a published inventory covers all %d released artifact(s)", total)
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

	return Established("the inventories covering %d artifact(s) were scanned against a vulnerability database,"+
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
		return Established("the scan identified no known vulnerability in the release's inventories")
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
		return Unevaluated("the release's resolved dependency sources were not read, so where the build" +
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
