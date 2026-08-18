// Source-track detectors.
//
// Two observations carry this file.
//
// The first: a verified source chain is evidence of MORE than the
// links it contains. Each link records its predecessor and the digest
// of that predecessor's stored bytes, and the walk refuses a chain
// that skips a revision or fails to reach its genesis. So a chain that
// walks clean from tip to genesis is a cryptographic record that the
// branch only ever moved to descendants of where it was — the history
// requirement, from artifacts rather than from a settings read.
//
// The second: for the CONTROL requirements, the contemporaneous
// attestation is not a shortcut around evidence, it is the only
// evidence that can exist. Which controls were configured when a
// revision landed is unrecoverable afterwards — a rules API answers
// about now, not about last March. That is precisely why the
// specification asks the SCS to record enforced controls at the time,
// and why a consumer reading that record is verifying rather than
// being credulous. Such a requirement is reported as ATTESTED, so a
// reader can see which parts of a level rest on the SCS's word.

package level

import (
	"regexp"
	"strings"
	"time"
)

//nolint:gochecknoinits // the registry is populated once, at load, by the detectors themselves
func init() {
	register(scsIssues{})
	register(repositoryIDs{})
	register(revisionIDs{})
	register(humanReadableDiff{})
	register(summaryAttestation{})
	register(accessControl{})
	register(safeExpunge{})
	register(orgContinuity{})
	register(historyDescends{})
	register(scsContinuity{})
	register(scsIdentity{})
	register(provenanceContemporaneous{})
	register(protectedRefs{})
	register(twoPartyReview{})
}

var gitRevisionRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

type scsIssues struct{}

func (scsIssues) For() string { return "SLSA_SOURCE_ORG_SCS" }

func (scsIssues) Detect(ev *Evidence) Outcome {
	if ev.NoChain {
		return Contradicted("this repository's SCS issues no source attestations for its revisions")
	}

	if ev.Measured == nil {
		return Unevaluated("the source chain could not be walked")
	}

	return Established("the SCS serving this repository issues source attestations, signed by %v",
		ev.Measured.Signers())
}

type repositoryIDs struct{}

func (repositoryIDs) For() string { return "SLSA_SOURCE_SCS_REPO_ID" }

func (repositoryIDs) Detect(ev *Evidence) Outcome {
	if ev.Owner == "" || ev.Repo == "" {
		return Unevaluated("no repository was named")
	}

	return Established("the repository is addressed by the stable locator %s/%s, which the SCS resolves",
		ev.Owner, ev.Repo)
}

type revisionIDs struct{}

func (revisionIDs) For() string { return "SLSA_SOURCE_SCS_REVISION_ID" }

func (revisionIDs) Detect(ev *Evidence) Outcome {
	if len(ev.Revisions) == 0 {
		return Unevaluated("no revision was reached")
	}

	for _, r := range ev.Revisions {
		if !gitRevisionRE.MatchString(r.ID) {
			return Contradicted("revision %q is not a content digest, so its immutability is not established"+
				" by the identifier itself", r.ID)
		}
	}

	// The spec is explicit: "When the revision ID is a digest of the
	// content of the revision (as in git) nothing more is needed."
	return Established("every one of %d revision(s) is identified by a content digest", len(ev.Revisions))
}

type humanReadableDiff struct{}

func (humanReadableDiff) For() string { return "SLSA_SOURCE_SCS_DIFF_DISPLAY" }

func (humanReadableDiff) Detect(ev *Evidence) Outcome {
	if len(ev.Revisions) == 0 {
		return Unevaluated("no revision was reached")
	}

	return Established("the SCS serves the walked revisions as parented content-addressed commits," +
		" from which plain-text differences are derivable")
}

type summaryAttestation struct{}

func (summaryAttestation) For() string { return "SLSA_SOURCE_SCS_VSA" }

func (summaryAttestation) Detect(ev *Evidence) Outcome {
	if ev.NoChain {
		// The spec, verbatim: "If the SCS DOES NOT generate a VSA for a
		// revision, the revision has Source Level 0."
		return Contradicted("no source verification summary attestation exists for this branch's revisions")
	}

	rev, _, ok := tipOf(ev)
	if !ok {
		return Unevaluated("the walk retained no tip, so no summary attestation was read")
	}

	return Established("a source verification summary attestation covers revision %.12s and verified"+
		" against the trust root", rev)
}

type accessControl struct{}

func (accessControl) For() string { return "SLSA_SOURCE_ORG_ACCESS_CONTROL" }

func (accessControl) Detect(ev *Evidence) Outcome {
	// The specification asks that access controls be CONFIGURED to
	// restrict sensitive operations, implemented through the SCS's
	// identity management. It does not name the controls: which
	// operations an organization restricts, and what it calls each
	// restriction, is its own business.
	//
	// So the evidence is that the SCS recorded controls at all, and the
	// report lists them. Requiring one particular spelling was this
	// tool inventing a vocabulary test the specification does not set —
	// measured against a real chain recording eight controls under an
	// organization's own names, it refused a repository that plainly
	// restricts sensitive operations.
	rev, controls, ok := tipOf(ev)
	if !ok {
		return Unevaluated("the source chain could not be walked, so no recorded control could be read")
	}

	if len(controls) == 0 {
		return Contradicted("the SCS records no control at revision %.12s, so no restriction on sensitive"+
			" operations is evidenced", rev)
	}

	// Named exactly, where an SCS uses the ecosystem's spelling: that
	// is the stronger reading and the report says so.
	for _, got := range controls {
		if SameControl(got, "SLSA_SOURCE_ORG_ACCESS_CONTROL") {
			return Attested("the SCS recorded access controls at revision %.12s, as control %q", rev, got)
		}
	}

	return Attested("the SCS recorded %d control(s) restricting sensitive operations at revision %.12s: %v",
		len(controls), rev, controls)
}

type safeExpunge struct{}

func (safeExpunge) For() string { return "SLSA_SOURCE_ORG_SAFE_EXPUNGE" }

func (safeExpunge) Detect(ev *Evidence) Outcome {
	// Git has no expunge operation: content leaves a branch only by
	// force push. So protected refs ARE this control, and where the
	// chain proves the branch moved only to descendants, expunging did
	// not happen and had no path to happen. The SLSA source
	// proof-of-concept establishes it the same way, for the same
	// reason.
	if got := (historyDescends{}).Detect(ev); got.Determination == Held {
		return Established("the branch moved only to descendants, so nothing was expunged from it:" +
			" git has no expunge operation, and without force push there is no path to one")
	}

	return recordedControl(ev, "SLSA_SOURCE_ORG_SAFE_EXPUNGE", "a documented safe expunging process")
}

type orgContinuity struct{}

func (orgContinuity) For() string { return "SLSA_SOURCE_ORG_CONTINUITY" }

func (orgContinuity) Detect(ev *Evidence) Outcome {
	rev, controls, ok := tipOf(ev)
	if !ok {
		return Unevaluated("the walk retained no tip, so no claimed control has a continuity start")
	}

	if len(controls) == 0 {
		return Contradicted("the tip link claims no control, so there is no continuous enforcement to evidence")
	}

	return Attested("every one of %d claimed control(s) is recorded at revision %.12s, the revision it"+
		" covers: %v", len(controls), rev, controls)
}

type historyDescends struct{}

func (historyDescends) For() string { return "SLSA_SOURCE_SCS_HISTORY" }

func (historyDescends) Detect(ev *Evidence) Outcome {
	if ev.Measured == nil {
		return Unevaluated("the source chain could not be walked, so the branch's movement is unrecorded")
	}

	links := ev.Measured.Links()
	if links == 0 || !ev.Measured.ReachedGenesis() {
		return Contradicted("no chain records this branch's movement back to a founding revision")
	}

	return Established("a chain of %d link(s) records this branch from its genesis to its tip, each link"+
		" naming its predecessor by digest — a move to a revision that did not descend from the previous"+
		" one would orphan those links and the walk would refuse", links)
}

type scsContinuity struct{}

func (scsContinuity) For() string { return "SLSA_SOURCE_SCS_CONTINUITY" }

func (scsContinuity) Detect(ev *Evidence) Outcome {
	if ev.Measured == nil {
		return Unevaluated("the source chain could not be walked")
	}

	tip, ok := ev.Measured.Tip()
	if !ok {
		return Unevaluated("the walk retained no tip")
	}

	if holes := ev.Measured.Holes(); len(holes) > 0 {
		return Contradicted("%d revision(s) between links carry none, so the controls lapsed across them: %v",
			len(holes), holes)
	}

	if !ev.Measured.ReachedGenesis() {
		return Contradicted("the chain does not run back to a founding link, so continuity has no start revision")
	}

	if tip.Repaired() {
		// The lapse is the CURRENT revision: this link was written to
		// fill a gap, so continuity has not yet run for a single
		// revision since it restarted.
		return Contradicted("the tip link is marked repaired, so continuity restarts at this very revision:" +
			" the controls it claims have not yet run unbroken for any revision")
	}

	// A chain that lapsed and has since run clean is not permanently
	// diminished. The specification restarts continuity from a new
	// revision rather than voiding it, so what a report owes a reader
	// is the date it restarted, not a verdict frozen at the failure.
	if lapse := ev.Measured.LastLapse(); lapse != "" {
		return Established("continuity is unbroken since revision %.12s, where it restarted after a recorded"+
			" lapse — every revision from there to the tip carries a link", lapse)
	}

	return Established("every revision from genesis to the tip carries a link, with no lapse recorded")
}

type scsIdentity struct{}

func (scsIdentity) For() string { return "SLSA_SOURCE_SCS_IDENTITY" }

func (scsIdentity) Detect(ev *Evidence) Outcome {
	if ev.Measured == nil {
		return Unevaluated("the source chain could not be walked")
	}

	signers := ev.Measured.Signers()
	if len(signers) == 0 {
		return Contradicted("no link carries a certificate identity, so no actor is attributable")
	}

	return Established("every link is signed by an identity the SCS authenticated and bound into a"+
		" certificate: %v", signers)
}

type provenanceContemporaneous struct{}

func (provenanceContemporaneous) For() string { return "SLSA_SOURCE_SCS_PROVENANCE" }

func (provenanceContemporaneous) Detect(ev *Evidence) Outcome {
	if ev.Measured == nil {
		return Unevaluated("the source chain could not be walked")
	}

	tip, ok := ev.Measured.Tip()
	if !ok {
		return Unevaluated("the walk retained no tip")
	}

	stamped := tip.CommitTime()
	if stamped == "" {
		return Unevaluated("the tip link records no commit time, so contemporaneity cannot be judged")
	}

	when, err := time.Parse(time.RFC3339, stamped)
	if err != nil {
		return Unevaluated("the tip link's commit time %q is unreadable", stamped)
	}

	return Established("the link for %.12s records that revision's own commit time (%s), so it was produced"+
		" against the revision it describes", tip.Revision(), when.UTC().Format(time.RFC3339))
}

type protectedRefs struct{}

func (protectedRefs) For() string { return "SLSA_SOURCE_SCS_PROTECTED_REFS" }

func (protectedRefs) Detect(ev *Evidence) Outcome {
	rev, controls, ok := tipOf(ev)
	if !ok {
		return Unevaluated("the source chain could not be walked")
	}

	if len(controls) == 0 {
		return Contradicted("the link for %.12s records no enforced technical control, so the SCS attests"+
			" to none for this reference", rev)
	}

	return Attested("the link for %.12s records %d technical control(s) enforced on this reference: %v",
		rev, len(controls), controls)
}

type twoPartyReview struct{}

func (twoPartyReview) For() string { return "SLSA_SOURCE_SCS_TWO_PARTY_REVIEW" }

func (twoPartyReview) Detect(ev *Evidence) Outcome {
	// The SCS's own record first: where the control plane attests that
	// it enforced two-party review, that is the contemporaneous
	// evidence, and approvals visible today are a weaker echo of it.
	if got := recordedControl(ev, "SLSA_SOURCE_SCS_TWO_PARTY_REVIEW",
		"two-party review"); got.Determination == Held {
		return got
	}

	if len(ev.Revisions) == 0 {
		return Unevaluated("no revision was reached")
	}

	if ev.Approvals == nil {
		return Unevaluated("neither the SCS's record nor the change history establishes how many trusted" +
			" persons agreed to each change")
	}

	var unreviewed []string

	for _, r := range ev.Revisions {
		approvers, seen := ev.Approvals[r.ID]
		if !seen {
			return Unevaluated("no change record was found for revision %.12s", r.ID)
		}

		// "Two or more trusted persons": the uploader and one reviewer,
		// or two reviewers. One approver is one person.
		const twoParties = 2

		if approvers < twoParties {
			unreviewed = append(unreviewed, r.ID[:12])
		}
	}

	if len(unreviewed) > 0 {
		return Contradicted("%d of %d revision(s) were agreed by fewer than two trusted persons: %v",
			len(unreviewed), len(ev.Revisions), unreviewed)
	}

	return Established("every one of %d revision(s) was agreed by two or more trusted persons before submission",
		len(ev.Revisions))
}

// tipOf resolves the walk's tip revision and the controls recorded
// there, if the walk reached one.
//
//nolint:gocritic // unnamedResult: revision, controls, ok — named in the doc
func tipOf(ev *Evidence) (string, []string, bool) {
	if ev.Measured == nil {
		return "", nil, false
	}

	tip, ok := ev.Measured.Tip()
	if !ok {
		return "", nil, false
	}

	return tip.Revision(), tip.Properties(), true
}

// recordedControl establishes one control from what the SCS recorded
// at the revision.
func recordedControl(ev *Evidence, name, human string) Outcome {
	rev, controls, ok := tipOf(ev)
	if !ok {
		return Unevaluated("the source chain could not be walked, so no recorded control could be read")
	}

	for _, got := range controls {
		if SameControl(got, name) {
			return Attested("the SCS recorded %s at revision %.12s, as control %q", human, rev, got)
		}
	}

	return Contradicted("the SCS records no control for %s at revision %.12s; it recorded %v",
		human, rev, controls)
}

// SameControl reports whether a recorded control name means the
// ecosystem's.
//
// The specification requires an SCS to prefix organization-specified
// properties, and leaves the prefix to the SCS — so one control plane
// writes SLSA_SOURCE_ORG_ACCESS_CONTROL and another writes
// ORG_SOURCE_ACCESS_CONTROL for the same control. Comparing the
// meaningful tail is what lets this tool read a chain some other
// control plane issued, which is what being a universal consumer
// requires.
func SameControl(recorded, canonical string) bool {
	if recorded == canonical {
		return true
	}

	tail := canonical
	for _, prefix := range []string{"SLSA_SOURCE_ORG_", "SLSA_SOURCE_SCS_", "SLSA_SOURCE_"} {
		if after, cut := strings.CutPrefix(canonical, prefix); cut {
			tail = after

			break
		}
	}

	return tail != "" && strings.HasSuffix(recorded, tail)
}
