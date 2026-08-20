// The blast-radius walk: which published releases ship an affected
// package? Every release's SBOM is scanned and every finding joined
// against the committed VEX decisions by the exact (advisory,
// package, version) triple. The report model carries the bash's
// whole taxonomy as types: a VEX decision is a DECLARED exception
// (its origin is the reviewed statement file), the unfixed
// base-layer background is a DERIVED exception (its remediation is
// the rebuild cadence, not a per-CVE judgment — but an OS finding
// WITH a shipped fix gates like everything else), and a decision
// matching no current finding surfaces as a stale exception: a
// retirement candidate, never an archaeology project.
//
// A decision excuses on its STATUS, never its existence (#222): only
// one that denies the advisory applies is an exit, and that question
// is asked of `vexjoin.Decision.Excuses()` alone. A decision that is
// not an exit is reported as seen — a judgment a human made, stated
// and not silent — over a finding that stays red.
//
// A decision is registered SUBJECT-AGNOSTICALLY (#147): it judges a
// package version, not the release that happens to carry it, so it
// excuses its triple wherever the scan meets it. That is also what
// makes staleness honest here — this walk DISCOVERS rather than
// enumerating obligations, so each scanned subject is recorded as
// swept, and a decision that met nothing across a swept corpus is
// stale by evidence rather than by a fabricated subject.

package assert

import (
	"errors"
	"fmt"
	"strings"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/population"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/sbomwalk"
	"github.com/monumental-archive/stele/internal/triage"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

// BlastRadiusPolicy parameterises the scan walk — the triage classes
// are org policy, never code.
type BlastRadiusPolicy struct {
	// OSEcosystems are the ecosystem substrings classed as OS base
	// layers (matched lowercase). Unfixed findings there are the
	// rebuild cadence's input; fixable ones gate.
	OSEcosystems []string `json:"osEcosystems"`
	// Canary is the known-positive the scan must reproduce, or it
	// cannot see. Optional, but an org with any history should pin one.
	Canary *CanaryPolicy `json:"canary,omitempty"`
}

// CanaryPolicy names the pinned release and the advisory it must
// yield.
type CanaryPolicy struct {
	Repo     *string `json:"repo"`
	Tag      *string `json:"tag"`
	Advisory *string `json:"advisory"`
}

func (b *BlastRadiusPolicy) validate() error {
	if len(b.OSEcosystems) == 0 {
		return errors.New("blastRadius.osEcosystems is empty — every finding would gate, including the base-layer background")
	}

	if b.Canary != nil {
		for name, f := range map[string]*string{
			"repo": b.Canary.Repo, "tag": b.Canary.Tag, "advisory": b.Canary.Advisory,
		} {
			if f == nil || *f == "" {
				return fmt.Errorf("blastRadius.canary.%s is absent or empty", name)
			}
		}
	}

	return nil
}

// BlastRadius walks one org's SBOMs and seals the triage verdict.
func BlastRadius(
	pol *Policy, pop *population.Set, forge gh.Forge, scanner osv.Scanner, decisions *vexjoin.Decisions,
	j *report.Journal, log Logf,
) (*report.Report, error) {
	if pol.BlastRadius == nil {
		return nil, errors.New("assert: the policy declares no blastRadius section")
	}

	org := pop.Owner()

	repos, err := BlastRadiusSubjects.Enumerate(pop)
	if err != nil {
		return nil, err
	}

	w := &blastWalk{pol: pol.BlastRadius, org: org, decisions: decisions, j: j, log: log}

	// Every recorded decision enters the judgment once, before the
	// scan, and SUBJECT-AGNOSTICALLY: a decision judges a package
	// version, not the release that happens to carry it, so it excuses
	// its triple wherever the scan meets it. One that meets nothing is
	// answered by what the walk swept.
	//
	// Whether it excuses is the DECISION's property, answered by
	// vexjoin's one door (#222): excusing on a decision's existence
	// would let a statement whose status ADMITS the advisory clear the
	// finding it admits. A non-excusing decision is still a judgment a
	// human made and recorded, so it is stated rather than dropped —
	// the finding stays red and the report names the decision seen.
	// The status set is not re-derived here; this asks Excuses().
	var notExcusing []string

	all := decisions.All()

	for i := range all {
		if !all[i].Excuses() {
			notExcusing = append(notExcusing, all[i].Key.String()+"="+all[i].Status)

			continue
		}

		// The assertion an exception must meet is DERIVED from the key,
		// never spelled by hand beside the producer of the finding it
		// excuses (docs/vex-join.md).
		j.Except(report.Declared("", all[i].Key.String(), all[i].Origin))
	}

	walk := &sbomwalk.Walk{
		Org: org, SBOMSuffix: *pol.Evidence.SBOMSuffix, Forge: forge, Scanner: scanner,
	}

	if err := walk.Releases(repos, w.inventory); err != nil {
		return nil, err
	}

	covered := report.PopulationFromListing(w.scanned, "SBOMs scanned")

	facts := []report.Fact{}
	if len(notExcusing) > 0 {
		facts = append(facts, report.Fact{
			Name: "decisionsSeenNotExcusing", Value: strings.Join(notExcusing, " "),
		})
	}

	if len(w.missing) > 0 {
		facts = append(facts, report.Fact{Name: "releasesWithoutSBOM", Value: strings.Join(w.missing, " ")})
	}

	return report.Seal("assert blast-radius", pop.Subject(), covered, j,
		w.canary(), report.NoJudgedSet(), facts...), nil
}

type blastWalk struct {
	pol        *BlastRadiusPolicy
	org        string
	decisions  *vexjoin.Decisions
	j          *report.Journal
	log        Logf
	scanned    int
	missing    []string
	canarySeen bool
}

// inventory answers for one thing the shared walk found — the
// blast-radius reading of it. A release with no inventory is recorded
// rather than failed: pre-standup releases predate the obligation,
// and the evidence walk owns the completeness question. A defect the
// walk DID reach is a finding: bytes nothing attests, or a scan that
// read nothing, must never pass for a clean release.
func (w *blastWalk) inventory(inv *sbomwalk.Inventory) error {
	switch inv.Defect {
	case sbomwalk.DefectNoInventory:
		w.missing = append(w.missing, inv.Subject())

		return nil
	case sbomwalk.DefectUnattested:
		w.j.Check(inv.Subject(), inv.Asset+":unattested").
			Diverged("no attestation in the store covers the downloaded SBOM bytes")

		return nil
	case sbomwalk.DefectZeroPackages:
		w.j.Check(inv.Subject(), inv.Asset+":empty-scan").
			Diverged("the SBOM parsed to zero packages — a scan that reads nothing must not report clean")

		return nil
	case sbomwalk.DefectNone:
	}

	w.scanned++
	w.log("assert: blast-radius: %s scanned", inv.Subject())

	if err := w.judge(inv.Subject(), inv.Report); err != nil {
		return err
	}

	// The inventory was read whole: every advisory on this subject was
	// observed, so one a decision names and the scan did not meet was
	// observed to be ABSENT — which is what makes that decision stale
	// by evidence rather than by a fabricated subject.
	w.j.Swept(inv.Subject())

	w.noteCanary(inv.Repo, inv.Tag, inv.Report)

	return nil
}

// judge classifies every finding through the SHARED derivation and
// joins it against the decisions. Neither the classification nor the
// join lives here: this walk and the VEX leg must agree on what a
// finding IS, and two implementations of that drift into disagreeing
// about whether a release was ever covered (internal/triage).
func (w *blastWalk) judge(subject string, out []byte) error {
	pol := &triage.Policy{BaseEcosystems: w.pol.OSEcosystems}

	findings, err := pol.Findings(out)
	if err != nil {
		return fmt.Errorf("assert: %s: %w", subject, err)
	}

	split := triage.Join(findings, w.decisions)

	for i := range findings {
		w.record(subject, &findings[i])
	}

	for i := range split.Rebuild {
		// The perpetual base-layer background: no shipped fix anywhere,
		// so remediation is the next build on a refreshed base digest
		// and a per-advisory decision would decide nothing. DERIVED, so
		// a human cannot widen it.
		w.j.Except(report.Derived(subject, split.Rebuild[i].String(),
			"unfixed OS base-layer package: remediation is the next release on a refreshed base digest"))
	}

	return nil
}

// record adds one finding as a fact carrying no verdict of its own;
// Seal decides what the set of facts amounts to.
func (w *blastWalk) record(subject string, f *triage.Finding) {
	// The finding's ID is the canonical triple — the spelling a
	// decision must use to join it. The detail names the package as
	// the scanner reported it, which is the spelling a reader will
	// find in the manifest; for all but a case-folded ecosystem the
	// two are one string (docs/vex-join.md).
	w.j.Check(subject, f.String()).Diverged(
		fmt.Sprintf("%s affects %s@%s (%s)", f.Key.Advisory(), f.Package, f.Key.Version(), f.Ecosystem))
}

// noteCanary records whether this scan reproduced the declared
// known-positive. A walk that declares one and misses it cannot see,
// which is CANNOT_JUDGE rather than a pass.
func (w *blastWalk) noteCanary(repo, tag string, out []byte) {
	if w.pol.Canary == nil || repo != *w.pol.Canary.Repo || tag != *w.pol.Canary.Tag {
		return
	}

	pol := &triage.Policy{BaseEcosystems: w.pol.OSEcosystems}

	findings, err := pol.Findings(out)
	if err != nil {
		return
	}

	for i := range findings {
		if findings[i].Key.Advisory() == *w.pol.Canary.Advisory {
			w.canarySeen = true

			return
		}
	}
}

func (w *blastWalk) canary() report.Canary {
	if w.pol.Canary == nil {
		return report.NoCanary()
	}

	key := *w.pol.Canary.Advisory + " in " + *w.pol.Canary.Repo + "@" + *w.pol.Canary.Tag
	if w.canarySeen {
		return report.CanarySeen(key)
	}

	return report.CanaryMissed(key)
}
