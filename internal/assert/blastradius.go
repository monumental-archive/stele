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

package assert

import (
	"errors"
	"fmt"
	"strings"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/report"
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
	pol *Policy, pop Population, forge gh.Forge, scanner osv.Scanner, decisions *vexjoin.Decisions, log Logf,
) (*report.Report, error) {
	if pol.BlastRadius == nil {
		return nil, errors.New("assert: the policy declares no blastRadius section")
	}

	org, repos, err := pop.Resolve(forge)
	if err != nil {
		return nil, err
	}

	w := &blastWalk{
		pol: pol.BlastRadius, evidence: pol.Evidence, org: org,
		forge: forge, scanner: scanner, decisions: decisions, log: log,
		used: map[vexjoin.Key]bool{},
	}

	for _, repo := range repos {
		if err := w.repo(repo); err != nil {
			return nil, err
		}
	}

	w.staleDecisions()

	covered := report.PopulationFromListing(w.scanned, "SBOMs scanned")

	facts := []report.Fact{}
	if len(w.missing) > 0 {
		facts = append(facts, report.Fact{Name: "releasesWithoutSBOM", Value: strings.Join(w.missing, " ")})
	}

	return report.Seal("assert blast-radius", pop.Subject(), covered, w.findings, w.exceptions,
		w.canary(), report.NoJudgedSet(), facts...), nil
}

type blastWalk struct {
	pol        *BlastRadiusPolicy
	evidence   *EvidencePolicy
	org        string
	forge      gh.Forge
	scanner    osv.Scanner
	decisions  *vexjoin.Decisions
	log        Logf
	scanned    int
	missing    []string
	findings   []report.Finding
	exceptions []report.Exception
	used       map[vexjoin.Key]bool
	canarySeen bool
}

func (w *blastWalk) repo(repo string) error {
	tags, err := w.forge.ReleaseTags(w.org, repo)
	if err != nil {
		return fmt.Errorf("assert: releases of %s/%s: %w", w.org, repo, err)
	}

	for _, tag := range tags {
		if err := w.release(repo, tag); err != nil {
			return err
		}
	}

	return nil
}

func (w *blastWalk) release(repo, tag string) error {
	subject := repo + "@" + tag

	assets, err := w.forge.ReleaseAssets(w.org, repo, tag)
	if err != nil {
		return fmt.Errorf("assert: assets of %s: %w", subject, err)
	}

	var sboms []string

	for _, a := range assets {
		if strings.HasSuffix(a, *w.evidence.SBOMSuffix) {
			sboms = append(sboms, a)
		}
	}

	if len(sboms) == 0 {
		// Pre-standup releases are recorded, not failed — they predate
		// the obligation. The evidence walk owns the completeness
		// question; this walk scans what exists.
		w.missing = append(w.missing, subject)

		return nil
	}

	for _, name := range sboms {
		if err := w.scanSBOM(repo, tag, name); err != nil {
			return err
		}
	}

	return nil
}

// scanSBOM downloads, trust-checks and scans one SBOM asset.
func (w *blastWalk) scanSBOM(repo, tag, name string) error {
	subject := repo + "@" + tag

	sbom, err := w.forge.Asset(w.org, repo, tag, name)
	if err != nil {
		return fmt.Errorf("assert: sbom of %s: %w", subject, err)
	}

	// Trust nothing downloaded: the asset must be one the attestation
	// store vouches for. Presence depth, like the evidence walk; the
	// cryptographic judgment is the full-depth leg.
	stored, err := w.forge.Attestations(w.org, repo, chain.SHA256Hex(sbom))
	if err != nil {
		return fmt.Errorf("assert: store for %s sbom: %w", subject, err)
	}

	if len(stored) == 0 {
		w.finding(subject, name+":unattested", "no attestation in the store covers the downloaded SBOM bytes")

		return nil
	}

	out, err := w.scanner.Scan(sbom)
	if errors.Is(err, osv.ErrZeroPackages) {
		w.finding(subject, name+":empty-scan",
			"the SBOM parsed to zero packages — a scan that reads nothing must not report clean")

		return nil
	}

	if err != nil {
		return fmt.Errorf("assert: scanning %s: %w", subject, err)
	}

	w.scanned++
	w.log("assert: blast-radius: %s scanned", subject)

	if err := w.judge(subject, out); err != nil {
		return err
	}

	w.noteCanary(repo, tag, out)

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
		w.exceptions = append(w.exceptions, report.Derived(subject, split.Rebuild[i].String(),
			"unfixed OS base-layer package: remediation is the next release on a refreshed base digest"))
	}

	for i := range split.Decided {
		d := &split.Decided[i]
		w.used[d.Finding.Key] = true
		w.exceptions = append(w.exceptions, report.Declared(subject, d.Finding.String(), d.Decision.Origin))
	}

	return nil
}

// record adds one finding as a fact carrying no verdict of its own;
// Seal decides what the set of facts amounts to.
func (w *blastWalk) record(subject string, f *triage.Finding) {
	w.findings = append(w.findings, report.Finding{
		Subject: subject, Assertion: f.String(),
		Detail: fmt.Sprintf("%s affects %s@%s (%s)", f.Key.Advisory, f.Key.Package, f.Key.Version, f.Ecosystem),
	})
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
		if findings[i].Key.Advisory == *w.pol.Canary.Advisory {
			w.canarySeen = true

			return
		}
	}
}

// staleDecisions surfaces every decision that matched no current
// finding — retirement candidates by name. The exception's subject
// matches nothing, so Seal lists it stale.
func (w *blastWalk) staleDecisions() {
	all := w.decisions.All()
	for i := range all {
		d := &all[i]
		if !w.used[d.Key] {
			w.exceptions = append(w.exceptions, report.Declared(
				"(no current finding)",
				d.Key.Advisory+":"+d.Key.Package+"@"+d.Key.Version,
				d.Origin))
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

func (w *blastWalk) finding(subject, assertion, detail string) {
	w.findings = append(w.findings, report.Finding{Subject: subject, Assertion: assertion, Detail: detail})
}
