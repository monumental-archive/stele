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
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/report"
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

	org, repos, err := pop.resolve(forge)
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

	return report.Seal("assert blast-radius", pop.Subject(), covered, w.findings, w.exceptions, w.canary(), facts...), nil
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

	return w.judge(repo, tag, subject, out)
}

// The scanner's report shape — foreign, read leniently.
type scanReport struct {
	Results []struct {
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID       string `json:"id"`
				Affected []struct {
					Ranges []struct {
						Events []struct {
							Fixed string `json:"fixed"`
						} `json:"events"`
					} `json:"ranges"`
				} `json:"affected"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

// judge classifies every finding and joins it against the decisions.
func (w *blastWalk) judge(repo, tag, subject string, out []byte) error {
	decoded, err := jsonx.DecodeForeign[scanReport](out)
	if err != nil {
		return fmt.Errorf("assert: scanner report for %s: %w", subject, err)
	}

	for _, res := range decoded.Results {
		for _, pkg := range res.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				w.judgeOne(repo, tag, subject, pkg.Package.Name, pkg.Package.Version, pkg.Package.Ecosystem, vuln.ID,
					fixable(vuln))
			}
		}
	}

	return nil
}

type vulnEntry = struct {
	ID       string `json:"id"`
	Affected []struct {
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

func fixable(v vulnEntry) bool {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return true
				}
			}
		}
	}

	return false
}

func (w *blastWalk) judgeOne(repo, tag, subject, pkg, version, ecosystem, advisory string, fix bool) {
	key := vexjoin.Key{Advisory: advisory, Package: pkg, Version: version}
	assertion := advisory + ":" + pkg + "@" + version
	isOS := w.osEcosystem(ecosystem)

	w.findings = append(w.findings, report.Finding{
		Subject: subject, Assertion: assertion,
		Detail: fmt.Sprintf("%s affects %s@%s (%s)", advisory, pkg, version, ecosystem),
	})

	switch {
	case isOS && !fix:
		// The perpetual base-layer background: no shipped fix anywhere,
		// remediation is the rebuild cadence — a per-CVE decision would
		// decide nothing. Derived, so a human cannot widen it.
		w.exceptions = append(w.exceptions, report.Derived(subject, assertion,
			"unfixed OS base-layer package: remediation is the next release on a refreshed base digest"))
	case w.decisions.Has(key):
		all := w.decisions.All()
		for i := range all {
			d := &all[i]
			if d.Key == key {
				w.used[key] = true
				w.exceptions = append(w.exceptions, report.Declared(subject, assertion, d.Origin))

				break
			}
		}
	}

	if w.pol.Canary != nil && repo == *w.pol.Canary.Repo && tag == *w.pol.Canary.Tag &&
		advisory == *w.pol.Canary.Advisory {
		w.canarySeen = true
	}
}

func (w *blastWalk) osEcosystem(ecosystem string) bool {
	lower := strings.ToLower(ecosystem)
	for _, e := range w.pol.OSEcosystems {
		if strings.Contains(lower, e) {
			return true
		}
	}

	return false
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
