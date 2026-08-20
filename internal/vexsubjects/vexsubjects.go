// Package vexsubjects derives which published releases one VEX
// decision reaches, and the subjects a signed claim about that
// decision is bound to.
//
// A VEX decision is keyed by the DEPENDENCY (pkg:<type>/…/<name>@
// <version>), never by a release tag, so which releases it concerns
// is derived rather than declared — and it is derived through the
// same join the blast-radius audit runs, from the other direction.
// Blast-radius asks "which findings on this release has nobody
// decided?"; this asks "which releases does this decision decide
// something on?", and both are `triage.Join` over one scanned
// inventory. A second implementation of that question would be two
// answers to "is this release affected", which is the drift the
// shared-derivation law exists to prevent: the attestation would bind
// a decision to releases whose own derived VEX document never carries
// it.
//
// The walk itself is shared too (internal/sbomwalk), including the
// rule that bytes the attestation store does not vouch for are not
// evidence about a release.
package vexsubjects

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/sbomwalk"
	"github.com/monumental-archive/stele/internal/triage"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

// Logf receives the derivation's progress lines.
type Logf func(format string, args ...any)

// Subject is one released file a claim is signed over: the name the
// release publishes it under and the digest its checksum manifest
// pins.
type Subject struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// Release is one release the decision reaches, with the advisories it
// was reached BY — so a reader sees why a release is on this list
// without re-running the join.
type Release struct {
	Repo       string   `json:"repo"`
	Tag        string   `json:"tag"`
	Advisories []string `json:"advisories"`
}

// Subject renders the release in the repo@tag form the org's reports
// and log lines speak.
func (r Release) Subject() string { return r.Repo + "@" + r.Tag }

// Document is what the derivation emits: the decision it was run for,
// the releases it reaches, and every subject a claim over that
// decision is bound to. The subjects are flat and the releases carry
// none: what the signer needs is one manifest, and stating each
// subject twice would be two renderings of one fact.
type Document struct {
	Decision string    `json:"decision"`
	Releases []Release `json:"releases"`
	Subjects []Subject `json:"subjects"`
}

// Deriver holds what the walk needs. Every value is the org's own
// declaration, read from the policy that already carries it: what an
// inventory asset is called, what a checksum manifest is called, and
// which ecosystems are OS base layers.
type Deriver struct {
	Org        string
	SBOMSuffix string
	Checksums  string
	Triage     *triage.Policy
	Forge      gh.Forge
	Scanner    osv.Scanner
	Log        Logf
}

// Affected derives the document for one decision file's decisions
// over the given repositories.
//
// It fails closed on everything the walk could not read: an
// inventory the store does not vouch for and a scan that read nothing
// both refuse the whole derivation rather than quietly shrinking the
// subject set. A subject set that silently lost a release is a signed
// claim that says less than the truth, and nothing downstream can
// tell that from a decision that genuinely reached fewer releases.
func (d *Deriver) Affected(repos []string, decisions *vexjoin.Decisions, origin string) (*Document, error) {
	if decisions.Len() == 0 {
		return nil, fmt.Errorf("vexsubjects: %s decides nothing — a document with no versioned product"+
			" cannot reach a release", origin)
	}

	if d.Checksums == "" {
		return nil, errors.New("vexsubjects: no checksum manifest declared — the subjects have no source")
	}

	w := &sbomwalk.Walk{Org: d.Org, SBOMSuffix: d.SBOMSuffix, Forge: d.Forge, Scanner: d.Scanner}
	a := &affected{d: d, decisions: decisions, byRelease: map[string]map[string]bool{}}

	if err := w.Releases(repos, a.inventory); err != nil {
		return nil, err
	}

	doc := &Document{Decision: origin, Releases: a.releases}

	for i := range a.releases {
		subjects, err := d.subjects(a.releases[i])
		if err != nil {
			return nil, err
		}

		doc.Subjects = append(doc.Subjects, subjects...)
	}

	if len(doc.Releases) == 0 {
		return nil, fmt.Errorf("vexsubjects: no published release ships a package %s names — a claim bound to"+
			" nothing is not signed", origin)
	}

	return doc, nil
}

// affected accumulates the walk's answer: which releases the decision
// decided something on, in walk order, and which advisories did it.
type affected struct {
	d         *Deriver
	decisions *vexjoin.Decisions
	releases  []Release
	// byRelease is the advisory set per release, so one release
	// carrying several inventories that hit the same advisory names it
	// once.
	byRelease map[string]map[string]bool
}

// inventory answers for one thing the shared walk found. A release
// with no inventory is skipped: nothing can be derived from an
// absence, and whether that absence is owed is the evidence walk's
// question, not this one's.
func (a *affected) inventory(inv *sbomwalk.Inventory) error {
	switch inv.Defect {
	case sbomwalk.DefectNoInventory:
		return nil
	case sbomwalk.DefectUnattested:
		return fmt.Errorf("vexsubjects: %s: %s is not vouched for by the attestation store — a subject set"+
			" derived from bytes nobody published is not evidence", inv.Subject(), inv.Asset)
	case sbomwalk.DefectZeroPackages:
		return fmt.Errorf("vexsubjects: %s: %s parsed to zero packages — a scan that reads nothing must not"+
			" report a release unaffected", inv.Subject(), inv.Asset)
	case sbomwalk.DefectNone:
	}

	findings, err := a.d.Triage.Findings(inv.Report)
	if err != nil {
		return fmt.Errorf("vexsubjects: %s: %w", inv.Subject(), err)
	}

	// The SAME join blast-radius runs, asked from the other side:
	// every Decided entry here is this document's decision matching
	// this inventory on the exact (advisory, package, version) triple.
	split := triage.Join(findings, a.decisions)
	if len(split.Decided) == 0 {
		return nil
	}

	seen, known := a.byRelease[inv.Subject()]
	if !known {
		seen = map[string]bool{}
		a.byRelease[inv.Subject()] = seen
		a.releases = append(a.releases, Release{Repo: inv.Repo, Tag: inv.Tag})
	}

	for i := range split.Decided {
		seen[split.Decided[i].Finding.Key.Advisory] = true
	}

	a.releases[len(a.releases)-1].Advisories = sortedKeys(seen)

	a.d.logf("derive: vex-subjects: %s ships %d decided package version(s) via %s",
		inv.Subject(), len(split.Decided), inv.Asset)

	return nil
}

// subjects reads one affected release's checksum manifest into the
// subjects a claim is bound to. A release that ships a named package
// and no manifest refuses the derivation: the claim would name a
// release nothing pins.
func (d *Deriver) subjects(r Release) ([]Subject, error) {
	raw, err := d.Forge.Asset(d.Org, r.Repo, r.Tag, d.Checksums)
	if err != nil {
		return nil, fmt.Errorf("vexsubjects: %s ships a named package but its %s is unreadable: %w",
			r.Subject(), d.Checksums, err)
	}

	var out []Subject

	// "<digest>  <name>", the sha256sum record every manifest in the
	// org is written and read as; anything else on the line is not one.
	const manifestFields = 2

	for line := range strings.SplitSeq(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != manifestFields {
			continue
		}

		out = append(out, Subject{Name: fields[1], SHA256: fields[0]})
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("vexsubjects: %s: %s pins nothing — a claim bound to an empty manifest is"+
			" bound to nothing", r.Subject(), d.Checksums)
	}

	return out, nil
}

// logf emits a progress line when the caller wanted them.
func (d *Deriver) logf(format string, args ...any) {
	if d.Log != nil {
		d.Log(format, args...)
	}
}

// sortedKeys renders a set deterministically — the derived document
// is an input to a signature, so its bytes may not depend on map
// iteration.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}
