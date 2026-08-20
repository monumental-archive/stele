// Package sbomwalk is the one traversal from an org's published
// releases to their scanned inventories: which releases carry SBOM
// assets, those assets' bytes, the store's word that the bytes are
// the published ones, and the scanner's report over them.
//
// It exists because two legs ask different questions of the same
// walk — `assert blast-radius` asks which findings nobody decided,
// `derive vex-subjects` asks which releases one decision reaches —
// and two traversals of one body of evidence drift into disagreeing
// about what was looked at (the .github#434 law: share the
// definition, never share the derivation). What a walk MEANS stays
// with its caller: nothing here classifies a finding, excuses one, or
// decides what a defect costs. The visitor is handed what was found
// and answers for it.
package sbomwalk

import (
	"errors"
	"fmt"
	"strings"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/osv"
)

// Defect names what the walk could not deliver about one inventory.
// It is a fact, never a verdict: whether an unattested inventory is a
// finding, a refusal or a skip is the caller's judgment, and the walk
// stating it would decide two callers' policies from one place.
type Defect string

const (
	// DefectNone is an inventory fetched, trusted and scanned.
	DefectNone Defect = ""
	// DefectNoInventory is a release carrying no SBOM asset at all —
	// reported per RELEASE, with no asset name.
	DefectNoInventory Defect = "no-inventory"
	// DefectUnattested is an inventory the attestation store does not
	// vouch for: bytes downloaded that nothing published.
	DefectUnattested Defect = "unattested"
	// DefectZeroPackages is an inventory the scanner read as empty — a
	// scan that reads nothing must not report clean.
	DefectZeroPackages Defect = "zero-packages"
)

// Inventory is one thing the walk reached: an SBOM asset with the
// scanner's report over it, or a release-shaped absence.
type Inventory struct {
	Repo string
	Tag  string
	// Asset is the SBOM asset's name, empty for DefectNoInventory.
	Asset string
	// Report is the scanner's JSON, non-nil only when Defect is
	// DefectNone — a caller cannot reach a judgment through bytes the
	// walk did not obtain.
	Report []byte
	Defect Defect
}

// Subject renders the release this inventory belongs to, in the
// repo@tag form every report and log line in the org speaks.
func (i *Inventory) Subject() string { return i.Repo + "@" + i.Tag }

// Walk holds what the traversal needs. SBOMSuffix is the org's
// spelling of an inventory asset, supplied by the caller's policy —
// which files are inventories is an org fact, not this package's.
type Walk struct {
	Org        string
	SBOMSuffix string
	Forge      gh.Forge
	Scanner    osv.Scanner
}

// Visit answers for one thing the walk found. Returning an error
// stops the walk: a caller that treats a defect as fatal says so by
// returning, and one that records it says so by not.
type Visit func(*Inventory) error

// Releases walks every release of every named repository and calls
// visit once per SBOM asset, plus once per release that ships none.
// The order is the forge's listing order throughout — a walk that
// sorted would report a different traversal than it performed.
func (w *Walk) Releases(repos []string, visit Visit) error {
	if w.SBOMSuffix == "" {
		return errors.New("sbomwalk: no SBOM suffix declared — every asset or none would be an inventory")
	}

	for _, repo := range repos {
		tags, err := w.Forge.ReleaseTags(w.Org, repo)
		if err != nil {
			return fmt.Errorf("sbomwalk: releases of %s/%s: %w", w.Org, repo, err)
		}

		for _, tag := range tags {
			if rerr := w.release(repo, tag, visit); rerr != nil {
				return rerr
			}
		}
	}

	return nil
}

// release visits one release's inventories, or its absence of them.
func (w *Walk) release(repo, tag string, visit Visit) error {
	assets, err := w.Forge.ReleaseAssets(w.Org, repo, tag)
	if err != nil {
		return fmt.Errorf("sbomwalk: assets of %s/%s@%s: %w", w.Org, repo, tag, err)
	}

	found := 0

	for _, name := range assets {
		if !strings.HasSuffix(name, w.SBOMSuffix) {
			continue
		}

		found++

		inv, ierr := w.inventory(repo, tag, name)
		if ierr != nil {
			return ierr
		}

		if verr := visit(inv); verr != nil {
			return verr
		}
	}

	if found == 0 {
		return visit(&Inventory{Repo: repo, Tag: tag, Defect: DefectNoInventory})
	}

	return nil
}

// inventory fetches one SBOM asset, holds it against the store, and
// scans it. Trust before scan, always: bytes nothing published are
// not evidence about a release, whatever they contain.
func (w *Walk) inventory(repo, tag, name string) (*Inventory, error) {
	inv := &Inventory{Repo: repo, Tag: tag, Asset: name}

	sbom, err := w.Forge.Asset(w.Org, repo, tag, name)
	if err != nil {
		return nil, fmt.Errorf("sbomwalk: %s of %s/%s@%s: %w", name, w.Org, repo, tag, err)
	}

	stored, err := w.Forge.Attestations(w.Org, repo, chain.SHA256Hex(sbom))
	if err != nil {
		return nil, fmt.Errorf("sbomwalk: store for %s of %s/%s@%s: %w", name, w.Org, repo, tag, err)
	}

	if len(stored) == 0 {
		inv.Defect = DefectUnattested

		return inv, nil
	}

	report, err := w.Scanner.Scan(sbom)

	switch {
	case errors.Is(err, osv.ErrZeroPackages):
		inv.Defect = DefectZeroPackages

		return inv, nil
	case err != nil:
		return nil, fmt.Errorf("sbomwalk: scanning %s of %s/%s@%s: %w", name, w.Org, repo, tag, err)
	}

	inv.Report = report

	return inv, nil
}
