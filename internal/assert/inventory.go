// This file: the inventory admissibility judgment (stele#396). An
// inventory another tool produced — an image scanner's SPDX document,
// above all — is handed to stele to be judged before it is published
// or signed over. The rule is sbom.Admit, the one function every
// inventory stele reads or writes passes; this target only reports it
// per document, so the canon's shell copies of the rule go.
//
// What the target can say splits three ways, and the report keeps
// them apart: a document that admits is clean; one carrying no PURL or
// a versionless PURL is a FINDING about that inventory; one that will
// not read or parse is BLINDNESS — the run did not see an inventory at
// all, so it cannot judge, and it never passes over what it could not
// read.

package assert

import (
	"errors"
	"fmt"
	"strings"

	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/sbom"
)

// The assertion vocabulary for inventory findings.
const (
	assertInventoryReadable = "inventory-readable"
	assertInventoryPurls    = "inventory-purls"
	assertVersionedPurl     = "versioned-purl"
)

// InventoryFile is one handed document: the name the caller knows it
// by, its bytes, and the error reading it, if the read failed.
type InventoryFile struct {
	Name    string
	Content []byte
	ReadErr error
}

// Inventories judges each handed inventory by the admissibility rule.
// The population is the handed set against the documents that could be
// read: any document the run could not read leaves it short, which is
// CANNOT_JUDGE, with the unreadable document named as a finding.
func Inventories(files []InventoryFile, j *report.Journal, log Logf) *report.Report {
	readable := 0
	names := make([]string, 0, len(files))

	for _, f := range files {
		names = append(names, f.Name)

		if judgeInventory(j, f, log) {
			readable++
		}
	}

	pop := report.PopulationAgainstDeclared(readable, len(files), "handed inventory documents")

	return report.Seal("assert inventory", strings.Join(names, ","), pop, j,
		report.NoCanary(), report.NoJudgedSet())
}

// judgeInventory judges one document and reports whether it could be
// read at all.
func judgeInventory(j *report.Journal, f InventoryFile, log Logf) bool {
	readable := j.Check(f.Name, assertInventoryReadable)

	if f.ReadErr != nil {
		readable.Diverged(fmt.Sprintf("the document could not be read, so no inventory was judged: %v", f.ReadErr))

		return false
	}

	_, err := sbom.AdmitBytes(f.Content)

	var refusal *sbom.InadmissibleError

	switch {
	case err == nil:
		log("assert: inventory: %s admits", f.Name)
	case errors.As(err, &refusal):
		recordInadmissible(j, f.Name, refusal)
		log("assert: inventory: %s: %v", f.Name, err)
	default:
		// The rule's one other answer: not an SPDX document at all.
		readable.Diverged(fmt.Sprintf("no inventory was judged: %v", err))

		return false
	}

	return true
}

// recordInadmissible names every way the document fails the rule:
// no PURL at all, or each PURL that carries no version.
func recordInadmissible(j *report.Journal, name string, refusal *sbom.InadmissibleError) {
	purls := j.Check(name, assertInventoryPurls)
	if refusal.Total == 0 {
		purls.Diverged("the inventory carries no PURL — an inventory carrying none gates on nothing")
	}

	versioned := j.Check(name, assertVersionedPurl)
	for _, purl := range refusal.Bare {
		versioned.DivergedFrom("a versioned PURL", purl,
			"a versionless PURL is invisible to every scanner, so an inventory carrying one gates on a set it"+
				" cannot see")
	}
}
