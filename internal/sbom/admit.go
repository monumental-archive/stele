// The admissibility rule (stele#396): one rule for every inventory
// stele reads or writes, whoever produced it. An inventory is judged
// by the package URLs it carries, because the PURL is what every
// advisory scanner matches on: a package without a versioned PURL is
// invisible to all of them, so an inventory carrying one gates on a
// set it cannot see, and an inventory carrying none gates on nothing.
//
// It was three shell copies in the canon — two after an image scan,
// one reporting (not refusing) on the forge's dependency graph — and
// it is applied here wherever an inventory crosses into or out of
// this tool, so the copies go.

package sbom

import (
	"errors"
	"fmt"
	"strings"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// ErrNotSPDX reports a document the rule cannot read at all: not
// inadmissible, unreadable — a judge reports it as blindness, never
// as a finding about the inventory.
var ErrNotSPDX = errors.New("sbom: not an SPDX JSON document")

// purlRefType is SPDX's reference type for a package URL.
const purlRefType = "purl"

// bareShown bounds how many versionless PURLs a refusal names: enough
// to find them, not a dump of the document.
const bareShown = 3

// InadmissibleError is the rule's refusal: the document, how many PURLs it
// carries, and every one without a version. Typed so a caller judging
// many documents can name each PURL as its own finding; its message is
// the one every caller prints.
type InadmissibleError struct {
	Name  string
	Total int
	Bare  []string
}

func (e *InadmissibleError) Error() string {
	named := ""
	if len(e.Bare) > 0 {
		named = " (" + strings.Join(e.Bare[:min(len(e.Bare), bareShown)], ", ")
		if len(e.Bare) > bareShown {
			named += fmt.Sprintf(", and %d more", len(e.Bare)-bareShown)
		}

		named += ")"
	}

	return fmt.Sprintf(
		"sbom: %s has %d PURLs, %d versionless%s — a versionless PURL is invisible to every scanner, so an"+
			" inventory carrying one gates on a set it cannot see", e.Name, e.Total, len(e.Bare), named,
	)
}

// Admit is the rule: an inventory carrying no PURL, or any PURL
// without a version, is refused as *InadmissibleError.
func Admit(doc *Document) error {
	refusal := &InadmissibleError{Name: doc.Name}

	for _, p := range doc.Packages {
		for _, ref := range p.ExternalRefs {
			if ref.ReferenceType != purlRefType {
				continue
			}

			refusal.Total++

			if !versioned(ref.ReferenceLocator) {
				refusal.Bare = append(refusal.Bare, ref.ReferenceLocator)
			}
		}
	}

	if refusal.Total > 0 && len(refusal.Bare) == 0 {
		return nil
	}

	return refusal
}

// AdmitBytes reads an inventory another tool produced and admits it.
// A document that is not SPDX JSON carries no PURL this rule can see,
// and is refused as such rather than waved through.
func AdmitBytes(raw []byte) (*Document, error) {
	doc, err := jsonx.DecodeForeign[Document](raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotSPDX, err)
	}

	if err := Admit(doc); err != nil {
		return nil, err
	}

	return doc, nil
}

// versioned reports whether a package URL carries a version: the
// purl spec puts it after an `@` in the last path segment, before any
// qualifiers or subpath. An `@` anywhere else (a scope spelled
// unencoded) is not a version.
func versioned(purl string) bool {
	body, _, _ := strings.Cut(purl, "#")
	body, _, _ = strings.Cut(body, "?")

	name := body[strings.LastIndex(body, "/")+1:]

	_, version, found := strings.Cut(name, "@")

	return found && version != ""
}
