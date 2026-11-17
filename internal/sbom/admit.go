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
	"fmt"
	"strings"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// purlRefType is SPDX's reference type for a package URL.
const purlRefType = "purl"

// bareShown bounds how many versionless PURLs a refusal names: enough
// to find them, not a dump of the document.
const bareShown = 3

// Admit refuses an inventory carrying no PURL, or any PURL without a
// version, naming the document and the counts.
func Admit(doc *Document) error {
	total := 0

	var bare []string

	for _, p := range doc.Packages {
		for _, ref := range p.ExternalRefs {
			if ref.ReferenceType != purlRefType {
				continue
			}

			total++

			if !versioned(ref.ReferenceLocator) {
				bare = append(bare, ref.ReferenceLocator)
			}
		}
	}

	if total > 0 && len(bare) == 0 {
		return nil
	}

	named := ""
	if len(bare) > 0 {
		named = " (" + strings.Join(bare[:min(len(bare), bareShown)], ", ")
		if len(bare) > bareShown {
			named += fmt.Sprintf(", and %d more", len(bare)-bareShown)
		}

		named += ")"
	}

	return fmt.Errorf(
		"sbom: %s has %d PURLs, %d versionless%s — a versionless PURL is invisible to every scanner, so an"+
			" inventory carrying one gates on a set it cannot see", doc.Name, total, len(bare), named,
	)
}

// AdmitBytes reads an inventory another tool produced and admits it.
// A document that is not SPDX JSON carries no PURL this rule can see,
// and is refused as such rather than waved through.
func AdmitBytes(raw []byte) (*Document, error) {
	doc, err := jsonx.DecodeForeign[Document](raw)
	if err != nil {
		return nil, fmt.Errorf("sbom: not an SPDX JSON document: %w", err)
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
