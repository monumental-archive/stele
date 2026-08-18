// The citation reader: CITATION.cff's `version:` and `date-released:`,
// located through the YAML parser's node positions. The citation is
// release metadata like any other mirror — a stale version there is
// exactly the drift a release commit exists to prevent.

package manifest

import (
	"fmt"

	yaml "go.yaml.in/yaml/v3"
)

// citation is the pair of rewritten scalars: two sites of one type, in
// a struct rather than a bare pair, which is the two values a caller
// transposes without the compiler noticing.
type citation struct {
	version  Site
	released Site
}

// citationSites locates the two rewritten scalars.
//
// Both are required: a CITATION.cff without them is not a shape this
// package invents fields for — the refusal names what is missing and a
// human decides whether the file is malformed or the convention moved.
func citationSites(data []byte) (citation, error) {
	var doc yaml.Node

	if err := yaml.Unmarshal(data, &doc); err != nil {
		return citation{}, fmt.Errorf("manifest: parsing %s: %w", citationFile, err)
	}

	version, err := citationScalar(data, &doc, "version")
	if err != nil {
		return citation{}, err
	}

	released, err := citationScalar(data, &doc, "date-released")
	if err != nil {
		return citation{}, err
	}

	return citation{version: version, released: released}, nil
}

// citationScalar finds one top-level mapping value and its byte range.
func citationScalar(data []byte, doc *yaml.Node, key string) (Site, error) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return Site{}, fmt.Errorf("manifest: %s is not a YAML mapping", citationFile)
	}

	mapping := doc.Content[0]

	// A mapping node's Content alternates key, value.
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		k, v := mapping.Content[i], mapping.Content[i+1]
		if k.Value != key {
			continue
		}

		// Plain scalars only. The canonical file spells both values as
		// plain scalars; a quoted or flowed value means the file is not
		// the shape this reader knows, and splicing into a style it did
		// not measure corrupts the file. Refuse by name instead.
		if v.Kind != yaml.ScalarNode || v.Style != 0 {
			return Site{}, fmt.Errorf(
				"manifest: %s %s is not a plain scalar; rewrite refused for a shape it might corrupt",
				citationFile, key)
		}

		off, err := offsetAt(data, v.Line, v.Column)
		if err != nil {
			return Site{}, fmt.Errorf("manifest: %s %s: %w", citationFile, key, err)
		}

		return Site{
			Path:  citationFile,
			Field: key,
			Value: v.Value,
			off:   off,
			end:   off + len(v.Value),
		}, nil
	}

	return Site{}, fmt.Errorf("manifest: %s carries no %s", citationFile, key)
}

// offsetAt converts the parser's 1-based line and column to a byte
// offset. The YAML parser counts columns in characters over lines it
// already decoded, and a plain scalar in this file is ASCII; a
// non-ASCII line before the value would shift the arithmetic, so the
// conversion walks bytes and refuses if the position falls outside the
// data rather than trusting the multiplication.
func offsetAt(data []byte, line, column int) (int, error) {
	at := 0

	for l := 1; l < line; l++ {
		next := indexByte(data, at, '\n')
		if next < 0 {
			return 0, fmt.Errorf("position %d:%d is outside the file", line, column)
		}

		at = next + 1
	}

	off := at + column - 1
	if off > len(data) {
		return 0, fmt.Errorf("position %d:%d is outside the file", line, column)
	}

	return off, nil
}

// indexByte finds b at or after from.
func indexByte(data []byte, from int, b byte) int {
	for i := from; i < len(data); i++ {
		if data[i] == b {
			return i
		}
	}

	return -1
}
