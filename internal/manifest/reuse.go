// The REUSE reader: the licence a tree declares for itself when it has
// no package manifest to declare it in.
//
// A repository whose artifact is an image and whose tree is a
// Dockerfile has no Cargo.toml, and until this reader its licence was
// whatever the forge's detector made of the licence file. That
// detector reads text, and the text of the GNU licences does not say
// whether "or any later version" applies: measured 2026-11-15 on
// monumental-archive-db, a tree declaring AGPL-3.0-only was published
// as `AGPL-3.0`, an identifier SPDX deprecated because it cannot say
// which of the two it means. REUSE.toml is where such a tree states
// the answer, in SPDX's own spelling.

package manifest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/pelletier/go-toml/v2"
)

// The file, at the tree root by the REUSE specification, and the two
// keys this reader walks.
const (
	reuseFile        = "REUSE.toml"
	reuseAnnotations = "annotations"
	reuseIdentifier  = "SPDX-License-Identifier"
)

// ReuseLicence reads the one licence expression a REUSE.toml declares.
//
// ok is true only when every annotation that names a licence names the
// SAME expression. That is the shape in which the file states a
// licence for the tree; a file annotating different paths with
// different licences states several, and choosing among them — or
// joining them with an operator the author never wrote — would be this
// tool composing a declaration rather than reading one. Absence and
// plurality are both answers, and the caller decides what follows.
//
// Per-file SPDX headers are not read. They can override an annotation
// for the files that carry them, so this is the tree's declaration and
// not an audit of every file in it.
//
//nolint:gocritic // unnamedResult: the value, whether one was declared, and any error
func ReuseLicence(root string) (string, bool, error) {
	data, err := os.ReadFile(filepath.Join(root, reuseFile)) //nolint:gosec // a tree the operator named
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}

	if err != nil {
		return "", false, fmt.Errorf("manifest: reading %s: %w", reuseFile, err)
	}

	var doc map[string]any
	if uerr := toml.Unmarshal(data, &doc); uerr != nil {
		return "", false, fmt.Errorf("manifest: %s is not readable as TOML: %w", reuseFile, uerr)
	}

	declared, err := reuseDeclared(doc)
	if err != nil {
		return "", false, err
	}

	if len(declared) != 1 {
		return "", false, nil
	}

	return declared[0], true, nil
}

// reuseDeclared lists the distinct licence expressions the document's
// annotations name, in the order it names them. A document with no
// annotations key declares none; an annotations key that is not a list
// of tables is a shape this reader does not understand, refused for
// the same reason a mistyped identifier is.
func reuseDeclared(doc map[string]any) ([]string, error) {
	raw, present := doc[reuseAnnotations]
	if !present {
		return nil, nil
	}

	annotations, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("manifest: %s: %s is not a list of tables", reuseFile, reuseAnnotations)
	}

	var declared []string

	for _, entry := range annotations {
		table, isTable := entry.(map[string]any)
		if !isTable {
			return nil, fmt.Errorf("manifest: %s: %s is not a list of tables", reuseFile, reuseAnnotations)
		}

		ids, err := reuseIdentifiers(table[reuseIdentifier])
		if err != nil {
			return nil, err
		}

		for _, id := range ids {
			if !slices.Contains(declared, id) {
				declared = append(declared, id)
			}
		}
	}

	return declared, nil
}

// reuseIdentifiers reads one annotation's licence value. The
// specification allows a string or a list of strings; an annotation
// carrying neither key is a copyright-only annotation and declares no
// licence. Any other type is a file this reader does not understand,
// refused rather than skipped: skipping it could turn two declarations
// into one.
func reuseIdentifiers(value any) ([]string, error) {
	switch v := value.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{v}, nil
	case []any:
		ids := make([]string, 0, len(v))

		for _, item := range v {
			id, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("manifest: %s: a %s list holds a value that is not a string",
					reuseFile, reuseIdentifier)
			}

			ids = append(ids, id)
		}

		return ids, nil
	default:
		return nil, fmt.Errorf("manifest: %s: %s is neither a string nor a list of strings",
			reuseFile, reuseIdentifier)
	}
}
