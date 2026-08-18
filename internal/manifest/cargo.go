// The Cargo reader: where versions live in a Cargo.toml, found by
// parsing, never by pattern-matching lines. The parser is go-toml's
// low-level one because it reports the byte range of every value in the
// original document — parse for location, splice the bytes, leave every
// other byte (comments, formatting, ordering) exactly as the file's
// owners wrote it.

package manifest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2/unstable"
)

// workspaceTable is Cargo's inheritance root: fields under
// [workspace.package] are what members inherit with `field.workspace
// = true`.
const workspaceTable = "workspace"

// record is one key/value the walk saw: the full dotted key (table
// prefix included) and the value node's location. Inline tables expand
// into one record per member, so `edtf-core = { path = "...", version =
// "..." }` and a `[workspace.dependencies.edtf-core]` sub-table produce
// identical records — the two spellings TOML allows for one fact.
type record struct {
	key    []string
	kind   unstable.Kind
	value  string
	off    int
	end    int
	quoted bool
}

// cargoSites reads a Cargo.toml and returns its kind and version sites.
func cargoSites(data []byte) (string, []Site, error) {
	records, err := cargoRecords(data)
	if err != nil {
		return "", nil, err
	}

	if site, ok := versionSite(records, workspaceTable, "package"); ok {
		sites := append([]Site{site}, dependencySites(records)...)

		return KindCargoWorkspace, sites, nil
	}

	if site, ok := versionSite(records, "package"); ok {
		return KindCargoPackage, []Site{site}, nil
	}

	// A Cargo.toml with a version in neither place is a shape this
	// package does not know — a virtual workspace with per-member
	// versions, or something newer. Refused by name: falling through to
	// "no manifest" while a manifest sits in the tree is how a mirror
	// escapes the rewrite.
	return "", nil, fmt.Errorf(
		"manifest: %s carries neither workspace.package.version nor package.version; "+
			"an unknown manifest shape is added at the kind, not guessed at", cargoFile)
}

// versionSite finds the version key directly under the named table.
func versionSite(records []record, table ...string) (Site, bool) {
	want := append(slices.Clone(table), "version")

	for _, r := range records {
		if !slices.Equal(r.key, want) {
			continue
		}

		return Site{
			Path:   cargoFile,
			Field:  strings.Join(want, "."),
			Value:  r.value,
			off:    r.off,
			end:    r.end,
			quoted: r.quoted,
		}, true
	}

	return Site{}, false
}

// dependencySites finds the internal path-dependency constraints: every
// [workspace.dependencies] entry that carries BOTH `path` and `version`.
// The pairing is the definition — `path` alone is a local dependency
// with no version to mirror, `version` alone is an external dependency
// whose version is its own and must never be rewritten, even when it
// happens to equal the released one.
func dependencySites(records []record) []Site {
	const prefixLen = 2 // workspace, dependencies

	hasPath := make(map[string]bool)

	for _, r := range records {
		if len(r.key) == prefixLen+2 && r.key[0] == workspaceTable && r.key[1] == "dependencies" &&
			r.key[3] == "path" {
			hasPath[r.key[2]] = true
		}
	}

	var sites []Site

	for _, r := range records {
		if len(r.key) == prefixLen+2 && r.key[0] == workspaceTable && r.key[1] == "dependencies" &&
			r.key[3] == "version" && hasPath[r.key[2]] {
			sites = append(sites, Site{
				Path:   cargoFile,
				Field:  "workspace.dependencies." + r.key[2],
				Value:  r.value,
				off:    r.off,
				end:    r.end,
				quoted: r.quoted,
			})
		}
	}

	return sites
}

// cargoRecords walks the document into flat records.
func cargoRecords(data []byte) ([]record, error) {
	parser := &unstable.Parser{}
	parser.Reset(data)

	var table []string

	var records []record

	for parser.NextExpression() {
		expr := parser.Expression()

		// Only three kinds appear at expression level — the parser
		// yields values inside their KeyValue, never bare — so the
		// remaining kinds are unreachable here, not unhandled.
		switch expr.Kind { //nolint:exhaustive // value kinds cannot be expressions
		case unstable.Table:
			table = keyParts(expr.Key())
		case unstable.ArrayTable:
			// Array tables ([[bin]], [[test]]) carry no version sites;
			// their members must not be mistaken for the enclosing table's.
			table = nil
		case unstable.KeyValue:
			key := append(slices.Clone(table), keyParts(expr.Key())...)
			records = append(records, valueRecords(key, expr.Value())...)
		default:
			// Comments locate nothing.
		}
	}

	if err := parser.Error(); err != nil {
		return nil, fmt.Errorf("manifest: parsing %s: %w", cargoFile, err)
	}

	return records, nil
}

// valueRecords turns one value node into records, expanding an inline
// table into one record per member.
func valueRecords(key []string, value *unstable.Node) []record {
	if value.Kind == unstable.InlineTable {
		var records []record

		for it := value.Children(); it.Next(); {
			kv := it.Node()
			member := append(slices.Clone(key), keyParts(kv.Key())...)
			records = append(records, valueRecords(member, kv.Value())...)
		}

		return records
	}

	// Raw is the value's token in the document; for a string that token
	// includes its quotes, and the splice replaces the whole token, so
	// quoting stays the format's business rather than offset arithmetic.
	return []record{{
		key:    key,
		kind:   value.Kind,
		value:  string(value.Data),
		off:    int(value.Raw.Offset),
		end:    int(value.Raw.Offset) + int(value.Raw.Length),
		quoted: value.Kind == unstable.String,
	}}
}

// keyParts flattens a key iterator.
func keyParts(it unstable.Iterator) []string {
	var parts []string

	for it.Next() {
		parts = append(parts, string(it.Node().Data))
	}

	return parts
}

// CargoPackageField reads one string field of a tree's Cargo.toml
// package table, preferring `[workspace.package]` over `[package]` —
// Cargo's own inheritance order, so a workspace member inheriting
// `license.workspace = true` resolves to the same value Cargo would
// give it.
//
// ok is false when the tree has no Cargo.toml, or has one that
// declares the field in neither table. Absence is an answer here: a
// repository with no manifest is a legitimate shape, and the caller
// decides what to do about it.
//
// It goes through this package's one Cargo reader rather than a
// second parse, so a manifest spelling `derive bump` understands and
// a manifest the facts resolver understands cannot diverge. The
// alternative — the bash's — is `taplo get` in one place and version
// regexes in another.
//
//nolint:gocritic // unnamedResult: the value, whether it was declared, and any error
func CargoPackageField(root, field string) (string, bool, error) {
	data, err := os.ReadFile(filepath.Join(root, cargoFile)) //nolint:gosec // a tree the operator named
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}

	if err != nil {
		return "", false, fmt.Errorf("manifest: reading %s: %w", cargoFile, err)
	}

	records, err := cargoRecords(data)
	if err != nil {
		return "", false, err
	}

	for _, table := range [][]string{{workspaceTable, "package"}, {"package"}} {
		if value, ok := stringField(records, append(table, field)); ok {
			return value, true, nil
		}
	}

	return "", false, nil
}

// stringField finds one string-valued key by its full dotted path.
func stringField(records []record, key []string) (string, bool) {
	for _, r := range records {
		if r.kind == unstable.String && slices.Equal(r.key, key) {
			return r.value, true
		}
	}

	return "", false
}
