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

// packageTable is a package's own table, [package].
const packageTable = "package"

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

	if site, ok := versionSite(records, workspaceTable, packageTable); ok {
		sites := append([]Site{site}, dependencySites(records)...)

		return KindCargoWorkspace, sites, nil
	}

	if site, ok := versionSite(records, packageTable); ok {
		return KindCargoPackage, []Site{site}, nil
	}

	// A Cargo.toml with a version in neither place is a shape this
	// package does not know — a virtual workspace with per-member
	// versions, or something newer. Refused by name: falling through to
	// "no manifest" while a manifest sits in the tree is how a mirror
	// escapes the rewrite.
	return "", nil, fmt.Errorf(
		"manifest: %s carries neither workspace.package.version nor package.version; "+
			"an unknown manifest shape is added at the kind, not guessed at", cargoFile,
	)
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
	records, _, err := cargoDocument(data)

	return records, err
}

// cargoDocument walks the document into flat records and the table
// headers it declares — a table can be declared with no keys at all
// (`[workspace]` alone), and only its header says it exists.
func cargoDocument(data []byte) ([]record, [][]string, error) {
	parser := &unstable.Parser{}
	parser.Reset(data)

	var table []string

	var (
		records []record
		tables  [][]string
	)

	for parser.NextExpression() {
		expr := parser.Expression()

		// Only three kinds appear at expression level — the parser
		// yields values inside their KeyValue, never bare — so the
		// remaining kinds are unreachable here, not unhandled.
		switch expr.Kind { //nolint:exhaustive // value kinds cannot be expressions
		case unstable.Table:
			table = keyParts(expr.Key())
			tables = append(tables, table)
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
		return nil, nil, fmt.Errorf("manifest: parsing %s: %w", cargoFile, err)
	}

	return records, tables, nil
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

	for _, table := range [][]string{{workspaceTable, packageTable}, {packageTable}} {
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

// MemberVersion resolves the version of the Cargo package at dir, a
// directory inside the tree at root, by Cargo's own rule: the
// package's `package.version`, or — when it says `version.workspace =
// true` — the `workspace.package.version` of its workspace root. The
// root is the directory its `package.workspace` names, or else the
// nearest enclosing directory whose Cargo.toml declares a
// `[workspace]`, searched no higher than root: a checkout's manifests
// are the checkout's, and a workspace above it is not the release's.
//
// The site names the file the version was read from, so a refusal
// points at the line that carries it.
func MemberVersion(root, dir string) (Site, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return Site{}, fmt.Errorf("manifest: %w", err)
	}

	member := dir
	if !filepath.IsAbs(member) {
		member = filepath.Join(absRoot, member)
	}

	if rel, rerr := filepath.Rel(absRoot, member); rerr != nil || rel == ".." ||
		strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return Site{}, fmt.Errorf("manifest: %s is outside the tree at %s — the package judged is the tree's", dir,
			root)
	}

	path := filepath.Join(member, cargoFile)

	data, err := os.ReadFile(path) //nolint:gosec // a directory inside the tree the operator named
	if errors.Is(err, os.ErrNotExist) {
		return Site{}, fmt.Errorf("manifest: no %s at %s — the package to judge is not there", cargoFile, dir)
	}

	if err != nil {
		return Site{}, fmt.Errorf("manifest: reading %s: %w", path, err)
	}

	records, _, err := cargoDocument(data)
	if err != nil {
		return Site{}, fmt.Errorf("manifest: %s: %w", path, err)
	}

	shown := filepath.Join(dir, cargoFile)

	if site, ok := versionSite(records, packageTable); ok {
		site.Path = shown

		return site, nil
	}

	if !inheritsVersion(records) {
		return Site{}, fmt.Errorf("manifest: %s states neither package.version nor version.workspace = true",
			shown)
	}

	return workspaceVersion(absRoot, member, records, shown)
}

// inheritsVersion reports `version.workspace = true` under [package].
func inheritsVersion(records []record) bool {
	for _, r := range records {
		if slices.Equal(r.key, []string{packageTable, "version", workspaceTable}) && r.kind == unstable.Bool &&
			r.value == "true" {
			return true
		}
	}

	return false
}

// workspaceVersion finds the member's workspace root and reads the
// version it gives its members.
func workspaceVersion(root, member string, records []record, shown string) (Site, error) {
	wsDir, err := workspaceRoot(root, member, records)
	if err != nil {
		return Site{}, fmt.Errorf("manifest: %s inherits its version: %w", shown, err)
	}

	data, err := os.ReadFile(filepath.Join(wsDir, cargoFile)) //nolint:gosec // inside the tree, found above
	if err != nil {
		return Site{}, fmt.Errorf("manifest: %s inherits its version: %w", shown, err)
	}

	wsRecords, _, err := cargoDocument(data)
	if err != nil {
		return Site{}, fmt.Errorf("manifest: %s inherits its version: %w", shown, err)
	}

	site, ok := versionSite(wsRecords, workspaceTable, packageTable)
	if !ok {
		return Site{}, fmt.Errorf("manifest: %s inherits its version, but its workspace root %s carries no"+
			" workspace.package.version", shown, relTo(root, filepath.Join(wsDir, cargoFile)))
	}

	site.Path = relTo(root, filepath.Join(wsDir, cargoFile))
	site.Field += ", inherited by " + shown

	return site, nil
}

// workspaceRoot is the directory a member's workspace lives in: the
// one its package.workspace names, or the nearest directory — the
// member's own first, as Cargo searches — whose Cargo.toml declares
// [workspace], no higher than root.
func workspaceRoot(root, member string, records []record) (string, error) {
	if named, ok := stringField(records, []string{packageTable, workspaceTable}); ok {
		return filepath.Join(member, named), nil
	}

	for dir := member; ; dir = filepath.Dir(dir) {
		declares, err := declaresWorkspace(filepath.Join(dir, cargoFile))
		if err != nil {
			return "", err
		}

		if declares {
			return dir, nil
		}

		if dir == root || dir == filepath.Dir(dir) {
			return "", errors.New("no enclosing Cargo.toml in the tree declares [workspace]")
		}
	}
}

// declaresWorkspace reports whether a Cargo.toml declares a
// [workspace] table; an absent file declares nothing.
func declaresWorkspace(path string) (bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // a directory inside the tree, on the walk up
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("reading %s: %w", path, err)
	}

	records, tables, err := cargoDocument(data)
	if err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}

	for _, t := range tables {
		if len(t) > 0 && t[0] == workspaceTable {
			return true, nil
		}
	}

	return slices.ContainsFunc(records, func(r record) bool { return r.key[0] == workspaceTable }), nil
}

// relTo renders path relative to root for a refusal, or as it is when
// it is not under root.
func relTo(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return rel
	}

	return path
}
