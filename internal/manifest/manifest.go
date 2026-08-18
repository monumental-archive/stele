// Package manifest locates and rewrites version mirrors: the files in a
// release tree that carry a copy of the version whose single source is
// the git history. A Cargo workspace
// mirrors it into `[workspace.package] version` and into the internal
// path-dependency constraints; a single crate into `[package] version`;
// a citation file into CITATION.cff's `version:`. At release time every
// copy must equal the derived truth.
//
// Mirrors are DERIVED STATE, and this package applies the discipline the
// org settled for derived state generally (the pgrx upgrade-script
// precedent): derived, never typed; a mirror found already wrong is
// evidence of a broken earlier release and is REFUSED, never silently
// repaired.
//
// The mechanics follow one rule with two halves — share the definition,
// never share the derivation. The definition of "where versions live" is
// the reader (Detect), and it is deliberately shared by every leg:
// detection, the pre-write agreement check, and the post-write
// verification all see the tree through the same parser, so the legs
// cannot disagree about what a mirror is. The derivation — the byte
// splice that rewrites a value — is verified by RE-READING its output
// through that reader, never by trusting the splicer's own bookkeeping:
// a writer checked by its own inverse passes its own exam.
//
// A whole-file scan for the old version string is deliberately NOT the
// check. An external dependency may legitimately pin a version that
// equals the released one, so "no old-version mention survives" is not a
// fact about correct rewriting — the site list is. Parse for location,
// splice the bytes, re-read the result.
package manifest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The manifest kinds this package knows. A closed set, deliberately:
// a new kind (package.json, a new ecosystem) is added HERE, at the type
// — its read, its sites, its refusals, its table tests — never as
// another pattern at a rewrite site.
const (
	// KindCargoWorkspace is the canonical workspace shape:
	// `[workspace.package] version` is the source and internal
	// path-dependency constraints in `[workspace.dependencies]` mirror it.
	KindCargoWorkspace = "cargo-workspace"

	// KindCargoPackage is a single crate: `[package] version`. Its
	// `[dependencies]` entries are NOT version sites even when they carry
	// `path`: a single crate's path dependencies are other projects with
	// their own versions, not members inheriting this one.
	KindCargoPackage = "cargo-package"

	// KindNone is a tree with no manifest: tags are the only source and
	// the release commit carries no version rewrite. A legitimate answer,
	// stated — not a fallback reached by failing to detect.
	KindNone = "none"
)

// The files a detection reads, at the tree root by definition: manifests
// that govern a release live where the release is cut from.
const (
	cargoFile    = "Cargo.toml"
	citationFile = "CITATION.cff"
)

// Site is one location in one file that carries a copy of the version:
// the field it spells (for a reader of a refusal), the value it
// currently carries, and the byte range a rewrite replaces.
type Site struct {
	// Path names the file, relative to the tree root.
	Path string

	// Field names the location the way its format spells it —
	// "workspace.package.version", "workspace.dependencies.edtf-core",
	// "version" — so a refusal can point at a line a human recognises.
	Field string

	// Value is the version text the site carries now.
	Value string

	// The byte range of the value inside the file, and whether the
	// format quotes it there (TOML strings are quoted; a YAML plain
	// scalar is not).
	off, end int
	quoted   bool
}

// Set is every version mirror one tree carries, plus the citation date
// site, which rides the same rewrite but is a date, not a version.
type Set struct {
	// Kind is the detected manifest kind.
	Kind string

	// Sites are the version mirrors, in file order.
	Sites []Site

	// DateSite is CITATION.cff's date-released, when the file exists.
	// Not a version site: it never votes in the agreement check.
	DateSite *Site

	root  string
	files map[string][]byte
}

// Detect reads the tree and returns its version mirrors.
//
// Detection is total and honest: a root Cargo.toml either matches
// exactly one known shape or the refusal names what was found. There is
// no silent fall-through to "no manifest" while a manifest sits in the
// tree — that is how a mirror escapes the rewrite and drifts.
func Detect(root string) (*Set, error) {
	files := make(map[string][]byte)

	for _, name := range []string{cargoFile, citationFile} {
		data, err := os.ReadFile(filepath.Join(root, name)) //nolint:gosec // a tree the operator named
		if errors.Is(err, os.ErrNotExist) {
			continue
		}

		if err != nil {
			return nil, fmt.Errorf("manifest: reading %s: %w", name, err)
		}

		files[name] = data
	}

	set, err := detect(files)
	if err != nil {
		return nil, err
	}

	set.root = root

	return set, nil
}

// detect is the reader proper, over bytes rather than a filesystem, so
// the post-rewrite verification reads its candidate output through
// EXACTLY this code path — the shared definition.
func detect(files map[string][]byte) (*Set, error) {
	set := &Set{Kind: KindNone, files: files}

	if data, ok := files[cargoFile]; ok {
		kind, sites, err := cargoSites(data)
		if err != nil {
			return nil, err
		}

		set.Kind = kind
		set.Sites = sites
	}

	if data, ok := files[citationFile]; ok {
		cite, err := citationSites(data)
		if err != nil {
			return nil, err
		}

		set.Sites = append(set.Sites, cite.version)
		set.DateSite = &cite.released
	}

	return set, nil
}

// Version is the pre-write agreement check: every site carries the same
// version, or the refusal names each one. Mirrors that disagree are
// evidence that an earlier release went wrong, and this package's
// discipline is to surface that, never to pick a winner and heal.
func (s *Set) Version() (string, error) {
	if len(s.Sites) == 0 {
		return "", errors.New("manifest: no version mirrors in this tree")
	}

	version := s.Sites[0].Value

	var disagree []string

	for _, site := range s.Sites {
		if site.Value != version {
			disagree = append(disagree, fmt.Sprintf("%s %s = %q", site.Path, site.Field, site.Value))
		}
	}

	if len(disagree) > 0 {
		return "", fmt.Errorf(
			"manifest: mirrors disagree — %s %s = %q, but %s; "+
				"a disagreeing mirror is evidence of a broken earlier release, not something to repair here",
			s.Sites[0].Path, s.Sites[0].Field, version, strings.Join(disagree, ", "))
	}

	return version, nil
}

// Check asserts every version mirror equals expect — the drift gate a
// CI run holds between releases, so a mirror edited by hand is caught on
// the pull request that edits it, not discovered at the next release.
func (s *Set) Check(expect string) error {
	var wrong []string

	for _, site := range s.Sites {
		if site.Value != expect {
			wrong = append(wrong, fmt.Sprintf("%s %s = %q", site.Path, site.Field, site.Value))
		}
	}

	if len(wrong) > 0 {
		return fmt.Errorf("manifest: mirrors do not carry %q: %s", expect, strings.Join(wrong, ", "))
	}

	return nil
}

// Files lists the files the sites live in, in a stable order — the list
// a release commit must contain, produced by the detection rather than
// maintained beside it.
func (s *Set) Files() []string {
	seen := make(map[string]bool)

	var out []string

	for _, site := range s.Sites {
		if !seen[site.Path] {
			seen[site.Path] = true

			out = append(out, site.Path)
		}
	}

	if s.DateSite != nil && !seen[s.DateSite.Path] {
		out = append(out, s.DateSite.Path)
	}

	sort.Strings(out)

	return out
}
