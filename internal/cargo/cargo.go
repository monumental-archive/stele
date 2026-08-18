// Package cargo computes the dependency closure of one shipped Cargo
// package, scoped to the target it was built for.
//
// The closure comes from `cargo metadata`, not from a reimplementation
// of it. Cargo's resolver decides what a package depends on: feature
// unification across a workspace, `cfg(...)` target predicates,
// optional dependencies, dev- and build-dependency exclusion, and
// renamed packages. Reimplementing any of that would be a second
// resolver that agrees with the real one until a workspace uses a
// feature it got wrong — which is the transliteration-wearing-a-proof
// failure the porting rules name, and the reason osv-scanner and
// cosign are subprocesses too. Cargo ships with the toolchain that
// built the artifact, so it is neither a new trust surface nor a new
// network dependency.
//
// What this package adds is the SCOPING the org needs and `cargo
// metadata` does not do by itself: a workspace-wide inventory
// describes what COULD have been linked into anything the workspace
// builds, while an artifact's consumer wants what went into the one
// artifact they hold. The walk from a named root through the resolved
// graph is that difference, and on a real multi-class workspace it is
// most of the gap between an artifact's true dependency count and its
// workspace's.
package cargo

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// Package is one resolved dependency: what it is, and where it came
// from. Source is empty for a workspace member, which is how a local
// path dependency is told from a registry one.
type Package struct {
	Name    string
	Version string
	Source  string
}

// Purl renders the package identifier advisory matching runs on.
// Registry packages are crates.io by convention of the ecosystem; a
// workspace member has no registry and is rendered without one.
func (p Package) Purl() string {
	return "pkg:cargo/" + p.Name + "@" + p.Version
}

// Selection is how an artifact was built. Cargo resolves a different
// dependency graph per selection, so an inventory derived under the
// wrong one describes an artifact nobody shipped.
//
// Features are why this type exists rather than a bare triple. A
// workspace that builds one crate once per feature set — a Postgres
// extension against pg16 and pg17, say — publishes those as SEPARATE
// artifacts with separate digests, and their dependency graphs differ
// because the features that select the Postgres bindings differ.
// Resolving them all under one selection would give every artifact
// the same inventory and quietly assert that they are identical.
// Fields are unexported and Select is the only constructor, so a
// contradictory selection cannot exist to be passed anywhere. The
// alternative — validating inside the production resolver — puts the
// guard where a test double bypasses it and the contradiction reaches
// cargo instead of the caller.
type Selection struct {
	target            string
	features          []string
	noDefaultFeatures bool
	allFeatures       bool
}

// Select builds a selection, refusing the one combination cargo
// itself refuses.
func Select(target string, features []string, noDefault, all bool) (Selection, error) {
	if all && len(features) > 0 {
		return Selection{}, errors.New("cargo: --all-features and an explicit feature list are exclusive")
	}

	return Selection{
		target: target, features: features, noDefaultFeatures: noDefault, allFeatures: all,
	}, nil
}

// Target reports the triple this selection resolves for.
func (s Selection) Target() string { return s.target }

// Features reports the features this selection enables.
func (s Selection) Features() []string { return s.features }

// Args renders the selection as cargo flags. No error: a Selection
// that exists is already coherent.
func (s Selection) Args() []string {
	var args []string

	if s.target != "" {
		args = append(args, "--filter-platform", s.target)
	}

	if s.allFeatures {
		args = append(args, "--all-features")
	}

	if len(s.features) > 0 {
		args = append(args, "--features", strings.Join(s.features, ","))
	}

	if s.noDefaultFeatures {
		args = append(args, "--no-default-features")
	}

	return args
}

// Resolver runs `cargo metadata`. An interface so the closure walk is
// exercised against recorded output rather than against whatever
// crates happen to be vendored on the machine running the tests.
type Resolver interface {
	// Metadata returns the resolved graph for one manifest under one
	// selection.
	Metadata(manifestDir string, sel Selection) ([]byte, error)
}

// Runner is the production Resolver over the cargo binary.
type Runner struct {
	Bin string
}

// Metadata implements Resolver.
//
// --locked is not optional: a resolution that is allowed to update the
// lockfile describes a dependency set that differs from the one the
// artifact was built with, which makes the inventory a description of
// a build nobody shipped.
func (r Runner) Metadata(manifestDir string, sel Selection) ([]byte, error) {
	bin := r.Bin
	if bin == "" {
		bin = "cargo"
	}

	args := append([]string{"metadata", "--format-version", "1", "--locked"}, sel.Args()...)

	// The CLI has no cancellation surface, so context.Background is the
	// honest parent — the same reading internal/osv takes of the
	// scanner it runs.
	//nolint:gosec // the binary name is operator configuration, the dir is the caller's tree
	cmd := exec.CommandContext(context.Background(), bin, args...)
	cmd.Dir = manifestDir

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("cargo: metadata in %s: %w: %s", manifestDir, err,
				strings.TrimSpace(string(exitErr.Stderr)))
		}

		return nil, fmt.Errorf("cargo: metadata in %s: %w", manifestDir, err)
	}

	return out, nil
}

// metadataDoc is cargo's own output shape, read leniently: it is
// somebody else's schema and it grows.
type metadataDoc struct {
	Packages []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Source  string `json:"source"`
	} `json:"packages"`
	Resolve *struct {
		Nodes []struct {
			ID   string `json:"id"`
			Deps []struct {
				Pkg      string `json:"pkg"`
				DepKinds []struct {
					Kind string `json:"kind"`
				} `json:"dep_kinds"`
			} `json:"deps"`
		} `json:"nodes"`
	} `json:"resolve"`
}

// ErrNoResolution reports metadata with no resolved graph — cargo
// answered, but not with the thing a closure needs.
var ErrNoResolution = errors.New("cargo: metadata carries no resolved dependency graph")

// Closure returns the packages reachable from the named root, the
// root included, ordered.
//
// Only NORMAL dependency edges are followed. A dev-dependency is used
// to test the package and a build-dependency to build it; neither ends
// up in the shipped artifact, so an inventory that carried them would
// describe the machine that produced the artifact rather than the
// artifact itself — and would put advisories a consumer cannot be
// exposed to into their triage surface.
func Closure(metadata []byte, root string) ([]Package, error) {
	doc, err := jsonx.DecodeForeign[metadataDoc](metadata)
	if err != nil {
		return nil, fmt.Errorf("cargo: metadata: %w", err)
	}

	if doc.Resolve == nil || len(doc.Resolve.Nodes) == 0 {
		return nil, ErrNoResolution
	}

	byID := make(map[string]Package, len(doc.Packages))
	rootIDs := []string{}

	for _, p := range doc.Packages {
		byID[p.ID] = Package{Name: p.Name, Version: p.Version, Source: p.Source}
		if p.Name == root {
			rootIDs = append(rootIDs, p.ID)
		}
	}

	switch len(rootIDs) {
	case 0:
		return nil, fmt.Errorf("cargo: %q is not a package in this workspace", root)
	case 1:
	default:
		// One name resolving to several packages means the closure has
		// no single starting point, and guessing would describe an
		// artifact nobody built.
		return nil, fmt.Errorf("cargo: %q names %d packages in this workspace", root, len(rootIDs))
	}

	edges := make(map[string][]string, len(doc.Resolve.Nodes))

	for _, node := range doc.Resolve.Nodes {
		for _, dep := range node.Deps {
			if normalEdge(dep.DepKinds) {
				edges[node.ID] = append(edges[node.ID], dep.Pkg)
			}
		}
	}

	return walk(rootIDs[0], edges, byID), nil
}

// normalEdge reports whether this dependency ends up in the artifact.
// cargo spells a normal dependency as the empty kind; an edge with no
// kinds at all predates the field and is normal by the same reading.
func normalEdge(kinds []struct {
	Kind string `json:"kind"`
},
) bool {
	if len(kinds) == 0 {
		return true
	}

	for _, k := range kinds {
		if k.Kind == "" {
			return true
		}
	}

	return false
}

// walk collects everything reachable from the root.
func walk(root string, edges map[string][]string, byID map[string]Package) []Package {
	seen := map[string]bool{root: true}
	queue := []string{root}

	var out []Package

	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]

		if pkg, ok := byID[id]; ok {
			out = append(out, pkg)
		}

		for _, next := range edges[id] {
			if seen[next] {
				continue
			}

			seen[next] = true

			queue = append(queue, next)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}

		return out[i].Version < out[j].Version
	})

	return out
}
