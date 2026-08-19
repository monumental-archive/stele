// Package npm computes the dependency closure of one shipped npm
// package — the wasm-npm class's JS half (#40, .github#492 item 2).
//
// The closure comes from `npm ls`, not from a reimplementation of
// npm's resolution. Which package a nested `require` resolves to is
// decided by npm — hoisting, dedup, peer ranges, overrides — and a
// hand-written walk of package-lock.json would be a second resolver
// that agrees with the real one until a tree uses a feature it got
// wrong: the transliteration-wearing-a-proof failure the porting
// rules name, and the same conclusion as internal/cargo, osv-scanner
// and cosign. npm ships with the toolchain that built the artifact,
// so it is neither a new trust surface nor a new network dependency.
//
// Two facts about the flags, because each is a correctness claim:
//
//   - --package-lock-only resolves from the lockfile alone. The
//     inventory must describe the recorded resolution the artifact
//     was built from, never whatever node_modules happens to hold on
//     the machine running the derivation — and it must not install a
//     byte to answer.
//   - --omit=dev --omit=peer --omit=optional keeps production edges
//     only. A dev dependency tests the package and never reaches the
//     consumer; an omitted-optional edge was not in the build. What
//     ships is the production closure, which is what a consumer's
//     triage surface must describe.
package npm

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// Package is one resolved dependency.
type Package struct {
	Name    string
	Version string
}

// Resolver runs `npm ls`. An interface so the closure walk is
// exercised against recorded output rather than whatever node
// happens to be installed on the machine running the tests.
type Resolver interface {
	// Tree returns the resolved production dependency tree for the
	// package rooted at dir.
	Tree(dir string) ([]byte, error)
}

// Runner is the production Resolver over the npm binary.
type Runner struct {
	Bin string
}

// Tree implements Resolver.
func (r Runner) Tree(dir string) ([]byte, error) {
	bin := r.Bin
	if bin == "" {
		bin = "npm"
	}

	args := []string{
		"ls", "--all", "--json", "--package-lock-only",
		"--omit=dev", "--omit=peer", "--omit=optional",
	}

	// The CLI has no cancellation surface, so context.Background is the
	// honest parent — the same reading internal/cargo takes.
	//nolint:gosec // the binary name is operator configuration, the dir is the caller's tree
	cmd := exec.CommandContext(context.Background(), bin, args...)
	cmd.Dir = dir

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("npm: ls in %s: %w: %s", dir, err,
				strings.TrimSpace(string(exitErr.Stderr)))
		}

		return nil, fmt.Errorf("npm: ls in %s: %w", dir, err)
	}

	return out, nil
}

// lsNode is one node of npm's own output shape, read leniently: it
// is somebody else's evolving schema, but every field the closure
// needs is read explicitly.
type lsNode struct {
	Version      string            `json:"version"`
	Dependencies map[string]lsNode `json:"dependencies"`
}

// lsDoc is the tree's root, which alone carries its own name.
type lsDoc struct {
	lsNode

	Name string `json:"name"`
}

// Closure returns the shipped package and everything reachable from
// it, the dependencies deduplicated by (name, version) and ordered.
// The root travels as its own return value, never as a position in a
// sorted list — the same contract as cargo.Closure, for the same
// reason.
//
//nolint:gocritic // unnamedResult: the root, its dependencies, and any error
func Closure(tree []byte) (Package, []Package, error) {
	doc, err := jsonx.DecodeForeign[lsDoc](tree)
	if err != nil {
		return Package{}, nil, fmt.Errorf("npm: ls output: %w", err)
	}

	if doc.Name == "" || doc.Version == "" {
		return Package{}, nil, errors.New("npm: the tree names no versioned root package — an inventory of an" +
			" unnamed artifact describes nothing a consumer can hold")
	}

	root := Package{Name: doc.Name, Version: doc.Version}
	seen := map[string]Package{}

	if err := collect(doc.Dependencies, seen); err != nil {
		return Package{}, nil, err
	}

	// The root is not its own dependency: it is the artifact the
	// closure describes, whatever a cyclic workspace layout says.
	delete(seen, root.Name+"\x00"+root.Version)

	out := make([]Package, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}

		return out[i].Version < out[j].Version
	})

	return root, out, nil
}

// collect walks one dependency map. npm's tree nests the SAME
// resolved package under every dependent (deduplicated links render
// with their version restated), so the walk keys by (name, version)
// and depth carries no meaning.
//
// A dependency with no version is refused, never skipped: npm renders
// an unmet or unresolvable edge that way, and an inventory that
// silently dropped it would under-describe the artifact exactly
// where its resolution is broken.
func collect(deps map[string]lsNode, seen map[string]Package) error {
	for name, node := range deps {
		if node.Version == "" {
			return fmt.Errorf("npm: %s resolves to no version — the lockfile does not cover this tree", name)
		}

		key := name + "\x00" + node.Version
		if _, dup := seen[key]; dup {
			continue
		}

		seen[key] = Package{Name: name, Version: node.Version}

		if err := collect(node.Dependencies, seen); err != nil {
			return err
		}
	}

	return nil
}
