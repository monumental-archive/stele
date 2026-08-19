// The npm closure walk, against recorded `npm ls` output.
//
// The rows carry the package's two claims: the root travels on its
// own (never as a position), and a dependency npm could not resolve
// refuses rather than vanishing — an inventory that silently dropped
// an unresolved edge would under-describe the artifact exactly where
// its resolution is broken.

package npm_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/npm"
)

// A shipped wasm package: a scoped root, a diamond (two dependents of
// one resolved leaf), and a nested transitive edge.
const tree = `{
  "name": "@acme/widget-wasm",
  "version": "1.2.0",
  "dependencies": {
    "zlib-shim": {
      "version": "3.0.0",
      "dependencies": {
        "leaf": {"version": "1.0.0"}
      }
    },
    "aardvark": {
      "version": "2.0.0",
      "dependencies": {
        "leaf": {"version": "1.0.0"}
      }
    }
  }
}`

func names(pkgs []npm.Package) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p.Name+"@"+p.Version)
	}

	return out
}

func TestClosureWalksAndDeduplicates(t *testing.T) {
	t.Parallel()

	root, deps, err := npm.Closure([]byte(tree))
	if err != nil {
		t.Fatalf("Closure = %v", err)
	}

	// The root arrives on its own: "@acme/widget-wasm" sorts before
	// every dependency here, so a positional read would happen to pass —
	// which is exactly why the contract is the return value, not the
	// order.
	if root.Name != "@acme/widget-wasm" || root.Version != "1.2.0" {
		t.Errorf("root = %s@%s", root.Name, root.Version)
	}

	if got := strings.Join(names(deps), ","); got != "aardvark@2.0.0,leaf@1.0.0,zlib-shim@3.0.0" {
		t.Errorf("closure = %s, want the diamond's leaf once", got)
	}
}

// One package at two resolved versions is two entries: npm trees
// legitimately carry both when dedup cannot collapse them, and an
// inventory choosing one would describe an artifact nobody built.
func TestClosureKeepsBothVersions(t *testing.T) {
	t.Parallel()

	forked := `{"name": "w", "version": "1.0.0", "dependencies": {
	  "a": {"version": "1.0.0", "dependencies": {"leaf": {"version": "1.0.0"}}},
	  "b": {"version": "1.0.0", "dependencies": {"leaf": {"version": "2.0.0"}}}}}`

	_, deps, err := npm.Closure([]byte(forked))
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(names(deps), ","); got != "a@1.0.0,b@1.0.0,leaf@1.0.0,leaf@2.0.0" {
		t.Errorf("closure = %s, want both leaf versions", got)
	}
}

func TestClosureRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tree string
		want string
	}{
		{"output that is not JSON", "not json", "ls output"},
		{"a tree with no root name", `{"version": "1.0.0"}`, "no versioned root"},
		{"a root with no version", `{"name": "w"}`, "no versioned root"},
		{
			"a dependency the lockfile does not cover",
			`{"name": "w", "version": "1.0.0", "dependencies": {"ghost": {}}}`,
			"resolves to no version",
		},
		{
			"an unresolved edge below the surface",
			`{"name": "w", "version": "1.0.0", "dependencies": {
			  "a": {"version": "1.0.0", "dependencies": {"ghost": {}}}}}`,
			"resolves to no version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := npm.Closure([]byte(tt.tree))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Closure = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}
