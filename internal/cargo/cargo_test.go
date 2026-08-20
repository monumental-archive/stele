// The closure walk, against recorded cargo output.
//
// The rows carry the two reasons this package exists: an artifact's
// inventory is its OWN closure and not its workspace's, and only
// normal dependency edges reach the artifact — a dev- or
// build-dependency describes the machine that produced it.

package cargo_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/cargo"
)

// A workspace of three members. lab-cli ships mimalloc; lab-wasm ships
// wasm-bindgen; both share lab-core. Only lab-cli has a dev-dependency
// and a build-dependency, neither of which reaches the artifact.
const workspace = `{
  "packages": [
    {"id": "lab-cli 0.1.0 (path+file:///w/cli)", "name": "lab-cli", "version": "0.1.0", "source": ""},
    {"id": "lab-wasm 0.1.0 (path+file:///w/wasm)", "name": "lab-wasm", "version": "0.1.0", "source": ""},
    {"id": "lab-core 0.1.0 (path+file:///w/core)", "name": "lab-core", "version": "0.1.0", "source": ""},
    {"id": "mimalloc 0.1.39 (registry+https://github.com/rust-lang/crates.io-index)",
     "name": "mimalloc", "version": "0.1.39", "source": "registry+https://github.com/rust-lang/crates.io-index"},
    {"id": "wasm-bindgen 0.2.92 (registry+https://github.com/rust-lang/crates.io-index)",
     "name": "wasm-bindgen", "version": "0.2.92", "source": "registry+https://github.com/rust-lang/crates.io-index"},
    {"id": "serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
     "name": "serde", "version": "1.0.0", "source": "registry+https://github.com/rust-lang/crates.io-index"},
    {"id": "criterion 0.5.1 (registry+https://github.com/rust-lang/crates.io-index)",
     "name": "criterion", "version": "0.5.1", "source": "registry+https://github.com/rust-lang/crates.io-index"},
    {"id": "cc 1.0.83 (registry+https://github.com/rust-lang/crates.io-index)",
     "name": "cc", "version": "1.0.83", "source": "registry+https://github.com/rust-lang/crates.io-index"}
  ],
  "resolve": {"nodes": [
    {"id": "lab-cli 0.1.0 (path+file:///w/cli)", "deps": [
      {"pkg": "lab-core 0.1.0 (path+file:///w/core)", "dep_kinds": [{"kind": ""}]},
      {"pkg": "mimalloc 0.1.39 (registry+https://github.com/rust-lang/crates.io-index)",
       "dep_kinds": [{"kind": ""}]},
      {"pkg": "criterion 0.5.1 (registry+https://github.com/rust-lang/crates.io-index)",
       "dep_kinds": [{"kind": "dev"}]},
      {"pkg": "cc 1.0.83 (registry+https://github.com/rust-lang/crates.io-index)",
       "dep_kinds": [{"kind": "build"}]}
    ]},
    {"id": "lab-wasm 0.1.0 (path+file:///w/wasm)", "deps": [
      {"pkg": "lab-core 0.1.0 (path+file:///w/core)", "dep_kinds": [{"kind": ""}]},
      {"pkg": "wasm-bindgen 0.2.92 (registry+https://github.com/rust-lang/crates.io-index)",
       "dep_kinds": [{"kind": ""}]}
    ]},
    {"id": "lab-core 0.1.0 (path+file:///w/core)", "deps": [
      {"pkg": "serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)", "dep_kinds": [{"kind": ""}]}
    ]},
    {"id": "mimalloc 0.1.39 (registry+https://github.com/rust-lang/crates.io-index)", "deps": []},
    {"id": "wasm-bindgen 0.2.92 (registry+https://github.com/rust-lang/crates.io-index)", "deps": []},
    {"id": "serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)", "deps": []},
    {"id": "criterion 0.5.1 (registry+https://github.com/rust-lang/crates.io-index)", "deps": []},
    {"id": "cc 1.0.83 (registry+https://github.com/rust-lang/crates.io-index)", "deps": []}
  ]}
}`

func names(pkgs []cargo.Package) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p.Name)
	}

	return out
}

// The whole reason this package exists: an artifact's inventory is its
// OWN closure. Both members here live in one workspace, and neither
// closure contains the other's dependencies.
func TestClosureIsScopedToTheArtifact(t *testing.T) {
	t.Parallel()

	cliRoot, cli, err := cargo.Closure([]byte(workspace), "lab-cli")
	if err != nil {
		t.Fatalf("Closure(lab-cli) = %v", err)
	}

	wasmRoot, wasm, err := cargo.Closure([]byte(workspace), "lab-wasm")
	if err != nil {
		t.Fatalf("Closure(lab-wasm) = %v", err)
	}

	// The root arrives on its own, never as a position: "lab-wasm"
	// sorts AFTER lab-core, so a positional reading would promote a
	// dependency to artifact here.
	if cliRoot.Name != "lab-cli" || wasmRoot.Name != "lab-wasm" {
		t.Errorf("roots = %q, %q", cliRoot.Name, wasmRoot.Name)
	}

	if got := strings.Join(names(cli), ","); got != "lab-core,mimalloc,serde" {
		t.Errorf("lab-cli closure = %s", got)
	}

	if got := strings.Join(names(wasm), ","); got != "lab-core,serde,wasm-bindgen" {
		t.Errorf("lab-wasm closure = %s", got)
	}

	// Each other's exclusive dependencies are absent — the over-claim a
	// workspace-wide inventory makes.
	for _, absent := range []string{"wasm-bindgen"} {
		if strings.Contains(strings.Join(names(cli), ","), absent) {
			t.Errorf("the binary's inventory claims %s, which only the npm package ships", absent)
		}
	}

	if strings.Contains(strings.Join(names(wasm), ","), "mimalloc") {
		t.Error("the npm package's inventory claims mimalloc, which only the binary ships")
	}
}

// A dev-dependency tests the package and a build-dependency builds it;
// neither ends up in the artifact, so neither belongs in an inventory
// a consumer triages against.
func TestClosureFollowsOnlyNormalEdges(t *testing.T) {
	t.Parallel()

	_, cli, err := cargo.Closure([]byte(workspace), "lab-cli")
	if err != nil {
		t.Fatal(err)
	}

	joined := strings.Join(names(cli), ",")
	for _, absent := range []string{"criterion", "cc"} {
		if strings.Contains(joined, absent) {
			t.Errorf("closure carries %s, which never reaches the artifact", absent)
		}
	}
}

// An edge predating dep_kinds is normal by the same reading, so an
// older cargo's output does not silently produce an empty closure.
func TestClosureTreatsAnUnkindedEdgeAsNormal(t *testing.T) {
	t.Parallel()

	legacy := `{"packages": [
	  {"id": "a 1.0.0 (path+file:///a)", "name": "a", "version": "1.0.0", "source": ""},
	  {"id": "b 2.0.0 (registry+x)", "name": "b", "version": "2.0.0", "source": "registry+x"}],
	 "resolve": {"nodes": [
	  {"id": "a 1.0.0 (path+file:///a)", "deps": [{"pkg": "b 2.0.0 (registry+x)"}]},
	  {"id": "b 2.0.0 (registry+x)", "deps": []}]}}`

	root, got, err := cargo.Closure([]byte(legacy), "a")
	if err != nil {
		t.Fatal(err)
	}

	if root.Name != "a" {
		t.Errorf("root = %q", root.Name)
	}

	if strings.Join(names(got), ",") != "b" {
		t.Fatalf("closure = %v, want the unkinded edge followed", names(got))
	}
}

// A workspace member is told from a registry package by its empty
// source — which is what decides whether a purl points anywhere a
// consumer can fetch.
func TestClosureCarriesProvenance(t *testing.T) {
	t.Parallel()

	root, got, err := cargo.Closure([]byte(workspace), "lab-cli")
	if err != nil {
		t.Fatal(err)
	}

	bySource := map[string]string{}
	for _, p := range got {
		bySource[p.Name] = p.Source
	}

	if root.Source != "" || bySource["lab-core"] != "" {
		t.Error("a workspace member carries a registry source")
	}

	if !strings.HasPrefix(bySource["serde"], "registry+") {
		t.Errorf("serde source = %q, want a registry", bySource["serde"])
	}
}

// A cycle is legal in a resolved graph (dev-cycles aside, build
// scripts create them) and must terminate rather than hang.
func TestClosureTerminatesOnACycle(t *testing.T) {
	t.Parallel()

	cyclic := `{"packages": [
	  {"id": "a 1.0.0 (path+file:///a)", "name": "a", "version": "1.0.0", "source": ""},
	  {"id": "b 1.0.0 (path+file:///b)", "name": "b", "version": "1.0.0", "source": ""}],
	 "resolve": {"nodes": [
	  {"id": "a 1.0.0 (path+file:///a)", "deps": [{"pkg": "b 1.0.0 (path+file:///b)", "dep_kinds": [{"kind": ""}]}]},
	  {"id": "b 1.0.0 (path+file:///b)", "deps": [{"pkg": "a 1.0.0 (path+file:///a)", "dep_kinds": [{"kind": ""}]}]}]}}`

	root, got, err := cargo.Closure([]byte(cyclic), "a")
	if err != nil {
		t.Fatal(err)
	}

	if root.Name != "a" || len(got) != 1 || got[0].Name != "b" {
		t.Fatalf("closure = %s + %v, want the root and b once", root.Name, names(got))
	}
}

// One crate at two major versions is ordinary in a resolved Rust
// graph — windows-sys and syn both routinely appear twice — and both
// copies belong in the inventory, because a consumer triaging an
// advisory needs to know which versions the artifact actually links.
// The ordering has to be total for that: name alone leaves the two
// copies interchangeable, and an inventory whose row order wanders
// between runs re-renders on every derivation.
func TestClosureOrdersDuplicateNamesByVersion(t *testing.T) {
	t.Parallel()

	twice := `{"packages": [
	  {"id": "a 1.0.0 (path+file:///a)", "name": "a", "version": "1.0.0", "source": ""},
	  {"id": "dup 0.52.0 (registry+x)", "name": "dup", "version": "0.52.0", "source": "registry+x"},
	  {"id": "dup 0.48.0 (registry+x)", "name": "dup", "version": "0.48.0", "source": "registry+x"},
	  {"id": "mid 1.0.0 (registry+x)", "name": "mid", "version": "1.0.0", "source": "registry+x"}],
	 "resolve": {"nodes": [
	  {"id": "a 1.0.0 (path+file:///a)", "deps": [
	    {"pkg": "dup 0.52.0 (registry+x)", "dep_kinds": [{"kind": ""}]},
	    {"pkg": "mid 1.0.0 (registry+x)", "dep_kinds": [{"kind": ""}]}]},
	  {"id": "mid 1.0.0 (registry+x)", "deps": [
	    {"pkg": "dup 0.48.0 (registry+x)", "dep_kinds": [{"kind": ""}]}]},
	  {"id": "dup 0.52.0 (registry+x)", "deps": []},
	  {"id": "dup 0.48.0 (registry+x)", "deps": []}]}}`

	_, got, err := cargo.Closure([]byte(twice), "a")
	if err != nil {
		t.Fatal(err)
	}

	// Both copies survive, and the older sorts first: discovery order
	// reached 0.52.0 first, so an unstable tiebreak would show here.
	versions := make([]string, 0, len(got))
	for _, p := range got {
		versions = append(versions, p.Name+"@"+p.Version)
	}

	if strings.Join(versions, ",") != "dup@0.48.0,dup@0.52.0,mid@1.0.0" {
		t.Fatalf("closure = %v, want both dup versions ordered oldest first", versions)
	}
}

func TestClosureRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metadata string
		root     string
		want     string
	}{
		{"metadata that is not JSON", "not json", "a", "metadata"},
		{
			"metadata with no resolved graph",
			`{"packages": [{"id": "a", "name": "a", "version": "1", "source": ""}]}`,
			"a", "no resolved dependency graph",
		},
		{"a root that is not in the workspace", workspace, "absent", "is not a package in this workspace"},
		{
			"a name resolving to several packages",
			`{"packages": [
			  {"id": "a 1.0.0 (registry+x)", "name": "a", "version": "1.0.0", "source": "registry+x"},
			  {"id": "a 2.0.0 (registry+x)", "name": "a", "version": "2.0.0", "source": "registry+x"}],
			 "resolve": {"nodes": [{"id": "a 1.0.0 (registry+x)", "deps": []}]}}`,
			"a", "names 2 packages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := cargo.Closure([]byte(tt.metadata), tt.root)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Closure = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}
