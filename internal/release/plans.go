// The inventory plan producers (stele#396): what a build leg states
// about the inventories its artifacts owe, written as the plan
// document `assert plans` judges. The artifact-to-package mapping
// exists with certainty exactly once, in the leg that built the
// artifact, so the leg states it as data from its own inputs; the
// prove leg derives the closures from that data.
//
// Nothing here knows a class. A class declares in the assert policy
// which producer kind writes its plan and that kind's parameters (the
// artifact suffix, the variant templates), and the documents are named
// under the class's one planned prefix — so the producer and the
// judgment read one declaration, and a stranger's class with its own
// naming shape needs no change here.

package release

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/monumental-archive/stele/internal/assert"
)

// PlanEntry is one planned document, in the field order `assert plans`
// reads and the canon's jq wrote.
type PlanEntry struct {
	Class    string     `json:"class"`
	Doc      string     `json:"doc"`
	Artifact string     `json:"artifact"`
	Params   PlanParams `json:"params"`
}

// PlanParams is the cargo closure description the derive leg reads.
type PlanParams struct {
	CargoPackage      string   `json:"cargoPackage"`
	Features          []string `json:"features,omitempty"`
	NoDefaultFeatures bool     `json:"noDefaultFeatures,omitempty"`
}

// PlanInputs are the leg's own inputs. Which fields a kind reads is
// its own: a crates leg reads Dir and Version, a variants leg CrateDir
// and Variant.
type PlanInputs struct {
	// Dir holds the packaged crates (crates).
	Dir string
	// Version is the release version every packaged crate is named
	// for (crates).
	Version string
	// CrateDir is the crate the cell built (variants).
	CrateDir string
	// Variant is the variant this cell built (variants).
	Variant string
}

// InventoryPlan writes one class's plan from the leg's inputs, by the producer
// kind the class declares.
func InventoryPlan(class string, cp *assert.ClassPolicy, in *PlanInputs) ([]PlanEntry, error) {
	inv := cp.Inventory

	switch {
	case inv == nil:
		return nil, fmt.Errorf("class %q declares no inventory — its leg has no plan to write", class)
	case *inv.Kind == assert.InventoryCrates:
		return cratesPlan(class, cp.PlannedPrefix(), *inv.ArtifactSuffix, in)
	case *inv.Kind == assert.InventoryVariants:
		return variantPlan(class, cp.PlannedPrefix(), inv, in)
	default:
		return nil, fmt.Errorf("class %q declares inventory kind %q, which stele writes no plan for", class, *inv.Kind)
	}
}

// cratesPlan reads the packaged crates: what the packaging step left is
// exactly what the registry receives, so the planned set, the signed
// set and the published set cannot differ.
func cratesPlan(class, prefix, suffix string, in *PlanInputs) ([]PlanEntry, error) {
	if in.Dir == "" || in.Version == "" {
		return nil, fmt.Errorf("%s plans from packaged crates: the directory and the version are required", class)
	}

	paths, err := filepath.Glob(filepath.Join(in.Dir, "*.crate"))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", class, err)
	}

	names := map[string]bool{}

	for _, path := range paths {
		base := filepath.Base(path)

		name, ok := strings.CutSuffix(base, "-"+in.Version+".crate")
		if !ok || name == "" {
			return nil, fmt.Errorf("packaged crate %s is not named for version %s", base, in.Version)
		}

		names[name] = true
	}

	if len(names) == 0 {
		return nil, errors.New("cargo package produced no crates — a class that ships nothing plans nothing")
	}

	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}

	sort.Strings(sorted)

	entries := make([]PlanEntry, 0, len(sorted))
	for _, name := range sorted {
		entries = append(entries, PlanEntry{
			Class:    class,
			Doc:      prefix + name + suffix,
			Artifact: name + suffix,
			Params:   PlanParams{CargoPackage: name},
		})
	}

	return entries, nil
}

// variantRE is a variant as a cell names it: one plain segment, since
// it is spliced into a document name and a feature name.
var variantRE = regexp.MustCompile(`^[A-Za-z0-9_.]+$`)

// variantPlan reads the crate's own name and plans the cell's one
// document: this crate, built with exactly the declared features for
// this variant, because those are the cell's own build inputs.
func variantPlan(class, prefix string, inv *assert.InventoryPolicy, in *PlanInputs) ([]PlanEntry, error) {
	if in.CrateDir == "" || !variantRE.MatchString(in.Variant) {
		return nil, fmt.Errorf(
			"%s plans one cell: the crate directory and a plain variant are required (variant %q)",
			class, in.Variant,
		)
	}

	pkg, err := cratePackageName(in.CrateDir)
	if err != nil {
		return nil, err
	}

	artifact := inv.VariantArtifact(pkg, in.Variant)

	return []PlanEntry{{
		Class:    class,
		Doc:      prefix + artifact,
		Artifact: artifact,
		Params: PlanParams{
			CargoPackage:      pkg,
			Features:          inv.VariantFeatures(in.Variant),
			NoDefaultFeatures: *inv.NoDefaultFeatures,
		},
	}}, nil
}

// cargoManifest is the one field read from a crate's Cargo.toml.
type cargoManifest struct {
	Package *struct {
		Name *string `toml:"name"`
	} `toml:"package"`
}

// cratePackageName reads package.name from the crate's manifest.
func cratePackageName(dir string) (string, error) {
	path := filepath.Join(dir, "Cargo.toml")

	raw, err := os.ReadFile(path) //nolint:gosec // the caller names the crate its leg built
	if err != nil {
		return "", fmt.Errorf("reading the crate manifest: %w", err)
	}

	var m cargoManifest
	if err := toml.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}

	if m.Package == nil || m.Package.Name == nil || *m.Package.Name == "" {
		return "", fmt.Errorf("%s names no package — a cell plans the crate it built", path)
	}

	return *m.Package.Name, nil
}
