// The inventory plan producers (stele#396): what a build leg states
// about the inventories its artifacts owe, written as the plan
// document `assert plans` judges. The artifact-to-package mapping
// exists with certainty exactly once, in the leg that built the
// artifact, so the leg states it as data from its own inputs; the
// prove leg derives the closures from that data.
//
// Two producers were shell in the canon's build workflows. What each
// class's leg plans is a release contract fact, so it lives in the
// rows below beside #393's subject definitions. The prefix a document
// is named under is NOT one of those facts: it is the class's planned
// prefix as the assert policy declares it, handed in by the caller,
// so the producer and the judgment cannot disagree about a name.

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
)

// The plan shapes a class's leg produces.
const (
	// shapeCrates plans one document per packaged crate: the leg
	// packaged crates for a registry, and each crate is an artifact.
	shapeCrates = "crates"
	// shapeExtension plans one document for one crate built for one
	// Postgres major: the same crate built per major is one artifact
	// per major (#492).
	shapeExtension = "extension"
)

// PlanClass is one class's statement of how its build leg plans its
// inventories.
type PlanClass struct {
	// Name is the evidence class, as the manifest and the policy
	// spell it, and as the plan entry carries it.
	Name  string
	shape string
}

// planClasses are the release contract's plan-producer rows. Adding a
// class whose leg plans in an existing shape is adding a row.
func planClasses() []*PlanClass {
	return []*PlanClass{
		{Name: "rust-crate", shape: shapeCrates},
		{Name: "pgrx-extension", shape: shapeExtension},
	}
}

// PlanClassNamed returns the plan-producer definition for name.
func PlanClassNamed(name string) (*PlanClass, bool) {
	for _, c := range planClasses() {
		if c.Name == name {
			return c, true
		}
	}

	return nil, false
}

// PlanClasses lists the classes with a plan producer, for a usage
// line.
func PlanClasses() []string {
	out := make([]string, 0, len(planClasses()))
	for _, c := range planClasses() {
		out = append(out, c.Name)
	}

	return out
}

// Crates reports whether the class plans from packaged crates.
func (c *PlanClass) Crates() bool { return c.shape == shapeCrates }

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

// PlanInputs are the leg's own inputs. Which fields a class reads is
// its shape's: a crates leg reads Dir and Version, an extension leg
// CrateDir and Major.
type PlanInputs struct {
	// Prefix is the class's planned prefix, from the assert policy.
	Prefix string
	// Dir holds the packaged crates (a crates leg).
	Dir string
	// Version is the release version every packaged crate is named
	// for (a crates leg).
	Version string
	// CrateDir is the extension crate's directory (an extension leg).
	CrateDir string
	// Major is the Postgres major this cell built (an extension leg).
	Major string
}

// Plan writes the class's plan from the leg's inputs.
func (c *PlanClass) Plan(in *PlanInputs) ([]PlanEntry, error) {
	if in.Prefix == "" {
		return nil, fmt.Errorf("%s: no planned prefix — the policy names the documents, the leg does not", c.Name)
	}

	if c.shape == shapeCrates {
		return c.cratesPlan(in)
	}

	return c.extensionPlan(in)
}

// crateSuffix names a source crate's artifact apart from a binary
// built out of it (the canon's #833): the prefix says what the
// artifact is made of, the suffix which artifact it is.
const crateSuffix = "-crate"

// cratesPlan reads the packaged crates: what `cargo package` left is
// exactly what the registry receives, so the planned set, the signed
// set and the published set cannot differ.
func (c *PlanClass) cratesPlan(in *PlanInputs) ([]PlanEntry, error) {
	if in.Dir == "" || in.Version == "" {
		return nil, fmt.Errorf("%s plans from packaged crates: the directory and the version are required", c.Name)
	}

	paths, err := filepath.Glob(filepath.Join(in.Dir, "*.crate"))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Name, err)
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
			Class:    c.Name,
			Doc:      in.Prefix + name + crateSuffix,
			Artifact: name + crateSuffix,
			Params:   PlanParams{CargoPackage: name},
		})
	}

	return entries, nil
}

// majorRE is a Postgres major as a cell names it.
var planMajorRE = regexp.MustCompile(`^\d+$`)

// ExtensionArtifact names the artifact one extension crate built for
// one major is: the one definition the producer writes and the
// per-major coverage check reads.
func ExtensionArtifact(pkg, major string) string { return pkg + "-pg" + major }

// extensionPlan reads the crate's own name and plans the cell's one
// document: this crate, built with exactly `--features pg<major>` and
// no defaults, because those are the cell's own build inputs.
func (c *PlanClass) extensionPlan(in *PlanInputs) ([]PlanEntry, error) {
	if in.CrateDir == "" || !planMajorRE.MatchString(in.Major) {
		return nil, fmt.Errorf(
			"%s plans one cell: the crate directory and a numeric Postgres major are required (major %q)",
			c.Name, in.Major,
		)
	}

	pkg, err := cratePackageName(in.CrateDir)
	if err != nil {
		return nil, err
	}

	artifact := ExtensionArtifact(pkg, in.Major)

	return []PlanEntry{{
		Class:    c.Name,
		Doc:      in.Prefix + artifact,
		Artifact: artifact,
		Params: PlanParams{
			CargoPackage:      pkg,
			Features:          []string{"pg" + in.Major},
			NoDefaultFeatures: true,
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
