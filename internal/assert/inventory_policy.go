// This file: what a class's release owes as inventory, declared on
// the class (stele#396). Which classes an organisation has, how its
// build legs name what they build, and which of them ship binaries
// that carry their own module list are that organisation's facts, so
// they are policy: a class declares an inventory KIND, and the kind's
// parameters. The kinds are code — each names a judgment the derive
// leg knows how to compute — and the parameters are the adopter's,
// exactly as the base-approval mechanisms are (stele#247): a kind this
// version does not implement is refused at load, and so is a
// parameter the declared kind does not read.

package assert

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// InventoryKind names one inventory judgment this engine implements.
type InventoryKind string

const (
	// InventoryBinaries means the class's shipped binaries carry their own
	// module list, and the release's inventory is read out of them.
	InventoryBinaries InventoryKind = "binaries"
	// InventoryNone means the class adds no inventory of its own (an image
	// of binaries another class already describes).
	InventoryNone InventoryKind = "none"
	// InventoryPlanned means the class's build leg emits an inventory plan,
	// and each planned document is derived from it.
	InventoryPlanned InventoryKind = "planned"
	// InventoryCrates means planned, and stele writes the plan from the
	// leg's packaged crates — one document per crate.
	InventoryCrates InventoryKind = "crates"
	// InventoryVariants means planned, and stele writes the plan for one
	// crate built once per variant (a Postgres major, for one) — one
	// document per variant, and every requested variant must be
	// covered.
	InventoryVariants InventoryKind = "variants"
)

// The placeholders a variants template may name.
const (
	placeholderPackage = "{package}"
	placeholderVariant = "{variant}"
)

// InventoryPolicy is a class's inventory declaration: the kind, and
// that kind's parameters, flat on the declaration because it IS one
// kind's declaration.
type InventoryPolicy struct {
	// Kind selects the judgment.
	Kind *InventoryKind `json:"kind"`
	// ArtifactSuffix is appended to each packaged crate's name to name
	// the artifact and its document (crates): the suffix that tells a
	// source crate apart from a binary built out of it.
	ArtifactSuffix *string `json:"artifactSuffix,omitempty"`
	// Artifact is the artifact-name template for one variant, naming
	// {package} and {variant} (variants).
	Artifact *string `json:"artifact,omitempty"`
	// Features are the cargo feature templates one variant is built
	// with; each may name {variant} (variants).
	Features []string `json:"features,omitempty"`
	// NoDefaultFeatures states whether a variant is built with the
	// default features off — declared, never defaulted (variants).
	NoDefaultFeatures *bool `json:"noDefaultFeatures,omitempty"`
}

// Produces reports whether stele writes this kind's plan.
func (k InventoryKind) Produces() bool { return k == InventoryCrates || k == InventoryVariants }

// Planned reports whether a class of this kind plans its inventory.
func (k InventoryKind) Planned() bool { return k == InventoryPlanned || k.Produces() }

// VariantArtifact renders the variants template for one package and
// one variant.
func (p *InventoryPolicy) VariantArtifact(pkg, variant string) string {
	return strings.NewReplacer(placeholderPackage, pkg, placeholderVariant, variant).Replace(*p.Artifact)
}

// VariantFeatures renders the feature templates for one variant.
func (p *InventoryPolicy) VariantFeatures(variant string) []string {
	out := make([]string, 0, len(p.Features))
	for _, f := range p.Features {
		out = append(out, strings.ReplaceAll(f, placeholderVariant, variant))
	}

	return out
}

// inventoryParams is every parameter this engine reads off an
// inventory declaration, and whether each is declared. One table, so
// "required by my kind" and "read by nobody here" cannot drift apart.
func (p *InventoryPolicy) inventoryParams() map[string]bool {
	return map[string]bool{
		"artifactSuffix":    p.ArtifactSuffix != nil,
		"artifact":          p.Artifact != nil,
		"features":          p.Features != nil,
		"noDefaultFeatures": p.NoDefaultFeatures != nil,
	}
}

// inventoryOwns names the parameters one kind reads. A kind absent
// from this switch is a kind this engine does not implement — the one
// place that fact is written. A kind with no parameters owns the
// empty, non-nil list.
func inventoryOwns(k InventoryKind) []string {
	switch k {
	case InventoryBinaries, InventoryNone, InventoryPlanned:
		return []string{}
	case InventoryCrates:
		return []string{"artifactSuffix"}
	case InventoryVariants:
		return []string{"artifact", "features", "noDefaultFeatures"}
	default:
		return nil
	}
}

// validate holds the declaration to exactly its kind's parameters, and
// to what its kind needs of the class around it.
func (p *InventoryPolicy) validate(class string, c *ClassPolicy) error {
	where := "evidence.classes." + class + ".inventory"

	if p.Kind == nil || *p.Kind == "" {
		return fmt.Errorf("%s.kind is absent or empty", where)
	}

	owned := inventoryOwns(*p.Kind)
	if owned == nil {
		return fmt.Errorf("%s.kind %q is not an inventory kind this stele implements", where, *p.Kind)
	}

	declared := p.inventoryParams()

	for _, name := range owned {
		if !declared[name] {
			return fmt.Errorf("%s.%s is absent — the %s kind requires it", where, name, *p.Kind)
		}
	}

	for _, name := range slices.Sorted(maps.Keys(declared)) {
		if declared[name] && !slices.Contains(owned, name) {
			return fmt.Errorf("%s.%s is declared but the %s kind does not read it", where, name, *p.Kind)
		}
	}

	return p.validateKind(where, c)
}

// validateKind checks what each kind needs beyond its parameters'
// presence.
func (p *InventoryPolicy) validateKind(where string, c *ClassPolicy) error {
	planned := c.plannedPrefixes()

	switch {
	case !p.Kind.Planned() && len(planned) > 0:
		return fmt.Errorf("%s.kind %q owes no plan, but the class declares planned prefixes (%s)",
			where, *p.Kind, strings.Join(planned, ", "))
	case p.Kind.Produces() && len(planned) != 1:
		return fmt.Errorf("%s.kind %q writes the plan under the class's one planned prefix, and the class"+
			" declares %d", where, *p.Kind, len(planned))
	}

	switch *p.Kind {
	case InventoryCrates:
		if *p.ArtifactSuffix == "" {
			return fmt.Errorf("%s.artifactSuffix is empty — a source crate's artifact must be named apart from"+
				" a binary built out of it", where)
		}
	case InventoryVariants:
		for _, ph := range []string{placeholderPackage, placeholderVariant} {
			if !strings.Contains(*p.Artifact, ph) {
				return fmt.Errorf("%s.artifact %q does not name %s — one artifact per package per variant",
					where, *p.Artifact, ph)
			}
		}

		for i, f := range p.Features {
			if f == "" {
				return fmt.Errorf("%s.features[%d] is empty", where, i)
			}
		}
	case InventoryBinaries, InventoryNone, InventoryPlanned:
	}

	return nil
}

// PlannedPrefix is the class's one planned prefix, for a kind that
// writes its plan; load already proved there is exactly one.
func (c *ClassPolicy) PlannedPrefix() string { return c.plannedPrefixes()[0] }
