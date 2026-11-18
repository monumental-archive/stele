package assert_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
)

// inventoryPolicy is a minimal assert policy whose one class, "x",
// carries the given extra members — its assetPrefixes and inventory.
func inventoryPolicy(members string) string {
	return `{"schema": 9, "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",
	  "umbrellaBundle": "u.jsonl", "manifestAsset": "m.json",
	  "classes": {"x": {"bundles": ["a.intoto.jsonl"]` + members + `}}}}`
}

const plannedPrefix = `, "assetPrefixes": [{"prefix": "sbom-x-", "planned": true}]`

// TestInventoryDeclarations: every kind with exactly its parameters
// loads, and every guard refuses by name.
func TestInventoryDeclarations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		members string
		want    string // "" loads
	}{
		{name: "binaries", members: `, "inventory": {"kind": "binaries"}`},
		{name: "none", members: `, "inventory": {"kind": "none"}`},
		{name: "planned, with a planned prefix", members: plannedPrefix + `, "inventory": {"kind": "planned"}`},
		{name: "planned, with none", members: `, "inventory": {"kind": "planned"}`},
		{name: "crates", members: plannedPrefix + `, "inventory": {"kind": "crates", "artifactSuffix": "-src"}`},
		{
			name: "variants",
			members: plannedPrefix + `, "inventory": {"kind": "variants", "artifact": "{package}_v{variant}",` +
				` "features": ["v{variant}"], "noDefaultFeatures": false}`,
		},
		{
			name: "variants built with no features",
			members: plannedPrefix + `, "inventory": {"kind": "variants", "artifact": "{package}-{variant}",` +
				` "features": [], "noDefaultFeatures": true}`,
		},
		{name: "no kind", members: `, "inventory": {}`, want: "evidence.classes.x.inventory.kind is absent or empty"},
		{
			name:    "an unknown kind",
			members: `, "inventory": {"kind": "wheels"}`,
			want:    `evidence.classes.x.inventory.kind "wheels" is not an inventory kind this stele implements`,
		},
		{
			name:    "a parameter the kind does not read",
			members: `, "inventory": {"kind": "binaries", "artifactSuffix": "-crate"}`,
			want:    "evidence.classes.x.inventory.artifactSuffix is declared but the binaries kind does not read it",
		},
		{
			name:    "a missing parameter",
			members: plannedPrefix + `, "inventory": {"kind": "crates"}`,
			want:    "evidence.classes.x.inventory.artifactSuffix is absent — the crates kind requires it",
		},
		{
			name: "variants missing noDefaultFeatures",
			members: plannedPrefix + `, "inventory": {"kind": "variants", "artifact": "{package}-{variant}",` +
				` "features": ["{variant}"]}`,
			want: "evidence.classes.x.inventory.noDefaultFeatures is absent — the variants kind requires it",
		},
		{
			name:    "an unknown parameter",
			members: `, "inventory": {"kind": "none", "prefix": "x"}`,
			want:    "unknown field",
		},
		{
			name:    "a kind owing no plan beside planned prefixes",
			members: plannedPrefix + `, "inventory": {"kind": "none"}`,
			want:    `evidence.classes.x.inventory.kind "none" owes no plan, but the class declares planned prefixes (sbom-x-)`,
		},
		{
			name:    "a producing kind with no planned prefix",
			members: `, "inventory": {"kind": "crates", "artifactSuffix": "-crate"}`,
			want: `evidence.classes.x.inventory.kind "crates" writes the plan under the class's one planned prefix,` +
				` and the class declares 0`,
		},
		{
			name: "a producing kind with two planned prefixes",
			members: `, "assetPrefixes": [{"prefix": "sbom-a-", "planned": true}, {"prefix": "sbom-b-", "planned": true}],` +
				` "inventory": {"kind": "crates", "artifactSuffix": "-crate"}`,
			want: `writes the plan under the class's one planned prefix, and the class declares 2`,
		},
		{
			name:    "an empty artifact suffix",
			members: plannedPrefix + `, "inventory": {"kind": "crates", "artifactSuffix": ""}`,
			want:    "evidence.classes.x.inventory.artifactSuffix is empty",
		},
		{
			name: "a variants template naming no variant",
			members: plannedPrefix + `, "inventory": {"kind": "variants", "artifact": "{package}",` +
				` "features": [], "noDefaultFeatures": true}`,
			want: `evidence.classes.x.inventory.artifact "{package}" does not name {variant}`,
		},
		{
			name: "a variants template naming no package",
			members: plannedPrefix + `, "inventory": {"kind": "variants", "artifact": "ext-{variant}",` +
				` "features": [], "noDefaultFeatures": true}`,
			want: `evidence.classes.x.inventory.artifact "ext-{variant}" does not name {package}`,
		},
		{
			name: "an empty feature template",
			members: plannedPrefix + `, "inventory": {"kind": "variants", "artifact": "{package}-{variant}",` +
				` "features": [""], "noDefaultFeatures": true}`,
			want: "evidence.classes.x.inventory.features[0] is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := assert.LoadPolicy(strings.NewReader(inventoryPolicy(tt.members)))

			if tt.want == "" {
				if err != nil {
					t.Fatalf("LoadPolicy = %v, want the declaration to load", err)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("LoadPolicy error = %v\nwant it to carry %q", err, tt.want)
			}
		})
	}
}

// TestInventoryTemplates: a variant renders through the declared
// templates, whatever naming shape the class chose.
func TestInventoryTemplates(t *testing.T) {
	t.Parallel()

	pol, err := assert.LoadPolicy(strings.NewReader(inventoryPolicy(plannedPrefix +
		`, "inventory": {"kind": "variants", "artifact": "{package}_v{variant}", "features": ["v{variant}", "std"],` +
		` "noDefaultFeatures": false}`)))
	if err != nil {
		t.Fatal(err)
	}

	cp := pol.Evidence.Classes["x"]
	inv := cp.Inventory

	if got := inv.VariantArtifact("mod", "3"); got != "mod_v3" {
		t.Errorf("VariantArtifact = %q", got)
	}

	if got := strings.Join(inv.VariantFeatures("3"), ","); got != "v3,std" {
		t.Errorf("VariantFeatures = %q", got)
	}

	if cp.PlannedPrefix() != "sbom-x-" || !inv.Kind.Produces() || !inv.Kind.Planned() {
		t.Errorf("PlannedPrefix = %q, Produces = %v, Planned = %v", cp.PlannedPrefix(), inv.Kind.Produces(),
			inv.Kind.Planned())
	}

	for kind, planned := range map[assert.InventoryKind]bool{
		assert.InventoryBinaries: false, assert.InventoryNone: false, assert.InventoryPlanned: true,
		assert.InventoryCrates: true, assert.InventoryVariants: true,
	} {
		if kind.Planned() != planned {
			t.Errorf("%s.Planned() = %v", kind, kind.Planned())
		}
	}
}
