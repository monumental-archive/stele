// The policy loader's guards: every malformed shape refuses by name.

package assert_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
)

func TestLoadPolicyRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		json string
		want string
	}{
		// The wrong value is DERIVED from the implemented constant, so
		// an epoch-bump sweep over `"schema": N` literals can never
		// rewrite this row into agreement with the document it must
		// refuse (the guard carries no second copy of the number).
		{
			"wrong schema",
			strings.Replace(testPolicyJSON, `"schema": 4`,
				fmt.Sprintf(`"schema": %d`, assert.PolicySchema+1), 1),
			"schema",
		},
		{"unknown field", strings.Replace(testPolicyJSON, `"schema": 4`, `"schema": 4, "extra": true`, 1), "unknown"},
		{
			"empty classes",
			`{"schema": 4, "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",
			  "umbrellaBundle": "u.jsonl", "manifestAsset": "m.json", "debtFile": "d.txt", "classes": {}}}`,
			"classes is empty",
		},
		{
			"a class requiring nothing",
			`{"schema": 4, "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",
			  "umbrellaBundle": "u.jsonl", "manifestAsset": "m.json", "debtFile": "d.txt",
			  "classes": {"idle": {"bundles": []}}}}`,
			"requires nothing",
		},
		{
			"missing required string",
			`{"schema": 4, "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",
			  "umbrellaBundle": "u.jsonl", "manifestAsset": "m.json",
			  "classes": {"a": {"bundles": ["b"]}}}}`,
			"debtFile",
		},
		{
			"unparsable epoch",
			strings.Replace(testPolicyJSON, `"storeVsaFromVersion": "1.13.0"`, `"storeVsaFromVersion": "not-a-version"`, 1),
			"storeVsaFromVersion",
		},
		{
			"non-positive population",
			strings.Replace(testPolicyJSON, `"storeVsaFromVersion": "1.13.0"`,
				`"storeVsaFromVersion": "1.13.0", "expectedRepos": 0`, 1),
			"expectedRepos",
		},
		{
			"unparsable decision epoch",
			strings.Replace(testPolicyJSON, `"storeVsaFromVersion": "1.13.0"`,
				`"storeVsaFromVersion": "1.13.0", "decisionFromVersion": "not-a-version"`, 1),
			"decisionFromVersion",
		},
		{
			"an empty enrichment name",
			strings.Replace(testPolicyJSON, `"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}`,
				`"oci-image": {"bundles": ["attestations-image.intoto.jsonl"], "enrichment": [""]}`, 1),
			"empty dependency name",
		},
		{
			"an asset obligation with no prefix",
			strings.Replace(testPolicyJSON, `"assetPrefixes": [{"prefix": "attestations-extimg-pg"}]`,
				`"assetPrefixes": [{}]`, 1),
			"no prefix",
		},
		{
			"an asset obligation with an empty prefix",
			strings.Replace(testPolicyJSON, `"assetPrefixes": [{"prefix": "attestations-extimg-pg"}]`,
				`"assetPrefixes": [{"prefix": ""}]`, 1),
			"no prefix",
		},
		{
			"a duplicated asset prefix",
			strings.Replace(testPolicyJSON, `"assetPrefixes": [{"prefix": "attestations-extimg-pg"}]`,
				`"assetPrefixes": [{"prefix": "p"}, {"prefix": "p"}]`, 1),
			"names \"p\" twice",
		},
		{
			"an unparsable asset obligation epoch",
			strings.Replace(testPolicyJSON, `"assetPrefixes": [{"prefix": "attestations-extimg-pg"}]`,
				`"assetPrefixes": [{"prefix": "p", "owedFrom": "not-a-version"}]`, 1),
			"owedFrom",
		},
		{
			"a duplicated enrichment name",
			strings.Replace(testPolicyJSON, `"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}`,
				`"oci-image": {"bundles": ["attestations-image.intoto.jsonl"], "enrichment": ["base-images", "base-images"]}`, 1),
			"names \"base-images\" twice",
		},
		// The gate fires FIRST (stele#107): a pre-#84 policy declares
		// schema 1 and carries the old vocabulary; it must refuse as a
		// VERSION mismatch, never incidentally as an unknown field.
		{
			"a pre-rename policy refuses as a version error",
			strings.NewReplacer(
				`"schema": 4`, `"schema": 1`,
				`"storeVsaFromVersion": "1.13.0"`, `"storeVsaFromCanon": "1.13.0"`,
			).Replace(testPolicyJSON),
			"not the implemented schema",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := assert.LoadPolicy(strings.NewReader(tt.json)); err == nil ||
				!strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestParseDebt(t *testing.T) {
	t.Parallel()

	debt, err := assert.ParseDebt([]byte("# reviewed in PR 9\n\nwidget@v1.0.0(sbom)\n"), "debt.txt")
	if err != nil {
		t.Fatalf("ParseDebt: %v", err)
	}

	if len(debt) != 1 {
		t.Fatalf("debt = %d entries, want 1", len(debt))
	}

	for _, bad := range []string{"no-parens\n", "widget@v1.0.0()\n", "(sbom)\n"} {
		if _, err := assert.ParseDebt([]byte(bad), "debt.txt"); err == nil {
			t.Fatalf("%q did not refuse", bad)
		}
	}
}

// TestTagsPolicyRefusals: the tags section is optional, but declared
// means every field, validated strictly (stele#83).
func TestTagsPolicyRefusals(t *testing.T) {
	t.Parallel()

	const base = `{"schema": 4, "issuer": "https://token.example.com",
	  "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",
	    "umbrellaBundle": "u.jsonl", "manifestAsset": "m.json", "debtFile": "d.txt",
	    "classes": {"a": {"bundles": ["b"]}}},
	  "tags": {"tagPattern": "^v[0-9]", "taggerName": "mint[bot]",
	    "identityPattern": "^https://github\\.com/acme/", "notesRef": "refs/notes/commits",
	    "epochs": {"widget": "v1.0.0", "gadget": "pending"}}}`

	if _, err := assert.LoadPolicy(strings.NewReader(base)); err != nil {
		t.Fatalf("the base tags policy must load: %v", err)
	}

	tests := []struct {
		name string
		from string
		to   string
		want string
	}{
		{"missing tagger", `"taggerName": "mint[bot]",`, ``, "taggerName"},
		{"bad tag pattern", `"tagPattern": "^v[0-9]"`, `"tagPattern": "("`, "pattern"},
		{
			"bad identity pattern", `"identityPattern": "^https://github\\.com/acme/"`,
			`"identityPattern": "("`, "pattern",
		},
		{"unqualified notes ref", `"notesRef": "refs/notes/commits"`, `"notesRef": "commits"`, "fully qualified"},
		{"no epochs", `"epochs": {"widget": "v1.0.0", "gadget": "pending"}`, `"epochs": {}`, "epochs"},
		{
			"unparsable epoch", `"epochs": {"widget": "v1.0.0", "gadget": "pending"}`,
			`"epochs": {"widget": "soon"}`, "epochs[widget]",
		},
		{"issuer missing beside tags", `"issuer": "https://token.example.com",`, ``, "issuer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := strings.Replace(base, tt.from, tt.to, 1)
			if doc == base {
				t.Fatalf("mutation %q did not apply", tt.from)
			}

			if _, err := assert.LoadPolicy(strings.NewReader(doc)); err == nil ||
				!strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

// TestEnrichmentDemand pins the one derivation of what a release owes
// its enrichment claim (stele#122): nil when the obligation is not
// owed, the empty demand when its classes declare nothing extra, and
// a sorted, deduplicated union otherwise — independent of class
// declaration order, because what a release owes is a set.
func TestEnrichmentDemand(t *testing.T) {
	t.Parallel()

	enriched := strings.Replace(testPolicyJSON,
		`"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]},`,
		`"oci-image": {"bundles": ["attestations-image.intoto.jsonl"], "enrichment": ["base-images"]},`, 1)
	enriched = strings.Replace(enriched,
		`"assetPrefixes": [{"prefix": "attestations-extimg-pg"}]`,
		`"assetPrefixes": [{"prefix": "attestations-extimg-pg"}], "enrichment": ["pgrx-base", "base-images"]`, 1)

	p, err := assert.LoadPolicy(strings.NewReader(enriched))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	t.Run("not owed is nil, never the empty demand", func(t *testing.T) {
		t.Parallel()

		if d := p.Evidence.EnrichmentDemand(&assert.Contract{
			Classes: []string{"pgrx-extension"}, Enrichment: false,
		}); d != nil {
			t.Fatalf("demand = %+v, want nil for pre-epoch history", d)
		}
	})

	t.Run("owed with no class extras is the empty demand", func(t *testing.T) {
		t.Parallel()

		d := p.Evidence.EnrichmentDemand(&assert.Contract{Classes: []string{"rust-crate"}, Enrichment: true})
		if d == nil || len(d.AlsoRequired) != 0 {
			t.Fatalf("demand = %+v, want the empty demand", d)
		}
	})

	t.Run("the union is sorted, deduplicated and order-independent", func(t *testing.T) {
		t.Parallel()

		want := []string{"base-images", "pgrx-base"}

		for _, classes := range [][]string{
			{"oci-image", "pgrx-extension"},
			{"pgrx-extension", "oci-image"},
		} {
			d := p.Evidence.EnrichmentDemand(&assert.Contract{Classes: classes, Enrichment: true})
			if d == nil || !slices.Equal(d.AlsoRequired, want) {
				t.Fatalf("demand for %v = %+v, want %v", classes, d, want)
			}
		}
	})
}
