// The policy loader's guards: every malformed shape refuses by name.

package assert_test

import (
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
		{"wrong schema", strings.Replace(testPolicyJSON, `"schema": 1`, `"schema": 2`, 1), "schema"},
		{"unknown field", strings.Replace(testPolicyJSON, `"schema": 1`, `"schema": 1, "extra": true`, 1), "unknown"},
		{
			"empty classes",
			`{"schema": 1, "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",
			  "umbrellaBundle": "u.jsonl", "manifestAsset": "m.json", "debtFile": "d.txt", "classes": {}}}`,
			"classes is empty",
		},
		{
			"a class requiring nothing",
			`{"schema": 1, "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",
			  "umbrellaBundle": "u.jsonl", "manifestAsset": "m.json", "debtFile": "d.txt",
			  "classes": {"idle": {"bundles": []}}}}`,
			"requires nothing",
		},
		{
			"missing required string",
			`{"schema": 1, "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",
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
			"a pre-rename policy refuses as unknown field",
			strings.Replace(testPolicyJSON, `"storeVsaFromVersion": "1.13.0"`,
				`"storeVsaFromCanon": "1.13.0"`, 1),
			"storeVsaFromCanon",
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

	const base = `{"schema": 1, "issuer": "https://token.example.com",
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
