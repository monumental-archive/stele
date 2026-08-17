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
			strings.Replace(testPolicyJSON, `"storeVsaFromCanon": "1.13.0"`, `"storeVsaFromCanon": "not-a-version"`, 1),
			"storeVsaFromCanon",
		},
		{
			"non-positive population",
			strings.Replace(testPolicyJSON, `"storeVsaFromCanon": "1.13.0"`,
				`"storeVsaFromCanon": "1.13.0", "expectedRepos": 0`, 1),
			"expectedRepos",
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
