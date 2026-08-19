// The plans judgment's guards: both directions of .github#544's drift
// (an owed prefix no plan satisfies, a plan document nothing owes),
// the merge rules, and every shape refusal — each a table row,
// because these branches fire only when a build leg is already
// defective, which is exactly when they are least exercised.

package assert_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/report"
)

// plansPolicy declares two classes: one owing a planned inventory
// from an epoch, one owing a planned inventory beside an UNPLANNED
// attestation prefix — the pgrx shape, which is why the fulfillment
// channel is declared rather than inferred.
const plansPolicy = `{
  "schema": 4,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "debtFile": "debt.txt",
    "classes": {
      "wasm-npm": {
        "bundles": ["attestations-npm.intoto.jsonl"],
        "assetPrefixes": [{ "prefix": "sbom-npm-", "owedFrom": "1.42.0", "planned": true }]
      },
      "pgrx-extension": {
        "bundles": ["attestations-extensions.intoto.jsonl"],
        "assetPrefixes": [
          { "prefix": "attestations-extimg-pg" },
          { "prefix": "sbom-pgrx-", "planned": true }
        ]
      },
      "oci-image": { "bundles": ["attestations-image.intoto.jsonl"] }
    }
  }
}`

func loadPlansPolicy(t *testing.T) *assert.Policy {
	t.Helper()

	pol, err := assert.LoadPolicy(strings.NewReader(plansPolicy))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	return pol
}

func planFiles(docs ...string) []assert.PlanFile {
	entries := make([]string, 0, len(docs))
	for _, d := range docs {
		entries = append(entries, `{"doc": "`+d+`", "cargoPackage": "lab-wasm"}`)
	}

	return []assert.PlanFile{{Name: "plans/plan.json", Content: []byte("[" + strings.Join(entries, ",") + "]")}}
}

func TestPlans(t *testing.T) {
	tests := []struct {
		name      string
		classes   []string
		machinery string
		files     []assert.PlanFile
		verdict   report.Verdict
		finding   string // substring of some finding's Detail; empty means no findings
	}{
		{
			"a satisfied planned obligation passes",
			[]string{"wasm-npm"},
			"1.43.0", planFiles("sbom-npm-lab-wasm"),
			report.VerdictPass, "",
		},
		{
			".github#544: the misnamed document fails both ways",
			[]string{"wasm-npm"},
			"1.43.0", planFiles("sbom-cargo-lab-wasm"),
			report.VerdictFail, "red on the evidence walk",
		},
		{
			"a plan document nothing owes is an orphan",
			[]string{"wasm-npm"},
			"1.43.0", planFiles("sbom-npm-lab-wasm", "sbom-cargo-lab-wasm"),
			report.VerdictFail, "misnamed obligation-bearer or an undeclared obligation",
		},
		{
			"pre-epoch machinery owes nothing",
			[]string{"wasm-npm"},
			"1.41.0", nil,
			report.VerdictPass, "",
		},
		{
			"an unparsable machinery version fails toward the stricter obligation",
			[]string{"wasm-npm"},
			"not-a-version", nil,
			report.VerdictFail, "red on the evidence walk",
		},
		{
			"an unplanned prefix is never demanded of the plans",
			[]string{"pgrx-extension"},
			"1.43.0", planFiles("sbom-pgrx-lab-pg-pg16"),
			report.VerdictPass, "",
		},
		{
			"a class with no planned obligations passes with no plans",
			[]string{"oci-image"},
			"1.43.0", nil,
			report.VerdictPass, "",
		},
		{
			"an undeclared class is drift, not a shrug",
			[]string{"zip-bundle"},
			"1.43.0", nil,
			report.VerdictFail, "undeclared class owes unknowable evidence",
		},
		{
			"no classes judged is no judgment",
			nil, "1.43.0", nil,
			report.VerdictCannotJudge, "",
		},
		{
			"empty and repeated class names collapse",
			[]string{"", "wasm-npm", "wasm-npm"},
			"1.43.0", planFiles("sbom-npm-lab-wasm"),
			report.VerdictPass, "",
		},
		{
			"a plan that does not decode is a finding",
			[]string{"oci-image"},
			"1.43.0",
			[]assert.PlanFile{{Name: "plans/plan.json", Content: []byte(`{"doc": "not-an-array"}`)}},
			report.VerdictFail, "plan does not decode",
		},
		{
			"an unknown plan field is version skew, refused",
			[]string{"oci-image"},
			"1.43.0",
			[]assert.PlanFile{{Name: "p", Content: []byte(`[{"doc": "sbom-npm-x", "cargoPackage": "x", "extra": 1}]`)}},
			report.VerdictFail, "plan does not decode",
		},
		{
			"two different claims on one document are refused, never last-writer-wins",
			[]string{"wasm-npm"},
			"1.43.0",
			[]assert.PlanFile{{Name: "p", Content: []byte(
				`[{"doc": "sbom-npm-x", "cargoPackage": "a"}, {"doc": "sbom-npm-x", "cargoPackage": "b"}]`)}},
			report.VerdictFail, "legs disagree about what was built",
		},
		{
			"identical restatements from matrix legs collapse",
			[]string{"wasm-npm"},
			"1.43.0",
			append(planFiles("sbom-npm-lab-wasm"), planFiles("sbom-npm-lab-wasm")...),
			report.VerdictPass, "",
		},
	}

	pol := loadPlansPolicy(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := assert.Plans(pol, tt.classes, tt.machinery, tt.files, discard)

			if rep.Verdict() != tt.verdict {
				t.Fatalf("verdict = %s, want %s\nfindings: %+v", rep.Verdict(), tt.verdict, rep.Findings())
			}

			if tt.finding == "" {
				if len(rep.Findings()) != 0 {
					t.Fatalf("findings = %+v, want none", rep.Findings())
				}

				return
			}

			for _, f := range rep.Findings() {
				if strings.Contains(f.Detail, tt.finding) {
					return
				}
			}

			t.Fatalf("no finding contains %q\nfindings: %+v", tt.finding, rep.Findings())
		})
	}
}

// TestPlansEntryShapeRefusals pins every vocabulary guard: a field
// that steps outside its charset is a finding naming the field, so a
// defective leg's output never reaches a command line downstream.
func TestPlansEntryShapeRefusals(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  string
	}{
		{"absent doc", `{"cargoPackage": "x"}`, "doc is absent"},
		{"empty doc", `{"doc": "", "cargoPackage": "x"}`, "doc is absent"},
		{"doc outside the vocabulary", `{"doc": "a;b", "cargoPackage": "x"}`, "document-name vocabulary"},
		{"doc with a leading dot", `{"doc": ".hidden", "cargoPackage": "x"}`, "document-name vocabulary"},
		{"absent package", `{"doc": "sbom-npm-x"}`, "cargoPackage is absent"},
		{"package outside the vocabulary", `{"doc": "sbom-npm-x", "cargoPackage": "a.b"}`, "package-name vocabulary"},
		{
			"feature outside the vocabulary",
			`{"doc": "sbom-npm-x", "cargoPackage": "x", "features": ["ok", "no,pe"]}`,
			"feature-name vocabulary",
		},
		{
			"artifact outside the vocabulary",
			`{"doc": "sbom-npm-x", "cargoPackage": "x", "artifact": "a/b"}`,
			"artifact-name vocabulary",
		},
	}

	pol := loadPlansPolicy(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := []assert.PlanFile{{Name: "p", Content: []byte("[" + tt.entry + "]")}}

			rep := assert.Plans(pol, []string{"oci-image"}, "1.43.0", files, discard)
			if rep.Verdict() != report.VerdictFail {
				t.Fatalf("verdict = %s, want FAIL", rep.Verdict())
			}

			for _, f := range rep.Findings() {
				if f.Assertion == "plan-shape" && strings.Contains(f.Detail, tt.want) {
					return
				}
			}

			t.Fatalf("no plan-shape finding contains %q\nfindings: %+v", tt.want, rep.Findings())
		})
	}
}
