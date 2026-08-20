// The plans judgment's guards: both directions of .github#544's drift
// (an owed prefix no plan satisfies, a plan document outside its
// class's vocabulary), the stele#143 epoch separation, the merge
// rules, and every shape refusal — each a table row, because these
// branches fire only when a build leg is already defective, which is
// exactly when they are least exercised. The #143 lesson is a
// standing rule for this table: every epoch row runs WITH a plan
// present, because the row that passes no plans never exercises the
// vocabulary leg, and a guard that skips when it should run looks
// exactly like success.

package assert_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/report"
)

// plansPolicy declares three shapes: a class owing a planned
// inventory from an epoch, a class owing a planned inventory beside
// an UNPLANNED attestation prefix (the pgrx shape, which is why the
// fulfillment channel is declared rather than inferred), and a class
// declaring no planned prefixes at all — no vocabulary, so its plans
// are absent from the judgment, not refused by it.
const plansPolicy = `{
  "schema": 6,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
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

// planFiles builds one plan file of class/doc pairs, with the
// ecosystem-specific closure riding in params as the format intends.
func planFiles(classDocs ...[2]string) []assert.PlanFile {
	entries := make([]string, 0, len(classDocs))
	for _, cd := range classDocs {
		entries = append(entries,
			`{"class": "`+cd[0]+`", "doc": "`+cd[1]+`", "params": {"cargoPackage": "lab-wasm"}}`)
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
			"1.43.0", planFiles([2]string{"wasm-npm", "sbom-npm-lab-wasm"}),
			report.VerdictPass, "",
		},
		{
			".github#544: the misnamed document fails both ways",
			[]string{"wasm-npm"},
			"1.43.0", planFiles([2]string{"wasm-npm", "sbom-cargo-lab-wasm"}),
			report.VerdictFail, "red on the evidence walk",
		},
		{
			"a plan document outside its class's vocabulary is an orphan",
			[]string{"wasm-npm"},
			"1.43.0", planFiles([2]string{"wasm-npm", "sbom-npm-lab-wasm"}, [2]string{"wasm-npm", "sbom-cargo-lab-wasm"}),
			report.VerdictFail, "misnamed obligation-bearer or an undeclared obligation",
		},
		{
			"stele#143: a pre-epoch release emitting a correct plan passes",
			[]string{"wasm-npm"},
			"1.41.0", planFiles([2]string{"wasm-npm", "sbom-npm-lab-wasm"}),
			report.VerdictPass, "",
		},
		{
			"pre-epoch machinery owes nothing even with no plans",
			[]string{"wasm-npm"},
			"1.41.0", nil,
			report.VerdictPass, "",
		},
		{
			"a pre-epoch plan outside the vocabulary is still an orphan",
			[]string{"wasm-npm"},
			"1.41.0", planFiles([2]string{"wasm-npm", "sbom-cargo-lab-wasm"}),
			report.VerdictFail, "misnamed obligation-bearer or an undeclared obligation",
		},
		{
			"stele#143: another class's plan cannot satisfy an obligation by prefix coincidence",
			[]string{"wasm-npm", "pgrx-extension"},
			"1.43.0",
			planFiles([2]string{"pgrx-extension", "sbom-npm-lab-wasm"}, [2]string{"pgrx-extension", "sbom-pgrx-lab-pg"}),
			report.VerdictFail, "no plan of this class names a document",
		},
		{
			"a plan naming a class this release does not declare is drift",
			[]string{"wasm-npm"},
			"1.43.0",
			planFiles([2]string{"wasm-npm", "sbom-npm-lab-wasm"}, [2]string{"zip-bundle", "sbom-zip-lab"}),
			report.VerdictFail, "a leg ran for an undeclared class",
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
			"1.43.0", planFiles([2]string{"pgrx-extension", "sbom-pgrx-lab-pg-pg16"}),
			report.VerdictPass, "",
		},
		{
			"a class declaring no planned prefixes has no vocabulary: its plan is absent, not refused",
			[]string{"oci-image"},
			"1.43.0", planFiles([2]string{"oci-image", "sbom-image-lab"}),
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
			"a plan of an undeclared class is refused once, by the class, not once per entry",
			[]string{"zip-bundle"},
			"1.43.0", planFiles([2]string{"zip-bundle", "sbom-zip-lab"}),
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
			"1.43.0", planFiles([2]string{"wasm-npm", "sbom-npm-lab-wasm"}),
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
			[]assert.PlanFile{{Name: "p", Content: []byte(`[{"class": "oci-image", "doc": "sbom-npm-x", "extra": 1}]`)}},
			report.VerdictFail, "plan does not decode",
		},
		{
			"two different claims on one document are refused, never last-writer-wins",
			[]string{"wasm-npm"},
			"1.43.0",
			[]assert.PlanFile{{Name: "p", Content: []byte(
				`[{"class": "wasm-npm", "doc": "sbom-npm-x", "params": {"cargoPackage": "a"}},
				  {"class": "wasm-npm", "doc": "sbom-npm-x", "params": {"cargoPackage": "b"}}]`)}},
			report.VerdictFail, "legs disagree about what was built",
		},
		{
			"one document claimed by two classes is a disagreement, not a coincidence",
			[]string{"wasm-npm", "pgrx-extension"},
			"1.43.0",
			[]assert.PlanFile{{Name: "p", Content: []byte(
				`[{"class": "wasm-npm", "doc": "sbom-npm-x"}, {"class": "pgrx-extension", "doc": "sbom-npm-x"}]`)}},
			report.VerdictFail, "legs disagree about what was built",
		},
		{
			"identical restatements from matrix legs collapse",
			[]string{"wasm-npm"},
			"1.43.0",
			append(planFiles([2]string{"wasm-npm", "sbom-npm-lab-wasm"}),
				planFiles([2]string{"wasm-npm", "sbom-npm-lab-wasm"})...),
			report.VerdictPass, "",
		},
		{
			"restatements collapse by canonical content, not by byte accident",
			[]string{"wasm-npm"},
			"1.43.0",
			[]assert.PlanFile{
				{Name: "a", Content: []byte(
					`[{"class": "wasm-npm", "doc": "sbom-npm-x", "params": {"a": 1, "b": "two"}}]`)},
				{Name: "b", Content: []byte(
					`[{"class":"wasm-npm","doc":"sbom-npm-x","params":{ "b" : "two", "a" : 1 }}]`)},
			},
			report.VerdictPass, "",
		},
	}

	pol := loadPlansPolicy(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := assert.Plans(pol, tt.classes, tt.machinery, tt.files, report.NewJournal(), discard)

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
// defective leg's output never reaches a command line downstream —
// including inside params, whose content is opaque to the judgment
// but whose charset is not.
func TestPlansEntryShapeRefusals(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  string
	}{
		{"absent class", `{"doc": "sbom-npm-x"}`, "class is absent"},
		{"empty class", `{"class": "", "doc": "sbom-npm-x"}`, "class is absent"},
		{"class outside the vocabulary", `{"class": "a;b", "doc": "sbom-npm-x"}`, "class-name vocabulary"},
		{"absent doc", `{"class": "wasm-npm"}`, "doc is absent"},
		{"empty doc", `{"class": "wasm-npm", "doc": ""}`, "doc is absent"},
		{"doc outside the vocabulary", `{"class": "wasm-npm", "doc": "a;b"}`, "document-name vocabulary"},
		{"doc with a leading dot", `{"class": "wasm-npm", "doc": ".hidden"}`, "document-name vocabulary"},
		{
			"artifact outside the vocabulary",
			`{"class": "wasm-npm", "doc": "sbom-npm-x", "artifact": "a/b"}`,
			"artifact-name vocabulary",
		},
		{
			"params key outside the vocabulary",
			`{"class": "wasm-npm", "doc": "sbom-npm-x", "params": {"bad key": "x"}}`,
			"params-key vocabulary",
		},
		{
			"params value outside the vocabulary",
			`{"class": "wasm-npm", "doc": "sbom-npm-x", "params": {"cargoPackage": "a; rm -rf"}}`,
			"params-value vocabulary",
		},
		{
			"nested params value outside the vocabulary",
			`{"class": "wasm-npm", "doc": "sbom-npm-x", "params": {"features": ["ok", "no|pe"]}}`,
			"params-value vocabulary",
		},
		{
			"params that are not an object",
			`{"class": "wasm-npm", "doc": "sbom-npm-x", "params": "cargoPackage=x"}`,
			"params is not an object",
		},
	}

	pol := loadPlansPolicy(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := []assert.PlanFile{{Name: "p", Content: []byte("[" + tt.entry + "]")}}

			rep := assert.Plans(pol, []string{"oci-image"}, "1.43.0", files, report.NewJournal(), discard)
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

// TestPlansEmitsTheJudgedSet pins stele#151: the judgment carries the
// set it judged, so a consuming leg iterates that instead of
// re-collapsing the same plan files with a derivation of its own.
// Every row states what the emitted set must be, against inputs
// whose raw bytes say something different — restated matrix legs,
// params spelled two ways, files named in an order a caller chose.
func TestPlansEmitsTheJudgedSet(t *testing.T) {
	tests := []struct {
		name  string
		files []assert.PlanFile
		want  string
	}{
		{
			"a release planning nothing emits an empty set, never null",
			nil,
			`[]`,
		},
		{
			"the entries are the ones judged, params canonical",
			[]assert.PlanFile{{Name: "a", Content: []byte(
				`[{"class": "wasm-npm", "doc": "sbom-npm-x", "artifact": "x.tgz", "params": {"b": "two", "a": 1}}]`)}},
			`[{"class":"wasm-npm","doc":"sbom-npm-x","artifact":"x.tgz","params":{"a":1,"b":"two"}}]`,
		},
		{
			"matrix legs restating one mapping collapse to one entry",
			[]assert.PlanFile{
				{Name: "a", Content: []byte(`[{"class": "wasm-npm", "doc": "sbom-npm-x", "params": {"a": 1}}]`)},
				{Name: "b", Content: []byte(`[{"class":"wasm-npm","doc":"sbom-npm-x","params":{ "a" : 1 }}]`)},
			},
			`[{"class":"wasm-npm","doc":"sbom-npm-x","params":{"a":1}}]`,
		},
		{
			"the set is ordered by document, not by the order the files were named",
			[]assert.PlanFile{
				{Name: "z", Content: []byte(`[{"class": "wasm-npm", "doc": "sbom-npm-z"}]`)},
				{Name: "a", Content: []byte(`[{"class": "wasm-npm", "doc": "sbom-npm-a"}]`)},
			},
			`[{"class":"wasm-npm","doc":"sbom-npm-a"},{"class":"wasm-npm","doc":"sbom-npm-z"}]`,
		},
		{
			"a refused entry is judged and dropped, never emitted",
			[]assert.PlanFile{{Name: "a", Content: []byte(
				`[{"class": "wasm-npm", "doc": "sbom-npm-x"},` +
					`{"class": "wasm-npm", "doc": "sbom-npm-y", "params": {"cargoPackage": "a; rm -rf"}}]`)}},
			`[{"class":"wasm-npm","doc":"sbom-npm-x"}]`,
		},
		{
			"a document two legs disagree about is refused, and the first claim stands alone",
			[]assert.PlanFile{
				{Name: "a", Content: []byte(`[{"class": "wasm-npm", "doc": "sbom-npm-x", "params": {"a": 1}}]`)},
				{Name: "b", Content: []byte(`[{"class": "wasm-npm", "doc": "sbom-npm-x", "params": {"a": 2}}]`)},
			},
			`[{"class":"wasm-npm","doc":"sbom-npm-x","params":{"a":1}}]`,
		},
	}

	pol := loadPlansPolicy(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := assert.Plans(pol, []string{"wasm-npm"}, "1.41.0", tt.files, report.NewJournal(), discard)

			if got := string(rep.Judged()); got != tt.want {
				t.Fatalf("judged set = %s, want %s", got, tt.want)
			}
		})
	}
}
