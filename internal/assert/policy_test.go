// The policy loader's guards: every malformed shape refuses by name.

package assert_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/verify"
)

// schemaPlusOne renders the epoch this build does NOT implement —
// derived, never written, so an epoch bump cannot sweep both sides of
// the mutation to the same value and leave the row asserting a
// refusal against a valid document.
func schemaPlusOne() string {
	return fmt.Sprintf(`"schema": %d`, assert.PolicySchema+1)
}

func TestLoadPolicyRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		json string
		want string
	}{
		{"wrong schema", strings.Replace(testPolicyJSON, `"schema": 7`, schemaPlusOne(), 1), "schema"},
		{"unknown field", strings.Replace(testPolicyJSON, `"schema": 7`, `"schema": 7, "extra": true`, 1), "unknown"},
		{
			"empty classes",
			`{"schema": 7, "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",
			  "umbrellaBundle": "u.jsonl", "manifestAsset": "m.json", "classes": {}}}`,
			"classes is empty",
		},
		{
			"a class requiring nothing",
			`{"schema": 7, "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",
			  "umbrellaBundle": "u.jsonl", "manifestAsset": "m.json",
			  "classes": {"idle": {"bundles": []}}}}`,
			"requires nothing",
		},
		{
			"missing required string",
			`{"schema": 7, "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",
			  "umbrellaBundle": "u.jsonl",
			  "classes": {"a": {"bundles": ["b"]}}}}`,
			"manifestAsset",
		},
		{
			"unparsable epoch",
			strings.Replace(testPolicyJSON, `"storeVsaFromVersion": "1.13.0"`, `"storeVsaFromVersion": "not-a-version"`, 1),
			"storeVsaFromVersion",
		},
		{
			"a population declared as nothing",
			strings.Replace(testPolicyJSON, `"evidence": {`,
				`"population": {"repositories": []}, "evidence": {`, 1),
			"population.repositories is empty",
		},
		{
			"a population entry with no repository",
			strings.Replace(testPolicyJSON, `"evidence": {`,
				`"population": {"repositories": [{"tracks": ["build"], "reason": "why"}]}, "evidence": {`, 1),
			"repositories[0].repo is absent or empty",
		},
		{
			"a narrowing with no reason",
			strings.Replace(testPolicyJSON, `"evidence": {`,
				`"population": {"repositories": [{"repo": "signer", "tracks": ["source"]}]}, "evidence": {`, 1),
			"repositories[0].reason is absent or empty",
		},
		{
			"a track name this release does not judge",
			strings.Replace(testPolicyJSON, `"evidence": {`,
				`"population": {"repositories": [{"repo": "a", "tracks": ["BUILD"], `+
					`"reason": "the SlsaResult spelling"}]}, "evidence": {`, 1),
			"no track this release judges",
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
				`"schema": 7`, `"schema": 1`,
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

// TestTagsPolicyRefusals: the tags section is optional, but declared
// means every field, validated strictly (stele#83).
func TestTagsPolicyRefusals(t *testing.T) {
	t.Parallel()

	const base = `{"schema": 7, "issuer": "https://token.example.com",
	  "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",
	    "umbrellaBundle": "u.jsonl", "manifestAsset": "m.json", 	    "classes": {"a": {"bundles": ["b"]}}},
	  "tags": {"tagPattern": "^v[0-9]", "taggerName": "mint[bot]",
	    "identityPattern": "^https://github\\.com/acme/", "proofFloor": {"floor": "certificate-transparency"},
	    "notesRef": "refs/notes/commits",
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
		{
			"missing proof floor", `"proofFloor": {"floor": "certificate-transparency"},`, ``,
			"proofFloor",
		},
		{
			"unknown proof floor", `"proofFloor": {"floor": "certificate-transparency"}`,
			`"proofFloor": {"floor": "vibes"}`, "not a floor this verifier judges",
		},
		{"no epochs", `"epochs": {"widget": "v1.0.0", "gadget": "pending"}`, `"epochs": {}`, "epochs"},
		{
			"unparsable epoch", `"epochs": {"widget": "v1.0.0", "gadget": "pending"}`,
			`"epochs": {"widget": "soon"}`, "epochs[widget]",
		},
		{"issuer missing beside tags", `"issuer": "https://token.example.com",`, ``, "issuer"},

		// The floor-with-a-from (stele#186). Half a declaration is a
		// declaration with a hole in it, and a hole here is tags owing
		// nothing at all.
		{
			"a rise with nothing beneath it", `"proofFloor": {"floor": "certificate-transparency"}`,
			`"proofFloor": {"floor": "observer-timestamp", "from": {"widget": "v1.2.0"}}`,
			"together or not at all",
		},
		{
			"a floor beneath a boundary that is never named",
			`"proofFloor": {"floor": "certificate-transparency"}`,
			`"proofFloor": {"floor": "observer-timestamp", "before": "certificate-transparency"}`,
			"together or not at all",
		},
		{
			"one floor on both sides of a boundary",
			`"proofFloor": {"floor": "certificate-transparency"}`,
			`"proofFloor": {"floor": "observer-timestamp", "from": {"widget": "v1.2.0"},
			  "before": "observer-timestamp"}`,
			"declares nothing",
		},
		{
			"an unknown floor beneath the boundary",
			`"proofFloor": {"floor": "certificate-transparency"}`,
			`"proofFloor": {"floor": "observer-timestamp", "from": {"widget": "v1.2.0"},
			  "before": "vibes"}`,
			"not a floor this verifier judges",
		},
		{
			"an unparsable boundary tag",
			`"proofFloor": {"floor": "certificate-transparency"}`,
			`"proofFloor": {"floor": "observer-timestamp", "from": {"widget": "soon"},
			  "before": "certificate-transparency"}`,
			"proofFloor.from[widget]",
		},
		{
			"a rise for a repository that owes no signature",
			`"proofFloor": {"floor": "certificate-transparency"}`,
			`"proofFloor": {"floor": "observer-timestamp", "from": {"stranger": "v1.2.0"},
			  "before": "certificate-transparency"}`,
			"tags.epochs does not name",
		},
		{
			"a rise for a repository declared unsigned",
			`"proofFloor": {"floor": "certificate-transparency"}`,
			`"proofFloor": {"floor": "observer-timestamp", "from": {"gadget": "v1.2.0"},
			  "before": "certificate-transparency"}`,
			"declared unsigned",
		},
		{
			"a rise before signing began",
			`"proofFloor": {"floor": "certificate-transparency"}`,
			`"proofFloor": {"floor": "observer-timestamp", "from": {"widget": "v0.9.0"},
			  "before": "certificate-transparency"}`,
			"before the signing epoch",
		},
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

// enrichedPolicy is the test policy with enrichment names hung off two
// of its three classes: oci-image owes one, pgrx-extension owes two
// (declared out of order, so sorting is observable), rust-crate owes
// none.
func enrichedPolicy(t *testing.T) *assert.Policy {
	t.Helper()

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

	return p
}

// app and ext are one artifact of each enriched class.
var demandSubjects = []verify.Subject{
	{Name: "app.tar.gz", SHA256: strings.Repeat("a", 64)},
	{Name: "ext.tar.gz", SHA256: strings.Repeat("b", 64)},
}

// TestEnrichmentDemandAttributed pins the derivation where the
// manifest says which class built what (stele#206): each artifact owes
// exactly its own class's names, in full, and nothing is excused.
// Holding every artifact to the release's whole class set is the
// defect this replaced — it asks a rust binary to answer for a pgrx
// tarball's build.
func TestEnrichmentDemandAttributed(t *testing.T) {
	t.Parallel()

	p := enrichedPolicy(t)

	ad := p.Evidence.EnrichmentDemand(&assert.Contract{
		Classes:    []string{"oci-image", "pgrx-extension"},
		Enrichment: true, Attributed: true, ManifestSchema: 3,
		ArtifactClasses: map[string]string{"app.tar.gz": "oci-image", "ext.tar.gz": "pgrx-extension"},
	}, demandSubjects)

	if ad.Demand == nil {
		t.Fatal("demand = nil, want a per-artifact demand")
	}

	want := map[string][]string{
		"app.tar.gz": {"base-images"},
		"ext.tar.gz": {"base-images", "pgrx-base"},
	}
	for artifact, names := range want {
		if got := ad.Demand.ByArtifact[artifact]; !slices.Equal(got, names) {
			t.Fatalf("%s owes %v, want %v", artifact, got, names)
		}
	}

	if len(ad.Excused) != 0 {
		t.Fatalf("excused = %+v, want nothing excused where the class is knowable", ad.Excused)
	}

	if len(ad.Defects) != 0 {
		t.Fatalf("defects = %+v, want none", ad.Defects)
	}
}

// TestEnrichmentDemandBranches walks every other branch of the
// derivation: the obligation not owed at all, the classless narrowing
// and its loud line, a narrowing with nothing to narrow, and the two
// ways an attributing manifest can be broken — which are DEFECTS held
// to the whole declared set, never narrowings (stele#206, ruling (a)).
func TestEnrichmentDemandBranches(t *testing.T) {
	t.Parallel()

	p := enrichedPolicy(t)

	tests := []struct {
		name string
		c    *assert.Contract
		// nilDemand asserts the obligation is not owed at all.
		nilDemand bool
		// owed is what each artifact must owe; absent means nothing.
		owed map[string][]string
		// excused and defect are substrings every note must carry, and
		// the count of artifacts they must cover.
		excused, defect string
		notes           int
	}{
		{
			name:      "not owed is nil, never the empty demand",
			c:         &assert.Contract{Classes: []string{"pgrx-extension"}, Enrichment: false},
			nilDemand: true,
		},
		{
			name: "classless narrows every artifact and names what it excused",
			c: &assert.Contract{
				Classes: []string{"oci-image", "pgrx-extension"}, Enrichment: true,
				Attributed: false, ManifestSchema: 2,
			},
			excused: "class unknowable under schema 2 — excused: base-images, pgrx-base",
			notes:   2,
		},
		{
			name: "no manifest at all names its own cause, never a schema it never carried",
			c: &assert.Contract{
				Classes: []string{"pgrx-extension"}, Enrichment: true,
				Attributed: false, ManifestSchema: 0,
			},
			excused: "class unknowable: no manifest attributes this release's artifacts",
			notes:   2,
		},
		{
			name: "a classless release owing no class extras excuses nothing and says nothing",
			c: &assert.Contract{
				Classes: []string{"rust-crate"}, Enrichment: true,
				Attributed: false, ManifestSchema: 2,
			},
		},
		{
			name: "an attributed artifact the manifest omits is a defect, held to the whole set",
			c: &assert.Contract{
				Classes: []string{"oci-image", "pgrx-extension"}, Enrichment: true,
				Attributed: true, ManifestSchema: 3,
				ArtifactClasses: map[string]string{"app.tar.gz": "oci-image"},
			},
			owed: map[string][]string{
				"app.tar.gz": {"base-images"},
				"ext.tar.gz": {"base-images", "pgrx-base"},
			},
			defect: "attributes every artifact to a class and this one to none" +
				" — held to the whole declared set (base-images, pgrx-base)",
			notes: 1,
		},
		{
			name: "an artifact attributed to a class the policy does not define is a defect",
			c: &assert.Contract{
				Classes: []string{"oci-image", "pgrx-extension"}, Enrichment: true,
				Attributed: true, ManifestSchema: 3,
				ArtifactClasses: map[string]string{"app.tar.gz": "oci-image", "ext.tar.gz": "conjured"},
			},
			owed: map[string][]string{
				"app.tar.gz": {"base-images"},
				"ext.tar.gz": {"base-images", "pgrx-base"},
			},
			defect: `built by class "conjured", which the policy does not define`,
			notes:  1,
		},
		{
			name: "a broken attribution with nothing to name still refuses to narrow",
			c: &assert.Contract{
				Classes: []string{"rust-crate"}, Enrichment: true,
				Attributed: true, ManifestSchema: 3,
			},
			defect: "attributes every artifact to a class and this one to none",
			notes:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ad := p.Evidence.EnrichmentDemand(tt.c, demandSubjects)

			if tt.nilDemand {
				if ad.Demand != nil {
					t.Fatalf("demand = %+v, want nil for pre-epoch history", ad.Demand)
				}

				return
			}

			if ad.Demand == nil {
				t.Fatal("demand = nil, want a demand where the obligation is owed")
			}

			for _, s := range demandSubjects {
				if got := ad.Demand.ByArtifact[s.Name]; !slices.Equal(got, tt.owed[s.Name]) {
					t.Fatalf("%s owes %v, want %v", s.Name, got, tt.owed[s.Name])
				}
			}

			assertNotes(t, "excused", ad.Excused, tt.excused, tt.notes)
			assertNotes(t, "defect", ad.Defects, tt.defect, tt.notes)
		})
	}
}

// assertNotes holds one note list to its expected substring and count.
// want empty means the list must be empty: a narrowing or a defect
// that says nothing is the silence this mechanism exists to prevent.
func assertNotes(t *testing.T, kind string, notes []assert.ArtifactNote, want string, count int) {
	t.Helper()

	if want == "" {
		if len(notes) != 0 {
			t.Fatalf("%s notes = %+v, want none", kind, notes)
		}

		return
	}

	if len(notes) != count {
		t.Fatalf("%s notes = %+v, want %d", kind, notes, count)
	}

	for _, n := range notes {
		if n.Artifact == "" {
			t.Fatalf("%s note %+v names no artifact — an unattributable note cannot be audited", kind, n)
		}

		if !strings.Contains(n.Detail, want) {
			t.Fatalf("%s note for %s = %q, want substring %q", kind, n.Artifact, n.Detail, want)
		}
	}
}
