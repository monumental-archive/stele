package policy_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/policy"
)

// valid is a complete, passing document. Each refusal case below is
// this document with exactly one fact broken, so a failing row names
// its guard and nothing else.
const valid = `{
  "schema": 7,
  "issuer": "https://token.example.com",
  "trust": {
    "provenance": {"signerWorkflow": "acme/signer/.github/workflows/sign.yml"},
    "verdict": {
      "verifierWorkflow": "acme/canon/.github/workflows/verify-release.yml",
      "legacyVerdicts": [
        {"repository": "acme/lab", "tag": "v0.1.0", "signerWorkflow": "acme/signer/.github/workflows/sign.yml"}
      ]
    },
    "decision": {
      "signerWorkflow": "acme/canon/.github/workflows/publish.yml",
      "predicateType": "https://acme.example/attestations/release-decision/v1",
      "requiredConclusion": "OPEN"
    }
  },
  "build": {
    "buildTypes": {
      "https://actions.github.io/buildtypes/workflow/v1": {"externalParameterKeys": ["workflow", "inputs"]}
    },
    "resourceUri": "pkg:github/{owner}/{repo}@v{version}",
    "sourceRepository": "https://github.com/{owner}/{repo}",
    "targetLevel": "SLSA_BUILD_LEVEL_3",
    "denySelfHostedRunners": true
  },
  "source": {
    "identity": "https://github.com/{owner}/{repo}/.github/workflows/source-attest.yml@refs/heads/main",
    "notesRef": "refs/notes/commits",
    "provenancePredicateType": "https://acme.example/attestations/source-provenance/v1",
    "propertyPrefix": "ACME_SOURCE_",
    "resourceUri": "git+https://github.com/{owner}/{repo}",
    "protectedBranches": [
      {
        "name": "main",
        "targetLevel": "SLSA_SOURCE_LEVEL_3",
        "levels": [{"level": "SLSA_SOURCE_LEVEL_3", "requiredProperties": [
          {"name": "ACME_SOURCE_GATED", "since": "2026-08-09T16:29:06+01:00"}
        ]}]
      }
    ],
    "healedContinuity": true,
    "underclaimLevel": "SLSA_SOURCE_LEVEL_2",
    "legacyLeaves": [
      {"repository": "acme/canon",
       "revision": "e1ad2dde9fd24fc521b4b37453dac052e655212b",
       "reason": "pre-v2 healed fork"}
    ]
  }
}`

// mutate applies one JSON-text substitution to the valid document.
// Every old string below occurs exactly once there, asserted by the
// helper so a refactor of the fixture cannot silently blunt a row.
func mutate(t *testing.T, from, to string) string {
	t.Helper()

	if n := strings.Count(valid, from); n != 1 {
		t.Fatalf("mutation target %q occurs %d times in the valid document, want exactly 1", from, n)
	}

	return strings.Replace(valid, from, to, 1)
}

const wantUnknownField = "unknown field"

func TestLoadValid(t *testing.T) {
	t.Parallel()

	p, err := policy.Load(strings.NewReader(valid))
	if err != nil {
		t.Fatalf("Load(valid) = %v", err)
	}

	if got := *p.Trust.Provenance.SignerWorkflow; got != "acme/signer/.github/workflows/sign.yml" {
		t.Errorf("signerWorkflow = %q", got)
	}

	if got := len(p.Source.ProtectedBranches[0].Levels[0].RequiredProperties); got != 1 {
		t.Errorf("requiredProperties length = %d, want 1", got)
	}
}

// TestLoadWithoutDecision pins the optional section: a release
// decision is an obligation an org declares, never a precondition of
// using the verifier — a fresh adopter or a single repository omits
// the section and the policy loads; a partial declaration still
// refuses field by field (the row above).
func TestLoadWithoutDecision(t *testing.T) {
	t.Parallel()

	trimmed := strings.Replace(valid, `"decision": {
      "signerWorkflow": "acme/canon/.github/workflows/publish.yml",
      "predicateType": "https://acme.example/attestations/release-decision/v1",
      "requiredConclusion": "OPEN"
    }`, `"decision": null`, 1)

	p, err := policy.Load(strings.NewReader(trimmed))
	if err != nil {
		t.Fatalf("Load without trust.decision = %v — the section must be optional", err)
	}

	if p.Trust.Decision != nil {
		t.Fatal("an absent section decoded as present")
	}
}

// TestLoadMinimal proves the universality floor (#82): a valid policy
// is schema + issuer + a provenance identity, possibly templated to
// the repository itself. Verdicts, decisions, build and source are
// obligations an org declares; the verbs refuse at use, not at load.
func TestLoadMinimal(t *testing.T) {
	t.Parallel()

	const minimal = `{
	  "schema": 7,
	  "issuer": "https://token.example.com",
	  "trust": {
	    "provenance": {"signerWorkflow": "{owner}/{repo}/.github/workflows/release.yml"}
	  }
	}`

	p, err := policy.Load(strings.NewReader(minimal))
	if err != nil {
		t.Fatalf("Load minimal = %v — issuer plus a provenance identity must be a valid policy", err)
	}

	if p.Trust.Verdict != nil || p.Trust.Decision != nil || p.Build != nil || p.Source != nil {
		t.Fatal("absent sections decoded as present")
	}
}

// TestLoadTemplatedIdentities: workflow identities are roles — the
// self-attesting template is accepted, and only {owner}/{repo} are
// vocabulary (a per-tag identity is a wildcard, not a role).
func TestLoadTemplatedIdentities(t *testing.T) {
	t.Parallel()

	templated := strings.Replace(valid,
		`"provenance": {"signerWorkflow": "acme/signer/.github/workflows/sign.yml"}`,
		`"provenance": {"signerWorkflow": "{owner}/{repo}/.github/workflows/release.yml"}`, 1)
	if _, err := policy.Load(strings.NewReader(templated)); err != nil {
		t.Fatalf("Load templated signerWorkflow = %v — the self-attesting role must be expressible", err)
	}

	for _, bad := range []string{
		"{owner}/{repo}/.github/workflows/{tag}.yml",
		"{owner}/{typo}/.github/workflows/release.yml",
		"{owner}/{repo}",
	} {
		doc := strings.Replace(valid,
			`"provenance": {"signerWorkflow": "acme/signer/.github/workflows/sign.yml"}`,
			`"provenance": {"signerWorkflow": "`+bad+`"}`, 1)
		if _, err := policy.Load(strings.NewReader(doc)); err == nil {
			t.Fatalf("Load accepted signerWorkflow %q", bad)
		}
	}
}

// schemaPlusOne renders the epoch this build does NOT implement. A
// guard must not carry a second hand-maintained copy of the number it
// guards: written as a literal, an epoch bump can sweep both sides of
// the mutation to the same value, and the row then asserts a refusal
// against a perfectly valid document (stele#107's lesson applied to
// its own tests).
func schemaPlusOne() string {
	return fmt.Sprintf(`"schema": %d`, policy.Schema+1)
}

func TestLoadRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"not json at all", valid, "not json", "decode"},
		{"unknown field", `"schema": 7`, `"schema": 7, "surprise": true`, wantUnknownField},
		{"schema absent", `"schema": 7,`, ``, "schema is absent"},
		{"schema newer", `"schema": 7`, schemaPlusOne(), "not the implemented schema"},
		// The gate fires FIRST (stele#107): a schema-1 document
		// carrying the pre-#84 vocabulary this decoder no longer knows
		// must refuse as a VERSION mismatch, never incidentally as an
		// unknown field — that is the whole reason the gate exists.
		{
			"old schema with old vocabulary is a version error",
			`"schema": 7`,
			`"schema": 1, "storeVsaFromCanon": true`,
			"not the implemented schema",
		},
		{"issuer absent", `"issuer": "https://token.example.com",`, ``, "issuer"},
		{"issuer not https", `"issuer": "https://token.example.com"`, `"issuer": "http://token.example.com"`, "issuer"},
		{
			"unknown field nested",
			`"requiredConclusion": "OPEN"`,
			`"requiredConclusion": "OPEN", "surprise": 1`,
			wantUnknownField,
		},
		{
			"trust null",
			`"trust": {
    "provenance": {"signerWorkflow": "acme/signer/.github/workflows/sign.yml"},
    "verdict": {
      "verifierWorkflow": "acme/canon/.github/workflows/verify-release.yml",
      "legacyVerdicts": [
        {"repository": "acme/lab", "tag": "v0.1.0", "signerWorkflow": "acme/signer/.github/workflows/sign.yml"}
      ]
    },
    "decision": {
      "signerWorkflow": "acme/canon/.github/workflows/publish.yml",
      "predicateType": "https://acme.example/attestations/release-decision/v1",
      "requiredConclusion": "OPEN"
    }
  }`,
			`"trust": null`,
			"trust is absent",
		},
		{
			"decision declared but its signer broken",
			`"signerWorkflow": "acme/canon/.github/workflows/publish.yml",
      "predicateType"`,
			`"signerWorkflow": "not-a-workflow",
      "predicateType"`,
			"trust.decision.signerWorkflow",
		},
		{
			"provenance absent",
			`"provenance": {"signerWorkflow": "acme/signer/.github/workflows/sign.yml"},`,
			`"provenance": null,`,
			"trust.provenance is absent",
		},
		{
			"signer workflow malformed",
			`"provenance": {"signerWorkflow": "acme/signer/.github/workflows/sign.yml"}`,
			`"provenance": {"signerWorkflow": "not-a-workflow"}`,
			"trust.provenance.signerWorkflow",
		},
		{
			"verifier workflow absent",
			`"verifierWorkflow": "acme/canon/.github/workflows/verify-release.yml",`,
			``,
			"trust.verdict.verifierWorkflow",
		},
		{
			"legacy verdict repo malformed",
			`{"repository": "acme/lab", "tag": "v0.1.0"`,
			`{"repository": "acme", "tag": "v0.1.0"`,
			"legacyVerdicts[0].repository",
		},
		{"legacy verdict tag empty", `"tag": "v0.1.0"`, `"tag": ""`, "legacyVerdicts[0].tag"},
		{
			"legacy verdict signer malformed",
			`"tag": "v0.1.0", "signerWorkflow": "acme/signer/.github/workflows/sign.yml"`,
			`"tag": "v0.1.0", "signerWorkflow": "nope"`,
			"legacyVerdicts[0].signerWorkflow",
		},
		{
			"decision signer malformed",
			`"signerWorkflow": "acme/canon/.github/workflows/publish.yml"`,
			`"signerWorkflow": "publish.yml"`,
			"trust.decision.signerWorkflow",
		},
		{
			"decision predicate not https",
			`"predicateType": "https://acme.example/attestations/release-decision/v1"`,
			`"predicateType": "release-decision/v1"`,
			"trust.decision.predicateType",
		},
		{
			"decision conclusion empty",
			`"requiredConclusion": "OPEN"`,
			`"requiredConclusion": ""`,
			"trust.decision.requiredConclusion",
		},
		{
			"buildTypes empty",
			`"buildTypes": {
      "https://actions.github.io/buildtypes/workflow/v1": {"externalParameterKeys": ["workflow", "inputs"]}
    }`,
			`"buildTypes": {}`,
			"build.buildTypes is absent or empty",
		},
		{
			"buildType key not a URI",
			`"https://actions.github.io/buildtypes/workflow/v1": {"externalParameterKeys"`,
			`"workflow/v1": {"externalParameterKeys"`,
			"not an https URI",
		},
		{
			"externalParameterKeys absent",
			`{"externalParameterKeys": ["workflow", "inputs"]}`,
			`{}`,
			"externalParameterKeys is absent",
		},
		{
			"resourceUri unknown placeholder",
			`"resourceUri": "pkg:github/{owner}/{repo}@v{version}"`,
			`"resourceUri": "pkg:github/{blorp}/{repo}@v{version}"`,
			"unknown placeholder {blorp}",
		},
		{
			"sourceRepository empty",
			`"sourceRepository": "https://github.com/{owner}/{repo}"`,
			`"sourceRepository": ""`,
			"build.sourceRepository is absent or empty",
		},
		{
			"build level malformed",
			`"targetLevel": "SLSA_BUILD_LEVEL_3"`,
			`"targetLevel": "SLSA_BUILD_L3"`,
			"build.targetLevel",
		},
		{"deny runners absent", `,
    "denySelfHostedRunners": true`, ``, "denySelfHostedRunners is absent"},
		{
			"source identity unknown placeholder",
			`source-attest.yml@refs/heads/main"`,
			`source-attest.yml@{ref}"`,
			"unknown placeholder {ref}",
		},
		{"notesRef unqualified", `"notesRef": "refs/notes/commits"`, `"notesRef": "commits"`, "source.notesRef"},
		{
			"source predicate not https",
			`"provenancePredicateType": "https://acme.example/attestations/source-provenance/v1"`,
			`"provenancePredicateType": "source-provenance/v1"`,
			"source.provenancePredicateType",
		},
		{"property prefix empty", `"propertyPrefix": "ACME_SOURCE_"`, `"propertyPrefix": ""`, "source.propertyPrefix"},
		{
			"source resourceUri empty",
			`"resourceUri": "git+https://github.com/{owner}/{repo}"`,
			`"resourceUri": ""`,
			"source.resourceUri is absent or empty",
		},
		{"branches empty", `"protectedBranches": [
      {
        "name": "main",
        "targetLevel": "SLSA_SOURCE_LEVEL_3",
        "levels": [{"level": "SLSA_SOURCE_LEVEL_3", "requiredProperties": [
          {"name": "ACME_SOURCE_GATED", "since": "2026-08-09T16:29:06+01:00"}
        ]}]
      }
    ]`, `"protectedBranches": []`, "source.protectedBranches is absent or empty"},
		{"branch name empty", `"name": "main"`, `"name": ""`, "protectedBranches[0].name"},
		{
			// A branch declaring a target with no level claims under it
			// establishes that target from nothing, which is the same as
			// claiming it outright.
			"a branch that claims a target but establishes no level",
			`"levels": [{"level": "SLSA_SOURCE_LEVEL_3", "requiredProperties": [
          {"name": "ACME_SOURCE_GATED", "since": "2026-08-09T16:29:06+01:00"}
        ]}]`,
			`"levels": []`,
			"protectedBranches[0].levels is absent or empty",
		},
		{
			"a level claim naming no readable level",
			`"levels": [{"level": "SLSA_SOURCE_LEVEL_3"`,
			`"levels": [{"level": "SOURCE_3"`,
			"levels[0].level",
		},
		{
			// One level, one claim: two entries for a level are two
			// property sets for one rung, and nothing decides between
			// them.
			"one level claimed twice",
			`"levels": [{"level": "SLSA_SOURCE_LEVEL_3", "requiredProperties": [
          {"name": "ACME_SOURCE_GATED", "since": "2026-08-09T16:29:06+01:00"}
        ]}]`,
			`"levels": [
          {"level": "SLSA_SOURCE_LEVEL_3", "requiredProperties": [
            {"name": "ACME_SOURCE_GATED", "since": "2026-08-09T16:29:06+01:00"}]},
          {"level": "SLSA_SOURCE_LEVEL_3", "requiredProperties": [
            {"name": "ACME_SOURCE_DCO", "since": "2026-08-09T16:29:06+01:00"}]}]`,
			"declares SLSA_SOURCE_LEVEL_3 more than once",
		},
		{
			// A required property with no name matches every property
			// and none: the join it drives is by name.
			"a required property with no name",
			`{"name": "ACME_SOURCE_GATED", "since": "2026-08-09T16:29:06+01:00"}`,
			`{"name": "", "since": "2026-08-09T16:29:06+01:00"}`,
			"name is absent or empty",
		},
		{
			"branch level malformed",
			`"targetLevel": "SLSA_SOURCE_LEVEL_3"`,
			`"targetLevel": "LEVEL_3"`,
			"protectedBranches[0].targetLevel",
		},
		{
			"required properties empty",
			`"levels": [{"level": "SLSA_SOURCE_LEVEL_3", "requiredProperties": [
          {"name": "ACME_SOURCE_GATED", "since": "2026-08-09T16:29:06+01:00"}
        ]}]`,
			`"levels": [{"level": "SLSA_SOURCE_LEVEL_3", "requiredProperties": []}]`,
			"requiredProperties is absent or empty",
		},
		{
			"property outside prefix",
			`"name": "ACME_SOURCE_GATED"`,
			`"name": "OTHER_GATED"`,
			"must carry the property prefix",
		},
		{
			"since absent",
			`"name": "ACME_SOURCE_GATED", "since": "2026-08-09T16:29:06+01:00"`,
			`"name": "ACME_SOURCE_GATED"`,
			"since is absent",
		},
		{"since not rfc3339", `"since": "2026-08-09T16:29:06+01:00"`, `"since": "9 Aug 2026"`, "not RFC 3339"},
		{"healed continuity absent", `"healedContinuity": true,`, ``, "healedContinuity is absent"},
		{
			"underclaim level malformed",
			`"underclaimLevel": "SLSA_SOURCE_LEVEL_2"`,
			`"underclaimLevel": "two"`,
			"source.underclaimLevel",
		},
		{
			"leaf repo malformed",
			`{"repository": "acme/canon",`,
			`{"repository": "canon",`,
			"legacyLeaves[0].repository",
		},
		{
			"leaf revision abbreviated",
			`"revision": "e1ad2dde9fd24fc521b4b37453dac052e655212b"`,
			`"revision": "e1ad2dde"`,
			"full 40-hex",
		},
		{"leaf reason empty", `"reason": "pre-v2 healed fork"`, `"reason": ""`, "legacyLeaves[0].reason"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := tt.new
			if tt.old != valid {
				doc = mutate(t, tt.old, tt.new)
			}

			_, err := policy.Load(strings.NewReader(doc))
			if err == nil {
				t.Fatal("Load accepted a document it must refuse")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Load error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestLoadEmptyExternalParameterKeys pins the nil/empty distinction:
// an explicit empty list is the reject-all stance and loads clean.
func TestLoadEmptyExternalParameterKeys(t *testing.T) {
	t.Parallel()

	doc := mutate(t, `{"externalParameterKeys": ["workflow", "inputs"]}`, `{"externalParameterKeys": []}`)

	p, err := policy.Load(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Load(empty externalParameterKeys) = %v", err)
	}

	keys := p.Build.BuildTypes["https://actions.github.io/buildtypes/workflow/v1"].ExternalParameterKeys
	if keys == nil || len(keys) != 0 {
		t.Errorf("ExternalParameterKeys = %v, want present and empty", keys)
	}
}

// TestLoadTrailingData pins the one-document rule end to end.
func TestLoadTrailingData(t *testing.T) {
	t.Parallel()

	if _, err := policy.Load(strings.NewReader(valid + "{}")); err == nil {
		t.Fatal("Load accepted trailing data")
	}
}

// The enrichment obligation: absent means it does not exist, declared
// means every field of it — plus the one cross-section rule, because
// an obligation proved under an identity nobody declared could never
// be proved at all.
func TestEnrichmentSection(t *testing.T) {
	t.Parallel()

	// declare splices one enrichment object into the valid document's
	// build section — one source of policy truth, mutated per row.
	declare := func(section string) string {
		return strings.Replace(valid, `"denySelfHostedRunners": true`,
			`"denySelfHostedRunners": true,
    "enrichment": `+section, 1)
	}

	// verdictSection is the block a row removes to prove the
	// cross-section rule: the enrichment verifies under the verdict
	// identity, so declaring one without the other is unprovable.
	const verdictSection = `"verdict": {
      "verifierWorkflow": "acme/canon/.github/workflows/verify-release.yml",
      "legacyVerdicts": [
        {"repository": "acme/lab", "tag": "v0.1.0", "signerWorkflow": "acme/signer/.github/workflows/sign.yml"}
      ]
    },
    `

	const good = `{
      "predicateType": "https://acme.example/attestations/build-enrichment/v1",
      "required": ["toolbelt-lock"],
      "permitted": ["Cargo.lock"]
    }`

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "a whole declaration loads",
			doc:  declare(good),
		},
		{
			name: "permitted may be absent: the required names are then the whole set",
			doc: declare(`{
      "predicateType": "https://acme.example/attestations/build-enrichment/v1",
      "required": ["toolbelt-lock"]
    }`),
		},
		{
			name: "an obligation with no identity to prove it under",
			doc:  strings.Replace(declare(good), verdictSection, "", 1),
			want: "could never be proven",
		},
		{
			name: "a predicate type that is not a URI",
			doc: declare(`{
      "predicateType": "build-enrichment/v1",
      "required": ["toolbelt-lock"]
    }`),
			want: "predicateType must be present and an https URI",
		},
		{
			name: "an obligation requiring nothing",
			doc: declare(`{
      "predicateType": "https://acme.example/attestations/build-enrichment/v1",
      "required": []
    }`),
			want: "an obligation requiring nothing is not an obligation",
		},
		{
			name: "an empty dependency name",
			doc: declare(`{
      "predicateType": "https://acme.example/attestations/build-enrichment/v1",
      "required": ["toolbelt-lock", ""]
    }`),
			want: "empty dependency name",
		},
		{
			name: "a name that is both required and permitted",
			doc: declare(`{
      "predicateType": "https://acme.example/attestations/build-enrichment/v1",
      "required": ["toolbelt-lock"],
      "permitted": ["toolbelt-lock"]
    }`),
			want: "one closed set",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p, err := policy.Load(strings.NewReader(tc.doc))

			if tc.want == "" {
				if err != nil {
					t.Fatalf("Load = %v, want the declaration accepted", err)
				}

				if p.Build.Enrichment == nil || len(p.Build.Enrichment.Required) == 0 {
					t.Fatalf("build.enrichment = %+v, want the declaration decoded", p.Build.Enrichment)
				}

				return
			}

			if err == nil {
				t.Fatalf("Load accepted %s", tc.name)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load error = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// The claims table is an obligation like every other section: absent
// means the org does not derive claims with this tool. Declared, it
// is validated, and the cross-check that gives the section its reason
// to exist fires — a property a branch REQUIRES but the table cannot
// derive is unclaimable, so that branch could never reach its target
// level. Today that is a silent permanent under-claim spread across a
// policy file, an org doc and a shell script; here it refuses at
// load.
func TestLoadClaimsTable(t *testing.T) {
	t.Parallel()

	const declared = `"protectedBranches": [`

	// withClaims splices a claims table beside the branch that
	// requires ACME_SOURCE_GATED.
	withClaims := func(t *testing.T, table string) string {
		t.Helper()

		return mutate(t, declared, `"claims": `+table+`,
    `+declared)
	}

	gatedMatcher := `{"properties": [{"name": "ACME_SOURCE_GATED", "scope": "branchRules",
	  "match": {"$contains": [{"type": "required_status_checks"}]}}]}`

	t.Run("a table deriving every required property loads", func(t *testing.T) {
		t.Parallel()

		p, err := policy.Load(strings.NewReader(withClaims(t, gatedMatcher)))
		if err != nil {
			t.Fatalf("Load = %v", err)
		}

		if p.Source.Claims == nil || !p.Source.Claims.Declares("ACME_SOURCE_GATED") {
			t.Fatal("the claims table did not survive the load")
		}
	})

	t.Run("an absent table is an undeclared obligation, not an error", func(t *testing.T) {
		t.Parallel()

		p, err := policy.Load(strings.NewReader(valid))
		if err != nil {
			t.Fatalf("Load = %v", err)
		}

		if p.Source.Claims != nil {
			t.Fatal("a table appeared from nowhere")
		}
	})

	tests := []struct {
		name  string
		table string
		want  string
	}{
		{
			"a required property the table cannot derive",
			`{"properties": [{"name": "ACME_SOURCE_OTHER", "scope": "branchRules",
			  "match": {"$contains": [{"type": "deletion"}]}}]}`,
			"could never reach SLSA_SOURCE_LEVEL_3",
		},
		{
			"the table's own validation runs at load",
			`{"properties": [{"name": "ACME_SOURCE_GATED", "scope": "branchRules"}]}`,
			"declares no match",
		},
		{
			"a matcher outside the language",
			`{"properties": [{"name": "ACME_SOURCE_GATED", "scope": "branchRules",
			  "match": {"$regex": "ci"}}]}`,
			"reserved operator namespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := policy.Load(strings.NewReader(withClaims(t, tt.table)))
			if err == nil {
				t.Fatalf("Load = nil error, want %q", tt.want)
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// An absent section is no obligation at all — the declared-obligation
// principle, which a minimal adopter depends on.
func TestEnrichmentAbsent(t *testing.T) {
	t.Parallel()

	p, err := policy.Load(strings.NewReader(valid))
	if err != nil {
		t.Fatalf("Load = %v", err)
	}

	if p.Build.Enrichment != nil {
		t.Errorf("build.enrichment = %+v, want nil when undeclared", p.Build.Enrichment)
	}
}
