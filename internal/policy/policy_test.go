package policy_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/policy"
)

// valid is a complete, passing document. Each refusal case below is
// this document with exactly one fact broken, so a failing row names
// its guard and nothing else.
const valid = `{
  "schema": 1,
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
        "requiredProperties": [
          {"name": "ACME_SOURCE_GATED", "since": "2026-08-09T16:29:06+01:00"}
        ]
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

	if got := len(p.Source.ProtectedBranches[0].RequiredProperties); got != 1 {
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

func TestLoadRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"not json at all", valid, "not json", "decode"},
		{"unknown field", `"schema": 1`, `"schema": 1, "surprise": true`, wantUnknownField},
		{"schema absent", `"schema": 1,`, ``, "schema is absent"},
		{"schema newer", `"schema": 1`, `"schema": 2`, "not the implemented schema"},
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
			"verdict null",
			`"verdict": {
      "verifierWorkflow": "acme/canon/.github/workflows/verify-release.yml",
      "legacyVerdicts": [
        {"repository": "acme/lab", "tag": "v0.1.0", "signerWorkflow": "acme/signer/.github/workflows/sign.yml"}
      ]
    }`,
			`"verdict": null`,
			"trust.verdict is absent",
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
			"build null",
			`"build": {
    "buildTypes": {
      "https://actions.github.io/buildtypes/workflow/v1": {"externalParameterKeys": ["workflow", "inputs"]}
    },
    "resourceUri": "pkg:github/{owner}/{repo}@v{version}",
    "sourceRepository": "https://github.com/{owner}/{repo}",
    "targetLevel": "SLSA_BUILD_LEVEL_3",
    "denySelfHostedRunners": true
  }`,
			`"build": null`,
			"build is absent",
		},
		{
			"source null",
			`"source": {
    "identity": "https://github.com/{owner}/{repo}/.github/workflows/source-attest.yml@refs/heads/main",
    "notesRef": "refs/notes/commits",
    "provenancePredicateType": "https://acme.example/attestations/source-provenance/v1",
    "propertyPrefix": "ACME_SOURCE_",
    "resourceUri": "git+https://github.com/{owner}/{repo}",
    "protectedBranches": [
      {
        "name": "main",
        "targetLevel": "SLSA_SOURCE_LEVEL_3",
        "requiredProperties": [
          {"name": "ACME_SOURCE_GATED", "since": "2026-08-09T16:29:06+01:00"}
        ]
      }
    ],
    "healedContinuity": true,
    "underclaimLevel": "SLSA_SOURCE_LEVEL_2",
    "legacyLeaves": [
      {"repository": "acme/canon",
       "revision": "e1ad2dde9fd24fc521b4b37453dac052e655212b",
       "reason": "pre-v2 healed fork"}
    ]
  }`,
			`"source": null`,
			"source is absent",
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
        "requiredProperties": [
          {"name": "ACME_SOURCE_GATED", "since": "2026-08-09T16:29:06+01:00"}
        ]
      }
    ]`, `"protectedBranches": []`, "source.protectedBranches is absent or empty"},
		{"branch name empty", `"name": "main"`, `"name": ""`, "protectedBranches[0].name"},
		{
			"branch level malformed",
			`"targetLevel": "SLSA_SOURCE_LEVEL_3"`,
			`"targetLevel": "LEVEL_3"`,
			"protectedBranches[0].targetLevel",
		},
		{
			"required properties empty",
			`"requiredProperties": [
          {"name": "ACME_SOURCE_GATED", "since": "2026-08-09T16:29:06+01:00"}
        ]`,
			`"requiredProperties": []`,
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
