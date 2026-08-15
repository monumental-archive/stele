package vsa_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/vsa"
)

const valid = `{
  "verifier": {"id": "https://github.com/acme/canon/.github/workflows/verify-release.yml"},
  "timeVerified": "2026-08-15T12:00:00Z",
  "resourceUri": "pkg:github/acme/widget@v1.0.0",
  "policy": {
    "uri": "https://github.com/acme/canon/tree/v1.2.3",
    "digest": {"gitCommit": "e1ad2dde9fd24fc521b4b37453dac052e655212b"}
  },
  "inputAttestations": [
    {"uri": "https://api.github.com/repos/acme/widget/attestations/sha256:abc",
     "digest": {"sha256": "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"}}
  ],
  "verificationResult": "PASSED",
  "verifiedLevels": ["SLSA_BUILD_LEVEL_3", "ACME_SOURCE_GATED"],
  "dependencyLevels": {"SLSA_BUILD_LEVEL_2": 1},
  "slsaVersion": "1.2"
}`

func decode(t *testing.T, doc string) *vsa.Predicate {
	t.Helper()

	p, err := jsonx.Decode[vsa.Predicate](strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Decode = %v", err)
	}

	return p
}

func mutate(t *testing.T, from, to string) string {
	t.Helper()

	if n := strings.Count(valid, from); n != 1 {
		t.Fatalf("mutation target %q occurs %d times, want exactly 1", from, n)
	}

	return strings.Replace(valid, from, to, 1)
}

func TestValidate(t *testing.T) {
	t.Parallel()

	p := decode(t, valid)
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate(valid) = %v", err)
	}

	if lvl, ok := p.Level("BUILD"); !ok || lvl != "SLSA_BUILD_LEVEL_3" {
		t.Errorf("Level(BUILD) = %q, %v", lvl, ok)
	}

	if _, ok := p.Level("SOURCE"); ok {
		t.Error("Level(SOURCE) reported a claim the predicate does not make")
	}
}

func TestValidateRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		from string
		to   string
		want string
	}{
		{
			"verifier null",
			`"verifier": {"id": "https://github.com/acme/canon/.github/workflows/verify-release.yml"}`,
			`"verifier": null`,
			"verifier.id",
		},
		{
			"verifier id empty",
			`"id": "https://github.com/acme/canon/.github/workflows/verify-release.yml"`,
			`"id": ""`,
			"verifier.id",
		},
		{
			"resourceUri absent",
			`"resourceUri": "pkg:github/acme/widget@v1.0.0",`,
			``,
			"resourceUri",
		},
		{
			"policy uri absent",
			`"uri": "https://github.com/acme/canon/tree/v1.2.3",`,
			``,
			"policy.uri",
		},
		{"result absent", `"verificationResult": "PASSED",`, ``, "verificationResult is absent"},
		{"result lowercase", `"verificationResult": "PASSED"`, `"verificationResult": "passed"`, "neither PASSED nor FAILED"},
		{
			"levels absent",
			`"verifiedLevels": ["SLSA_BUILD_LEVEL_3", "ACME_SOURCE_GATED"],`,
			``,
			"verifiedLevels is absent",
		},
		{
			"level malformed",
			`"SLSA_BUILD_LEVEL_3"`,
			`"SLSA_BUILD_L3"`,
			"is not SLSA_<TRACK>_LEVEL_",
		},
		{
			"level empty custom value",
			`"ACME_SOURCE_GATED"`,
			`""`,
			"empty value",
		},
		{
			"track claimed twice",
			`"SLSA_BUILD_LEVEL_3"`,
			`"SLSA_BUILD_LEVEL_3", "SLSA_BUILD_LEVEL_2"`,
			"claims track BUILD more than once",
		},
		{"slsaVersion malformed", `"slsaVersion": "1.2"`, `"slsaVersion": "v1.2"`, "slsaVersion"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := decode(t, mutate(t, tt.from, tt.to)).Validate(); err == nil {
				t.Fatal("Validate accepted a predicate it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Validate error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestValidateMinimal pins the optional set: a predicate carrying
// only the required fields (and UNEVALUATED, a legal level form)
// validates — optionality is the spec's, not an accident of the
// fixture.
func TestValidateMinimal(t *testing.T) {
	t.Parallel()

	const minimal = `{
  "verifier": {"id": "https://example.com/verifier"},
  "resourceUri": "pkg:github/acme/widget@v1.0.0",
  "policy": {"uri": "https://example.com/policy"},
  "verificationResult": "FAILED",
  "verifiedLevels": ["SLSA_SOURCE_LEVEL_UNEVALUATED"]
}`

	if err := decode(t, minimal).Validate(); err != nil {
		t.Fatalf("Validate(minimal) = %v", err)
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	const pin = "e1ad2dde9fd24fc521b4b37453dac052e655212b"

	p, err := vsa.New(
		"https://github.com/acme/canon/.github/workflows/verify-release.yml",
		"2026-08-15T12:00:00Z",
		"pkg:github/acme/widget@v1.0.0",
		"https://github.com/acme/canon/tree/"+pin, pin,
		vsa.ResultPassed,
		[]string{"SLSA_BUILD_LEVEL_3"},
	)
	if err != nil {
		t.Fatalf("New = %v", err)
	}

	// The assembler's invariants: the pinned spec version, the policy
	// carried as uri AND digest — round-tripped through the encoder
	// and this package's own consumer read.
	b, err := jsonx.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal = %v", err)
	}

	back, err := jsonx.DecodeBytes[vsa.Predicate](b)
	if err != nil {
		t.Fatalf("DecodeBytes = %v", err)
	}

	if err := back.Validate(); err != nil {
		t.Fatalf("Validate(round-trip) = %v", err)
	}

	if back.SlsaVersion == nil || *back.SlsaVersion != vsa.SpecVersion {
		t.Errorf("slsaVersion = %v, want %s pinned by the assembler", back.SlsaVersion, vsa.SpecVersion)
	}

	if back.Policy.Digest["gitCommit"] != pin {
		t.Errorf("policy.digest.gitCommit = %q, want the pin", back.Policy.Digest["gitCommit"])
	}
}

func TestNewRefusals(t *testing.T) {
	t.Parallel()

	const pin = "e1ad2dde9fd24fc521b4b37453dac052e655212b"

	tests := []struct {
		name                                  string
		verifier, when, resource, uri, digest string
		levels                                []string
		want                                  string
	}{
		{
			"policy digest is not a commit",
			"https://v.example", "2026-08-15T12:00:00Z", "pkg:x", "https://p.example", "v1.2.3",
			[]string{"SLSA_BUILD_LEVEL_3"},
			"not a full commit digest",
		},
		{
			"unparsable timeVerified",
			"https://v.example", "yesterday", "pkg:x", "https://p.example", pin,
			[]string{"SLSA_BUILD_LEVEL_3"},
			"timeVerified",
		},
		{
			"levels violating the one-per-track rule",
			"https://v.example", "2026-08-15T12:00:00Z", "pkg:x", "https://p.example", pin,
			[]string{"SLSA_BUILD_LEVEL_3", "SLSA_BUILD_LEVEL_2"},
			"more than once",
		},
		{
			"empty verifier",
			"", "2026-08-15T12:00:00Z", "pkg:x", "https://p.example", pin,
			[]string{"SLSA_BUILD_LEVEL_3"},
			"verifier.id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := vsa.New(tt.verifier, tt.when, tt.resource, tt.uri, tt.digest, vsa.ResultPassed, tt.levels)
			if err == nil {
				t.Fatal("New assembled what it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("New error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}
