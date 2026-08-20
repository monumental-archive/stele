// The root-of-trust map: the spec's own answer to "whose word do we
// take, and how far".
//
// Two properties carry this file. First, absence is an ANSWER — the
// spec defaults an unmapped attester to the track's floor, so a caller
// must be able to tell "trusted to nothing" from "never declared", and
// collapsing the two would silently promote every stranger to whatever
// the floor happens to be. Second, a map that demands more than it
// vouches for is refused AT LOAD: a target no declared attester reaches
// caps below the demand on every run, so the disagreement is in the
// file and reporting it nightly would blame the evidence for it.

package policy_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/policy"
)

// rootsSection is a declared map: one attester trusted to Build 3 and
// Source 3, another trusted less far. It is spliced into the valid
// document, which declares no map of its own.
const rootsSection = `"slsaRootsOfTrust": [
    {"attesterId": "https://github.com/acme/signer",
     "maxLevels": ["SLSA_BUILD_LEVEL_3", "SLSA_SOURCE_LEVEL_3"]},
    {"attesterId": "https://gitlab.example/other/signer",
     "maxLevels": ["SLSA_BUILD_LEVEL_1"]}
  ],
  `

// withRoots is the valid document plus that map.
func withRoots(t *testing.T, section string) string {
	t.Helper()

	return mutate(t, `"schema": 6,`, `"schema": 6,
  `+section)
}

// TestMaxLevelDistinguishesUnmappedFromTrustedToNothing is the
// contract MaxLevel's second result exists for. An attester nobody
// declared is not an attester trusted to zero: the first takes the
// spec's floor, the second is a deliberate refusal to vouch, and a
// caller that could not tell them apart would apply the wrong one.
func TestMaxLevelDistinguishesUnmappedFromTrustedToNothing(t *testing.T) {
	t.Parallel()

	p, err := policy.Load(strings.NewReader(withRoots(t, rootsSection)))
	if err != nil {
		t.Fatalf("Load = %v", err)
	}

	for _, tt := range []struct {
		name     string
		attester string
		track    string
		want     int
		declared bool
	}{
		{"a declared attester on a track it is trusted on", "https://github.com/acme/signer", "BUILD", 3, true},
		{"the same attester on its other track", "https://github.com/acme/signer", "SOURCE", 3, true},
		{
			// Declared, but this map says nothing about DEPENDENCY. That
			// is not "trusted to 3 everywhere": a level is per track.
			"a declared attester on a track the map is silent about",
			"https://github.com/acme/signer", "DEPENDENCY", 0, false,
		},
		{"a second attester trusted less far", "https://gitlab.example/other/signer", "BUILD", 1, true},
		{"an attester nobody declared", "https://github.com/stranger/signer", "BUILD", 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, declared := p.MaxLevel(tt.attester, tt.track)
			if got != tt.want || declared != tt.declared {
				t.Errorf("MaxLevel(%q, %q) = %d, %v; want %d, %v",
					tt.attester, tt.track, got, declared, tt.want, tt.declared)
			}
		})
	}
}

// TestNoMapDeclaredContradictsNothing: the map is optional, and a
// policy without one must not acquire an unsatisfiable demand. This is
// the adopter with a target level and no vouching map — the spec
// default applies and there is nothing to reconcile.
func TestNoMapDeclaredContradictsNothing(t *testing.T) {
	t.Parallel()

	p, err := policy.Load(strings.NewReader(valid))
	if err != nil {
		t.Fatalf("Load(no map) = %v", err)
	}

	if _, declared := p.MaxLevel("https://github.com/acme/signer", "BUILD"); declared {
		t.Error("an undeclared map answered as though it declared something")
	}
}

// TestReachabilitySkipsSectionsAPolicyDoesNotDeclare: a map is
// reconciled against the targets that EXIST. A policy declaring a
// build target, a root of trust, and no source section at all must
// load — the adopter who publishes binaries and makes no source claim
// is the ordinary case, and inventing a source demand to check against
// would refuse a policy that contradicts nothing.
func TestReachabilitySkipsSectionsAPolicyDoesNotDeclare(t *testing.T) {
	t.Parallel()

	const buildOnly = `{
	  "schema": 6,
	  "issuer": "https://token.example.com",
	  "slsaRootsOfTrust": [
	    {"attesterId": "https://github.com/acme/signer", "maxLevels": ["SLSA_BUILD_LEVEL_3"]}
	  ],
	  "trust": {
	    "provenance": {"signerWorkflow": "acme/signer/.github/workflows/sign.yml"}
	  },
	  "build": {
	    "buildTypes": {
	      "https://actions.github.io/buildtypes/workflow/v1": {"externalParameterKeys": ["workflow"]}
	    },
	    "resourceUri": "pkg:github/{owner}/{repo}@v{version}",
	    "sourceRepository": "https://github.com/{owner}/{repo}",
	    "targetLevel": "SLSA_BUILD_LEVEL_3",
	    "denySelfHostedRunners": true
	  }
	}`

	p, err := policy.Load(strings.NewReader(buildOnly))
	if err != nil {
		t.Fatalf("Load(build only, with a map) = %v", err)
	}

	if p.Source != nil {
		t.Fatal("an absent source section decoded as present")
	}
}

// TestParseLevel: the one splitter both the map and every target level
// are read through. UNEVALUATED and FAILED are the rows that matter —
// they are SlsaResult values, and they are answers about the ABSENCE
// of a level, so treating either as one would let a failed
// verification satisfy a demand.
func TestParseLevel(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		in    string
		track string
		n     int
		ok    bool
	}{
		{"SLSA_BUILD_LEVEL_3", "BUILD", 3, true},
		{"SLSA_SOURCE_LEVEL_0", "SOURCE", 0, true},
		{"SLSA_DEPENDENCY_LEVEL_10", "DEPENDENCY", 10, true},
		{"UNEVALUATED", "", 0, false},
		{"FAILED", "", 0, false},
		{"SLSA_BUILD_LEVEL_three", "", 0, false},
		{"slsa_build_level_3", "", 0, false},
		{"SLSA_BUILD_LEVEL_3 ", "", 0, false},
		// The regexp admits any run of digits; a number no int can hold
		// still must not parse to one. Without this guard the value
		// would land as whatever Atoi returned beside its error.
		{"SLSA_BUILD_LEVEL_99999999999999999999999", "", 0, false},
	} {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()

			track, n, ok := policy.ParseLevel(tt.in)
			if track != tt.track || n != tt.n || ok != tt.ok {
				t.Errorf("ParseLevel(%q) = %q, %d, %v; want %q, %d, %v",
					tt.in, track, n, ok, tt.track, tt.n, tt.ok)
			}
		})
	}
}

// TestRootsOfTrustRefusals. A map that cannot answer the one question
// it exists to answer is refused at load rather than consulted at
// verify, where the failure would read as a level nobody reached.
func TestRootsOfTrustRefusals(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		section string
		want    string
	}{
		{
			"an attester with no id",
			`"slsaRootsOfTrust": [{"maxLevels": ["SLSA_BUILD_LEVEL_3"]}],
  `,
			"attesterId must be present and an https URI",
		},
		{
			// An attester id is compared against a builder.id, which is
			// a URI. A bare name would never match one.
			"an attester id that is not an https URI",
			`"slsaRootsOfTrust": [{"attesterId": "acme/signer", "maxLevels": ["SLSA_BUILD_LEVEL_3"]}],
  `,
			"attesterId must be present and an https URI",
		},
		{
			"one attester declared twice",
			`"slsaRootsOfTrust": [
    {"attesterId": "https://github.com/acme/signer", "maxLevels": ["SLSA_BUILD_LEVEL_3"]},
    {"attesterId": "https://github.com/acme/signer", "maxLevels": ["SLSA_BUILD_LEVEL_1"]}
  ],
  `,
			"twice — two entries for one attester are two answers",
		},
		{
			"an attester trusted to nothing",
			`"slsaRootsOfTrust": [{"attesterId": "https://github.com/acme/signer", "maxLevels": []}],
  `,
			"an attester trusted to nothing is not a root of trust",
		},
		{
			"a level the vocabulary does not admit",
			`"slsaRootsOfTrust": [
    {"attesterId": "https://github.com/acme/signer", "maxLevels": ["TRUSTED_COMPLETELY"]}],
  `,
			"maxLevels[0] must be SLSA_<TRACK>_LEVEL_<N>",
		},
		{
			// A level implies every level below it, so two entries for
			// one track are a contradiction rather than emphasis.
			"one track claimed twice",
			`"slsaRootsOfTrust": [
    {"attesterId": "https://github.com/acme/signer",
     "maxLevels": ["SLSA_BUILD_LEVEL_3", "SLSA_BUILD_LEVEL_1"]}],
  `,
			"claims track BUILD more than once",
		},
		{
			"a build target no declared attester reaches",
			`"slsaRootsOfTrust": [
    {"attesterId": "https://github.com/acme/signer",
     "maxLevels": ["SLSA_BUILD_LEVEL_2", "SLSA_SOURCE_LEVEL_3"]}],
  `,
			"build.targetLevel demands SLSA_BUILD_LEVEL_3",
		},
		{
			"a branch target no declared attester reaches",
			`"slsaRootsOfTrust": [
    {"attesterId": "https://github.com/acme/signer",
     "maxLevels": ["SLSA_BUILD_LEVEL_3", "SLSA_SOURCE_LEVEL_2"]}],
  `,
			"source.protectedBranches[0].targetLevel demands SLSA_SOURCE_LEVEL_3",
		},
		{
			// Nobody is trusted on SOURCE at all, which is a different
			// shape from being trusted too little, and must refuse the
			// same way rather than passing for want of an entry.
			"a track no declared attester is trusted on at all",
			`"slsaRootsOfTrust": [
    {"attesterId": "https://github.com/acme/signer", "maxLevels": ["SLSA_BUILD_LEVEL_3"]}],
  `,
			"no slsaRootsOfTrust entry is trusted that far on the SOURCE track",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := policy.Load(strings.NewReader(withRoots(t, tt.section)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}
