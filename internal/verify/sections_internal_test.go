// The declared-obligation guards (#82): each engine entry refuses by
// name when the policy section it needs is undeclared, and the
// templated identity role composes with identityRef into the
// self-attesting SAN.

package verify

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/policy"
)

// minimalPolicy is the universality floor: issuer plus a provenance
// identity templated to the repository itself.
func minimalPolicy(t *testing.T) *policy.Policy {
	t.Helper()

	const doc = `{
	  "schema": 7,
	  "issuer": "https://token.example.com",
	  "trust": {
	    "provenance": {"signerWorkflow": "{owner}/{repo}/.github/workflows/release.yml"}
	  }
	}`

	p, err := policy.Load(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	return p
}

func TestEngineRefusesUndeclaredSections(t *testing.T) {
	t.Parallel()

	p := minimalPolicy(t)
	c := Coords{Owner: "acme", Repo: "widget", Tag: "v1.0.0"}
	subjects := []Subject{{Name: "app", SHA256: strings.Repeat("5", 64)}}
	pins := Pins{Signer: strings.Repeat("a", 40), Machinery: strings.Repeat("b", 40)}
	silent := func(string, ...any) {}

	if _, err := Release(p, c, subjects, SBOMs{Assets: subjects}, pins, nil, nil, silent); err == nil ||
		!strings.Contains(err.Error(), "no build section") {
		t.Errorf("Release without build = %v, want the section refusal", err)
	}

	if _, err := ReleaseProvenance(p, c, subjects, pins, nil, nil, silent); err == nil ||
		!strings.Contains(err.Error(), "no build section") {
		t.Errorf("ReleaseProvenance without build = %v, want the section refusal", err)
	}

	if _, err := VSA(p, c, subjects, pins, nil, nil, silent, nil); err == nil ||
		!strings.Contains(err.Error(), "no trust.verdict") {
		t.Errorf("VSA without verdict = %v, want the section refusal", err)
	}

	if _, err := Chain(p, c, "refs/heads/main", nil, nil, silent); err == nil ||
		!strings.Contains(err.Error(), "no source section") {
		t.Errorf("Chain without source = %v, want the section refusal", err)
	}

	rv := &ReleaseVerdict{}
	if _, err := rv.VSAPredicate(p, c, "https://policy.example", strings.Repeat("b", 40),
		"2026-08-18T00:00:00Z"); err == nil || !strings.Contains(err.Error(), "no trust.verdict") {
		t.Errorf("VSAPredicate without verdict = %v, want the section refusal", err)
	}
}

// TestSelfAttestingIdentity proves the #82 composition: a templated
// role expands to the repository under verification, identityRef
// recognises it as the repo's own workflow, and the SAN lands on the
// release tag — no signer repo anywhere.
func TestSelfAttestingIdentity(t *testing.T) {
	t.Parallel()

	p := minimalPolicy(t)
	c := Coords{Owner: "acme", Repo: "widget", Tag: "v1.0.0"}

	workflow := expandWorkflow(*p.Trust.Provenance.SignerWorkflow, c)
	if workflow != "acme/widget/.github/workflows/release.yml" {
		t.Fatalf("expandWorkflow = %q", workflow)
	}

	ref := identityRef(workflow, c, strings.Repeat("a", 40))
	if ref != "refs/tags/v1.0.0" {
		t.Fatalf("identityRef = %q — the self-attesting workflow runs at the release tag", ref)
	}

	san := workflowSAN(workflow, ref)
	want := "https://github.com/acme/widget/.github/workflows/release.yml@refs/tags/v1.0.0"

	if san != want {
		t.Fatalf("SAN = %q, want %q", san, want)
	}
}
