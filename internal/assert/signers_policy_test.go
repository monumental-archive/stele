package assert_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
)

// TestSignerCertificatesPolicyRefusals: the section is optional, but
// declared means a log the reader can use as written, at least one
// signer, and every signer's callers — each refusal by name.
func TestSignerCertificatesPolicyRefusals(t *testing.T) {
	t.Parallel()

	const base = `{"schema": 8, "issuer": "https://token.example.com",
	  "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",
	    "umbrellaBundle": "u.jsonl", "manifestAsset": "m.json", "classes": {"a": {"bundles": ["b"]}}},
	  "signerCertificates": {"log": "https://ct.example/2026",
	    "signers": [
	      {"workflow": "acme/signer/.github/workflows/sign.yml", "callers": ["acme/.github"]},
	      {"workflow": "acme/signer/.github/workflows/sign-source.yml", "callers": ["acme/.github", "acme/tools"]}
	    ]}}`

	pol, err := assert.LoadPolicy(strings.NewReader(base))
	if err != nil {
		t.Fatalf("the base policy must load: %v", err)
	}

	if n := len(pol.SignerCertificates.Signers); n != 2 {
		t.Fatalf("%d signers loaded, want 2", n)
	}

	const sign = `"workflow": "acme/signer/.github/workflows/sign.yml", "callers": ["acme/.github"]`

	tests := []struct {
		name, from, to, want string
	}{
		{
			"issuer missing beside the section", `"issuer": "https://token.example.com",`, ``,
			"issuer is required when signerCertificates is declared",
		},
		{"log absent", `"log": "https://ct.example/2026",`, ``, "signerCertificates.log is absent or empty"},
		{"log empty", `"log": "https://ct.example/2026"`, `"log": ""`, "signerCertificates.log is absent or empty"},
		{
			"log does not parse", `"log": "https://ct.example/2026"`, `"log": "https://ct.example/%zz"`,
			"does not parse",
		},
		{
			"log over http", `"log": "https://ct.example/2026"`, `"log": "http://ct.example/2026"`,
			"is not an https URL",
		},
		{"log with no host", `"log": "https://ct.example/2026"`, `"log": "https:///2026"`, "is not an https URL"},
		{
			"log with a query", `"log": "https://ct.example/2026"`, `"log": "https://ct.example/2026?x=1"`,
			"carries more than a base URL",
		},
		{
			"log with a fragment", `"log": "https://ct.example/2026"`, `"log": "https://ct.example/2026#x"`,
			"carries more than a base URL",
		},
		{
			"log with a user", `"log": "https://ct.example/2026"`, `"log": "https://me@ct.example/2026"`,
			"carries more than a base URL",
		},
		{
			"log with a trailing slash", `"log": "https://ct.example/2026"`, `"log": "https://ct.example/2026/"`,
			"spell it as the trusted root does",
		},
		{"signers absent", `,
	    "signers": [
	      {` + sign + `},
	      {"workflow": "acme/signer/.github/workflows/sign-source.yml", "callers": ["acme/.github", "acme/tools"]}
	    ]`, ``, "signerCertificates.signers is absent or empty"},
		{
			"workflow absent", `"workflow": "acme/signer/.github/workflows/sign.yml", `, ``,
			"signerCertificates.signers[0].workflow is absent or empty",
		},
		{
			"workflow empty", `"workflow": "acme/signer/.github/workflows/sign.yml"`, `"workflow": ""`,
			"signerCertificates.signers[0].workflow is absent or empty",
		},
		{
			"workflow without a path", `"acme/signer/.github/workflows/sign.yml"`, `"acme/signer"`,
			`"acme/signer" is not owner/repo/path without a ref`,
		},
		{
			"workflow with an empty segment", `"acme/signer/.github/workflows/sign.yml"`, `"acme//sign.yml"`,
			"is not owner/repo/path without a ref",
		},
		{
			"workflow with a ref", `"acme/signer/.github/workflows/sign.yml"`,
			`"acme/signer/.github/workflows/sign.yml@main"`, "is not owner/repo/path without a ref",
		},
		{
			"the same workflow twice", `"acme/signer/.github/workflows/sign-source.yml"`,
			`"acme/signer/.github/workflows/sign.yml"`, "a certificate must match exactly one signer",
		},
		{
			"callers absent", `, "callers": ["acme/.github"]`, ``,
			"signerCertificates.signers[0].callers is absent or empty — a signer nobody may call",
		},
		{
			"callers empty", `"callers": ["acme/.github"]`, `"callers": []`,
			"signerCertificates.signers[0].callers is absent or empty",
		},
		{
			"a caller without an owner", `"callers": ["acme/.github"]`, `"callers": ["/.github"]`,
			`signerCertificates.signers[0].callers[0] "/.github" is not owner/name`,
		},
		{"a caller without a slash", `"callers": ["acme/.github"]`, `"callers": ["acme"]`, "is not owner/name"},
		{
			"a caller with a path", `"callers": ["acme/.github"]`, `"callers": ["acme/.github/x"]`,
			"is not owner/name",
		},
		{
			"the same caller twice", `"callers": ["acme/.github", "acme/tools"]`,
			`"callers": ["acme/tools", "acme/tools"]`, "signers[1].callers[1] names acme/tools twice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := strings.Replace(base, tt.from, tt.to, 1)
			if doc == base {
				t.Fatalf("the row's edit %q matched nothing", tt.from)
			}

			if _, err := assert.LoadPolicy(strings.NewReader(doc)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}
