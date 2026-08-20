package verify_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

// The test org is acme — zero real org names, the universality
// boundary exercised rather than asserted.
const (
	issuer     = "https://token.actions.githubusercontent.com"
	signerWF   = "acme/signer/.github/workflows/sign.yml"
	verifierWF = "acme/canon/.github/workflows/verify-release.yml"
	publishWF  = "acme/canon/.github/workflows/publish.yml"

	decisionType = "https://acme.example/attestations/release-decision/v1"
	sourceType   = "https://acme.example/attestations/source-provenance/v1"
	buildType    = "https://actions.github.io/buildtypes/workflow/v1"

	signerPin    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	machineryPin = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	srcRev       = "cccccccccccccccccccccccccccccccccccccccc"
	leafRev      = "dddddddddddddddddddddddddddddddddddddddd"
)

var (
	coords = verify.Coords{Owner: "acme", Repo: "widget", Tag: "v1.2.3"}
	pins   = verify.Pins{Signer: signerPin, Machinery: machineryPin}
)

const policyJSON = `{
  "schema": 6,
  "issuer": "` + issuer + `",
  "trust": {
    "provenance": {"signerWorkflow": "` + signerWF + `"},
    "verdict": {
      "verifierWorkflow": "` + verifierWF + `",
      "legacyVerdicts": [
        {"repository": "acme/relic", "tag": "v0.1.0", "signerWorkflow": "` + signerWF + `"}
      ]
    },
    "decision": {
      "signerWorkflow": "` + publishWF + `",
      "predicateType": "` + decisionType + `",
      "requiredConclusion": "OPEN"
    }
  },
  "build": {
    "buildTypes": {"` + buildType + `": {"externalParameterKeys": ["workflow", "inputs"]}},
    "resourceUri": "pkg:github/{owner}/{repo}@v{version}",
    "sourceRepository": "https://github.com/{owner}/{repo}",
    "targetLevel": "SLSA_BUILD_LEVEL_3",
    "denySelfHostedRunners": true
  },
  "source": {
    "identity": "https://github.com/{owner}/{repo}/.github/workflows/source-attest.yml@refs/heads/main",
    "notesRef": "refs/notes/commits",
    "provenancePredicateType": "` + sourceType + `",
    "propertyPrefix": "ORG_SOURCE_",
    "resourceUri": "git+https://github.com/{owner}/{repo}",
    "protectedBranches": [
      {
        "name": "main",
        "targetLevel": "SLSA_SOURCE_LEVEL_3",
        "levels": [{"level": "SLSA_SOURCE_LEVEL_3", "requiredProperties": [
          {"name": "ORG_SOURCE_GATED", "since": "2020-01-01T00:00:00Z"},
          {"name": "ORG_SOURCE_FUTURE", "since": "2099-01-01T00:00:00Z"}
        ]}]
      }
    ],
    "healedContinuity": true,
    "underclaimLevel": "SLSA_SOURCE_LEVEL_2",
    "legacyLeaves": [
      {"repository": "acme/widget", "revision": "` + leafRev + `", "reason": "pre-v2 healed fork"}
    ]
  }
}`

func loadPolicy(t *testing.T) *policy.Policy {
	t.Helper()

	p, err := policy.Load(strings.NewReader(policyJSON))
	if err != nil {
		t.Fatalf("policy.Load = %v", err)
	}

	return p
}

// mustJSON marshals through jsonx — the module's one JSON boundary.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()

	var buf bytes.Buffer
	if err := jsonx.Encode(&buf, v); err != nil {
		t.Fatalf("jsonx.Encode = %v", err)
	}

	return bytes.TrimRight(buf.Bytes(), "\n")
}

func digestHex(b []byte) string {
	d := sha256.Sum256(b)

	return hex.EncodeToString(d[:])
}

// fakeBundle is the test wire format: the statement travels beside
// the identity and digests the fake verifier will accept, so a test
// scripts cryptography by data, and the engine's guards fire on the
// same seams the real trust layer exposes.
type fakeBundle struct {
	Stmt jsonx.Raw `json:"stmt"`
	// PeekStmt, when set, is what Peek returns INSTEAD of Stmt — the
	// selection/verification divergence a hostile store could stage,
	// which the engine must catch by re-judging verified bytes.
	PeekStmt jsonx.Raw              `json:"peekStmt,omitempty"`
	SAN      string                 `json:"san"`
	Issuer   string                 `json:"issuer"`
	Digests  []string               `json:"digests"`
	Ext      certificate.Extensions `json:"ext"`
	Broken   bool                   `json:"broken"`
}

func (fb *fakeBundle) bytes(t *testing.T) []byte {
	t.Helper()

	return mustJSON(t, fb)
}

// fakeBV enforces exactly what the real boundary enforces — identity
// equality and digest membership — against the fake bundle's script.
type fakeBV struct{}

var (
	errSigner = fakeError("identity mismatch")
	errDigest = fakeError("digest not covered")
	errBroken = fakeError("unparsable bundle")
)

type fakeError string

func (e fakeError) Error() string { return string(e) }

// asMap and asList are checked casts for statement surgery: a test
// mutating a path that does not exist should die loudly, not nil-op.
func asMap(v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		panic("test statement path is not an object")
	}

	return m
}

func asList(v any) []any {
	l, ok := v.([]any)
	if !ok {
		panic("test statement path is not an array")
	}

	return l
}

func (f fakeBV) Attestation(bundleJSON []byte, id trust.Identity, sha256Hex string) (*trust.Verified, error) {
	fb, err := f.check(bundleJSON, id, sha256Hex)
	if err != nil {
		return nil, err
	}

	return &trust.Verified{Payload: fb.Stmt, SAN: fb.SAN, Extensions: fb.Ext}, nil
}

func (f fakeBV) Blob(bundleJSON []byte, id trust.Identity, sha256Hex string) (*trust.Verified, error) {
	fb, err := f.check(bundleJSON, id, sha256Hex)
	if err != nil {
		return nil, err
	}

	return &trust.Verified{SAN: fb.SAN, Extensions: fb.Ext}, nil
}

func (f fakeBV) Peek(bundleJSON []byte) ([]byte, error) {
	fb, err := f.decode(bundleJSON)
	if err != nil || fb.Broken {
		return nil, errBroken
	}

	if fb.PeekStmt != nil {
		return fb.PeekStmt, nil
	}

	return fb.Stmt, nil
}

func (fakeBV) decode(bundleJSON []byte) (*fakeBundle, error) {
	return jsonx.DecodeForeign[fakeBundle](bundleJSON)
}

func (f fakeBV) check(bundleJSON []byte, id trust.Identity, sha256Hex string) (*fakeBundle, error) {
	fb, err := f.decode(bundleJSON)
	if err != nil {
		return nil, err
	}

	if fb.SAN != id.SAN || fb.Issuer != id.Issuer {
		return nil, errSigner
	}

	if !slices.Contains(fb.Digests, sha256Hex) {
		return nil, errDigest
	}

	return fb, nil
}

// fakeStore serves bundles by digest; a digest it does not know is a
// fetch error, the store's honest shape.
type fakeStore struct {
	bundles map[string][]verify.StoredBundle
}

func (s fakeStore) Bundles(_, sha256Hex string) ([]verify.StoredBundle, error) {
	got, ok := s.bundles[sha256Hex]
	if !ok {
		return nil, fakeError("no attestations for " + sha256Hex)
	}

	return got, nil
}

func discardLog(string, ...any) {}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
