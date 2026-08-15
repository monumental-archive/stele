package trust_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/testing/data"

	"github.com/monumental-archive/stele/internal/trust"
)

const (
	san    = "https://github.com/acme/widget/.github/workflows/source-attest.yml@refs/heads/main"
	issuer = "https://token.actions.githubusercontent.com"
)

// digestOf is the sha256 of artifact, hex — the digest verification
// asserts against.
func digestOf(artifact []byte) string {
	digest := sha256.Sum256(artifact)

	return hex.EncodeToString(digest[:])
}

// statementOver renders a minimal in-toto statement whose subject is
// the sha256 of artifact — the envelope body the virtual CA attests.
func statementOver(artifact []byte) []byte {
	stmt := `{"_type": "https://in-toto.io/Statement/v1",` +
		` "subject": [{"name": "a", "digest": {"sha256": "` + digestOf(artifact) + `"}}],` +
		` "predicateType": "https://example.com/p/v1", "predicate": {}}`

	return []byte(stmt)
}

const (
	algSHA256  = "sha256"
	wantVerify = "verify"
)

// harness stands up one virtual sigstore, one attested entity and a
// verifier over that virtual world's trusted material.
func harness(t *testing.T) (*trust.Verifier, *ca.TestEntity, string) {
	t.Helper()

	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore = %v", err)
	}

	body := statementOver([]byte("the artifact bytes"))
	digestHex := digestOf([]byte("the artifact bytes"))

	entity, err := vs.Attest(san, issuer, body)
	if err != nil {
		t.Fatalf("Attest = %v", err)
	}

	v, err := trust.NewVerifier(vs)
	if err != nil {
		t.Fatalf("NewVerifier = %v", err)
	}

	return v, entity, digestHex
}

func TestVerify(t *testing.T) {
	t.Parallel()

	v, entity, digestHex := harness(t)

	got, err := v.Verify(entity, trust.Identity{SAN: san, Issuer: issuer}, algSHA256, digestHex)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}

	wantBody := statementOver([]byte("the artifact bytes"))
	if !bytes.Equal(got.Payload, wantBody) {
		t.Errorf("Payload = %q, want the exact attested statement bytes", got.Payload)
	}

	if got.SAN != san {
		t.Errorf("SAN = %q, want %q", got.SAN, san)
	}
}

func TestVerifyRefusals(t *testing.T) {
	t.Parallel()

	v, entity, digestHex := harness(t)

	otherDigest := sha256.Sum256([]byte("different bytes"))

	tests := []struct {
		name      string
		id        trust.Identity
		alg       string
		digestHex string
		want      string
	}{
		{"SAN empty", trust.Identity{Issuer: issuer}, algSHA256, digestHex, "half identity"},
		{"issuer empty", trust.Identity{SAN: san}, algSHA256, digestHex, "half identity"},
		{
			"wrong SAN",
			trust.Identity{SAN: "https://github.com/acme/other/.github/workflows/x.yml@refs/heads/main", Issuer: issuer},
			algSHA256, digestHex,
			wantVerify,
		},
		{"wrong issuer", trust.Identity{SAN: san, Issuer: "https://issuer.example.com"}, algSHA256, digestHex, wantVerify},
		{"digest not hex", trust.Identity{SAN: san, Issuer: issuer}, algSHA256, "zz", "not hex"},
		{"digest empty", trust.Identity{SAN: san, Issuer: issuer}, algSHA256, "", "not hex"},
		{
			"wrong artifact digest",
			trust.Identity{SAN: san, Issuer: issuer},
			algSHA256, hex.EncodeToString(otherDigest[:]),
			wantVerify,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := v.Verify(entity, tt.id, tt.alg, tt.digestHex); err == nil {
				t.Fatal("Verify accepted what it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Verify error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestVerifyForeignWorld pins the root-of-trust boundary: an entity
// attested by a DIFFERENT virtual sigstore refuses against this
// verifier's trusted material even with the identity strings equal —
// the trust is in the keys, not the names.
func TestVerifyForeignWorld(t *testing.T) {
	t.Parallel()

	v, _, digestHex := harness(t)
	_, foreign, _ := harness(t)

	if _, err := v.Verify(foreign, trust.Identity{SAN: san, Issuer: issuer}, algSHA256, digestHex); err == nil {
		t.Fatal("Verify accepted an entity from a foreign trust world")
	}
}

func TestLoadBundleRefusals(t *testing.T) {
	t.Parallel()

	if _, err := trust.LoadBundle([]byte("not json")); err == nil {
		t.Error("LoadBundle accepted non-JSON")
	}
}

func TestLoadRootRefusals(t *testing.T) {
	t.Parallel()

	if _, err := trust.LoadRoot([]byte("not json")); err == nil {
		t.Error("LoadRoot accepted non-JSON")
	}
}

// TestLoadRoundTrips pins the success paths through this package's
// own parsers, on real upstream shapes round-tripped byte-for-byte
// through their canonical marshalling.
func TestLoadRoundTrips(t *testing.T) {
	t.Parallel()

	rootJSON, err := data.TrustedRoot(t, "public-good.json").MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON(trusted root) = %v", err)
	}

	if _, lerr := trust.LoadRoot(rootJSON); lerr != nil {
		t.Errorf("LoadRoot = %v", lerr)
	}

	bundleJSON, err := data.Bundle(t, "dsse.sigstore.json").MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON(bundle) = %v", err)
	}

	if _, lerr := trust.LoadBundle(bundleJSON); lerr != nil {
		t.Errorf("LoadBundle = %v", lerr)
	}
}

// TestEmptyTrustWorld pins where empty trusted material fails: the
// verifier builds (sigstore-go validates options, not anchors), and
// the refusal lands at Verify — an entity nothing vouches for.
func TestEmptyTrustWorld(t *testing.T) {
	t.Parallel()

	v, err := trust.NewVerifier(root.TrustedMaterialCollection{})
	if err != nil {
		t.Fatalf("NewVerifier = %v", err)
	}

	_, entity, digestHex := harness(t)

	if _, err := v.Verify(entity, trust.Identity{SAN: san, Issuer: issuer}, algSHA256, digestHex); err == nil {
		t.Fatal("Verify accepted an entity in an empty trust world")
	}
}

// TestVerifyBareSignature pins the DSSE boundary: a message-signature
// entity verifies cryptographically but carries no envelope, and an
// attestation verifier must refuse it — a bare signature attests
// nothing.
func TestVerifyBareSignature(t *testing.T) {
	t.Parallel()

	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore = %v", err)
	}

	artifact := []byte("the artifact bytes")
	digest := sha256.Sum256(artifact)

	entity, err := vs.Sign(san, issuer, artifact)
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}

	v, err := trust.NewVerifier(vs)
	if err != nil {
		t.Fatalf("NewVerifier = %v", err)
	}

	_, err = v.Verify(entity, trust.Identity{SAN: san, Issuer: issuer}, algSHA256, hex.EncodeToString(digest[:]))
	if err == nil {
		t.Fatal("Verify accepted a bare signature as an attestation")
	}

	if !strings.Contains(err.Error(), "no DSSE envelope") {
		t.Errorf("Verify error = %q, want it to name the missing envelope", err)
	}
}
