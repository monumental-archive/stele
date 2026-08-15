// Package trust is the cryptographic boundary: Sigstore bundle
// verification against a pinned identity, wrapped so the rest of the
// verifier never touches sigstore-go directly. The wrapper fixes the
// org's verification stance in one place — a transparency log entry
// AND an observer timestamp required, identity always (issuer, SAN)
// exact — and returns the verified envelope's own payload bytes, so
// what the caller parses is exactly what the signature covered (the
// DSSE rule).
package trust

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/monumental-archive/stele/internal/dsse"
)

// Identity is one root of trust's expectation: the certificate's SAN
// and OIDC issuer, both exact — pattern matching is how an identity
// check becomes a suggestion.
type Identity struct {
	SAN    string
	Issuer string
}

// Verified is a successful verification: the payload bytes the
// signature covered and the certificate facts the caller's policy
// checks continue on.
type Verified struct {
	Payload    []byte
	SAN        string
	Extensions certificate.Extensions
}

// Verifier verifies signed entities against one trusted material
// set. The verification options are deliberately not configurable.
type Verifier struct {
	v *verify.Verifier
}

// LoadRoot parses a trusted-root document (the TUF-delivered JSON).
func LoadRoot(rootJSON []byte) (*root.TrustedRoot, error) {
	tr, err := root.NewTrustedRootFromJSON(rootJSON)
	if err != nil {
		return nil, fmt.Errorf("trust: parse trusted root: %w", err)
	}

	return tr, nil
}

// LoadBundle parses a Sigstore bundle from its JSON encoding.
func LoadBundle(bundleJSON []byte) (*bundle.Bundle, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("trust: parse bundle: %w", err)
	}

	return &b, nil
}

// NewVerifier builds a verifier over the given trusted material with
// the org stance: one transparency log entry and one observer
// timestamp, both required.
func NewVerifier(trusted root.TrustedMaterial) (*Verifier, error) {
	v, err := verify.NewVerifier(trusted,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("trust: build verifier: %w", err)
	}

	return &Verifier{v: v}, nil
}

// Verify proves one signed entity: signature chain to the trusted
// material, certificate identity equal to id, and the statement's
// subject covering the artifact digest (alg, hex). It returns the
// envelope's own payload bytes — never a re-encoding.
//
// Coverage note, deliberate: the error returns wrapping sigstore-go
// calls that cannot fail after a successful Verify (signature
// content, payload base64, missing certificate) are fail-closed
// posture against library drift, not reachable guards — inducing
// them would mean faking the cryptographic boundary, and a fake
// there proves nothing. Every branch reachable through real signed
// material is table-tested.
func (t *Verifier) Verify(entity verify.SignedEntity, id Identity, alg, digestHex string) (*Verified, error) {
	if id.SAN == "" || id.Issuer == "" {
		return nil, errors.New("trust: identity must carry both SAN and issuer — a half identity matches half the world")
	}

	digest, err := hex.DecodeString(digestHex)
	if err != nil || len(digest) == 0 {
		return nil, fmt.Errorf("trust: artifact digest is not hex: %q", digestHex)
	}

	ci, err := verify.NewShortCertificateIdentity(id.Issuer, "", id.SAN, "")
	if err != nil {
		return nil, fmt.Errorf("trust: identity: %w", err)
	}

	result, err := t.v.Verify(entity, verify.NewPolicy(
		verify.WithArtifactDigest(alg, digest),
		verify.WithCertificateIdentity(ci),
	))
	if err != nil {
		return nil, fmt.Errorf("trust: verify: %w", err)
	}

	sig, err := entity.SignatureContent()
	if err != nil {
		return nil, fmt.Errorf("trust: signature content: %w", err)
	}

	env := sig.EnvelopeContent()
	if env == nil || env.RawEnvelope() == nil {
		return nil, errors.New("trust: the entity carries no DSSE envelope — a bare signature attests nothing")
	}

	payload, err := dsse.DecodeBase64(env.RawEnvelope().Payload)
	if err != nil {
		return nil, fmt.Errorf("trust: envelope payload: %w", err)
	}

	if result.Signature == nil || result.Signature.Certificate == nil {
		return nil, errors.New("trust: verification returned no certificate — nothing to hold the policy against")
	}

	return &Verified{
		Payload:    payload,
		SAN:        result.Signature.Certificate.SubjectAlternativeName,
		Extensions: result.Signature.Certificate.Extensions,
	}, nil
}
