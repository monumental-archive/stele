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
	v       *verify.Verifier
	trusted root.TrustedMaterial
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

	return &Verifier{v: v, trusted: trusted}, nil
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
	result, err := t.verifyEntity(entity, id, alg, digestHex)
	if err != nil {
		return nil, err
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

// VerifyBlob proves one message-signature entity (a cosign
// sign-blob bundle) over the artifact whose digest the caller
// supplies: signature chain, identity, digest — the same stance as
// Verify, minus the envelope, because a blob signature covers the
// artifact bytes directly. Payload is nil by construction: the
// caller already holds the artifact, and returning a copy would
// invite parsing something other than what was hashed.
func (t *Verifier) VerifyBlob(entity verify.SignedEntity, id Identity, alg, digestHex string) (*Verified, error) {
	result, err := t.verifyEntity(entity, id, alg, digestHex)
	if err != nil {
		return nil, err
	}

	if result.Signature == nil || result.Signature.Certificate == nil {
		return nil, errors.New("trust: verification returned no certificate — nothing to hold the policy against")
	}

	return &Verified{
		SAN:        result.Signature.Certificate.SubjectAlternativeName,
		Extensions: result.Signature.Certificate.Extensions,
	}, nil
}

// MeasureBlob proves a message-signature bundle cryptographically and
// reports WHO signed it, asserting no expected identity.
//
// This is measurement, not gating, and the distinction is the whole
// reason it is a separate entry point with a separate name. Verify and
// VerifyBlob answer "is this signed by the party I already decided to
// trust" — the question a release gate asks. This answers "is this
// signature genuine, and whose is it" — the question a measurement
// asks when it has no business being told the answer in advance.
//
// The signature, the certificate chain to a trusted root, the
// transparency log inclusion and the artifact digest binding are ALL
// still proven. The only thing not asserted is the identity, which is
// returned instead, so a caller that wants to compare it to something
// can — and one that only wants to record it need not be handed an
// expectation it would then be tempted to write down somewhere.
//
// Never route a gate through this. A gate that accepts any genuine
// signature accepts an attacker's genuine signature.
func (t *Verifier) MeasureBlob(b *bundle.Bundle, alg, digestHex string) (*Verified, error) {
	digest, err := hex.DecodeString(digestHex)
	if err != nil || len(digest) == 0 {
		return nil, fmt.Errorf("trust: artifact digest is not hex: %q", digestHex)
	}

	result, err := t.v.Verify(b, verify.NewPolicy(
		verify.WithArtifactDigest(alg, digest),
		verify.WithoutIdentitiesUnsafe(),
	))
	if err != nil {
		return nil, fmt.Errorf("trust: measure: %w", err)
	}

	if result.Signature == nil || result.Signature.Certificate == nil {
		return nil, errors.New("trust: the bundle carries no certificate, so nothing identifies its signer")
	}

	return &Verified{
		Payload:    nil,
		SAN:        result.Signature.Certificate.SubjectAlternativeName,
		Extensions: result.Signature.Certificate.Extensions,
	}, nil
}

// MeasureAttestation proves a DSSE bundle cryptographically and
// returns the signed statement together with who signed it, asserting
// no expected identity.
//
// The measurement counterpart of Verify, and the same warning applies:
// this answers "is this genuine, and whose is it", never "is this from
// the party I trust". A gate routed through it accepts an attacker's
// genuine signature.
func (t *Verifier) MeasureAttestation(b *bundle.Bundle, alg, digestHex string) (*Verified, error) {
	digest, err := hex.DecodeString(digestHex)
	if err != nil || len(digest) == 0 {
		return nil, fmt.Errorf("trust: artifact digest is not hex: %q", digestHex)
	}

	result, err := t.v.Verify(b, verify.NewPolicy(
		verify.WithArtifactDigest(alg, digest),
		verify.WithoutIdentitiesUnsafe(),
	))
	if err != nil {
		return nil, fmt.Errorf("trust: measure: %w", err)
	}

	sig, err := b.SignatureContent()
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
		return nil, errors.New("trust: the bundle carries no certificate, so nothing identifies its signer")
	}

	return &Verified{
		Payload:    payload,
		SAN:        result.Signature.Certificate.SubjectAlternativeName,
		Extensions: result.Signature.Certificate.Extensions,
	}, nil
}

// verifyEntity runs the shared cryptographic core: both entry points
// verify the same way and differ only in what a success returns.
func (t *Verifier) verifyEntity(
	entity verify.SignedEntity, id Identity, alg, digestHex string,
) (*verify.VerificationResult, error) {
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

	return result, nil
}

// PeekStatement returns a bundle's DSSE payload bytes WITHOUT
// verifying anything. It exists for exactly one job: selecting which
// bundles from an attestation store are worth verifying (by
// predicate type), the way a verifier filters a store that also
// holds verdicts and VEX over the same subject. Nothing read through
// this function may inform a verdict — the post-verification path
// re-decodes from Verified.Payload, the bytes the signature covered.
func PeekStatement(bundleJSON []byte) ([]byte, error) {
	b, err := LoadBundle(bundleJSON)
	if err != nil {
		return nil, err
	}

	sig, err := b.SignatureContent()
	if err != nil {
		return nil, fmt.Errorf("trust: signature content: %w", err)
	}

	env := sig.EnvelopeContent()
	if env == nil || env.RawEnvelope() == nil {
		return nil, errors.New("trust: the bundle carries no DSSE envelope — nothing to peek at")
	}

	payload, err := dsse.DecodeBase64(env.RawEnvelope().Payload)
	if err != nil {
		return nil, fmt.Errorf("trust: envelope payload: %w", err)
	}

	return payload, nil
}
