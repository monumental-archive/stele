// Package dsse implements the Dead Simple Signing Envelope — the
// envelope shape, its validation, and the pre-authentication encoding
// (PAE) that is the only thing a DSSE signature ever signs. Spec:
// secure-systems-lab/dsse protocol.md. Signature verification itself
// lives with the trust code; this package owns the bytes.
package dsse

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
)

// Envelope is the DSSE envelope, decoded strictly: the spec defines
// exactly these fields, and an unrecognised key is version skew or a
// forgery signal (the jsonx contract, enforced by the caller's
// Decode). Payload and PayloadType are required; pointer fields keep
// absent distinguishable from empty.
type Envelope struct {
	Payload     *string     `json:"payload"`
	PayloadType *string     `json:"payloadType"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one signature over the envelope's PAE. KeyID is the
// spec's optional, unauthenticated hint; Sig is required.
type Signature struct {
	KeyID *string `json:"keyid"`
	Sig   *string `json:"sig"`
}

// Validate refuses an envelope whose required fields are absent,
// empty, or undecodable. It returns the decoded payload so the caller
// verifies and parses the same bytes — the spec's requirement that
// the body verified is the body handed to the application layer.
func (e *Envelope) Validate() ([]byte, error) {
	if e.Payload == nil {
		return nil, errors.New("dsse: payload is absent")
	}

	body, err := DecodeBase64(*e.Payload)
	if err != nil {
		return nil, fmt.Errorf("dsse: payload: %w", err)
	}

	if e.PayloadType == nil || *e.PayloadType == "" {
		return nil, errors.New("dsse: payloadType is absent or empty")
	}

	if len(e.Signatures) == 0 {
		return nil, errors.New("dsse: no signatures — an unsigned envelope is not an envelope")
	}

	for i, s := range e.Signatures {
		if s.Sig == nil || *s.Sig == "" {
			return nil, fmt.Errorf("dsse: signatures[%d].sig is absent or empty", i)
		}

		if _, err := DecodeBase64(*s.Sig); err != nil {
			return nil, fmt.Errorf("dsse: signatures[%d].sig: %w", i, err)
		}
	}

	return body, nil
}

// PAE renders the pre-authentication encoding:
//
//	"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
//
// with lengths in ASCII decimal. This is the exact byte string a DSSE
// signature covers — never the payload alone, which is what makes the
// payloadType unforgeable.
func PAE(payloadType string, body []byte) []byte {
	// Two decimal lengths of at most 20 digits each, plus three
	// separating spaces — the fixed overhead beyond the two fields.
	const overhead = 2*20 + 3

	out := make([]byte, 0, len("DSSEv1")+len(payloadType)+len(body)+overhead)
	out = append(out, "DSSEv1 "...)
	out = strconv.AppendInt(out, int64(len(payloadType)), base10)
	out = append(out, ' ')
	out = append(out, payloadType...)
	out = append(out, ' ')
	out = strconv.AppendInt(out, int64(len(body)), base10)
	out = append(out, ' ')
	out = append(out, body...)

	return out
}

// base10 names AppendInt's radix: PAE lengths are ASCII decimal.
const base10 = 10

// DecodeBase64 accepts standard or URL-safe base64, padded or not —
// the spec requires verifiers to accept either alphabet, and both
// paddings circulate in the wild. Anything else is refused.
func DecodeBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}

	return nil, errors.New("not base64 in any accepted alphabet")
}
