// Package jsonx is the one package in this module permitted to import
// encoding/json — depguard enforces the boundary (.golangci.yml). The
// reason is a data property no linter can see: encoding/json silently
// turns an absent field into a zero value, which is hostile in a tool
// whose job is asserting that facts are PRESENT. The contract here:
//
//   - Types decoded through this package declare every
//     must-be-present field as a POINTER, so absent (nil) and zero
//     (pointer to zero) are distinguishable, and the caller's
//     validation rejects nil explicitly.
//   - Unknown fields are an error: evidence formats are closed specs,
//     and an unrecognised key is a version skew or a forgery signal,
//     never noise.
//   - Trailing data after the value is an error: one document means
//     one document.
package jsonx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrTrailingData reports input that continues past the first value.
var ErrTrailingData = errors.New("jsonx: trailing data after value")

// Raw is a deferred JSON value, byte-preserved. It exists so decode
// types outside this package can carry an arbitrary sub-document (an
// in-toto predicate) without importing encoding/json themselves —
// the boundary stays whole.
type Raw = json.RawMessage

// Decode reads exactly one JSON value from r into a fresh T, rejecting
// unknown fields and trailing data.
func Decode[T any](r io.Reader) (*T, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	value := new(T)
	if err := dec.Decode(value); err != nil {
		return nil, fmt.Errorf("jsonx: decode: %w", err)
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrTrailingData
	}

	return value, nil
}

// DecodeBytes decodes exactly one JSON value from b under the same
// contract as Decode — the entry point for a Raw sub-document a
// carrier type deferred (an in-toto predicate, a ledger pointer).
func DecodeBytes[T any](b []byte) (*T, error) {
	return Decode[T](bytes.NewReader(b))
}

// DecodeForeign decodes one JSON value from b tolerating unknown
// fields — for FOREIGN envelopes only: API responses whose schema
// somebody else owns and extends (the GitHub attestations endpoint).
// Evidence formats never come through here; an evidence decoder that
// shrugged at unknown keys would wave through version skew and
// forgery signals alike, which is the whole reason Decode refuses
// them. Trailing data is still an error: one document means one
// document.
func DecodeForeign[T any](b []byte) (*T, error) {
	dec := json.NewDecoder(bytes.NewReader(b))

	value := new(T)
	if err := dec.Decode(value); err != nil {
		return nil, fmt.Errorf("jsonx: decode: %w", err)
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrTrailingData
	}

	return value, nil
}

// Encode writes v to w followed by a newline, the canonical layout for
// line-oriented evidence files.
func Encode(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("jsonx: encode: %w", err)
	}

	return nil
}
