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

// Epoch is the one document epoch every live-read stele document
// carries — both policies and the report reference this constant,
// never a local copy, so the "one number" of docs/versioning.md is
// one definition and a bump that lands on one document and misses
// another is unrepresentable (share the definition, never share the
// derivation). Identifiers written into history — chain note
// version, evidence-manifest schema — keep their own numbers and do
// not reference this.
const Epoch = 4

// DecodeVersioned decodes one schema-versioned document under the
// Decode contract, with the version gate structurally first: the
// declared `schema` field is peeked tolerantly before the strict
// decode, so an absent or unimplemented schema refuses with a VERSION
// error even when the rest of the document is unreadable to this
// implementation. The order is the point (stele#107): a version gate
// that runs after strict decoding never fires — the unknown-field
// refusal wins the race and a version skew reports as a field typo.
// The rule for when `want` moves is docs/versioning.md.
func DecodeVersioned[T any](r io.Reader, want int) (*T, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("jsonx: read: %w", err)
	}

	var peek struct {
		Schema *int `json:"schema"`
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&peek); err != nil {
		return nil, fmt.Errorf("jsonx: decode: %w", err)
	}

	switch {
	case peek.Schema == nil:
		return nil, errors.New("jsonx: schema is absent")
	case *peek.Schema != want:
		return nil, fmt.Errorf(
			"jsonx: schema %d is not the implemented schema %d — refusing, never best-efforting", *peek.Schema, want)
	}

	return DecodeBytes[T](b)
}

// Marshal renders v as one JSON value in memory — the encode-side
// counterpart of DecodeBytes, for building the Raw sub-documents and
// statement bytes the emit leg signs. No trailing newline: the bytes
// returned are exactly the bytes hashed, base64-carried and verified.
func Marshal(v any) (Raw, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("jsonx: marshal: %w", err)
	}

	return b, nil
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

// Value decodes one arbitrary JSON value — the entry point for data
// whose shape is not known to any Go type: a policy-declared matcher
// tree and the forge response it runs against. Objects land as
// map[string]any, arrays as []any, and numbers as json.Number rather
// than float64: an equality test between an id read from policy and
// the same id read from an API must not depend on whether both
// survived a round trip through a binary float.
//
// Unknown fields have no meaning here (there is no schema to be
// unknown to), but trailing data is still an error.
func Value(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()

	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("jsonx: value: %w", err)
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrTrailingData
	}

	return v, nil
}

// Number is a JSON number in its source spelling — see Value.
type Number = json.Number
