package jsonx_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// claim is the pointer-field shape the package contract mandates:
// absent and zero must be distinguishable.
type claim struct {
	Level *int `json:"level"`
}

func TestDecode(t *testing.T) {
	zero := 0
	three := 3

	tests := []struct {
		name      string
		input     string
		wantLevel *int
		wantErr   bool
	}{
		{name: "present non-zero", input: `{"level": 3}`, wantLevel: &three},
		{name: "present zero is not absent", input: `{"level": 0}`, wantLevel: &zero},
		{name: "absent is nil, never zero", input: `{}`, wantLevel: nil},
		{name: "unknown field is version skew, rejected", input: `{"level": 3, "extra": true}`, wantErr: true},
		{name: "malformed input rejected", input: `{"level":`, wantErr: true},
		{name: "trailing data rejected", input: `{"level": 3}{"level": 4}`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := jsonx.Decode[claim](strings.NewReader(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Decode(%q) succeeded, want error", tt.input)
				}

				return
			}

			if err != nil {
				t.Fatalf("Decode(%q) failed: %v", tt.input, err)
			}

			switch {
			case tt.wantLevel == nil:
				if got.Level != nil {
					t.Fatalf("Decode(%q).Level = %d, want nil (absent)", tt.input, *got.Level)
				}
			case got.Level == nil:
				t.Fatalf("Decode(%q).Level = nil, want %d", tt.input, *tt.wantLevel)
			case *got.Level != *tt.wantLevel:
				t.Fatalf("Decode(%q).Level = %d, want %d", tt.input, *got.Level, *tt.wantLevel)
			}
		})
	}
}

func TestDecodeTrailingDataError(t *testing.T) {
	_, err := jsonx.Decode[claim](strings.NewReader(`{"level": 1} true`))
	if !errors.Is(err, jsonx.ErrTrailingData) {
		t.Fatalf("Decode with trailing data = %v, want ErrTrailingData", err)
	}
}

func TestEncode(t *testing.T) {
	var sb strings.Builder

	three := 3
	if err := jsonx.Encode(&sb, claim{Level: &three}); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if got, want := sb.String(), "{\"level\":3}\n"; got != want {
		t.Fatalf("Encode wrote %q, want %q", got, want)
	}
}

// failWriter exercises the encode error guard — the guard-branch rule.
type failWriter struct{}

var errSink = errors.New("sink closed")

func (failWriter) Write([]byte) (int, error) { return 0, errSink }

func TestEncodeWriteFailure(t *testing.T) {
	if err := jsonx.Encode(failWriter{}, claim{}); err == nil {
		t.Fatal("Encode to a failing writer succeeded, want error")
	}
}

// TestValueKeepsNumbersInTheirSourceSpelling is the reason Value
// exists rather than a bare json.Unmarshal into any. A matcher tree
// read from policy is compared against a forge response read the same
// way, and float64 is the wrong carrier for both sides: a GitHub node
// or ruleset id past 2^53 does not survive the round trip, so two
// equal ids would compare unequal — or, worse, two different ids would
// compare equal after both rounded to the same float.
func TestValueKeepsNumbersInTheirSourceSpelling(t *testing.T) {
	t.Parallel()

	// Past 2^53: the smallest integer float64 cannot represent exactly
	// is 9007199254740993, and it rounds to its even neighbour.
	const beyondFloat = "9007199254740993"

	got, err := jsonx.Value([]byte(`{"id": ` + beyondFloat + `}`))
	if err != nil {
		t.Fatalf("Value = %v", err)
	}

	obj, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("Value returned %T, want an object as map[string]any", got)
	}

	num, ok := obj["id"].(jsonx.Number)
	if !ok {
		t.Fatalf("id landed as %T, want jsonx.Number — a float cannot carry this id", obj["id"])
	}

	if num.String() != beyondFloat {
		t.Errorf("id = %s, want %s exactly", num, beyondFloat)
	}
}

// TestValueShapes: the two container shapes a matcher tree walks, and
// the scalars at its leaves, all arrive as the plain Go kinds a walk
// can type-switch on.
func TestValueShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"an object", `{"a": 1}`, "map[string]interface {}"},
		{"an array", `[1, 2]`, "[]interface {}"},
		{"a string", `"x"`, "string"},
		{"a bool", `true`, "bool"},
		{"a number", `1.5`, "json.Number"},
		{"null", `null`, "<nil>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := jsonx.Value([]byte(tt.input))
			if err != nil {
				t.Fatalf("Value(%s) = %v", tt.input, err)
			}

			if kind := fmt.Sprintf("%T", got); kind != tt.want {
				t.Errorf("Value(%s) landed as %s, want %s", tt.input, kind, tt.want)
			}
		})
	}
}

// TestValueRefusals: there is no schema for Value to be strict about,
// so an unknown field is meaningless here — but a second value still
// is not one value. Policy and forge responses both arrive as whole
// documents, and silently reading the first of two would judge against
// half the input.
func TestValueRefusals(t *testing.T) {
	t.Parallel()

	if _, err := jsonx.Value([]byte(`{"a":`)); err == nil {
		t.Error("Value accepted malformed input")
	}

	_, err := jsonx.Value([]byte(`{"a": 1} {"a": 2}`))
	if !errors.Is(err, jsonx.ErrTrailingData) {
		t.Errorf("Value with trailing data = %v, want ErrTrailingData", err)
	}

	// No schema means no unknown fields: whatever the tree carries is
	// the tree.
	if _, err := jsonx.Value([]byte(`{"anything": {"nested": []}}`)); err != nil {
		t.Errorf("Value refused a shape it has no schema for: %v", err)
	}
}

// TestDecodeBytes pins the deferred-sub-document entry point to the
// same contract as Decode: strict fields, one value.
func TestDecodeBytes(t *testing.T) {
	t.Parallel()

	type pair struct {
		A *int `json:"a"`
	}

	got, err := jsonx.DecodeBytes[pair]([]byte(`{"a": 1}`))
	if err != nil || got.A == nil || *got.A != 1 {
		t.Fatalf("DecodeBytes = %+v, %v", got, err)
	}

	if _, err := jsonx.DecodeBytes[pair]([]byte(`{"a": 1, "b": 2}`)); err == nil {
		t.Error("DecodeBytes accepted an unknown field")
	}
}

func TestDecodeForeign(t *testing.T) {
	t.Parallel()

	type envelope struct {
		Kept *string `json:"kept"`
	}

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "unknown fields are tolerated", input: `{"kept": "v", "novel": 1}`},
		{name: "not json is refused", input: `nonsense`, wantErr: true},
		{name: "trailing data is refused", input: `{"kept": "v"} {}`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := jsonx.DecodeForeign[envelope]([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("DecodeForeign accepted what it must refuse")
				}

				return
			}

			if err != nil {
				t.Fatalf("DecodeForeign = %v", err)
			}

			if got.Kept == nil || *got.Kept != "v" {
				t.Errorf("Kept = %v, want v", got.Kept)
			}
		})
	}
}

// TestMarshal pins the encode-side contract the signing legs depend
// on: exactly one value, and NO trailing newline — Encode's newline
// would change the bytes that get hashed, base64-carried and verified.
func TestMarshal(t *testing.T) {
	t.Parallel()

	three := 3

	got, err := jsonx.Marshal(claim{Level: &three})
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if want := `{"level":3}`; string(got) != want {
		t.Fatalf("Marshal = %q, want %q — the signed bytes carry no newline", got, want)
	}
}

// TestMarshalRefusesUnrenderable is the guard branch: a value
// encoding/json cannot render must surface as an error, never as
// half a document.
func TestMarshalRefusesUnrenderable(t *testing.T) {
	t.Parallel()

	got, err := jsonx.Marshal(make(chan int))
	if err == nil {
		t.Fatalf("Marshal(chan) = %q, want a refusal", got)
	}

	if got != nil {
		t.Fatalf("Marshal(chan) returned %q alongside its error — a refusal carries no bytes", got)
	}
}

// versioned is a schema-carrying shape under the DecodeVersioned
// contract.
type versioned struct {
	Schema *int    `json:"schema"`
	Name   *string `json:"name"`
}

// failReader errors on every read — the io guard branch.
type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestDecodeVersioned(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{name: "matching schema decodes", input: `{"schema": 2, "name": "x"}`},
		{name: "absent schema refused", input: `{"name": "x"}`, wantErr: "schema is absent"},
		{
			name:  "newer schema refused with a version error",
			input: `{"schema": 7, "name": "x"}`, wantErr: "not the implemented schema",
		},
		// The reason this function exists (stele#107): on a document
		// from a DIFFERENT schema whose fields this implementation does
		// not know, the version gate must win over the unknown-field
		// refusal — the reader is told the document is another version,
		// not that a field is a typo.
		{
			name:  "old schema with unknown fields is a version error",
			input: `{"schema": 1, "storeVsaFromCanon": true}`, wantErr: "not the implemented schema",
		},
		{
			name:  "matching schema with unknown field is field skew",
			input: `{"schema": 2, "surprise": true}`, wantErr: "unknown field",
		},
		{name: "malformed input rejected", input: `{"schema":`, wantErr: "decode"},
		{name: "trailing data rejected", input: `{"schema": 2}{"schema": 2}`, wantErr: "trailing data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := jsonx.DecodeVersioned[versioned](strings.NewReader(tt.input), 2)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("DecodeVersioned(%q) error = %v, want %q", tt.input, err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("DecodeVersioned(%q) failed: %v", tt.input, err)
			}

			if got.Schema == nil || *got.Schema != 2 {
				t.Fatalf("DecodeVersioned(%q).Schema = %v, want 2", tt.input, got.Schema)
			}
		})
	}
}

// TestDecodeVersionedReadFailure is the io guard branch: a reader
// that cannot be read surfaces as an error, never as an absent
// schema.
func TestDecodeVersionedReadFailure(t *testing.T) {
	t.Parallel()

	if _, err := jsonx.DecodeVersioned[versioned](failReader{}, 2); err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("DecodeVersioned(failReader) error = %v, want a read error", err)
	}
}

// A concatenated stream is not one document, which is the whole
// difference from DecodeForeign: trailing data there is an error,
// here it is the next value.
func TestDecodeForeignStream(t *testing.T) {
	t.Parallel()

	type msg struct {
		N *int `json:"n"`
	}

	got, err := jsonx.DecodeForeignStream[msg](strings.NewReader(`{"n":1}{"n":2}
	  {"n":3}`))
	if err != nil {
		t.Fatalf("DecodeForeignStream: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("decoded %d values, want 3", len(got))
	}

	for i := range got {
		if got[i].N == nil || *got[i].N != i+1 {
			t.Errorf("value %d = %v, want %d", i, got[i].N, i+1)
		}
	}
}

// An empty stream is zero values, not an error: a producer that
// emitted nothing is a fact for the caller to judge, not a decode
// failure. What the caller must NOT be handed is a prefix it cannot
// tell from the whole, so a stream that breaks mid-value fails.
func TestDecodeForeignStreamEdges(t *testing.T) {
	t.Parallel()

	type msg struct {
		N *int `json:"n"`
	}

	empty, err := jsonx.DecodeForeignStream[msg](strings.NewReader(""))
	if err != nil || empty != nil {
		t.Fatalf("empty stream = (%v, %v), want (nil, nil)", empty, err)
	}

	// Unknown fields are tolerated — foreign schemas grow.
	grown, err := jsonx.DecodeForeignStream[msg](strings.NewReader(`{"n":1,"added_later":true}`))
	if err != nil || len(grown) != 1 {
		t.Fatalf("unknown field = (%v, %v), want one value", grown, err)
	}

	truncated, err := jsonx.DecodeForeignStream[msg](strings.NewReader(`{"n":1}{"n":`))
	if err == nil {
		t.Fatal("a truncated stream decoded clean")
	}

	if truncated != nil {
		t.Errorf("values = %v, want nothing — a prefix must not pass as the whole", truncated)
	}

	if !strings.Contains(err.Error(), "value 2") {
		t.Errorf("err = %v, want it to name which value failed", err)
	}
}
