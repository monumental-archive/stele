package jsonx_test

import (
	"errors"
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
