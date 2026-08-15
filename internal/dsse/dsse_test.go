package dsse_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/dsse"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// TestPAEKnownAnswer pins the spec's own worked example — the one
// byte string a DSSE signature covers, so a drift here is a broken
// verifier, not a style change.
func TestPAEKnownAnswer(t *testing.T) {
	t.Parallel()

	got := dsse.PAE("http://example.com/HelloWorld", []byte("hello world"))
	want := []byte("DSSEv1 29 http://example.com/HelloWorld 11 hello world")

	if !bytes.Equal(got, want) {
		t.Errorf("PAE = %q, want %q", got, want)
	}
}

// TestPAEEmpty pins the zero-length edges: lengths render as plain 0
// with no leading zeros and the trailing space survives.
func TestPAEEmpty(t *testing.T) {
	t.Parallel()

	got := dsse.PAE("", nil)
	want := []byte("DSSEv1 0  0 ")

	if !bytes.Equal(got, want) {
		t.Errorf("PAE(empty) = %q, want %q", got, want)
	}
}

// TestDecodeBase64Alphabets pins the spec MUST: verifiers accept
// standard and URL-safe alphabets alike, padded or not.
func TestDecodeBase64Alphabets(t *testing.T) {
	t.Parallel()

	// 0xfb 0xef 0xbe forces alphabet-distinct encodings (+/ vs -_).
	raw := []byte{0xfb, 0xef, 0xbe, 0x01}

	tests := []struct {
		name string
		in   string
	}{
		{"standard padded", base64.StdEncoding.EncodeToString(raw)},
		{"standard raw", base64.RawStdEncoding.EncodeToString(raw)},
		{"url padded", base64.URLEncoding.EncodeToString(raw)},
		{"url raw", base64.RawURLEncoding.EncodeToString(raw)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := dsse.DecodeBase64(tt.in)
			if err != nil {
				t.Fatalf("DecodeBase64(%q) = %v", tt.in, err)
			}

			if !bytes.Equal(got, raw) {
				t.Errorf("DecodeBase64(%q) = %x, want %x", tt.in, got, raw)
			}
		})
	}

	if _, err := dsse.DecodeBase64("not!base64"); err == nil {
		t.Error("DecodeBase64 accepted bytes outside every alphabet")
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	payload := base64.StdEncoding.EncodeToString([]byte(`{"x":1}`))
	sig := base64.StdEncoding.EncodeToString([]byte("sig-bytes"))
	valid := `{"payload": "` + payload + `", "payloadType": "application/vnd.in-toto+json",` +
		` "signatures": [{"keyid": "", "sig": "` + sig + `"}]}`

	env, err := jsonx.Decode[dsse.Envelope](strings.NewReader(valid))
	if err != nil {
		t.Fatalf("Decode(valid) = %v", err)
	}

	body, err := env.Validate()
	if err != nil {
		t.Fatalf("Validate(valid) = %v", err)
	}

	if string(body) != `{"x":1}` {
		t.Errorf("Validate body = %q, want the decoded payload", body)
	}
}

func TestValidateRefusals(t *testing.T) {
	t.Parallel()

	str := func(s string) *string { return &s }
	goodSig := base64.StdEncoding.EncodeToString([]byte("sig"))

	tests := []struct {
		name string
		env  dsse.Envelope
		want string
	}{
		{"payload absent", dsse.Envelope{
			PayloadType: str("t"),
			Signatures:  []dsse.Signature{{Sig: str(goodSig)}},
		}, "payload is absent"},
		{"payload not base64", dsse.Envelope{
			Payload:     str("!!!"),
			PayloadType: str("t"),
			Signatures:  []dsse.Signature{{Sig: str(goodSig)}},
		}, "payload"},
		{"payloadType absent", dsse.Envelope{
			Payload:    str(goodSig),
			Signatures: []dsse.Signature{{Sig: str(goodSig)}},
		}, "payloadType"},
		{"payloadType empty", dsse.Envelope{
			Payload:     str(goodSig),
			PayloadType: str(""),
			Signatures:  []dsse.Signature{{Sig: str(goodSig)}},
		}, "payloadType"},
		{"no signatures", dsse.Envelope{
			Payload:     str(goodSig),
			PayloadType: str("t"),
		}, "no signatures"},
		{"sig absent", dsse.Envelope{
			Payload:     str(goodSig),
			PayloadType: str("t"),
			Signatures:  []dsse.Signature{{}},
		}, "signatures[0].sig is absent"},
		{"sig empty", dsse.Envelope{
			Payload:     str(goodSig),
			PayloadType: str("t"),
			Signatures:  []dsse.Signature{{Sig: str("")}},
		}, "signatures[0].sig is absent"},
		{"sig not base64", dsse.Envelope{
			Payload:     str(goodSig),
			PayloadType: str("t"),
			Signatures:  []dsse.Signature{{Sig: str("!!!")}},
		}, "signatures[0].sig"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := tt.env.Validate(); err == nil {
				t.Fatal("Validate accepted an envelope it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Validate error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}
