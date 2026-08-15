package intoto_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/jsonx"
)

const (
	sha256Hex = "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"
	commitHex = "e1ad2dde9fd24fc521b4b37453dac052e655212b"
)

const valid = `{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {"name": "artifact.tar.gz", "digest": {"sha256": "` + sha256Hex + `"}},
    {"uri": "https://example.com/commit", "digest": {"gitCommit": "` + commitHex + `"},
     "annotations": {"sourceRefs": ["refs/heads/main"]}}
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {"anything": ["goes", "here"]}
}`

func decode(t *testing.T, doc string) *intoto.Statement {
	t.Helper()

	s, err := jsonx.Decode[intoto.Statement](strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Decode = %v", err)
	}

	return s
}

func TestValidate(t *testing.T) {
	t.Parallel()

	s := decode(t, valid)
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate(valid) = %v", err)
	}

	// The predicate travels raw and byte-preserved: judged later, by
	// the predicate's own decoder, never here.
	if got := string(s.Predicate); got != `{"anything": ["goes", "here"]}` {
		t.Errorf("Predicate = %q, want the raw sub-document", got)
	}
}

func TestValidateRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"type absent", `"_type": "https://in-toto.io/Statement/v1",`, ``, "_type is absent"},
		{"type foreign", `https://in-toto.io/Statement/v1`, `https://in-toto.io/Statement/v0.1`, "is not"},
		{"subject empty", `{"name": "artifact.tar.gz", "digest": {"sha256": "` + sha256Hex + `"}},
    {"uri": "https://example.com/commit", "digest": {"gitCommit": "` + commitHex + `"},
     "annotations": {"sourceRefs": ["refs/heads/main"]}}`, ``, "subject is absent or empty"},
		{"digest missing", `"digest": {"sha256": "` + sha256Hex + `"}`, `"digest": {}`, "subject[0] has no digest"},
		{"sha256 malformed", sha256Hex, "abc123", "not 64 lowercase hex"},
		{"sha256 uppercase", sha256Hex, strings.ToUpper(sha256Hex), "not 64 lowercase hex"},
		{"gitCommit malformed", commitHex, "e1ad2dde", "not 40 lowercase hex"},
		{
			"unknown algorithm empty value",
			`"digest": {"sha256": "` + sha256Hex + `"}`,
			`"digest": {"blake3": ""}`,
			"digest blake3 carries an empty value",
		},
		{
			"predicateType absent",
			`"predicateType": "https://slsa.dev/provenance/v1",`,
			``,
			"predicateType",
		},
		{
			"predicateType not a URI",
			`"predicateType": "https://slsa.dev/provenance/v1"`,
			`"predicateType": "provenance"`,
			"predicateType",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if n := strings.Count(valid, tt.old); n != 1 {
				t.Fatalf("mutation target %q occurs %d times, want exactly 1", tt.old, n)
			}

			s := decode(t, strings.Replace(valid, tt.old, tt.new, 1))

			if err := s.Validate(); err == nil {
				t.Fatal("Validate accepted a statement it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Validate error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestUnknownAlgorithmPasses pins the open-set rule: an algorithm
// this tool does not know is carried, not refused — only its
// emptiness would be.
func TestUnknownAlgorithmPasses(t *testing.T) {
	t.Parallel()

	doc := strings.Replace(valid,
		`"digest": {"sha256": "`+sha256Hex+`"}`,
		`"digest": {"blake3": "abc123"}`, 1)

	if err := decode(t, doc).Validate(); err != nil {
		t.Fatalf("Validate(unknown algorithm) = %v", err)
	}
}

// TestStrictDecode pins the jsonx contract end to end for statements:
// an unrecognised statement-level key is refused at decode.
func TestStrictDecode(t *testing.T) {
	t.Parallel()

	doc := strings.Replace(valid, `"predicate":`, `"surprise": 1, "predicate":`, 1)

	if _, err := jsonx.Decode[intoto.Statement](strings.NewReader(doc)); err == nil {
		t.Fatal("Decode accepted an unknown statement field")
	}
}
