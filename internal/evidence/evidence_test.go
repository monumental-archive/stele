// The one manifest definition, held from both sides: what the writer
// renders the reader admits (the round trip), and every malformed
// shape refuses by name — a manifest that cannot answer the policy
// epochs must never excuse an obligation silently.

package evidence_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/evidence"
)

// The writer-reader agreement, on the BYTES: a manifest New can build
// comes back identical through Parse, which is the property that
// makes the two legs one definition rather than two.
func TestRenderedManifestReadsBack(t *testing.T) {
	t.Parallel()

	m, err := evidence.New([]string{"go-binary", "oci-image"}, true, "1.40.0")
	if err != nil {
		t.Fatalf("New = %v", err)
	}

	var rendered bytes.Buffer
	if encErr := m.Encode(&rendered); encErr != nil {
		t.Fatalf("Encode = %v", encErr)
	}

	back, err := evidence.Parse(rendered.Bytes())
	if err != nil {
		t.Fatalf("Parse(own bytes) = %v", err)
	}

	if *back.Schema != evidence.Schema || !*back.StoreVSA || *back.MachineryVersion != "1.40.0" {
		t.Errorf("round trip changed the facts: %+v", back)
	}

	if strings.Join(back.Classes, ",") != "go-binary,oci-image" {
		t.Errorf("classes = %v", back.Classes)
	}
}

func TestNewRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		classes []string
		version string
		want    string
	}{
		{"no classes", nil, "1.0.0", "required"},
		{"an empty class name", []string{"go-binary", ""}, "1.0.0", "no name"},
		{"a class declared twice", []string{"go-binary", "go-binary"}, "1.0.0", "declared twice"},
		{"a machinery version semver cannot read", []string{"go-binary"}, "release-3", "machineryVersion"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := evidence.New(tt.classes, false, tt.version)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("New = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestParseRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"not JSON", "not json", "evidence"},
		{"an absent field", `{"schema": 1, "classes": ["a"], "storeVsa": true}`, "required"},
		{
			"a schema this format does not speak",
			`{"schema": 2, "classes": ["a"], "storeVsa": true, "machineryVersion": "1.0.0"}`,
			"schema 2 is not 1",
		},
		{
			"a field outside the format",
			`{"schema": 1, "classes": ["a"], "storeVsa": true, "machineryVersion": "1.0.0", "extra": 1}`,
			"unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := evidence.Parse([]byte(tt.doc))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}
