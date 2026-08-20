// The one manifest definition, held from both sides: what the writer
// renders the reader admits (the round trip), and every malformed
// shape refuses by name — a manifest that cannot answer the policy
// epochs must never excuse an obligation silently, and an asset the
// typing cannot place must never land in a population by default.

package evidence_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/evidence"
)

const (
	digestA = "1111111111111111111111111111111111111111111111111111111111111111"
	digestB = "2222222222222222222222222222222222222222222222222222222222222222"
)

// oneOfEach is the shape every valid fixture below starts from: an
// artifact and a document about it, which is what a release ships.
func oneOfEach() []evidence.Entry {
	return []evidence.Entry{
		evidence.NewEntry("widget-x86_64.tar.gz", digestA, evidence.TypeBuildSubject),
		evidence.NewEntry("attestations-image.intoto.jsonl", digestB, evidence.TypeEvidence),
	}
}

// The writer-reader agreement, on the BYTES: a manifest New can build
// comes back identical through Parse, which is the property that
// makes the two legs one definition rather than two.
func TestRenderedManifestReadsBack(t *testing.T) {
	t.Parallel()

	m, err := evidence.New([]string{"go-binary", "oci-image"}, true, "1.40.0", oneOfEach())
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

	subjects := back.Subjects()
	if len(subjects) != 1 || subjects[0].Name != "widget-x86_64.tar.gz" || subjects[0].SHA256 != digestA {
		t.Errorf("subjects = %+v, want the artifact alone", subjects)
	}
}

// The population a repro walk judges is READ, never re-derived: the
// typing decides it, and a document typed as evidence stays out of it
// however it is named.
func TestSubjectsReadTheTypingAlone(t *testing.T) {
	t.Parallel()

	m, err := evidence.New([]string{"go-binary"}, true, "1.0.0", []evidence.Entry{
		// Named exactly like an artifact, typed as a document: the
		// name loses, because the type is the answer.
		evidence.NewEntry("widget-x86_64.tar.gz", digestA, evidence.TypeEvidence),
		evidence.NewEntry("odd-name-no-convention-would-match", digestB, evidence.TypeBuildSubject),
	})
	if err != nil {
		t.Fatalf("New = %v", err)
	}

	subjects := m.Subjects()
	if len(subjects) != 1 || subjects[0].Name != "odd-name-no-convention-would-match" {
		t.Fatalf("subjects = %+v", subjects)
	}
}

// Subjects is total on a manifest nobody validated: a zero-value
// entry is skipped rather than dereferenced. The constructors both
// validate, so this guard fires only for a caller that built the
// struct by hand — which is exactly when a panic would be worst.
func TestSubjectsSkipsUnbuiltEntries(t *testing.T) {
	t.Parallel()

	m := &evidence.Manifest{Entries: []evidence.Entry{{}, evidence.NewEntry("a", digestA, evidence.TypeBuildSubject)}}
	if got := m.Subjects(); len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("Subjects = %+v", got)
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

			_, err := evidence.New(tt.classes, false, tt.version, oneOfEach())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("New = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// Every typing guard gets its own row. An entry that cannot be placed
// must refuse the manifest rather than default into a population —
// the failure mode this field exists to prevent — so each way of
// failing to place one is exercised here.
func TestEntryRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entries []evidence.Entry
		want    string
	}{
		{"no entries at all", nil, "lists nothing"},
		{
			"an entry naming no asset",
			[]evidence.Entry{evidence.NewEntry("", digestA, evidence.TypeBuildSubject)},
			"has no name",
		},
		{
			"an entry pinning no bytes",
			[]evidence.Entry{{Name: new("a.tar.gz"), Type: new(evidence.TypeBuildSubject)}},
			"has no sha256",
		},
		{
			"an entry whose digest is not one",
			[]evidence.Entry{evidence.NewEntry("a.tar.gz", "cafe", evidence.TypeBuildSubject)},
			"is not a sha256 digest",
		},
		{
			"an untyped entry",
			[]evidence.Entry{{Name: new("a.tar.gz"), SHA256: new(digestA)}},
			"has no type",
		},
		{
			"a type outside the closed vocabulary",
			[]evidence.Entry{evidence.NewEntry("a.tar.gz", digestA, "artefact")},
			"is neither",
		},
		{
			"the same asset twice",
			[]evidence.Entry{
				evidence.NewEntry("a.tar.gz", digestA, evidence.TypeBuildSubject),
				evidence.NewEntry("a.tar.gz", digestB, evidence.TypeEvidence),
			},
			"appears twice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := evidence.New([]string{"go-binary"}, false, "1.0.0", tt.entries)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("New = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestParseRefusals(t *testing.T) {
	t.Parallel()

	const entries = `"entries": [{"name": "a.tar.gz", "sha256": "` + digestA + `", "type": "build-subject"}]`

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"not JSON", "not json", "evidence"},
		{"an absent field", `{"schema": 2, "classes": ["a"], "storeVsa": true, ` + entries + `}`, "required"},
		{
			// Pre-v1 there is no dual-version reader: manifests
			// published under the untyped schema re-emit typed at the
			// canon train, and until they do this reader refuses them
			// rather than guessing a population (stele#156).
			"the retired untyped schema",
			`{"schema": 1, "classes": ["a"], "storeVsa": true, "machineryVersion": "1.0.0"}`,
			"schema 1 is not 2",
		},
		{
			"a field outside the format",
			`{"schema": 2, "classes": ["a"], "storeVsa": true, "machineryVersion": "1.0.0", ` +
				entries + `, "extra": 1}`,
			"unknown",
		},
		{
			"an entry field outside the format",
			`{"schema": 2, "classes": ["a"], "storeVsa": true, "machineryVersion": "1.0.0", ` +
				`"entries": [{"name": "a", "sha256": "` + digestA + `", "type": "evidence", "size": 4}]}`,
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
