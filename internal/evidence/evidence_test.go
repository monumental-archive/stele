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
	digestC = "3333333333333333333333333333333333333333333333333333333333333333"
	digestD = "4444444444444444444444444444444444444444444444444444444444444444"
)

// oneOfEach is the shape every valid fixture below starts from: an
// artifact and a document about it, which is what a release ships.
func oneOfEach() []evidence.Entry {
	return []evidence.Entry{
		evidence.NewSubject("widget-x86_64.tar.gz", digestA, "go-binary"),
		evidence.NewEvidence("attestations-image.intoto.jsonl", digestB),
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
		evidence.NewEvidence("widget-x86_64.tar.gz", digestA),
		evidence.NewSubject("odd-name-no-convention-would-match", digestB, "go-binary"),
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

	m := &evidence.Manifest{Entries: []evidence.Entry{{}, evidence.NewSubject("a", digestA, "go-binary")}}
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
			[]evidence.Entry{evidence.NewSubject("", digestA, "go-binary")},
			"has no name",
		},
		{
			"an entry pinning no bytes",
			[]evidence.Entry{{Name: new("a.tar.gz"), Type: new(evidence.TypeBuildSubject)}},
			"has no sha256",
		},
		{
			"an entry whose digest is not one",
			[]evidence.Entry{evidence.NewSubject("a.tar.gz", "cafe", "go-binary")},
			"is not a sha256 digest",
		},
		{
			"an untyped entry",
			[]evidence.Entry{{Name: new("a.tar.gz"), SHA256: new(digestA)}},
			"has no type",
		},
		{
			"a type outside the closed vocabulary",
			[]evidence.Entry{{Name: new("a.tar.gz"), SHA256: new(digestA), Type: new("artefact")}},
			"is neither",
		},
		{
			"the same asset twice",
			[]evidence.Entry{
				evidence.NewSubject("a.tar.gz", digestA, "go-binary"),
				evidence.NewEvidence("a.tar.gz", digestB),
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

	const entries = `"entries": [{"name": "a.tar.gz", "sha256": "` + digestA +
		`", "type": "build-subject", "class": "a"}]`

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"not JSON", "not json", "evidence"},
		{"an absent field", `{"schema": 3, "classes": ["a"], "storeVsa": true, ` + entries + `}`, "required"},
		{
			// The number names a shape. Below the first there was no
			// format; above the current one there is a document this
			// build has never written, and guessing at it is exactly
			// the best-effort read the refusal boundary exists to stop.
			"a schema below the first",
			`{"schema": 0, "classes": ["a"], "storeVsa": true, "machineryVersion": "1.0.0"}`,
			"not a manifest schema this build reads",
		},
		{
			"a schema above the current one",
			`{"schema": 4, "classes": ["a"], "storeVsa": true, "machineryVersion": "1.0.0", ` + entries + `}`,
			"not a manifest schema this build reads",
		},
		{
			// A document that lies about its own format is worse than
			// an old one: the schema number is what a reader trusts to
			// know which fields were promised.
			"an old schema carrying a field it never had",
			`{"schema": 1, "classes": ["a"], "storeVsa": true, "machineryVersion": "1.0.0", ` + entries + `}`,
			"schema 1 carries no entries",
		},
		{
			// The other direction of the same promise: a schema that
			// OWED a field and does not carry it. Held at schema 2
			// because schema 3 cannot reach it — New always writes the
			// current schema and validates before rendering, so only a
			// document read from history can owe and omit.
			"a typed schema missing the entries it owed",
			`{"schema": 2, "classes": ["a"], "storeVsa": true, "machineryVersion": "1.0.0"}`,
			"entries is required",
		},
		{
			"a typed schema carrying a class it never had",
			`{"schema": 2, "classes": ["a"], "storeVsa": true, "machineryVersion": "1.0.0", ` +
				`"entries": [{"name": "a.tar.gz", "sha256": "` + digestA + `", "type": "build-subject",` +
				` "class": "a"}]}`,
			"which schema 2 does not have",
		},
		{
			// The class rules, from the reader's side: every one is a
			// distinct way an artifact lands in a population it does
			// not belong to, or in none at all.
			"an artifact no class claims",
			`{"schema": 3, "classes": ["a"], "storeVsa": true, "machineryVersion": "1.0.0", ` +
				`"entries": [{"name": "a.tar.gz", "sha256": "` + digestA + `", "type": "build-subject"}]}`,
			"has no class",
		},
		{
			"an artifact whose class the release never shipped",
			`{"schema": 3, "classes": ["a"], "storeVsa": true, "machineryVersion": "1.0.0", ` +
				`"entries": [{"name": "a.tar.gz", "sha256": "` + digestA + `", "type": "build-subject",` +
				` "class": "b"}]}`,
			"is not one this release declared",
		},
		{
			"a document claiming a class",
			`{"schema": 3, "classes": ["a"], "storeVsa": true, "machineryVersion": "1.0.0", ` +
				`"entries": [{"name": "sbom.spdx.json", "sha256": "` + digestA + `", "type": "evidence",` +
				` "class": "a"}]}`,
			"belongs to no one class",
		},
		{
			"a field outside the format",
			`{"schema": 3, "classes": ["a"], "storeVsa": true, "machineryVersion": "1.0.0", ` +
				entries + `, "extra": 1}`,
			"unknown",
		},
		{
			"an entry field outside the format",
			`{"schema": 3, "classes": ["a"], "storeVsa": true, "machineryVersion": "1.0.0", ` +
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

// History reads for exactly what its own schema promised, and no
// further. The reader answers the four facts every manifest has
// carried since the first byte; the entries a schema never had are
// absent rather than guessed, and the class answer a schema never
// carried is REFUSED rather than answered emptily — an empty
// population and no population are different facts (stele#185).
func TestOlderSchemasReadForWhatTheyPromised(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		doc         string
		wantSubject int
	}{
		{
			"the untyped schema: the facts, and no population at all",
			`{"schema": 1, "classes": ["go-binary"], "storeVsa": true, "machineryVersion": "1.44.3"}`,
			0,
		},
		{
			"the typed schema: a population, and no class answer",
			`{"schema": 2, "classes": ["go-binary"], "storeVsa": true, "machineryVersion": "1.46.0",` +
				` "entries": [{"name": "a.tar.gz", "sha256": "` + digestA + `", "type": "build-subject"}]}`,
			1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, err := evidence.Parse([]byte(tt.doc))
			if err != nil {
				t.Fatalf("Parse = %v, want history to read", err)
			}

			if m.Current() {
				t.Error("Current = true on a manifest below this build's schema")
			}

			if *m.MachineryVersion == "" || !*m.StoreVSA || len(m.Classes) != 1 {
				t.Errorf("the facts every schema carries did not survive: %+v", m)
			}

			if got := m.Subjects(); len(got) != tt.wantSubject {
				t.Errorf("Subjects = %+v, want %d", got, tt.wantSubject)
			}

			if got, ok := m.SubjectsOf("go-binary"); ok {
				t.Errorf("SubjectsOf = %+v, ok = true — a schema below the class answer must say it has none", got)
			}

			if m.Attributes() {
				t.Error("Attributes = true on a schema that carries no class on any entry")
			}

			// The three-state seam a consumer narrows on (stele#206):
			// "no answer" must never arrive as an empty map, or a walk
			// reads "this manifest attributes nothing" as "no artifact
			// owes anything class-specific" and excuses in silence.
			if got, ok := m.ArtifactClasses(); ok || got != nil {
				t.Errorf("ArtifactClasses = %+v, ok = %v, want no answer at all", got, ok)
			}
		})
	}
}

// The attribution, read from the manifest's own entries: every
// artifact maps to the class that built it, documents map to nothing
// because a document ABOUT a release belongs to no one class, and the
// answer is present — which is what lets the demand be per artifact
// instead of the whole declared set (stele#206).
func TestArtifactClassesReadsTheAttribution(t *testing.T) {
	t.Parallel()

	m, err := evidence.New([]string{"go-binary", "source-archive"}, true, "1.48.0",
		[]evidence.Entry{
			evidence.NewSubject("tool-linux-amd64.tar.gz", digestA, "go-binary"),
			evidence.NewSubject("src-1.0.0.tar.gz", digestB, "source-archive"),
			evidence.NewEvidence("attestations.intoto.jsonl", digestC),
		})
	if err != nil {
		t.Fatalf("New = %v", err)
	}

	if !m.Attributes() {
		t.Fatal("Attributes = false on the schema that carries the class")
	}

	got, ok := m.ArtifactClasses()
	if !ok {
		t.Fatal("ArtifactClasses ok = false on the schema that carries the answer")
	}

	want := map[string]string{
		"tool-linux-amd64.tar.gz": "go-binary",
		"src-1.0.0.tar.gz":        "source-archive",
	}
	if len(got) != len(want) {
		t.Fatalf("ArtifactClasses = %+v, want %+v", got, want)
	}

	for artifact, class := range want {
		if got[artifact] != class {
			t.Errorf("%s attributed to %q, want %q", artifact, got[artifact], class)
		}
	}

	if _, named := got["attestations.intoto.jsonl"]; named {
		t.Error("a document ABOUT the release was attributed to a class")
	}
}

// The class answer, read from the manifest's own typing: a per-class
// population is the artifacts THAT class built and nothing else, a
// class that built nothing is an empty population rather than no
// answer, and the whole-release population is unchanged by the
// narrowing existing at all.
func TestSubjectsOfScopesToOneClass(t *testing.T) {
	t.Parallel()

	m, err := evidence.New([]string{"go-binary", "oci-image", "source-archive"}, true, "1.47.0",
		[]evidence.Entry{
			evidence.NewSubject("tool-linux-amd64.tar.gz", digestA, "go-binary"),
			evidence.NewSubject("tool-darwin-arm64.tar.gz", digestB, "go-binary"),
			evidence.NewSubject("src-1.0.0.tar.gz", digestC, "source-archive"),
			evidence.NewEvidence("attestations.intoto.jsonl", digestD),
		})
	if err != nil {
		t.Fatalf("New = %v", err)
	}

	if got := m.Subjects(); len(got) != 3 {
		t.Errorf("Subjects = %+v, want every artifact whatever built it", got)
	}

	got, ok := m.SubjectsOf("go-binary")
	if !ok {
		t.Fatal("SubjectsOf ok = false on the schema that carries the answer")
	}

	if len(got) != 2 || got[0].Name != "tool-linux-amd64.tar.gz" || got[1].SHA256 != digestB {
		t.Errorf("SubjectsOf(go-binary) = %+v", got)
	}

	// A class that publishes to a registry rather than the release
	// ships no assets. That is a population of zero, which seals
	// CANNOT_JUDGE downstream — never a missing answer.
	if empty, emptyOK := m.SubjectsOf("oci-image"); !emptyOK || len(empty) != 0 {
		t.Errorf("SubjectsOf(oci-image) = %+v, ok = %v, want an empty population that IS an answer",
			empty, emptyOK)
	}

	if !m.Declares("source-archive") || m.Declares("rust-binary") {
		t.Error("Declares does not read the manifest's own class list")
	}
}

// TestPinsReadsBothPopulations: the cross-check (stele#219) asks about
// every name the manifest pins, artifacts and documents alike, because
// the checksum manifest pins both and a disagreement over an evidence
// document is the same defect as one over an artifact.
func TestPinsReadsBothPopulations(t *testing.T) {
	t.Parallel()

	m, err := evidence.New([]string{"go-binary"}, true, "1.48.0", []evidence.Entry{
		evidence.NewSubject("tool-linux-amd64.tar.gz", digestA, "go-binary"),
		evidence.NewEvidence("attestations.intoto.jsonl", digestC),
	})
	if err != nil {
		t.Fatalf("New = %v", err)
	}

	got, ok := m.Pins()
	if !ok {
		t.Fatal("Pins ok = false on a schema that carries entries")
	}

	want := map[string]string{
		"tool-linux-amd64.tar.gz":   digestA,
		"attestations.intoto.jsonl": digestC,
	}

	if len(got) != len(want) {
		t.Fatalf("Pins = %+v, want %+v", got, want)
	}

	for name, digest := range want {
		if got[name] != digest {
			t.Errorf("%s pins %q, want %q", name, got[name], digest)
		}
	}
}

// TestPinsCannotAnswerBelowEntries: "cannot pin" and "pins nothing"
// are different facts, and only the first may excuse the cross-check.
// A schema below entries carries no answer at all, and an empty map
// read as one would silently excuse a document that pins plenty.
func TestPinsCannotAnswerBelowEntries(t *testing.T) {
	t.Parallel()

	doc := `{"schema": 1, "classes": ["go-binary"], "storeVsa": true, "machineryVersion": "1.48.0"}`

	m, err := evidence.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}

	if got, ok := m.Pins(); ok || got != nil {
		t.Fatalf("Pins = %+v, %v — want no answer from a schema that carries no entries", got, ok)
	}
}
