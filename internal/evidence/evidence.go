// Package evidence holds the release evidence manifest: the ONE
// definition of the document `stele emit manifest` writes and the
// assert contract reader decodes (docs/assert-policy-schema.md).
//
// It exists because the two legs must agree on what the manifest IS —
// field names, required-ness, the semver rule on machineryVersion —
// and two definitions of that drift into a writer whose output the
// reader refuses (the .github#434 law: share the definition, never
// share the derivation). What each leg DOES with the document stays
// its own: the writer renders declared facts, the reader derives
// obligations from them through the policy epochs, and neither can
// see the other's half.
//
// Every field is required from the first byte (stele#114): the
// obligations are derived from machineryVersion through the policy
// epochs, so a manifest that omits it cannot answer the epochs and
// would excuse obligations silently. Nothing emitted the manifest
// before this writer existed, which is why the fields were free to
// require.
//
// The manifest also TYPES what the release published (stele#156) and
// says which class BUILT each artifact (stele#185). Three legs needed
// to know which released assets are build subjects — the level walk,
// the reproducibility walk, the publish machinery's own resume guard
// — and each derived its own answer, so agreement was maintained by
// memory. Both facts are stamped once, here, at the only moment the
// publisher holds them natively; downstream walks READ them. Deriving
// them again at every walk is the defect, not the mechanism.
package evidence

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// Schema is the manifest's own format number — outside the
// live-document epoch (docs/versioning.md), because manifests are
// published release assets, immutable once shipped. It moved to 2
// when entries gained their type (stele#156) and to 3 when they
// gained the class that built them (stele#185).
//
// A manifest below this number is HISTORY, and history is admitted by
// a declared epoch or not at all: the reader answers what that
// manifest's own schema promised and nothing more, and whether a
// release of its vintage may still speak that schema is the policy's
// `manifestSchemaFromVersion` to say (internal/assert). Absent an
// epoch, only the current schema is admitted — which is the correct
// default for an adopter with no history to excuse.
const Schema = 3

// The schema each part of the document arrived at — the manifest's
// own numbers, not the live-document epoch. firstSchema is the oldest
// shape this reader can answer for at all: below it there is no
// document to read, because the format did not exist.
const (
	firstSchema = 1
	// entriesFrom: the schema from which a manifest lists what the
	// release published.
	entriesFrom = 2
	// classFrom: the schema from which each artifact names the class
	// that built it.
	classFrom = 3
)

// The entry types — what a released asset IS. The two carry opposite
// obligations, which is the whole reason the distinction is worth a
// field: a build artifact must rebuild bit-for-bit, while a signature
// bundle CANNOT, because a Sigstore signature embeds a fresh
// timestamp and certificate on every signing. That non-reproducibility
// is a security property, and a walk that could not tell the two apart
// reported it as a defect.
//
// The vocabulary is deliberately closed: an asset that is neither is
// a manifest this reader refuses, because unknown defaulting into
// either population is the failure this typing exists to prevent.
const (
	// TypeBuildSubject: an artifact OF the build.
	TypeBuildSubject = "build-subject"
	// TypeEvidence: a document ABOUT the release — an attestation
	// bundle, an inventory, a triage decision, a digest manifest.
	TypeEvidence = "evidence"
)

// sha256RE is this format's digest spelling: lowercase hex, 64 of it.
// An entry whose digest is not one pins nothing.
var sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Manifest is the release evidence manifest. Pointer fields, because
// the reader must tell absent from zero: a manifest missing storeVsa
// is malformed, not a store-layout release.
//
// It declares FACTS — the classes shipped, the verdict layout, the
// machinery version that published the release, what it published,
// what each asset is and which class built it — never obligations;
// those are always derived by the reader through the policy epochs.
type Manifest struct {
	Schema           *int     `json:"schema"`
	Classes          []string `json:"classes"`
	StoreVSA         *bool    `json:"storeVsa"`
	MachineryVersion *string  `json:"machineryVersion"`
	Entries          []Entry  `json:"entries,omitempty"`
}

// Entry is one asset the release published, pinned, typed, and — for
// an artifact — attributed to the class that built it. Pointer fields
// for the manifest's own reason: an entry whose type is ABSENT is
// malformed, and absent must never decode into one of the two
// populations.
//
// A manifest cannot pin itself — a document carrying its own digest
// is not a document — so the entries are the assets published BESIDE
// it. Nothing is lost: the manifest is an evidence document, and so
// is the checksum manifest that pins it.
type Entry struct {
	Name   *string `json:"name"`
	SHA256 *string `json:"sha256"`
	Type   *string `json:"type"`
	// Class names the evidence class whose build leg produced this
	// artifact — required on a build subject, and absent on an
	// evidence document, which is about the RELEASE and belongs to no
	// single class. It scopes a per-class reproducibility rebuild: a
	// walk that rebuilt one class and judged the whole release
	// reported every other class as missing from its own rebuild
	// (measured on release-lab v0.25.3, stele#185).
	Class *string `json:"class,omitempty"`
}

// NewSubject builds one build-subject entry — an artifact OF the
// build, which always names the class whose leg produced it. Two
// constructors rather than one with a nullable class: an entry the
// reader must refuse is then unrepresentable on the writing side,
// which is stronger than a writer that can build one and a validate
// that catches it.
func NewSubject(name, sha256, class string) Entry {
	t := TypeBuildSubject

	return Entry{Name: &name, SHA256: &sha256, Type: &t, Class: &class}
}

// NewEvidence builds one evidence entry — a document ABOUT the
// release, which names no class. Which classes a document covers is
// the release's declared set, and a per-entry answer here would be a
// second vocabulary for a question nothing asks.
func NewEvidence(name, sha256 string) Entry {
	t := TypeEvidence

	return Entry{Name: &name, SHA256: &sha256, Type: &t}
}

// Asset is one entry read back as values — the shape a walk consumes
// once Validate has proven every field present.
type Asset struct {
	Name   string
	SHA256 string
}

// New builds a valid manifest or refuses — the only constructor, so
// an invalid manifest exists nowhere on the writing side. It always
// writes the CURRENT schema: history is read, never written.
func New(classes []string, storeVSA bool, machineryVersion string, entries []Entry) (*Manifest, error) {
	schema := Schema
	m := &Manifest{
		Schema:           &schema,
		Classes:          classes,
		StoreVSA:         &storeVSA,
		MachineryVersion: &machineryVersion,
		Entries:          entries,
	}

	if err := m.Validate(); err != nil {
		return nil, err
	}

	return m, nil
}

// Current reports whether this manifest speaks the schema this build
// writes. A manifest that does not is readable for exactly what its
// own schema promised — nothing is decoded two ways — and whether a
// release of its vintage may still speak it is the epoch's question,
// which lives in the policy the caller holds and not here.
func (m *Manifest) Current() bool {
	return m.Schema != nil && *m.Schema == Schema
}

// Subjects lists the entries typed as build subjects, in the order
// the manifest carries them — the population a reproducibility walk
// judges. READ from the manifest's own typing: a walk that re-derived
// it here would be the second answer this field exists to retire.
func (m *Manifest) Subjects() []Asset {
	return m.subjects(nil)
}

// SubjectsOf narrows Subjects to the artifacts ONE class built — the
// population a per-class rebuild is judged against. ok=false means
// this manifest carries no class answer (a schema below 3), and the
// caller must SAY so rather than silently narrow or widen a
// population it cannot scope: an empty result and "no answer" are
// different facts, and conflating them is how a rebuild nobody ran
// reads as a rebuild that found nothing.
func (m *Manifest) SubjectsOf(class string) ([]Asset, bool) {
	if !m.Current() {
		return nil, false
	}

	return m.subjects(&class), true
}

// Declares reports whether the release named this class among the
// ones it shipped — asked before a class-scoped walk narrows to it,
// so a class the release never shipped refuses instead of sealing an
// honest-looking verdict over a population of zero.
func (m *Manifest) Declares(class string) bool {
	return slices.Contains(m.Classes, class)
}

// Validate holds the shared shape rules. Both legs call it: the
// writer before rendering, the reader after decoding, so what leaves
// one is what the other admits — by construction, not by review.
//
// It validates against the manifest's OWN declared schema, because
// that is what the document promised when it shipped. This is not a
// dual-version reader: every field is decoded exactly one way, and
// what a schema number selects is which fields are PROMISED, never
// how any of them is read. A manifest carrying a field its schema
// does not promise is refused as loudly as one missing a field its
// schema does — a document that lies about its own format is worse
// than one that is merely old.
func (m *Manifest) Validate() error {
	if m.Schema == nil || m.StoreVSA == nil || m.MachineryVersion == nil || len(m.Classes) == 0 {
		return errors.New("evidence: schema, classes, storeVsa and machineryVersion are all required")
	}

	if *m.Schema < firstSchema || *m.Schema > Schema {
		return fmt.Errorf("evidence: schema %d is not a manifest schema this build reads (%d through %d)",
			*m.Schema, firstSchema, Schema)
	}

	seen := make(map[string]bool, len(m.Classes))

	for i, class := range m.Classes {
		if class == "" {
			return fmt.Errorf("evidence: classes[%d] is empty — a class with no name declares nothing", i)
		}

		if seen[class] {
			return fmt.Errorf("evidence: class %q is declared twice — what a release ships is a set", class)
		}

		seen[class] = true
	}

	if _, err := semver.NewVersion(*m.MachineryVersion); err != nil {
		return fmt.Errorf("evidence: machineryVersion %q: %w — a declaration that cannot answer the policy"+
			" epochs excuses nothing silently", *m.MachineryVersion, err)
	}

	return m.validateEntries(seen)
}

// Parse decodes and validates one manifest at whatever schema it
// declares — the reader's entry, and the writer's own post-render
// check: what the writer verifies is the rendered bytes read back
// through this same seam, never its own bookkeeping.
//
// The schema number is READ, never judged against the present: which
// schemas a release may still speak is a question about WHEN it was
// published, the epoch answers it, and the epoch is policy. A caller
// holding one asks Current(); a caller holding none is reading a
// document it did not fetch through the org's contract and takes the
// manifest for what it says it is.
func Parse(raw []byte) (*Manifest, error) {
	m, err := jsonx.DecodeBytes[Manifest](raw)
	if err != nil {
		return nil, fmt.Errorf("evidence: %w", err)
	}

	if err := m.Validate(); err != nil {
		return nil, err
	}

	return m, nil
}

// Encode writes the manifest as one JSON value plus newline.
func (m *Manifest) Encode(w io.Writer) error {
	if err := jsonx.Encode(w, m); err != nil {
		return fmt.Errorf("evidence: %w", err)
	}

	return nil
}

// subjects is the one build-subject filter; class nil takes every
// class. One walk, so the whole-release and per-class populations
// cannot disagree about what a build subject is.
func (m *Manifest) subjects(class *string) []Asset {
	var out []Asset

	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Name == nil || e.SHA256 == nil || e.Type == nil || *e.Type != TypeBuildSubject {
			continue
		}

		if class != nil && (e.Class == nil || *e.Class != *class) {
			continue
		}

		out = append(out, Asset{Name: *e.Name, SHA256: *e.SHA256})
	}

	return out
}

// validateEntries holds the typing rules, against what this
// manifest's own schema promised. Every entry names an asset, pins
// its bytes, says what it is, and — from schema 3 — says which
// declared class built it; a manifest carrying an entry that fails
// any of those is refused whole, because the failure mode this typing
// exists to prevent is precisely an asset landing in a population it
// does not belong to.
func (m *Manifest) validateEntries(declared map[string]bool) error {
	if *m.Schema < entriesFrom {
		if len(m.Entries) != 0 {
			return fmt.Errorf("evidence: schema %d carries no entries, and this manifest has %d — a"+
				" document that lies about its own format reads worse than an old one",
				*m.Schema, len(m.Entries))
		}

		return nil
	}

	if len(m.Entries) == 0 {
		return errors.New("evidence: entries is required — a manifest that lists nothing says nothing about" +
			" what the release published")
	}

	seen := make(map[string]bool, len(m.Entries))

	for i := range m.Entries {
		e := &m.Entries[i]

		if err := m.validateEntry(i, e, declared); err != nil {
			return err
		}

		if seen[*e.Name] {
			return fmt.Errorf("evidence: entry %q appears twice — what a release published is a set", *e.Name)
		}

		seen[*e.Name] = true
	}

	return nil
}

// validateEntry holds one entry's rules, split out because the guard
// count is the point: each branch is a distinct way an asset lands in
// a population it does not belong to.
func (m *Manifest) validateEntry(i int, e *Entry, declared map[string]bool) error {
	switch {
	case e.Name == nil || *e.Name == "":
		return fmt.Errorf("evidence: entries[%d] has no name — an entry naming no asset types nothing", i)
	case e.SHA256 == nil:
		return fmt.Errorf("evidence: entries[%d] (%s) has no sha256 — an entry that pins no bytes"+
			" pins nothing", i, *e.Name)
	case !sha256RE.MatchString(*e.SHA256):
		return fmt.Errorf("evidence: entries[%d] (%s): sha256 %q is not a sha256 digest",
			i, *e.Name, *e.SHA256)
	case e.Type == nil:
		return fmt.Errorf("evidence: entries[%d] (%s) has no type — an unclassified asset must never"+
			" default into either population", i, *e.Name)
	case *e.Type != TypeBuildSubject && *e.Type != TypeEvidence:
		return fmt.Errorf("evidence: entries[%d] (%s): type %q is neither %q nor %q — the vocabulary is"+
			" closed on purpose", i, *e.Name, *e.Type, TypeBuildSubject, TypeEvidence)
	}

	return m.validateEntryClass(i, e, declared)
}

// validateEntryClass holds the class rules. A class is owed by an
// artifact and refused on a document: what a document is about is the
// release, and attributing one to a single class would be a second
// vocabulary. The name must be one the manifest already declared —
// an entry claiming a class the release did not ship is incoherent
// about its own document, and the check needs no policy to make it.
func (m *Manifest) validateEntryClass(i int, e *Entry, declared map[string]bool) error {
	if *m.Schema < classFrom {
		if e.Class != nil {
			return fmt.Errorf("evidence: entries[%d] (%s) carries a class, which schema %d does not have"+
				" — a document that lies about its own format reads worse than an old one",
				i, *e.Name, *m.Schema)
		}

		return nil
	}

	if *e.Type == TypeEvidence {
		if e.Class != nil {
			return fmt.Errorf("evidence: entries[%d] (%s) is %s and carries class %q — a document ABOUT the"+
				" release belongs to no one class", i, *e.Name, TypeEvidence, *e.Class)
		}

		return nil
	}

	switch {
	case e.Class == nil || *e.Class == "":
		return fmt.Errorf("evidence: entries[%d] (%s) has no class — an artifact no class claims cannot be"+
			" scoped by a per-class rebuild, and would go unjudged in silence", i, *e.Name)
	case !declared[*e.Class]:
		return fmt.Errorf("evidence: entries[%d] (%s): class %q is not one this release declared (%v)"+
			" — an artifact built by a class the release does not ship places nothing",
			i, *e.Name, *e.Class, m.Classes)
	}

	return nil
}
