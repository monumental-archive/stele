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
// The manifest also TYPES what the release published (stele#156).
// Three legs needed to know which released assets are build subjects
// — the level walk, the reproducibility walk, the publish machinery's
// own resume guard — and each derived its own answer, so agreement
// was maintained by memory. The classification is stamped once, here,
// at the only moment the publisher holds it natively; downstream
// walks READ it. Deriving it again at every walk is the defect, not
// the mechanism.
package evidence

import (
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// Schema is the manifest's own format number — outside the
// live-document epoch (docs/versioning.md), because manifests are
// published release assets, immutable once shipped. It moved to 2
// when entries gained their type (stele#156); pre-v1 there is no
// dual-version reader, so a schema-1 manifest is refused and the
// manifests already published re-emit typed at the canon train (the
// note-format v3 precedent).
const Schema = 2

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
// machinery version that published the release, what it published and
// what each asset is — never obligations; those are always derived by
// the reader through the policy epochs.
type Manifest struct {
	Schema           *int     `json:"schema"`
	Classes          []string `json:"classes"`
	StoreVSA         *bool    `json:"storeVsa"`
	MachineryVersion *string  `json:"machineryVersion"`
	Entries          []Entry  `json:"entries"`
}

// Entry is one asset the release published, pinned and typed.
// Pointer fields for the manifest's own reason: an entry whose type
// is ABSENT is malformed, and absent must never decode into one of
// the two populations.
//
// A manifest cannot pin itself — a document carrying its own digest
// is not a document — so the entries are the assets published BESIDE
// it. Nothing is lost: the manifest is an evidence document, and so
// is the checksum manifest that pins it.
type Entry struct {
	Name   *string `json:"name"`
	SHA256 *string `json:"sha256"`
	Type   *string `json:"type"`
}

// NewEntry builds one typed entry — the writing side's spelling, so
// callers never hold the pointers the decode contract requires.
func NewEntry(name, sha256, entryType string) Entry {
	return Entry{Name: &name, SHA256: &sha256, Type: &entryType}
}

// Asset is one entry read back as values — the shape a walk consumes
// once Validate has proven every field present.
type Asset struct {
	Name   string
	SHA256 string
}

// New builds a valid manifest or refuses — the only constructor, so
// an invalid manifest exists nowhere on the writing side.
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

// Subjects lists the entries typed as build subjects, in the order
// the manifest carries them — the population a reproducibility walk
// judges. READ from the manifest's own typing: a walk that re-derived
// it here would be the second answer this field exists to retire.
func (m *Manifest) Subjects() []Asset {
	var out []Asset

	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Name == nil || e.SHA256 == nil || e.Type == nil || *e.Type != TypeBuildSubject {
			continue
		}

		out = append(out, Asset{Name: *e.Name, SHA256: *e.SHA256})
	}

	return out
}

// Validate holds the shared shape rules. Both legs call it: the
// writer before rendering, the reader after decoding, so what leaves
// one is what the other admits — by construction, not by review.
func (m *Manifest) Validate() error {
	if m.Schema == nil || m.StoreVSA == nil || m.MachineryVersion == nil || len(m.Classes) == 0 {
		return errors.New("evidence: schema, classes, storeVsa and machineryVersion are all required")
	}

	if *m.Schema != Schema {
		return fmt.Errorf("evidence: schema %d is not %d", *m.Schema, Schema)
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

	return m.validateEntries()
}

// Parse decodes and validates one manifest — the reader's entry, and
// the writer's own post-render check: what the writer verifies is the
// rendered bytes read back through this same seam, never its own
// bookkeeping.
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

// validateEntries holds the typing rules. Every entry names an asset,
// pins its bytes and says what it is; a manifest carrying an entry
// that fails any of the three is refused whole, because the failure
// mode this typing exists to prevent is precisely an asset landing in
// a population it does not belong to.
func (m *Manifest) validateEntries() error {
	if len(m.Entries) == 0 {
		return errors.New("evidence: entries is required — a manifest that lists nothing says nothing about" +
			" what the release published")
	}

	seen := make(map[string]bool, len(m.Entries))

	for i := range m.Entries {
		e := &m.Entries[i]

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
		case seen[*e.Name]:
			return fmt.Errorf("evidence: entry %q appears twice — what a release published is a set", *e.Name)
		}

		seen[*e.Name] = true
	}

	return nil
}
