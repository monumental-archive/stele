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
package evidence

import (
	"errors"
	"fmt"
	"io"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// Schema is the manifest's own format number — outside the
// live-document epoch (docs/versioning.md), because manifests are
// published release assets, immutable once shipped.
const Schema = 1

// Manifest is the release evidence manifest. Pointer fields, because
// the reader must tell absent from zero: a manifest missing storeVsa
// is malformed, not a store-layout release.
//
// It declares FACTS — the classes shipped, the verdict layout, the
// machinery version that published the release — never obligations;
// those are always derived by the reader through the policy epochs.
type Manifest struct {
	Schema           *int     `json:"schema"`
	Classes          []string `json:"classes"`
	StoreVSA         *bool    `json:"storeVsa"`
	MachineryVersion *string  `json:"machineryVersion"`
}

// New builds a valid manifest or refuses — the only constructor, so
// an invalid manifest exists nowhere on the writing side.
func New(classes []string, storeVSA bool, machineryVersion string) (*Manifest, error) {
	schema := Schema
	m := &Manifest{
		Schema:           &schema,
		Classes:          classes,
		StoreVSA:         &storeVSA,
		MachineryVersion: &machineryVersion,
	}

	if err := m.Validate(); err != nil {
		return nil, err
	}

	return m, nil
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

	return nil
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
