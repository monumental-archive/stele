// Package imagefacts resolves the OCI image metadata facts a release
// asserts on its images: one map, derived once, before anything is
// built.
//
// Deliberately NOT in internal/assert, which holds the CHECKER for
// the same facts. The org's rule is that a check must not be the
// writer inverted — a derivation verified by its own inverse passes
// its own exam. Keeping the two in separate packages means no helper
// can be quietly shared between them, so `assert image-facts`
// re-derives hygiene independently and a resolver bug cannot
// self-certify. The duplication is the point.
//
// Two defect classes the bash guarded against are unrepresentable
// here rather than checked:
//
//   - "a provenance fact is missing" — provenance facts are struct
//     fields, not map entries, so the map is RENDERED from a value
//     that already has them. The bash assembles a map with jq and
//     then asks jq whether the required keys are present.
//   - "the continuous archetype carries a version" — the two
//     archetypes are two constructors, so a continuous release with
//     a version does not typecheck. The bash tests an environment
//     variable in a case statement.
//
// Hygiene is likewise enforced at construction rather than audited
// afterwards: every value passes the same emptiness and control-
// character rules as it is set, so an unhygienic Facts cannot exist
// to be checked.
package imagefacts

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The OCI annotation keys. Spec, not org convention — the image spec
// defines them and every consumer reads them by these names.
const (
	KeySource      = "org.opencontainers.image.source"
	KeyRevision    = "org.opencontainers.image.revision"
	KeyVersion     = "org.opencontainers.image.version"
	KeyCreated     = "org.opencontainers.image.created"
	KeyLicenses    = "org.opencontainers.image.licenses"
	KeyTitle       = "org.opencontainers.image.title"
	KeyDescription = "org.opencontainers.image.description"
)

var (
	revisionRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	controlRE  = regexp.MustCompile(`[\x00-\x1f\x7f]`)
)

// Archetype is the release shape. The interface is unexported-method
// sealed: the only two values are Versioned and Continuous, so a
// caller cannot invent a third and the switch over them is total.
type Archetype interface {
	version() (string, bool)
}

// Versioned is a release that names a version.
type Versioned struct{ Version string }

func (v Versioned) version() (string, bool) { return v.Version, true }

// Continuous is a release with no version surface. It carries no
// version FIELD, which is what makes "continuous with a version"
// unspellable rather than merely refused.
type Continuous struct{}

func (Continuous) version() (string, bool) { return "", false }

// Provenance is what the facts are derived FROM: the guard-proven
// ref, the repository as the forge names it, the released commit's
// own instant, and the declared licence. None of these is a caller
// input by choice — a caller input is a place to be silently wrong
// about what gets signed.
type Provenance struct {
	// ServerURL and Repository compose the source URL, rendered once
	// and canonically: verbatim case, no trailing slash, no .git, so
	// an equality check against it never needs normalising the other
	// side.
	ServerURL  string
	Repository string
	// Revision is the full lowercase commit SHA.
	Revision string
	// Committed is the released commit's own time. Never a wall
	// clock: the release date IS the date of what is released, and
	// the one wall-clock value would otherwise be published beside
	// commit-pinned ones.
	Committed time.Time
	// Licence is the declaration, in any spelling; the canonical
	// form is what ships.
	Licence string
	// RepositoryField is the manifest's own repository URL where one
	// is declared, checked against the derived source. Empty when the
	// tree declares none.
	RepositoryField string
}

// Editorial facts are caller inputs with derived defaults, omitted
// rather than emitted empty.
type Editorial struct {
	Title       string
	Description string
}

// Facts is a resolved, validated fact set. Constructor: Resolve,
// alone — the zero value renders nothing.
type Facts struct {
	source    string
	revision  string
	version   string
	created   string
	licences  string
	title     string
	descr     string
	committed time.Time
}

// Resolve derives and validates the whole fact set.
func Resolve(a Archetype, p *Provenance, e Editorial) (*Facts, error) {
	if a == nil {
		return nil, errors.New("imagefacts: an archetype is required: versioned or continuous")
	}

	if !revisionRE.MatchString(p.Revision) {
		return nil, fmt.Errorf("imagefacts: revision %q is not a full lowercase commit SHA", p.Revision)
	}

	if p.Repository == "" {
		return nil, errors.New("imagefacts: the repository is required")
	}

	if p.Committed.IsZero() {
		return nil, errors.New("imagefacts: no commit time — the released commit dates the release")
	}

	licence, err := checkLicence(p.Licence)
	if err != nil {
		return nil, err
	}

	source, err := sourceURL(p)
	if err != nil {
		return nil, err
	}

	version, versioned := a.version()
	if versioned && strings.TrimSpace(version) == "" {
		return nil, errors.New("imagefacts: a versioned release needs a version")
	}

	facts := &Facts{
		source:    source,
		revision:  p.Revision,
		version:   version,
		created:   p.Committed.UTC().Format(time.RFC3339),
		licences:  licence,
		title:     e.Title,
		descr:     e.Description,
		committed: p.Committed,
	}

	if facts.title == "" {
		facts.title = defaultTitle(p.Repository)
	}

	if err := facts.hygiene(); err != nil {
		return nil, err
	}

	return facts, nil
}

// Epoch is the released commit's instant as SOURCE_DATE_EPOCH sees
// it. One read, two renderings: the annotation and the epoch cannot
// disagree because neither is derived from the other's output.
func (f *Facts) Epoch() int64 { return f.committed.Unix() }

// Map renders the annotation map. Provenance keys are struct fields,
// so they are always present; editorial keys are omitted when empty
// rather than emitted as "", which reads as set — deliberately
// stricter than the OCI spec, which permits empty values.
func (f *Facts) Map() map[string]string {
	m := map[string]string{
		KeySource:   f.source,
		KeyRevision: f.revision,
		KeyCreated:  f.created,
		KeyLicenses: f.licences,
		KeyTitle:    f.title,
	}

	if f.version != "" {
		m[KeyVersion] = f.version
	}

	if f.descr != "" {
		m[KeyDescription] = f.descr
	}

	return m
}

// Keys lists the rendered keys in a stable order.
func (f *Facts) Keys() []string {
	m := f.Map()

	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}

// hygiene refuses a value that is empty, padded, or carries control
// characters. Run at construction, over the rendered map, so no
// caller can observe a Facts that would fail it.
func (f *Facts) hygiene() error {
	for _, k := range f.Keys() {
		v := f.Map()[k]

		switch {
		case v == "":
			return fmt.Errorf("imagefacts: %s is empty", k)
		case controlRE.MatchString(v):
			return fmt.Errorf("imagefacts: %s carries control characters", k)
		case strings.TrimSpace(v) != v:
			return fmt.Errorf("imagefacts: %s is padded with whitespace", k)
		}
	}

	return nil
}

// sourceURL renders the repository URL and holds it against the
// manifest's own declaration where there is one.
//
// These ARE two independent statements of one fact, unlike the
// licence tiers, and npm trusted publishing already fails on their
// mismatch — at publish time, after the images are pushed. Checking
// here turns that into a five-second failure with the remedy named.
// The stale case is real: a transferred repository keeps its old URL
// in the manifest.
func sourceURL(p *Provenance) (string, error) {
	server := p.ServerURL
	if server == "" {
		return "", errors.New("imagefacts: the forge server URL is required")
	}

	source := strings.TrimSuffix(server, "/") + "/" + p.Repository

	if p.RepositoryField == "" {
		return source, nil
	}

	declared := strings.TrimSuffix(strings.TrimSuffix(p.RepositoryField, "/"), ".git")
	if declared != source {
		return "", fmt.Errorf("imagefacts: the manifest declares repository %q but the release is %q —"+
			" update the repository field (it goes stale after a transfer)", p.RepositoryField, source)
	}

	return source, nil
}

// defaultTitle is the repository's own name, the last path segment.
func defaultTitle(repository string) string {
	if i := strings.LastIndex(repository, "/"); i >= 0 {
		return repository[i+1:]
	}

	return repository
}
