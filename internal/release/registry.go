// Registry-class subjects (stele#393, added 2026-11-17): what a release
// published to a registry rather than attached as an asset. Each
// planned leg leaves one file behind recording the digest it pushed,
// in the class's declared form (stele#442), and the set is the
// signer's input — so a partial set, or one carrying a leg the plan
// never asked for, is refused by name before anything is signed.
//
// Reading that directory is one reader, Digests, whichever form the
// class declares: the subject derivation and any other leg comparing
// what a build pushed share it, so what a digest file SAYS has one
// definition.

package release

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// RegistryClass is one registry class's statement of what a planned
// leg leaves behind. It is compiled from the class's declared shape
// (shape.go); no class is written here.
type RegistryClass struct {
	// Name is the evidence class, as the policy spells it.
	Name string
	// Unit is what one planned entry is called in a refusal.
	Unit string
	// Form is how each leg records what it pushed.
	Form RegistryForm
	// Extension is the digest files' suffix in the directory; empty
	// reads every non-hidden file (a bare digest only).
	Extension string
	// LegField is the digest document field naming its leg (document
	// form only).
	LegField string
	entry    *regexp.Regexp
}

// RegistryDigest is one leg's record, as its digest file states it.
type RegistryDigest struct {
	// File is the digest file's name in the directory.
	File string
	// Label is the leg the file records: the document's leg field,
	// or a bare digest file's name less the extension.
	Label string
	// SHA256 is the pushed digest's hex.
	SHA256 string
	// Image is the image pushed; a bare digest does not name one.
	Image string
}

var sha256DigestRE = regexp.MustCompile(`^sha256:([0-9a-f]{64})$`)

// Digests reads every digest file in dir, in file-name order. A file
// that does not read as the class's form, and two files recording one
// leg, are each refused by name, all of them together. Whether the
// legs read are the legs wanted is the caller's question.
func (c *RegistryClass) Digests(dir string) ([]RegistryDigest, error) {
	digests, _, refusals, err := c.scan(dir)
	if err != nil {
		return nil, err
	}

	if len(refusals) > 0 {
		return nil, fmt.Errorf("release: %s digests: %w", c.Name, errors.Join(refusals...))
	}

	return digests, nil
}

// RegistrySubjects computes the registry subject lines for the digest
// files in dir against the planned entries.
func (c *RegistryClass) RegistrySubjects(dir string, planned []string) (*Registry, error) {
	// A subject line names the image pushed, and a bare digest names
	// none: inventing one would sign a name no build stated.
	if c.Form != FormDocument {
		return nil, fmt.Errorf("release: %s subjects: a %s class records no image name, so it has no subject lines",
			c.Name, c.Form)
	}

	plannedSet, err := c.plan(planned)
	if err != nil {
		return nil, err
	}

	digests, listed, refusals, err := c.scan(dir)
	if err != nil {
		return nil, err
	}

	partial := func(detail string) error {
		return fmt.Errorf("%d image digests for %d planned %ss; refusing a partial set: %s",
			listed, len(planned), c.Unit, detail)
	}

	out := &Registry{}
	read := map[string]bool{}

	for _, d := range digests {
		read[d.Label] = true

		if !plannedSet[d.Label] {
			refusals = append(refusals, partial(fmt.Sprintf("%s names %s %s, which is not planned", d.File, c.Unit, d.Label)))

			continue
		}

		out.Lines = append(out.Lines, d.Label+" "+d.SHA256+"  "+d.Image)
	}

	for _, leg := range planned {
		if !read[leg] {
			refusals = append(refusals, partial(fmt.Sprintf("no digest for %s %s", c.Unit, leg)))
		}
	}

	if len(refusals) > 0 {
		return nil, fmt.Errorf("release: %s subjects: %w", c.Name, errors.Join(refusals...))
	}

	return out, nil
}

// scan is Digests' work, returning the refusals unjoined and the
// count of files listed, so the subject derivation can judge the plan
// beside them and report everything at once.
func (c *RegistryClass) scan(dir string) ([]RegistryDigest, int, []error, error) {
	names, err := assetNames(dir, c.Extension)
	if err != nil {
		return nil, 0, nil, err
	}

	var (
		refusals []error
		out      []RegistryDigest
		byLeg    = map[string]string{}
	)

	for _, name := range names {
		d, rerr := c.read(dir, name)
		if rerr != nil {
			refusals = append(refusals, fmt.Errorf("%s: %w", name, rerr))

			continue
		}

		if prior, ok := byLeg[d.Label]; ok {
			refusals = append(refusals, fmt.Errorf("%s and %s both name %s %s", prior, name, c.Unit, d.Label))

			continue
		}

		byLeg[d.Label] = name
		out = append(out, d)
	}

	return out, len(names), refusals, nil
}

// read decodes one digest file in the class's form.
func (c *RegistryClass) read(dir, name string) (RegistryDigest, error) {
	path := filepath.Join(dir, name)

	if c.Form == FormBareDigest {
		raw, err := os.ReadFile(path) //nolint:gosec // G304: the digest directory is the caller's, by design
		if err != nil {
			return RegistryDigest{}, fmt.Errorf("reading: %w", err)
		}

		m := sha256DigestRE.FindStringSubmatch(strings.TrimSuffix(string(raw), "\n"))
		if m == nil {
			return RegistryDigest{}, errors.New("is not one sha256:<64 hex> digest")
		}

		return RegistryDigest{File: name, Label: strings.TrimSuffix(name, c.Extension), SHA256: m[1]}, nil
	}

	return c.readDocument(path, name)
}

// readDocument decodes one digest document. The leg's field is the
// policy's to name, so the document is read as a set of string fields
// and held to exactly the four it must carry: the signer is given what
// these say, so an absent one is refused rather than read as empty,
// and an extra one rather than ignored.
func (c *RegistryClass) readDocument(path, name string) (RegistryDigest, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the digest directory is the caller's, by design
	if err != nil {
		return RegistryDigest{}, fmt.Errorf("reading: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only close

	doc, err := jsonx.Decode[map[string]*string](f)
	if err != nil {
		return RegistryDigest{}, err
	}

	fields := []string{c.LegField, docImage, docTag, docDigest}

	for _, k := range slices.Sorted(maps.Keys(*doc)) {
		if !slices.Contains(fields, k) {
			return RegistryDigest{}, fmt.Errorf("unknown field %q", k)
		}
	}

	get := func(k string) string {
		if v := (*doc)[k]; v != nil {
			return *v
		}

		return ""
	}

	leg, image, digest := get(c.LegField), get(docImage), (*doc)[docDigest]

	switch {
	case leg == "":
		return RegistryDigest{}, fmt.Errorf("no %s", c.LegField)
	case image == "":
		return RegistryDigest{}, errors.New("no image")
	case strings.ContainsAny(image, " \t\n\\"):
		return RegistryDigest{}, fmt.Errorf("image %q carries a character a subject line cannot", image)
	case get(docTag) == "":
		return RegistryDigest{}, errors.New("no tag")
	case digest == nil:
		return RegistryDigest{}, errors.New("no digest")
	}

	m := sha256DigestRE.FindStringSubmatch(*digest)
	if m == nil {
		return RegistryDigest{}, fmt.Errorf("digest %q is not sha256:<64 hex>", *digest)
	}

	return RegistryDigest{File: name, Label: leg, SHA256: m[1], Image: image}, nil
}

// plan validates the planned entries.
func (c *RegistryClass) plan(planned []string) (map[string]bool, error) {
	if len(planned) == 0 {
		return nil, fmt.Errorf(
			"release: %s subjects: the plan names no %ss — a release that publishes nothing is not a release",
			c.Name, c.Unit,
		)
	}

	set := map[string]bool{}

	for _, entry := range planned {
		if !c.entry.MatchString(entry) {
			return nil, fmt.Errorf("release: %s subjects: %w", c.Name, mismatch(c.Unit, entry, c.entry))
		}

		if set[entry] {
			return nil, fmt.Errorf("release: %s subjects: %s %q is planned twice", c.Name, c.Unit, entry)
		}

		set[entry] = true
	}

	return set, nil
}

// Registry is a release's registry subject lines, in digest-file name
// order — the order the shell's glob read them in.
type Registry struct {
	Lines []string
}

// Bytes renders the registry subject lines.
func (r *Registry) Bytes() []byte { return joinLines(r.Lines) }
