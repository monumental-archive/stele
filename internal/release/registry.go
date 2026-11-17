// Registry-class subjects (stele#393, added 2026-11-17): what a release
// published to a registry rather than attached as an asset. Each
// planned leg leaves one digest document behind, and the set is the
// signer's input — so a partial set, or one carrying a leg the plan
// never asked for, is refused by name before anything is signed.

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
// leg leaves behind: one digest document naming the leg, the image
// and the digest pushed. It is compiled from the class's declared
// shape (shape.go); no class is written here.
type RegistryClass struct {
	// Name is the evidence class, as the policy spells it.
	Name string
	// Unit is what one planned entry is called in a refusal.
	Unit string
	// Shape is what an entry failing the pattern is not, in a refusal.
	Shape string
	// Extension is the digest documents' suffix in the directory.
	Extension string
	// LegField is the digest document field naming its leg.
	LegField string
	entry    *regexp.Regexp
}

var sha256DigestRE = regexp.MustCompile(`^sha256:([0-9a-f]{64})$`)

// RegistrySubjects computes the registry subject lines for the digest
// documents in dir against the planned entries.
func (c *RegistryClass) RegistrySubjects(dir string, planned []string) (*Registry, error) {
	plannedSet, err := c.plan(planned)
	if err != nil {
		return nil, err
	}

	names, err := assetNames(dir, c.Extension)
	if err != nil {
		return nil, err
	}

	var (
		refusals []error
		byLeg    = map[string]string{}
		out      = &Registry{}
	)

	partial := func(detail string) error {
		return fmt.Errorf("%d image digests for %d planned %ss; refusing a partial set: %s",
			len(names), len(planned), c.Unit, detail)
	}

	for _, name := range names {
		leg, line, rerr := c.read(filepath.Join(dir, name))
		if rerr != nil {
			refusals = append(refusals, fmt.Errorf("%s: %w", name, rerr))

			continue
		}

		if !plannedSet[leg] {
			refusals = append(refusals, partial(fmt.Sprintf("%s names %s %s, which is not planned", name, c.Unit, leg)))

			continue
		}

		if prior, ok := byLeg[leg]; ok {
			refusals = append(refusals, fmt.Errorf("%s and %s both name %s %s", prior, name, c.Unit, leg))

			continue
		}

		byLeg[leg] = name
		out.Lines = append(out.Lines, line)
	}

	for _, leg := range planned {
		if _, ok := byLeg[leg]; !ok {
			refusals = append(refusals, partial(fmt.Sprintf("no digest for %s %s", c.Unit, leg)))
		}
	}

	if len(refusals) > 0 {
		return nil, fmt.Errorf("release: %s subjects: %w", c.Name, errors.Join(refusals...))
	}

	return out, nil
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
			return nil, fmt.Errorf("release: %s subjects: planned %s %q is not %s", c.Name, c.Unit, entry, c.Shape)
		}

		if set[entry] {
			return nil, fmt.Errorf("release: %s subjects: %s %q is planned twice", c.Name, c.Unit, entry)
		}

		set[entry] = true
	}

	return set, nil
}

// read decodes one digest document into its leg and its line. The
// leg's field is the policy's to name, so the document is read as a
// set of string fields and held to exactly the four it must carry:
// the signer is given what these say, so an absent one is refused
// rather than read as empty, and an extra one rather than ignored.
//
//nolint:gocritic // unnamedResult: the leg, then its subject line
func (c *RegistryClass) read(path string) (string, string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the digest directory is the caller's, by design
	if err != nil {
		return "", "", fmt.Errorf("reading: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only close

	doc, err := jsonx.Decode[map[string]*string](f)
	if err != nil {
		return "", "", err
	}

	fields := []string{c.LegField, docImage, docTag, docDigest}

	for _, k := range slices.Sorted(maps.Keys(*doc)) {
		if !slices.Contains(fields, k) {
			return "", "", fmt.Errorf("unknown field %q", k)
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
		return "", "", fmt.Errorf("no %s", c.LegField)
	case image == "":
		return "", "", errors.New("no image")
	case strings.ContainsAny(image, " \t\n\\"):
		return "", "", fmt.Errorf("image %q carries a character a subject line cannot", image)
	case get(docTag) == "":
		return "", "", errors.New("no tag")
	case digest == nil:
		return "", "", errors.New("no digest")
	}

	m := sha256DigestRE.FindStringSubmatch(*digest)
	if m == nil {
		return "", "", fmt.Errorf("digest %q is not sha256:<64 hex>", *digest)
	}

	return leg, leg + " " + m[1] + "  " + image, nil
}

// Registry is a release's registry subject lines, in digest-document
// name order — the order the shell's glob read them in.
type Registry struct {
	Lines []string
}

// Bytes renders the registry subject lines.
func (r *Registry) Bytes() []byte { return joinLines(r.Lines) }
