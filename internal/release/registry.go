// Registry-class subjects (stele#393, added 2026-11-17): what a release
// published to a registry rather than attached as an asset. Each
// planned leg leaves one digest document behind, and the set is the
// signer's input — so a partial set, or one carrying a leg the plan
// never asked for, is refused by name before anything is signed.

package release

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// RegistryClass is one registry class's statement of what a planned
// leg leaves behind: one digest document naming the leg, the image
// and the digest pushed.
type RegistryClass struct {
	// Name is the evidence class, as the manifest spells it.
	Name string
	// Unit is what one planned entry is called in a refusal.
	Unit string
	// Extension is the digest documents' suffix in the directory.
	Extension string
	entry     *regexp.Regexp
}

// registryClasses are the release contract's class definitions for
// the classes whose subjects live in a registry.
func registryClasses() []*RegistryClass {
	return []*RegistryClass{
		{
			Name: "pgrx-extension-image", Unit: "major", Extension: ".json",
			entry: majorRE,
		},
	}
}

// majorRE is a planned Postgres major.
var majorRE = regexp.MustCompile(`^\d+$`)

// RegistryClassNamed returns the registry class definition for name.
func RegistryClassNamed(name string) (*RegistryClass, bool) {
	for _, c := range registryClasses() {
		if c.Name == name {
			return c, true
		}
	}

	return nil, false
}

// digestDoc is the document one leg writes. Every field is required:
// the signer is given what these say, so an absent one is refused
// rather than read as empty.
type digestDoc struct {
	PG     *string `json:"pg"`
	Image  *string `json:"image"`
	Tag    *string `json:"tag"`
	Digest *string `json:"digest"`
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
			return nil, fmt.Errorf("release: %s subjects: planned %s %q is not a %s", c.Name, c.Unit, entry, c.Unit)
		}

		if set[entry] {
			return nil, fmt.Errorf("release: %s subjects: %s %q is planned twice", c.Name, c.Unit, entry)
		}

		set[entry] = true
	}

	return set, nil
}

// read decodes one digest document into its leg and its line.
//
//nolint:gocritic // unnamedResult: the leg, then its subject line
func (c *RegistryClass) read(path string) (string, string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the digest directory is the caller's, by design
	if err != nil {
		return "", "", fmt.Errorf("reading: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only close

	doc, err := jsonx.Decode[digestDoc](f)
	if err != nil {
		return "", "", err
	}

	switch {
	case doc.PG == nil || *doc.PG == "":
		return "", "", errors.New("no pg")
	case doc.Image == nil || *doc.Image == "":
		return "", "", errors.New("no image")
	case strings.ContainsAny(*doc.Image, " \t\n\\"):
		return "", "", fmt.Errorf("image %q carries a character a subject line cannot", *doc.Image)
	case doc.Tag == nil || *doc.Tag == "":
		return "", "", errors.New("no tag")
	case doc.Digest == nil:
		return "", "", errors.New("no digest")
	}

	m := sha256DigestRE.FindStringSubmatch(*doc.Digest)
	if m == nil {
		return "", "", fmt.Errorf("digest %q is not sha256:<64 hex>", *doc.Digest)
	}

	return *doc.PG, *doc.PG + " " + m[1] + "  " + *doc.Image, nil
}

// Registry is a release's registry subject lines, in digest-document
// name order — the order the shell's glob read them in.
type Registry struct {
	Lines []string
}

// Bytes renders the registry subject lines.
func (r *Registry) Bytes() []byte { return joinLines(r.Lines) }
