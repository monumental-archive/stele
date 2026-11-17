// The subject manifest: which digests a release's provenance names
// (stele#393). A build class's matrix plans a list of legs; each leg
// produces a fixed set of assets; the manifest is those assets'
// digests, once flat and once grouped by the leg that built them.
//
// It was three copies of one shell block in the canon's build
// workflows plus a fourth for registry images, each deciding what gets
// signed and none tested. What a planned leg PRODUCES is a release
// contract fact, declared on the class's assert-policy entry
// (stele#442, shape.go) and nowhere else: no caller passes a name
// pattern, and no code spells one.
//
// The byte format is the one the canon's signing and attach steps
// already read — `sha256sum`'s two-space line for a subject, the same
// line prefixed with the leg's label for a leg subject — so the swap
// changes who computes the lines and nothing about what they say.

package release

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// AssetClass is one build class's statement of what a planned leg
// produces. The planned entry is the matrix's own spelling of a leg —
// whatever the class's declared entry pattern accepts — and leg turns
// it into the assets that leg must have left behind.
type AssetClass struct {
	// Name is the evidence class, as the policy spells it.
	Name string
	// Unit is what one planned entry is called in a refusal.
	Unit string
	// Kind is what one asset is called in a refusal.
	Kind string
	// Extension is the suffix every asset of the class carries; a
	// file with it that no leg claims is unplanned.
	Extension string
	leg       func(entry string) (Leg, error)
}

// Leg is one planned entry and the assets it must produce.
type Leg struct {
	// Entry is the planned entry as the plan spelled it.
	Entry string
	// Label prefixes this leg's lines in the leg-grouped manifest:
	// the grain the manifest's `--leg-subjects` reads back.
	Label string
	// Assets are the expected assets, in the order the leg's lines
	// are written.
	Assets []Expected
}

// Expected is one asset a leg must produce exactly once.
type Expected struct {
	// Kind and Of name it in a refusal: "expected exactly one <Kind>
	// for <Of>".
	Kind, Of string
	// Suffix is what the asset's name ends with. Any non-empty,
	// non-hidden stem before it is the release's own naming.
	Suffix string
}

// Subject is one digest line: the asset's sha256 and its name.
type Subject struct {
	Digest string
	Name   string
}

// line renders the sha256sum line the canon reads.
func (s Subject) line() string { return s.Digest + "  " + s.Name }

// LegSubject is a subject with the label of the leg that built it.
type LegSubject struct {
	Subject

	Label string
}

// Manifest is a build's subjects, flat and by leg.
type Manifest struct {
	// Subjects are every asset in name order — the order the shell's
	// glob listed them in, under the runner's C.UTF-8 collation.
	Subjects []Subject
	// Legs are the same subjects in plan order, each leg's assets in
	// the class's order.
	Legs []LegSubject
}

// SubjectLines renders the flat subject lines.
func (m *Manifest) SubjectLines() []byte {
	lines := make([]string, 0, len(m.Subjects))
	for _, s := range m.Subjects {
		lines = append(lines, s.line())
	}

	return joinLines(lines)
}

// LegLines renders the leg-grouped lines.
func (m *Manifest) LegLines() []byte {
	lines := make([]string, 0, len(m.Legs))
	for _, s := range m.Legs {
		lines = append(lines, s.Label+" "+s.line())
	}

	return joinLines(lines)
}

// joinLines is `printf '%s\n'` over the lines.
func joinLines(lines []string) []byte {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}

	return []byte(b.String())
}

// Subjects computes the manifest for the assets in dir against the
// planned entries. Every planned asset must be present exactly once
// and every file carrying the class's extension must be planned; each
// refusal names the asset, and all of them are reported together.
func (c *AssetClass) Subjects(dir string, planned []string) (*Manifest, error) {
	legs, err := c.legs(planned)
	if err != nil {
		return nil, err
	}

	names, err := assetNames(dir, c.Extension)
	if err != nil {
		return nil, err
	}

	var (
		refusals []error
		claimed  = map[string]string{}
		chosen   = make([][]string, len(legs))
		perLeg   = len(legs[0].Assets)
	)

	for i, leg := range legs {
		for _, want := range leg.Assets {
			found := matching(names, want.Suffix)
			if len(found) != 1 {
				refusals = append(refusals, missingOrTwo(want, found))

				// Named already, as this leg's doubles: reporting them
				// again as unplanned would say the plan never asked.
				for _, name := range found {
					claimed[name] = leg.Entry
				}

				continue
			}

			if prior, ok := claimed[found[0]]; ok {
				refusals = append(refusals, fmt.Errorf(
					"%s is claimed by both %s and %s", found[0], prior, leg.Entry,
				))

				continue
			}

			claimed[found[0]] = leg.Entry
			chosen[i] = append(chosen[i], found[0])
		}
	}

	for _, name := range names {
		if _, ok := claimed[name]; !ok {
			refusals = append(refusals, fmt.Errorf(
				"unplanned %s %s: %d %ss for %d planned %ss%s",
				c.Kind, name, len(names), c.Kind, len(legs), c.Unit, each(perLeg),
			))
		}
	}

	if len(refusals) > 0 {
		return nil, fmt.Errorf("release: %s subjects: %w", c.Name, errors.Join(refusals...))
	}

	return digestAll(dir, names, legs, chosen)
}

// legs parses the plan, refusing an empty or repeated one.
func (c *AssetClass) legs(planned []string) ([]Leg, error) {
	if len(planned) == 0 {
		return nil, fmt.Errorf(
			"release: %s subjects: the plan names no %ss — a release that builds nothing is not a release",
			c.Name, c.Unit,
		)
	}

	seen := map[string]bool{}
	legs := make([]Leg, 0, len(planned))

	for _, entry := range planned {
		if seen[entry] {
			return nil, fmt.Errorf("release: %s subjects: %s %q is planned twice", c.Name, c.Unit, entry)
		}

		seen[entry] = true

		leg, err := c.leg(entry)
		if err != nil {
			return nil, fmt.Errorf("release: %s subjects: %w", c.Name, err)
		}

		legs = append(legs, leg)
	}

	return legs, nil
}

func each(n int) string {
	if n > 1 {
		return fmt.Sprintf(" (%d each)", n)
	}

	return ""
}

func missingOrTwo(want Expected, found []string) error {
	msg := fmt.Sprintf("expected exactly one %s for %s (*%s), found %d", want.Kind, want.Of, want.Suffix, len(found))
	if len(found) > 0 {
		msg += ": " + strings.Join(found, ", ")
	}

	return errors.New(msg)
}

// matching returns the names a `*<suffix>` glob would match: a
// non-empty stem is not required by the glob, so neither is it here.
func matching(names []string, suffix string) []string {
	var out []string

	for _, n := range names {
		if strings.HasSuffix(n, suffix) {
			out = append(out, n)
		}
	}

	return out
}

// assetNames lists the files in dir carrying ext, in byte order —
// what `./*<ext>` expands to under C.UTF-8. Hidden names are not
// listed, as the glob does not list them. A name sha256sum would
// escape, or an entry that is not a regular file, is refused: either
// would put a line in the manifest that names something else.
func assetNames(dir, ext string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("release: reading the asset directory: %w", err)
	}

	var names []string

	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ext) {
			continue
		}

		if strings.ContainsAny(name, "\\\n") {
			return nil, fmt.Errorf("release: asset %q carries a character a subject line cannot", name)
		}

		info, serr := os.Stat(filepath.Join(dir, name))
		if serr != nil {
			return nil, fmt.Errorf("release: reading asset %s: %w", name, serr)
		}

		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("release: asset %s is not a regular file", name)
		}

		names = append(names, name)
	}

	sort.Strings(names)

	return names, nil
}

func digestAll(dir string, names []string, legs []Leg, chosen [][]string) (*Manifest, error) {
	digests := make(map[string]string, len(names))
	m := &Manifest{Subjects: make([]Subject, 0, len(names))}

	for _, name := range names {
		d, err := FileDigest(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}

		digests[name] = d
		m.Subjects = append(m.Subjects, Subject{Digest: d, Name: name})
	}

	for i, leg := range legs {
		for _, name := range chosen[i] {
			m.Legs = append(m.Legs, LegSubject{Subject{Digest: digests[name], Name: name}, leg.Label})
		}
	}

	return m, nil
}

// FileDigest is the sha256 of one file's bytes, hex-encoded: the
// digest a `sha256sum` line carries, defined once for every leg that
// hashes an asset.
func FileDigest(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the asset directory is the caller's, by design
	if err != nil {
		return "", fmt.Errorf("release: hashing %s: %w", filepath.Base(path), err)
	}
	defer f.Close() //nolint:errcheck // read-only close

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("release: hashing %s: %w", filepath.Base(path), err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
