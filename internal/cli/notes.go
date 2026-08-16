// `derive notes`: the changelog section for the release the same history
// would cut. Shares the version derivation rather than re-deciding it —
// notes that describe a different release than the one being cut is the
// defect two independent readings would eventually produce.

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/monumental-archive/stele/internal/derive"
)

// deriveNotes is the second derivation mode.
const deriveNotes = "notes"

// A changelog section heading, and the length of an ISO 8601 date.
const sectionMarker = "## "

// notesArgs is everything `derive notes` reads beyond the version flags.
type notesArgs struct {
	groups     string
	order      string
	breaking   string
	compareURL string
	releaseURL string
	pullURL    string
	date       string
	changelog  string
}

// parseGroups reads "type=Heading,type=Heading".
func parseGroups(s string) (map[string]string, error) {
	groups := make(map[string]string)

	for pair := range strings.SplitSeq(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		typ, heading, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("derive notes: %q is not type=Heading", pair)
		}

		groups[strings.TrimSpace(typ)] = strings.TrimSpace(heading)
	}

	return groups, nil
}

// runDeriveNotes derives the release, renders its section, and either
// prints it or splices it into a changelog.
func runDeriveNotes(da *deriveArgs, na *notesArgs, out *latch) error {
	groups, err := parseGroups(na.groups)
	if err != nil {
		return err
	}

	notes, err := derive.NewNotes(&derive.NotesOptions{
		Groups:        groups,
		Order:         splitTypes(na.order),
		BreakingGroup: na.breaking,
		CompareURL:    na.compareURL,
		ReleaseURL:    na.releaseURL,
		PullURL:       na.pullURL,
	})
	if err != nil {
		return err
	}

	d, err := deriveRelease(da, out)
	if err != nil {
		return err
	}

	next, releases := d.decision.Next()
	if !releases {
		out.logf("nothing to release; no notes to render")

		return nil
	}

	date := na.date
	if date == "" {
		// The ref's own committer date, never a wall clock: a renderer
		// that reads the time renders a different document every run, and
		// the release date IS the date of what is being released.
		date, err = d.date()
		if err != nil {
			return err
		}
	}

	section, err := notes.Render(derive.Release{
		Version:   next,
		Previous:  d.base.Version,
		TagPrefix: da.prefix,
		Date:      date,
	}, d.commits)
	if err != nil {
		return err
	}

	if na.changelog == "" {
		out.logf("%s", strings.TrimRight(section, "\n"))

		return nil
	}

	return splice(na.changelog, section, next.String(), out)
}

// splice inserts the section above the newest one already in the file.
//
// Above the FIRST "## " heading, wherever that is: a Keep a Changelog
// file is a preamble followed by sections in descending version order,
// so the newest section's position is the only one that does not depend
// on parsing the preamble or understanding what it says. A file with no
// sections yet gets the first one appended, preamble untouched.
func splice(path, section, version string, out *latch) error {
	existing, err := os.ReadFile(path) //nolint:gosec // a path the operator named
	if err != nil {
		return fmt.Errorf("derive notes: reading %s: %w", path, err)
	}

	// Refused, not overwritten and not appended twice. A changelog with
	// two sections for one version cannot be read, and re-running a
	// release step is normal — so this must be safe to repeat, not
	// destructive on the second run.
	for line := range strings.Lines(string(existing)) {
		if strings.HasPrefix(line, sectionMarker) && strings.Contains(line, version) {
			return fmt.Errorf("derive notes: %s already carries a section for %s", path, version)
		}
	}

	at := cutAtFirstSection(string(existing))

	var b strings.Builder

	b.WriteString(strings.TrimRight(at.before, "\n"))
	b.WriteString("\n\n")
	b.WriteString(strings.TrimRight(section, "\n"))
	b.WriteString("\n")

	if at.found {
		b.WriteString("\n")
		b.WriteString(at.sections)
	}

	if err := os.WriteFile(path, []byte(b.String()), ownerRW); err != nil {
		return fmt.Errorf("derive notes: writing %s: %w", path, err)
	}

	out.logf("wrote the %s section to %s", version, path)

	return nil
}

// split is a changelog cut in two at its newest section heading.
// Both halves are strings in a fixed order, which is the pair a caller
// transposes without the compiler noticing.
type split struct {
	before   string
	sections string
	found    bool
}

// cutAtFirstSection splits a changelog at its newest section heading.
func cutAtFirstSection(content string) split {
	idx := 0

	for line := range strings.Lines(content) {
		if strings.HasPrefix(line, sectionMarker) {
			return split{before: content[:idx], sections: content[idx:], found: true}
		}

		idx += len(line)
	}

	return split{before: content}
}
