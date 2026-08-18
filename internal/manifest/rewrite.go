// The rewrite: splice every site to the next version, re-read the
// result through the same reader that found the sites, and only then
// touch the filesystem. The re-read is the verification — the splicer
// is never trusted to check its own work (share the definition, never
// share the derivation).

package manifest

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sort"
)

// ownerRW matches the permissions a checkout gives the files this
// package rewrites.
const ownerRW = 0o644

// Rewrite sets every version site to next and the citation date site,
// when there is one, to date. Nothing is written unless every file's
// rewritten bytes re-read to exactly the expected sites and values.
//
// Idempotent by construction: sites already carrying next splice to the
// same bytes, so re-running a release step rewrites nothing and refuses
// nothing — safe to repeat, not destructive on the second run.
func (s *Set) Rewrite(next, date string) ([]string, error) {
	rewritten := make(map[string][]byte, len(s.files))
	maps.Copy(rewritten, s.files)

	perFile := make(map[string][]edit)

	for _, site := range s.Sites {
		perFile[site.Path] = append(perFile[site.Path], edit{site: site, to: next})
	}

	if s.DateSite != nil {
		perFile[s.DateSite.Path] = append(perFile[s.DateSite.Path], edit{site: *s.DateSite, to: date})
	}

	changed := make([]string, 0, len(perFile))

	for path, edits := range perFile {
		out, err := splice(rewritten[path], edits)
		if err != nil {
			return nil, fmt.Errorf("manifest: %s: %w", path, err)
		}

		rewritten[path] = out

		changed = append(changed, path)
	}

	if err := s.verify(rewritten, next, date); err != nil {
		return nil, err
	}

	for _, path := range changed {
		if err := os.WriteFile(s.rooted(path), rewritten[path], ownerRW); err != nil {
			return nil, fmt.Errorf("manifest: writing %s: %w", path, err)
		}
	}

	sort.Strings(changed)

	return changed, nil
}

// verify re-reads the rewritten bytes through the shared reader and
// holds the result against what the rewrite claims: the same sites, in
// the same places by field, every version now next, the date now date.
// A site that vanished, appeared, or carries anything else means the
// splice — not the reader — got something wrong, and nothing reaches
// the filesystem.
func (s *Set) verify(rewritten map[string][]byte, next, date string) error {
	after, err := detect(rewritten)
	if err != nil {
		return fmt.Errorf(
			"manifest: the rewritten tree no longer parses, which a rewrite cannot have been meant to do: %w", err)
	}

	if len(after.Sites) != len(s.Sites) {
		return fmt.Errorf("manifest: the rewrite changed the mirror set itself: %d site(s) before, %d after",
			len(s.Sites), len(after.Sites))
	}

	for i, site := range after.Sites {
		if site.Path != s.Sites[i].Path || site.Field != s.Sites[i].Field {
			return fmt.Errorf("manifest: the rewrite changed the mirror set itself: %s %s became %s %s",
				s.Sites[i].Path, s.Sites[i].Field, site.Path, site.Field)
		}

		if site.Value != next {
			return fmt.Errorf("manifest: %s %s reads back %q, not %q", site.Path, site.Field, site.Value, next)
		}
	}

	if s.DateSite != nil {
		if after.DateSite == nil {
			return fmt.Errorf("manifest: the rewrite lost %s date-released", s.DateSite.Path)
		}

		if after.DateSite.Value != date {
			return fmt.Errorf("manifest: %s date-released reads back %q, not %q", s.DateSite.Path, after.DateSite.Value, date)
		}
	}

	return nil
}

// edit is one splice: a site and the text that replaces its value.
type edit struct {
	site Site
	to   string
}

// splice applies edits to one file, back to front so earlier offsets
// stay valid, refusing overlap outright — overlapping sites mean the
// reader located two values in the same bytes, which is a reader defect
// this function must surface, not paper over.
func splice(data []byte, edits []edit) ([]byte, error) {
	sort.Slice(edits, func(i, j int) bool { return edits[i].site.off > edits[j].site.off })

	prev := len(data) + 1

	out := data

	for _, e := range edits {
		site := e.site
		if site.off < 0 || site.end > len(data) || site.off >= site.end {
			return nil, fmt.Errorf("%s site has an impossible range [%d,%d)", site.Field, site.off, site.end)
		}

		if site.end > prev {
			return nil, fmt.Errorf("%s site overlaps another rewrite", site.Field)
		}

		prev = site.off

		value := e.to
		if site.quoted {
			value = `"` + value + `"`
		}

		out = append(out[:site.off:site.off], append([]byte(value), out[site.end:]...)...)
	}

	return out, nil
}

// rooted resolves a relative manifest path against the tree root.
func (s *Set) rooted(path string) string {
	if s.root == "" {
		return path
	}

	return filepath.Join(s.root, path)
}
