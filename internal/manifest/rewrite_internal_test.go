// The guards that fire only when the reader itself is defective: sites
// with impossible ranges, sites that overlap. Unreachable through
// Detect on a well-formed tree by construction, which is exactly why
// they get direct table tests — a guard that fires only in degraded
// states is the least exercised code in the org.

package manifest

import (
	"strings"
	"testing"
)

func TestSpliceGuards(t *testing.T) {
	data := []byte("version = \"1.0.0\"\n")

	for _, tc := range []struct {
		name  string
		edits []edit
		match string
	}{
		{
			name:  "an offset past the file",
			edits: []edit{{site: Site{Field: "f", off: 30, end: 40}, to: "x"}},
			match: "impossible range",
		},
		{
			name:  "a negative offset",
			edits: []edit{{site: Site{Field: "f", off: -1, end: 3}, to: "x"}},
			match: "impossible range",
		},
		{
			name:  "an empty range",
			edits: []edit{{site: Site{Field: "f", off: 3, end: 3}, to: "x"}},
			match: "impossible range",
		},
		{
			name: "overlapping sites",
			edits: []edit{
				{site: Site{Field: "a", off: 2, end: 8}, to: "x"},
				{site: Site{Field: "b", off: 6, end: 12}, to: "x"},
			},
			match: "overlaps",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := splice(data, tc.edits)
			if err == nil || !strings.Contains(err.Error(), tc.match) {
				t.Fatalf("splice() error = %v, want a refusal mentioning %q", err, tc.match)
			}
		})
	}
}

func TestOffsetAtGuards(t *testing.T) {
	data := []byte("one\ntwo\n")

	for _, tc := range []struct {
		name         string
		line, column int
	}{
		{name: "a line past the file", line: 9, column: 1},
		{name: "a column past the file", line: 2, column: 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := offsetAt(data, tc.line, tc.column); err == nil {
				t.Fatalf("offsetAt(%d, %d) accepted a position outside the file", tc.line, tc.column)
			}
		})
	}
}

// verify's own guards: a rewrite whose output re-reads to a different
// mirror set, or to the wrong values, must never reach the filesystem.
// Reached by corrupting the recorded ranges after detection — the
// stand-in for a reader/splicer disagreement.
func TestVerifyRefusesABadSplice(t *testing.T) {
	files := map[string][]byte{
		cargoFile: []byte("[package]\nname = \"demo\"\nversion = \"1.0.0\"\n"),
	}

	set, err := detect(files)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}

	// Shift the recorded range so the splice lands on the wrong bytes.
	set.Sites[0].off -= 2
	set.Sites[0].end -= 2

	if _, err := set.Rewrite("2.0.0", ""); err == nil {
		t.Fatal("a splice that missed its site reached the filesystem")
	}
}
