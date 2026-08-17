package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// releaseHistory is a history that releases 1.1.0 over 1.0.0.
func releaseHistory() *stubHistory {
	return &stubHistory{
		tags:       []string{"v1.0.0"},
		commits:    []string{"a", "b"},
		commitTime: "2026-08-16T09:30:00+01:00",
		messages: map[string]string{
			"a": "feat: add a thing (#12)",
			"b": "fix: repair another (#13)",
		},
	}
}

// outcome is one invocation's result, kept together because three bare
// results in a fixed order is the shape a caller transposes.
type outcome struct {
	stdout string
	stderr string
	code   int
}

func runNotes(t *testing.T, hist deriveHistory, extra ...string) outcome {
	t.Helper()

	withHistory(t, hist, nil)

	var stdout, stderr bytes.Buffer

	args := append([]string{"notes", "--git-dir", "."}, extra...)
	code := deriveCmd(args, &stdout, &stderr)

	return outcome{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

func readFile(t *testing.T, path string) string {
	t.Helper()

	b, err := os.ReadFile(path) //nolint:gosec // a path this test just wrote
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

func TestNotesPrintsASection(t *testing.T) {
	got := runNotes(t, releaseHistory(),
		"--pull-url", "https://example.test/o/r/pull/",
		"--compare-url", "https://example.test/o/r/compare/")
	if got.code != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got.code, got.stderr)
	}

	for _, want := range []string{
		"## [1.1.0](https://example.test/o/r/compare/v1.0.0...v1.1.0) - 2026-08-16",
		"### Added",
		"- add a thing ([#12](https://example.test/o/r/pull/12))",
		"### Fixed",
		"- repair another ([#13](https://example.test/o/r/pull/13))",
	} {
		if !strings.Contains(got.stdout, want) {
			t.Errorf("stdout =\n%s\nwant it to contain %q", got.stdout, want)
		}
	}
}

// The date defaults to the committer date of the ref, never a clock: the
// same commits must render the same bytes on any day.
func TestNotesDateComesFromTheRef(t *testing.T) {
	got := runNotes(t, releaseHistory())
	if got.code != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got.code, got.stderr)
	}

	// 2026-08-16T09:30+01:00 is 2026-08-16T08:30Z — the same day here.
	if !strings.Contains(got.stdout, "- 2026-08-16") {
		t.Errorf("stdout =\n%s\nwant the ref's own commit date", got.stdout)
	}

	given := runNotes(t, releaseHistory(), "--date", "2001-01-01")
	if given.code != exitOK || !strings.Contains(given.stdout, "- 2001-01-01") {
		t.Errorf("stdout =\n%s\nwant the given date", given.stdout)
	}
}

// The committer's offset must not decide the calendar date. A commit at
// 03:30+05:00 is 22:30Z the previous day, and dating the release by the
// committer's local calendar puts it a day ahead of the world that read
// it. Taken from a real release whose published date this got wrong.
func TestNotesDateIsUTC(t *testing.T) {
	hist := releaseHistory()
	hist.commitTime = "2026-08-16T03:30:33+05:00"

	got := runNotes(t, hist)
	if got.code != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got.code, got.stderr)
	}

	if !strings.Contains(got.stdout, "- 2026-08-15") {
		t.Errorf("stdout =\n%s\nwant 2026-08-15, the UTC date of that instant", got.stdout)
	}
}

func TestNotesRefusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hist  deriveHistory
		extra []string
		match string
	}{
		{
			name: "a group pair is malformed", hist: releaseHistory(),
			extra: []string{"--groups", "featAdded"}, match: "not type=Heading",
		},
		{
			name: "a heading appears in no ordering", hist: releaseHistory(),
			extra: []string{"--groups", "feat=Added", "--group-order", "Fixed"},
			match: "appears in no ordering",
		},
		{
			name: "the ref reports no usable date",
			hist: &stubHistory{
				tags: []string{"v1.0.0"}, commits: []string{"a"},
				messages:   map[string]string{"a": "feat: a thing"},
				commitTime: "2026",
			},
			match: "no usable commit date",
		},
		{
			name: "reading the commit date fails",
			hist: &stubHistory{
				tags: []string{"v1.0.0"}, commits: []string{"a"},
				messages: map[string]string{"a": "feat: a thing"},
				timeErr:  errors.New("git said no"),
			},
			match: "git said no",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runNotes(t, tc.hist, tc.extra...)
			if got.code != exitRefused {
				t.Fatalf("deriveCmd = %d, want %d", got.code, exitRefused)
			}

			if !strings.Contains(got.stderr, tc.match) {
				t.Errorf("stderr = %q, want it to mention %q", got.stderr, tc.match)
			}
		})
	}
}

func TestNotesNothingToRelease(t *testing.T) {
	got := runNotes(t, &stubHistory{
		tags: []string{"v1.0.0"}, commits: []string{"a"},
		messages: map[string]string{"a": "chore: tidy"}, commitTime: "2026-08-16T00:00:00Z",
	})
	if got.code != exitOK {
		t.Fatalf("deriveCmd = %d", got.code)
	}

	if !strings.Contains(got.stdout, "no notes to render") || strings.Contains(got.stdout, "##") {
		t.Errorf("stdout =\n%s\nwant no section", got.stdout)
	}
}

// Splicing goes above the newest section and leaves the preamble alone.
func TestNotesSplicesIntoAChangelog(t *testing.T) {
	const preamble = "# Changelog\n\nAll notable changes are recorded here.\n\n"
	const older = "## [1.0.0](https://example.test/x) - 2026-01-01\n\n### Added\n\n- the first thing\n"

	path := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(path, []byte(preamble+older), 0o600); err != nil {
		t.Fatal(err)
	}

	got := runNotes(t, releaseHistory(), "--changelog", path)
	if got.code != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got.code, got.stderr)
	}

	if !strings.Contains(got.stdout, "wrote the 1.1.0 section") {
		t.Errorf("stdout = %q, want it to say what it wrote", got.stdout)
	}

	content := readFile(t, path)

	if !strings.HasPrefix(content, preamble) {
		t.Errorf("content =\n%s\nwant the preamble untouched", content)
	}

	// Newest first: the new section must precede the one it supersedes.
	newer := strings.Index(content, "## 1.1.0 - ")
	old := strings.Index(content, "## [1.0.0]")

	if newer < 0 || old < 0 || newer > old {
		t.Errorf("content =\n%s\nwant 1.1.0 above 1.0.0", content)
	}

	if !strings.Contains(content, "- the first thing") {
		t.Error("the older section was lost")
	}
}

// A release step is normally re-runnable. Writing a second section for
// one version would produce a changelog nobody can read, so the second
// run refuses instead of appending or overwriting.
func TestNotesSpliceIsNotRepeatable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(path, []byte("# Changelog\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if first := runNotes(t, releaseHistory(), "--changelog", path); first.code != exitOK {
		t.Fatalf("first run = %d (stderr: %s)", first.code, first.stderr)
	}

	before := readFile(t, path)

	second := runNotes(t, releaseHistory(), "--changelog", path)
	if second.code != exitRefused {
		t.Fatalf("second run = %d, want %d", second.code, exitRefused)
	}

	if !strings.Contains(second.stderr, "already carries a section for 1.1.0") {
		t.Errorf("stderr = %q, want it to name the existing section", second.stderr)
	}

	// Refused means untouched, not partially rewritten.
	if readFile(t, path) != before {
		t.Error("the refused run still modified the changelog")
	}
}

// A changelog with no sections yet gets the first one, preamble intact.
func TestNotesSpliceIntoAnEmptyChangelog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(path, []byte("# Changelog\n\nNothing yet.\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := runNotes(t, releaseHistory(), "--changelog", path); got.code != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got.code, got.stderr)
	}

	if content := readFile(t, path); !strings.HasPrefix(content, "# Changelog\n\nNothing yet.\n\n## 1.1.0 - ") {
		t.Errorf("content =\n%s\nwant the section below the preamble", content)
	}
}

// The duplicate guard matches the version as a delimited token, never a
// substring: 1.1.0 sits inside 1.1.0-rc.1 and inside 11.1.0, and a
// substring match would refuse a release the file has never seen.
func TestNotesSpliceIsNotFooledBySuperstrings(t *testing.T) {
	const decoys = "# Changelog\n\n" +
		"## [1.1.0-rc.1](https://example.test/x) - 2026-01-02\n\n- a candidate\n\n" +
		"## [11.1.0](https://example.test/y) - 2026-01-01\n\n- another component's count\n"

	path := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(path, []byte(decoys), 0o600); err != nil {
		t.Fatal(err)
	}

	got := runNotes(t, releaseHistory(), "--changelog", path)
	if got.code != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s), want the decoys ignored", got.code, got.stderr)
	}

	if !strings.Contains(readFile(t, path), "## 1.1.0 - ") {
		t.Error("the 1.1.0 section was not written")
	}
}

// An adopted changelog may head its sections with the tag spelling
// ("## [v1.1.0]"), where the leading "v" would hide the version from a
// token match. The guard checks the tag spelling too.
func TestNotesSpliceRefusesTheTagSpelling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(path, []byte("# Changelog\n\n## [v1.1.0] - 2026-01-01\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := runNotes(t, releaseHistory(), "--changelog", path)
	if got.code != exitRefused {
		t.Fatalf("deriveCmd = %d, want %d", got.code, exitRefused)
	}

	if !strings.Contains(got.stderr, "already carries a section for 1.1.0") {
		t.Errorf("stderr = %q, want the tag-spelled section named", got.stderr)
	}
}

// An empty changelog gets a section and nothing else: an invented
// leading separator would start the file with blank lines, which is
// what first-line lint rules refuse.
func TestNotesSpliceIntoAnEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if got := runNotes(t, releaseHistory(), "--changelog", path); got.code != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got.code, got.stderr)
	}

	if content := readFile(t, path); !strings.HasPrefix(content, "## 1.1.0 - ") {
		t.Errorf("content =\n%s\nwant the section on the first line", content)
	}
}

func TestNotesSpliceMissingFile(t *testing.T) {
	got := runNotes(t, releaseHistory(), "--changelog", filepath.Join(t.TempDir(), "absent.md"))
	if got.code != exitRefused {
		t.Fatalf("deriveCmd = %d, want %d", got.code, exitRefused)
	}

	if !strings.Contains(got.stderr, "reading") {
		t.Errorf("stderr = %q, want it to name the read failure", got.stderr)
	}
}

func TestParseGroups(t *testing.T) {
	groups, err := parseGroups(" feat=Added , fix=Fixed ,, ")
	if err != nil {
		t.Fatalf("parseGroups: %v", err)
	}

	if len(groups) != 2 || groups["feat"] != "Added" || groups["fix"] != "Fixed" {
		t.Errorf("parseGroups = %v", groups)
	}
}

// Two headings for one type is a configuration defect, refused like
// every duplicate on this surface — silently letting the last one win
// would bury it.
func TestParseGroupsRefusesADuplicateType(t *testing.T) {
	if _, err := parseGroups("feat=Added,fix=Fixed,feat=Changed"); err == nil ||
		!strings.Contains(err.Error(), "mapped twice") {
		t.Errorf("parseGroups = %v, want a duplicate-type refusal", err)
	}
}

func TestMentionsVersion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		line    string
		needles []string
		want    bool
	}{
		{name: "bracketed heading", line: "## [1.2.3](x) - d", needles: []string{"1.2.3"}, want: true},
		{name: "plain heading", line: "## 1.2.3 - d", needles: []string{"1.2.3"}, want: true},
		{name: "at the line's end", line: "## 1.2.3", needles: []string{"1.2.3"}, want: true},
		{name: "inside a longer patch", line: "## [1.2.30](x) - d", needles: []string{"1.2.3"}, want: false},
		{name: "inside a prerelease", line: "## [1.2.3-rc.1](x) - d", needles: []string{"1.2.3"}, want: false},
		{name: "inside a longer major", line: "## [11.2.3](x) - d", needles: []string{"1.2.3"}, want: false},
		{
			name: "tag spelling via the second needle",
			line: "## [v1.2.3] - d", needles: []string{"1.2.3", "v1.2.3"}, want: true,
		},
		{name: "absent entirely", line: "## [2.0.0](x) - d", needles: []string{"1.2.3"}, want: false},
		// The substring fails its boundary check at one offset and must
		// still be found at a later one.
		{name: "a decoy before the real one", line: "## 11.2.3 then 1.2.3", needles: []string{"1.2.3"}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mentionsVersion(tc.line, tc.needles...); got != tc.want {
				t.Errorf("mentionsVersion(%q, %v) = %t, want %t", tc.line, tc.needles, got, tc.want)
			}
		})
	}
}
