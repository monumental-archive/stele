package derive_test

import (
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/derive"
)

// The conventions measured in the corpus: the canon's cliff.toml groups,
// GitHub's URL shapes.
func testNotes(t *testing.T) *derive.Notes {
	t.Helper()

	n, err := derive.NewNotes(&derive.NotesOptions{
		Groups: map[string]string{
			"feat": "Added",
			"fix":  "Fixed",
			"docs": "Documentation",
			"perf": "Changed",
		},
		Order:         []string{"Breaking", "Added", "Changed", "Fixed", "Documentation"},
		BreakingGroup: "Breaking",
		CompareURL:    "https://example.test/o/r/compare/",
		ReleaseURL:    "https://example.test/o/r/releases/tag/",
		PullURL:       "https://example.test/o/r/pull/",
	})
	if err != nil {
		t.Fatalf("NewNotes: %v", err)
	}

	return &n
}

func TestNewNotesRefuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts derive.NotesOptions
	}{
		{name: "empty heading in the ordering", opts: derive.NotesOptions{Order: []string{""}}},
		{
			name: "heading ordered twice",
			opts: derive.NotesOptions{Order: []string{"Added", "Added"}},
		},
		// Refused rather than appended last: silently ordering it is a
		// decision nobody made, and it would move on the next addition.
		{
			name: "a heading appears in no ordering",
			opts: derive.NotesOptions{Groups: map[string]string{"feat": "Added"}, Order: []string{"Fixed"}},
		},
		{
			name: "the breaking heading appears in no ordering",
			opts: derive.NotesOptions{Order: []string{"Added"}, BreakingGroup: "Breaking"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := derive.NewNotes(&tc.opts); err == nil {
				t.Fatal("NewNotes accepted conventions it cannot render deterministically")
			}
		})
	}
}

// An empty heading in Groups is DECLARED silence, not a configuration
// defect: it silences exactly its key while the bare-type fallback still
// applies to every other scope. Each row breaks one fact about that
// contract.
func TestDeclaredSilence(t *testing.T) {
	notes, err := derive.NewNotes(&derive.NotesOptions{
		Groups: map[string]string{
			"chore":        "Miscellaneous",
			"chore(canon)": "", // declared silence for exactly this scope
			"fix":          "Fixed",
		},
		Order:         []string{"Breaking", "Fixed", "Miscellaneous"},
		BreakingGroup: "Breaking",
	})
	if err != nil {
		t.Fatalf("NewNotes refused declared silence: %v", err)
	}

	got, err := notes.Render(derive.Release{
		Version: mustVersion(t, "1.1.0"),
		Date:    "2026-08-18",
	}, parseAll(t,
		"chore(canon): bump the canon pin",
		"chore(deps): bump a dependency",
		"chore: tidy the taskfile",
		"chore(canon)!: retire the v2 note format",
		"fix: close the right file",
	))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	for _, tc := range []struct {
		name, needle string
		want         bool
	}{
		{name: "the silenced scope writes no entry", needle: "bump the canon pin", want: false},
		{name: "an unlisted scope falls back to the bare type", needle: "- bump a dependency", want: true},
		{name: "the bare type keeps its heading", needle: "- tidy the taskfile", want: true},
		{name: "a break in the silenced scope still surfaces", needle: "- retire the v2 note format", want: true},
		{name: "other types are untouched", needle: "- close the right file", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(got, tc.needle) != tc.want {
				t.Errorf("Render() contains %q = %v, want %v\n%s", tc.needle, !tc.want, tc.want, got)
			}
		})
	}
}

func TestRenderRefuses(t *testing.T) {
	t.Run("conventions not built by NewNotes", func(t *testing.T) {
		var zero derive.Notes

		if _, err := zero.Render(derive.Release{Version: mustVersion(t, "1.0.0")}, nil); err == nil {
			t.Fatal("a zero Notes rendered")
		}
	})

	t.Run("no version", func(t *testing.T) {
		if _, err := testNotes(t).Render(derive.Release{}, nil); err == nil {
			t.Fatal("rendered notes for no version")
		}
	})
}

// The shape the corpus renders, reproduced from commits alone.
func TestRenderSection(t *testing.T) {
	got, err := testNotes(t).Render(derive.Release{
		Version:   mustVersion(t, "1.29.1"),
		Previous:  mustVersion(t, "1.29.0"),
		TagPrefix: "v",
		Date:      "2026-08-15",
	}, parseAll(t,
		"feat: lint gate stubs for trigger closure (#432)",
		"fix: read the trusted root without a pipeline (#438)",
		"docs: document the ledger-fork heal path (#435)",
		"chore: tidy up (#400)",
	))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	want := "## [1.29.1](https://example.test/o/r/compare/v1.29.0...v1.29.1) - 2026-08-15\n" +
		"\n### Added\n\n" +
		"- lint gate stubs for trigger closure ([#432](https://example.test/o/r/pull/432))\n" +
		"\n### Fixed\n\n" +
		"- read the trusted root without a pipeline ([#438](https://example.test/o/r/pull/438))\n" +
		"\n### Documentation\n\n" +
		"- document the ledger-fork heal path ([#435](https://example.test/o/r/pull/435))\n"

	if got != want {
		t.Errorf("Render() =\n%q\nwant\n%q", got, want)
	}

	// A silent type contributes no entry, and its heading never appears.
	if strings.Contains(got, "tidy up") {
		t.Error("a chore reached the changelog")
	}
}

// A break rendered identically to a feature loses the one fact a reader
// most needs, so it is lifted out of its type's group.
func TestRenderLiftsBreakingChanges(t *testing.T) {
	got, err := testNotes(t).Render(derive.Release{
		Version:   mustVersion(t, "2.0.0"),
		Previous:  mustVersion(t, "1.9.0"),
		TagPrefix: "v",
		Date:      "2026-08-16",
	}, parseAll(t,
		"feat: an ordinary feature",
		"feat!: a breaking feature",
		"docs: a note\n\nBREAKING CHANGE: even a silent type can break",
	))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	// Breaking is ordered first, so it precedes Added.
	breaking := strings.Index(got, "### Breaking")
	added := strings.Index(got, "### Added")

	if breaking < 0 || added < 0 || breaking > added {
		t.Fatalf("Render() =\n%s\nwant Breaking before Added", got)
	}

	for _, want := range []string{"- a breaking feature", "- even a silent type can break", "- an ordinary feature"} {
		if !strings.Contains(got, want) {
			t.Errorf("Render() =\n%s\nwant it to contain %q", got, want)
		}
	}

	// The breaking feature was lifted OUT of Added, not copied into both.
	if strings.Count(got, "a breaking feature") != 1 {
		t.Error("a breaking change rendered in two groups")
	}
}

func TestRenderFirstRelease(t *testing.T) {
	got, err := testNotes(t).Render(derive.Release{
		Version:   mustVersion(t, "0.1.0"),
		TagPrefix: "v",
		Date:      "2026-08-16",
	}, parseAll(t, "feat: the first thing"))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	// Nothing to compare against, so the heading links the release.
	if !strings.HasPrefix(got, "## [0.1.0](https://example.test/o/r/releases/tag/v0.1.0) - 2026-08-16\n") {
		t.Errorf("Render() =\n%s\nwant a release link, not a compare link", got)
	}
}

// Every link is optional: an unconfigured prefix renders plain text
// rather than a broken href.
func TestRenderWithoutLinks(t *testing.T) {
	n, err := derive.NewNotes(&derive.NotesOptions{
		Groups: map[string]string{"fix": "Fixed"},
		Order:  []string{"Fixed"},
	})
	if err != nil {
		t.Fatalf("NewNotes: %v", err)
	}

	got, err := n.Render(derive.Release{
		Version:   mustVersion(t, "1.0.1"),
		Previous:  mustVersion(t, "1.0.0"),
		TagPrefix: "v",
		Date:      "2026-08-16",
	}, parseAll(t, "fix: repair it (#7)", "fix: repair another thing"))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	want := "## 1.0.1 - 2026-08-16\n\n### Fixed\n\n- repair it (#7)\n- repair another thing\n"
	if got != want {
		t.Errorf("Render() =\n%q\nwant\n%q", got, want)
	}
}

// Rendering must not depend on map iteration: Go randomises it, and a
// changelog whose sections shuffle between runs cannot be diffed or
// reproduced. Rendering the same input repeatedly is how that shows.
func TestRenderIsDeterministic(t *testing.T) {
	n := testNotes(t)
	rel := derive.Release{
		Version:   mustVersion(t, "1.1.0"),
		Previous:  mustVersion(t, "1.0.0"),
		TagPrefix: "v",
		Date:      "2026-08-16",
	}
	commits := parseAll(t,
		"feat: one", "fix: two", "docs: three", "perf: four", "feat!: five",
	)

	first, err := n.Render(rel, commits)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	for range 24 {
		again, renderErr := n.Render(rel, commits)
		if renderErr != nil {
			t.Fatalf("Render: %v", renderErr)
		}

		if again != first {
			t.Fatalf("Render() is not deterministic:\n%s\nvs\n%s", first, again)
		}
	}
}

func TestRenderNoEntries(t *testing.T) {
	got, err := testNotes(t).Render(derive.Release{
		Version:   semver.New(1, 0, 1, "", ""),
		Previous:  semver.New(1, 0, 0, "", ""),
		TagPrefix: "v",
		Date:      "2026-08-16",
	}, parseAll(t, "chore: tidy"))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	// The heading still renders — the release happened — but no empty
	// section is invented beneath it.
	if strings.Contains(got, "###") {
		t.Errorf("Render() =\n%s\nwant no section headings", got)
	}
}

// TestRenderScopedGroups: a scoped key wins over the bare type, so
// dependency bumps carry a heading while bare chores (release
// commits, pin bumps) stay out of the notes — the split type-only
// grouping cannot express.
func TestRenderScopedGroups(t *testing.T) {
	n, err := derive.NewNotes(&derive.NotesOptions{
		Groups: map[string]string{
			"feat":        "Added",
			"chore(deps)": "Dependencies",
		},
		Order:         []string{"Breaking", "Added", "Dependencies"},
		BreakingGroup: "Breaking",
		CompareURL:    "https://example.test/o/r/compare/",
		ReleaseURL:    "https://example.test/o/r/releases/tag/",
		PullURL:       "https://example.test/o/r/pull/",
	})
	if err != nil {
		t.Fatalf("NewNotes: %v", err)
	}

	got, err := n.Render(derive.Release{
		Version:   mustVersion(t, "1.1.0"),
		Previous:  mustVersion(t, "1.0.0"),
		TagPrefix: "v",
		Date:      "2026-08-18",
	}, parseAll(t,
		"feat: add the widget (#1)",
		"chore(deps): update example to v2 (#2)",
		"chore: release v1.1.0 (#3)",
		"chore(canon): bump the self-pin (#4)",
	))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	if !strings.Contains(got, "### Dependencies") || !strings.Contains(got, "update example to v2") {
		t.Fatalf("notes lack the scoped dependencies entry:\n%s", got)
	}

	for _, silent := range []string{"release v1.1.0", "bump the self-pin"} {
		if strings.Contains(got, silent) {
			t.Fatalf("unmapped chore %q reached the changelog:\n%s", silent, got)
		}
	}
}
