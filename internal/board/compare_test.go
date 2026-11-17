// The board measured against the board published (stele#418): every
// kind of drift, both directions, and the seeding that makes the
// comparison judge against what was published.

package board_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/board"
	"github.com/monumental-archive/stele/internal/level"
)

// writeDoc places one file of a board by path, for states the engine
// would never write itself.
func writeDoc(t *testing.T, path, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// shieldOf is a measured shield carrying message.
func shieldOf(message string) string {
	return `{"schemaVersion":1,"label":"SLSA Source","message":"` + message + `","color":"brightgreen"}` + "\n"
}

// TestCompare: one row per kind of drift, and the identical boards
// that drift nowhere.
func TestCompare(t *testing.T) {
	t.Parallel()

	widget := cell()
	retired := board.Cell{Repo: "retired", Track: level.TrackBuild}

	for _, tt := range []struct {
		name      string
		measured  map[string]string
		published map[string]string
		want      []string
	}{
		{
			name:      "identical boards",
			measured:  map[string]string{paths("", widget).shield: shieldOf("L1")},
			published: map[string]string{paths("", widget).shield: shieldOf("L1")},
		},
		{
			name:     "a measured cell never published",
			measured: map[string]string{paths("", widget).shield: shieldOf("L1")},
			want:     []string{"widget source: measured, never published"},
		},
		{
			name:      "a differing cell names both messages",
			measured:  map[string]string{paths("", widget).shield: shieldOf("L2")},
			published: map[string]string{paths("", widget).shield: shieldOf("L1")},
			want:      []string{"widget source: published L1, measured L2"},
		},
		{
			name:      "a differing cell whose published shield will not read",
			measured:  map[string]string{paths("", widget).shield: shieldOf("L2")},
			published: map[string]string{paths("", widget).shield: "not a shield"},
			want:      []string{"widget source: published an unreadable shield, measured L2"},
		},
		{
			name:      "a published cell outside the population",
			published: map[string]string{paths("", retired).shield: shieldOf("L1")},
			want:      []string{"retired build: published, outside the declared population"},
		},
		{
			// Reports carry the moment they were sealed; two honest runs
			// differ there, so they are never compared.
			name: "reports that differ are not drift",
			measured: map[string]string{
				paths("", widget).shield: shieldOf("L1"), paths("", widget).report: "{}",
			},
			published: map[string]string{
				paths("", widget).shield: shieldOf("L1"), paths("", widget).report: `{"x":1}`,
			},
		},
		{
			name:      "a track this release does not judge is not a cell to compare",
			published: map[string]string{filepath.Join("widget", "future.shield.json"): shieldOf("L1")},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, p := t.TempDir(), t.TempDir()
			for rel, content := range tt.measured {
				writeDoc(t, filepath.Join(m, rel), content)
			}

			for rel, content := range tt.published {
				writeDoc(t, filepath.Join(p, rel), content)
			}

			drift, err := board.Board{Dir: m}.Compare(board.Board{Dir: p})
			if err != nil {
				t.Fatalf("Compare = %v", err)
			}

			got := make([]string, 0, len(drift))
			for _, d := range drift {
				got = append(got, d.String())
			}

			if !slices.Equal(got, tt.want) {
				t.Fatalf("drift = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestCompareRefusals: a board the comparison cannot read refuses,
// rather than reading as one that holds nothing.
func TestCompareRefusals(t *testing.T) {
	t.Parallel()

	widget := cell()

	for _, tt := range []struct {
		name    string
		arrange func(t *testing.T, m, p string) (string, string)
		want    string
	}{
		{
			name: "the measured board is not a directory",
			arrange: func(t *testing.T, m, p string) (string, string) {
				t.Helper()

				f := filepath.Join(m, "file")
				writeDoc(t, f, "")

				return f, p
			},
			want: "board: reading",
		},
		{
			name: "the published board is not a directory",
			arrange: func(t *testing.T, m, p string) (string, string) {
				t.Helper()

				f := filepath.Join(p, "file")
				writeDoc(t, f, "")

				return m, f
			},
			want: "board: reading",
		},
		{
			name: "the measured shield cannot be read",
			arrange: func(t *testing.T, m, p string) (string, string) {
				t.Helper()

				writeDoc(t, filepath.Join(p, paths("", widget).shield), shieldOf("L1"))

				// A directory where the shield's file would be: listed
				// as a cell, unreadable as one.
				if err := os.MkdirAll(filepath.Join(m, paths("", widget).shield), 0o750); err != nil {
					t.Fatal(err)
				}

				return m, p
			},
			want: "board: reading widget source",
		},
		{
			name: "the published shield cannot be read",
			arrange: func(t *testing.T, m, p string) (string, string) {
				t.Helper()

				writeDoc(t, filepath.Join(m, paths("", widget).shield), shieldOf("L1"))

				if err := os.MkdirAll(filepath.Join(p, paths("", widget).shield), 0o750); err != nil {
					t.Fatal(err)
				}

				return m, p
			},
			want: "board: reading published widget source",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, p := tt.arrange(t, t.TempDir(), t.TempDir())

			if _, err := (board.Board{Dir: m}).Compare(board.Board{Dir: p}); err == nil ||
				!strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Compare = %v, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestSeed: the measured board starts as exactly what was published —
// each cell's documents as they stand, nothing the layout does not
// name — and a board that already holds anything is refused.
func TestSeed(t *testing.T) {
	t.Parallel()

	widget := cell()
	build := board.Cell{Repo: "widget", Track: level.TrackBuild}

	p := t.TempDir()
	writeDoc(t, filepath.Join(p, paths("", widget).shield), shieldOf("L3"))
	writeDoc(t, filepath.Join(p, paths("", widget).report), `{"report":1}`)
	writeDoc(t, filepath.Join(p, paths("", build).shield), shieldOf("L1"))
	writeDoc(t, filepath.Join(p, "widget", "future.shield.json"), "{}")
	writeDoc(t, filepath.Join(p, "README.md"), "not a cell")

	m := filepath.Join(t.TempDir(), "measured")

	if err := (board.Board{Dir: m}).Seed(board.Board{Dir: p}); err != nil {
		t.Fatalf("Seed = %v", err)
	}

	for _, rel := range []string{paths("", widget).shield, paths("", widget).report, paths("", build).shield} {
		if got, want := read(t, filepath.Join(m, rel)), read(t, filepath.Join(p, rel)); got != want {
			t.Errorf("%s = %q, want the published %q", rel, got, want)
		}
	}

	for _, rel := range []string{paths("", build).report, filepath.Join("widget", "future.shield.json"), "README.md"} {
		if _, err := os.Stat(filepath.Join(m, rel)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was seeded — it is not a document of a cell the board holds (%v)", rel, err)
		}
	}

	if drift, err := (board.Board{Dir: m}).Compare(board.Board{Dir: p}); err != nil || len(drift) != 0 {
		t.Errorf("a freshly seeded board drifts: %v, %v", drift, err)
	}

	// An existing directory that holds nothing is as empty as an absent
	// one.
	empty := t.TempDir()
	if err := (board.Board{Dir: empty}).Seed(board.Board{Dir: p}); err != nil {
		t.Errorf("Seed into an empty directory = %v", err)
	}
}

// TestSeedRefusals: every guard branch of the seeding.
func TestSeedRefusals(t *testing.T) {
	t.Parallel()

	widget := cell()

	for _, tt := range []struct {
		name    string
		arrange func(t *testing.T, m, p string) (string, string)
		want    string
		is      error
	}{
		{
			name: "the measured board already holds something",
			arrange: func(t *testing.T, m, p string) (string, string) {
				t.Helper()

				writeDoc(t, filepath.Join(m, "stray"), "")

				return m, p
			},
			want: "a comparison seeds it from the published board",
			is:   board.ErrNotEmpty,
		},
		{
			name: "the measured board cannot be listed",
			arrange: func(t *testing.T, m, p string) (string, string) {
				t.Helper()

				f := filepath.Join(m, "file")
				writeDoc(t, f, "")

				return f, p
			},
			want: "board: reading",
		},
		{
			name: "the published board cannot be listed",
			arrange: func(t *testing.T, m, p string) (string, string) {
				t.Helper()

				f := filepath.Join(p, "file")
				writeDoc(t, f, "")

				return filepath.Join(m, "fresh"), f
			},
			want: "board: reading",
		},
		{
			name: "a published document cannot be read",
			arrange: func(t *testing.T, m, p string) (string, string) {
				t.Helper()

				shield := filepath.Join(p, paths("", widget).shield)
				writeDoc(t, shield, shieldOf("L1"))

				if err := os.Chmod(shield, 0o000); err != nil {
					t.Fatal(err)
				}

				return filepath.Join(m, "fresh"), p
			},
			want: "board: seeding widget source: reading",
		},
		{
			name: "a published document is a directory",
			arrange: func(t *testing.T, m, p string) (string, string) {
				t.Helper()

				if err := os.MkdirAll(filepath.Join(p, paths("", widget).shield), 0o750); err != nil {
					t.Fatal(err)
				}

				return filepath.Join(m, "fresh"), p
			},
			want: "board: seeding widget source",
		},
		{
			name: "the measured board's repository directory cannot be made",
			arrange: func(t *testing.T, m, p string) (string, string) {
				t.Helper()

				writeDoc(t, filepath.Join(p, paths("", widget).shield), shieldOf("L1"))

				locked := filepath.Join(m, "locked")
				if err := os.Mkdir(locked, 0o500); err != nil {
					t.Fatal(err)
				}

				t.Cleanup(func() { _ = os.Chmod(locked, 0o700) }) //nolint:gosec,errcheck // G302: test cleanup

				return filepath.Join(locked, "fresh"), p
			},
			want: "board: seeding widget source",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, p := tt.arrange(t, t.TempDir(), t.TempDir())

			err := board.Board{Dir: m}.Seed(board.Board{Dir: p})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Seed = %v, want it to name %q", err, tt.want)
			}

			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("Seed = %v, want it to wrap %v", err, tt.is)
			}
		})
	}
}
