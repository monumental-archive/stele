// The publish rule's guard branches, one row each. This is the code
// that decides whether a run which could not judge is allowed to
// erase a level somebody proved — the branch that fires only in a
// degraded state, and the one that looks exactly like success when it
// is wrong.

package board_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/board"
	"github.com/monumental-archive/stele/internal/level"
)

// epoch is a fixed stamp: a judgment's clock is an input, never a
// reason for a test to differ from itself.
var epoch = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

// measured is an assessment whose shield carries a level: the source
// track holds L1 for any repository with a branch under a chain, and
// what matters here is only that the shield is not grey.
func measured(t *testing.T, track level.Track) *level.Assessment {
	t.Helper()

	lad := level.NewLadder(track)
	lad.Hold(1, "the fixture establishes this rung")

	a := level.Seal(track, lad, &level.Inputs{
		Subject: "acme/widget", InScope: 1, Determined: 1,
		PopulationDetail: "repositories with a determinable ladder", Now: epoch,
	})

	if !a.Shield().Measured() {
		t.Fatalf("the fixture is not measured: %s", a.Shield().Message)
	}

	return a
}

// blind is an assessment that could establish nothing — the shield a
// run publishes when it could not see.
func blind(t *testing.T, track level.Track) *level.Assessment {
	t.Helper()

	lad := level.NewLadder(track)
	lad.Blind(1, "the fixture could not see")

	a := level.Seal(track, lad, &level.Inputs{
		Subject: "acme/widget", InScope: 1, Determined: 0,
		PopulationDetail: "repositories with a determinable ladder", Now: epoch,
	})

	if a.Shield().Measured() {
		t.Fatalf("the fixture is measured: %s", a.Shield().Message)
	}

	return a
}

func cell() board.Cell { return board.Cell{Repo: "widget", Track: level.TrackSource} }

// docs are one cell's two documents, by the layout alone — spelled
// out here rather than asked of the package, so the format itself is
// under test and not merely self-consistent.
type docs struct{ report, shield string }

func paths(dir string, c board.Cell) docs {
	base := filepath.Join(dir, c.Repo, c.Track.Key())

	return docs{report: base + ".report.json", shield: base + ".shield.json"}
}

func read(t *testing.T, path string) string {
	t.Helper()

	b, err := os.ReadFile(path) //nolint:gosec // a path this test just wrote
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	return string(b)
}

// TestPublishRule is the whole of stele#135 as a table: what may
// replace what, and what a caller is told about it.
func TestPublishRule(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		// prior is the shield already published at the cell, or "" for
		// a cell nobody has published.
		prior string
		// now is whether this run could measure.
		now  bool
		want board.Outcome
		// keeps is whether the PRIOR bytes must survive.
		keeps bool
	}{
		{
			name: "a measurement publishes onto absence",
			now:  true, want: board.Published,
		},
		{
			name:  "a measurement replaces an older measurement",
			prior: `{"schemaVersion":1,"label":"SLSA Source","message":"L1","color":"brightgreen"}`,
			now:   true, want: board.Published,
		},
		{
			name:  "a measurement replaces grey",
			prior: `{"schemaVersion":1,"label":"SLSA Source","message":"unmeasured","color":"lightgrey"}`,
			now:   true, want: board.Published,
		},
		{
			name: "grey publishes onto absence and nothing pages",
			now:  false, want: board.Unmeasured,
		},
		{
			name:  "grey replaces grey — the same answer as last week",
			prior: `{"schemaVersion":1,"label":"SLSA Source","message":"unmeasured","color":"lightgrey"}`,
			now:   false, want: board.Unmeasured,
		},
		{
			// The one outcome worth waking anyone for.
			name:  "grey NEVER replaces a level",
			prior: `{"schemaVersion":1,"label":"SLSA Source","message":"L3","color":"brightgreen"}`,
			now:   false, want: board.Kept, keeps: true,
		},
		{
			// A board file whose contents cannot be read is a cell
			// whose state is unknown, and "could not see" must not
			// overwrite an unknown.
			name:  "grey never replaces a shield this release cannot read",
			prior: `{"schemaVersion":1,"unknownField":"from a later stele"}`,
			now:   false, want: board.Kept, keeps: true,
		},
		{
			name:  "grey never replaces a shield that is not JSON at all",
			prior: "not json",
			now:   false, want: board.Kept, keeps: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			c := cell()
			at := paths(dir, c)

			seedPrior(t, at, tc.prior)

			a := measured(t, c.Track)
			if !tc.now {
				a = blind(t, c.Track)
			}

			b := board.Board{Dir: dir}

			got, err := b.Publish(c, a)
			if err != nil {
				t.Fatalf("Publish: %v", err)
			}

			if got != tc.want {
				t.Fatalf("outcome = %q, want %q", got, tc.want)
			}

			if tc.keeps {
				if held := read(t, at.shield); held != tc.prior {
					t.Fatalf("the published judgment was overwritten:\n%s", held)
				}

				return
			}

			landed(t, a, at)
		})
	}
}

// seedPrior puts a shield and a report at one cell, as a previous
// run's publish would have left them.
func seedPrior(t *testing.T, at docs, prior string) {
	t.Helper()

	if prior == "" {
		return
	}

	if err := os.MkdirAll(filepath.Dir(at.shield), 0o750); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{at.shield, at.report} {
		if err := os.WriteFile(p, []byte(prior), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// landed checks the cell's two documents against the seal that wrote
// them. They are two renders of ONE seal, so a board carrying a
// report and a shield that disagree is worse than one carrying
// neither.
func landed(t *testing.T, a *level.Assessment, at docs) {
	t.Helper()

	if !strings.Contains(read(t, at.shield), a.Shield().Message) {
		t.Fatalf("the shield does not carry this run's message")
	}

	if !strings.Contains(read(t, at.report), a.Level()) {
		t.Fatalf("the report does not carry this run's level")
	}
}

// TestPublishWritesNothingHalfway: the cell's two documents are one
// seal, so a run that cannot finish leaves the previous state rather
// than a board saying two different things about one cell.
func TestPublishWritesNothingHalfway(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	c := cell()
	at := paths(dir, c)

	// A directory where the cell's documents belong: every write into
	// it fails, whatever the caller does.
	if err := os.MkdirAll(at.report, 0o750); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(at.shield, 0o750); err != nil {
		t.Fatal(err)
	}

	_, err := board.Board{Dir: dir}.Publish(c, measured(t, c.Track))
	if err == nil {
		t.Fatal("Publish reported success over a writer that cannot write")
	}

	if !strings.Contains(err.Error(), c.String()) {
		t.Fatalf("the failure does not name the cell: %v", err)
	}
}

// TestPublishRefusesAnUnreadablePrior: a prior shield the process
// cannot read is not the same as one that says unmeasured, and
// guessing which would be guessing about a published level.
func TestPublishRefusesAnUnreadablePrior(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	c := cell()
	at := paths(dir, c)

	// A directory in the shield's place: open succeeds, read does not.
	if err := os.MkdirAll(at.shield, 0o750); err != nil {
		t.Fatal(err)
	}

	got, err := board.Board{Dir: dir}.Publish(c, blind(t, c.Track))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if got != board.Kept {
		t.Fatalf("outcome = %q, want %q — an unreadable cell is not an empty one", got, board.Kept)
	}
}

// TestBoardCannotBeBuilt: the degraded states the filesystem itself
// puts a board in, each named rather than swallowed.
func TestBoardCannotBeBuilt(t *testing.T) {
	t.Parallel()

	t.Run("a file where a repository's directory belongs", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		c := cell()

		if err := os.WriteFile(filepath.Join(dir, c.Repo), []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}

		b := board.Board{Dir: dir}

		_, err := b.Publish(c, measured(t, c.Track))
		if err == nil || !strings.Contains(err.Error(), c.String()) {
			t.Fatalf("Publish = %v, want a refusal naming the cell", err)
		}
	})

	t.Run("a repository directory this process cannot read", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		c := cell()
		b := board.Board{Dir: dir}

		if _, err := b.Publish(c, measured(t, c.Track)); err != nil {
			t.Fatalf("Publish: %v", err)
		}

		repo := filepath.Join(dir, c.Repo)
		if err := os.Chmod(repo, 0o000); err != nil {
			t.Fatal(err)
		}

		//nolint:errcheck,gosec // a DIRECTORY mode, restored so TempDir can clean up
		t.Cleanup(func() { _ = os.Chmod(repo, 0o750) })

		if _, err := b.Prune(nil); err == nil || !strings.Contains(err.Error(), c.Repo) {
			t.Fatalf("Prune = %v, want a refusal naming the directory it could not read", err)
		}
	})
}

// TestPublishRefusesAnUnopenablePrior is the sharper edge of the
// never-overwrite rule, and the one direction that cannot be guessed.
//
// A prior shield the process cannot even OPEN is not an absent one.
// Absent means nobody has published this cell, and grey may land;
// unreadable means a document is there and its contents are unknown.
// Treating the second as the first would publish "could not see" over
// a level somebody proved — the exact erasure stele#135 exists to
// prevent — so the run refuses and the caller goes red instead.
func TestPublishRefusesAnUnopenablePrior(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	c := cell()
	b := board.Board{Dir: dir}

	if _, err := b.Publish(c, measured(t, c.Track)); err != nil {
		t.Fatalf("seeding the prior level: %v", err)
	}

	shield := paths(dir, c).shield
	if err := os.Chmod(shield, 0o000); err != nil {
		t.Fatal(err)
	}

	//nolint:errcheck // restored so TempDir can clean up
	t.Cleanup(func() { _ = os.Chmod(shield, 0o600) })

	_, err := b.Publish(c, blind(t, c.Track))
	if err == nil || !strings.Contains(err.Error(), c.String()) {
		t.Fatalf("Publish = %v, want a refusal naming the cell it could not read", err)
	}
}

// TestPublishRefusesAnUnwritableCell: the repository's directory
// exists but nothing may be staged into it. A board that reported
// success here would leave last run's documents in place while
// claiming this run's judgment had been published.
func TestPublishRefusesAnUnwritableCell(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	c := cell()
	b := board.Board{Dir: dir}

	if _, err := b.Publish(c, measured(t, c.Track)); err != nil {
		t.Fatalf("seeding the cell: %v", err)
	}

	repo := filepath.Join(dir, c.Repo)

	//nolint:gosec // G302: a DIRECTORY mode; read and traverse without write is the point
	if err := os.Chmod(repo, 0o500); err != nil {
		t.Fatal(err)
	}

	//nolint:errcheck,gosec // a DIRECTORY mode, restored so TempDir can clean up
	t.Cleanup(func() { _ = os.Chmod(repo, 0o750) })

	_, err := b.Publish(c, measured(t, c.Track))
	if err == nil || !strings.Contains(err.Error(), c.String()) {
		t.Fatalf("Publish = %v, want a refusal naming the cell it could not stage", err)
	}
}

// TestPruneRefusesWhatItCannotRemove: a cell Prune names but cannot
// delete must fail loudly. Returning the cell as removed while the
// document stayed would tell the caller a level was retracted that a
// reader can still fetch.
func TestPruneRefusesWhatItCannotRemove(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	c := cell()

	// A non-empty directory wearing a report's name: the layout reads
	// it as a cell, and removing it cannot succeed.
	at := paths(dir, c)
	if err := os.MkdirAll(at.report, 0o750); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(at.report, "occupant"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := board.Board{Dir: dir}.Prune(nil)
	if err == nil || !strings.Contains(err.Error(), c.String()) {
		t.Fatalf("Prune = %v, want a refusal naming the cell it could not remove", err)
	}
}

// TestPruneRefusesABoardThatIsNotADirectory: --out-dir pointed at a
// file is an operator error, and the run must say so rather than read
// the board as holding nothing — which is what an empty listing would
// mean, and would prune every cell the board actually has.
func TestPruneRefusesABoardThatIsNotADirectory(t *testing.T) {
	t.Parallel()

	file := filepath.Join(t.TempDir(), "board")
	if err := os.WriteFile(file, []byte("not a board"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := (board.Board{Dir: file}).Prune(nil); err == nil {
		t.Fatal("Prune read a regular file as an empty board")
	}
}

// TestTidyRefusesADirectoryItCannotRemove: the emptied repository
// directory is the last thing a prune clears, and a board that left
// one behind names a repository it no longer says anything about. A
// failure to clear it is reported rather than swallowed, because the
// caller's next action is to publish that board.
func TestTidyRefusesADirectoryItCannotRemove(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	c := cell()
	b := board.Board{Dir: dir}

	if _, err := b.Publish(c, measured(t, c.Track)); err != nil {
		t.Fatalf("seeding the cell: %v", err)
	}

	// Readable and traversable, but not writable: the cell's documents
	// still delete (their own directory allows it), and the now-empty
	// repository directory cannot, because that removal writes here.
	//nolint:gosec // G302: a DIRECTORY mode; read and traverse without write is the point
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}

	//nolint:errcheck,gosec // a DIRECTORY mode, restored so TempDir can clean up
	t.Cleanup(func() { _ = os.Chmod(dir, 0o750) })

	if _, err := b.Prune(nil); err == nil || !strings.Contains(err.Error(), c.Repo) {
		t.Fatalf("Prune = %v, want a refusal naming the directory it could not remove", err)
	}
}

// TestPrune: a cell the population no longer holds produces no file,
// and the removals are named so a reader can tell deletion from
// absence.
func TestPrune(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	b := board.Board{Dir: dir}

	held := []board.Cell{
		{Repo: "widget", Track: level.TrackSource},
		{Repo: "widget", Track: level.TrackBuild},
		{Repo: "signer", Track: level.TrackSource},
		{Repo: "signer", Track: level.TrackBuild},
		{Repo: "gone", Track: level.TrackDependency},
	}

	for _, c := range held {
		if _, err := b.Publish(c, measured(t, c.Track)); err != nil {
			t.Fatalf("Publish %s: %v", c, err)
		}
	}

	// A file the board did not write, in a repository directory that
	// survives: not the board's to delete.
	stray := filepath.Join(dir, "widget", "notes.md")
	if err := os.WriteFile(stray, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}

	keep := []board.Cell{
		{Repo: "widget", Track: level.TrackSource},
		{Repo: "widget", Track: level.TrackBuild},
		{Repo: "signer", Track: level.TrackSource},
	}

	removed, err := b.Prune(keep)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}

	want := map[string]bool{"signer build": true, "gone dependency": true}
	if len(removed) != len(want) {
		t.Fatalf("removed = %v, want %v", removed, want)
	}

	for _, c := range removed {
		if !want[c.String()] {
			t.Fatalf("Prune removed %s, which the population still holds", c)
		}
	}

	for _, c := range keep {
		at := paths(dir, c)
		for _, p := range []string{at.report, at.shield} {
			if _, err := os.Stat(p); err != nil {
				t.Fatalf("Prune removed a cell the population holds: %s", p)
			}
		}
	}

	for _, c := range []board.Cell{
		{Repo: "signer", Track: level.TrackBuild},
		{Repo: "gone", Track: level.TrackDependency},
	} {
		at := paths(dir, c)
		for _, p := range []string{at.report, at.shield} {
			if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s survived the prune: %v", p, err)
			}
		}
	}

	if _, err := os.Stat(stray); err != nil {
		t.Fatalf("Prune deleted a file the board did not write: %v", err)
	}

	// The emptied repository directory goes; the one still holding a
	// cell stays.
	if _, err := os.Stat(filepath.Join(dir, "gone")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an emptied repository directory survived: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "widget")); err != nil {
		t.Fatalf("a repository directory still holding cells was removed: %v", err)
	}
}

// TestPruneEdges: the states a prune meets that are not a full board.
func TestPruneEdges(t *testing.T) {
	t.Parallel()

	t.Run("a board that does not exist yet prunes nothing", func(t *testing.T) {
		t.Parallel()

		b := board.Board{Dir: filepath.Join(t.TempDir(), "absent")}

		removed, err := b.Prune(nil)
		if err != nil || len(removed) != 0 {
			t.Fatalf("Prune = %v, %v", removed, err)
		}
	})

	t.Run("a track this release does not judge is not this release's to delete", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "widget"), 0o750); err != nil {
			t.Fatal(err)
		}

		// A board written by a stele that judges a track this one does
		// not: pruning it would silently narrow somebody's board to
		// our own vocabulary.
		future := filepath.Join(dir, "widget", "platform.report.json")
		if err := os.WriteFile(future, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}

		b := board.Board{Dir: dir}

		removed, err := b.Prune(nil)
		if err != nil || len(removed) != 0 {
			t.Fatalf("Prune = %v, %v", removed, err)
		}

		if _, err := os.Stat(future); err != nil {
			t.Fatalf("a track this release does not judge was deleted: %v", err)
		}
	})

	t.Run("loose files at the board root are not cells", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()

		readme := filepath.Join(dir, "README.md")
		if err := os.WriteFile(readme, []byte("the board"), 0o600); err != nil {
			t.Fatal(err)
		}

		b := board.Board{Dir: dir}
		if _, err := b.Prune(nil); err != nil {
			t.Fatalf("Prune: %v", err)
		}

		if _, err := os.Stat(readme); err != nil {
			t.Fatalf("Prune deleted a file at the board root: %v", err)
		}
	})
}
