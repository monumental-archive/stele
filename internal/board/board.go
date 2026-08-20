// Package board publishes measured levels as a directory of cells,
// and owns the one rule about what may replace what.
//
// The rule is stele#135's and it is the judge's, not a workflow's: a
// cell that cannot be judged today never publishes over a level
// somebody proved yesterday. The canon carried it as a shell `if`
// between the judgment and the published state — which is a place the
// two can disagree, and the only reason they had not is that nobody
// had edited the `if` yet.
//
// What "cannot be judged" MEANS depends entirely on whether the cell
// was ever judgeable, and merging the two is how a board becomes
// unreadable:
//
//   - never judged, still not judgeable — a repository that publishes
//     nothing has no build level. That is a fact about it, not a
//     fault: grey publishes and nothing pages. An alarm here would
//     fire every week forever over repositories behaving exactly as
//     intended.
//   - judged before, not judgeable now — evidence went missing, a
//     credential narrowed, a forge read degraded. The previous
//     judgment stands and the run goes red, because something that
//     could be proven no longer can.
//
// A cell outside the population is a third thing again and produces
// no file at all. Not grey, not red, not there — an org that declared
// a repository bears no build evidence is not owed a build badge for
// it, and a board carrying one would be publishing a number nobody
// measured.
package board

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/monumental-archive/stele/internal/level"
)

// dirPerm is the mode of a repository's directory. The documents
// themselves take os.CreateTemp's own 0600 and keep it through the
// rename — the mode this wants anyway, so nothing sets it twice.
const dirPerm = 0o750

// The cell layout. Two documents per cell, named for the track, under
// a directory named for the repository — the whole format, and the
// only thing about the board's shape that is code. WHICH repositories
// and tracks exist is the population's to say, never this file's.
const (
	reportSuffix = ".report.json"
	shieldSuffix = ".shield.json"
)

// Cell is one repository × track — the unit a board publishes.
type Cell struct {
	Repo  string
	Track level.Track
}

func (c Cell) String() string { return c.Repo + " " + c.Track.Key() }

// Outcome is what publishing one cell did. Four values, because the
// four are what a caller must be able to tell apart to decide whether
// anybody should be woken.
type Outcome string

// The four outcomes.
const (
	// Published: a measurement was written.
	Published Outcome = "published"
	// Unmeasured: nothing could be measured, and nothing ever was
	// here, so grey published. Information, never a finding.
	Unmeasured Outcome = "unmeasured"
	// Kept: nothing could be measured and a LEVEL is already published
	// here. The good judgment stands and the caller must go red — this
	// is the one outcome worth waking anyone for.
	Kept Outcome = "kept"
	// Removed: a cell the population no longer holds, deleted.
	Removed Outcome = "removed"
)

// Board is a published board rooted at Dir.
type Board struct {
	Dir string
}

// Publish writes one cell's judgment, or declines to.
//
// The decision reads the board's own prior state rather than anything
// the caller passes in, so a caller cannot get it wrong by forgetting
// to ask.
func (b Board) Publish(c Cell, a *level.Assessment) (Outcome, error) {
	if a.Shield().Measured() {
		return Published, b.write(c, a)
	}

	held, err := b.priorMeasured(c)
	if err != nil {
		return "", err
	}

	if held {
		return Kept, nil
	}

	return Unmeasured, b.write(c, a)
}

// Prune removes every cell the board holds that keep does not name,
// and returns them.
//
// A board is derived state whole: it is this engine's own output and
// nothing else writes it, so a cell left behind after the population
// stopped holding it is not history worth keeping — it is a published
// level for a repository and track nobody measured this run, which is
// the exact lie the population declaration exists to end. Removals
// are returned so the caller can name each one: a board that quietly
// shrank is a board whose reader cannot tell deletion from absence.
//
// Only the cell layout is touched. A file the board did not write is
// not the board's to delete.
func (b Board) Prune(keep []Cell) ([]Cell, error) {
	held, err := b.cells()
	if err != nil {
		return nil, err
	}

	var removed []Cell

	for _, c := range held {
		if slices.ContainsFunc(keep, func(k Cell) bool { return k == c }) {
			continue
		}

		for _, path := range []string{b.reportPath(c), b.shieldPath(c)} {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("board: removing %s: %w", c, err)
			}
		}

		removed = append(removed, c)
	}

	return removed, b.tidy()
}

// priorMeasured reports whether this cell already holds a level.
//
// Three prior states, and only one of them permits an overwrite with
// grey. An ABSENT shield is a cell nobody has published, so grey may
// land. A shield saying unmeasured is the same answer as last week.
// Anything else — a level, or a document this release cannot read —
// counts as held: a board file that will not parse is one whose
// contents are unknown, and overwriting an unknown with "could not
// see" is the mute direction. It stays, and the caller goes red.
func (b Board) priorMeasured(c Cell) (bool, error) {
	f, err := os.Open(b.shieldPath(c))

	switch {
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("board: reading %s: %w", c, err)
	}

	defer f.Close() //nolint:errcheck // read-only close

	prior, derr := level.DecodeShield(f)
	if derr != nil {
		return true, nil
	}

	return prior.Measured(), nil
}

// write puts both documents down together. They are two renders of
// one seal, so a run that wrote the report and failed on the shield
// would leave a board saying two different things about one cell —
// the report lands only once the shield beside it has.
func (b Board) write(c Cell, a *level.Assessment) error {
	if err := os.MkdirAll(filepath.Join(b.Dir, c.Repo), dirPerm); err != nil {
		return fmt.Errorf("board: %s: %w", c, err)
	}

	shield, err := staged(b.shieldPath(c), a.Shield().Encode)
	if err != nil {
		return fmt.Errorf("board: %s: %w", c, err)
	}

	report, err := staged(b.reportPath(c), a.Report().Encode)
	if err != nil {
		_ = os.Remove(shield) //nolint:errcheck // the encode error is the one that matters

		return fmt.Errorf("board: %s: %w", c, err)
	}

	for _, s := range []struct{ tmp, final string }{
		{shield, b.shieldPath(c)}, {report, b.reportPath(c)},
	} {
		if err := os.Rename(s.tmp, s.final); err != nil {
			return fmt.Errorf("board: %s: %w", c, err)
		}
	}

	return nil
}

// staged encodes into a sibling temporary file and returns its path.
// A document is renamed into place only once it is whole: a board is
// read by other tools, and a half-written report is a document that
// parses as something it is not.
func staged(final string, encode func(io.Writer) error) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(final), "."+filepath.Base(final)+".")
	if err != nil {
		return "", fmt.Errorf("staging %s: %w", final, err)
	}

	if err := encode(f); err != nil {
		_ = f.Close()           //nolint:errcheck // the encode error is the one that matters
		_ = os.Remove(f.Name()) //nolint:errcheck // best-effort cleanup of a doomed temp file

		return "", err
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name()) //nolint:errcheck // best-effort cleanup of a doomed temp file

		return "", fmt.Errorf("staging %s: %w", final, err)
	}

	return f.Name(), nil
}

// cells reads what the board currently holds, by the layout alone.
func (b Board) cells() ([]Cell, error) {
	repos, err := os.ReadDir(b.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("board: reading %s: %w", b.Dir, err)
	}

	var out []Cell

	for _, repo := range repos {
		if !repo.IsDir() {
			continue
		}

		files, rerr := os.ReadDir(filepath.Join(b.Dir, repo.Name()))
		if rerr != nil {
			return nil, fmt.Errorf("board: reading %s: %w", repo.Name(), rerr)
		}

		for _, f := range files {
			name, ok := strings.CutSuffix(f.Name(), reportSuffix)
			if !ok {
				continue
			}

			// A track this release does not judge is not a cell this
			// release may delete: the board may have been written by a
			// stele that judges more than this one does, and pruning
			// what we cannot name would silently narrow somebody's
			// board to our own vocabulary.
			if t, known := level.TrackByName(name); known {
				out = append(out, Cell{Repo: repo.Name(), Track: t})
			}
		}
	}

	return out, nil
}

// tidy removes repository directories the prune emptied. An empty
// directory is not a cell, and leaving one behind names a repository
// the board no longer says anything about.
func (b Board) tidy() error {
	repos, err := os.ReadDir(b.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("board: reading %s: %w", b.Dir, err)
	}

	for _, repo := range repos {
		if !repo.IsDir() {
			continue
		}

		dir := filepath.Join(b.Dir, repo.Name())

		entries, rerr := os.ReadDir(dir)
		if rerr != nil {
			return fmt.Errorf("board: reading %s: %w", repo.Name(), rerr)
		}

		if len(entries) > 0 {
			continue
		}

		if err := os.Remove(dir); err != nil {
			return fmt.Errorf("board: removing %s: %w", repo.Name(), err)
		}
	}

	return nil
}

func (b Board) reportPath(c Cell) string {
	return filepath.Join(b.Dir, c.Repo, c.Track.Key()+reportSuffix)
}

func (b Board) shieldPath(c Cell) string {
	return filepath.Join(b.Dir, c.Repo, c.Track.Key()+shieldSuffix)
}
