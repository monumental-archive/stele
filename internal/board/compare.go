// This file: the board measured against the board published
// (stele#418). The canon decided in shell whether the cells each
// repository published are the cells a fresh measurement gives — a
// judgment, kept between the measurement and the published state,
// which is the place the replace rule was moved out of for the same
// reason. It lives here, beside that rule, and reads cells through
// the same layout.

package board

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/monumental-archive/stele/internal/level"
)

// DriftKind is one way a published cell can disagree with the
// measurement.
type DriftKind string

// The three kinds, both directions of the comparison.
const (
	// NeverPublished: the measurement holds the cell and the published
	// board does not — a repository whose publisher never ran, or never
	// published that track.
	NeverPublished DriftKind = "measured, never published"
	// Differs: both hold the cell and its shield differs.
	Differs DriftKind = "published and measured differ"
	// OutsidePopulation: the published board holds a cell the
	// measurement does not — a level published for a repository and
	// track the declared population says bears none.
	OutsidePopulation DriftKind = "published, outside the declared population"
)

// Drift is one cell on which the published board and the measured one
// disagree. Published and Measured are the shields' messages, set for
// Differs alone.
type Drift struct {
	Cell      Cell
	Kind      DriftKind
	Published string
	Measured  string
}

func (d Drift) String() string {
	if d.Kind == Differs {
		return fmt.Sprintf("%s: published %s, measured %s", d.Cell, d.Published, d.Measured)
	}

	return fmt.Sprintf("%s: %s", d.Cell, d.Kind)
}

// ErrNotEmpty is Seed refusing a board directory that already holds
// something.
var ErrNotEmpty = errors.New("board: the directory to seed is not empty")

// Seed copies every cell the published board holds into b, so that a
// measurement over b judges what may replace what against what was
// published: a cell that cannot be judged today keeps the level the
// published board proved, rather than publishing grey into a
// directory that never held it and calling the difference drift.
//
// b must hold nothing yet. A board that already holds cells would mix
// another run's state into the comparison, and the comparison would
// then measure that run as much as this one.
func (b Board) Seed(published Board) error {
	if err := b.mustBeEmpty(); err != nil {
		return err
	}

	held, err := published.cellsWith(reportSuffix, shieldSuffix)
	if err != nil {
		return err
	}

	for _, c := range held {
		if err := os.MkdirAll(filepath.Join(b.Dir, c.Repo), dirPerm); err != nil {
			return fmt.Errorf("board: seeding %s: %w", c, err)
		}

		for _, doc := range []func(Cell) string{published.reportPath, published.shieldPath} {
			if err := copyCellFile(doc(c), filepath.Join(b.Dir, c.Repo, filepath.Base(doc(c)))); err != nil {
				return fmt.Errorf("board: seeding %s: %w", c, err)
			}
		}
	}

	return nil
}

// mustBeEmpty refuses a board directory that holds anything.
func (b Board) mustBeEmpty() error {
	entries, err := os.ReadDir(b.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("board: reading %s: %w", b.Dir, err)
	}

	if len(entries) > 0 {
		return fmt.Errorf("%w: %s — a comparison seeds it from the published board, and another run's cells"+
			" there would be compared as this run's", ErrNotEmpty, b.Dir)
	}

	return nil
}

// copyCellFile copies one document of a cell, if the published board
// has it: a cell may hold its shield without its report or the other
// way about, and each is copied as it stands.
func copyCellFile(from, to string) error {
	src, err := os.Open(from) //nolint:gosec // G304: a path built from the board's own layout
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("reading %s: %w", from, err)
	}
	defer src.Close() //nolint:errcheck // read-only close

	staged, err := staged(to, func(w io.Writer) error {
		_, cerr := io.Copy(w, src)

		return cerr //nolint:wrapcheck // staged wraps it with the path
	})
	if err != nil {
		return err
	}

	if err := os.Rename(staged, to); err != nil {
		return fmt.Errorf("placing %s: %w", to, err)
	}

	return nil
}

// Compare reports every cell on which b, as measured, and the
// published board disagree, in both directions. Shields are compared,
// never reports: a report carries the moment it was sealed, so two
// honest measurements a minute apart differ in bytes, while the
// shield is the sealed judgment with no clock in it — what a badge
// renders.
func (b Board) Compare(published Board) ([]Drift, error) {
	measured, err := b.cellsWith(shieldSuffix)
	if err != nil {
		return nil, err
	}

	held, err := published.cellsWith(shieldSuffix)
	if err != nil {
		return nil, err
	}

	var drift []Drift

	for _, c := range measured {
		if !slices.Contains(held, c) {
			drift = append(drift, Drift{Cell: c, Kind: NeverPublished})

			continue
		}

		d, differs, cerr := b.differs(published, c)
		if cerr != nil {
			return nil, cerr
		}

		if differs {
			drift = append(drift, d)
		}
	}

	for _, c := range held {
		if !slices.Contains(measured, c) {
			drift = append(drift, Drift{Cell: c, Kind: OutsidePopulation})
		}
	}

	return drift, nil
}

// differs compares one cell's two shields byte for byte, and names
// both messages when they differ.
func (b Board) differs(published Board, c Cell) (Drift, bool, error) {
	now, err := os.ReadFile(b.shieldPath(c))
	if err != nil {
		return Drift{}, false, fmt.Errorf("board: reading %s: %w", c, err)
	}

	was, err := os.ReadFile(published.shieldPath(c))
	if err != nil {
		return Drift{}, false, fmt.Errorf("board: reading published %s: %w", c, err)
	}

	if bytes.Equal(now, was) {
		return Drift{}, false, nil
	}

	return Drift{Cell: c, Kind: Differs, Published: shieldMessage(was), Measured: shieldMessage(now)}, true, nil
}

// shieldMessage reads a shield's message through the one shield
// reader; a shield that will not read is named as such rather than
// quoted.
func shieldMessage(raw []byte) string {
	s, err := level.DecodeShield(bytes.NewReader(raw))
	if err != nil {
		return "an unreadable shield"
	}

	return s.Message
}
