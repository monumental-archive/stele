// The board form: `stele level --org <org> --out-dir <dir>`, every
// track at once, published as files.
//
// It exists because the canon's cron carried the loop AND the publish
// rule as workflow bash — enumerate the org, iterate repo × track,
// and decide by shell `if` whether a run that could not judge may
// overwrite a level somebody proved. That `if` sits between the
// judgment and the published state, which is a place the two can
// disagree; the rule is the judge's (stele#152, stele#135) and it
// lives in internal/board now.
//
// What this file does is fetching and reporting. It measures each
// cell through exactly the same path the single-cell form uses, so a
// board can never say something `stele level build --repo …` would
// not, and it enumerates through internal/population alone, so a cell
// nobody declared is not a cell.

package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/monumental-archive/stele/internal/board"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/level"
	"github.com/monumental-archive/stele/internal/population"
)

// boardArgs is the board form's input.
type boardArgs struct {
	org        string
	outDir     string
	policyPath string
	ref        string
	notesRef   string
	root       rootFlags
}

// levelBoard measures every cell the population holds and publishes
// it under --out-dir.
func levelBoard(args []string, stdout, stderr io.Writer) int {
	opts, code := parseBoardArgs(args, stderr)
	if code != exitOK {
		return code
	}

	out := &latch{w: stdout}
	forge := newForge()

	cells, code := opts.cells(forge, out)
	if code != exitOK {
		return code
	}

	b := board.Board{Dir: opts.outDir}
	kept := 0

	for _, c := range cells {
		outcome, err := b.Publish(c, opts.measure(c, forge, out))
		if err != nil {
			if _, werr := fmt.Fprintf(stderr, "%v\n", err); werr != nil {
				return exitIO
			}

			return exitIO
		}

		if outcome == board.Kept {
			kept++
		}

		out.logf("level: %s: %s", c, outcome)
	}

	if code := opts.prune(b, cells, out); code != exitOK {
		return code
	}

	if out.err != nil {
		return exitIO
	}

	return boardExit(kept, stderr)
}

// boardExit reports the one state worth waking anyone for. A grey
// cell is NOT it: a repository that publishes nothing has no build
// level, that is a fact about it rather than a fault, and a run that
// went red over it would fire every week forever until the board was
// something nobody read.
func boardExit(kept int, stderr io.Writer) int {
	if kept == 0 {
		return exitOK
	}

	if _, err := fmt.Fprintf(stderr,
		"stele level: %d cell(s) were judged before and cannot be judged now;"+
			" the published judgments stand — investigate\n", kept); err != nil {
		return exitIO
	}

	return exitBlind
}

// cells enumerates the board's grid through the population component.
//
// An empty grid ends the run rather than publishing an empty board: a
// walk over nobody has measured nothing, and a board that quietly
// became empty is indistinguishable from an org that lost every
// repository.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func (opts *boardArgs) cells(forge gh.Forge, out *latch) ([]board.Cell, int) {
	var declared *population.Declaration

	if opts.policyPath != "" {
		pol, err := loadAssertPolicy(opts.policyPath)
		if err != nil {
			out.logf("level: %v", err)

			return nil, exitBlind
		}

		declared = pol.Population
	}

	pop, err := resolvePopulation(population.Scope{Org: opts.org}, forge, declared)
	if err != nil {
		out.logf("level: the organisation's population could not be enumerated: %v", err)

		return nil, exitBlind
	}

	grid := pop.Grid()
	if len(grid) == 0 {
		out.logf("level: %s's population holds no cell — a board over nobody publishes nothing", opts.org)

		return nil, exitBlind
	}

	cells := make([]board.Cell, 0, len(grid))
	for _, m := range grid {
		cells = append(cells, board.Cell{Repo: m.Repo, Track: m.Track})
	}

	return cells, exitOK
}

// measure judges one cell through the single-cell path, so the board
// and `stele level <track> --repo …` cannot answer differently.
func (opts *boardArgs) measure(c board.Cell, forge gh.Forge, out *latch) *level.Assessment {
	la := &levelArgs{
		track: c.Track.Key(), owner: opts.org, name: c.Repo,
		repo: opts.org + "/" + c.Repo,
		ref:  opts.ref, notesRef: opts.notesRef, root: opts.root,
	}

	return level.Assess(c.Track, la.gather(forge, out))
}

// prune drops cells the population no longer holds, naming each: a
// board that quietly shrank is one whose reader cannot tell a
// deletion from an absence.
func (opts *boardArgs) prune(b board.Board, cells []board.Cell, out *latch) int {
	removed, err := b.Prune(cells)
	if err != nil {
		out.logf("level: %v", err)

		return exitIO
	}

	for _, c := range removed {
		out.logf("level: %s: %s (outside the declared population)", c, board.Removed)
	}

	return exitOK
}

//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseBoardArgs(args []string, stderr io.Writer) (*boardArgs, int) {
	opts := &boardArgs{}

	fs := flag.NewFlagSet("stele level", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.org, "org", "", "organisation whose repositories to measure")
	fs.StringVar(&opts.outDir, "out-dir", "",
		"publish every cell here as <repo>/<track>.report.json and <repo>/<track>.shield.json")
	fs.StringVar(&opts.policyPath, "policy", "",
		"assert policy whose declared population scopes the board (membership only: no declaration reaches a verdict)")
	fs.StringVar(&opts.ref, "ref", defaultBranch, "fully qualified branch ref to measure")
	fs.StringVar(&opts.notesRef, "notes-ref", defaultNotesRef, "fully qualified notes ref carrying the source chain")
	opts.root.register(fs)

	if err := fs.Parse(args); err != nil {
		return nil, exitUsage
	}

	fail := func(msg string) (*boardArgs, int) {
		if _, werr := fmt.Fprintf(stderr, "stele level: %s\n", msg); werr != nil {
			return nil, exitIO
		}

		return nil, exitUsage
	}

	switch {
	case opts.org == "":
		return fail("--out-dir publishes an organisation's board, so --org is required")
	case opts.outDir == "":
		// The track-less form measures every track, and there is
		// nowhere but a directory to put the answer: one document per
		// cell is the format, and there is no combined one.
		return fail("a track is required: build, source or dependency\n" +
			"stele level: or --out-dir <dir> to publish every track as its own document")
	}

	return opts, exitOK
}
