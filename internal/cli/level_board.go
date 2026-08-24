// The board form: every track at once, published as files.
//
// It exists because the canon's cron carried the loop AND the publish
// rule as workflow bash — enumerate the org, iterate repo × track,
// and decide by shell `if` whether a run that could not judge may
// overwrite a level somebody proved. That `if` sits between the
// judgment and the published state, which is a place the two can
// disagree; the rule is the judge's (stele#152, stele#135) and it
// lives in internal/board now.
//
// TWO SCOPES, one form. `--org <org>` publishes the organisation's
// whole board. `--repo <owner>/<name>` publishes ONE repository's own
// cells (stele#252): it enumerates nothing, reconciles nothing, and
// touches no other repository's cells — so a repository can publish
// its own levels with a credential over itself, which is all a
// repository judging itself ever needed. The org form is unchanged by
// its arrival, and neither form learns anything about levels the
// other does not.
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
	"strings"

	"github.com/monumental-archive/stele/internal/board"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/level"
	"github.com/monumental-archive/stele/internal/population"
)

// boardArgs is the board form's input. Exactly one of org and repo is
// set; owner and name are the resolved coordinates both scopes
// measure through, so nothing below asks which scope it is in to find
// out who it is looking at.
type boardArgs struct {
	org         string
	repo        string
	owner, name string
	outDir      string
	policyPath  string
	ref         string
	notesRef    string
	root        rootFlags
}

// plan is what one run answers for: the cells it measures, and the
// population members it could not look at.
//
// The second list is not a smaller version of the first. A cell in
// `cells` gets measured and published under the never-overwrite law;
// a repository in `unlooked` gets nothing done to it at all, INCLUDING
// not being pruned — its published cells are exactly as proven as
// they were before this run started, and a run that could not see a
// repository has no standing to delete what a run that could see it
// wrote.
type plan struct {
	cells    []board.Cell
	unlooked []string
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

	p, code := opts.plan(forge, out)
	if code != exitOK {
		return code
	}

	b := board.Board{Dir: opts.outDir}
	kept := 0

	for _, c := range p.cells {
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

	if code := opts.prune(b, p, out); code != exitOK {
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

// plan enumerates what this run answers for, through the population
// component and nothing else.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func (opts *boardArgs) plan(forge gh.Forge, out *latch) (plan, int) {
	var declared *population.Declaration

	if opts.policyPath != "" {
		pol, err := loadAssertPolicy(opts.policyPath)
		if err != nil {
			out.logf("level: %v", err)

			return plan{}, exitBlind
		}

		declared = pol.Population
	}

	pop, err := resolvePopulation(population.Scope{Org: opts.org, Repo: opts.repo}, forge, declared)
	if err != nil {
		out.logf("level: the population could not be enumerated: %v", err)

		return plan{}, exitBlind
	}

	grid := pop.Grid()

	cells := make([]board.Cell, 0, len(grid))
	for _, m := range grid {
		cells = append(cells, board.Cell{Repo: m.Repo, Track: m.Track})
	}

	p := plan{cells: cells, unlooked: pop.UnexercisedRoster()}

	for _, name := range p.unlooked {
		out.logf("level: %s: not looked at — outside the declared enumeration coverage;"+
			" its published cells stand", name)
	}

	if len(cells) == 0 {
		return p, opts.empty(out)
	}

	return p, exitOK
}

// empty decides what an empty grid means, which depends entirely on
// which question was asked.
//
// Over an ORGANISATION it ends the run: a walk over nobody has
// measured nothing, and a board that quietly became empty is
// indistinguishable from an org that lost every repository.
//
// Over ONE REPOSITORY it is the declaration working. A repository
// declared to bear evidence on no track owes no cell, and the only
// way to reach this point is a policy that said so in as many words —
// so the run publishes nothing, removes any cell that declaration
// used to hold, and exits clean. An exclusion produces nothing: no
// finding, no count, no cell, and no exit code either.
func (opts *boardArgs) empty(out *latch) int {
	if opts.repo != "" {
		out.logf("level: %s bears evidence on no track — nothing to publish", opts.repo)

		return exitOK
	}

	out.logf("level: %s's population holds no cell — a board over nobody publishes nothing", opts.org)

	return exitBlind
}

// measure judges one cell through the single-cell path, so the board
// and `stele level <track> --repo …` cannot answer differently.
func (opts *boardArgs) measure(c board.Cell, forge gh.Forge, out *latch) *level.Assessment {
	la := &levelArgs{
		track: c.Track.Key(), owner: opts.owner, name: c.Repo,
		repo: opts.owner + "/" + c.Repo,
		ref:  opts.ref, notesRef: opts.notesRef, root: opts.root,
	}

	return level.Assess(c.Track, la.gather(forge, out))
}

// prune drops cells the population no longer holds, naming each: a
// board that quietly shrank is one whose reader cannot tell a
// deletion from an absence.
//
// Which cells are even eligible is the scope's answer, not this
// function's. A run over one repository may remove that repository's
// cells and no others — every other cell on the board belongs to a
// run this one knows nothing about — and a run over an organisation
// spares the members it could not look at, for the same reason at a
// different grain.
func (opts *boardArgs) prune(b board.Board, p plan, out *latch) int {
	removed, err := opts.removals(b, p)
	if err != nil {
		out.logf("level: %v", err)

		return exitIO
	}

	for _, c := range removed {
		out.logf("level: %s: %s (outside the declared population)", c, board.Removed)
	}

	return exitOK
}

func (opts *boardArgs) removals(b board.Board, p plan) ([]board.Cell, error) {
	if opts.repo != "" {
		return b.PruneRepo(opts.name, p.cells)
	}

	return b.Prune(p.cells, p.unlooked)
}

//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseBoardArgs(args []string, stderr io.Writer) (*boardArgs, int) {
	opts := &boardArgs{}

	fs := flag.NewFlagSet("stele level", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.org, "org", "", "organisation whose repositories to measure (this or --repo)")
	fs.StringVar(&opts.repo, "repo", "",
		"owner/repo whose own cells to publish, enumerating nothing (this or --org)")
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
	case opts.org != "" && opts.repo != "":
		// Two populations is two questions; answering one and
		// labelling it the other is how a measurement stops meaning
		// anything. The single-cell form refuses the same pair.
		return fail("--repo and --org name two different populations — choose one")
	case opts.org == "" && opts.repo == "":
		return fail("--out-dir publishes a board, so --org or --repo is required")
	case opts.outDir == "":
		// The track-less form measures every track, and there is
		// nowhere but a directory to put the answer: one document per
		// cell is the format, and there is no combined one.
		return fail("a track is required: build, source or dependency\n" +
			"stele level: or --out-dir <dir> to publish every track as its own document")
	case opts.repo == "":
		opts.owner = opts.org

		return opts, exitOK
	}

	owner, name, ok := strings.Cut(opts.repo, "/")
	if !ok || owner == "" || name == "" {
		return fail("--repo must be owner/repo")
	}

	opts.owner, opts.name = owner, name

	return opts, exitOK
}
