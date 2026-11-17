// `derive population` (stele#388): the population stele computes,
// printed, so no caller keeps a second implementation of how a roster
// is read. The set comes from resolvePopulation — the one door every
// assert target enumerates through — and is printed as the set
// returned it; nothing here re-reads the declaration.
//
// With --repo and --tracks it answers the one question a single
// repository's caller asks: is this repository a member, and do the
// tracks it states equal the ones the roster declares for it.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/monumental-archive/stele/internal/level"
	"github.com/monumental-archive/stele/internal/population"
)

// derivePopulation is the mode name.
const derivePopulation = "population"

// populationArgs is everything `derive population` reads.
type populationArgs struct {
	policyPath string
	org        string
	repo       string
	tracks     string
	out        string
}

// parsePopulationArgs reads the flag surface.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parsePopulationArgs(args []string, stderr io.Writer) (*populationArgs, int) {
	pa := &populationArgs{}

	flags := flag.NewFlagSet("stele derive population", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&pa.policyPath, "policy", "", "path to the committed assert policy (required)")
	flags.StringVar(&pa.org, "org", "", "organisation whose population is printed (this or --repo)")
	flags.StringVar(&pa.repo, "repo", "",
		"owner/name to ask about: is it a member, and do --tracks equal its declared tracks (this or --org)")
	flags.StringVar(&pa.tracks, "tracks", "",
		"whitespace- or comma-separated tracks the caller states for --repo")
	flags.StringVar(&pa.out, "out", "", "file to write the document to; empty prints to stdout")

	if err := flags.Parse(args); err != nil {
		return pa, exitUsage
	}

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele derive population: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch {
	case pa.policyPath == "":
		return pa, usageFail("--policy is required")
	case pa.org == "" && pa.repo == "":
		return pa, usageFail("--org or --repo is required")
	case pa.org != "" && pa.repo != "":
		return pa, usageFail("--org and --repo are exclusive: one population, named once")
	case pa.repo != "" && !strings.Contains(pa.repo, "/"):
		return pa, usageFail("--repo must be owner/name")
	case pa.org != "" && pa.tracks != "":
		return pa, usageFail("--tracks is stated for one repository: it goes with --repo")
	}

	return pa, exitOK
}

// runDerivePopulation resolves the population and prints it. Exit
// codes as everywhere: 1 when the roster and the listing disagree, or
// a single repository's question is refused; 4 when the population
// could not be enumerated at all.
func runDerivePopulation(pa *populationArgs, stdout, stderr io.Writer) int {
	pol, err := loadAssertPolicy(pa.policyPath)
	if err != nil {
		return say(stderr, exitUsage, "stele derive population: %v", err)
	}

	set, err := resolvePopulation(population.Scope{Org: pa.org, Repo: pa.repo}, newForge(), pol.Population)

	var disagree *population.ReconcileError

	switch {
	case errors.As(err, &disagree):
		if code := printPopulation(pa.out, new(disagree.RefusedDocument()), stdout, stderr); code != exitOK {
			return code
		}

		return say(stderr, exitRefused, "derive population: %v", err)
	case err != nil:
		return say(stderr, exitBlind, "derive population: %v — the population could not be enumerated", err)
	}

	// A listing that came back with nobody in it is the degraded forge
	// (stele#69), not an organisation that owns nothing: printed as an
	// empty population it would read as a clean answer. A declared
	// population cannot reach here empty — the reconciliation refuses a
	// listing that does not show what the roster names.
	if len(set.Roster()) == 0 && len(set.UnexercisedRoster()) == 0 {
		return say(stderr, exitBlind, "derive population: the listing of %s holds no repository the population"+
			" admits — an empty answer is a blind read until shown otherwise", set.Subject())
	}

	if pa.repo != "" {
		if rerr := askMembership(pa, set, pol.Population != nil); rerr != nil {
			return say(stderr, exitRefused, "derive population: %v", rerr)
		}
	}

	return printPopulation(pa.out, new(set.Document()), stdout, stderr)
}

// askMembership answers the single-repository question: the repository
// is a member of the declared population, the caller stated tracks,
// and — where the roster names this member's tracks — the stated ones
// are exactly those. A roster that leaves the tracks to the default
// declares every track, present and future, so any stated set agrees
// with it: the caller narrows what it RUNS, never what is owed.
func askMembership(pa *populationArgs, set *population.Set, declared bool) error {
	_, name, _ := strings.Cut(pa.repo, "/")

	if declared && !set.Declared() {
		return fmt.Errorf("%s is not in the declared population — the organisation has not said it bears evidence,"+
			" and a repository nobody declared is asked nothing", pa.repo)
	}

	stated, err := statedTracks(pa.tracks)
	if err != nil {
		return err
	}

	m, _ := set.Member(name)

	if m.TracksDeclared && !slices.Equal(stated, m.Tracks) {
		return fmt.Errorf("%s states the tracks %v, but the roster declares %v — the roster is what the engine reads,"+
			" so one of them is wrong", pa.repo, stated, m.Tracks)
	}

	return nil
}

// statedTracks reads the caller's tracks into spec order, refusing
// none, an unknown name, or the same name twice.
func statedTracks(spec string) ([]string, error) {
	fields := strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	if len(fields) == 0 {
		return nil, errors.New("no tracks stated — a caller that names no track has asked nothing to be judged")
	}

	seen := map[string]bool{}

	for _, f := range fields {
		if _, ok := level.TrackByName(f); !ok {
			return nil, fmt.Errorf("the stated track %q is no track this release judges", f)
		}

		if seen[f] {
			return nil, fmt.Errorf("the stated track %q is named twice", f)
		}

		seen[f] = true
	}

	var out []string

	for _, t := range level.Tracks() {
		if seen[t.Key()] {
			out = append(out, t.Key())
		}
	}

	return out, nil
}

// printPopulation writes the document where asked.
func printPopulation(path string, doc *population.Document, stdout, stderr io.Writer) int {
	out := &latch{w: stderr}

	if err := writeJSONDoc(path, doc, stdout, out); err != nil {
		return say(stderr, exitIO, "derive population: %v", err)
	}

	if out.err != nil {
		return exitIO
	}

	return exitOK
}

// say writes one line to stderr and returns the code, or the stream
// failure's code when the line cannot be written.
func say(stderr io.Writer, code int, format string, args ...any) int {
	if _, err := fmt.Fprintf(stderr, format+"\n", args...); err != nil {
		return exitIO
	}

	return code
}
