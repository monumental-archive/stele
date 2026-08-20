// The surface statements, held to the binary. MAINTENANCE.md is where
// "breaking" acquires a referent, and it had drifted into promising a
// `verify level` mode retired at #125 while omitting the whole assert
// verb, four derive modes and two of the five exit codes (stele#146).
// The synopsis had drifted the other way: `assert plans` shipped at
// #142 and `assert permissions` at #165, and neither reached it.
//
// So the oracle is the DISPATCH, not the synopsis: every verb refuses
// a missing mode by enumerating the ones it accepts, right beside the
// switch that accepts them, and that enumeration is what the synopsis
// and the document are both held to. Anchoring on the synopsis would
// have left exactly the gap that let two targets ship unmentioned.

package cli

import (
	"bytes"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The two shapes this file reads: a synopsis verb at two spaces with
// its modes at four, and the enumeration every verb prints when its
// mode is missing.
var (
	verbRE = regexp.MustCompile(`(?m)^ {2}stele ([a-z]+)`)
	modeRE = regexp.MustCompile(`(?m)^ {4}([a-z][a-z-]*) +\S`)
	// Multi-line: a verb whose refusal also points at a form that is
	// not a mode (level's board) carries that on its own line, so the
	// mode list stays exactly the modes.
	refusaRE = regexp.MustCompile(`(?m)^stele [a-z]+: an? [a-z]+ is required: (.+)$`)
)

// The exit codes this binary can answer with, named where they are
// defined rather than spelled again as literals. The synopsis is held
// to exactly this set, so a sixth code cannot reach a caller
// unannounced — and cannot be announced without existing.
var exitCodes = []string{"0", "1", "2", "3", "4"}

// TestExitCodesAreTheOnesDefined pins the list above to the constants
// beside it: a renumbering that edited one and not the other would
// leave every other test in this file checking the wrong vocabulary.
func TestExitCodesAreTheOnesDefined(t *testing.T) {
	t.Parallel()

	defined := []int{exitOK, exitRefused, exitUsage, exitIO, exitBlind}
	if len(defined) != len(exitCodes) {
		t.Fatalf("%d codes defined, %d under test", len(defined), len(exitCodes))
	}

	for i, code := range defined {
		if got := strconv.Itoa(code); got != exitCodes[i] {
			t.Errorf("code %d is %s, the surface calls it %s", i, got, exitCodes[i])
		}
	}
}

// synopsis renders `stele help`.
func synopsis(t *testing.T) string {
	t.Helper()

	var help bytes.Buffer
	if err := usage(&help); err != nil {
		t.Fatalf("rendering the synopsis: %v", err)
	}

	return help.String()
}

// verbs lists the commands the synopsis names. There is no refusal
// that enumerates verbs — an unknown one points at `stele help` —
// so this is the statement, and every verb it names is proven
// dispatchable by the mode read that follows.
func verbs(t *testing.T) []string {
	t.Helper()

	var out []string

	for _, m := range verbRE.FindAllStringSubmatch(synopsis(t), -1) {
		if !slices.Contains(out, m[1]) {
			out = append(out, m[1])
		}
	}

	if len(out) < 7 {
		t.Fatalf("parsed %v from the synopsis, want help, version and the five verbs", out)
	}

	return out
}

// dispatchModes asks the binary which modes a verb accepts, by making
// it refuse. Two verbs take none: their names are the whole command.
func dispatchModes(t *testing.T, verb string) []string {
	t.Helper()

	var stdout, stderr bytes.Buffer

	if code := Run([]string{verb}, &stdout, &stderr); code != exitUsage {
		return nil
	}

	m := refusaRE.FindStringSubmatch(strings.TrimSpace(stderr.String()))
	if m == nil {
		return nil
	}

	listed := strings.ReplaceAll(m[1], " or ", ", ")

	var out []string

	for mode := range strings.SplitSeq(listed, ", ") {
		if mode = strings.TrimSpace(mode); mode != "" {
			out = append(out, mode)
		}
	}

	return out
}

// synopsisModes lists the modes the synopsis prints under one verb.
func synopsisModes(t *testing.T, verb string) []string {
	t.Helper()

	var (
		out     []string
		current string
	)

	for line := range strings.SplitSeq(synopsis(t), "\n") {
		if m := verbRE.FindStringSubmatch(line); m != nil {
			current = m[1]

			continue
		}

		if m := modeRE.FindStringSubmatch(line); m != nil && current == verb {
			out = append(out, m[1])
		}
	}

	return out
}

// commands is every invocable command: the bare ones, the verbs, and
// each verb with each mode the dispatch accepts.
func commands(t *testing.T) []string {
	t.Helper()

	var out []string

	for _, verb := range verbs(t) {
		out = append(out, "stele "+verb)

		for _, mode := range dispatchModes(t, verb) {
			out = append(out, "stele "+verb+" "+mode)
		}
	}

	if len(out) < 30 {
		t.Fatalf("parsed %d command(s), want every verb and mode: %v", len(out), out)
	}

	return out
}

// TestSynopsisMatchesTheDispatch holds the two halves of the binary's
// own account of itself together, in both directions: a mode it
// accepts and does not print is a feature nobody can find, and a mode
// it prints and does not accept is a promise it breaks on use.
func TestSynopsisMatchesTheDispatch(t *testing.T) {
	t.Parallel()

	for _, verb := range verbs(t) {
		dispatched := dispatchModes(t, verb)
		printed := synopsisModes(t, verb)

		if len(dispatched) == 0 {
			if len(printed) > 0 {
				t.Errorf("the synopsis prints modes under %q, which takes none: %v", verb, printed)
			}

			continue
		}

		for _, mode := range dispatched {
			if !slices.Contains(printed, mode) {
				t.Errorf("`stele %s %s` dispatches and the synopsis never mentions it", verb, mode)
			}
		}

		for _, mode := range printed {
			if !slices.Contains(dispatched, mode) {
				t.Errorf("the synopsis prints `stele %s %s`, which the dispatch refuses", verb, mode)
			}
		}
	}
}

// TestSynopsisNamesEveryExitCode: a caller told 0 and 2 will read a 4
// as a crash. The codes are part of the answer, so they are part of
// the synopsis.
func TestSynopsisNamesEveryExitCode(t *testing.T) {
	t.Parallel()

	block := regexp.MustCompile(`(?s)exit codes: .*?\n\n`).FindString(synopsis(t))
	if block == "" {
		t.Fatal("the synopsis names no exit codes — a caller cannot tell a refusal from a usage error")
	}

	for _, code := range exitCodes {
		if !regexp.MustCompile(`\b` + code + `\b`).MatchString(block) {
			t.Errorf("the synopsis's exit-code line does not name %s", code)
		}
	}
}

// TestMaintenanceStatesTheSurface: every command the binary dispatches
// and every code it can exit with is a row in MAINTENANCE.md. A mode
// that ships undocumented carries no compatibility promise, which is
// the same as having no maintainer.
func TestMaintenanceStatesTheSurface(t *testing.T) {
	t.Parallel()

	doc := maintenance(t)

	for _, command := range commands(t) {
		if !rowNames(doc, "`"+command+"`") {
			t.Errorf("the binary dispatches %q and MAINTENANCE.md carries no row for it", command)
		}
	}

	for _, code := range exitCodes {
		if !rowNames(doc, "`"+code+"`") {
			t.Errorf("the binary can exit %s and MAINTENANCE.md carries no row for it", code)
		}
	}
}

// TestMaintenanceNamesNothingRetired is the direction that caught the
// original defect: the document promised `verify level` for two
// releases after #125 made level a verb of its own. A promise about a
// command nobody can invoke is worse than no promise — it reads as
// coverage.
func TestMaintenanceNamesNothingRetired(t *testing.T) {
	t.Parallel()

	doc := maintenance(t)
	invocable := commands(t)
	named := regexp.MustCompile("`(stele [a-z]+(?: [a-z][a-z-]*)?)`")

	for line := range strings.SplitSeq(doc, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}

		for _, m := range named.FindAllStringSubmatch(line, -1) {
			if !slices.Contains(invocable, m[1]) {
				t.Errorf("MAINTENANCE.md promises %q, which the binary does not dispatch", m[1])
			}
		}
	}
}

// TestReadmeNamesEveryVerb holds the third statement of the surface to
// the same dispatch. The README's table is per-verb where
// MAINTENANCE.md's is per-mode — the front door describes, the
// maintenance statement enumerates — so this is the check that fits
// it: a sixth verb cannot ship without the front door acquiring a row
// for it. The fourth statement, the repository description, lives on
// the forge and is checked by reading.
func TestReadmeNamesEveryVerb(t *testing.T) {
	t.Parallel()

	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("reading the front door: %v", err)
	}

	for _, verb := range verbs(t) {
		if verb == "help" || verb == cmdVersion {
			// Not commands the front door describes: one prints the
			// synopsis, the other the build's own version.
			continue
		}

		if !rowNames(string(readme), "`"+verb+"`") {
			t.Errorf("the binary dispatches %q and README.md carries no row for it", verb)
		}
	}
}

// maintenance reads the document, refusing an empty one rather than
// passing every check against nothing.
func maintenance(t *testing.T) string {
	t.Helper()

	doc, err := os.ReadFile("../../MAINTENANCE.md")
	if err != nil {
		t.Fatalf("reading the maintenance statement: %v", err)
	}

	if len(doc) == 0 {
		t.Fatal("MAINTENANCE.md is empty")
	}

	return string(doc)
}

// rowNames reports whether the document carries a table row naming
// this token. A row and not a mention: the surface is an enumeration,
// and a command buried in a sentence is not one the table accounts
// for.
func rowNames(doc, token string) bool {
	for line := range strings.SplitSeq(doc, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "|") && strings.Contains(line, token) {
			return true
		}
	}

	return false
}
