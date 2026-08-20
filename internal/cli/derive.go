// The derive verb: argument surface for the derivation modes. `derive
// version` reads a git history and reports the release its conventional
// commits call for — the decision every other release step waits on.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/convcommit"
	"github.com/monumental-archive/stele/internal/derive"
	"github.com/monumental-archive/stele/internal/gitrepo"
)

// The derivation modes, the dispatch vocabulary.
const deriveVersion = "version"

// notesRefUnused is passed to gitrepo.Open because the ledger is not
// this verb's business; the history reads never touch it.
const notesRefUnused = "refs/notes/commits"

// The derive-side effect seam, swapped only by tests — the same pattern
// as the verify and emit seams.
//
//nolint:gochecknoglobals // test seam, written only by test setup
var openDeriveGit = func(dir string) (deriveHistory, error) {
	return gitrepo.Open(dir, notesRefUnused)
}

// deriveHistory is the history a version decision reads. Narrow on
// purpose: this verb never writes, never networks, and never touches
// the ledger, and a seam that could is a seam that will.
type deriveHistory interface {
	Tags(ref string) ([]string, error)
	AllTags() ([]string, error)
	Commits(from, to string, paths ...string) ([]string, error)
	Message(rev string) (string, error)
	CommitTime(rev string) (string, error)
}

// derived is one reading of a history: the base, the range, and the
// decision they produce. Both modes take it from here rather than each
// deriving its own, because notes describing a different release than
// the one being cut is exactly what two independent readings drift into.
type derived struct {
	history  deriveHistory
	base     derive.Base
	decision derive.Decision
	commits  []convcommit.Commit
	ref      string
}

// date reads the release date from the ref being released.
//
// Never a wall clock: a renderer that reads the time renders a different
// document every run, and the release date IS the date of what is
// released.
//
// And normalised to UTC, which is not pedantry. Git records the
// committer's own offset, so the calendar date inside that timestamp is
// the date where the committer was sitting: a commit made at
// 2026-08-16T03:30+05:00 is 2026-08-15T22:30Z, and reading its leading
// characters dates the release a day later than the rest of the world
// saw it. Measured against a published changelog, which is how it was
// found. One instant, one date, wherever it was authored.
func (d *derived) date() (string, error) {
	stamp, err := d.history.CommitTime(d.ref)
	if err != nil {
		return "", err
	}

	at, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return "", fmt.Errorf("derive: %s reported no usable commit date (%q): %w", d.ref, stamp, err)
	}

	return at.UTC().Format(time.DateOnly), nil
}

// deriveArgs is everything `derive version` reads.
type deriveArgs struct {
	gitDir    string
	ref       string
	prefix    string
	minor     string
	silent    string
	paths     string
	releaseAs string
	zeroX     bool
}

// deriveCmd dispatches `stele derive <mode>`.
func deriveCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		if _, err := fmt.Fprintln(stderr,
			"stele derive: a mode is required: version, notes, bump, release-plan, sbom, claims, facts, vex or"+
				" vex-subjects"); err != nil {
			return exitIO
		}

		return exitUsage
	}

	mode := args[0]
	switch mode {
	case deriveVersion, deriveNotes, deriveBump, deriveReleasePlan, deriveSBOM, deriveClaims, deriveFacts,
		deriveVEX, deriveVEXSubjects:
	default:
		if _, err := fmt.Fprintf(stderr,
			"stele derive: unknown mode %q (version, notes, bump, release-plan, sbom, claims, facts, vex,"+
				" vex-subjects)\n", mode); err != nil {
			return exitIO
		}

		return exitUsage
	}

	// vex-subjects walks the org's published inventories rather than
	// local ones: which releases a decision reaches is a fact about
	// what is published, so it shares the assert engine's walk.
	if mode == deriveVEXSubjects {
		va, code := parseVEXSubjectsArgs(args[1:], stderr)
		if code != exitOK {
			return code
		}

		return runDeriveMode(va.out, stdout, stderr,
			func(doc io.Writer, log *latch) error { return runDeriveVEXSubjects(va, doc, log) })
	}

	// vex scans inventories and renders a document.
	if mode == deriveVEX {
		va, code := parseVEXArgs(args[1:], stderr)
		if code != exitOK {
			return code
		}

		return runDeriveMode(va.out, stdout, stderr,
			func(doc io.Writer, log *latch) error { return runDeriveVEX(va, doc, log) })
	}

	// facts reads a named checkout and the forge, and reports
	// key=value lines rather than a document.
	if mode == deriveFacts {
		fa, code := parseFactsArgs(args[1:], stderr)
		if code != exitOK {
			return code
		}

		out := &latch{w: stdout}

		return finishDerive(runDeriveFacts(fa, out), out, stderr)
	}

	// claims reads the forge, not a git history: no --git-dir, no
	// range, nothing in common with the version derivation but the
	// verb.
	if mode == deriveClaims {
		ca, code := parseClaimsArgs(args[1:], stderr)
		if code != exitOK {
			return code
		}

		return runDeriveMode(ca.out, stdout, stderr,
			func(doc io.Writer, log *latch) error { return runDeriveClaims(ca, doc, log) })
	}

	// sbom reads binaries, not a git history; it shares nothing with
	// the version derivation but the verb.
	if mode == deriveSBOM {
		sa, code := parseSBOMArgs(args[1:], stderr)
		if code != exitOK {
			return code
		}

		return runDeriveMode(sa.out, stdout, stderr,
			func(doc io.Writer, log *latch) error { return runDeriveSBOM(sa, doc, log) })
	}

	da, na, bump, plan, code := parseDeriveArgs(mode, args[1:], stderr)
	if code != exitOK {
		return code
	}

	// The plan writes a document, so it owns stdout the way every other
	// document mode does: the payload alone when no --out is named.
	if mode == deriveReleasePlan {
		return runDeriveMode(plan.out, stdout, stderr,
			func(doc io.Writer, log *latch) error { return runDeriveReleasePlan(da, na, plan, doc, log) })
	}

	out := &latch{w: stdout}

	return finishDerive(runDerive(mode, da, na, bump, out), out, stderr)
}

// finishDerive maps one mode's outcome onto its exit code: a broken
// stream is exitIO, a refusal is exitRefused. Shared so a new mode
// cannot invent a third mapping.
func finishDerive(err error, out *latch, stderr io.Writer) int {
	if out.err != nil {
		return exitIO
	}

	if err != nil {
		if _, werr := fmt.Fprintf(stderr, "%v\n", err); werr != nil {
			return exitIO
		}

		return exitRefused
	}

	return exitOK
}

// parseDeriveArgs reads the flag surface.
func parseDeriveArgs(
	mode string, args []string, stderr io.Writer,
) (*deriveArgs, *notesArgs, *bumpArgs, *planArgs, int) {
	da, na, bump, plan := &deriveArgs{}, &notesArgs{}, &bumpArgs{}, &planArgs{}

	fs := flag.NewFlagSet("stele derive "+mode, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&da.gitDir, "git-dir", "", "local clone with full history and tags fetched (required)")
	fs.StringVar(&da.ref, "ref", "HEAD", "revision the release would be cut from")
	fs.StringVar(&da.prefix, "tag-prefix", derive.DefaultTagPrefix,
		"tag namespace to release within; one history may carry several")
	fs.StringVar(&da.paths, "paths", "",
		"comma-separated paths this component owns; only commits touching them count. "+
			"One history releasing several components needs this, or each derives the others' changes")
	fs.StringVar(&da.minor, "minor-types", "feat", "comma-separated commit types that raise the minor")
	fs.StringVar(&da.silent, "silent-types", "chore,ci,docs,style,test",
		"comma-separated commit types that release nothing; every other type is a patch")
	fs.StringVar(&da.releaseAs, "release-as", "",
		"release this exact version instead of the derived one; refused unless it is an increase over the "+
			"derived base and a name the namespace has not taken. The decision reports as declared")
	fs.BoolVar(&da.zeroX, "zero-major-bumps-minor", true,
		"below 1.0.0, raise the minor for a breaking change rather than declaring 1.0.0")

	if mode == deriveNotes || mode == deriveReleasePlan {
		fs.StringVar(&na.groups, "groups", "feat=Added,fix=Fixed,perf=Changed,docs=Documentation",
			"comma-separated type=Heading pairs, scoped keys like chore(deps)=Deps win over the bare type;"+
				" a type with no heading writes no entry, and an explicit empty heading (chore(canon)=)"+
				" declares silence for exactly that key while the bare type keeps its heading")
		fs.StringVar(&na.order, "group-order", "Breaking,Added,Changed,Fixed,Documentation",
			"headings in the order they render; rendering never depends on map order")
		fs.StringVar(&na.breaking, "breaking-group", "Breaking",
			"heading breaking changes are lifted into; empty leaves them in their type's group")
		fs.StringVar(&na.compareURL, "compare-url", "",
			"URL prefix a <previous>...<version> range appends to; empty renders plain text")
		fs.StringVar(&na.releaseURL, "release-url", "",
			"URL prefix a lone tag appends to, used for a first release")
		fs.StringVar(&na.pullURL, "pull-url", "", "URL prefix a pull request number appends to")
		fs.StringVar(&na.date, "date", "",
			"release date; defaults to the committer date of --ref, never a wall clock")
		fs.StringVar(&na.changelog, "changelog", "",
			"changelog to splice the section into, above its newest section; empty prints instead")
	}

	if mode == deriveReleasePlan {
		registerPlanFlags(fs, plan)
	}

	if mode == deriveBump {
		fs.BoolVar(&bump.check, "check", false,
			"assert every mirror carries the version last released, rewriting nothing; "+
				"the drift gate a CI run holds between releases. Mirrors carrying exactly "+
				"the version this range derives are the release being cut (check=pending), "+
				"not drift")
		fs.StringVar(&bump.date, "date", "",
			"release date for CITATION.cff's date-released; defaults to the committer date of --ref, never a wall clock")
	}

	if err := fs.Parse(args); err != nil {
		return da, na, bump, plan, exitUsage
	}

	if da.gitDir == "" {
		if _, err := fmt.Fprintf(stderr, "stele derive %s: --git-dir is required\n", mode); err != nil {
			return da, na, bump, plan, exitIO
		}

		return da, na, bump, plan, exitUsage
	}

	return da, na, bump, plan, exitOK
}

// runDerive dispatches the mode onto the shared derivation.
func runDerive(mode string, da *deriveArgs, na *notesArgs, bump *bumpArgs, out *latch) error {
	switch mode {
	case deriveNotes:
		return runDeriveNotes(da, na, out)
	case deriveBump:
		return runDeriveBump(da, bump, out)
	default:
		return runDeriveVersion(da, out)
	}
}

// splitTypes reads a comma-separated type list, dropping the empty
// string a bare "" or a trailing comma would otherwise contribute.
func splitTypes(s string) []string {
	var out []string

	for part := range strings.SplitSeq(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}

	return out
}

// deriveRelease is the whole derivation: find the namespace's latest
// release, read the commits since it, and decide what they call for.
func deriveRelease(da *deriveArgs, out *latch) (*derived, error) {
	rules, err := derive.NewRules(splitTypes(da.minor), splitTypes(da.silent), da.zeroX)
	if err != nil {
		return nil, err
	}

	history, err := openDeriveGit(da.gitDir)
	if err != nil {
		return nil, err
	}

	tags, err := history.Tags(da.ref)
	if err != nil {
		return nil, err
	}

	base := derive.LatestTag(da.prefix, tags)

	// Named, never merely dropped: a base reached by ignoring tags is
	// not the same fact as a base with nothing to ignore, and a reader
	// of a clean run must not have to guess which they got.
	for _, skipped := range base.Skipped {
		out.logf("skipped %q: in the %q namespace but not a version", skipped, da.prefix)
	}

	from := ""
	if base.Version != nil {
		from = derive.Tag(da.prefix, base.Version)
	}

	commits, unconventional, err := readRange(history, from, da.ref, splitTypes(da.paths))
	if err != nil {
		return nil, err
	}

	// Counted and reported rather than silently dropped. A break stated
	// only in prose is invisible to every implementation of this format,
	// so the honest thing is to say how much prose was in the range.
	if unconventional > 0 {
		out.logf("%d commit(s) in the range are not conventional and cast no vote", unconventional)
	}

	// A namespace with no release starts from 0.0.0, so a first feature
	// lands on 0.1.0. Stated here rather than defaulted inside the
	// engine: "never released" and "released 0.0.0" are different facts,
	// and only the caller knows which one it is looking at.
	start := base.Version
	if start == nil {
		start = derive.Unreleased()

		out.logf("no release in the %q namespace; deriving the first one", da.prefix)
	}

	decision, err := rules.Decide(start, commits)
	if err != nil {
		return nil, err
	}

	out.logf("base %s, %d commit(s) in range", start, len(commits))

	if da.releaseAs != "" {
		if decision, err = declare(da, history, decision, out); err != nil {
			return nil, err
		}
	}

	return &derived{history: history, base: base, decision: decision, commits: commits, ref: da.ref}, nil
}

// declare judges the caller's declared version against the derivation.
// The names already taken come from every tag in the repository, not
// from the ones this ref descends from: reachability is the right
// question for measuring a range and the wrong one for minting a name
// (gitrepo.AllTags).
func declare(da *deriveArgs, history deriveHistory, decision derive.Decision, out *latch) (derive.Decision, error) {
	version, err := semver.StrictNewVersion(da.releaseAs)
	if err != nil {
		return derive.Decision{}, fmt.Errorf("derive: --release-as %q: %w", da.releaseAs, err)
	}

	all, err := history.AllTags()
	if err != nil {
		return derive.Decision{}, err
	}

	taken, skipped := derive.Versions(da.prefix, all)

	// Named for the same reason LatestTag's are: a name checked against
	// a set something was quietly dropped from is a weaker check than
	// the reader is being shown.
	for _, tag := range skipped {
		out.logf("skipped %q: in the %q namespace but not a version", tag, da.prefix)
	}

	declared, err := decision.Declare(version, taken)
	if err != nil {
		return derive.Decision{}, err
	}

	out.logf("declared %s over the derived base %s", version, declared.Base())

	return declared, nil
}

// runDeriveVersion reports the decision.
func runDeriveVersion(da *deriveArgs, out *latch) error {
	d, err := deriveRelease(da, out)
	if err != nil {
		return err
	}

	return reportVersion(da.prefix, d, out)
}

// readRange lists the commits a release would cover and parses each
// message, counting the ones that say nothing about versioning.
func readRange(history deriveHistory, from, to string, paths []string) ([]convcommit.Commit, int, error) {
	revs, err := history.Commits(from, to, paths...)
	if err != nil {
		return nil, 0, err
	}

	commits := make([]convcommit.Commit, 0, len(revs))
	unconventional := 0

	for _, rev := range revs {
		message, msgErr := history.Message(rev)
		if msgErr != nil {
			return nil, 0, msgErr
		}

		commit, parseErr := convcommit.Parse(message)
		if parseErr != nil {
			if errors.Is(parseErr, convcommit.ErrNotConventional) {
				unconventional++

				continue
			}

			return nil, 0, parseErr
		}

		commits = append(commits, commit)
	}

	return commits, unconventional, nil
}

// reportVersion renders the decision.
func reportVersion(prefix string, d *derived, out *latch) error {
	decision := d.decision

	next, releases := decision.Next()
	if !releases {
		out.logf("release=false")
		out.logf("nothing to release: no version-bumping commits since %s", decision.Base())

		return nil
	}

	// Requested and applied are both stated. They differ exactly when a
	// 0.x line absorbed a breaking change into its minor, or when a
	// human declared the number, and a reader told only the applied
	// bump would conclude the range asked for it.
	switch {
	case decision.Declared():
		out.logf("bump=%s (declared; the range requested %s)", decision.Applied(), decision.Requested())
	case decision.Requested() != decision.Applied():
		out.logf("bump=%s (requested %s, absorbed by the 0.x rule)", decision.Applied(), decision.Requested())
	default:
		out.logf("bump=%s", decision.Applied())
	}

	out.logf("declared=%t", decision.Declared())
	out.logf("release=true")
	out.logf("version=%s", next)
	out.logf("tag=%s", derive.Tag(prefix, next))

	return nil
}

// runDeriveMode runs one mode that writes its own document, mapping
// the two failure kinds onto their exit codes: a broken stream is
// exitIO, a refusal is exitRefused. Shared so a new mode cannot
// invent a third mapping.
//
// It also decides who owns stdout. When the document is going there
// (no --out), progress moves to stderr: a caller piping the payload
// into a job output must receive the payload and nothing else, and a
// progress line in the middle of a JSON document is a corruption that
// only shows up in production. When the document has a file of its
// own, progress keeps stdout.
func runDeriveMode(docPath string, stdout, stderr io.Writer, run func(io.Writer, *latch) error) int {
	logTo := stdout
	if docPath == "" {
		logTo = stderr
	}

	out := &latch{w: logTo}

	return finishDerive(run(stdout, out), out, stderr)
}
