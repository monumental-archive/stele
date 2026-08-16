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
	Commits(from, to string, paths ...string) ([]string, error)
	Message(rev string) (string, error)
}

// deriveArgs is everything `derive version` reads.
type deriveArgs struct {
	gitDir string
	ref    string
	prefix string
	minor  string
	silent string
	paths  string
	zeroX  bool
}

// deriveCmd dispatches `stele derive <mode>`.
func deriveCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		if _, err := fmt.Fprintln(stderr, "stele derive: a mode is required: version"); err != nil {
			return exitIO
		}

		return exitUsage
	}

	if args[0] != deriveVersion {
		if _, err := fmt.Fprintf(stderr, "stele derive: unknown mode %q (version)\n", args[0]); err != nil {
			return exitIO
		}

		return exitUsage
	}

	da, code := parseDeriveArgs(args[1:], stderr)
	if code != exitOK {
		return code
	}

	out := &latch{w: stdout}

	err := runDeriveVersion(da, out)
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
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseDeriveArgs(args []string, stderr io.Writer) (*deriveArgs, int) {
	da := &deriveArgs{}

	fs := flag.NewFlagSet("stele derive version", flag.ContinueOnError)
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
	fs.BoolVar(&da.zeroX, "zero-major-bumps-minor", true,
		"below 1.0.0, raise the minor for a breaking change rather than declaring 1.0.0")

	if err := fs.Parse(args); err != nil {
		return da, exitUsage
	}

	if da.gitDir == "" {
		if _, err := fmt.Fprintln(stderr, "stele derive version: --git-dir is required"); err != nil {
			return da, exitIO
		}

		return da, exitUsage
	}

	return da, exitOK
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

// runDeriveVersion is the whole derivation: find the namespace's latest
// release, read the commits since it, and report what they call for.
func runDeriveVersion(da *deriveArgs, out *latch) error {
	rules, err := derive.NewRules(splitTypes(da.minor), splitTypes(da.silent), da.zeroX)
	if err != nil {
		return err
	}

	history, err := openDeriveGit(da.gitDir)
	if err != nil {
		return err
	}

	tags, err := history.Tags(da.ref)
	if err != nil {
		return err
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
		return err
	}

	// Counted and reported rather than silently dropped. A break stated
	// only in prose is invisible to every implementation of this format,
	// so the honest thing is to say how much prose was in the range.
	if unconventional > 0 {
		out.logf("%d commit(s) in the range are not conventional and cast no vote", unconventional)
	}

	return report(rules, da.prefix, base, commits, out)
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

// report renders the decision.
func report(rules derive.Rules, prefix string, base derive.Base, commits []convcommit.Commit, out *latch) error {
	// A namespace with no release starts from 0.0.0, so a first feature
	// lands on 0.1.0. Stated here rather than defaulted inside the
	// engine: "never released" and "released 0.0.0" are different facts,
	// and only the caller knows which one it is looking at.
	start := base.Version
	if start == nil {
		start = derive.Unreleased()

		out.logf("no release in the %q namespace; deriving the first one", prefix)
	}

	decision, err := rules.Decide(start, commits)
	if err != nil {
		return err
	}

	out.logf("base %s, %d commit(s) in range", start, len(commits))

	next, releases := decision.Next()
	if !releases {
		out.logf("release=false")
		out.logf("nothing to release: no version-bumping commits since %s", start)

		return nil
	}

	// Requested and applied are both stated. They differ exactly when a
	// 0.x line absorbed a breaking change into its minor, and a reader
	// told only the applied bump would conclude nothing broke.
	if decision.Requested() != decision.Applied() {
		out.logf("bump=%s (requested %s, absorbed by the 0.x rule)", decision.Applied(), decision.Requested())
	} else {
		out.logf("bump=%s", decision.Applied())
	}

	out.logf("release=true")
	out.logf("version=%s", next)
	out.logf("tag=%s", derive.Tag(prefix, next))

	return nil
}
