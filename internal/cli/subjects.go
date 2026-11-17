// `derive subjects`: the digests a build's provenance names, computed
// against the legs its matrix planned (stele#393). The class
// definitions — what one planned leg leaves behind — are the release
// contract's own (internal/release); this file is the argument surface
// and the placement, nothing else.
//
// The planned legs arrive as DATA, the build workflow's own `expected`
// list, never as a name pattern: which names a leg produces is the
// class's definition, and a pattern on the command line would be a
// second one. The lines are printed and, when asked, written to
// files; writing them to GITHUB_OUTPUT stays the workflow's one line.

package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/release"
)

// deriveSubjects is the mode name.
const deriveSubjects = "subjects"

// subjectsArgs is the mode's whole argument surface.
type subjectsArgs struct {
	class          string
	expected       string
	dir            string
	subjectsOut    string
	legSubjectsOut string
	registryOut    string
	assetClass     *release.AssetClass
	registryClass  *release.RegistryClass
}

// parseSubjectsArgs parses and validates the flags.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseSubjectsArgs(args []string, stderr io.Writer) (*subjectsArgs, int) {
	sa := &subjectsArgs{}

	flags := flag.NewFlagSet("stele derive subjects", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&sa.class, "class", "", "the evidence class whose build this is (required)")
	flags.StringVar(&sa.expected, "expected", "",
		"path to the planned legs, the build matrix's JSON list of strings; /dev/stdin reads a pipe (required)")
	flags.StringVar(&sa.dir, "dir", "",
		"directory holding the built assets, or the digest documents for a registry class (required)")
	flags.StringVar(&sa.subjectsOut, "subjects-out", "", "file to write the subject lines to as well")
	flags.StringVar(&sa.legSubjectsOut, "leg-subjects-out", "", "file to write the leg-grouped subject lines to")
	flags.StringVar(&sa.registryOut, "registry-subjects-out", "",
		"file to write a registry class's subject lines to as well")

	if err := flags.Parse(args); err != nil {
		return sa, exitUsage
	}

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele derive subjects: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch {
	case flags.NArg() > 0:
		return sa, usageFail(fmt.Sprintf("unexpected argument %q", flags.Arg(0)))
	case sa.class == "":
		return sa, usageFail("--class is required")
	case sa.expected == "":
		return sa, usageFail("--expected is required")
	case sa.dir == "":
		return sa, usageFail("--dir is required")
	}

	if c, ok := release.AssetClassNamed(sa.class); ok {
		sa.assetClass = c
		if sa.registryOut != "" {
			return sa, usageFail(fmt.Sprintf(
				"--registry-subjects-out: %s ships files, not registry subjects", sa.class,
			))
		}

		return sa, exitOK
	}

	if c, ok := release.RegistryClassNamed(sa.class); ok {
		sa.registryClass = c
		if sa.subjectsOut != "" || sa.legSubjectsOut != "" {
			return sa, usageFail(fmt.Sprintf(
				"--subjects-out and --leg-subjects-out: %s publishes to a registry; its lines are"+
					" --registry-subjects-out", sa.class,
			))
		}

		return sa, exitOK
	}

	// A class the release contract knows for its inventory alone is not
	// unknown: it has no subjects defined, and says so by name.
	if release.ClassDefined(sa.class) {
		return sa, usageFail(fmt.Sprintf("class %q has no file or registry subjects defined: subjects are defined"+
			" for %s", sa.class, strings.Join(release.SubjectClasses(), ", ")))
	}

	return sa, usageFail(fmt.Sprintf("unknown class %q: subjects are defined for %s",
		sa.class, strings.Join(release.SubjectClasses(), ", ")))
}

// runDeriveSubjects computes the lines, then places them. Nothing is
// written until the whole set has been judged, so a refused set
// leaves no file a later step could mistake for a manifest.
func runDeriveSubjects(sa *subjectsArgs, out *latch) error {
	planned, err := readPlannedLegs(sa.expected)
	if err != nil {
		return err
	}

	var (
		primary []byte
		files   = map[string][]byte{}
	)

	if sa.registryClass != nil {
		r, rerr := sa.registryClass.RegistrySubjects(sa.dir, planned)
		if rerr != nil {
			return fmt.Errorf("derive subjects: %w", rerr)
		}

		primary = r.Bytes()
		files[sa.registryOut] = primary
	} else {
		m, merr := sa.assetClass.Subjects(sa.dir, planned)
		if merr != nil {
			return fmt.Errorf("derive subjects: %w", merr)
		}

		primary = m.SubjectLines()
		files[sa.subjectsOut] = primary
		files[sa.legSubjectsOut] = m.LegLines()
	}

	for path, content := range files {
		if path == "" {
			continue
		}

		if err := os.WriteFile(path, content, ownerRW); err != nil {
			return fmt.Errorf("derive subjects: writing %s: %w", path, err)
		}
	}

	// The lines the shell printed, so a run's log shows what was
	// computed.
	if out.err == nil {
		_, out.err = out.w.Write(primary)
	}

	return nil
}

// readPlannedLegs reads the matrix's planned list: a JSON array of
// strings, each present. A null in it is refused rather than read as
// an empty leg.
func readPlannedLegs(path string) ([]string, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the --expected flag; reading where asked is the feature
	if err != nil {
		return nil, fmt.Errorf("derive subjects: reading the planned legs: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only close

	list, err := jsonx.Decode[[]*string](f)
	if err != nil {
		return nil, fmt.Errorf("derive subjects: the planned legs in %s are not a JSON list of strings: %w", path, err)
	}

	planned := make([]string, 0, len(*list))

	for i, entry := range *list {
		if entry == nil {
			return nil, fmt.Errorf("derive subjects: planned leg %d in %s is null", i, path)
		}

		planned = append(planned, *entry)
	}

	return planned, nil
}
