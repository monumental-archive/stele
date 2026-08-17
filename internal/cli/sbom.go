// `derive sbom`: the release SBOM read out of the shipped binaries'
// embedded module lists (#46) — never from the source tree, whose scan
// describes what could have been linked rather than what was.

package cli

import (
	"debug/buildinfo"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/sbom"
)

// deriveSBOM is the mode name.
const deriveSBOM = "sbom"

// The binary-reading seam, swapped only by tests: constructing real
// per-case Go binaries to exercise refusal branches would test the
// toolchain, not the guards.
//
//nolint:gochecknoglobals // test seam, written only by test setup
var readBinary = buildinfo.ReadFile

// sbomArgs is everything `derive sbom` reads.
type sbomArgs struct {
	binaries      []string
	out           string
	expectVersion string
}

// parseSBOMArgs reads the flag surface. The binaries are positional:
// they are file paths, and a comma-separated flag would make a legal
// path unspellable.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseSBOMArgs(args []string, stderr io.Writer) (*sbomArgs, int) {
	sa := &sbomArgs{}

	fs := flag.NewFlagSet("stele derive sbom", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&sa.out, "out", "", "file to write the SPDX document to; empty prints to stdout")
	fs.StringVar(&sa.expectVersion, "expect-version", "",
		"version the pipeline believes it is releasing; refused unless the binaries agree. "+
			"A bare number is read as its v-prefixed tag")

	if err := fs.Parse(args); err != nil {
		return sa, exitUsage
	}

	sa.binaries = fs.Args()
	if len(sa.binaries) == 0 {
		if _, err := fmt.Fprintln(stderr, "stele derive sbom: at least one binary path is required"); err != nil {
			return sa, exitIO
		}

		return sa, exitUsage
	}

	return sa, exitOK
}

// runDeriveSBOM reads every leg, derives the union document, and
// writes it where asked.
func runDeriveSBOM(sa *sbomArgs, out *latch) error {
	bins := make([]sbom.Binary, 0, len(sa.binaries))

	for _, path := range sa.binaries {
		info, err := readBinary(path)
		if err != nil {
			return fmt.Errorf("derive sbom: %s: %w", path, err)
		}

		bins = append(bins, sbom.Binary{Name: path, Info: info})
	}

	doc, err := sbom.Derive(bins, "stele-"+selfVersion())
	if err != nil {
		return err
	}

	root := doc.Packages[0]

	// The cross-check, not the source: the version in the document came
	// from the artifact, and the pipeline's belief is only allowed to
	// agree or to stop the release.
	if sa.expectVersion != "" {
		want := sa.expectVersion
		if want[0] != 'v' {
			want = "v" + want
		}

		if root.VersionInfo != want {
			return fmt.Errorf("derive sbom: the binaries are %s@%s but the release believes it is cutting %s — "+
				"the build did not check out the tag it is publishing", root.Name, root.VersionInfo, want)
		}
	}

	if err := writeDoc(sa.out, doc, out); err != nil {
		return err
	}

	out.logf("%s@%s: %d packages, %d platform(s)", root.Name, root.VersionInfo, len(doc.Packages), len(bins))

	return nil
}

// writeDoc places the document: a named file, or the latch's stream
// when unnamed — through the latch, so a failed stdout write is the
// same exitIO every other stream failure is.
func writeDoc(path string, doc *sbom.Document, out *latch) error {
	if path == "" {
		if out.err == nil {
			out.err = jsonx.Encode(out.w, doc)
		}

		return nil
	}

	f, err := os.Create(path) //nolint:gosec // the path is the --out flag; writing where asked is the feature
	if err != nil {
		return fmt.Errorf("derive sbom: %w", err)
	}

	if err := jsonx.Encode(f, doc); err != nil {
		return errors.Join(err, f.Close())
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("derive sbom: %w", err)
	}

	return nil
}

// selfVersion names this binary in the document's creator field, read
// from its own build info the same way `stele version` reports it.
func selfVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}

	return develVersion
}
