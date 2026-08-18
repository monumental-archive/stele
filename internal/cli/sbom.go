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
	"strings"

	"github.com/monumental-archive/stele/internal/cargo"
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

	// The Cargo path: an artifact's own closure, scoped to the package
	// that ships it (.github#492).
	cargoRoot string
	tree      string
	target    string
	created   string
	unionOf   string
	unionName string
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
	fs.StringVar(&sa.cargoRoot, "cargo-package", "",
		"derive from this Cargo package's own resolved closure rather than from binaries — "+
			"the inventory of one artifact, not of the workspace that built it")
	fs.StringVar(&sa.tree, "tree", "", "workspace root to resolve in (with --cargo-package)")
	fs.StringVar(&sa.target, "target", "",
		"target triple the artifact was built for; empty resolves without platform filtering")
	fs.StringVar(&sa.created, "created", "",
		"the artifact's own instant, RFC 3339, never a clock reading (with --cargo-package or --union)")
	fs.StringVar(&sa.unionOf, "union", "",
		"comma-separated per-artifact documents to aggregate into the release view; "+
			"the view is folded from them, never derived a second time")
	fs.StringVar(&sa.unionName, "union-name", "", "the release the aggregated view describes (with --union)")

	if err := fs.Parse(args); err != nil {
		return sa, exitUsage
	}

	sa.binaries = fs.Args()
	if sa.cargoRoot != "" || sa.unionOf != "" {
		return sa, exitOK
	}

	if len(sa.binaries) == 0 {
		if _, err := fmt.Fprintln(stderr, "stele derive sbom: at least one binary path is required"); err != nil {
			return sa, exitIO
		}

		return sa, exitUsage
	}

	return sa, exitOK
}

// runDeriveSBOM dispatches the three sources: an artifact's Cargo
// closure, an aggregation of per-artifact documents, or the shipped
// binaries' embedded module lists.
func runDeriveSBOM(sa *sbomArgs, doc io.Writer, out *latch) error {
	switch {
	case sa.cargoRoot != "" && sa.unionOf != "":
		return errors.New("derive sbom: --cargo-package and --union are exclusive: one derives, one aggregates")
	case sa.cargoRoot != "":
		return runDeriveCargoSBOM(sa, doc, out)
	case sa.unionOf != "":
		return runDeriveUnion(sa, doc, out)
	}

	return runDeriveBinarySBOM(sa, doc, out)
}

// runDeriveBinarySBOM reads every leg, unions the platform legs, and
// writes the document where asked.
func runDeriveBinarySBOM(sa *sbomArgs, doc io.Writer, out *latch) error {
	bins := make([]sbom.Binary, 0, len(sa.binaries))

	for _, path := range sa.binaries {
		info, err := readBinary(path)
		if err != nil {
			return fmt.Errorf("derive sbom: %s: %w", path, err)
		}

		bins = append(bins, sbom.Binary{Name: path, Info: info})
	}

	document, err := sbom.Derive(bins, "stele-"+selfVersion())
	if err != nil {
		return err
	}

	root := document.Packages[0]

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

	if err := writeJSONDoc(sa.out, document, doc, out); err != nil {
		return err
	}

	out.logf("%s@%s: %d packages, %d platform(s)", root.Name, root.VersionInfo, len(document.Packages), len(bins))

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

// The Cargo resolver seam, swapped only by tests: resolving for real
// needs a workspace and a toolchain, which would test cargo rather
// than this wiring.
//
//nolint:gochecknoglobals // test seam, written only by test setup
var newCargoResolver = func() cargo.Resolver { return cargo.Runner{} }

// runDeriveCargoSBOM derives one artifact's inventory from its own
// resolved closure — the .github#492 rule that the unit of description
// is the artifact, because the artifact is the unit of consumption.
func runDeriveCargoSBOM(sa *sbomArgs, doc io.Writer, out *latch) error {
	switch {
	case sa.tree == "":
		return errors.New("derive sbom: --tree is required with --cargo-package")
	case sa.created == "":
		return errors.New("derive sbom: --created is required — an artifact's inventory is dated by the" +
			" artifact, never by the run that described it")
	}

	metadata, err := newCargoResolver().Metadata(sa.tree, sa.target)
	if err != nil {
		return err
	}

	closure, err := cargo.Closure(metadata, sa.cargoRoot)
	if err != nil {
		return err
	}

	deps := make([]sbom.Package, 0, len(closure))
	for _, pkg := range closure {
		deps = append(deps, sbom.CargoPackage(pkg.Name, pkg.Version))
	}

	document, err := sbom.FromPackages(deps[0].Name+"@"+deps[0].VersionInfo, sa.created,
		"stele-"+selfVersion(), deps)
	if err != nil {
		return err
	}

	if err := writeJSONDoc(sa.out, document, doc, out); err != nil {
		return err
	}

	out.logf("%s: %d packages", document.Name, len(document.Packages))

	return nil
}

// runDeriveUnion folds per-artifact documents into the release view.
// Its input is documents and nothing else, so the view cannot be
// derived a second time from a tree.
func runDeriveUnion(sa *sbomArgs, doc io.Writer, out *latch) error {
	switch {
	case sa.unionName == "":
		return errors.New("derive sbom: --union-name is required — the view must name the release it describes")
	case sa.created == "":
		return errors.New("derive sbom: --created is required, and it is the release's own instant")
	}

	var docs []*sbom.Document

	for path := range strings.SplitSeq(sa.unionOf, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}

		body, err := os.ReadFile(path) //nolint:gosec // the caller names the documents to aggregate
		if err != nil {
			return fmt.Errorf("derive sbom: %w", err)
		}

		parsed, err := jsonx.DecodeForeign[sbom.Document](body)
		if err != nil {
			return fmt.Errorf("derive sbom: %s: %w", path, err)
		}

		docs = append(docs, parsed)
	}

	view, err := sbom.Union(sa.unionName, sa.created, "stele-"+selfVersion(), docs)
	if err != nil {
		return err
	}

	if err := writeJSONDoc(sa.out, view, doc, out); err != nil {
		return err
	}

	out.logf("%s: %d packages aggregated from %d artifact(s)", view.Name, len(view.Packages)-1, len(docs))

	return nil
}
