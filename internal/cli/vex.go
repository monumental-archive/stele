// `derive vex`: this release's own coverage document, derived from
// the inventories it ships and the decisions a human recorded (#40).
//
// The input is a set of (subject, inventory) PAIRS from the first
// line of code, not a directory glob resolving to one document. Today
// a caller passes one pair; under per-artifact inventories it passes
// several, and the statements then name the artifact a consumer
// actually holds rather than the release that contained it. Building
// it any other way would mean cutting this mechanism over twice.
//
// The undecided refusal lives here rather than in a judging verb
// because it is not a gate bolted onto a derivation — it IS the
// derivation refusing bad input. A coverage document for a release
// with undecided gate-class findings would be a false claim of
// coverage, which is the same law as `derive bump`'s drift refusal:
// derived state is refused when stale, never silently repaired.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/triage"
	"github.com/monumental-archive/stele/internal/vex"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

// deriveVEX is the mode name.
const deriveVEX = "vex"

// The scanner seam, swapped only by tests.
//
//nolint:gochecknoglobals // test seam, written only by test setup
var newVEXScanner = func() osv.Scanner { return osv.Runner{} }

// vexArgs is everything `derive vex` reads.
type vexArgs struct {
	subjects   string
	vexDir     string
	ecosystems string
	author     string
	id         string
	released   string
	out        string
}

// subject pairs one artifact identifier with the inventory describing
// it. The identifier is what a statement's product will be, so the
// caller decides the unit of description — the release, or one
// artifact within it.
type subject struct {
	product   string
	inventory string
}

// parseVEXArgs reads the flag surface.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseVEXArgs(args []string, stderr io.Writer) (*vexArgs, int) {
	va := &vexArgs{}

	flags := flag.NewFlagSet("stele derive vex", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&va.subjects, "subjects", "",
		"comma-separated <product-id>=<inventory-path> pairs; one per artifact this release ships (required)")
	flags.StringVar(&va.vexDir, "vex", "", "directory of recorded *.openvex.json decisions (required)")
	flags.StringVar(&va.ecosystems, "base-ecosystems", "",
		"comma-separated ecosystem substrings whose upgrades arrive by rebuild; "+
			"findings there with no published fix are reported, never gated")
	flags.StringVar(&va.author, "author", "", "who asserts these statements (required)")
	flags.StringVar(&va.id, "id", "", "the derived document's identifier (required)")
	flags.StringVar(&va.released, "released", "",
		"RFC 3339 instant of the release this document describes, never a clock reading (required)")
	flags.StringVar(&va.out, "out", "", "file to write the document to; empty prints to stdout")

	if err := flags.Parse(args); err != nil {
		return va, exitUsage
	}

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele derive vex: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch {
	case va.subjects == "":
		return va, usageFail("--subjects is required")
	case va.vexDir == "":
		return va, usageFail("--vex is required")
	case va.author == "":
		return va, usageFail("--author is required")
	case va.id == "":
		return va, usageFail("--id is required")
	case va.released == "":
		return va, usageFail("--released is required")
	}

	return va, exitOK
}

// parseSubjects reads the pairs. A pair whose product or inventory is
// empty is refused: a statement about "" describes nothing.
func parseSubjects(spec string) ([]subject, error) {
	var out []subject

	for pair := range strings.SplitSeq(spec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		product, inventory, ok := strings.Cut(pair, "=")
		if !ok || strings.TrimSpace(product) == "" || strings.TrimSpace(inventory) == "" {
			return nil, fmt.Errorf("derive vex: %q is not <product-id>=<inventory-path>", pair)
		}

		out = append(out, subject{product: strings.TrimSpace(product), inventory: strings.TrimSpace(inventory)})
	}

	if len(out) == 0 {
		return nil, errors.New("derive vex: no subjects — a document describing nothing covers nothing")
	}

	return out, nil
}

// runDeriveVEX scans every inventory, joins, refuses the undecided,
// and renders what the decisions cover.
func runDeriveVEX(va *vexArgs, doc io.Writer, out *latch) error {
	subjects, err := parseSubjects(va.subjects)
	if err != nil {
		return err
	}

	released, err := time.Parse(time.RFC3339, va.released)
	if err != nil {
		return fmt.Errorf("derive vex: --released %q is not RFC 3339: %w", va.released, err)
	}

	decisions, err := readVEXDir(va.vexDir)
	if err != nil {
		return fmt.Errorf("derive vex: reading decisions from %s: %w", va.vexDir, err)
	}

	pol := &triage.Policy{BaseEcosystems: splitTypes(va.ecosystems)}
	scanner := newVEXScanner()

	var (
		coverage  []vex.Coverage
		undecided []string
		rebuilds  int
	)

	for _, s := range subjects {
		split, serr := scanSubject(pol, scanner, decisions, s)
		if serr != nil {
			return serr
		}

		rebuilds += len(split.Rebuild)

		for i := range split.Undecided {
			undecided = append(undecided, s.product+": "+split.Undecided[i].String())
		}

		for i := range split.Decided {
			coverage = append(coverage, coverageOf(s.product, &split.Decided[i]))
		}

		out.logf("%s: %d decided, %d undecided, %d on the rebuild cadence",
			s.product, len(split.Decided), len(split.Undecided), len(split.Rebuild))
	}

	// Sealing is where the refusal lives, not here: Render takes only
	// a *vex.Complete, so no caller — this one or a later one — can
	// render a coverage document beside untriaged findings.
	sort.Strings(undecided)

	complete, err := vex.Cover(coverage, undecided)
	if err != nil {
		return fmt.Errorf("derive vex: triage before releasing: %w", err)
	}

	return renderVEX(va, released, complete, rebuilds, doc, out)
}

// scanSubject scans one inventory and splits its findings.
func scanSubject(
	pol *triage.Policy, scanner osv.Scanner, decisions *vexjoin.Decisions, s subject,
) (triage.Split, error) {
	inventory, err := os.ReadFile(s.inventory)
	if err != nil {
		return triage.Split{}, fmt.Errorf("derive vex: %s: %w", s.product, err)
	}

	report, err := scanner.Scan(inventory)
	if errors.Is(err, osv.ErrZeroPackages) {
		// A scan that read nothing must not report clean: an inventory
		// parsing to zero packages would derive a document asserting
		// coverage of an empty dependency set.
		return triage.Split{}, fmt.Errorf("derive vex: %s: %s parsed to zero packages", s.product,
			filepath.Base(s.inventory))
	}

	if err != nil {
		return triage.Split{}, fmt.Errorf("derive vex: scanning %s: %w", s.product, err)
	}

	findings, err := pol.Findings(report)
	if err != nil {
		return triage.Split{}, err
	}

	return triage.Join(findings, decisions), nil
}

// coverageOf carries one decision onto one product. The judgment and
// its moment travel from the recorded statement, so the derived
// document asserts what a human decided and when, not what this run
// concluded and now.
func coverageOf(product string, d *triage.Decided) vex.Coverage {
	return vex.Coverage{
		Product:         product,
		Subcomponent:    d.Decision.Purl,
		Advisory:        d.Finding.Key.Advisory(),
		Status:          d.Decision.Status,
		Justification:   d.Decision.Justification,
		ImpactStatement: d.Decision.ImpactStatement,
		ActionStatement: d.Decision.ActionStatement,
		Decided:         d.Decision.Decided,
	}
}

// renderVEX writes the document, or reports honestly that no decision
// applies. Nothing to say is the ordinary outcome, not a failure, and
// saying so in machine-readable form spares the caller a glob.
func renderVEX(
	va *vexArgs, released time.Time, complete *vex.Complete, rebuilds int, doc io.Writer, out *latch,
) error {
	document, err := vex.Render(
		vex.Options{ID: va.id, Author: va.author, Released: released}, complete)
	if errors.Is(err, vex.ErrNoCoverage) {
		out.logf("derived=false")
		out.logf("no recorded decision applies to this release; %d finding(s) on the rebuild cadence", rebuilds)

		return nil
	}

	if err != nil {
		return err
	}

	if err := writeJSONDoc(va.out, document, doc, out); err != nil {
		return err
	}

	out.logf("derived=true")
	out.logf("statements=%d", len(document.Statements))

	return nil
}
