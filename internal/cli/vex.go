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

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/sbom"
	"github.com/monumental-archive/stele/internal/triage"
	"github.com/monumental-archive/stele/internal/verify"
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
	policyPath  string
	subjects    string
	inventories string
	vexDir      string
	id          string
	released    string
	out         string

	// The coordinates the id and the release view's product derive
	// from (stele#397): a release by its version, a stream publish by
	// its run.
	repo         string
	version      string
	run          string
	releaseView  string
	verifyPolicy string
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
	flags.StringVar(&va.policyPath, "policy", "",
		"path to the committed assert policy: blastRadius names the base-layer ecosystems and the author (required)")
	flags.StringVar(&va.subjects, "subjects", "",
		"comma-separated <product-id>=<inventory-path> pairs; one per artifact this release ships "+
			"(this or --inventories)")
	flags.StringVar(&va.inventories, "inventories", "",
		"directory of the inventories to cover, found by the policy's evidence.sbomSuffix; each document's "+
			"own name is its product (this or --subjects)")
	flags.StringVar(&va.vexDir, "vex", "", "directory of recorded *.openvex.json decisions (required)")
	flags.StringVar(&va.id, "id", "",
		"the derived document's identifier; absent, derived from the policy's blastRadius.vexId for --repo with "+
			"--version or --run")
	flags.StringVar(&va.repo, "repo", "", "owner/name the document describes (to derive the id or the release view)")
	flags.StringVar(&va.version, "version", "", "the release's version, without the tag's v (this or --run)")
	flags.StringVar(&va.run, "run", "", "the run that made a stream publish (this or --version)")
	flags.StringVar(&va.releaseView, "release-view", "",
		"the release view's inventory: excluded from --inventories, its product is the verify policy's "+
			"build.resourceUri for --repo and --version")
	flags.StringVar(&va.verifyPolicy, "verify-policy", "",
		"path to the committed verify policy (with --release-view, and only then)")
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
	case va.policyPath == "":
		return va, usageFail("--policy is required")
	case va.subjects == "" && va.inventories == "":
		return va, usageFail("--subjects or --inventories is required")
	case va.subjects != "" && va.inventories != "":
		return va, usageFail("--subjects and --inventories are exclusive: one subject list, named once")
	case va.vexDir == "":
		return va, usageFail("--vex is required")
	case va.released == "":
		return va, usageFail("--released is required")
	}

	if msg := va.coordinateRefusal(); msg != "" {
		return va, usageFail(msg)
	}

	return va, exitOK
}

// coordinateRefusal checks the coordinate flags against each other:
// what derives the id, and what names the release view.
func (va *vexArgs) coordinateRefusal() string {
	switch {
	case va.version != "" && va.run != "":
		return "--version and --run are exclusive: a document describes a release or a stream publish, not both"
	case va.repo != "" && !strings.Contains(va.repo, "/"):
		return "--repo must be owner/name"
	case va.id == "" && (va.repo == "" || va.version == "" && va.run == ""):
		return "--id is required unless --repo with --version or --run derives it from the policy's blastRadius.vexId"
	case va.releaseView != "" && va.verifyPolicy == "":
		return "--release-view needs --verify-policy: the view's product is that policy's build.resourceUri"
	case va.verifyPolicy != "" && va.releaseView == "":
		return "--verify-policy is read only for --release-view"
	case va.releaseView != "" && (va.repo == "" || va.version == ""):
		return "--release-view needs --repo and --version: the view's product is the release's resource"
	}

	return ""
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
	pol, err := loadAssertPolicy(va.policyPath)
	if err != nil {
		return fmt.Errorf("derive vex: %w", err)
	}

	br := pol.BlastRadius

	switch {
	case br == nil:
		return fmt.Errorf("derive vex: %s declares no blastRadius section — the base-layer"+
			" classification this derivation reads has no source", va.policyPath)
	case br.VEXAuthor == nil:
		return fmt.Errorf("derive vex: %s declares no blastRadius.vexAuthor — a document's statements"+
			" are asserted by someone, and only the org can say who", va.policyPath)
	}

	subjects, err := vexSubjects(va, *pol.Evidence.SBOMSuffix)
	if err != nil {
		return err
	}

	id, err := vexDocumentID(va, br.VEXID)
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

	classes := &triage.Policy{BaseEcosystems: br.OSEcosystems}
	scanner := newVEXScanner()

	var (
		coverage  []vex.Coverage
		undecided []string
		rebuilds  int
	)

	for _, s := range subjects {
		split, serr := scanSubject(classes, scanner, decisions, s)
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

	return renderVEX(va, vex.Options{ID: id, Author: *br.VEXAuthor, Released: released}, complete, rebuilds, doc, out)
}

// vexDocumentID is the caller's --id, or the policy's template for a
// release (by version) or a stream publish (by run).
func vexDocumentID(va *vexArgs, ids *assert.VEXIDPolicy) (string, error) {
	if va.id != "" {
		return va.id, nil
	}

	owner, repo, _ := strings.Cut(va.repo, "/")

	var (
		id  string
		err error
	)

	if va.version != "" {
		id, err = ids.ReleaseID(owner, repo, va.version)
	} else {
		id, err = ids.StreamID(owner, repo, va.run)
	}

	if err != nil {
		return "", fmt.Errorf("derive vex: %w", err)
	}

	return id, nil
}

// releaseViewSubject names the release view under the release's
// resource — the verify policy's build.resourceUri, the definition
// the release verdict names, so the two documents speak for the same
// thing by construction.
func releaseViewSubject(va *vexArgs) (subject, error) {
	f, err := os.Open(va.verifyPolicy)
	if err != nil {
		return subject{}, fmt.Errorf("derive vex: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only close

	vp, err := policy.Load(f)
	if err != nil {
		return subject{}, fmt.Errorf("derive vex: verify policy: %w", err)
	}

	owner, repo, _ := strings.Cut(va.repo, "/")

	product, err := verify.ReleaseResource(vp, verify.Coords{Owner: owner, Repo: repo, Tag: "v" + va.version})
	if err != nil {
		return subject{}, fmt.Errorf("derive vex: %w", err)
	}

	return subject{product: product, inventory: va.releaseView}, nil
}

// vexSubjects is the subject list: the caller's pairs, or the
// inventories found in a directory — every regular file carrying the
// policy's SBOM suffix, in name order so the document reads the same
// on every run, each under its own document name. A document with no
// name is refused: a statement about "" describes nothing, and a
// product id composed in its place would be a fact nobody stated.
func vexSubjects(va *vexArgs, suffix string) ([]subject, error) {
	var out []subject

	// The release view leads, as the release's own statements always
	// have; discovery then skips the same file.
	var view os.FileInfo

	if va.releaseView != "" {
		s, err := releaseViewSubject(va)
		if err != nil {
			return nil, err
		}

		if view, err = os.Stat(va.releaseView); err != nil {
			return nil, fmt.Errorf("derive vex: --release-view: %w", err)
		}

		out = append(out, s)
	}

	if va.inventories == "" {
		pairs, err := parseSubjects(va.subjects)

		return append(out, pairs...), err
	}

	entries, err := os.ReadDir(va.inventories)
	if err != nil {
		return nil, fmt.Errorf("derive vex: --inventories: %w", err)
	}

	discovered := 0

	for _, e := range entries { // os.ReadDir returns name order
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), suffix) {
			continue
		}

		path := filepath.Join(va.inventories, e.Name())

		if view != nil {
			if info, serr := os.Stat(path); serr == nil && os.SameFile(info, view) {
				continue
			}
		}

		name, nerr := inventoryName(path)
		if nerr != nil {
			return nil, nerr
		}

		out = append(out, subject{product: name, inventory: path})
		discovered++
	}

	// A release whose only inventory is its view (no per-artifact
	// documents) is a release described whole; with no view, an empty
	// directory describes nothing.
	if discovered == 0 && view == nil {
		return nil, fmt.Errorf("derive vex: %s holds no *%s inventory — a document describing nothing covers nothing",
			va.inventories, suffix)
	}

	return out, nil
}

// spdxName is the one field discovery reads of an inventory.
type spdxName struct {
	Name *string `json:"name"`
}

// inventoryName reads an inventory's own document name.
func inventoryName(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // a file in the directory the caller named
	if err != nil {
		return "", fmt.Errorf("derive vex: %w", err)
	}

	doc, err := jsonx.DecodeForeign[spdxName](raw)
	if err != nil {
		return "", fmt.Errorf("derive vex: %s is not an inventory document: %w", filepath.Base(path), err)
	}

	if doc.Name == nil || strings.TrimSpace(*doc.Name) == "" {
		return "", fmt.Errorf("derive vex: %s carries no name — its statements would name no product",
			filepath.Base(path))
	}

	return *doc.Name, nil
}

// scanSubject scans one inventory and splits its findings.
func scanSubject(
	pol *triage.Policy, scanner osv.Scanner, decisions *vexjoin.Decisions, s subject,
) (triage.Split, error) {
	inventory, err := os.ReadFile(s.inventory)
	if err != nil {
		return triage.Split{}, fmt.Errorf("derive vex: %s: %w", s.product, err)
	}

	// The inventory is another tool's document as often as this one's
	// (an image scanner's, the forge's dependency graph): admitted
	// before it is scanned, because a versionless PURL is a package
	// the scan cannot see and the coverage below would not cover.
	if _, aerr := sbom.AdmitBytes(inventory); aerr != nil {
		return triage.Split{}, fmt.Errorf("derive vex: %s: %w", s.product, aerr)
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
	va *vexArgs, opts vex.Options, complete *vex.Complete, rebuilds int, doc io.Writer, out *latch,
) error {
	document, err := vex.Render(opts, complete)
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
