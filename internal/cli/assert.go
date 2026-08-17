// The assert verb: read evidence, read a declaration, report
// divergence. Exit codes split three ways because the report's
// verdicts do (docs/report-schema.md): 0 PASS, 1 FAIL, and 4 for
// CANNOT_JUDGE — a run that could not look must never exit like one
// that looked and found drift, or like one that found none.
//
// image-facts keeps the environment contract its bash predecessor
// declared (IMAGE, DIGEST, FACTS): the canon passes values via env:,
// never ${{ }} interpolated into shell, and the callers already
// speak it.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/oci"
	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

// exitBlind is CANNOT_JUDGE's own exit code: the run could not see
// enough to judge. Distinct from FAIL (1), usage (2) and stream
// failure (3).
const exitBlind = 4

// The assert targets.
const (
	targetImageFacts  = "image-facts"
	targetEvidence    = "evidence"
	targetBlastRadius = "blast-radius"
)

// The effect seams, swapped only by tests.
//
//nolint:gochecknoglobals // test seams, written only by test setup
var (
	newOCIReader = func() oci.Reader { return oci.Client{} }

	newScanner = func() osv.Scanner { return osv.Runner{} }

	newForge = func() gh.Forge {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			token = os.Getenv("GH_TOKEN")
		}

		return gh.New(token)
	}
)

// assertCmd dispatches `stele assert <target>`.
func assertCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		if _, err := fmt.Fprintln(stderr, "stele assert: a target is required: image-facts"); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch args[0] {
	case targetImageFacts:
		return assertImageFacts(args[1:], stdout, stderr)
	case targetEvidence:
		return assertEvidence(args[1:], stdout, stderr)
	case targetBlastRadius:
		return assertBlastRadius(args[1:], stdout, stderr)
	default:
		if _, err := fmt.Fprintf(stderr,
			"stele assert: unknown target %q (image-facts, evidence, blast-radius)\n", args[0]); err != nil {
			return exitIO
		}

		return exitUsage
	}
}

// assertEvidence runs the evidence-completeness walk: policy loaded,
// the forge chosen (live, snapshot replay, or capture-through), the
// contract sources stacked manifest-first, the debt file parsed into
// declared exceptions.
func assertEvidence(args []string, stdout, stderr io.Writer) int {
	var (
		jsonOut                   bool
		org, policyPath, debtPath string
		snapshotDir, captureDir   string
	)

	flags := flag.NewFlagSet("stele assert evidence", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&org, "org", "", "organisation whose releases are walked (required)")
	flags.StringVar(&policyPath, "policy", "", "path to the committed assert policy (required)")
	flags.StringVar(&debtPath, "debt", "", "path to the committed evidence-debt file (defaults to the policy's debtFile)")
	flags.StringVar(&snapshotDir, "snapshot", "", "replay a captured snapshot directory instead of the live API")
	flags.StringVar(&captureDir, "capture", "", "record every live answer into this directory while walking")
	flags.BoolVar(&jsonOut, "json", false,
		"emit the verdict as one JSON report document on stdout (progress moves to stderr)")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele assert evidence: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch {
	case org == "":
		return usageFail("--org is required")
	case policyPath == "":
		return usageFail("--policy is required")
	case snapshotDir != "" && captureDir != "":
		return usageFail("--snapshot and --capture are exclusive: replay reads, capture writes")
	}

	pf, err := os.Open(policyPath) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return usageFail(err.Error())
	}
	defer pf.Close() //nolint:errcheck // read-only close

	pol, err := assert.LoadPolicy(pf)
	if err != nil {
		return usageFail(err.Error())
	}

	if debtPath == "" {
		debtPath = *pol.Evidence.DebtFile
	}

	debt, code := loadDebt(debtPath, stderr)
	if code != exitOK {
		return code
	}

	forge := newForge()
	if snapshotDir != "" {
		forge = gh.Snapshot{Dir: snapshotDir}
	} else if captureDir != "" {
		forge = gh.Capture{Live: forge, Dir: captureDir}
	}

	src := assert.Sources{
		assert.ManifestSource{Forge: forge, Asset: *pol.Evidence.ManifestAsset},
		assert.WorkflowSource{Forge: forge, Policy: pol.Evidence},
	}

	out := &latch{w: stdout}
	if jsonOut {
		out = &latch{w: stderr}
	}

	rep, err := assert.Evidence(pol, org, forge, src, debt, out.logf)
	if out.err != nil {
		return exitIO
	}

	if err != nil {
		rep = report.Seal("assert "+targetEvidence, org,
			report.PopulationFromListing(0, "walk incomplete"),
			[]report.Finding{{Subject: org, Assertion: targetEvidence, Detail: err.Error()}},
			nil, report.NoCanary())

		if _, werr := fmt.Fprintf(stderr, "%v\n", err); werr != nil {
			return exitIO
		}
	}

	return emitReport(rep, jsonOut, stdout, stderr)
}

// loadDebt parses the committed debt file. An absent file is no debt
// — the walk owes nothing to a file nobody wrote; a malformed one is
// a usage refusal, because a reviewed file that parses as nothing
// would excuse nothing silently.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func loadDebt(path string, stderr io.Writer) ([]report.Exception, int) {
	content, err := os.ReadFile(path) //nolint:gosec // the debt path is operator-supplied by design
	if errors.Is(err, fs.ErrNotExist) {
		return nil, exitOK
	}

	if err == nil {
		parsed, perr := assert.ParseDebt(content, path)
		if perr == nil {
			return parsed, exitOK
		}

		err = perr
	}

	if _, werr := fmt.Fprintf(stderr, "stele assert evidence: %v\n", err); werr != nil {
		return nil, exitIO
	}

	return nil, exitUsage
}

// assertImageFacts runs the image-facts target: env contract read and
// refused by name (#82 — a missing input fails by its name, never by
// expanding to nothing), the engine judged, the report sealed out.
func assertImageFacts(args []string, stdout, stderr io.Writer) int {
	var jsonOut bool

	flags := flag.NewFlagSet("stele assert image-facts", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.BoolVar(&jsonOut, "json", false,
		"emit the verdict as one JSON report document on stdout (progress moves to stderr)")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	image, digest, facts := os.Getenv("IMAGE"), os.Getenv("DIGEST"), os.Getenv("FACTS")

	for name, v := range map[string]string{"IMAGE": image, "DIGEST": digest, "FACTS": facts} {
		if v == "" {
			if _, err := fmt.Fprintf(stderr, "stele assert image-facts: %s must be set\n", name); err != nil {
				return exitIO
			}

			return exitUsage
		}
	}

	out := &latch{w: stdout}
	if jsonOut {
		out = &latch{w: stderr}
	}

	rep, err := assert.ImageFacts(image, digest, []byte(facts), newOCIReader(), out.logf)
	if out.err != nil {
		return exitIO
	}

	if err != nil {
		// Infrastructure refused before the engine could judge: sealed
		// as CANNOT_JUDGE over an empty population, the error carried
		// as the finding — partial sight is reported, never a verdict.
		rep = report.Seal("assert "+targetImageFacts, image+"@"+digest,
			report.PopulationFromEvidence(0, "registry read incomplete"),
			[]report.Finding{{Subject: image + "@" + digest, Assertion: targetImageFacts, Detail: err.Error()}},
			nil, report.NoCanary())

		if _, werr := fmt.Fprintf(stderr, "%v\n", err); werr != nil {
			return exitIO
		}
	}

	return emitReport(rep, jsonOut, stdout, stderr)
}

// emitReport writes the sealed report (JSON or the human lines) and
// maps its verdict to the exit code.
func emitReport(rep *report.Report, jsonOut bool, stdout, stderr io.Writer) int {
	if jsonOut {
		if err := rep.Encode(stdout); err != nil {
			return exitIO
		}
	} else {
		out := &latch{w: stdout}
		findings := rep.Findings()
		for i := range findings {
			out.logf("assert: %s: %s: %s", findings[i].Subject, findings[i].Assertion, findingLine(&findings[i]))
		}

		out.logf("assert: %s", rep.Verdict())

		if out.err != nil {
			return exitIO
		}
	}

	if rep.Verdict() == report.VerdictPass {
		return exitOK
	}

	if rep.Verdict() == report.VerdictFail {
		return exitRefused
	}

	// CANNOT_JUDGE — Seal admits no fourth verdict.
	if _, err := fmt.Fprintln(stderr, "stele assert: the run could not see enough to judge"); err != nil {
		return exitIO
	}

	return exitBlind
}

// findingLine renders one finding's substance for the human stream.
func findingLine(f *report.Finding) string {
	if f.Expected != "" || f.Actual != "" {
		return fmt.Sprintf("%s (expected %q, actual %q)", f.Detail, f.Expected, f.Actual)
	}

	return f.Detail
}

// assertBlastRadius runs the SBOM scan walk: policy and VEX decisions
// loaded, the forge and scanner seams resolved, the verdict sealed.
func assertBlastRadius(args []string, stdout, stderr io.Writer) int {
	var (
		jsonOut                 bool
		org, policyPath, vexDir string
		snapshotDir, captureDir string
	)

	flags := flag.NewFlagSet("stele assert blast-radius", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&org, "org", "", "organisation whose SBOMs are scanned (required)")
	flags.StringVar(&policyPath, "policy", "", "path to the committed assert policy (required)")
	flags.StringVar(&vexDir, "vex", "", "directory of committed *.openvex.json decisions (required)")
	flags.StringVar(&snapshotDir, "snapshot", "", "replay a captured snapshot directory instead of the live API")
	flags.StringVar(&captureDir, "capture", "", "record every live answer into this directory while walking")
	flags.BoolVar(&jsonOut, "json", false,
		"emit the verdict as one JSON report document on stdout (progress moves to stderr)")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele assert blast-radius: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch {
	case org == "":
		return usageFail("--org is required")
	case policyPath == "":
		return usageFail("--policy is required")
	case vexDir == "":
		return usageFail("--vex is required")
	case snapshotDir != "" && captureDir != "":
		return usageFail("--snapshot and --capture are exclusive: replay reads, capture writes")
	}

	pf, err := os.Open(policyPath) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return usageFail(err.Error())
	}
	defer pf.Close() //nolint:errcheck // read-only close

	pol, err := assert.LoadPolicy(pf)
	if err != nil {
		return usageFail(err.Error())
	}

	decisions, code := loadVEX(vexDir, stderr)
	if code != exitOK {
		return code
	}

	forge := newForge()
	if snapshotDir != "" {
		forge = gh.Snapshot{Dir: snapshotDir}
	} else if captureDir != "" {
		forge = gh.Capture{Live: forge, Dir: captureDir}
	}

	out := &latch{w: stdout}
	if jsonOut {
		out = &latch{w: stderr}
	}

	rep, err := assert.BlastRadius(pol, org, forge, newScanner(), decisions, out.logf)
	if out.err != nil {
		return exitIO
	}

	if err != nil {
		rep = report.Seal("assert "+targetBlastRadius, org,
			report.PopulationFromListing(0, "walk incomplete"),
			[]report.Finding{{Subject: org, Assertion: targetBlastRadius, Detail: err.Error()}},
			nil, report.NoCanary())

		if _, werr := fmt.Fprintf(stderr, "%v\n", err); werr != nil {
			return exitIO
		}
	}

	return emitReport(rep, jsonOut, stdout, stderr)
}

// loadVEX parses every committed OpenVEX document in the directory.
// An empty or absent directory decides NOTHING (the vexjoin law); a
// malformed statement refuses, because a reviewed decision that
// parses as nothing decides nothing silently.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func loadVEX(dir string, stderr io.Writer) (*vexjoin.Decisions, int) {
	decisions := &vexjoin.Decisions{}

	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return decisions, exitOK
	}

	fail := func(err error) (*vexjoin.Decisions, int) {
		if _, werr := fmt.Fprintf(stderr, "stele assert blast-radius: %v\n", err); werr != nil {
			return nil, exitIO
		}

		return nil, exitUsage
	}

	if err != nil {
		return fail(err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".openvex.json") {
			continue
		}

		doc, rerr := os.ReadFile(dir + "/" + e.Name()) //nolint:gosec // the vex dir is operator-supplied by design
		if rerr != nil {
			return fail(rerr)
		}

		if perr := vexjoin.Parse(decisions, doc, e.Name()); perr != nil {
			return fail(perr)
		}
	}

	return decisions, exitOK
}
