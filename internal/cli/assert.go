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
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/oci"
	"github.com/monumental-archive/stele/internal/report"
)

// exitBlind is CANNOT_JUDGE's own exit code: the run could not see
// enough to judge. Distinct from FAIL (1), usage (2) and stream
// failure (3).
const exitBlind = 4

// The assert targets.
const targetImageFacts = "image-facts"

// newOCIReader is the registry seam, swapped only by tests.
//
//nolint:gochecknoglobals // test seam, written only by test setup
var newOCIReader = func() oci.Reader { return oci.Client{} }

// assertCmd dispatches `stele assert <target>`.
func assertCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		if _, err := fmt.Fprintln(stderr, "stele assert: a target is required: image-facts"); err != nil {
			return exitIO
		}

		return exitUsage
	}

	if args[0] != targetImageFacts {
		if _, err := fmt.Fprintf(stderr, "stele assert: unknown target %q (image-facts)\n", args[0]); err != nil {
			return exitIO
		}

		return exitUsage
	}

	return assertImageFacts(args[1:], stdout, stderr)
}

// assertImageFacts runs the image-facts target: env contract read and
// refused by name (#82 — a missing input fails by its name, never by
// expanding to nothing), the engine judged, the report sealed out.
func assertImageFacts(args []string, stdout, stderr io.Writer) int {
	var jsonOut bool

	fs := flag.NewFlagSet("stele assert image-facts", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&jsonOut, "json", false,
		"emit the verdict as one JSON report document on stdout (progress moves to stderr)")

	if err := fs.Parse(args); err != nil {
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
