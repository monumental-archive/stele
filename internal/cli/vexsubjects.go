// `derive vex-subjects`: which published releases one VEX decision
// reaches, and the subjects a claim about it is signed over. The
// walk, the trust rule and the join are the assert engine's own
// (internal/sbomwalk, internal/triage) — this file is the argument
// surface and the wiring, nothing else.

package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/triage"
	"github.com/monumental-archive/stele/internal/vexjoin"
	"github.com/monumental-archive/stele/internal/vexsubjects"
)

const deriveVEXSubjects = "vex-subjects"

// vexSubjectsArgs is the mode's whole argument surface. The org's
// conventions — what an inventory asset is called, what pins a
// release's bytes, which ecosystems are base layers — are read from
// the assert policy that already declares them, never restated as
// flags: a second spelling of an org fact is a second source of it.
type vexSubjectsArgs struct {
	policyPath  string
	decision    string
	org         string
	repo        string
	snapshotDir string
	out         string
}

// parseVEXSubjectsArgs parses and validates the flags.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseVEXSubjectsArgs(args []string, stderr io.Writer) (*vexSubjectsArgs, int) {
	va := &vexSubjectsArgs{}

	flags := flag.NewFlagSet("stele derive vex-subjects", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&va.policyPath, "policy", "", "path to the committed assert policy (required)")
	flags.StringVar(&va.decision, "decision", "",
		"path to the *.openvex.json decision whose affected releases are derived (required)")
	flags.StringVar(&va.org, "org", "", "organisation whose releases are walked (this or --repo)")
	flags.StringVar(&va.repo, "repo", "",
		"owner/name whose releases are walked — the single-repository population (this or --org)")
	flags.StringVar(&va.snapshotDir, "snapshot", "", "replay a captured snapshot directory instead of the live API")
	flags.StringVar(&va.out, "out", "", "file to write the document to; empty prints to stdout")

	if err := flags.Parse(args); err != nil {
		return va, exitUsage
	}

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele derive vex-subjects: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch {
	case va.policyPath == "":
		return va, usageFail("--policy is required")
	case va.decision == "":
		return va, usageFail("--decision is required")
	case va.org == "" && va.repo == "":
		return va, usageFail("--org or --repo is required")
	case va.org != "" && va.repo != "":
		return va, usageFail("--org and --repo are exclusive: one population, named once")
	case va.repo != "" && !strings.Contains(va.repo, "/"):
		return va, usageFail("--repo must be owner/name")
	}

	return va, exitOK
}

// runDeriveVEXSubjects derives the document and writes it whole.
func runDeriveVEXSubjects(va *vexSubjectsArgs, doc io.Writer, out *latch) error {
	pol, err := loadAssertPolicy(va.policyPath)
	if err != nil {
		return err
	}

	if pol.BlastRadius == nil {
		return fmt.Errorf("derive vex-subjects: %s declares no blastRadius section — the base-layer"+
			" classification this join reads has no source", va.policyPath)
	}

	decisions, err := readVEXFile(va.decision)
	if err != nil {
		return err
	}

	forge := newForge()
	if va.snapshotDir != "" {
		forge = gh.Snapshot{Dir: va.snapshotDir}
	}

	org, repos, err := assert.Population{Org: va.org, Repo: va.repo}.Resolve(forge)
	if err != nil {
		return fmt.Errorf("derive vex-subjects: %w", err)
	}

	d := &vexsubjects.Deriver{
		Org:        org,
		SBOMSuffix: *pol.Evidence.SBOMSuffix,
		Checksums:  *pol.Evidence.Checksums,
		Triage:     &triage.Policy{BaseEcosystems: pol.BlastRadius.OSEcosystems},
		Forge:      forge,
		Scanner:    newScanner(),
		Log:        out.logf,
	}

	document, err := d.Affected(repos, decisions, va.decision)
	if err != nil {
		return fmt.Errorf("derive vex-subjects: %w", err)
	}

	names := make([]string, 0, len(document.Releases))
	for _, r := range document.Releases {
		names = append(names, r.Subject())
	}

	out.logf("derive: vex-subjects: %d release(s) affected (%s), %d subject(s)",
		len(document.Releases), strings.Join(names, " "), len(document.Subjects))

	return writeJSONDoc(va.out, document, doc, out)
}

// loadAssertPolicy opens and decodes the committed assert policy.
func loadAssertPolicy(path string) (*assert.Policy, error) {
	f, err := os.Open(path) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return nil, fmt.Errorf("derive vex-subjects: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only close

	pol, err := assert.LoadPolicy(f)
	if err != nil {
		return nil, fmt.Errorf("derive vex-subjects: %w", err)
	}

	return pol, nil
}

// readVEXFile parses ONE decision document. One file, never a
// directory: this derivation binds a claim about the document that
// changed, and a set assembled from the whole directory would sign
// one statement over releases another statement reached.
func readVEXFile(path string) (*vexjoin.Decisions, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the decision path is operator-supplied by design
	if err != nil {
		return nil, fmt.Errorf("derive vex-subjects: %w", err)
	}

	decisions := &vexjoin.Decisions{}
	if perr := vexjoin.Parse(decisions, raw, path); perr != nil {
		return nil, fmt.Errorf("derive vex-subjects: %w", perr)
	}

	return decisions, nil
}
