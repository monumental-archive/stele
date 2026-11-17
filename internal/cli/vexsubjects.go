// `derive vex-subjects`: which published releases one VEX decision
// reaches, and the subjects a claim about it is signed over. The
// walk, the trust rule and the join are the assert engine's own
// (internal/sbomwalk, internal/triage) — this file is the argument
// surface and the wiring, nothing else.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/population"
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
	policyPath   string
	decisions    pathList
	org          string
	repo         string
	snapshotDir  string
	out          string
	unsignedOnly bool
	store        string
}

// pathList collects a repeatable path flag, in order.
type pathList []string

func (p *pathList) String() string { return strings.Join(*p, " ") }

func (p *pathList) Set(v string) error {
	*p = append(*p, v)

	return nil
}

// parseVEXSubjectsArgs parses and validates the flags.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseVEXSubjectsArgs(args []string, stderr io.Writer) (*vexSubjectsArgs, int) {
	va := &vexSubjectsArgs{}

	flags := flag.NewFlagSet("stele derive vex-subjects", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&va.policyPath, "policy", "", "path to the committed assert policy (required)")
	flags.Var(&va.decisions, "decision",
		"path to a *.openvex.json decision whose affected releases are derived; repeatable, at least one — "+
			"each is planned on its own, and one refused never hides the rest")
	flags.StringVar(&va.org, "org", "", "organisation whose releases are walked (this or --repo)")
	flags.StringVar(&va.repo, "repo", "",
		"owner/name whose releases are walked — the single-repository population (this or --org)")
	flags.StringVar(&va.snapshotDir, "snapshot", "", "replay a captured snapshot directory instead of the live API")
	flags.StringVar(&va.out, "out", "", "file to write the document to; empty prints to stdout")
	flags.BoolVar(&va.unsignedOnly, "unsigned-only", false,
		"omit every decision the attestation store already holds; a store that cannot be read is exit 4 "+
			"for that decision, never read as signed or unsigned (needs --store)")
	flags.StringVar(&va.store, "store", "",
		"owner/name whose attestation store holds the signed decisions — the repository the signer "+
			"persists them in (with --unsigned-only)")

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
	case len(va.decisions) == 0:
		return va, usageFail("--decision is required")
	case va.unsignedOnly && !strings.Contains(va.store, "/"):
		return va, usageFail("--unsigned-only needs --store owner/name: the store it asks is named, never assumed")
	case !va.unsignedOnly && va.store != "":
		return va, usageFail("--store is read only with --unsigned-only")
	case va.org == "" && va.repo == "":
		return va, usageFail("--org or --repo is required")
	case va.org != "" && va.repo != "":
		return va, usageFail("--org and --repo are exclusive: one population, named once")
	case va.repo != "" && !strings.Contains(va.repo, "/"):
		return va, usageFail("--repo must be owner/name")
	}

	seen := map[string]bool{}
	for _, d := range va.decisions {
		if seen[d] {
			return va, usageFail("--decision " + d + " is named twice — one decision is planned once")
		}

		seen[d] = true
	}

	return va, exitOK
}

// runVEXSubjectsCmd runs the mode and turns its plan into the exit
// code: the plan is written whole whatever it holds, and the code says
// what it found — 4 when any decision went unjudged because the store
// could not be read, 1 when any decision was refused, 0 otherwise.
func runVEXSubjectsCmd(va *vexSubjectsArgs, stdout, stderr io.Writer) int {
	logTo := stdout
	if va.out == "" {
		logTo = stderr
	}

	out := &latch{w: logTo}

	plan, err := runDeriveVEXSubjects(va, stdout, out)
	if out.err != nil {
		return exitIO
	}

	if err != nil {
		if _, werr := fmt.Fprintf(stderr, "%v\n", err); werr != nil {
			return exitIO
		}

		if errors.Is(err, vexsubjects.ErrStoreUnreadable) {
			return exitBlind
		}

		return exitRefused
	}

	switch {
	case plan.Blind():
		return exitBlind
	case len(plan.Refused) > 0:
		return exitRefused
	default:
		return exitOK
	}
}

// runDeriveVEXSubjects plans every decision and writes the plan whole.
func runDeriveVEXSubjects(va *vexSubjectsArgs, doc io.Writer, out *latch) (*vexsubjects.Plan, error) {
	pol, err := loadAssertPolicy(va.policyPath)
	if err != nil {
		return nil, fmt.Errorf("derive vex-subjects: %w", err)
	}

	if pol.BlastRadius == nil {
		return nil, fmt.Errorf("derive vex-subjects: %s declares no blastRadius section — the base-layer"+
			" classification this join reads has no source", va.policyPath)
	}

	forge := newForge()
	if va.snapshotDir != "" {
		forge = gh.Snapshot{Dir: va.snapshotDir}
	}

	pop, err := resolvePopulation(population.Scope{Org: va.org, Repo: va.repo}, forge, pol.Population)
	if err != nil {
		return nil, fmt.Errorf("derive vex-subjects: %w", err)
	}

	// The same track the blast-radius walk covers, and for the same
	// reason: this mode derives which releases an advisory reaches
	// from their SBOMs, so a repository declared outside the
	// dependency track has nothing here to be affected.
	repos, err := assert.BlastRadiusSubjects.Enumerate(pop)
	if err != nil {
		return nil, fmt.Errorf("derive vex-subjects: %w", err)
	}

	d := &vexsubjects.Deriver{
		Org:        pop.Owner(),
		SBOMSuffix: *pol.Evidence.SBOMSuffix,
		Checksums:  *pol.Evidence.Checksums,
		Triage:     &triage.Policy{BaseEcosystems: pol.BlastRadius.OSEcosystems},
		Forge:      forge,
		Scanner:    newScanner(),
		Log:        out.logf,
	}

	pl := &vexsubjects.Planner{
		Derive: func(decisions *vexjoin.Decisions, origin string) (*vexsubjects.Document, error) {
			return d.Affected(repos, decisions, origin)
		},
		UnsignedOnly: va.unsignedOnly,
		Log:          out.logf,
	}

	if va.unsignedOnly {
		store, ok := forge.(vexsubjects.Store)
		if !ok {
			return nil, errors.New("derive vex-subjects: --unsigned-only asks the live attestation store, and" +
				" this forge cannot read one")
		}

		pl.Store = store
		pl.StoreOwner, pl.StoreRepo, _ = strings.Cut(va.store, "/")
	}

	plan, err := pl.Plan(readDecisionFiles(va.decisions))
	if err != nil {
		return nil, fmt.Errorf("derive vex-subjects: %w", err)
	}

	out.logf("derive: vex-subjects: %d decision(s) to sign, %d already held, %d refused",
		len(plan.Cells), len(plan.Held), len(plan.Refused))

	return plan, writeJSONDoc(va.out, plan, doc, out)
}

// loadAssertPolicy opens and decodes the committed assert policy.
//
// It names NO verb. Three commands load a policy through here, and a
// helper that stamped its home file's verb on all of them told a
// `stele level` board consumer that `derive vex-subjects` had failed —
// a verb they never ran, in a published evidence document (stele#260).
// The verb belongs to the command that ran, so each caller adds its
// own at its own call site.
//
// What this DOES own is the path, because every caller named the same
// one: os.Open carries it already, the decoder never sees it, so only
// the decode leg gains it here.
func loadAssertPolicy(path string) (*assert.Policy, error) {
	f, err := os.Open(path) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return nil, err //nolint:wrapcheck // the path is in the message; a prefix would say it twice
	}
	defer f.Close() //nolint:errcheck // read-only close

	pol, err := assert.LoadPolicy(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	return pol, nil
}

// readDecisionFiles reads every named decision, in order. A file that
// cannot be read is carried as its error: the planner refuses it by
// name and plans the rest.
func readDecisionFiles(paths []string) []vexsubjects.DecisionFile {
	files := make([]vexsubjects.DecisionFile, 0, len(paths))

	for _, path := range paths {
		raw, err := os.ReadFile(path) //nolint:gosec // the decision path is operator-supplied by design
		files = append(files, vexsubjects.DecisionFile{Path: path, Raw: raw, Err: err})
	}

	return files
}
