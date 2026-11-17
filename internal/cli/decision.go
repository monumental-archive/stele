// `emit decision`: the release decision a commit point signs
// (stele#399). Its own flag surface, like `emit manifest`: it reads
// the verify policy only for trust.decision and needs no trusted
// root, repository or pins — it judges proof results the
// orchestration hands it and hashes the documents they covered.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/monumental-archive/stele/internal/emit"
	"github.com/monumental-archive/stele/internal/policy"
)

// emitDecision is the mode name.
const emitDecision = "decision"

// decisionArgs is everything `emit decision` reads.
type decisionArgs struct {
	policyPath   string
	in           emit.DecisionInputs
	predicateOut string
	subjectsOut  string
	p            *policy.Policy
}

// proofFlag collects `--proof name=result`, in order.
type proofFlag []emit.Proof

func (f *proofFlag) String() string { return fmt.Sprint(*f) }

// Set splits at the LAST '=': a proof's name is prose and may carry
// one, its result is a single word that never does.
func (f *proofFlag) Set(v string) error {
	name, result, ok := strings.CutLast(v, "=")
	if !ok {
		return fmt.Errorf("--proof %q is not name=result", v)
	}

	*f = append(*f, emit.Proof{Name: name, Result: result})

	return nil
}

// lineFlag collects a repeatable string flag, in order.
type lineFlag []string

func (f *lineFlag) String() string { return strings.Join(*f, "\n") }

func (f *lineFlag) Set(v string) error {
	*f = append(*f, v)

	return nil
}

// emitDecisionCmd runs `stele emit decision`.
func emitDecisionCmd(args []string, stdout, stderr io.Writer) int {
	da, code := parseDecisionArgs(args, stderr)
	if code != exitOK {
		return code
	}

	out := &latch{w: stdout}

	return finishDerive(runEmitDecision(da, out), out, stderr)
}

// parseDecisionArgs parses the flags and loads the policy — every
// usage refusal lands here, before anything is hashed or written.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseDecisionArgs(args []string, stderr io.Writer) (*decisionArgs, int) {
	da := &decisionArgs{}

	var (
		proofs proofFlag
		also   lineFlag
	)

	fs := flag.NewFlagSet("stele emit decision", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&da.policyPath, "policy", "",
		"the verify policy (required); its trust.decision names the predicate type and the conclusion")
	fs.StringVar(&da.in.Tag, "tag", "", "the release tag the decision opens (this, or --stream)")
	fs.BoolVar(&da.in.Stream, "stream", false, "the decision is for a stream: a publish with no tag")
	fs.StringVar(&da.in.Classes, "classes", "", "the evidence classes being published, as recorded (required)")
	fs.Var(&proofs, "proof",
		"one required proof as name=result, repeatable, in the order the record lists them; any result but "+
			"success refuses (at least one)")
	fs.StringVar(&da.in.Covered, "covered", "",
		"directory of the documents the decision covers (required); every regular file is a subject")
	fs.StringVar(&da.in.Inventory, "inventory", "",
		"the one planned inventory this decision is for: it covers that document and names nothing else")
	fs.Var(&also, "also",
		"a further subject line, `<sha256>  <name>`, covered beside the documents; repeatable")
	fs.StringVar(&da.predicateOut, "predicate-out", "", "file the decision predicate is written to (required)")
	fs.StringVar(&da.subjectsOut, "subjects-out", "", "file the sha256 subject lines are written to (required)")

	if err := fs.Parse(args); err != nil {
		return nil, exitUsage
	}

	da.in.Proofs, da.in.Also = proofs, also

	if err := da.load(); err != nil {
		if _, werr := fmt.Fprintf(stderr, "stele emit decision: %v\n", err); werr != nil {
			return nil, exitIO
		}

		return nil, exitUsage
	}

	return da, exitOK
}

// load requires the flags and reads the policy.
func (da *decisionArgs) load() error {
	switch {
	case da.policyPath == "":
		return errors.New("--policy is required")
	case da.in.Covered == "":
		return errors.New("--covered is required")
	case da.predicateOut == "" || da.subjectsOut == "":
		return errors.New("--predicate-out and --subjects-out are both required — the signer reads the two together")
	}

	pf, err := os.Open(da.policyPath)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	defer pf.Close() //nolint:errcheck // read-only close

	da.p, err = policy.Load(pf)

	return err
}

// runEmitDecision assembles the decision and writes both files, or
// neither. Its one stdout line is `predicate-type=<uri>`, shaped for a
// workflow step's outputs, so the signer is handed the type the policy
// names rather than a second copy of it.
func runEmitDecision(da *decisionArgs, out *latch) error {
	d, err := emit.Decide(da.p, &da.in, emitNow)
	if err != nil {
		return err
	}

	if err := os.WriteFile(da.subjectsOut, d.Subjects, ownerRW); err != nil {
		return fmt.Errorf("emit: writing the subjects: %w", err)
	}

	if err := os.WriteFile(da.predicateOut, d.Predicate, ownerRW); err != nil {
		_ = os.Remove(da.subjectsOut) //nolint:errcheck // best-effort: the run refuses either way

		return fmt.Errorf("emit: writing the predicate: %w", err)
	}

	out.logf("predicate-type=%s", d.PredicateType)

	return nil
}
