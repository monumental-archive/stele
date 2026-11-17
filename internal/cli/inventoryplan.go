// `derive inventory-plan`: the inventory plan a build leg states about what it
// built (stele#396). The class definitions — how a class's leg plans
// — are the release contract's own (internal/release); the prefix the
// documents are named under is the class's planned prefix in the
// assert policy, so the producer and `assert plans` read one name.
// This file is the argument surface and the placement, nothing else.

package cli

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/release"
)

// deriveInventoryPlan is the mode name.
const deriveInventoryPlan = "inventory-plan"

// inventoryPlanArgs is the mode's whole argument surface.
type inventoryPlanArgs struct {
	class    string
	policy   string
	out      string
	in       release.PlanInputs
	producer *release.PlanClass
}

// parseInventoryPlanArgs parses and validates the flags.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseInventoryPlanArgs(args []string, stderr io.Writer) (*inventoryPlanArgs, int) {
	pa := &inventoryPlanArgs{}

	flags := flag.NewFlagSet("stele derive inventory-plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&pa.class, "class", "", "the evidence class whose build leg this is (required)")
	flags.StringVar(&pa.policy, "policy", "",
		"the assert policy: the class's planned prefix names the documents (required)")
	flags.StringVar(&pa.out, "out", "", "file to write the plan to; empty prints to stdout")
	flags.StringVar(&pa.in.Dir, "dir", "", "directory holding the packaged crates (a crates leg)")
	flags.StringVar(&pa.in.Version, "version", "", "the version every packaged crate is named for (a crates leg)")
	flags.StringVar(&pa.in.CrateDir, "crate-dir", "", "the extension crate's directory (an extension leg)")
	flags.StringVar(&pa.in.Major, "major", "", "the Postgres major this cell built (an extension leg)")

	if err := flags.Parse(args); err != nil {
		return pa, exitUsage
	}

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele derive inventory-plan: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch {
	case flags.NArg() > 0:
		return pa, usageFail(fmt.Sprintf("unexpected argument %q", flags.Arg(0)))
	case pa.class == "":
		return pa, usageFail("--class is required")
	case pa.policy == "":
		return pa, usageFail("--policy is required")
	}

	producer, ok := release.PlanClassNamed(pa.class)
	if !ok {
		return pa, usageFail(fmt.Sprintf("unknown class %q: plans are produced for %s",
			pa.class, strings.Join(release.PlanClasses(), ", ")))
	}

	pa.producer = producer

	return pa, exitOK
}

// runDeriveInventoryPlan reads the class's planned prefix, writes the plan,
// and names every document it planned.
func runDeriveInventoryPlan(pa *inventoryPlanArgs, doc io.Writer, out *latch) error {
	prefix, err := plannedPrefix(pa.policy, pa.class)
	if err != nil {
		return err
	}

	pa.in.Prefix = prefix

	entries, err := pa.producer.Plan(&pa.in)
	if err != nil {
		return fmt.Errorf("derive inventory-plan: %w", err)
	}

	var rendered bytes.Buffer
	if err := jsonx.EncodeIndent(&rendered, entries); err != nil {
		return fmt.Errorf("derive inventory-plan: %w", err)
	}

	if pa.out == "" {
		if out.err == nil {
			_, out.err = doc.Write(rendered.Bytes())
		}
	} else if err := os.WriteFile(pa.out, rendered.Bytes(), ownerRW); err != nil {
		return fmt.Errorf("derive inventory-plan: %w", err)
	}

	for _, e := range entries {
		out.logf("plans inventory %s for package %s", e.Doc, e.Params.CargoPackage)
	}

	return nil
}

// plannedPrefix is the one prefix the assert policy declares this
// class's plans under. A class declaring none owes no planned
// inventory, and one declaring several leaves the leg no way to
// choose: both are refused rather than guessed.
func plannedPrefix(path, class string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return "", fmt.Errorf("derive inventory-plan: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only close

	pol, err := assert.LoadPolicy(f)
	if err != nil {
		return "", fmt.Errorf("derive inventory-plan: %w", err)
	}

	cp, ok := pol.Evidence.Classes[class]
	if !ok {
		return "", fmt.Errorf("derive inventory-plan: class %q is not declared in the assert policy", class)
	}

	prefixes := cp.PlannedPrefixes()

	switch len(prefixes) {
	case 0:
		return "", fmt.Errorf(
			"derive inventory-plan: class %q declares no planned prefix — it owes no planned inventory", class,
		)
	case 1:
		return prefixes[0], nil
	default:
		return "", fmt.Errorf("derive inventory-plan: class %q declares %d planned prefixes (%s) — a leg plans under one",
			class, len(prefixes), strings.Join(prefixes, ", "))
	}
}
