// `derive inventory-plan`: the inventory plan a build leg states
// about what it built (stele#396). How a class's leg plans is the
// class's own declaration in the assert policy — its inventory kind
// and that kind's parameters — and its documents are named under its
// planned prefix there, so the producer and `assert plans` read one
// declaration. This file is the argument surface and the placement.

package cli

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/monumental-archive/stele/internal/inventoryplan"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// deriveInventoryPlan is the mode name.
const deriveInventoryPlan = "inventory-plan"

// inventoryPlanArgs is the mode's whole argument surface.
type inventoryPlanArgs struct {
	class  string
	policy string
	out    string
	in     inventoryplan.PlanInputs
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
		"the assert policy: the class's inventory declaration and planned prefix (required)")
	flags.StringVar(&pa.out, "out", "", "file to write the plan to; empty prints to stdout")
	flags.StringVar(&pa.in.Dir, "dir", "", "directory holding the packaged crates (a crates leg)")
	flags.StringVar(&pa.in.Version, "version", "", "the version every packaged crate is named for (a crates leg)")
	flags.StringVar(&pa.in.CrateDir, "crate-dir", "", "the crate this cell built (a variants leg)")
	flags.StringVar(&pa.in.Variant, "variant", "", "the variant this cell built (a variants leg)")

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

	return pa, exitOK
}

// runDeriveInventoryPlan reads the class's declaration, writes the
// plan, and names every document it planned.
func runDeriveInventoryPlan(pa *inventoryPlanArgs, doc io.Writer, out *latch) error {
	pol, err := loadAssertPolicy(pa.policy)
	if err != nil {
		return fmt.Errorf("derive inventory-plan: %w", err)
	}

	cp, ok := pol.Evidence.Classes[pa.class]
	if !ok {
		return fmt.Errorf("derive inventory-plan: class %q is not declared in the assert policy", pa.class)
	}

	entries, err := inventoryplan.InventoryPlan(pa.class, &cp, &pa.in)
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
