// `derive classes`: the evidence classes a release request declares
// (stele#403). The vocabulary is the assert policy's evidence.classes;
// this file is the argument surface and the printing, nothing else.
// What the event is — a tag, a version — stays the workflow's.

package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/monumental-archive/stele/internal/assert"
)

// deriveClasses is the mode name.
const deriveClasses = "classes"

// classesArgs is the mode's whole argument surface.
type classesArgs struct {
	policy  string
	classes string
	given   givenFlag
}

// givenFlag collects `--given name=value`, one value per name.
type givenFlag map[string]string

func (g givenFlag) String() string { return fmt.Sprint(map[string]string(g)) }

// Set splits at the first '=': an input's name never carries one, its
// value (a crate, a path) may.
func (g givenFlag) Set(v string) error {
	name, value, ok := strings.Cut(v, "=")

	if !ok || name == "" {
		return fmt.Errorf("--given %q is not name=value", v)
	}

	if _, dup := g[name]; dup {
		return fmt.Errorf("--given %s is named twice — one input has one value", name)
	}

	g[name] = value

	return nil
}

// deriveClassesCmd runs `stele derive classes`.
func deriveClassesCmd(args []string, stdout, stderr io.Writer) int {
	ca, code := parseClassesArgs(args, stderr)
	if code != exitOK {
		return code
	}

	return runDeriveMode("", stdout, stderr,
		func(doc io.Writer, log *latch) error { return runDeriveClasses(ca, doc, log) })
}

// parseClassesArgs parses and validates the flags.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseClassesArgs(args []string, stderr io.Writer) (*classesArgs, int) {
	ca := &classesArgs{given: givenFlag{}}

	flags := flag.NewFlagSet("stele derive classes", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&ca.policy, "policy", "",
		"path to the assert policy whose evidence.classes is the vocabulary (required)")
	flags.StringVar(&ca.classes, "classes", "", "the requested classes, comma-separated (required)")
	flags.Var(ca.given, "given",
		"a request input an expansion turns on, as name=value; repeatable, and an empty value is not given")

	if err := flags.Parse(args); err != nil {
		return nil, exitUsage
	}

	if ca.policy == "" {
		if _, err := fmt.Fprintln(stderr, "stele derive classes: --policy is required"); err != nil {
			return nil, exitIO
		}

		return nil, exitUsage
	}

	return ca, exitOK
}

// runDeriveClasses validates the request and prints the declaration
// as `key=value` lines, the shape a workflow step's outputs take:
// classes first, then every declared output key in policy order,
// always — an output whose expansion did not fire is printed empty.
func runDeriveClasses(ca *classesArgs, doc io.Writer, out *latch) error {
	pol, err := loadAssertPolicy(ca.policy)
	if err != nil {
		return fmt.Errorf("derive classes: %w", err)
	}

	requested, err := assert.ParseClassRequest(ca.classes)
	if err != nil {
		return fmt.Errorf("derive classes: %w", err)
	}

	d, err := pol.DeclareClasses(requested, ca.given)
	if err != nil {
		return fmt.Errorf("derive classes: %w", err)
	}

	out.logf("derive: classes: the evidence declares %s", strings.Join(d.Classes, ","))

	lines := []string{"classes=" + strings.Join(d.Classes, ",")}
	for _, o := range d.Outputs {
		lines = append(lines, o.Key+"="+o.Value)
	}

	if _, err := fmt.Fprintln(doc, strings.Join(lines, "\n")); err != nil {
		out.err = err
	}

	return nil
}
