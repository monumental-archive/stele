// This file: the classes a release request declares (stele#403). The
// canon validated the requested classes against a list written in a
// workflow step and expanded them there; the vocabulary is this
// policy's evidence.classes, and the expansion is declared on the
// class that triggers it, as parameters of kinds this engine owns —
// so a stranger's classes and expansions derive with no code change.

package assert

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// ExpansionKind names one way requesting a class declares another.
type ExpansionKind string

const (
	// ExpandInstead declares the target in the class's place when the
	// expansion's input is given, and the class itself otherwise.
	ExpandInstead ExpansionKind = "instead"
	// ExpandAfter declares the target immediately after the class —
	// always, or only when the expansion's input is given.
	ExpandAfter ExpansionKind = "after"
)

// ClassExpansion is one declared expansion: the kind, then that
// kind's parameters, flat.
type ClassExpansion struct {
	// Kind selects the expansion.
	Kind *ExpansionKind `json:"kind"`
	// When names the request input the expansion turns on (required
	// for instead, optional for after).
	When *string `json:"when,omitempty"`
	// Class is the class the expansion declares.
	Class *string `json:"class"`
	// Output names a key the declaration prints: the target when the
	// expansion fired, empty otherwise. Optional.
	Output *string `json:"output,omitempty"`
}

// validateExpansions holds the declared expansions to what one pass
// can apply: known kinds with their parameters, targets the policy
// declares that declare nothing themselves, and output keys named
// once.
func validateExpansions(classes map[string]ClassPolicy) error {
	outputs := map[string]string{}

	for _, name := range slices.Sorted(maps.Keys(classes)) {
		for i, x := range classes[name].Declares {
			at := fmt.Sprintf("evidence.classes.%s.declares[%d]", name, i)

			if err := validateExpansion(at, x, classes); err != nil {
				return err
			}

			if x.Output == nil {
				continue
			}

			if prior, dup := outputs[*x.Output]; dup {
				return fmt.Errorf("%s.output %q is already %s's — one key, one answer", at, *x.Output, prior)
			}

			outputs[*x.Output] = at
		}
	}

	return nil
}

// validateExpansion holds one expansion's own parameters.
func validateExpansion(at string, x ClassExpansion, classes map[string]ClassPolicy) error {
	switch {
	case x.Kind == nil:
		return fmt.Errorf("%s names no kind (instead or after)", at)
	case *x.Kind != ExpandInstead && *x.Kind != ExpandAfter:
		return fmt.Errorf("%s.kind %q is not an expansion this engine applies (instead or after)", at, *x.Kind)
	case *x.Kind == ExpandInstead && x.When == nil:
		return fmt.Errorf("%s: an instead expansion names the input it turns on (when)", at)
	case x.When != nil && *x.When == "":
		return fmt.Errorf("%s.when is empty — an expansion turns on a named input", at)
	case x.Class == nil || *x.Class == "":
		return fmt.Errorf("%s names no class to declare", at)
	case x.Output != nil && *x.Output == "":
		return fmt.Errorf("%s.output is empty — an output key has a name", at)
	}

	target, declared := classes[*x.Class]

	switch {
	case !declared:
		return fmt.Errorf("%s.class %q is not declared in evidence.classes — an expansion declares a class the"+
			" policy knows", at, *x.Class)
	case len(target.Declares) > 0:
		return fmt.Errorf("%s.class %q declares expansions of its own — expansion is one pass, never a chain",
			at, *x.Class)
	}

	return nil
}

// ErrNoClasses is a request that names no class at all.
var ErrNoClasses = errors.New("assert: no classes requested — a release that builds nothing is not a release")

// ParseClassRequest reads a comma-separated class request. Space
// around a name is not part of it; an empty element anywhere is
// refused by position rather than dropped, because "a,,b" is a request
// somebody mistyped, and reading it as "a,b" decides for them.
func ParseClassRequest(csv string) ([]string, error) {
	if strings.TrimSpace(csv) == "" {
		return nil, ErrNoClasses
	}

	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))

	for i, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			return nil, fmt.Errorf("assert: requested class %d of %d is empty — a class request names a class"+
				" in every place", i+1, len(parts))
		}

		out = append(out, name)
	}

	return out, nil
}

// ClassOutput is one declared output key and its value.
type ClassOutput struct {
	Key, Value string
}

// ClassDeclaration is what a release request declares: the classes
// its evidence will carry, in request order after expansion, and
// every declared output key.
type ClassDeclaration struct {
	Classes []string
	Outputs []ClassOutput
}

// DeclareClasses validates the request against the classes this
// policy declares and applies their expansions in one pass, in request
// order. A class named twice is declared twice: the request is the
// caller's statement, recorded as made.
//
// Given carries the request's named inputs; an empty value is an input
// not given.
func (p *Policy) DeclareClasses(requested []string, given map[string]string) (*ClassDeclaration, error) {
	if len(requested) == 0 {
		return nil, ErrNoClasses
	}

	classes := p.Evidence.Classes

	for _, name := range requested {
		cp, declared := classes[name]

		switch {
		case !declared:
			return nil, fmt.Errorf("assert: unknown class requested: %q is not declared in evidence.classes —"+
				" an undeclared class owes evidence nobody can know", name)
		case cp.Requestable != nil && !*cp.Requestable:
			return nil, fmt.Errorf("assert: class %q is not requestable — another class's expansion declares"+
				" it, and a release never names it", name)
		}
	}

	if err := checkInputs(classes, requested, given); err != nil {
		return nil, err
	}

	fired := map[string]string{}
	d := &ClassDeclaration{}

	for _, name := range requested {
		entry, err := instead(name, classes[name].Declares, given, fired)
		if err != nil {
			return nil, err
		}

		d.Classes = append(d.Classes, entry)

		for _, x := range classes[name].Declares {
			if *x.Kind == ExpandAfter && turnsOn(x, given) {
				d.Classes = append(d.Classes, *x.Class)
				fire(x, fired)
			}
		}
	}

	for _, name := range slices.Sorted(maps.Keys(classes)) {
		for _, x := range classes[name].Declares {
			if x.Output != nil {
				d.Outputs = append(d.Outputs, ClassOutput{Key: *x.Output, Value: fired[*x.Output]})
			}
		}
	}

	return d, nil
}

// instead applies a class's instead expansions: the class itself, or
// the one target whose input is given. Two that both apply cannot both
// be the class.
func instead(name string, declares []ClassExpansion, given, fired map[string]string) (string, error) {
	var hit *ClassExpansion

	for i := range declares {
		x := &declares[i]
		if *x.Kind != ExpandInstead || !turnsOn(*x, given) {
			continue
		}

		if hit != nil {
			return "", fmt.Errorf("assert: class %q would be declared as both %q and %q — given %s and %s,"+
				" its instead expansions disagree", name, *hit.Class, *x.Class, *hit.When, *x.When)
		}

		hit = x
	}

	if hit == nil {
		return name, nil
	}

	fire(*hit, fired)

	return *hit.Class, nil
}

// turnsOn reports whether an expansion applies to this request.
func turnsOn(x ClassExpansion, given map[string]string) bool {
	return x.When == nil || given[*x.When] != ""
}

// fire records an expansion's output.
func fire(x ClassExpansion, fired map[string]string) {
	if x.Output != nil {
		fired[*x.Output] = *x.Class
	}
}

// checkInputs refuses an input no expansion turns on, and a given
// input none of whose declaring classes is requested: a declaration
// that does nothing is how a caller comes to believe something is
// built that nothing builds (#775 in the canon's history).
func checkInputs(classes map[string]ClassPolicy, requested []string, given map[string]string) error {
	declaring := map[string][]string{}

	for _, name := range slices.Sorted(maps.Keys(classes)) {
		for _, x := range classes[name].Declares {
			if x.When != nil && !slices.Contains(declaring[*x.When], name) {
				declaring[*x.When] = append(declaring[*x.When], name)
			}
		}
	}

	for _, input := range slices.Sorted(maps.Keys(given)) {
		owners, known := declaring[input]

		switch {
		case !known:
			return fmt.Errorf("assert: input %q is turned on by no expansion in evidence.classes", input)
		case given[input] == "":
			continue
		case !slices.ContainsFunc(owners, func(o string) bool { return slices.Contains(requested, o) }):
			return fmt.Errorf("assert: %s is declared but %s is not among the classes — it would build nothing",
				input, strings.Join(owners, " or "))
		}
	}

	return nil
}
