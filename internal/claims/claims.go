// Package claims derives an org's control claims from the forge's
// live enforcement state, and carries the payload those claims travel
// in. Ground truth is the rules API at the moment of emission, never
// configuration intent: a property whose rule is not live is simply
// absent, which is how a lapse under-claims and resets its own clock
// by construction.
//
// The design rule is the one report.Seal holds for the judging verbs,
// pointed the other way. There, the only constructor computes the
// verdict, so a green report that skipped the coverage question
// cannot exist. Here, a claim can only be constructed from a
// *RuleSet, and a *RuleSet can only be constructed from a read that
// succeeded and saw something — so claiming from a blind read is not
// a guard that can be forgotten, it is a program that does not
// compile. That distinction is the whole reason this package exists:
// absence must mean "the control is not live" and nothing else, or a
// consumer has to guess whether an absent property is a lapse or a
// narrowed credential.
//
// This file holds the payload and the declared table; match.go the
// match language; derive.go the read and the derivation.
package claims

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/monumental-archive/stele/internal/chain"
)

// Payload is what the claims stage produces and the emitter consumes:
// when enforcement was read, when each contributing ruleset last
// changed (epochs — the continuity horizon), and the derived control
// claims.
//
// It crosses a job boundary as JSON because the two stages hold
// disjoint capabilities by design (the reading credential must never
// be in the signing job), but it is ONE type on both sides. A second
// shape-check written in another language beside this one would be a
// second definition of the same contract, and the two would drift.
//
// Slices are pointers so an absent array and an empty one stay
// different facts: a payload with zero controls is an honest lapse;
// one MISSING the key is malformed.
type Payload struct {
	RulesReadAt       *string          `json:"rulesReadAt"`
	RulesetsUpdatedAt *[]int64         `json:"rulesetsUpdatedAt"`
	Controls          *[]chain.Control `json:"controls"`
}

// Validate refuses a payload whose shape could not have come from an
// honest claims stage.
func (p *Payload) Validate() error {
	if p.RulesReadAt == nil {
		return errors.New("claims: rulesReadAt is absent")
	}

	if _, err := time.Parse(time.RFC3339, *p.RulesReadAt); err != nil {
		return fmt.Errorf("claims: rulesReadAt: %w", err)
	}

	if p.RulesetsUpdatedAt == nil {
		return errors.New("claims: rulesetsUpdatedAt is absent — absent and empty are different facts")
	}

	if p.Controls == nil {
		return errors.New("claims: controls is absent — absent and an honest empty claim set are different facts")
	}

	for i, ctl := range *p.Controls {
		if ctl.Property == nil || *ctl.Property == "" {
			return fmt.Errorf("claims: controls[%d].property is absent or empty", i)
		}

		if len(ctl.Evidence) == 0 {
			return fmt.Errorf("claims: controls[%d] carries no evidence", i)
		}
	}

	return nil
}

// Horizon is the newest moment any contributing ruleset changed, and
// false when no change times were readable — absent under-claims.
func (p *Payload) Horizon() (int64, bool) {
	epochs := *p.RulesetsUpdatedAt
	if len(epochs) == 0 {
		return 0, false
	}

	newest := epochs[0]
	for _, e := range epochs[1:] {
		if e > newest {
			newest = e
		}
	}

	return newest, true
}

// Properties reports the claimed property set.
func (p *Payload) Properties() map[string]bool {
	out := make(map[string]bool, len(*p.Controls))

	for _, ctl := range *p.Controls {
		if ctl.Property != nil {
			out[*ctl.Property] = true
		}
	}

	return out
}

// Scope names where a property's matcher looks. The vocabulary is
// closed: each entry is a different KIND of evidence, not a different
// path into one, and an org that needs a fourth is asking for a
// mechanism this tool does not have rather than a string it can
// spell.
type Scope string

// The three scopes. See docs/policy-schema.md, `source.claims`.
const (
	// ScopeBranchRules matches the effective rules for the branch
	// being claimed, as the forge computes them — every contributing
	// ruleset already merged.
	ScopeBranchRules Scope = "branchRules"
	// ScopeTagRulesets matches each active tag ruleset's content.
	// Effective per-ref rules exist only for branches, so tag
	// properties are matched against conditions, rules and bypass
	// actors together.
	ScopeTagRulesets Scope = "tagRulesets"
	// ScopeGatedTask matches a control the org enforces inside its
	// own gate: claimable exactly when the named property is claimed
	// and the declared table exists in the declared file.
	ScopeGatedTask Scope = "gatedTask"
)

// Table is the declared control table — the frozen mapping from
// property name to what makes that property live. Everything in it
// is an org convention; nothing in it is in code.
type Table struct {
	Properties []Property `json:"properties"`
}

// Property is one declared control. The fields divide by scope, which
// is why they are individually optional and jointly validated: a
// rules-scoped property carries Match, a gated one carries
// RequiresProperty, File and TablePath, and neither may carry the
// other's.
type Property struct {
	Name  *string   `json:"name"`
	Scope *Scope    `json:"scope"`
	Match matchTree `json:"match,omitempty"`

	RequiresProperty *string  `json:"requiresProperty,omitempty"`
	File             *string  `json:"file,omitempty"`
	TablePath        []string `json:"tablePath,omitempty"`
}

// Validate refuses a table that could not derive honest claims. It is
// called from the policy loader, so everything below is refused
// before any emission consumes a field.
func (t *Table) Validate() error {
	if len(t.Properties) == 0 {
		return errors.New("claims.properties is empty — a table declaring no control claims nothing")
	}

	byName := make(map[string]Scope, len(t.Properties))

	for i := range t.Properties {
		if err := t.Properties[i].validate(); err != nil {
			return err
		}

		name := *t.Properties[i].Name
		if _, dup := byName[name]; dup {
			return fmt.Errorf("claims.properties: %q is declared twice — one property, one derivation", name)
		}

		byName[name] = *t.Properties[i].Scope
	}

	// The gated leg is resolved in a second pass over already-derived
	// claims, so its precondition must be a rules-scoped property in
	// this same table. One level, deliberately: a chain of gated
	// properties would need an ordering, and an ordering would need a
	// cycle check to be wrong about.
	for i := range t.Properties {
		p := &t.Properties[i]
		if *p.Scope != ScopeGatedTask {
			continue
		}

		scope, ok := byName[*p.RequiresProperty]

		switch {
		case !ok:
			return fmt.Errorf("claims.properties[%s].requiresProperty names %q, which is not declared",
				*p.Name, *p.RequiresProperty)
		case scope == ScopeGatedTask:
			return fmt.Errorf("claims.properties[%s].requiresProperty names %q, which is itself a gatedTask —"+
				" a gated claim rests on a forge-enforced one, never on another gated claim",
				*p.Name, *p.RequiresProperty)
		}
	}

	return nil
}

// Declares reports whether the table can derive the named property —
// the loader's cross-check against the required-property list.
func (t *Table) Declares(name string) bool {
	for i := range t.Properties {
		if t.Properties[i].Name != nil && *t.Properties[i].Name == name {
			return true
		}
	}

	return false
}

// validate refuses one property whose fields do not match its scope.
func (p *Property) validate() error {
	if p.Name == nil || *p.Name == "" {
		return errors.New("claims.properties: an entry has no name")
	}

	if p.Scope == nil {
		return fmt.Errorf("claims.properties[%s] has no scope", *p.Name)
	}

	switch *p.Scope {
	case ScopeBranchRules, ScopeTagRulesets:
		return p.validateRules()
	case ScopeGatedTask:
		return p.validateGated()
	default:
		return fmt.Errorf("claims.properties[%s]: scope %q is not one of %s, %s, %s",
			*p.Name, *p.Scope, ScopeBranchRules, ScopeTagRulesets, ScopeGatedTask)
	}
}

// validateRules holds the rules-scoped shape.
func (p *Property) validateRules() error {
	switch {
	case len(p.Match) == 0:
		return fmt.Errorf("claims.properties[%s] is rules-scoped but declares no match", *p.Name)
	case p.RequiresProperty != nil, p.File != nil, len(p.TablePath) > 0:
		return fmt.Errorf("claims.properties[%s] is rules-scoped but carries gatedTask fields", *p.Name)
	}

	m, err := compile(p.Match)
	if err != nil {
		return fmt.Errorf("claims.properties[%s]: %w", *p.Name, err)
	}

	// A scope is always an array, so a matcher that cannot match an
	// array can never claim its property — a permanent silent
	// under-claim, refused here rather than discovered in a year by
	// someone reading a level that never rose.
	if !m.matchesArray() {
		return fmt.Errorf("claims.properties[%s]: the top-level match is an object, which can never match a"+
			" rule list — use $contains, or an array for an exact list", *p.Name)
	}

	return nil
}

// validateGated holds the gatedTask shape.
func (p *Property) validateGated() error {
	switch {
	case len(p.Match) > 0:
		return fmt.Errorf("claims.properties[%s] is a gatedTask but carries a match", *p.Name)
	case p.RequiresProperty == nil || *p.RequiresProperty == "":
		return fmt.Errorf("claims.properties[%s] is a gatedTask with no requiresProperty — a gated claim with no"+
			" gate is an unconditional claim wearing a condition", *p.Name)
	case p.File == nil || *p.File == "":
		return fmt.Errorf("claims.properties[%s] declares no file", *p.Name)
	case len(p.TablePath) == 0:
		return fmt.Errorf("claims.properties[%s] declares no tablePath", *p.Name)
	}

	if slices.Contains(p.TablePath, "") {
		return fmt.Errorf("claims.properties[%s]: tablePath has an empty segment", *p.Name)
	}

	return nil
}

// NeedsTree reports whether deriving this table requires a reviewed
// tree — true when any property is gated on one. The caller asks so
// it can refuse a missing tree by flag name up front, rather than
// half-way through a derivation.
func (t *Table) NeedsTree() bool {
	for i := range t.Properties {
		if t.Properties[i].Scope != nil && *t.Properties[i].Scope == ScopeGatedTask {
			return true
		}
	}

	return false
}

// reads reports whether any declared property matches against scope,
// which is what makes an empty read of that scope blindness rather
// than an absent control. A scope nothing names is never read.
func (t *Table) reads(scope Scope) bool {
	for i := range t.Properties {
		if t.Properties[i].Scope != nil && *t.Properties[i].Scope == scope {
			return true
		}
	}

	return false
}
