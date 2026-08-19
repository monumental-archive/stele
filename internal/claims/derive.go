// The read and the derivation. Three outcomes must stay distinct all
// the way out, because a consumer of an absent property must never
// have to guess which one it is looking at:
//
//   - FAILURE — a read errored, or a listed ruleset's detail was
//     unreadable. Refused: claiming from a blind read asserts
//     controls nobody checked.
//   - BLINDNESS — a scope some declared property matches against came
//     back empty. Declaring a property against a scope IS the
//     statement that the scope is populated, so an empty read there
//     is a credential proving its own incapability. Refused. (The
//     bash refuses this too, but by citing a fact about one org —
//     "the org tag rulesets exist". Deriving it from the table is the
//     same guard in a form every adopter gets.)
//   - ABSENCE — the read succeeded, saw rules, and none of them make
//     the control live. Claimed as nothing, which is how a lapse
//     under-claims and resets its own clock.
//
// The first two are errors from this file. The third is the only
// thing a missing property in the payload can mean, and that is
// enforced structurally: matching runs on *ruleSet, whose constructor
// refuses an empty read, so there is no reachable path from a blind
// read to a claim.

package claims

import (
	"errors"
	"fmt"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// Reader is the forge's rules surface. Low-level on purpose: WHICH
// rulesets a derivation must fetch is engine logic (the branch rules
// name their own contributors, and only active tag rulesets count),
// and a seam that answered that question would be a second copy of
// it.
type Reader interface {
	// BranchRules returns the effective rules for one branch — every
	// contributing ruleset already merged by the forge.
	BranchRules(owner, repo, branch string) ([]byte, error)
	// Rulesets lists the repository's rulesets, inherited ones
	// included.
	Rulesets(owner, repo string) ([]byte, error)
	// Ruleset returns one ruleset's full detail. Listed-but-unreadable
	// is an error and never an absence: it means the credential cannot
	// see org-level ruleset content, and a derivation that shrugged
	// would drop exactly the controls it could not read.
	Ruleset(owner, repo string, id int64) ([]byte, error)
}

// TreeReader reads the reviewed org tree a gatedTask claim rests on.
// Ref names that tree, so the evidence says which reviewed code
// defined the control.
type TreeReader interface {
	File(path string) (content []byte, ok bool, err error)
	Ref() string
}

// Logf receives progress lines; the caller owns the stream.
type Logf func(format string, args ...any)

// Deriver holds the seams one derivation runs against.
type Deriver struct {
	Rules Reader
	Tree  TreeReader
	// Now stamps rulesReadAt. A wall clock, and legitimately so: the
	// fact being recorded IS a reading event, which is what separates
	// it from every other date in this tool.
	Now func() time.Time
	Log Logf
}

// ruleSet is a read that succeeded and saw something. newRuleSet is
// the only constructor and it refuses an empty read, so a matcher
// cannot be run against blindness — the guard is the type, not a
// branch someone can forget to write.
type ruleSet struct {
	scope Scope
	elems []any
}

// newRuleSet decodes one scope's read.
func newRuleSet(scope Scope, raw []byte) (*ruleSet, error) {
	v, err := jsonx.Value(raw)
	if err != nil {
		return nil, fmt.Errorf("claims: %s: %w", scope, err)
	}

	elems, isArray := v.([]any)
	if !isArray {
		return nil, fmt.Errorf("claims: %s: the forge answered with %T, not a list of rules", scope, v)
	}

	if len(elems) == 0 {
		return nil, fmt.Errorf("claims: %s came back empty, and a property is declared against it —"+
			" refusing to claim from a blind read", scope)
	}

	return &ruleSet{scope: scope, elems: elems}, nil
}

// claim runs one property's matcher and returns its witness. A miss
// is errNoMatch with the reason, which the caller reports and treats
// as an absent control.
func (rs *ruleSet) claim(p *Property) (jsonx.Raw, error) {
	m, err := compile(p.Match)
	if err != nil {
		return nil, err
	}

	witness, ok, why := m.match(anyElems(rs.elems), string(rs.scope))
	if !ok {
		return nil, fmt.Errorf("%w: %s", errNoMatch, why)
	}

	evidence, err := jsonx.Marshal(witness)
	if err != nil {
		return nil, fmt.Errorf("claims: %s evidence: %w", *p.Name, err)
	}

	return evidence, nil
}

func anyElems(e []any) any { return e }

// Derive reads the enforcement state and builds the payload.
func (d *Deriver) Derive(t *Table, owner, repo, branch string) (*Payload, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}

	state, err := d.read(t, owner, repo, branch)
	if err != nil {
		return nil, err
	}

	controls := make([]chain.Control, 0, len(t.Properties))
	claimed := map[string]bool{}

	// Rules-scoped first: the gated leg rests on what they claimed,
	// so it cannot run in the same pass.
	for i := range t.Properties {
		p := &t.Properties[i]
		if *p.Scope == ScopeGatedTask {
			continue
		}

		ctl, ok := d.claimRules(p, state)
		if !ok {
			continue
		}

		controls = append(controls, ctl)
		claimed[*p.Name] = true
	}

	for i := range t.Properties {
		p := &t.Properties[i]
		if *p.Scope != ScopeGatedTask {
			continue
		}

		ctl, gerr := d.claimGated(p, claimed)
		if gerr != nil {
			return nil, gerr
		}

		if ctl == nil {
			continue
		}

		controls = append(controls, *ctl)
	}

	readAt := d.Now().UTC().Format(time.RFC3339)

	return &Payload{RulesReadAt: &readAt, RulesetsUpdatedAt: &state.updatedAt, Controls: &controls}, nil
}

// state is one derivation's whole view of enforcement.
type state struct {
	branchRules *ruleSet
	tagRulesets *ruleSet
	updatedAt   []int64
}

// read performs exactly the reads the table needs. A scope no
// property names is never fetched: a derivation that read what it
// does not use would invent a blindness guard for a scope nobody
// declared anything against.
func (d *Deriver) read(t *Table, owner, repo, branch string) (*state, error) {
	st := &state{updatedAt: []int64{}}

	if t.reads(ScopeBranchRules) {
		if err := d.readBranch(st, owner, repo, branch); err != nil {
			return nil, err
		}
	}

	if t.reads(ScopeTagRulesets) {
		if err := d.readTags(st, owner, repo); err != nil {
			return nil, err
		}
	}

	return st, nil
}

// readBranch reads the effective branch rules and the change times of
// every ruleset behind them — the continuity horizon a healed link is
// level-guarded against. An unreadable contributor fails the run: a
// healed link guarded against a partial horizon would over-claim.
func (d *Deriver) readBranch(st *state, owner, repo, branch string) error {
	raw, err := d.Rules.BranchRules(owner, repo, branch)
	if err != nil {
		return fmt.Errorf("claims: reading the effective rules for %s: %w", branch, err)
	}

	rs, err := newRuleSet(ScopeBranchRules, raw)
	if err != nil {
		return err
	}

	st.branchRules = rs

	ids, err := contributingIDs(rs.elems)
	if err != nil {
		return err
	}

	for _, id := range ids {
		detail, derr := d.Rules.Ruleset(owner, repo, id)
		if derr != nil {
			return fmt.Errorf("claims: ruleset %d contributes to %s but its detail is unreadable — the"+
				" credential cannot see ruleset content: %w", id, branch, derr)
		}

		if err := st.addChangeTime(detail); err != nil {
			return err
		}
	}

	d.logf("claims: %s: %d effective rule(s) from %d ruleset(s)", branch, len(rs.elems), len(ids))

	return nil
}

// readTags fetches every active tag ruleset in full. Effective
// per-ref rules exist only for branches, so tag properties match
// ruleset content and the content has to be fetched one by one.
func (d *Deriver) readTags(st *state, owner, repo string) error {
	listing, err := d.Rules.Rulesets(owner, repo)
	if err != nil {
		return fmt.Errorf("claims: listing rulesets: %w", err)
	}

	ids, err := activeTagIDs(listing)
	if err != nil {
		return err
	}

	details := make([]any, 0, len(ids))

	for _, id := range ids {
		raw, derr := d.Rules.Ruleset(owner, repo, id)
		if derr != nil {
			return fmt.Errorf("claims: tag ruleset %d is listed but its detail is unreadable — the credential"+
				" cannot see ruleset content: %w", id, derr)
		}

		v, verr := jsonx.Value(raw)
		if verr != nil {
			return fmt.Errorf("claims: tag ruleset %d: %w", id, verr)
		}

		details = append(details, v)

		if aerr := st.addChangeTime(raw); aerr != nil {
			return aerr
		}
	}

	packed, err := jsonx.Marshal(details)
	if err != nil {
		return fmt.Errorf("claims: tag rulesets: %w", err)
	}

	rs, err := newRuleSet(ScopeTagRulesets, packed)
	if err != nil {
		return err
	}

	st.tagRulesets = rs
	d.logf("claims: %d active tag ruleset(s)", len(details))

	return nil
}

// addChangeTime folds one ruleset's last-changed moment into the
// horizon. RFC 3339 offsets are a library's problem, not a
// hand-rolled one: the bash applies them by hand from captured
// substrings because jq's date built-ins are UTC-only.
func (st *state) addChangeTime(detail []byte) error {
	v, err := jsonx.Value(detail)
	if err != nil {
		return fmt.Errorf("claims: ruleset detail: %w", err)
	}

	obj, ok := v.(map[string]any)
	if !ok {
		return errors.New("claims: a ruleset detail is not an object")
	}

	for _, key := range []string{"updated_at", "created_at"} {
		stamp, present := obj[key].(string)
		if !present || stamp == "" {
			continue
		}

		at, perr := time.Parse(time.RFC3339, stamp)
		if perr != nil {
			return fmt.Errorf("claims: ruleset %s (%q): %w", key, stamp, perr)
		}

		st.updatedAt = append(st.updatedAt, at.Unix())

		return nil
	}

	// No readable change time is not a failure: the horizon simply
	// does not cover this ruleset, and an absent horizon under-claims
	// on the emit side rather than guessing.
	return nil
}

// claimRules derives one rules-scoped property.
func (d *Deriver) claimRules(p *Property, st *state) (chain.Control, bool) {
	rs := st.branchRules
	if *p.Scope == ScopeTagRulesets {
		rs = st.tagRulesets
	}

	evidence, err := rs.claim(p)
	if err != nil {
		d.logf("claims: %s absent: %v", *p.Name, err)

		return chain.Control{}, false
	}

	name := *p.Name
	d.logf("claims: %s live", name)

	return chain.Control{Property: &name, Evidence: evidence}, true
}

// gatedEvidence is what a belt-carried claim rests on: the property
// whose liveness admitted it, and the reviewed tree and table that
// define it. The bash records `via: "ci / ci"` — a restatement of the
// gate matcher, which can drift from the matcher it restates. Naming
// the property cannot.
type gatedEvidence struct {
	Via       string   `json:"via"`
	Tree      string   `json:"tree"`
	File      string   `json:"file"`
	TablePath []string `json:"tablePath"`
}

// claimGated derives one belt-carried property. It is reachable only
// with the rules-derived claim set in hand, so a gated claim without
// its gate is unrepresentable.
func (d *Deriver) claimGated(p *Property, claimed map[string]bool) (*chain.Control, error) {
	if !claimed[*p.RequiresProperty] {
		d.logf("claims: %s absent: %s is not live, so the gate carries nothing", *p.Name, *p.RequiresProperty)

		return nil, nil //nolint:nilnil // absent control, not an error — the three-outcome rule
	}

	content, ok, err := d.Tree.File(*p.File)
	if err != nil {
		return nil, fmt.Errorf("claims: %s: reading %s: %w", *p.Name, *p.File, err)
	}

	if !ok {
		d.logf("claims: %s absent: %s is not in the reviewed tree", *p.Name, *p.File)

		return nil, nil //nolint:nilnil // absent control, not an error
	}

	present, err := tomlTableExists(content, p.TablePath)
	if err != nil {
		return nil, fmt.Errorf("claims: %s: %s: %w", *p.Name, *p.File, err)
	}

	if !present {
		d.logf("claims: %s absent: %s declares no %v", *p.Name, *p.File, p.TablePath)

		return nil, nil //nolint:nilnil // absent control, not an error
	}

	evidence, err := jsonx.Marshal(gatedEvidence{
		Via: *p.RequiresProperty, Tree: d.Tree.Ref(), File: *p.File, TablePath: p.TablePath,
	})
	if err != nil {
		return nil, fmt.Errorf("claims: %s evidence: %w", *p.Name, err)
	}

	name := *p.Name
	d.logf("claims: %s live", name)

	return &chain.Control{Property: &name, Evidence: evidence}, nil
}

// tomlTableExists parses the file and walks the declared path. A
// parser, never a pattern: a table is spellable in more than one
// legal way, and grep reads exactly one of them — which under-claims
// silently for every other.
func tomlTableExists(content []byte, path []string) (bool, error) {
	var doc map[string]any
	if err := toml.Unmarshal(content, &doc); err != nil {
		return false, fmt.Errorf("not readable as TOML: %w", err)
	}

	var cursor any = doc

	for _, seg := range path {
		table, ok := cursor.(map[string]any)
		if !ok {
			return false, nil
		}

		next, present := table[seg]
		if !present {
			return false, nil
		}

		cursor = next
	}

	return true, nil
}

// contributingIDs lists the rulesets behind the effective branch
// rules, deduplicated, in first-seen order.
func contributingIDs(rules []any) ([]int64, error) {
	var (
		out  []int64
		seen = map[int64]bool{}
	)

	for i, r := range rules {
		obj, ok := r.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("claims: branch rule %d is not an object", i)
		}

		id, ok, err := numberField(obj, "ruleset_id")
		if err != nil {
			return nil, fmt.Errorf("claims: branch rule %d: %w", i, err)
		}

		if !ok || seen[id] {
			continue
		}

		seen[id] = true

		out = append(out, id)
	}

	return out, nil
}

// activeTagIDs selects the active tag rulesets from a listing.
func activeTagIDs(listing []byte) ([]int64, error) {
	v, err := jsonx.Value(listing)
	if err != nil {
		return nil, fmt.Errorf("claims: ruleset listing: %w", err)
	}

	entries, ok := v.([]any)
	if !ok {
		return nil, errors.New("claims: the ruleset listing is not a list")
	}

	var out []int64

	for i, e := range entries {
		obj, isObj := e.(map[string]any)
		if !isObj {
			return nil, fmt.Errorf("claims: ruleset listing entry %d is not an object", i)
		}

		if obj["target"] != "tag" || obj["enforcement"] != "active" {
			continue
		}

		id, present, ferr := numberField(obj, "id")
		if ferr != nil {
			return nil, fmt.Errorf("claims: ruleset listing entry %d: %w", i, ferr)
		}

		if !present {
			return nil, fmt.Errorf("claims: ruleset listing entry %d has no id", i)
		}

		out = append(out, id)
	}

	return out, nil
}

// numberField reads one integral field: the value, whether the key
// was present, and any error reading it.
//
//nolint:gocritic // unnamedResult: value, present, error
func numberField(obj map[string]any, key string) (int64, bool, error) {
	raw, present := obj[key]
	if !present {
		return 0, false, nil
	}

	num, ok := raw.(jsonx.Number)
	if !ok {
		return 0, false, fmt.Errorf("%s is not a number", key)
	}

	id, err := num.Int64()
	if err != nil {
		return 0, false, fmt.Errorf("%s: %w", key, err)
	}

	return id, true, nil
}

func (d *Deriver) logf(format string, args ...any) {
	if d.Log != nil {
		d.Log(format, args...)
	}
}
