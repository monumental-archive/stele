// The derivation end to end, against the org's real frozen table and
// the same recorded rule fixtures the canon's dry run uses.
//
// The three cases that dry run exists to prove are rows here, by
// name — a blind read refuses, a readable-but-lapsed ruleset drops
// exactly its own property, and the full set derives the whole claim
// set in the shape the emitter accepts. That is the whole of
// dryrun.sh (77 lines of bash driving the real script under a lint
// task), moved into the gate.
//
// Degraded fixtures are DERIVED from the one canonical set, never
// written as second copies — the same discipline the bash dry run
// holds with jq, for the same reason: a second copy drifts.

package claims_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/claims"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// The recorded rules-API responses. Carried here because this engine
// is what they now exercise; the canon's copies leave with
// dryrun.sh.
const (
	branchRulesJSON = `[
	  {"type": "deletion", "ruleset_id": 1},
	  {"type": "non_fast_forward", "ruleset_id": 1},
	  {"type": "required_linear_history", "ruleset_id": 1},
	  {"type": "required_signatures", "ruleset_id": 1},
	  {"type": "required_status_checks", "ruleset_id": 1, "parameters": {
	    "strict_required_status_checks_policy": true,
	    "required_status_checks": [{"context": "ci / ci", "integration_id": 15368}]}},
	  {"type": "pull_request", "ruleset_id": 1, "parameters": {
	    "required_review_thread_resolution": true,
	    "allowed_merge_methods": ["squash"]}}
	]`

	rulesetListingJSON = `[
	  {"id": 1, "target": "branch", "enforcement": "active"},
	  {"id": 101, "target": "tag", "enforcement": "active"},
	  {"id": 102, "target": "tag", "enforcement": "active"},
	  {"id": 103, "target": "tag", "enforcement": "evaluate"},
	  {"id": 104, "target": "push", "enforcement": "active"}
	]`

	branchRulesetJSON = `{"id": 1, "target": "branch", "enforcement": "active",
	  "updated_at": "2020-01-01T00:00:00Z"}`

	immutableRulesetJSON = `{"id": 101, "target": "tag", "enforcement": "active",
	  "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}},
	  "rules": [{"type": "update"}, {"type": "deletion"}, {"type": "non_fast_forward"}],
	  "bypass_actors": [], "updated_at": "2020-01-01T00:00:00.000+01:00"}`

	mintedRulesetJSON = `{"id": 102, "target": "tag", "enforcement": "active",
	  "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
	  "rules": [{"type": "creation"}],
	  "bypass_actors": [{"actor_id": 4534781, "actor_type": "Integration", "bypass_mode": "always"}],
	  "updated_at": "2020-01-01T00:00:00.000+01:00"}`
)

// orgTableJSON is the org's frozen control table, verbatim from
// docs/policy-schema.md's `source.claims`.
const orgTableJSON = `{
  "properties": [
    {"name": "ORG_SOURCE_HISTORY_PROTECTED", "scope": "branchRules",
     "match": {"$contains": [{"type": "deletion"}, {"type": "non_fast_forward"},
       {"type": "required_linear_history"}]}},
    {"name": "ORG_SOURCE_SIGNED", "scope": "branchRules",
     "match": {"$contains": [{"type": "required_signatures"}]}},
    {"name": "ORG_SOURCE_GATED", "scope": "branchRules",
     "match": {"$contains": [{"type": "required_status_checks", "parameters": {
       "strict_required_status_checks_policy": true,
       "required_status_checks": {"$contains": [{"context": "ci / ci", "integration_id": 15368}]}}}]}},
    {"name": "ORG_SOURCE_REVIEWED_THREADS", "scope": "branchRules",
     "match": {"$contains": [{"type": "pull_request", "parameters": {
       "required_review_thread_resolution": true, "allowed_merge_methods": ["squash"]}}]}},
    {"name": "ORG_SOURCE_TAG_IMMUTABLE", "scope": "tagRulesets",
     "match": {"$contains": [{
       "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}},
       "rules": {"$contains": [{"type": "update"}, {"type": "deletion"}, {"type": "non_fast_forward"}]},
       "bypass_actors": []}]}},
    {"name": "ORG_SOURCE_RELEASE_TAG_MINTED", "scope": "tagRulesets",
     "match": {"$contains": [{
       "conditions": {"ref_name": {"include": ["refs/tags/v*"]}},
       "rules": {"$contains": [{"type": "creation"}]},
       "bypass_actors": [{"actor_id": 4534781, "actor_type": "Integration", "bypass_mode": "always"}]}]}},
    {"name": "ORG_SOURCE_DCO", "scope": "gatedTask", "requiresProperty": "ORG_SOURCE_GATED",
     "file": "mise/config.toml", "tablePath": ["tasks", "lint:dco"]},
    {"name": "ORG_SOURCE_CAPABILITY_BOUNDARY", "scope": "gatedTask", "requiresProperty": "ORG_SOURCE_GATED",
     "file": "mise/config.toml", "tablePath": ["tasks", "lint:capability-boundary"]}
  ]
}`

// beltConfig is the reviewed tree's task declaration, in a spelling
// the bash's `grep -q '^\[tasks."lint:dco"\]'` would MISS — a dotted
// key and an inline table are both legal TOML for the same table.
// The parser reads them; a pattern reads one.
const beltConfig = `
[tasks]
"lint:dco" = { run = "belt dco" }

[tasks."lint:capability-boundary"]
run = "belt capability-boundary"
`

func orgTable(t *testing.T) *claims.Table {
	t.Helper()

	table, err := jsonx.DecodeBytes[claims.Table]([]byte(orgTableJSON))
	if err != nil {
		t.Fatalf("decode the org table: %v", err)
	}

	return table
}

// fakeRules scripts the forge's rules surface.
type fakeRules struct {
	branch     string
	branchErr  error
	listing    string
	listingErr error
	rulesets   map[int64]string
	rulesetErr map[int64]error
	fetched    []int64
}

func (f *fakeRules) BranchRules(_, _, _ string) ([]byte, error) {
	if f.branchErr != nil {
		return nil, f.branchErr
	}

	return []byte(f.branch), nil
}

func (f *fakeRules) Rulesets(_, _ string) ([]byte, error) {
	if f.listingErr != nil {
		return nil, f.listingErr
	}

	return []byte(f.listing), nil
}

func (f *fakeRules) Ruleset(_, _ string, id int64) ([]byte, error) {
	f.fetched = append(f.fetched, id)

	if err := f.rulesetErr[id]; err != nil {
		return nil, err
	}

	body, ok := f.rulesets[id]
	if !ok {
		return nil, errors.New("no such ruleset")
	}

	return []byte(body), nil
}

// fakeTree scripts the reviewed canon tree.
type fakeTree struct {
	files map[string]string
	err   error
}

//nolint:gocritic // unnamedResult: content, found, error — the TreeReader shape
func (f fakeTree) File(path string) ([]byte, bool, error) {
	if f.err != nil {
		return nil, false, f.err
	}

	body, found := f.files[path]

	return []byte(body), found, nil
}

func (fakeTree) Ref() string { return "canonref" }

// liveRules returns the full, healthy fixture set.
func liveRules() *fakeRules {
	return &fakeRules{
		branch:  branchRulesJSON,
		listing: rulesetListingJSON,
		rulesets: map[int64]string{
			1: branchRulesetJSON, 101: immutableRulesetJSON, 102: mintedRulesetJSON,
		},
		rulesetErr: map[int64]error{},
	}
}

func liveTree() fakeTree {
	return fakeTree{files: map[string]string{"mise/config.toml": beltConfig}}
}

// deriver wires the seams with a frozen clock.
func deriver(rules claims.Reader, tree claims.TreeReader) *claims.Deriver {
	return &claims.Deriver{
		Rules: rules,
		Tree:  tree,
		Now:   func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) },
	}
}

// properties lists a payload's claims in order.
func properties(p *claims.Payload) []string {
	out := make([]string, 0, len(*p.Controls))
	for _, ctl := range *p.Controls {
		out = append(out, *ctl.Property)
	}

	return out
}

// mutate decodes a ruleset, hands it to fn, and re-encodes — how
// every degraded fixture below is derived from the canonical one.
func mutate(t *testing.T, doc string, fn func(map[string]any)) string {
	t.Helper()

	v, err := jsonx.Value([]byte(doc))
	if err != nil {
		t.Fatalf("mutate: %v", err)
	}

	obj, ok := v.(map[string]any)
	if !ok {
		t.Fatal("mutate: not an object")
	}

	fn(obj)

	raw, err := jsonx.Marshal(obj)
	if err != nil {
		t.Fatalf("mutate: %v", err)
	}

	return string(raw)
}

// The full fixture set derives the whole claim set, in declaration
// order, in the shape the emitter's decoder accepts.
func TestDeriveTheWholeClaimSet(t *testing.T) {
	t.Parallel()

	payload, err := deriver(liveRules(), liveTree()).Derive(orgTable(t), "acme", "widget", "main")
	if err != nil {
		t.Fatalf("Derive = %v", err)
	}

	if err := payload.Validate(); err != nil {
		t.Fatalf("the derived payload is not one the emitter accepts: %v", err)
	}

	want := []string{
		"ORG_SOURCE_HISTORY_PROTECTED", "ORG_SOURCE_SIGNED", "ORG_SOURCE_GATED",
		"ORG_SOURCE_REVIEWED_THREADS", "ORG_SOURCE_TAG_IMMUTABLE", "ORG_SOURCE_RELEASE_TAG_MINTED",
		"ORG_SOURCE_DCO", "ORG_SOURCE_CAPABILITY_BOUNDARY",
	}

	got := properties(payload)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("claimed %v, want %v", got, want)
	}

	if *payload.RulesReadAt != "2026-08-18T12:00:00Z" {
		t.Fatalf("rulesReadAt = %q", *payload.RulesReadAt)
	}

	// The horizon covers every contributing ruleset: the branch's own
	// plus both tag rulesets, offsets applied.
	if len(*payload.RulesetsUpdatedAt) != 3 {
		t.Fatalf("rulesetsUpdatedAt = %v, want one epoch per contributing ruleset", *payload.RulesetsUpdatedAt)
	}

	// 2020-01-01T00:00:00+01:00 is an hour BEFORE the UTC midnight —
	// the offset arithmetic the bash does by hand in jq.
	epochs := *payload.RulesetsUpdatedAt
	if epochs[0] != 1577836800 || epochs[1] != 1577833200 {
		t.Fatalf("epochs = %v, want the UTC ruleset then the +01:00 ones an hour earlier", epochs)
	}
}

// The evidence a claim carries is the matcher's witness. The row that
// matters: bypass_actors is present in the immutability evidence,
// because it is what the matcher examined — the field the bash's
// hand-written projection omits.
func TestEvidenceIsTheWitness(t *testing.T) {
	t.Parallel()

	payload, err := deriver(liveRules(), liveTree()).Derive(orgTable(t), "acme", "widget", "main")
	if err != nil {
		t.Fatalf("Derive = %v", err)
	}

	evidence := map[string]string{}
	for _, ctl := range *payload.Controls {
		evidence[*ctl.Property] = string(ctl.Evidence)
	}

	tests := []struct {
		property string
		want     string
	}{
		{
			"ORG_SOURCE_TAG_IMMUTABLE",
			`[{"bypass_actors":[],"conditions":{"ref_name":{"exclude":[],"include":["~ALL"]}},` +
				`"rules":[{"type":"update"},{"type":"deletion"},{"type":"non_fast_forward"}]}]`,
		},
		{
			"ORG_SOURCE_SIGNED",
			`[{"type":"required_signatures"}]`,
		},
		{
			"ORG_SOURCE_DCO",
			`{"via":"ORG_SOURCE_GATED","tree":"canonref","file":"mise/config.toml",` +
				`"tablePath":["tasks","lint:dco"]}`,
		},
	}

	for _, tt := range tests {
		if got := evidence[tt.property]; got != tt.want {
			t.Fatalf("%s evidence =\n  %s\nwant\n  %s", tt.property, got, tt.want)
		}
	}
}

// Blindness and failure are refusals; only a readable non-match is an
// absence. Every branch that decides which of the three a run is in.
func TestReadRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		degrade func(*fakeRules)
		want    string
	}{
		{
			"an empty tag read is the credential proving its own incapability",
			func(f *fakeRules) { f.listing = `[]` },
			"blind read",
		},
		{
			"an empty branch read is blindness too",
			func(f *fakeRules) { f.branch = `[]` },
			"blind read",
		},
		{
			"a branch read that errored cannot become an absent control",
			func(f *fakeRules) { f.branchErr = errors.New("503") },
			"reading the effective rules",
		},
		{
			"a ruleset listing that errored refuses",
			func(f *fakeRules) { f.listingErr = errors.New("403") },
			"listing rulesets",
		},
		{
			"a listed tag ruleset whose detail is unreadable refuses",
			func(f *fakeRules) { f.rulesetErr[101] = errors.New("403") },
			"cannot see ruleset content",
		},
		{
			"a branch ruleset whose detail is unreadable refuses: a partial horizon would over-claim",
			func(f *fakeRules) { f.rulesetErr[1] = errors.New("403") },
			"cannot see ruleset content",
		},
		{
			"a branch read that is not a list refuses",
			func(f *fakeRules) { f.branch = `{"type": "deletion"}` },
			"not a list of rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rules := liveRules()
			tt.degrade(rules)

			_, err := deriver(rules, liveTree()).Derive(orgTable(t), "acme", "widget", "main")
			if err == nil {
				t.Fatal("Derive = nil error, want a refusal")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Derive = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// A lapse must under-claim, never fail — and must drop EXACTLY its
// own property.
func TestLapseDropsExactlyItsOwnProperty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		degrade func(*testing.T, *fakeRules)
		gone    string
		kept    string
	}{
		{
			"a bypass actor granted on the all-tags ruleset drops immutability alone",
			func(t *testing.T, f *fakeRules) {
				t.Helper()
				f.rulesets[101] = mutate(t, immutableRulesetJSON, func(o map[string]any) {
					o["bypass_actors"] = []any{map[string]any{"actor_id": 1}}
				})
			},
			"ORG_SOURCE_TAG_IMMUTABLE",
			"ORG_SOURCE_RELEASE_TAG_MINTED",
		},
		{
			"a second bypass actor beside the minting app drops minting alone",
			func(t *testing.T, f *fakeRules) {
				t.Helper()
				f.rulesets[102] = mutate(t, mintedRulesetJSON, func(o map[string]any) {
					actors, isList := o["bypass_actors"].([]any)
					if !isList {
						t.Fatal("the minted fixture has no bypass_actors list")
					}

					o["bypass_actors"] = append(actors, map[string]any{
						"actor_id": 7, "actor_type": "OrganizationAdmin", "bypass_mode": "always",
					})
				})
			},
			"ORG_SOURCE_RELEASE_TAG_MINTED",
			"ORG_SOURCE_TAG_IMMUTABLE",
		},
		{
			"an unbound required check drops the gate alone",
			func(t *testing.T, f *fakeRules) {
				t.Helper()
				f.branch = strings.Replace(branchRulesJSON, `"integration_id": 15368`, `"integration_id": 1`, 1)
			},
			"ORG_SOURCE_GATED",
			"ORG_SOURCE_SIGNED",
		},
		{
			"a second merge method drops reviewed-threads alone",
			func(t *testing.T, f *fakeRules) {
				t.Helper()
				f.branch = strings.Replace(branchRulesJSON, `["squash"]`, `["squash", "merge"]`, 1)
			},
			"ORG_SOURCE_REVIEWED_THREADS",
			"ORG_SOURCE_GATED",
		},
		{
			"linear history lapsing drops history-protection alone",
			func(t *testing.T, f *fakeRules) {
				t.Helper()
				f.branch = strings.Replace(branchRulesJSON,
					`{"type": "required_linear_history", "ruleset_id": 1},`, ``, 1)
			},
			"ORG_SOURCE_HISTORY_PROTECTED",
			"ORG_SOURCE_SIGNED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rules := liveRules()
			tt.degrade(t, rules)

			payload, err := deriver(rules, liveTree()).Derive(orgTable(t), "acme", "widget", "main")
			if err != nil {
				t.Fatalf("Derive = %v, want a lapse to under-claim rather than fail", err)
			}

			claimed := payload.Properties()
			if claimed[tt.gone] {
				t.Fatalf("%s survived a lapse of exactly its own control", tt.gone)
			}

			if !claimed[tt.kept] {
				t.Fatalf("%s was dropped by a lapse in a different control", tt.kept)
			}
		})
	}
}

// The gated leg: claimable only while its gate is live and its table
// is in the reviewed tree, and every way of not being so is an
// absence rather than a failure.
func TestGatedClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rules   func(*fakeRules)
		tree    fakeTree
		want    bool
		wantErr string
	}{
		{
			name: "a live gate and a declared task claim",
			tree: liveTree(),
			want: true,
		},
		{
			name:  "no live gate carries nothing, even with the task declared",
			rules: func(f *fakeRules) { f.branch = strings.Replace(branchRulesJSON, `"ci / ci"`, `"other"`, 1) },
			tree:  liveTree(),
			want:  false,
		},
		{
			name: "a file absent from the reviewed tree is an absent control",
			tree: fakeTree{files: map[string]string{}},
			want: false,
		},
		{
			name: "a file that declares no such table is an absent control",
			tree: fakeTree{files: map[string]string{"mise/config.toml": "[tasks]\n\"lint:other\" = {}\n"}},
			want: false,
		},
		{
			name:    "a file that is not TOML is a failure, not an absence",
			tree:    fakeTree{files: map[string]string{"mise/config.toml": "this is not = = toml"}},
			wantErr: "not readable as TOML",
		},
		{
			name:    "a tree read that errored is a failure",
			tree:    fakeTree{err: errors.New("io")},
			wantErr: "reading mise/config.toml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rules := liveRules()
			if tt.rules != nil {
				tt.rules(rules)
			}

			payload, err := deriver(rules, tt.tree).Derive(orgTable(t), "acme", "widget", "main")

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Derive = %v, want it to mention %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("Derive = %v", err)
			}

			if got := payload.Properties()["ORG_SOURCE_DCO"]; got != tt.want {
				t.Fatalf("ORG_SOURCE_DCO claimed = %v, want %v", got, tt.want)
			}
		})
	}
}

// A scope no property names is never read — otherwise a derivation
// would invent a blindness guard for evidence nobody asked for.
func TestUnreadScopesAreNeverFetched(t *testing.T) {
	t.Parallel()

	const branchOnly = `{"properties": [
	  {"name": "P_SIGNED", "scope": "branchRules",
	   "match": {"$contains": [{"type": "required_signatures"}]}}]}`

	table, err := jsonx.DecodeBytes[claims.Table]([]byte(branchOnly))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	rules := liveRules()
	// Blind and broken, and irrelevant: nothing matches against tags.
	rules.listing = `[]`
	rules.listingErr = errors.New("403")

	payload, err := deriver(rules, liveTree()).Derive(table, "acme", "widget", "main")
	if err != nil {
		t.Fatalf("Derive = %v, want the tag scope to be untouched", err)
	}

	if !payload.Properties()["P_SIGNED"] {
		t.Fatal("P_SIGNED was not claimed")
	}

	for _, id := range rules.fetched {
		if id != 1 {
			t.Fatalf("fetched ruleset %d, want only the branch's contributor", id)
		}
	}
}

// A ruleset with no readable change time does not fail the run: the
// horizon simply does not cover it, and an absent horizon
// under-claims on the emit side rather than guessing.
func TestHorizonFallbacks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		ruleset   func(*testing.T) string
		wantCount int
		wantErr   string
	}{
		{
			name: "created_at stands in for a missing updated_at",
			ruleset: func(t *testing.T) string {
				t.Helper()

				return mutate(t, immutableRulesetJSON, func(o map[string]any) {
					delete(o, "updated_at")
					o["created_at"] = "2019-06-01T00:00:00Z"
				})
			},
			wantCount: 3,
		},
		{
			name: "neither is not a failure, only a gap in the horizon",
			ruleset: func(t *testing.T) string {
				t.Helper()

				return mutate(t, immutableRulesetJSON, func(o map[string]any) { delete(o, "updated_at") })
			},
			wantCount: 2,
		},
		{
			name: "an unparsable change time is a failure: a wrong horizon over-claims",
			ruleset: func(t *testing.T) string {
				t.Helper()

				return mutate(t, immutableRulesetJSON, func(o map[string]any) { o["updated_at"] = "last tuesday" })
			},
			wantErr: "ruleset updated_at",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rules := liveRules()
			rules.rulesets[101] = tt.ruleset(t)

			payload, err := deriver(rules, liveTree()).Derive(orgTable(t), "acme", "widget", "main")

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Derive = %v, want it to mention %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("Derive = %v", err)
			}

			if got := len(*payload.RulesetsUpdatedAt); got != tt.wantCount {
				t.Fatalf("horizon has %d epoch(s), want %d", got, tt.wantCount)
			}
		})
	}
}

// The table is policy, so everything it can be wrong about is refused
// at load rather than discovered as a level that never rose.
func TestTableValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		table string
		want  string
	}{
		{
			"a table declaring nothing claims nothing",
			`{"properties": []}`,
			"declaring no control",
		},
		{
			"an entry with no name",
			`{"properties": [{"scope": "branchRules", "match": {"$contains": [{"a": 1}]}}]}`,
			"has no name",
		},
		{
			"an entry with no scope",
			`{"properties": [{"name": "P", "match": {"$contains": [{"a": 1}]}}]}`,
			"has no scope",
		},
		{
			"a scope outside the closed vocabulary",
			`{"properties": [{"name": "P", "scope": "repoSettings", "match": {"$contains": [{"a": 1}]}}]}`,
			"is not one of",
		},
		{
			"one property, one derivation",
			`{"properties": [
			  {"name": "P", "scope": "branchRules", "match": {"$contains": [{"a": 1}]}},
			  {"name": "P", "scope": "tagRulesets", "match": {"$contains": [{"b": 2}]}}]}`,
			"declared twice",
		},
		{
			"a rules-scoped property with no matcher",
			`{"properties": [{"name": "P", "scope": "branchRules"}]}`,
			"declares no match",
		},
		{
			"a rules-scoped property carrying gatedTask fields",
			`{"properties": [{"name": "P", "scope": "branchRules", "match": {"$contains": [{"a": 1}]},
			  "file": "x.toml"}]}`,
			"carries gatedTask fields",
		},
		{
			"a matcher the language does not contain",
			`{"properties": [{"name": "P", "scope": "branchRules", "match": {"$regex": "x"}}]}`,
			"reserved operator namespace",
		},
		{
			"a top-level object matcher could never see a rule list",
			`{"properties": [{"name": "P", "scope": "branchRules", "match": {"type": "deletion"}}]}`,
			"can never match a rule list",
		},
		{
			"a gatedTask carrying a matcher",
			`{"properties": [{"name": "P", "scope": "gatedTask", "requiresProperty": "Q",
			  "file": "x.toml", "tablePath": ["a"], "match": {"$contains": [{"a": 1}]}}]}`,
			"carries a match",
		},
		{
			"a gated claim with no gate",
			`{"properties": [{"name": "P", "scope": "gatedTask", "file": "x.toml", "tablePath": ["a"]}]}`,
			"no requiresProperty",
		},
		{
			"a gatedTask with no file",
			`{"properties": [{"name": "P", "scope": "gatedTask", "requiresProperty": "Q", "tablePath": ["a"]}]}`,
			"declares no file",
		},
		{
			"a gatedTask with no tablePath",
			`{"properties": [{"name": "P", "scope": "gatedTask", "requiresProperty": "Q", "file": "x.toml"}]}`,
			"declares no tablePath",
		},
		{
			"a tablePath with an empty segment",
			`{"properties": [{"name": "P", "scope": "gatedTask", "requiresProperty": "Q",
			  "file": "x.toml", "tablePath": ["a", ""]}]}`,
			"empty segment",
		},
		{
			"a gate that is not declared at all",
			`{"properties": [{"name": "P", "scope": "gatedTask", "requiresProperty": "Q",
			  "file": "x.toml", "tablePath": ["a"]}]}`,
			"which is not declared",
		},
		{
			"a gated claim resting on another gated claim",
			`{"properties": [
			  {"name": "Q", "scope": "gatedTask", "requiresProperty": "R",
			   "file": "x.toml", "tablePath": ["a"]},
			  {"name": "R", "scope": "branchRules", "match": {"$contains": [{"a": 1}]}},
			  {"name": "P", "scope": "gatedTask", "requiresProperty": "Q",
			   "file": "x.toml", "tablePath": ["b"]}]}`,
			"never on another gated claim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			table, err := jsonx.DecodeBytes[claims.Table]([]byte(tt.table))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}

			err = table.Validate()
			if err == nil {
				t.Fatalf("Validate = nil error, want %q", tt.want)
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// The payload the emitter reads back: absent and empty stay different
// facts, and every field it must carry is refused when missing.
func TestPayloadValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{
			"an absent read time",
			`{"rulesetsUpdatedAt": [], "controls": []}`,
			"rulesReadAt is absent",
		},
		{
			"a read time that is not RFC 3339",
			`{"rulesReadAt": "last tuesday", "rulesetsUpdatedAt": [], "controls": []}`,
			"rulesReadAt",
		},
		{
			"an absent horizon is not an empty one",
			`{"rulesReadAt": "2026-08-18T12:00:00Z", "controls": []}`,
			"rulesetsUpdatedAt is absent",
		},
		{
			"an absent claim set is not an honest empty one",
			`{"rulesReadAt": "2026-08-18T12:00:00Z", "rulesetsUpdatedAt": []}`,
			"controls is absent",
		},
		{
			"a control with no property",
			`{"rulesReadAt": "2026-08-18T12:00:00Z", "rulesetsUpdatedAt": [],
			  "controls": [{"property": "", "evidence": {}}]}`,
			"property is absent or empty",
		},
		{
			"a control with no evidence",
			`{"rulesReadAt": "2026-08-18T12:00:00Z", "rulesetsUpdatedAt": [],
			  "controls": [{"property": "P"}]}`,
			"carries no evidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			payload, err := jsonx.DecodeBytes[claims.Payload]([]byte(tt.payload))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}

			err = payload.Validate()
			if err == nil {
				t.Fatalf("Validate = nil error, want %q", tt.want)
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// The three accessors the emitter and the policy loader read the
// payload and the table through. Exercised directly because their
// callers live in other packages, and a coverage report that only
// sees them from there hides which branch was taken.
func TestPayloadAccessors(t *testing.T) {
	t.Parallel()

	t.Run("the horizon is the newest change, whatever the order", func(t *testing.T) {
		t.Parallel()

		for _, tc := range []struct {
			name   string
			epochs []int64
			want   int64
			ok     bool
		}{
			{"ascending", []int64{10, 20, 30}, 30, true},
			{"descending", []int64{30, 20, 10}, 30, true},
			{"one", []int64{7}, 7, true},
			{"none readable is absent, and absent under-claims", []int64{}, 0, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				epochs := tc.epochs
				payload := &claims.Payload{RulesetsUpdatedAt: &epochs}

				got, ok := payload.Horizon()
				if got != tc.want || ok != tc.ok {
					t.Fatalf("Horizon = %d, %v; want %d, %v", got, ok, tc.want, tc.ok)
				}
			})
		}
	})

	t.Run("declares and needsTree read the table", func(t *testing.T) {
		t.Parallel()

		table := orgTable(t)
		if !table.Declares("ORG_SOURCE_GATED") {
			t.Error("Declares missed a property the table carries")
		}

		if table.Declares("ORG_SOURCE_ABSENT") {
			t.Error("Declares invented a property")
		}

		if !table.NeedsTree() {
			t.Error("NeedsTree = false for a table with gatedTask properties")
		}

		rulesOnly, err := jsonx.DecodeBytes[claims.Table]([]byte(
			`{"properties": [{"name": "P", "scope": "branchRules",
			  "match": {"$contains": [{"type": "deletion"}]}}]}`))
		if err != nil {
			t.Fatal(err)
		}

		if rulesOnly.NeedsTree() {
			t.Error("NeedsTree = true for a table that rests on no tree")
		}
	})
}

// Malformed forge answers are failures with named causes, never
// absences: everything here would otherwise become a claim set that
// silently dropped controls.
func TestMalformedForgeAnswers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		degrade func(*fakeRules)
		want    string
	}{
		{
			"a branch rule that is not an object",
			func(f *fakeRules) { f.branch = `["deletion"]` },
			"is not an object",
		},
		{
			"a ruleset_id that is not a number",
			func(f *fakeRules) { f.branch = `[{"type": "deletion", "ruleset_id": "one"}]` },
			"ruleset_id is not a number",
		},
		{
			"a ruleset listing that is not a list",
			func(f *fakeRules) { f.listing = `{"id": 1}` },
			"listing is not a list",
		},
		{
			"a listing entry that is not an object",
			func(f *fakeRules) { f.listing = `[101]` },
			"is not an object",
		},
		{
			"a tag ruleset with no id",
			func(f *fakeRules) { f.listing = `[{"target": "tag", "enforcement": "active"}]` },
			"has no id",
		},
		{
			"a ruleset detail that is not an object",
			func(f *fakeRules) { f.rulesets[101] = `["nope"]` },
			"not an object",
		},
		{
			"a ruleset detail that is not JSON",
			func(f *fakeRules) { f.rulesets[101] = `{` },
			"tag ruleset 101",
		},
		{
			"a branch read that is not JSON",
			func(f *fakeRules) { f.branch = `{` },
			"branchRules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rules := liveRules()
			tt.degrade(rules)

			_, err := deriver(rules, liveTree()).Derive(orgTable(t), "acme", "widget", "main")
			if err == nil {
				t.Fatal("Derive = nil error, want a named failure")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Derive = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// A table the loader would have refused is refused again at
// derivation: Derive validates before it reads, so a caller that
// skipped the policy loader cannot get a claim set out of a broken
// table.
func TestDeriveValidatesTheTable(t *testing.T) {
	t.Parallel()

	broken, err := jsonx.DecodeBytes[claims.Table]([]byte(`{"properties": []}`))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := deriver(liveRules(), liveTree()).Derive(broken, "acme", "widget", "main"); err == nil {
		t.Fatal("Derive = nil error, want the table refusal")
	}
}
