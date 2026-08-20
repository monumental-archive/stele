// The match language, row by row. Two groups matter most and are
// tested hardest:
//
//   - the ARRAY rule, because two of the org's real controls are
//     spelled as exact arrays (nobody bypasses, squash only) and a
//     subset reading of either would claim a control nobody holds;
//   - the WITNESS, because it is the evidence a claim carries. It
//     must be a restriction of the candidate to the examined paths —
//     nothing that decided the claim missing, nothing that did not
//     decide it present. The bash's projection omits bypass_actors
//     from its immutability evidence; the row named for that is what
//     makes the omission unwritable here.

package claims

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// matchJSON compiles a matcher and runs it against a candidate,
// returning the witness rendered back to JSON so a row can state the
// expectation as text.
//
//nolint:gocritic // unnamedResult: witness JSON, matched, why
func matchJSON(t *testing.T, matcher, candidate string) (string, bool, string) {
	t.Helper()

	m, err := compile([]byte(matcher))
	if err != nil {
		t.Fatalf("compile(%s) = %v", matcher, err)
	}

	c, err := jsonx.Value([]byte(candidate))
	if err != nil {
		t.Fatalf("candidate: %v", err)
	}

	w, matched, reason := m.match(c, "")
	if !matched {
		return "", false, reason
	}

	raw, err := jsonx.Marshal(w)
	if err != nil {
		t.Fatalf("marshal witness: %v", err)
	}

	return string(raw), true, ""
}

func TestCompileRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		matcher string
		want    string
	}{
		{"$contains beside another key", `{"$contains": [{"a": 1}], "b": 2}`, "must be the only key"},
		{"$contains over a non-array", `{"$contains": {"a": 1}}`, "non-empty array"},
		{"$contains over an empty array", `{"$contains": []}`, "non-empty array"},
		{
			"an unknown operator is not read as data",
			`{"$anyOf": [{"a": 1}]}`,
			"reserved operator namespace",
		},
		{
			"a reserved key nested deep is still refused",
			`{"$contains": [{"parameters": {"$not": true}}]}`,
			"reserved operator namespace",
		},
		{"not JSON at all", `{`, "value"},
		{"trailing data", `{"$contains": [{"a": 1}]} {}`, "trailing"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := compile([]byte(tt.matcher))
			if err == nil {
				t.Fatalf("compile(%s) = nil error, want %q", tt.matcher, tt.want)
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("compile(%s) = %v, want it to mention %q", tt.matcher, err, tt.want)
			}
		})
	}
}

func TestMatchSemantics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		matcher   string
		candidate string
		want      bool
	}{
		{
			"an object matcher is a subset: unnamed keys are not examined",
			`{"$contains": [{"type": "deletion"}]}`,
			`[{"type": "deletion", "ruleset_id": 1, "extra": "ignored"}]`,
			true,
		},
		{
			"a key the matcher names must be present",
			`{"$contains": [{"type": "deletion", "ruleset_id": 1}]}`,
			`[{"type": "deletion"}]`,
			false,
		},
		{
			"an array matcher is EXACT: a surplus element misses",
			`{"$contains": [{"allowed_merge_methods": ["squash"]}]}`,
			`[{"allowed_merge_methods": ["squash", "merge"]}]`,
			false,
		},
		{
			"an array matcher is EXACT: order is part of the match",
			`{"$contains": [{"m": ["a", "b"]}]}`,
			`[{"m": ["b", "a"]}]`,
			false,
		},
		{
			"an empty array matcher means empty, which is the control",
			`{"$contains": [{"bypass_actors": []}]}`,
			`[{"bypass_actors": []}]`,
			true,
		},
		{
			"one bypass actor is not none",
			`{"$contains": [{"bypass_actors": []}]}`,
			`[{"bypass_actors": [{"actor_id": 1}]}]`,
			false,
		},
		{
			"$contains satisfies each sub-matcher from some element",
			`{"$contains": [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "required_linear_history"}]}`,
			`[{"type": "required_linear_history"}, {"type": "deletion"}, {"type": "non_fast_forward"}]`,
			true,
		},
		{
			"$contains misses when one sub-matcher has no element",
			`{"$contains": [{"type": "deletion"}, {"type": "required_linear_history"}]}`,
			`[{"type": "deletion"}, {"type": "non_fast_forward"}]`,
			false,
		},
		{
			"$contains nests inside an object matcher",
			`{"$contains": [{"parameters": {"required_status_checks": {"$contains": [{"context": "ci / ci"}]}}}]}`,
			`[{"parameters": {"required_status_checks": [{"context": "other"}, {"context": "ci / ci"}]}}]`,
			true,
		},
		{
			"integers compare as integers, not as floating point",
			`{"$contains": [{"integration_id": 15368}]}`,
			`[{"integration_id": 15368}]`,
			true,
		},
		{
			"a large id survives: no float round trip decides a control",
			`{"$contains": [{"actor_id": 9007199254740993}]}`,
			`[{"actor_id": 9007199254740993}]`,
			true,
		},
		{
			"a different id misses",
			`{"$contains": [{"integration_id": 15368}]}`,
			`[{"integration_id": 15369}]`,
			false,
		},
		{
			"a number never equals its string spelling",
			`{"$contains": [{"integration_id": 15368}]}`,
			`[{"integration_id": "15368"}]`,
			false,
		},
		{"booleans compare", `{"$contains": [{"strict": true}]}`, `[{"strict": true}]`, true},
		{"true is not false", `{"$contains": [{"strict": true}]}`, `[{"strict": false}]`, false},
		{"null compares", `{"$contains": [{"x": null}]}`, `[{"x": null}]`, true},
		{"null is not absent", `{"$contains": [{"x": null}]}`, `[{"y": 1}]`, false},
		{
			"an object matcher against a scalar candidate misses",
			`{"$contains": [{"parameters": {"a": 1}}]}`,
			`[{"parameters": "nope"}]`,
			false,
		},
		{
			"an array matcher against an object candidate misses",
			`{"$contains": [{"m": ["a"]}]}`,
			`[{"m": {"0": "a"}}]`,
			false,
		},
		{
			"a top-level $contains against a non-array misses rather than panics",
			`{"$contains": [{"a": 1}]}`,
			`{"a": 1}`,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, ok, why := matchJSON(t, tt.matcher, tt.candidate)
			if ok != tt.want {
				t.Fatalf("match = %v (%s), want %v", ok, why, tt.want)
			}
		})
	}
}

func TestWitnessIsTheExaminedPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		matcher   string
		candidate string
		want      string
	}{
		{
			"unexamined keys are not carried",
			`{"$contains": [{"type": "required_signatures"}]}`,
			`[{"type": "required_signatures", "ruleset_id": 1, "noise": {"deep": true}}]`,
			`[{"type":"required_signatures"}]`,
		},
		{
			"the deciding field cannot be omitted: bypass_actors is carried because it was matched",
			`{"$contains": [{"conditions": {"ref_name": {"include": ["~ALL"]}}, "bypass_actors": []}]}`,
			`[{"id": 101, "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}},` +
				` "bypass_actors": [], "updated_at": "2020-01-01T00:00:00Z"}]`,
			`[{"bypass_actors":[],"conditions":{"ref_name":{"include":["~ALL"]}}}]`,
		},
		{
			"only the matched elements appear, in candidate order",
			`{"$contains": [{"type": "deletion"}, {"type": "non_fast_forward"}]}`,
			`[{"type": "non_fast_forward"}, {"type": "required_signatures"}, {"type": "deletion"}]`,
			`[{"type":"non_fast_forward"},{"type":"deletion"}]`,
		},
		{
			"two sub-matchers landing on one element merge into one witness",
			`{"$contains": [{"type": "pull_request"}, {"parameters": {"squash": true}}]}`,
			`[{"type": "pull_request", "parameters": {"squash": true, "other": 1}}]`,
			`[{"parameters":{"squash":true},"type":"pull_request"}]`,
		},
		{
			"a nested $contains carries only its own matched elements",
			`{"$contains": [{"parameters": {"checks": {"$contains": [{"context": "ci / ci"}]}}}]}`,
			`[{"parameters": {"checks": [{"context": "lint", "id": 1}, {"context": "ci / ci", "id": 2}]}}]`,
			`[{"parameters":{"checks":[{"context":"ci / ci"}]}}]`,
		},
		{
			"an exact array carries every element, since every one was compared",
			`{"$contains": [{"m": ["a", "b"]}]}`,
			`[{"m": ["a", "b"], "n": 1}]`,
			`[{"m":["a","b"]}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok, why := matchJSON(t, tt.matcher, tt.candidate)
			if !ok {
				t.Fatalf("match missed (%s), want a witness", why)
			}

			if got != tt.want {
				t.Fatalf("witness = %s, want %s", got, tt.want)
			}
		})
	}
}

// A miss has to say where it happened: a control that lapses is read
// by a human under time pressure, and "no element satisfies match[2]"
// beside the failing path is the difference between minutes and
// hours.
func TestMissNamesThePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		matcher   string
		candidate string
		want      []string
	}{
		{
			"a drifted scalar names the path and both sides",
			`{"$contains": [{"parameters": {"strict": true}}]}`,
			`[{"parameters": {"strict": false}}]`,
			[]string{"no element satisfies match[0]"},
		},
		{
			"an exact-array length mismatch says how many it found",
			`{"$contains": [{"m": ["a"]}]}`,
			`[{"m": ["a", "b"]}]`,
			[]string{"no element satisfies match[0]"},
		},
		{
			"the unsatisfied sub-matcher is identified by index",
			`{"$contains": [{"type": "deletion"}, {"type": "update"}]}`,
			`[{"type": "deletion"}]`,
			[]string{"match[1]"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, ok, why := matchJSON(t, tt.matcher, tt.candidate)
			if ok {
				t.Fatal("match succeeded, want a miss")
			}

			for _, want := range tt.want {
				if !strings.Contains(why, want) {
					t.Fatalf("why = %q, want it to mention %q", why, want)
				}
			}
		})
	}
}

// TestNumbersCompareWithoutAFloatRoundTrip. A control must never be
// decided by whether two values survived the same binary float.
// Integers compare as integers, so a required-approvals rule written
// `2` matches a forge answering `2` however either was spelled; a
// value no int64 holds, or one with a fraction, falls back to its
// SOURCE SPELLING, because the alternative is parsing it into a float
// and letting the comparison turn on rounding.
//
// The spelling fallback is deliberately strict: 1.50 and 1.5 are the
// same number and different spellings, and this reports a miss. That
// is the honest answer here — nothing in the rules vocabulary is a
// fractional quantity, so a fractional value on either side means the
// policy and the forge disagree about what the field IS, and saying
// "equal" would paper over it.
func TestNumbersCompareWithoutAFloatRoundTrip(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name      string
		matcher   string
		candidate string
		want      bool
	}{
		{"integers compare as integers", `{"n": 2}`, `{"n": 2}`, true},
		{"a different integer misses", `{"n": 2}`, `{"n": 3}`, false},
		{
			// Past 2^53 in both directions: float64 would collapse
			// these two onto one value and call them equal.
			"an id no float holds is compared exactly",
			`{"n": 9007199254740993}`, `{"n": 9007199254740993}`, true,
		},
		{
			"two ids a float would collapse together stay distinct",
			`{"n": 9007199254740993}`, `{"n": 9007199254740992}`, false,
		},
		{"a fraction matches its own spelling", `{"n": 1.5}`, `{"n": 1.5}`, true},
		{"a fraction spelled differently is reported, not smoothed over", `{"n": 1.50}`, `{"n": 1.5}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, ok, why := matchJSON(t, tt.matcher, tt.candidate)
			if ok != tt.want {
				t.Fatalf("match = %v (%s), want %v", ok, why, tt.want)
			}
		})
	}
}

// TestMissRendersEveryScalarShape: the miss message is the whole
// difference between a five-minute and a five-hour investigation when
// a control lapses, so every value a forge can put in a field has to
// render as something a reader recognises — a null especially, since
// "expected true, got " reads as a bug in the tool rather than an
// absent field in the answer.
func TestMissRendersEveryScalarShape(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name      string
		matcher   string
		candidate string
		want      string
	}{
		{"an absent value renders as null", `{"a": true}`, `{"a": null}`, ".a: null != true"},
		{"a string renders quoted", `{"a": "x"}`, `{"a": "y"}`, `.a: "y" != "x"`},
		{"a number renders in its own spelling", `{"a": 1}`, `{"a": 2}`, ".a: 2 != 1"},
		{"a bool renders as a bool", `{"a": true}`, `{"a": false}`, ".a: false != true"},
		{
			// Neither side is a scalar: a forge answering with a
			// structure where the policy wants a value still has to
			// produce a message naming what it found, rather than an
			// empty slot the reader cannot interpret.
			"a structure where a scalar was wanted still renders",
			`{"a": true}`, `{"a": {"nested": 1}}`, "map[nested:1]",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, ok, why := matchJSON(t, tt.matcher, tt.candidate)
			if ok {
				t.Fatal("match succeeded, want a miss")
			}

			if !strings.Contains(why, tt.want) {
				t.Errorf("why = %q, want it to carry %q", why, tt.want)
			}
		})
	}
}

// matchesArray is what the loader uses to refuse a matcher that could
// never see a rule list.
func TestMatchesArray(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		matcher string
		want    bool
	}{
		{"$contains matches arrays", `{"$contains": [{"a": 1}]}`, true},
		{"an exact array matches arrays", `[{"a": 1}]`, true},
		{"a bare object cannot", `{"type": "deletion"}`, false},
		{"a scalar cannot", `"deletion"`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m, err := compile([]byte(tt.matcher))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}

			if got := m.matchesArray(); got != tt.want {
				t.Fatalf("matchesArray = %v, want %v", got, tt.want)
			}
		})
	}
}
