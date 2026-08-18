// The match language: four rules and one escape operator, over the
// forge's own JSON. Every property is matched by RULE CONTENT — the
// parameters that make the control what it is — never by a ruleset's
// name or id, and the language gives a matcher nowhere to put one.
//
// The one thing here that is not obvious from the schema doc is the
// WITNESS. A claim has to carry evidence, and the tempting shape is
// to let the policy declare a projection beside the matcher. That is
// a second place to be wrong about what the claim rests on, and the
// bash proves the failure mode: its tag-immutability evidence records
// {id, rules, conditions} and omits bypass_actors, which is half of
// what "immutable" means. So the evidence is derived instead — as the
// matcher walks, it records the candidate restricted to exactly the
// paths it examined. Nothing that decided the claim can be missing,
// and nothing that did not decide it can be present.

package claims

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// matchTree is a declared matcher, held as bytes until compile reads
// it. Raw because it is arbitrary JSON by design: it mirrors whatever
// shape the forge serves, and no Go type can name that in advance.
type matchTree = jsonx.Raw

// containsKey is the reserved operator. The $ prefix marks the
// operator namespace, so a future operator can never be read as data
// that happens to share its name; compile refuses every other
// $-prefixed key for the same reason.
const containsKey = "$contains"

// matchKind is the compiled tree's node type.
type matchKind int

const (
	// kindObject is a SUBSET match: keys the matcher names must be
	// present and match; keys it does not name are not examined.
	kindObject matchKind = iota
	// kindArray is an EXACT match: same length, elementwise, in
	// order. Two of the org's controls live here — an empty
	// bypass_actors means nobody bypasses, and a one-element
	// allowed_merge_methods means that method and no other. A subset
	// reading of either would claim a control that is not held.
	kindArray
	// kindContains is "at least these": for each sub-matcher, some
	// element of the candidate must match it.
	kindContains
	// kindScalar is equality.
	kindScalar
)

// matcher is one compiled node.
type matcher struct {
	kind   matchKind
	obj    map[string]matcher
	arr    []matcher
	scalar any
}

// matchesArray reports whether this matcher can ever match an array —
// the loader's guard against a top-level object matcher, which would
// under-claim its property forever.
func (m matcher) matchesArray() bool {
	return m.kind == kindArray || m.kind == kindContains
}

// compile decodes and validates a declared matcher.
func compile(raw matchTree) (matcher, error) {
	v, err := jsonx.Value(raw)
	if err != nil {
		return matcher{}, fmt.Errorf("match: %w", err)
	}

	return compileValue(v, "")
}

// compileValue builds one node, refusing what the language does not
// contain. path names the position for the error, so a typo deep in a
// parameters tree reports where it is.
func compileValue(v any, path string) (matcher, error) {
	switch t := v.(type) {
	case map[string]any:
		return compileObject(t, path)
	case []any:
		arr := make([]matcher, 0, len(t))

		for i, e := range t {
			sub, err := compileValue(e, fmt.Sprintf("%s[%d]", path, i))
			if err != nil {
				return matcher{}, err
			}

			arr = append(arr, sub)
		}

		return matcher{kind: kindArray, arr: arr}, nil
	default:
		return matcher{kind: kindScalar, scalar: v}, nil
	}
}

// compileObject splits the operator case from the subset case.
func compileObject(obj map[string]any, path string) (matcher, error) {
	if raw, isOp := obj[containsKey]; isOp {
		if len(obj) != 1 {
			return matcher{}, fmt.Errorf("match%s: %s must be the only key in its object", path, containsKey)
		}

		elems, isArray := raw.([]any)
		if !isArray || len(elems) == 0 {
			return matcher{}, fmt.Errorf("match%s: %s takes a non-empty array of matchers", path, containsKey)
		}

		arr := make([]matcher, 0, len(elems))

		for i, e := range elems {
			sub, err := compileValue(e, fmt.Sprintf("%s.%s[%d]", path, containsKey, i))
			if err != nil {
				return matcher{}, err
			}

			arr = append(arr, sub)
		}

		return matcher{kind: kindContains, arr: arr}, nil
	}

	out := make(map[string]matcher, len(obj))

	for _, k := range sortedKeys(obj) {
		if strings.HasPrefix(k, "$") {
			return matcher{}, fmt.Errorf("match%s: %q is in the reserved operator namespace; %s is the only"+
				" operator this language has", path, k, containsKey)
		}

		sub, err := compileValue(obj[k], path+"."+k)
		if err != nil {
			return matcher{}, err
		}

		out[k] = sub
	}

	return matcher{kind: kindObject, obj: out}, nil
}

// match runs one node against a candidate. It returns the witness —
// the candidate restricted to the examined paths — and, on a miss,
// the path and reason, which is the difference between a five-minute
// and a five-hour investigation when a control lapses.
// The results are the witness, whether it matched, and why not.
//
//nolint:gocritic // unnamedResult: named results are refused by nonamedreturns; the doc line above names them
func (m matcher) match(c any, path string) (any, bool, string) {
	switch m.kind {
	case kindObject:
		return m.matchObject(c, path)
	case kindArray:
		return m.matchArray(c, path)
	case kindContains:
		return m.matchContains(c, path)
	case kindScalar:
		return m.matchScalar(c, path)
	default:
		return nil, false, path + ": unreachable match kind"
	}
}

//nolint:gocritic // unnamedResult: witness, matched, why — see match
func (m matcher) matchObject(c any, path string) (any, bool, string) {
	obj, isObj := c.(map[string]any)
	if !isObj {
		return nil, false, path + ": not an object"
	}

	fields := make(map[string]any, len(m.obj))

	for _, k := range sortedMatcherKeys(m.obj) {
		got, present := obj[k]
		if !present {
			return nil, false, path + "." + k + ": absent"
		}

		w, matched, reason := m.obj[k].match(got, path+"."+k)
		if !matched {
			return nil, false, reason
		}

		fields[k] = w
	}

	return fields, true, ""
}

//nolint:gocritic // unnamedResult: witness, matched, why — see match
func (m matcher) matchArray(c any, path string) (any, bool, string) {
	arr, isArr := c.([]any)
	if !isArr {
		return nil, false, path + ": not an array"
	}

	if len(arr) != len(m.arr) {
		return nil, false, fmt.Sprintf("%s: has %d element(s), the match declares exactly %d",
			path, len(arr), len(m.arr))
	}

	elems := make([]any, 0, len(arr))

	for i := range m.arr {
		w, matched, reason := m.arr[i].match(arr[i], fmt.Sprintf("%s[%d]", path, i))
		if !matched {
			return nil, false, reason
		}

		elems = append(elems, w)
	}

	return elems, true, ""
}

// matchContains satisfies each sub-matcher from some element. The
// witness keeps the ELEMENT order of the candidate and merges the
// witnesses of sub-matchers that landed on the same element, so it
// stays a restriction of the candidate rather than a bag of hits.
//
//nolint:gocritic // unnamedResult: witness, matched, why — see match
func (m matcher) matchContains(c any, path string) (any, bool, string) {
	arr, isArr := c.([]any)
	if !isArr {
		return nil, false, path + ": not an array"
	}

	hits := map[int]any{}

	for i := range m.arr {
		found := false

		for j, elem := range arr {
			w, matched, _ := m.arr[i].match(elem, fmt.Sprintf("%s[%d]", path, j))
			if !matched {
				continue
			}

			hits[j] = mergeWitness(hits[j], w)
			found = true

			break
		}

		if !found {
			// Reported against the sub-matcher, not against any one
			// element: "no element satisfied this" is the fact, and
			// naming the last element examined would be noise.
			_, _, reason := m.arr[i].match(nil, fmt.Sprintf("%s{%d}", path, i))

			return nil, false, fmt.Sprintf("%s: no element satisfies match[%d] (%s)", path, i, reason)
		}
	}

	indices := make([]int, 0, len(hits))
	for j := range hits {
		indices = append(indices, j)
	}

	sort.Ints(indices)

	matched := make([]any, 0, len(indices))
	for _, j := range indices {
		matched = append(matched, hits[j])
	}

	return matched, true, ""
}

//nolint:gocritic // unnamedResult: witness, matched, why — see match
func (m matcher) matchScalar(c any, path string) (any, bool, string) {
	if !scalarEqual(m.scalar, c) {
		return nil, false, fmt.Sprintf("%s: %s != %s", path, render(c), render(m.scalar))
	}

	return c, true, ""
}

// scalarEqual compares two decoded JSON scalars. Numbers arrive as
// jsonx.Number (their source spelling), so integers compare as
// integers where both sides are integral and by spelling otherwise —
// a control must never be decided by whether two values survived the
// same binary-float round trip.
func scalarEqual(want, got any) bool {
	wn, wIsNum := want.(jsonx.Number)
	gn, gIsNum := got.(jsonx.Number)

	if wIsNum != gIsNum {
		return false
	}

	if wIsNum {
		wi, werr := strconv.ParseInt(wn.String(), 10, 64)
		gi, gerr := strconv.ParseInt(gn.String(), 10, 64)

		if werr == nil && gerr == nil {
			return wi == gi
		}

		return wn.String() == gn.String()
	}

	return want == got
}

// mergeWitness folds a second witness of the same candidate element
// into the first. Only objects merge; anything else is the same value
// twice, since both witnesses restrict one element.
func mergeWitness(existing, addition any) any {
	if existing == nil {
		return addition
	}

	a, aok := existing.(map[string]any)

	b, bok := addition.(map[string]any)
	if !aok || !bok {
		return existing
	}

	for k, v := range b {
		if prior, clash := a[k]; clash {
			a[k] = mergeWitness(prior, v)

			continue
		}

		a[k] = v
	}

	return a
}

// render prints a scalar for a mismatch message.
func render(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return strconv.Quote(t)
	case jsonx.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	default:
		return fmt.Sprintf("%v", t)
	}
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}

func sortedMatcherKeys(m map[string]matcher) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}

// errNoMatch reports a property whose control is not live — an
// ABSENCE, never an error, and named here so a caller cannot confuse
// it with the two refusals derive.go raises.
var errNoMatch = errors.New("claims: the control is not live")
