// The schema document's examples, executed. docs/policy-schema.md
// taught the pre-#125 branch shape — `requiredProperties` on the
// branch instead of under `levels[]` — for two releases, and the
// canon's own migration was written against the loader's error
// message rather than against the doc (stele#150). Prose nothing
// executes drifts; this file makes the doc a test input.

package policy_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
)

// TestSchemaDocExamplesLoad splices every `json policy-fragment` fence
// in docs/policy-schema.md into the `json policy` document at the
// object it names, and runs the composition through policy.Load.
//
// Composition rather than fence-by-fence loading, for two reasons: a
// fragment is a member list, not a document, so it has no meaning
// apart from the document it belongs to; and the composed document is
// what an adopter actually writes by following this file, so the
// load-time cross-check — every required property declared in the
// claims table — is exercised across the two examples that state
// those two halves. Examples that agree separately and contradict
// together were the drift this closes.
func TestSchemaDocExamplesLoad(t *testing.T) {
	t.Parallel()

	doc, err := os.ReadFile("../../docs/policy-schema.md")
	if err != nil {
		t.Fatalf("reading the schema document: %v", err)
	}

	host, fragments := docExamples(t, string(doc))

	composed := host

	for _, f := range fragments {
		composed = splice(t, composed, f)
	}

	p, err := policy.Load(strings.NewReader(composed))
	if err != nil {
		t.Fatalf("the document's own examples do not compose into a policy Load accepts: %v\n%s", err, composed)
	}

	// The composition must be the whole teaching, not the host alone:
	// each fragment's section has to have landed where it was said to.
	switch {
	case len(p.SLSARootsOfTrust) == 0:
		t.Error("the slsaRootsOfTrust example did not reach the loaded policy")
	case p.Source == nil || p.Source.Claims == nil:
		t.Error("the claims example did not reach the loaded policy's source section")
	}
}

// fragment is one member-list example and the object it belongs to —
// the empty path being the document root.
type fragment struct {
	path string
	body string
}

// docExamples reads the tagged fences, refusing a document that
// carries too few: deleting the examples must fail loudly rather than
// leave a test that checks nothing.
func docExamples(t *testing.T, doc string) (string, []fragment) {
	t.Helper()

	hostRE := regexp.MustCompile("(?s)```json policy\n(.*?)```")
	fragRE := regexp.MustCompile("(?s)```json policy-fragment ?(\\S*)\n(.*?)```")

	hosts := hostRE.FindAllStringSubmatch(doc, -1)
	if len(hosts) != 1 {
		t.Fatalf("found %d `json policy` document example(s), want exactly the one the shape section teaches",
			len(hosts))
	}

	frags := fragRE.FindAllStringSubmatch(doc, -1)
	if len(frags) < 2 {
		t.Fatalf("found %d `json policy-fragment` example(s), want at least the roots-of-trust and claims sections",
			len(frags))
	}

	out := make([]fragment, 0, len(frags))
	for _, m := range frags {
		out = append(out, fragment{path: m[1], body: m[2]})
	}

	return hosts[0][1], out
}

// splice merges one fragment's members into the document at its
// declared path. A fragment naming an object the document does not
// carry is a fence pointing at nothing — a doc defect, not a silent
// no-op.
func splice(t *testing.T, document string, f fragment) string {
	t.Helper()

	host := decodeObject(t, document, "the document example")
	members := decodeObject(t, "{"+f.body+"}", "the "+f.path+" fragment")

	target := host
	if f.path != "" {
		nested, ok := host[f.path].(map[string]any)
		if !ok {
			t.Fatalf("the fragment names %q, which the document example does not carry as an object", f.path)
		}

		target = nested
	}

	for k, v := range members {
		if _, taken := target[k]; taken {
			t.Fatalf("the fragment restates %q, which the document example already carries — one shape, two places", k)
		}

		target[k] = v
	}

	merged, err := jsonx.Marshal(host)
	if err != nil {
		t.Fatalf("re-rendering the composed policy: %v", err)
	}

	return string(merged)
}

// decodeObject reads one JSON object, naming the example in the
// failure so a broken fence points at itself.
func decodeObject(t *testing.T, body, what string) map[string]any {
	t.Helper()

	v, err := jsonx.Value([]byte(body))
	if err != nil {
		t.Fatalf("%s is not JSON: %v", what, err)
	}

	obj, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s is not a JSON object", what)
	}

	return obj
}
