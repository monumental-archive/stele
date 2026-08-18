package chain_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// TestDocExamplesValidate runs every fenced example in
// docs/chain-format.md through the implementation. The canon's old
// format doc drifted into describing a note the engine refuses
// (stele#101) exactly because it was prose nothing executed; here a
// doc example the engine refuses is a red build. Fences are tagged
// `json note` and `json predicate`; at least one of each must exist,
// so deleting the examples cannot silently pass.
func TestDocExamplesValidate(t *testing.T) {
	t.Parallel()

	doc, err := os.ReadFile("../../docs/chain-format.md")
	if err != nil {
		t.Fatalf("reading the format spec: %v", err)
	}

	fenceRE := regexp.MustCompile("(?s)```json (note|predicate)\n(.*?)```")

	counts := map[string]int{}

	for _, m := range fenceRE.FindAllStringSubmatch(string(doc), -1) {
		kind, body := m[1], m[2]
		counts[kind]++

		switch kind {
		case "note":
			n, derr := jsonx.Decode[chain.Note](strings.NewReader(body))
			if derr != nil {
				t.Errorf("doc note example does not decode: %v", derr)

				continue
			}

			if verr := n.Validate(); verr != nil {
				t.Errorf("doc note example is refused by Validate: %v", verr)
			}
		case "predicate":
			p, derr := jsonx.Decode[chain.Predicate](strings.NewReader(body))
			if derr != nil {
				t.Errorf("doc predicate example does not decode: %v", derr)

				continue
			}

			if _, _, lerr := p.Ledger(); lerr != nil {
				t.Errorf("doc predicate example is refused by Ledger: %v", lerr)
			}
		}
	}

	for _, kind := range []string{"note", "predicate"} {
		if counts[kind] == 0 {
			t.Errorf("the spec carries no tagged %s example — the doc test is checking nothing", kind)
		}
	}
}
