package policy_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/policy"
)

// TestAdoptionFloorsValidate runs every `json policy-floor` fence in
// docs/adoption.md through policy.Load — the chain/doc_test.go
// pattern: a floor the guide claims and the validator refuses is a
// red build, never drift (stele#131/#132). At least two floors must
// exist (the minimal document and the chain-emission one), so
// deleting the examples cannot silently pass.
func TestAdoptionFloorsValidate(t *testing.T) {
	t.Parallel()

	doc, err := os.ReadFile("../../docs/adoption.md")
	if err != nil {
		t.Fatalf("reading the adopter guide: %v", err)
	}

	fenceRE := regexp.MustCompile("(?s)```json policy-floor\n(.*?)```")

	matches := fenceRE.FindAllStringSubmatch(string(doc), -1)
	if len(matches) < 2 {
		t.Fatalf("found %d policy-floor example(s), want at least the minimal and the chain-emission floors",
			len(matches))
	}

	for i, m := range matches {
		p, lerr := policy.Load(strings.NewReader(m[1]))
		if lerr != nil {
			t.Errorf("policy-floor example %d is refused by Load: %v", i+1, lerr)

			continue
		}

		// The floors are floors: nothing beyond what each claims to
		// need. The first is source-free; the second declares source
		// and still no build, verdict or decision sections.
		if p.Build != nil || p.Trust.Verdict != nil || p.Trust.Decision != nil {
			t.Errorf("policy-floor example %d declares sections the guide says the floor omits", i+1)
		}
	}

	if matches[0][1] == matches[1][1] {
		t.Error("the two floors are identical — the chain-emission floor must add the source section")
	}
}
