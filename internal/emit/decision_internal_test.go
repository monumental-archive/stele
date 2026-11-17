package emit

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/policy"
)

// decisionPolicy is a policy declaring only the decision gate —
// built, not loaded, so no schema number is restated here.
func decisionPolicy() *policy.Policy {
	pt := "https://acme.example/attestations/release-decision/v1"
	sw := "acme/canon/.github/workflows/publish.yml"
	open := "OPEN"

	return &policy.Policy{Trust: &policy.Trust{Decision: &policy.DecisionTrust{
		SignerWorkflow: &sw, PredicateType: &pt, RequiredConclusion: &open,
	}}}
}

// TestReadBackRefuses: a record the verifier's decision reader rejects
// is never written. Decide builds its record from the policy, so these
// are the shapes it could only reach through a defect of its own — the
// read-back is the guard that turns that defect into a refusal instead
// of a signed decision the release verdict refuses later.
func TestReadBackRefuses(t *testing.T) {
	t.Parallel()

	p := decisionPolicy()

	line := strings.Repeat("a", 64) + "  w.spdx.json"

	for _, tt := range []struct {
		name  string
		tag   string
		pred  string
		lines []string
		want  string
	}{
		{
			name:  "a conclusion the policy does not require",
			tag:   "v1",
			pred:  `{"tag":"v1","classes":"c","conclusion":"CLOSED","decidedAt":"x","proofs":[]}`,
			lines: []string{line},
			want:  "the release decision does not name conclusion OPEN",
		},
		{
			name:  "another tag",
			tag:   "v1",
			pred:  `{"tag":"v2","classes":"c","conclusion":"OPEN","decidedAt":"x","proofs":[]}`,
			lines: []string{line},
			want:  "the release decision does not name tag v1",
		},
		{
			name:  "a stream decision naming a tag",
			pred:  `{"tag":"v2","classes":"c","conclusion":"OPEN","decidedAt":"x","proofs":[]}`,
			lines: []string{line},
			want:  "the stream decision names tag v2 — a stream has none",
		},
		{
			name:  "a field the reader does not know",
			tag:   "v1",
			pred:  `{"tag":"v1","classes":"c","conclusion":"OPEN","decidedAt":"x","proofs":[],"extra":1}`,
			lines: []string{line},
			want:  "decision predicate",
		},
		{
			name:  "a subject the statement cannot carry",
			tag:   "v1",
			pred:  `{"tag":"v1","classes":"c","conclusion":"OPEN","decidedAt":"x","proofs":[]}`,
			lines: []string{"not-a-digest  w.spdx.json"},
			want:  "does not read back as one the verdict accepts",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := readBack(p, tt.tag, []byte(tt.pred), tt.lines)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("readBack = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}
