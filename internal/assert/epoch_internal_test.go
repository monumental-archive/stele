// The one epoch semantics, tested once at its shared definition
// (stele#109): three obligations delegate here, so three guard
// branches are these guard branches.

package assert

import "testing"

func TestOwedFrom(t *testing.T) {
	t.Parallel()

	epoch := "1.13.0"

	tests := []struct {
		name      string
		from      *string
		machinery string
		want      bool
	}{
		{"no epoch means always owed", nil, "0.0.1", true},
		{"pre-epoch is exempt", &epoch, "1.12.9", false},
		{"the epoch itself owes (inclusive)", &epoch, "1.13.0", true},
		{"post-epoch owes", &epoch, "2.0.0", true},
		{"an unparsable pin fails toward the stricter obligation", &epoch, "not-a-version", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := owedFrom(tt.from, tt.machinery); got != tt.want {
				t.Fatalf("owedFrom(%v, %q) = %v, want %v", tt.from, tt.machinery, got, tt.want)
			}
		})
	}
}

// TestEpochDelegation pins that all three obligations share the one
// definition — a fourth copy of the semantics is the drift this
// layout exists to make unrepresentable.
func TestEpochDelegation(t *testing.T) {
	t.Parallel()

	epoch := "1.13.0"
	e := &EvidencePolicy{
		StoreVSAFromVersion:   &epoch,
		DecisionFromVersion:   &epoch,
		EnrichmentFromVersion: &epoch,
	}

	for name, f := range map[string]func(string) bool{
		"storeVSA": e.storeVSA, "decision": e.decision, "enrichment": e.enrichment,
	} {
		if f("1.12.9") {
			t.Fatalf("%s(1.12.9) = true, want the pre-epoch exemption", name)
		}

		if !f("1.13.0") {
			t.Fatalf("%s(1.13.0) = false, want the obligation from the epoch inclusive", name)
		}
	}
}
