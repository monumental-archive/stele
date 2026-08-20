// The one epoch semantics, tested once at its shared definition
// (stele#109): four obligations delegate here, so four guard
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

// TestEpochDelegation pins that every obligation shares the one
// definition — a second copy of the semantics is the drift this
// layout exists to make unrepresentable. The manifest schema joined
// them at stele#185: it governs a document's own FORMAT rather than
// an obligation it carries, and delegates anyway, because a schema
// retirement decided by a second reading would be a behaviour of the
// reader rather than a fact the org declared.
func TestEpochDelegation(t *testing.T) {
	t.Parallel()

	epoch := "1.13.0"
	e := &EvidencePolicy{
		StoreVSAFromVersion:       &epoch,
		DecisionFromVersion:       &epoch,
		EnrichmentFromVersion:     &epoch,
		ManifestSchemaFromVersion: &epoch,
	}

	for name, f := range map[string]func(string) bool{
		"storeVSA": e.storeVSA, "decision": e.decision,
		"enrichment": e.enrichment, "manifestSchema": e.manifestSchema,
	} {
		if f("1.12.9") {
			t.Fatalf("%s(1.12.9) = true, want the pre-epoch exemption", name)
		}

		if !f("1.13.0") {
			t.Fatalf("%s(1.13.0) = false, want the obligation from the epoch inclusive", name)
		}
	}
}
