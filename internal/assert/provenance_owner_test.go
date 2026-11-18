// stele#458: a provenance-verified base is looked up in its owner's
// attestation store, never in a repository guessed from the image path.

package assert_test

import (
	"errors"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/report"
)

// storeShaped answers as the forge's attestation stores answered for
// the stele#402 measurement (internal/cli/testdata/base-images): an
// image whose package is not a repository — lab-pg, published by
// release-lab — is held by its publishing repository's store and by
// the owner's, while the store named after the package does not exist,
// which the forge reads as an empty store.
type storeShaped struct {
	held  map[string]bool
	asked []string
}

func (s *storeShaped) Verify(owner, repo, _ string, _ []assert.Candidate, _ string) error {
	s.asked = append(s.asked, owner+"/"+repo)

	if s.held[owner+"/"+repo] {
		return nil
	}

	return errors.New("the store holds no attestation for this subject")
}

// TestProvenanceVerifiedLooksUpByOwner is stele#458's named test: a
// base whose package name is not a repository is verified from the
// owner's store. Before the fix the walk asked the store named after
// the package, found it empty, and reported a finding against a base
// that was attested all along.
func TestProvenanceVerifiedLooksUpByOwner(t *testing.T) {
	t.Parallel()

	f := provenanceForge()
	f.files["widget:HEAD:Dockerfile"] = "FROM ghcr.io/acme/lab-pg:0.28.4-pg18-artifact@" + baseDigest + "\n"

	att := &storeShaped{held: map[string]bool{"acme/": true, "acme/release-lab": true}}

	rep := runStoreWalk(t, provenanceOnlyPolicyJSON, f, att, nil)
	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, findings = %+v; asked %v — a base attested in its owner's store was refused",
			rep.Verdict(), rep.Findings(), att.asked)
	}

	if len(att.asked) != 1 || att.asked[0] != "acme/" {
		t.Fatalf("asked = %v, want the owner's store alone", att.asked)
	}
}
