// A throttled store read is not a fact about the subject (stele#339).
// Every assertion that reads the attestation store — the two base-image
// mechanisms, the continuous digest, and both halves of the full-depth
// leg — must end the walk unseen when the host refuses it for its
// pace: the run seals CANNOT_JUDGE, and the journal holds no finding
// against the subject it never got to look at. The contrast row holds
// the other side: a refusal that IS about the subject still diverges.

package assert_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/report"
)

// throttled is the error a throttled store read reaches the walk as:
// internal/gh's own refusal, wrapped the way the CLI's store attestor
// and the verify engine wrap it.
func throttled() error {
	return fmt.Errorf("store read: %w", gh.ThrottleRefusal("gh: /repos/acme/x/attestations: HTTP 403", 0))
}

// storeWalk is one walk whose store read is scripted.
type storeWalk struct {
	policy   *assert.Policy
	forge    *fakeForge
	attestor *fakeAttestor
	pins     map[string][]byte
	deep     *fakeDeep
}

func (s storeWalk) run(t *testing.T, j *report.Journal) (*report.Report, error) {
	t.Helper()

	var full *assert.FullDepth

	if s.deep != nil {
		fd, err := assert.NewFullDepth(s.deep,
			"acme/canon/.github/workflows/verify-release.yml", "acme/signer/.github/workflows/sign.yml")
		if err != nil {
			t.Fatal(err)
		}

		full = fd
	}

	src := assert.Sources{
		assert.ManifestSource{Forge: s.forge, Policy: s.policy.Evidence, Asset: "evidence-manifest.json"},
	}

	return assert.Evidence(s.policy, orgPop(t, s.forge, nil), s.forge, src, s.attestor,
		j, s.pins, full, func(string, ...any) {})
}

func mustPolicy(t *testing.T, raw string) *assert.Policy {
	t.Helper()

	pol, err := assert.LoadPolicy(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	return pol
}

func TestThrottledStoreReadIsUnseen(t *testing.T) {
	t.Parallel()

	basePins := pinsFor([]byte("images = [\n  \"docker.io/library/debian:trixie@" + baseDigest + "\",\n]\n"))

	tests := []struct {
		name string
		walk func(t *testing.T) storeWalk
		// says is what the refusal must name: the assertion and the
		// subject the run could not see.
		says []string
	}{
		{
			name: "a pin-file base approval read",
			walk: func(t *testing.T) storeWalk {
				t.Helper()

				return storeWalk{
					policy: mustPolicy(t, baseOnlyPolicyJSON), forge: completeRelease(), pins: basePins,
					attestor: &fakeAttestor{refuse: map[string]error{baseDigest: throttled()}},
				}
			},
			says: []string{"base-image-approval:pgrx-bases", baseDigest},
		},
		{
			name: "a provenance-verified base read",
			walk: func(t *testing.T) storeWalk {
				t.Helper()

				return storeWalk{
					policy: mustPolicy(t, provenanceOnlyPolicyJSON), forge: provenanceForge(),
					attestor: &fakeAttestor{refuse: map[string]error{baseDigest: throttled()}},
				}
			},
			says: []string{"base-image-approval:org-bases", orgBaseRef},
		},
		{
			name: "a continuous-digest read",
			walk: func(t *testing.T) storeWalk {
				t.Helper()

				return storeWalk{
					policy: mustPolicy(t, continuousOnlyPolicyJSON), forge: continuousForge(),
					attestor: &fakeAttestor{refuse: map[string]error{contDigest: throttled()}},
				}
			},
			says: []string{"continuous-digest", "widget@"},
		},
		{
			name: "the full-depth release read",
			walk: func(t *testing.T) storeWalk {
				t.Helper()

				return storeWalk{
					policy: loadTestPolicy(t), forge: deepForge(), attestor: &fakeAttestor{},
					deep: &fakeDeep{releaseErr: throttled()},
				}
			},
			says: []string{"deep release check", "widget@v1.0.0"},
		},
		{
			name: "the full-depth verdict read",
			walk: func(t *testing.T) storeWalk {
				t.Helper()

				return storeWalk{
					policy: loadTestPolicy(t), forge: deepForge(), attestor: &fakeAttestor{},
					deep: &fakeDeep{vsaErr: throttled()},
				}
			},
			says: []string{"deep verdict check", "widget@v1.0.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			j := report.NewJournal()

			rep, err := tt.walk(t).run(t, j)
			if !errors.Is(err, gh.ErrThrottled) {
				t.Fatalf("Evidence = %v, %v — a throttled store read must end the walk unseen", rep, err)
			}

			if rep != nil {
				t.Fatalf("Evidence sealed %s beside the refusal — an unseen walk seals nothing", rep.Verdict())
			}

			for _, want := range tt.says {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not name %q", err, want)
				}
			}

			if f := j.Findings(); len(f) != 0 {
				t.Fatalf("journal holds %d finding(s) against a subject the run never saw: %+v", len(f), f)
			}
		})
	}
}

// TestRefusedStoreReadStillDiverges is the contrast: a store read
// refused for the CREDENTIAL is a fact the walk reports, so the same
// base-approval read that ends unseen under a throttle reddens here.
func TestRefusedStoreReadStillDiverges(t *testing.T) {
	t.Parallel()

	forbidden := fmt.Errorf("store read: gh: HTTP 403: %w", gh.ErrForbidden)

	j := report.NewJournal()

	rep, err := storeWalk{
		policy: mustPolicy(t, baseOnlyPolicyJSON), forge: completeRelease(),
		pins:     pinsFor([]byte("images = [\n  \"docker.io/library/debian:trixie@" + baseDigest + "\",\n]\n")),
		attestor: &fakeAttestor{refuse: map[string]error{baseDigest: forbidden}},
	}.run(t, j)
	if err != nil {
		t.Fatalf("Evidence = %v — a refused credential is an answer, not a blind run", err)
	}

	if rep.Verdict() != report.VerdictFail || len(rep.Findings()) != 1 {
		t.Fatalf("verdict = %s, findings = %+v — want one FAIL finding", rep.Verdict(), rep.Findings())
	}
}
