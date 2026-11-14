// A store read that could not be completed is not a fact about the
// subject (stele#339). Every assertion that reads the attestation
// store — the two base-image mechanisms, the continuous digest, and
// both halves of the full-depth leg, with the release-asset reads that
// leg makes first — must end the walk unseen when the
// host throttled the read or its transient ladder ran out (5xx, or a
// 429): the run seals CANNOT_JUDGE, and the journal holds no finding
// against the subject it never got to look at. A read that completed
// and refused — a bundle that does not verify — is still a finding.

package assert_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/report"
)

// liveRefusal is the error a real store read returns when every
// attempt meets respond: internal/gh's own client, ladder and
// classification, so the rows below test the walk against what the
// forge reader actually hands it rather than a hand-built error.
func liveRefusal(t *testing.T, respond func(http.ResponseWriter)) error {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		respond(w)
	}))
	t.Cleanup(srv.Close)

	c := gh.New("")
	c.HTTP = srv.Client()
	c.Base = srv.URL
	c.Sleep = func(time.Duration) {}

	_, err := c.Attestations("acme", ".github", strings.Repeat("8", 64))
	if err == nil {
		t.Fatal("the scripted store answered — the row would prove nothing")
	}

	// Wrapped the way the CLI's store attestor and the verify engine
	// wrap a store error before it reaches the walk.
	return fmt.Errorf("store read: %w", err)
}

// The refusals, each as a whole response. The secondary-limit body is
// the 2026-08-20 measured message quoted in internal/gh's Throttled
// comment; the 503 and 429 carry nothing but their status, which is
// all the ladder reads.
func secondaryLimitResponse(w http.ResponseWriter) {
	w.Header().Set("X-Ratelimit-Remaining", "4799")
	w.WriteHeader(http.StatusForbidden)
	//nolint:errcheck,gosec // test server write
	w.Write([]byte(`{"message":"You have exceeded a secondary rate limit. Please wait a few minutes` +
		` before you try again.","documentation_url":"https://docs.github.com/rest/overview/` +
		`rate-limits-for-the-rest-api#about-secondary-rate-limits"}`))
}

func unavailableResponse(w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) }

func tooManyResponse(w http.ResponseWriter) { w.WriteHeader(http.StatusTooManyRequests) }

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

// storeSite is one assertion that reads the store: a walk whose read
// refuses with the given error, and the words its refusal must carry.
type storeSite struct {
	name string
	walk func(t *testing.T, refusal error) storeWalk
	says []string
}

func storeSites() []storeSite {
	basePins := pinsFor([]byte("images = [\n  \"docker.io/library/debian:trixie@" + baseDigest + "\",\n]\n"))

	return []storeSite{
		{
			name: "a pin-file base approval read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				return storeWalk{
					policy: mustPolicy(t, baseOnlyPolicyJSON), forge: completeRelease(), pins: basePins,
					attestor: &fakeAttestor{refuse: map[string]error{baseDigest: refusal}},
				}
			},
			says: []string{"base-image-approval:pgrx-bases", baseDigest},
		},
		{
			name: "a provenance-verified base read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				return storeWalk{
					policy: mustPolicy(t, provenanceOnlyPolicyJSON), forge: provenanceForge(),
					attestor: &fakeAttestor{refuse: map[string]error{baseDigest: refusal}},
				}
			},
			says: []string{"base-image-approval:org-bases", orgBaseRef},
		},
		{
			name: "a continuous-digest read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				return storeWalk{
					policy: mustPolicy(t, continuousOnlyPolicyJSON), forge: continuousForge(),
					attestor: &fakeAttestor{refuse: map[string]error{contDigest: refusal}},
				}
			},
			says: []string{"continuous-digest", "widget@"},
		},
		{
			name: "the full-depth release read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				return storeWalk{
					policy: loadTestPolicy(t), forge: deepForge(), attestor: &fakeAttestor{},
					deep: &fakeDeep{releaseErr: refusal},
				}
			},
			says: []string{"deep release check", "widget@v1.0.0"},
		},
		{
			name: "the full-depth checksum-manifest read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				f := deepForge()
				f.assetErr = map[string]error{"widget@v1.0.0/checksums.txt": refusal}

				return storeWalk{policy: loadTestPolicy(t), forge: f, attestor: &fakeAttestor{}, deep: &fakeDeep{}}
			},
			says: []string{"deep release check", "widget@v1.0.0", "checksum manifest"},
		},
		{
			name: "the full-depth publish-workflow read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				f := deepForge()
				f.fileAtErr = map[string]error{"widget:v1.0.0:.github/workflows/publish.yml": refusal}

				return storeWalk{policy: loadTestPolicy(t), forge: f, attestor: &fakeAttestor{}, deep: &fakeDeep{}}
			},
			says: []string{"deep release check", "widget@v1.0.0", "publish workflow"},
		},
		{
			name: "the full-depth verdict read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				return storeWalk{
					policy: loadTestPolicy(t), forge: deepForge(), attestor: &fakeAttestor{},
					deep: &fakeDeep{vsaErr: refusal},
				}
			},
			says: []string{"deep verdict check", "widget@v1.0.0"},
		},
	}
}

// TestIncompleteStoreReadIsUnseen: every site, every way a store read
// can fail to complete. Each ends the walk with the reader's own
// refusal, seals nothing, and leaves the journal empty.
func TestIncompleteStoreReadIsUnseen(t *testing.T) {
	t.Parallel()

	refusals := []struct {
		name    string
		respond func(http.ResponseWriter)
		// throttled is whether the refusal is the host's pace (the
		// rest are an exhausted transient ladder).
		throttled bool
	}{
		{name: "throttled (secondary limit)", respond: secondaryLimitResponse, throttled: true},
		{name: "transient exhausted (503)", respond: unavailableResponse},
		{name: "transient exhausted (429)", respond: tooManyResponse},
	}

	for _, site := range storeSites() {
		for _, r := range refusals {
			t.Run(site.name+": "+r.name, func(t *testing.T) {
				t.Parallel()

				refusal := liveRefusal(t, r.respond)

				if errors.Is(refusal, gh.ErrThrottled) != r.throttled || errors.Is(refusal, gh.ErrForbidden) {
					t.Fatalf("the scripted refusal is %v — not the kind this row is about", refusal)
				}

				j := report.NewJournal()

				rep, err := site.walk(t, refusal).run(t, j)
				if !gh.Retryable(err) || errors.Is(err, gh.ErrThrottled) != r.throttled {
					t.Fatalf("Evidence = %v, %v — an incomplete store read must end the walk unseen", rep, err)
				}

				if rep != nil {
					t.Fatalf("Evidence sealed %s beside the refusal — an unseen walk seals nothing", rep.Verdict())
				}

				for _, want := range site.says {
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
}

// TestCompletedStoreRefusalStillDiverges is the other side, at every
// site: a read that COMPLETED and found nothing that verifies is a fact
// about the subject, and the walk reddens on it.
func TestCompletedStoreRefusalStillDiverges(t *testing.T) {
	t.Parallel()

	for _, site := range storeSites() {
		t.Run(site.name, func(t *testing.T) {
			t.Parallel()

			refusal := errors.New("verify: app: no bundle verifies under the expected identity")

			rep, err := site.walk(t, refusal).run(t, report.NewJournal())
			if err != nil {
				t.Fatalf("Evidence = %v — a verification failure is an answer, not a blind run", err)
			}

			if rep.Verdict() != report.VerdictFail || len(rep.Findings()) == 0 {
				t.Fatalf("verdict = %s, findings = %+v — want FAIL with the finding", rep.Verdict(), rep.Findings())
			}
		})
	}
}

// TestForbiddenStoreReadIsUnchanged pins what a credential refusal does
// at the store sites TODAY — it diverges — so this change is seen not to
// move it. Whether it should is a separate question, not this one's.
func TestForbiddenStoreReadIsUnchanged(t *testing.T) {
	t.Parallel()

	forbidden := liveRefusal(t, func(w http.ResponseWriter) {
		http.Error(w, `{"message":"Resource not accessible by personal access token"}`, http.StatusForbidden)
	})

	if !errors.Is(forbidden, gh.ErrForbidden) || gh.Retryable(forbidden) {
		t.Fatalf("the scripted refusal is %v — not a credential refusal", forbidden)
	}

	site := storeSites()[0]

	rep, err := site.walk(t, forbidden).run(t, report.NewJournal())
	if err != nil || rep.Verdict() != report.VerdictFail {
		t.Fatalf("Evidence = %v, %v — a credential refusal at a store site still diverges today", rep, err)
	}
}
