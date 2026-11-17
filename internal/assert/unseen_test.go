// A forge read that could not be completed is not a fact about the
// subject. Every assertion that reads the attestation store or a
// release asset — the presence leg's bundle reads, the two base-image
// mechanisms, the continuous digest, and both halves of the full-depth
// leg, with the release-asset and pin reads that leg makes first —
// must end the walk unseen when the host throttled the read, its
// transient ladder ran out (5xx, or a 429; stele#339), or the
// credential was refused (stele#343): the run seals CANNOT_JUDGE, and
// the journal holds no finding against the subject it never got to
// look at. A read that completed and refused — a bundle that does not
// verify — is still a finding.

package assert_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
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
	// source, when set, is the forge the contract is read from — so a
	// row can refuse the walk's own read of a listing the contract
	// source also makes, and reach the second of the two.
	source *fakeForge
	// workflowSource stacks the legacy adapter behind the manifest.
	workflowSource bool
	// selfSigned runs the deep leg under a templated signer identity:
	// pins come from the tag's own commit, the one deep read of it.
	selfSigned bool
}

func (s storeWalk) run(t *testing.T, j *report.Journal) (*report.Report, error) {
	t.Helper()

	var full *assert.FullDepth

	if s.deep != nil {
		verifier, signer := "acme/canon/.github/workflows/verify-release.yml", "acme/signer/.github/workflows/sign.yml"
		if s.selfSigned {
			verifier, signer = "", "{owner}/{repo}/.github/workflows/release.yml"
		}

		fd, err := assert.NewFullDepth(s.deep, s.forge, verifier, signer)
		if err != nil {
			t.Fatal(err)
		}

		full = fd
	}

	source := s.forge
	if s.source != nil {
		source = s.source
	}

	src := assert.Sources{
		assert.ManifestSource{Forge: source, Policy: s.policy.Evidence, Asset: "evidence-manifest.json"},
	}

	if s.workflowSource {
		src = append(src, assert.WorkflowSource{Forge: source, Policy: s.policy.Evidence})
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

// storeSite is one forge read in the evidence walk: a walk whose read
// refuses with the given error, and the words its refusal must carry.
type storeSite struct {
	name string
	walk func(t *testing.T, refusal error) storeWalk
	says []string
	// reads is "<subject>'s <thing>": what a refused credential's
	// message must say it could not read. Set at the sites that once
	// recorded a refusal as missing evidence.
	reads string
	// owes names the findings a row must record to reach its site —
	// the run history is read only to excuse a vsa finding, so that
	// row's walk carries one before the refused read. Any other
	// finding is a finding against a subject the run never saw.
	owes []string
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
			says:  []string{"base-image-approval:pgrx-bases", baseDigest},
			reads: "docker.io/library/debian:trixie@" + baseDigest + "'s approval attestations",
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
			says:  []string{"base-image-approval:org-bases", orgBaseRef},
			reads: orgBaseRef + "'s provenance attestations",
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
			says:  []string{"continuous-digest", "widget@"},
			reads: "widget@latest's attestations in the store",
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
			says:  []string{"deep release check", "widget@v1.0.0"},
			reads: "widget@v1.0.0's release attestations",
		},
		{
			name: "the full-depth checksum-manifest read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				f := deepForge()
				f.assetErr = map[string]error{"widget@v1.0.0/checksums.txt": refusal}

				return storeWalk{policy: loadTestPolicy(t), forge: f, attestor: &fakeAttestor{}, deep: &fakeDeep{}}
			},
			says:  []string{"deep release check", "widget@v1.0.0", "checksum manifest"},
			reads: "widget@v1.0.0's checksum manifest",
		},
		{
			name: "the full-depth publish-workflow read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				f := deepForge()
				f.fileAtErr = map[string]error{"widget:v1.0.0:.github/workflows/publish.yml": refusal}

				return storeWalk{policy: loadTestPolicy(t), forge: f, attestor: &fakeAttestor{}, deep: &fakeDeep{}}
			},
			says:  []string{"deep release check", "widget@v1.0.0", "publish workflow"},
			reads: "widget@v1.0.0's signing pins",
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
			says:  []string{"deep verdict check", "widget@v1.0.0"},
			reads: "widget@v1.0.0's verification summaries",
		},
		{
			name: "the presence leg's class-bundle read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				f := completeRelease()
				f.assetErr = map[string]error{"widget@v1.0.0/" + imageBundle: refusal}

				return storeWalk{policy: loadTestPolicy(t), forge: f, attestor: &fakeAttestor{}}
			},
			says:  []string{"store verdicts", "widget@v1.0.0", imageBundle},
			reads: "widget@v1.0.0's " + imageBundle,
		},
		{
			name: "the full-depth class-bundle read, against a manifest that names registry subjects",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				f := deepForge()
				f.lateAssetErr = map[string]error{"widget@v1.0.0/" + imageBundle: refusal}

				return storeWalk{policy: loadTestPolicy(t), forge: f, attestor: &fakeAttestor{}, deep: &fakeDeep{}}
			},
			says:  []string{"deep release check", "widget@v1.0.0", imageBundle},
			reads: "widget@v1.0.0's class bundles",
		},
		{
			name: "the full-depth class-bundle read, against a manifest that predates registry subjects",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				f := deepForge()
				f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = classlessManifest()
				f.lateAssetErr = map[string]error{"widget@v1.0.0/" + imageBundle: refusal}

				return storeWalk{policy: enrichedDeepPolicy(t), forge: f, attestor: &fakeAttestor{}, deep: &fakeDeep{}}
			},
			says:  []string{"deep release check", "widget@v1.0.0", imageBundle},
			reads: "widget@v1.0.0's class bundles",
		},
		{
			name: "the full-depth machinery publish-workflow read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				f := deepForge()
				f.fileAtErr = map[string]error{"canon:" + machineryPin40 + ":.github/workflows/publish.yml": refusal}

				return storeWalk{policy: loadTestPolicy(t), forge: f, attestor: &fakeAttestor{}, deep: &fakeDeep{}}
			},
			says:  []string{"deep release check", "widget@v1.0.0", "machinery publish workflow"},
			reads: "widget@v1.0.0's signing pins",
		},
		{
			name: "the full-depth tag-commit read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				f := deepForge()
				f.torn = map[string]error{"TagCommit": refusal}

				return storeWalk{
					policy: loadTestPolicy(t), forge: f, attestor: &fakeAttestor{}, deep: &fakeDeep{}, selfSigned: true,
				}
			},
			says:  []string{"deep release check", "widget@v1.0.0", "tag's commit"},
			reads: "widget@v1.0.0's signing pins",
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

// imageBundle is the fixture release's one class bundle asset.
const imageBundle = "attestations-image.intoto.jsonl"

// noManifest takes the contract manifest off the release, so the
// manifest source does not speak for it and the legacy workflow
// adapter behind it is asked.
func noManifest(f *fakeForge) {
	f.assets["widget@v1.0.0"] = slices.DeleteFunc(f.assets["widget@v1.0.0"],
		func(a string) bool { return a == "evidence-manifest.json" })
}

// returningSites are the walk's forge reads that never had a FAIL
// path: any error they meet ends the walk. They sit in the forbidden
// table beside storeSites so that table covers every forge read the
// evidence walk makes, and a credential refusal at any of them is held
// to the same answer.
func returningSites() []storeSite {
	torn := func(read string) func(f *fakeForge, refusal error) {
		return func(f *fakeForge, refusal error) { f.torn = map[string]error{read: refusal} }
	}

	file := func(key string) func(f *fakeForge, refusal error) {
		return func(f *fakeForge, refusal error) { f.fileAtErr = map[string]error{key: refusal} }
	}

	release := func(refuse func(*fakeForge, error)) func(t *testing.T, refusal error) storeWalk {
		return func(t *testing.T, refusal error) storeWalk {
			t.Helper()

			f := completeRelease()
			refuse(f, refusal)

			return storeWalk{policy: loadTestPolicy(t), forge: f, attestor: &fakeAttestor{}}
		}
	}

	return []storeSite{
		{
			name: "the release listing",
			walk: release(torn("ReleaseTags")),
			says: []string{"releases of acme/widget"},
		},
		{
			name: "the contract manifest's asset listing",
			walk: release(torn("ReleaseAssets")),
			says: []string{"contract of acme/widget@v1.0.0"},
		},
		{
			name: "the contract manifest's asset read",
			walk: release(func(f *fakeForge, refusal error) {
				f.assetErr = map[string]error{"widget@v1.0.0/evidence-manifest.json": refusal}
			}),
			says: []string{"manifest of acme/widget@v1.0.0"},
		},
		{
			name: "the walk's own asset listing",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				f := completeRelease()
				f.torn = map[string]error{"ReleaseAssets": refusal}

				// The contract is read from an untorn copy, so the
				// walk's second listing is the one that refuses.
				return storeWalk{policy: loadTestPolicy(t), forge: f, source: completeRelease(), attestor: &fakeAttestor{}}
			},
			says: []string{"assets of acme/widget@v1.0.0"},
		},
		{
			name: "the legacy workflow contract's publish-workflow read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				f := completeRelease()
				noManifest(f)
				file("widget:v1.0.0:.github/workflows/publish.yml")(f, refusal)

				return storeWalk{policy: loadTestPolicy(t), forge: f, attestor: &fakeAttestor{}, workflowSource: true}
			},
			says: []string{"workflow contract of acme/widget@v1.0.0"},
		},
		{
			name: "the legacy workflow contract's self-publish read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				f := completeRelease()
				noManifest(f)
				f.files = map[string]string{
					"widget:v1.0.0:.github/workflows/publish.yml": "on:\n  workflow_call:\njobs: {}\n",
				}
				file("widget:v1.0.0:.github/workflows/self-publish.yml")(f, refusal)

				return storeWalk{policy: loadTestPolicy(t), forge: f, attestor: &fakeAttestor{}, workflowSource: true}
			},
			says: []string{"workflow contract of acme/widget@v1.0.0"},
		},
		{
			name: "the presence leg's store read",
			walk: release(torn("Attestations")),
			says: []string{"store for sha256:" + subjectDigest},
		},
		{
			name: "the run-history read",
			walk: release(func(f *fakeForge, refusal error) {
				f.store = map[string][]string{}
				f.torn = map[string]error{"FailedRuns": refusal}
			}),
			says: []string{"run history of acme/widget@v1.0.0"},
			owes: []string{"vsa:" + subjectDigest[:12]},
		},
		{
			name: "the continuous stub read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				f := continuousForge()
				file(contStubPath)(f, refusal)

				return storeWalk{policy: mustPolicy(t, continuousOnlyPolicyJSON), forge: f, attestor: &fakeAttestor{}}
			},
			says: []string{"continuous stub of widget"},
		},
		{
			name: "the rolling-tag package read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				f := continuousForge()
				torn("PackageVersionDigest")(f, refusal)

				return storeWalk{policy: mustPolicy(t, continuousOnlyPolicyJSON), forge: f, attestor: &fakeAttestor{}}
			},
			says: []string{"package versions of widget"},
		},
		{
			name: "the shared reusable workflow read the signer pin comes from",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				f := continuousForge()
				file(contSharedPath)(f, refusal)

				return storeWalk{policy: mustPolicy(t, continuousOnlyPolicyJSON), forge: f, attestor: &fakeAttestor{}}
			},
			says: []string{".github/workflows/continuous.yml at " + sharedPin},
		},
		{
			name: "the provenance-verified scope's build-file read",
			walk: func(t *testing.T, refusal error) storeWalk {
				t.Helper()

				f := provenanceForge()
				file("widget:HEAD:Dockerfile")(f, refusal)

				return storeWalk{policy: mustPolicy(t, provenanceOnlyPolicyJSON), forge: f, attestor: &fakeAttestor{}}
			},
			says: []string{"build file of widget"},
		},
	}
}

// TestForbiddenReadIsUnseen: every forge read the evidence walk makes,
// each refused by a real credential refusal from a real gh.Client.
// None of them learned anything about the subject, so each ends the
// walk CANNOT_JUDGE — the reader's own ErrForbidden carried out, no
// report sealed, no finding recorded. Where a refusal used to be
// recorded as missing evidence, its message now says what it was.
func TestForbiddenReadIsUnseen(t *testing.T) {
	t.Parallel()

	refusals := []struct {
		name    string
		respond func(http.ResponseWriter)
	}{
		{name: "403", respond: func(w http.ResponseWriter) {
			http.Error(w, `{"message":"Resource not accessible by personal access token"}`, http.StatusForbidden)
		}},
		{name: "401", respond: func(w http.ResponseWriter) {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
		}},
	}

	for _, site := range slices.Concat(storeSites(), returningSites()) {
		for _, r := range refusals {
			t.Run(site.name+": "+r.name, func(t *testing.T) {
				t.Parallel()

				forbidden := liveRefusal(t, r.respond)

				if !errors.Is(forbidden, gh.ErrForbidden) || gh.Retryable(forbidden) {
					t.Fatalf("the scripted refusal is %v — not a credential refusal", forbidden)
				}

				j := report.NewJournal()

				rep, err := site.walk(t, forbidden).run(t, j)
				holdsForbiddenUnseen(t, &site, rep, err, j)
			})
		}
	}
}

// holdsForbiddenUnseen is one forbidden row's whole judgment: the
// reader's refusal carried out, nothing sealed, the message saying
// what it was, and no finding the row did not owe.
func holdsForbiddenUnseen(t *testing.T, site *storeSite, rep *report.Report, err error, j *report.Journal) {
	t.Helper()

	if !errors.Is(err, gh.ErrForbidden) {
		t.Fatalf("Evidence = %v, %v — a read the credential could not make must end the walk unseen", rep, err)
	}

	if rep != nil {
		t.Fatalf("Evidence sealed %s beside the refusal — an unseen walk seals nothing", rep.Verdict())
	}

	for _, want := range site.says {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}

	if site.reads != "" && !strings.Contains(err.Error(), "the credential cannot read "+site.reads) {
		t.Errorf("refusal %q does not say the credential cannot read %s", err, site.reads)
	}

	if strings.Contains(err.Error(), "no attestation verifies") ||
		strings.Contains(err.Error(), "carries no attestation") {
		t.Errorf("refusal %q speaks the vocabulary of missing evidence", err)
	}

	for _, f := range j.Findings() {
		if !slices.Contains(site.owes, f.Assertion) {
			t.Errorf("journal holds a finding against a subject the run never saw: %+v", f)
		}
	}
}
