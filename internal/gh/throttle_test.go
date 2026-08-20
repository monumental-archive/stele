// The one 403 that is not a fact about the subject: GitHub's
// SECONDARY rate limit, which arrives with the same status as a
// refused credential and means the opposite (stele#196). Measured
// 2026-08-20, an org-wide walk took one with the primary budget at
// 4799/5000 and reported live repositories as unreadable.

package gh_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
)

// The two documented shapes of a secondary-limit refusal, verbatim in
// the parts that carry the signal: the header GitHub sends when it has
// a wait to name, and the body it sends when it does not.
const (
	secondaryBody = `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes ` +
		`before you try again. If you reach out to GitHub Support for help, please include the request ID.",` +
		`"documentation_url":"https://docs.github.com/rest/overview/` +
		`rate-limits-for-the-rest-api#about-secondary-rate-limits"}`
	forbiddenBody = `{"message":"Resource not accessible by personal access token",` +
		`"documentation_url":"https://docs.github.com/rest/repos/repos#list-organization-repositories"}`
)

// refusalServer answers the repos listing with `refuse` scripted
// refusals before serving a real short page, counting attempts.
//
//nolint:gocritic // unnamedResult: client, attempt counter
func refusalServer(t *testing.T, refuse int, respond func(http.ResponseWriter)) (*gh.Client, *int) {
	t.Helper()

	seen := 0
	mux := http.NewServeMux()

	mux.HandleFunc("/orgs/acme/repos", func(w http.ResponseWriter, _ *http.Request) {
		seen++
		if seen <= refuse {
			respond(w)

			return
		}

		writeBody(w, []byte(`[{"name": "widget", "archived": false, "fork": false}]`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.New("test-token")
	c.Base = srv.URL
	c.Download = srv.URL
	c.Sleep = func(time.Duration) {} // no wall time in tests

	return c, &seen
}

// TestSecondaryRateLimitJoinsTheLadder pins the whole classification:
// a 403 carrying either documented secondary-limit signal is the host
// throttling THIS WALK and is retried; the same status without them
// is a fact about the subject and is returned at once.
func TestSecondaryRateLimitJoinsTheLadder(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		// respond writes one scripted refusal.
		respond func(http.ResponseWriter)
		// refuse is how many refusals precede the real page; more than
		// the ladder's bound exhausts it.
		refuse int
		// attempts is the reads the walk must make.
		attempts int
		// found is whether the listing answers.
		found bool
		// says is a fragment the refusal must carry; never is one it
		// must not.
		says, never string
	}{
		{
			name: "a retry-after header is the throttle, retried until it clears",
			respond: func(w http.ResponseWriter) {
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusForbidden)
			},
			refuse:   2,
			attempts: 3,
			found:    true,
		},
		{
			name: "the secondary-limit message alone is the throttle, retried until it clears",
			respond: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusForbidden)
				writeBody(w, []byte(secondaryBody))
			},
			refuse:   1,
			attempts: 2,
			found:    true,
		},
		{
			name: "a throttle that never clears refuses by the throttle, never by the subject",
			respond: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusForbidden)
				writeBody(w, []byte(secondaryBody))
			},
			refuse:   99,
			attempts: 4,
			says:     "throttled this walk",
			never:    "cannot read this",
		},
		{
			name: "a 403 without either signal is the subject, refused at once",
			respond: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusForbidden)
				writeBody(w, []byte(forbiddenBody))
			},
			refuse:   99,
			attempts: 1,
			says:     "cannot read this",
			never:    "throttled this walk",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, seen := refusalServer(t, tc.refuse, tc.respond)

			repos, err := c.ListRepos("acme")

			switch {
			case tc.found && (err != nil || len(repos) != 1):
				t.Fatalf("ListRepos = %v, %v — a throttled read must not end the walk", repos, err)
			case !tc.found && err == nil:
				t.Fatal("ListRepos answered where the forge refused")
			}

			if *seen != tc.attempts {
				t.Fatalf("attempts = %d, want %d", *seen, tc.attempts)
			}

			if tc.says != "" && !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("err = %v, want it to say %q", err, tc.says)
			}

			if tc.never != "" && strings.Contains(err.Error(), tc.never) {
				t.Fatalf("err = %v, must not say %q — that is the other refusal", err, tc.never)
			}
		})
	}
}

// TestThrottleIsNotTheForbiddenSentinel pins the typed half of the
// same rule: a caller that branches on ErrForbidden — an unreadable
// subject is unchecked, never clean — must not see a throttle there.
func TestThrottleIsNotTheForbiddenSentinel(t *testing.T) {
	t.Parallel()

	throttled, _ := refusalServer(t, 99, func(w http.ResponseWriter) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusForbidden)
	})

	if _, err := throttled.ListRepos("acme"); errors.Is(err, gh.ErrForbidden) {
		t.Fatalf("throttle err = %v, want it typed apart from ErrForbidden", err)
	}

	refused, _ := refusalServer(t, 99, func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusForbidden)
		writeBody(w, []byte(forbiddenBody))
	})

	if _, err := refused.ListRepos("acme"); !errors.Is(err, gh.ErrForbidden) {
		t.Fatalf("forbidden err = %v, want ErrForbidden", err)
	}
}

// TestAssetThrottleIsRetried pins the same classifier on the download
// host, where a walk pulling many assets earns a secondary limit
// first — and where a plain 403 (an expired object URL) still ends the
// download at once.
func TestAssetThrottleIsRetried(t *testing.T) {
	t.Parallel()

	seen := 0
	mux := http.NewServeMux()

	mux.HandleFunc("/acme/widget/releases/download/v1.0.0/app.bin", func(w http.ResponseWriter, _ *http.Request) {
		seen++
		if seen <= 2 {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusForbidden)

			return
		}

		writeBody(w, []byte("asset bytes"))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.New("test-token")
	c.Base = srv.URL
	c.Download = srv.URL
	c.Sleep = func(time.Duration) {}

	body, err := c.Asset("acme", "widget", "v1.0.0", "app.bin")
	if err != nil || string(body) != "asset bytes" {
		t.Fatalf("Asset = %q, %v — a throttled download must not end the walk", body, err)
	}

	if seen != 3 {
		t.Fatalf("attempts = %d, want 3 (two throttled, one answering)", seen)
	}
}
