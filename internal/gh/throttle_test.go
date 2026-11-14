// The one 403 that is not a fact about the subject: the forge rate
// limiting THIS CALLER, which arrives with the same status as a
// refused credential and means the opposite (stele#196, stele#209).
// Measured 2026-08-20, an org-wide walk took one with the primary
// budget at 4799/5000 and reported live repositories as unreadable.
//
// Two tables, because there are two questions and conflating them is
// how the first version of this shipped with a marker missing: what
// ONE response says (the classifier), and what a LADDER does with a
// run of them (retry, the host's own wait, the terminal refusal).

package gh_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
)

// The documented shapes of a rate-limit refusal, verbatim in the parts
// that carry the signal: the header the forge sends when it has a wait
// to name, and the body it sends when it does not.
const (
	secondaryBody = `{"message":"You have exceeded a secondary rate limit. Please wait a few minutes ` +
		`before you try again. If you reach out to GitHub Support for help, please include the request ID.",` +
		`"documentation_url":"https://docs.github.com/rest/overview/` +
		`rate-limits-for-the-rest-api#about-secondary-rate-limits"}`
	forbiddenBody = `{"message":"Resource not accessible by personal access token",` +
		`"documentation_url":"https://docs.github.com/rest/repos/repos#list-organization-repositories"}`
)

// TestThrottledClassifiesOneResponse walks every branch of the one
// classifier, on the response alone. A marker read wrongly here is a
// live subject reported unreadable (a throttle missed) or a narrowed
// credential hidden behind a retry ladder (a refusal miscalled), so
// each marker gets its own row and so does each way of malforming it.
func TestThrottledClassifiesOneResponse(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		status  int
		headers map[string]string
		body    string
		// wait is the pause the host NAMED; want is whether the
		// response is the host throttling this caller at all.
		wait time.Duration
		want bool
	}{
		{
			name:   "a bare 403 is a fact about the subject, never the pace",
			status: http.StatusForbidden,
			body:   forbiddenBody,
		},
		{
			name:    "retry-after marks the throttle and names the wait",
			status:  http.StatusForbidden,
			headers: map[string]string{"Retry-After": "60"},
			wait:    60 * time.Second,
			want:    true,
		},
		{
			name:    "a budget spent on this response's own resource is the throttle",
			status:  http.StatusForbidden,
			headers: map[string]string{"X-RateLimit-Remaining": "0"},
			body:    forbiddenBody,
			want:    true,
		},
		{
			name:   "the secondary-limit message alone is the throttle",
			status: http.StatusForbidden,
			body:   secondaryBody,
			want:   true,
		},
		{
			// The rejected inference, pinned: the counters are per
			// resource, and the measured refusal came with this one
			// healthy. A neighbouring number proves nothing in either
			// direction, so only exhaustion is a marker.
			name:    "a healthy remaining counter is no marker either way",
			status:  http.StatusForbidden,
			headers: map[string]string{"X-RateLimit-Remaining": "4799"},
			body:    forbiddenBody,
		},
		{
			name:    "a counter that will not parse is no counter",
			status:  http.StatusForbidden,
			headers: map[string]string{"X-RateLimit-Remaining": "unknown"},
			body:    forbiddenBody,
		},
		{
			// Presence is the marker; the number is only the wait. An
			// unreadable one must not cost the classification.
			name:    "a retry-after that will not parse still marks the throttle",
			status:  http.StatusForbidden,
			headers: map[string]string{"Retry-After": "in a little while"},
			body:    forbiddenBody,
			want:    true,
		},
		{
			name:    "a zero retry-after marks the throttle and names no wait",
			status:  http.StatusForbidden,
			headers: map[string]string{"Retry-After": "0"},
			want:    true,
		},
		{
			name:    "a negative retry-after names no wait",
			status:  http.StatusForbidden,
			headers: map[string]string{"Retry-After": "-30"},
			want:    true,
		},
		{
			// A bounded ladder is the guarantee that a walk against a
			// broken host still ends; a header that could name any wait
			// could hand that guarantee back.
			name:    "a wait past the bound is clamped, never honoured whole",
			status:  http.StatusForbidden,
			headers: map[string]string{"Retry-After": "86400"},
			wait:    120 * time.Second,
			want:    true,
		},
		{
			// Clamped in SECONDS, before the multiply: this many seconds
			// as a duration overflows, and an overflowed pause is a
			// negative one — no pause at all.
			name:    "a wait large enough to overflow is clamped, not inverted",
			status:  http.StatusForbidden,
			headers: map[string]string{"Retry-After": "9223372036854775807"},
			wait:    120 * time.Second,
			want:    true,
		},
		{
			name:    "401 is the credential, whatever else it carries",
			status:  http.StatusUnauthorized,
			headers: map[string]string{"Retry-After": "60"},
		},
		{
			// 429 says the same thing unambiguously and already rides the
			// ladder as a transient. This classifier answers the one
			// status that is ambiguous; widening it would move a settled
			// class for no evidence.
			name:    "429 needs no classifying and is not this question",
			status:  http.StatusTooManyRequests,
			headers: map[string]string{"Retry-After": "60"},
		},
		{
			name:    "a 200 carrying every marker is still an answer",
			status:  http.StatusOK,
			headers: map[string]string{"Retry-After": "60", "X-RateLimit-Remaining": "0"},
		},
		{
			name:   "404 is absence",
			status: http.StatusNotFound,
		},
		{
			name:    "5xx is the host failing, not the host throttling",
			status:  http.StatusServiceUnavailable,
			headers: map[string]string{"Retry-After": "60"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Set, never a map literal: Get canonicalises its key, and a
			// hand-spelled X-RateLimit-Remaining would sit under a key
			// nothing ever looks up — a test that passed by not asking.
			header := http.Header{}
			for k, v := range tc.headers {
				header.Set(k, v)
			}

			wait, got := gh.Throttled(tc.status, header, []byte(tc.body))
			if got != tc.want {
				t.Fatalf("Throttled(%d) = %v, want %v", tc.status, got, tc.want)
			}

			if wait != tc.wait {
				t.Fatalf("wait = %v, want %v", wait, tc.wait)
			}
		})
	}
}

// probe is one scripted forge and what a walk did to it: the reads it
// made, and the pauses it took between them.
type probe struct {
	client   *gh.Client
	attempts int
	waits    []time.Duration
}

// newProbe answers the repos listing with `refuse` scripted refusals
// before serving a real page.
func newProbe(t *testing.T, refuse int, respond func(http.ResponseWriter)) *probe {
	t.Helper()

	p := &probe{}
	mux := http.NewServeMux()

	mux.HandleFunc("/orgs/acme/repos", func(w http.ResponseWriter, _ *http.Request) {
		p.attempts++
		if p.attempts <= refuse {
			respond(w)

			return
		}

		writeBody(w, []byte(`[{"name": "widget", "archived": false, "fork": false}]`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.New("test-token")
	ownTransport(c, srv)
	c.Base = srv.URL
	c.Download = srv.URL
	// The clock is the assertion, not wall time: a ladder that honours
	// the host's wait and one that ignores it differ only here.
	c.Sleep = func(d time.Duration) { p.waits = append(p.waits, d) }
	p.client = c

	return p
}

// The scripted refusals, one per marker.
func retryAfter403(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(http.StatusForbidden)
}

func remainingZero403(w http.ResponseWriter) {
	w.Header().Set("X-Ratelimit-Remaining", "0")
	w.WriteHeader(http.StatusForbidden)
	writeBody(w, []byte(forbiddenBody))
}

func secondaryLimit403(w http.ResponseWriter) {
	w.WriteHeader(http.StatusForbidden)
	writeBody(w, []byte(secondaryBody))
}

func bare403(w http.ResponseWriter) {
	w.WriteHeader(http.StatusForbidden)
	writeBody(w, []byte(forbiddenBody))
}

// TestThrottleJoinsTheLadder pins what the ladder does with a run of
// classified responses: a throttle is retried and waits out the host's
// OWN number when it named one, a throttle that never clears ends the
// run naming the throttle, and a refusal of the subject never enters
// the ladder at all.
func TestThrottleJoinsTheLadder(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		// respond writes one scripted refusal.
		respond func(http.ResponseWriter)
		// refuse is how many refusals precede the real page; more than
		// the ladder's bound exhausts it.
		refuse int
		// attempts is the reads the walk must make, waits the pauses it
		// must take between them.
		attempts int
		waits    []time.Duration
		// found is whether the listing answers.
		found bool
		// says is a fragment the refusal must carry; never is one it
		// must not.
		says, never string
	}{
		{
			name:     "a named wait is honoured over the ladder's own backoff",
			respond:  retryAfter403,
			refuse:   2,
			attempts: 3,
			waits:    []time.Duration{60 * time.Second, 60 * time.Second},
			found:    true,
		},
		{
			name:     "the secondary-limit message alone is retried until it clears",
			respond:  secondaryLimit403,
			refuse:   1,
			attempts: 2,
			waits:    []time.Duration{3 * time.Second},
			found:    true,
		},
		{
			// The marker the first build of this missed: the walk that
			// died on 2026-08-20 was refused with a counter, not a body.
			name:     "a spent budget is retried, and waits the ladder's own backoff",
			respond:  remainingZero403,
			refuse:   1,
			attempts: 2,
			waits:    []time.Duration{3 * time.Second},
			found:    true,
		},
		{
			name:     "a throttle that never clears refuses by the throttle, never by the subject",
			respond:  secondaryLimit403,
			refuse:   99,
			attempts: 4,
			waits:    []time.Duration{3 * time.Second, 6 * time.Second, 9 * time.Second},
			says:     "throttled this walk",
			never:    "cannot read this",
		},
		{
			name:     "a 403 without a marker is the subject, refused at once",
			respond:  bare403,
			refuse:   99,
			attempts: 1,
			says:     "cannot read this",
			never:    "throttled this walk",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newProbe(t, tc.refuse, tc.respond)

			repos, err := p.client.ListRepos("acme")

			switch {
			case tc.found && (err != nil || len(repos) != 1):
				t.Fatalf("ListRepos = %v, %v — a throttled read must not end the walk", repos, err)
			case !tc.found && err == nil:
				t.Fatal("ListRepos answered where the forge refused")
			}

			if p.attempts != tc.attempts {
				t.Fatalf("attempts = %d, want %d", p.attempts, tc.attempts)
			}

			if !slices.Equal(p.waits, tc.waits) {
				t.Fatalf("waits = %v, want %v", p.waits, tc.waits)
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

// The scripted 429s: the status that needs no classifying, with and
// without the wait it is documented to carry.
func retryAfter429(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(http.StatusTooManyRequests)
}

func bare429(w http.ResponseWriter) {
	w.WriteHeader(http.StatusTooManyRequests)
}

func unreadableRetryAfter429(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "in a little while")
	w.WriteHeader(http.StatusTooManyRequests)
}

func overBoundRetryAfter429(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "86400")
	w.WriteHeader(http.StatusTooManyRequests)
}

// TestRateLimitWaitComesFromTheResponse pins stele#217: the wait a
// ladder takes comes from the response for BOTH statuses the forge
// rate limits with. A 429 carrying retry-after: 60 burned the ladder's
// four attempts in eighteen seconds, so the AMBIGUOUS status got the
// host's own number and the UNAMBIGUOUS one did not.
//
// The 429 is still a transient — what it MEANS is unchanged, and the
// classifier still answers only for the 403 — so every row here also
// asserts it is neither of the two sentinels a caller branches on.
func TestRateLimitWaitComesFromTheResponse(t *testing.T) {
	t.Parallel()

	// The ladder's own backoff is (attempt-1) × 3s.
	ladder := []time.Duration{3 * time.Second, 6 * time.Second, 9 * time.Second}

	for _, tc := range []struct {
		name     string
		respond  func(http.ResponseWriter)
		refuse   int
		attempts int
		waits    []time.Duration
		found    bool
	}{
		{
			name:     "a named wait is honoured, and the walk completes",
			respond:  retryAfter429,
			refuse:   2,
			attempts: 3,
			waits:    []time.Duration{60 * time.Second, 60 * time.Second},
			found:    true,
		},
		{
			name:     "a named wait is honoured on every attempt of an exhausted ladder",
			respond:  retryAfter429,
			refuse:   99,
			attempts: 4,
			waits:    []time.Duration{60 * time.Second, 60 * time.Second, 60 * time.Second},
		},
		{
			name:     "a 429 naming no wait still pauses on the ladder's own backoff",
			respond:  bare429,
			refuse:   99,
			attempts: 4,
			waits:    ladder,
		},
		{
			// Exactly what the same header does on a 403: one parse, and
			// a number it cannot read is a number it does not invent.
			name:     "a retry-after that will not parse falls back to the ladder's backoff",
			respond:  unreadableRetryAfter429,
			refuse:   99,
			attempts: 4,
			waits:    ladder,
		},
		{
			// And the same clamp: a bounded ladder is what makes a walk
			// against a broken host end.
			name:     "a wait past the bound is clamped, never honoured whole",
			respond:  overBoundRetryAfter429,
			refuse:   99,
			attempts: 4,
			waits:    []time.Duration{120 * time.Second, 120 * time.Second, 120 * time.Second},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newProbe(t, tc.refuse, tc.respond)

			repos, err := p.client.ListRepos("acme")

			switch {
			case tc.found && (err != nil || len(repos) != 1):
				t.Fatalf("ListRepos = %v, %v — a rate-limited read must not end the walk", repos, err)
			case !tc.found && err == nil:
				t.Fatal("ListRepos answered where the forge refused")
			}

			if p.attempts != tc.attempts {
				t.Fatalf("attempts = %d, want %d", p.attempts, tc.attempts)
			}

			if !slices.Equal(p.waits, tc.waits) {
				t.Fatalf("waits = %v, want %v", p.waits, tc.waits)
			}

			if tc.found {
				return
			}

			if !strings.Contains(err.Error(), "HTTP 429") {
				t.Fatalf("err = %v, want it to name the status", err)
			}

			// The vocabulary is unchanged: a 429 is neither the host's
			// classified throttle nor the credential's refusal.
			if errors.Is(err, gh.ErrThrottled) {
				t.Fatalf("err = %v — a 429 needs no classifying and must not borrow that word", err)
			}

			if errors.Is(err, gh.ErrForbidden) {
				t.Fatalf("err = %v — a 429 says nothing about the credential", err)
			}
		})
	}
}

// TestAssetRateLimitHonoursTheNamedWait is the download host's row: a
// walk pulling many assets is the pace that earns a 429, and that
// ladder reads the host's number through the same one place.
func TestAssetRateLimitHonoursTheNamedWait(t *testing.T) {
	t.Parallel()

	seen := 0
	waits := []time.Duration{}
	mux := http.NewServeMux()

	mux.HandleFunc("/acme/widget/releases/download/v1.0.0/app.bin", func(w http.ResponseWriter, _ *http.Request) {
		seen++
		if seen <= 2 {
			retryAfter429(w)

			return
		}

		writeBody(w, []byte("asset bytes"))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.New("test-token")
	ownTransport(c, srv)
	c.Base = srv.URL
	c.Download = srv.URL
	c.Sleep = func(d time.Duration) { waits = append(waits, d) }

	body, err := c.Asset("acme", "widget", "v1.0.0", "app.bin")
	if err != nil || string(body) != "asset bytes" {
		t.Fatalf("Asset = %q, %v — a rate-limited download must not end the walk", body, err)
	}

	if want := []time.Duration{60 * time.Second, 60 * time.Second}; !slices.Equal(waits, want) {
		t.Fatalf("waits = %v, want %v — the download ladder honours the host's number too", waits, want)
	}
}

// TestThrottleIsNotTheForbiddenSentinel pins the typed half of the
// same rule: a caller that branches on ErrForbidden — an unreadable
// subject is unchecked, never clean — must not see a throttle there,
// and one asking the throttle's own question must not see a refusal.
func TestThrottleIsNotTheForbiddenSentinel(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		respond   func(http.ResponseWriter)
		forbidden bool
		throttled bool
	}{
		{name: "a named wait", respond: retryAfter403, throttled: true},
		{name: "a spent budget", respond: remainingZero403, throttled: true},
		{name: "the secondary-limit message", respond: secondaryLimit403, throttled: true},
		{name: "a bare refusal", respond: bare403, forbidden: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newProbe(t, 99, tc.respond)

			_, err := p.client.ListRepos("acme")

			if got := errors.Is(err, gh.ErrForbidden); got != tc.forbidden {
				t.Fatalf("errors.Is(%v, ErrForbidden) = %v, want %v", err, got, tc.forbidden)
			}

			if got := errors.Is(err, gh.ErrThrottled); got != tc.throttled {
				t.Fatalf("errors.Is(%v, ErrThrottled) = %v, want %v", err, got, tc.throttled)
			}
		})
	}
}

// TestThrottledCaptureRecordsNothing is the capture leg's row: a
// snapshot holds FACTS, and a read the host throttled produced none.
// A capture that wrote a file here would replay a throttle as an
// answer about the subject — the same defect one layer down, and
// permanent, because a snapshot outlives the outage that made it.
func TestThrottledCaptureRecordsNothing(t *testing.T) {
	t.Parallel()

	p := newProbe(t, 99, secondaryLimit403)
	into := filepath.Join(t.TempDir(), "capture")

	_, err := (gh.Capture{Live: p.client, Dir: into}).ListRepos("acme")
	if err == nil || !strings.Contains(err.Error(), "throttled this walk") {
		t.Fatalf("ListRepos = %v, want the throttle refusal", err)
	}

	if _, serr := os.Stat(into); !os.IsNotExist(serr) {
		t.Fatalf("the capture wrote %s — a throttled read is not a fact to record", into)
	}
}

// TestAssetThrottleIsRetried pins the same classifier on the download
// host, where a walk pulling many assets earns a rate limit first —
// and where a plain 403 (an expired object URL) still ends the
// download at once.
func TestAssetThrottleIsRetried(t *testing.T) {
	t.Parallel()

	seen := 0
	waits := []time.Duration{}
	mux := http.NewServeMux()

	mux.HandleFunc("/acme/widget/releases/download/v1.0.0/app.bin", func(w http.ResponseWriter, _ *http.Request) {
		seen++
		if seen <= 2 {
			retryAfter403(w)

			return
		}

		writeBody(w, []byte("asset bytes"))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.New("test-token")
	ownTransport(c, srv)
	c.Base = srv.URL
	c.Download = srv.URL
	c.Sleep = func(d time.Duration) { waits = append(waits, d) }

	body, err := c.Asset("acme", "widget", "v1.0.0", "app.bin")
	if err != nil || string(body) != "asset bytes" {
		t.Fatalf("Asset = %q, %v — a throttled download must not end the walk", body, err)
	}

	if seen != 3 {
		t.Fatalf("attempts = %d, want 3 (two throttled, one answering)", seen)
	}

	if want := []time.Duration{60 * time.Second, 60 * time.Second}; !slices.Equal(waits, want) {
		t.Fatalf("waits = %v, want %v — the download ladder honours the host's number too", waits, want)
	}
}

// The two rate-limit refusals as GitHub sends them, for the store read
// (stele#339): whole responses rather than one marker each, so the row
// proves the classifier against what the forge actually sends.
//
// primaryLimit is the primary-limit refusal in the shape GitHub's
// REST rate-limit page documents
// (https://docs.github.com/rest/using-the-rest-api/rate-limits-for-the-rest-api,
// read 2026-11-15): a 403 carrying the five x-ratelimit-* headers that
// page names, with x-ratelimit-remaining at 0 — the marker Throttled's
// own comment quotes. The page shows no example body; the message here
// is the one GitHub's earlier REST overview printed for this case, and
// it carries no marker, so its wording cannot make the row pass.
//
// secondaryLimit is the secondary-limit refusal measured 2026-08-20 on
// an org-wide walk and quoted in Throttled's comment: a 403 whose
// primary budget is NOT spent (4799 of 5000 left) and whose body names
// the secondary limit.
func primaryLimit(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Ratelimit-Limit", "60")
	h.Set("X-Ratelimit-Remaining", "0")
	h.Set("X-Ratelimit-Used", "60")
	h.Set("X-Ratelimit-Reset", "1377013266")
	h.Set("X-Ratelimit-Resource", "core")
	w.WriteHeader(http.StatusForbidden)
	//nolint:errcheck,gosec // test server write
	w.Write([]byte(`{"message":"API rate limit exceeded for xxx.xxx.xxx.xxx. (But here's the good news:` +
		` Authenticated requests get a higher rate limit. Check out the documentation for more details.)",` +
		`"documentation_url":"https://docs.github.com/rest/overview/rate-limits-for-the-rest-api"}`))
}

func secondaryLimit(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Ratelimit-Limit", "5000")
	h.Set("X-Ratelimit-Remaining", "4799")
	h.Set("X-Ratelimit-Resource", "core")
	w.WriteHeader(http.StatusForbidden)
	//nolint:errcheck,gosec // test server write
	w.Write([]byte(secondaryBody))
}

// TestAttestationStoreThrottleIsTyped is stele#339's store-client row
// on the reader the evidence walk uses: both rate-limit refusals type
// as the host's pace, and a 403 carrying neither mark stays the
// credential's. A throttle that read as ErrForbidden would be judged as
// a fact about the subject — the FAIL the issue measured.
func TestAttestationStoreThrottleIsTyped(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		respond   func(http.ResponseWriter)
		throttled bool
	}{
		{name: "the primary limit, as documented", respond: primaryLimit, throttled: true},
		{name: "the secondary limit, as measured", respond: secondaryLimit, throttled: true},
		{name: "a 403 with neither mark", respond: func(w http.ResponseWriter) {
			w.Header().Set("X-Ratelimit-Remaining", "4799")
			w.WriteHeader(http.StatusForbidden)
			//nolint:errcheck,gosec // test server write
			w.Write([]byte(forbiddenBody))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				tc.respond(w)
			}))
			t.Cleanup(srv.Close)

			c := gh.New("")
			c.HTTP = srv.Client()
			c.Base = srv.URL
			c.Sleep = func(time.Duration) {}

			_, err := c.Attestations("acme", "widget", strings.Repeat("8", 64))

			if got := errors.Is(err, gh.ErrThrottled); got != tc.throttled {
				t.Fatalf("errors.Is(%v, ErrThrottled) = %v, want %v", err, got, tc.throttled)
			}

			if got := errors.Is(err, gh.ErrForbidden); got == tc.throttled {
				t.Fatalf("errors.Is(%v, ErrForbidden) = %v, want %v", err, got, !tc.throttled)
			}
		})
	}
}
