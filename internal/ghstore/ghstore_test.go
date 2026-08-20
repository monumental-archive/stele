package ghstore_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/ghstore"
)

const digest = "1111111111111111111111111111111111111111111111111111111111111111"

func client(t *testing.T, handler http.HandlerFunc) (*ghstore.Client, *atomic.Int32) {
	t.Helper()

	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)

	return &ghstore.Client{
		Base:  srv.URL,
		Token: "tok",
		HTTP:  srv.Client(),
		Sleep: func(time.Duration) {},
	}, &calls
}

func TestBundles(t *testing.T) {
	t.Parallel()

	c, calls := client(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/repos/acme/widget/attestations/sha256:"+digest {
			t.Errorf("path = %q", got)
		}

		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("auth = %q", got)
		}

		// The envelope carries fields this tool does not model —
		// lenient by design for a foreign schema.
		//nolint:errcheck,gosec // test server write
		w.Write([]byte(`{"attestations": [{"bundle": {"a": 1}, "bundle_url": "x"}, {"bundle": {"b": 2}}]}`))
	})

	got, err := c.Bundles("acme/widget", digest)
	if err != nil {
		t.Fatalf("Bundles = %v", err)
	}

	if len(got) != 2 || string(got[0].Bundle) != `{"a": 1}` {
		t.Errorf("Bundles = %v", got)
	}

	if got[0].URI == "" || !strings.Contains(got[0].URI, "sha256:") {
		t.Errorf("URI = %q, want the fetch address", got[0].URI)
	}

	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1", calls.Load())
	}
}

func TestBundlesRetries(t *testing.T) {
	t.Parallel()

	t.Run("404 then success", func(t *testing.T) {
		t.Parallel()

		// A dedicated server whose first answer is the propagation 404.
		var n atomic.Int32

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if n.Add(1) == 1 {
				http.Error(w, "not yet", http.StatusNotFound)

				return
			}

			w.Write([]byte(`{"attestations": [{"bundle": {}}]}`)) //nolint:errcheck,gosec // test server write
		}))
		t.Cleanup(srv.Close)

		cl := &ghstore.Client{Base: srv.URL, HTTP: srv.Client(), Sleep: func(time.Duration) {}}

		got, err := cl.Bundles("acme/widget", digest)
		if err != nil || len(got) != 1 {
			t.Errorf("Bundles = %v, %v — want the retry to succeed", got, err)
		}

		if n.Load() != 2 {
			t.Errorf("calls = %d, want 2", n.Load())
		}
	})

	t.Run("empty store is an error after all attempts", func(t *testing.T) {
		t.Parallel()

		c, calls := client(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{"attestations": []}`)) //nolint:errcheck,gosec // test server write
		})

		_, err := c.Bundles("acme/widget", digest)
		if err == nil || !strings.Contains(err.Error(), "no attestations") {
			t.Errorf("Bundles = %v, want the empty-store refusal", err)
		}

		if calls.Load() != 5 {
			t.Errorf("calls = %d, want all attempts", calls.Load())
		}

		// The other direction of stele#216: a caller branching on the
		// credential must not catch the empty store here.
		if errors.Is(err, gh.ErrForbidden) {
			t.Error("an empty store typed as a refusal — that is the other fact")
		}
	})

	t.Run("server error surfaces as status", func(t *testing.T) {
		t.Parallel()

		c, _ := client(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "secret prose", http.StatusInternalServerError)
		})

		_, err := c.Bundles("acme/widget", digest)
		if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
			t.Errorf("Bundles = %v, want the status", err)
		}

		if err != nil && strings.Contains(err.Error(), "secret prose") {
			t.Error("the server-controlled body leaked into the error")
		}
	})

	t.Run("garbage envelope is refused", func(t *testing.T) {
		t.Parallel()

		c, _ := client(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`not json`)) //nolint:errcheck,gosec // test server write
		})

		_, err := c.Bundles("acme/widget", digest)
		if err == nil || !strings.Contains(err.Error(), "decode envelope") {
			t.Errorf("Bundles = %v, want the decode refusal", err)
		}
	})
}

// TestPropagationSignalIsUnchanged holds the boundary stele#216 drew
// from the other side: the 404 that a just-published attestation
// answers with is the reason the ladder exists, so it still rides every
// attempt and is still typed as no refusal at all.
func TestPropagationSignalIsUnchanged(t *testing.T) {
	t.Parallel()

	c, calls := client(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not yet", http.StatusNotFound)
	})

	_, err := c.Bundles("acme/widget", digest)
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("Bundles = %v, want the propagation refusal", err)
	}

	if calls.Load() != 5 {
		t.Errorf("calls = %d, want all attempts — 404 is the propagation signal", calls.Load())
	}

	if errors.Is(err, gh.ErrForbidden) {
		t.Error("a 404 typed as a refusal — the propagation signal is not one")
	}
}

// TestBundlesFailFast pins the auditor stance (#19 item 4): a
// one-attempt budget makes exactly one call — a wrong digest refuses
// now instead of riding the propagation ladder.
func TestBundlesFailFast(t *testing.T) {
	t.Parallel()

	c, calls := client(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	c.Attempts = 1

	if _, err := c.Bundles("acme/widget", digest); err == nil {
		t.Fatal("an empty store did not refuse")
	}

	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want exactly 1 — fail fast means one look", calls.Load())
	}
}

// TestNewDefaults pins the constructor's stance: the public API, the
// documented retry budget, a bounded HTTP client and a real clock —
// a caller that takes the default gets the propagation ladder, not a
// zero-valued client that would panic on the first Sleep.
func TestNewDefaults(t *testing.T) {
	t.Parallel()

	c := ghstore.New("tok")

	if c.Base != "https://api.github.com" {
		t.Errorf("Base = %q, want the public API", c.Base)
	}

	if c.Token != "tok" {
		t.Errorf("Token = %q, want the one passed in", c.Token)
	}

	if c.Attempts != ghstore.DefaultAttempts {
		t.Errorf("Attempts = %d, want DefaultAttempts (%d)", c.Attempts, ghstore.DefaultAttempts)
	}

	if c.HTTP == nil || c.HTTP.Timeout == 0 {
		t.Errorf("HTTP = %+v, want a client with a timeout", c.HTTP)
	}

	if c.Sleep == nil {
		t.Fatal("Sleep is nil — the retry ladder would panic on its first backoff")
	}
}

// TestBundlesTransportFailures covers the three ways one fetch can
// fail before a status code exists: the URL never becomes a request,
// the connection never happens, and the body never finishes. Each is
// a fault, and each must surface as a refusal rather than an empty
// bundle list read as "nothing attested".
func TestBundlesTransportFailures(t *testing.T) {
	t.Parallel()

	t.Run("an unbuildable URL is refused", func(t *testing.T) {
		t.Parallel()

		// DEL is a control character net/url refuses, so the request
		// never exists to be sent.
		c := &ghstore.Client{Base: "http://example\x7f.invalid", HTTP: http.DefaultClient, Sleep: func(time.Duration) {}}

		_, err := c.Bundles("acme/widget", digest)
		if err == nil || !strings.Contains(err.Error(), "build request") {
			t.Fatalf("Bundles = %v, want the build-request refusal", err)
		}
	})

	t.Run("a dead endpoint is refused", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		base, cl := srv.URL, srv.Client()
		srv.Close() // nothing listens now: the dial fails

		c := &ghstore.Client{Base: base, HTTP: cl, Sleep: func(time.Duration) {}}

		_, err := c.Bundles("acme/widget", digest)
		if err == nil || !strings.Contains(err.Error(), "fetch") {
			t.Fatalf("Bundles = %v, want the fetch refusal", err)
		}
	})

	t.Run("a truncated body is refused", func(t *testing.T) {
		t.Parallel()

		// A response that promises more bytes than it delivers: the
		// read fails mid-envelope, which must never be read as an
		// empty attestation list.
		c, _ := client(t, func(w http.ResponseWriter, _ *http.Request) {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Error("the test server's ResponseWriter cannot be hijacked")

				return
			}

			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)

				return
			}
			defer conn.Close() //nolint:errcheck // the test server's socket

			//nolint:errcheck,gosec // test server write
			conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n{\"attestations\":"))
		})

		_, err := c.Bundles("acme/widget", digest)
		if err == nil || !strings.Contains(err.Error(), "read") {
			t.Fatalf("Bundles = %v, want the read refusal", err)
		}
	})
}

// The scripted rate-limit refusals, one per marker the classifier
// reads, plus the refusal that carries none of them.
const secondaryLimitBody = `{"message":"You have exceeded a secondary rate limit. ` +
	`Please wait a few minutes before you try again.",` +
	`"documentation_url":"https://docs.github.com/rest/overview/` +
	`rate-limits-for-the-rest-api#about-secondary-rate-limits"}`

func retryAfter403(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(http.StatusForbidden)
}

func remainingZero403(w http.ResponseWriter) {
	w.Header().Set("X-Ratelimit-Remaining", "0")
	w.WriteHeader(http.StatusForbidden)
}

func secondaryLimit403(w http.ResponseWriter) {
	w.WriteHeader(http.StatusForbidden)
	//nolint:errcheck,gosec // test server write
	w.Write([]byte(secondaryLimitBody))
}

func bare403(w http.ResponseWriter) {
	http.Error(w, "Resource not accessible by personal access token", http.StatusForbidden)
}

func unauthorized401(w http.ResponseWriter) {
	http.Error(w, "Bad credentials", http.StatusUnauthorized)
}

// throttleProbe is the store's ladder under a scripted rate limit: the
// reads it made, and the pauses it took between them.
type throttleProbe struct {
	client *ghstore.Client
	calls  atomic.Int32
	waits  []time.Duration
}

// newThrottleProbe refuses the first `refuse` reads, then serves a
// real bundle list.
func newThrottleProbe(t *testing.T, refuse int32, respond func(http.ResponseWriter)) *throttleProbe {
	t.Helper()

	p := &throttleProbe{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if p.calls.Add(1) <= refuse {
			respond(w)

			return
		}

		w.Write([]byte(`{"attestations": [{"bundle": {}}]}`)) //nolint:errcheck,gosec // test server write
	}))
	t.Cleanup(srv.Close)

	p.client = &ghstore.Client{
		Base: srv.URL,
		HTTP: srv.Client(),
		// The clock is the assertion: honouring the host's own number
		// and ignoring it differ nowhere else.
		Sleep: func(d time.Duration) { p.waits = append(p.waits, d) },
	}

	return p
}

// TestThrottleIsNotAFactAboutTheDigest pins stele#209 on the verify
// engine's store. This leg reads the same forge over the same statuses
// as the assert walk, so it asks the same classifier — and it is the
// leg where the confusion costs most, because "nothing is stored for
// this digest" is its documented finding. A throttle reported through
// that sentence would say the evidence is absent when the run simply
// never got to look.
func TestThrottleIsNotAFactAboutTheDigest(t *testing.T) {
	t.Parallel()

	// The ladder's own backoff is attempt × 5s, so the pauses below are
	// the ladder's when the host named no wait, and the host's when it
	// did.
	ladder := []time.Duration{10 * time.Second, 15 * time.Second, 20 * time.Second, 25 * time.Second}

	for _, tc := range []struct {
		name    string
		respond func(http.ResponseWriter)
		// refuse is how many reads are refused before a real answer;
		// more than the budget exhausts it.
		refuse int32
		calls  int32
		waits  []time.Duration
		// found is whether the store answers at all.
		found bool
		// throttled is whether the refusal types as the host's, not the
		// digest's; forbidden whether it types as the credential's;
		// says and never are fragments it must and must not carry.
		throttled   bool
		forbidden   bool
		says, never string
	}{
		{
			name:    "a named wait is honoured over the ladder's own backoff",
			respond: retryAfter403,
			refuse:  2,
			calls:   3,
			waits:   []time.Duration{60 * time.Second, 60 * time.Second},
			found:   true,
		},
		{
			name:    "a spent budget is retried on the ladder's own backoff",
			respond: remainingZero403,
			refuse:  2,
			calls:   3,
			waits:   ladder[:2],
			found:   true,
		},
		{
			name:      "a throttle that never clears names the throttle, never the evidence",
			respond:   secondaryLimit403,
			refuse:    99,
			calls:     5,
			waits:     ladder,
			throttled: true,
			says:      "throttled this walk",
			never:     "no attestations",
		},
		{
			// stele#216: a bare 403 is the credential's, typed as neither
			// the host's pace nor an empty store — and it leaves the
			// propagation ladder at once, because no wait turns a refused
			// credential into a permitted one.
			name:      "a bare 403 is the credential's, refused after one attempt",
			respond:   bare403,
			refuse:    99,
			calls:     1,
			forbidden: true,
			says:      "HTTP 403",
			never:     "throttled this walk",
		},
		{
			name:      "a 401 is the same fact and the same refusal",
			respond:   unauthorized401,
			refuse:    99,
			calls:     1,
			forbidden: true,
			says:      "HTTP 401",
			never:     "no attestations",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newThrottleProbe(t, tc.refuse, tc.respond)

			got, err := p.client.Bundles("acme/widget", digest)

			switch {
			case tc.found && (err != nil || len(got) != 1):
				t.Fatalf("Bundles = %v, %v — a throttled read must not end the fetch", got, err)
			case !tc.found && err == nil:
				t.Fatal("Bundles answered where the forge refused")
			}

			if p.calls.Load() != tc.calls {
				t.Fatalf("calls = %d, want %d", p.calls.Load(), tc.calls)
			}

			if !slices.Equal(p.waits, tc.waits) {
				t.Fatalf("waits = %v, want %v", p.waits, tc.waits)
			}

			if tc.found {
				return
			}

			if is := errors.Is(err, gh.ErrThrottled); is != tc.throttled {
				t.Fatalf("errors.Is(%v, ErrThrottled) = %v, want %v", err, is, tc.throttled)
			}

			if is := errors.Is(err, gh.ErrForbidden); is != tc.forbidden {
				t.Fatalf("errors.Is(%v, ErrForbidden) = %v, want %v", err, is, tc.forbidden)
			}

			if !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("err = %v, want it to say %q", err, tc.says)
			}

			if strings.Contains(err.Error(), tc.never) {
				t.Fatalf("err = %v, must not say %q — that is the other refusal", err, tc.never)
			}
		})
	}
}
