package ghstore_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
	})

	t.Run("server error surfaces as status", func(t *testing.T) {
		t.Parallel()

		c, _ := client(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "secret prose", http.StatusForbidden)
		})

		_, err := c.Bundles("acme/widget", digest)
		if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
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
