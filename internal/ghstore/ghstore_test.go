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
