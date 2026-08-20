package pkgtime_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/pkgtime"
)

func serve(t *testing.T, status int, body string) *pkgtime.Client {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		if _, err := w.Write([]byte(body)); err != nil {
			t.Errorf("serving the fixture: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	return &pkgtime.Client{GoProxy: srv.URL, HTTP: srv.Client()}
}

func TestPublished(t *testing.T) {
	t.Parallel()

	c := serve(t, http.StatusOK, `{"Version":"v1.2.3","Time":"2026-01-02T03:04:05Z"}`)

	when, ok, err := c.Published("pkg:golang/example.com/mod@v1.2.3")
	if err != nil || !ok {
		t.Fatalf("Published = %v, %v, %v", when, ok, err)
	}

	if got := when.UTC().Format(time.RFC3339); got != "2026-01-02T03:04:05Z" {
		t.Errorf("Published = %s, want the proxy's timestamp", got)
	}
}

// TestAnotherEcosystemIsNotAnError: a package this resolver does not
// serve is an answer. Guessing here would become a level.
func TestAnotherEcosystemIsNotAnError(t *testing.T) {
	t.Parallel()

	c := serve(t, http.StatusOK, `{}`)

	for _, purl := range []string{
		"pkg:npm/left-pad@1.3.0",
		"pkg:cargo/serde@1.0.0",
		"not-a-purl",
		"pkg:golang/example.com/mod", // no version
	} {
		when, ok, err := c.Published(purl)
		if ok || err != nil || !when.IsZero() {
			t.Errorf("Published(%q) = %v, %v, %v — want a clean unknown", purl, when, ok, err)
		}
	}
}

// TestModuleCaseEncoding: the proxy encodes an uppercase letter as "!"
// plus its lowercase form, so two modules differing only in case
// cannot collide on a case-insensitive filesystem.
func TestModuleCaseEncoding(t *testing.T) {
	t.Parallel()

	var asked string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		if _, err := w.Write([]byte(`{"Version":"v1.0.0","Time":"2026-01-02T03:04:05Z"}`)); err != nil {
			t.Errorf("serving the fixture: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	c := &pkgtime.Client{GoProxy: srv.URL, HTTP: srv.Client()}

	if _, _, err := c.Published("pkg:golang/github.com/Masterminds/semver@v1.0.0"); err != nil {
		t.Fatalf("Published = %v", err)
	}

	if !strings.Contains(asked, "!masterminds") {
		t.Errorf("asked for %q, want the proxy's case encoding", asked)
	}
}

func TestPublishedRefusals(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "the proxy has no such version", status: http.StatusNotFound, body: "not found"},
		{name: "the document is not json", status: http.StatusOK, body: "{{{"},
		{name: "the document carries no time", status: http.StatusOK, body: `{"Version":"v1.0.0"}`},
		{name: "the time is unreadable", status: http.StatusOK, body: `{"Version":"v1","Time":"yesterday"}`},
	} {
		c := serve(t, tt.status, tt.body)

		if _, ok, err := c.Published("pkg:golang/example.com/mod@v1.0.0"); err == nil || ok {
			t.Errorf("%s: Published = %v, %v — want a refusal", tt.name, ok, err)
		}
	}
}

// TestNonASCIIModuleRefuses: the proxy's encoding is defined over
// ASCII, so a path outside it has no faithful escaping.
func TestNonASCIIModuleRefuses(t *testing.T) {
	t.Parallel()

	c := serve(t, http.StatusOK, `{}`)

	if _, _, err := c.Published("pkg:golang/example.com/m%C3%B6d@v1.0.0"); err == nil {
		t.Error("a non-ASCII module path did not refuse")
	}
}

// TestNewUsesTheChecksummedProxy pins the production default. The
// package doc rests the whole trust argument on this being the same
// proxy a Go build already fetches through — a client pointed
// somewhere else by default would be a new network dependency nobody
// declared — and the timeout is what stops one unresponsive registry
// from hanging a walk over an entire inventory.
func TestNewUsesTheChecksummedProxy(t *testing.T) {
	t.Parallel()

	c := pkgtime.New()
	if c.GoProxy != "https://proxy.golang.org" {
		t.Errorf("GoProxy = %q, want the public checksummed proxy", c.GoProxy)
	}

	if c.HTTP == nil || c.HTTP.Timeout == 0 {
		t.Error("the default client has no timeout — one slow registry would hang the walk")
	}
}

// TestUnreadableProxyBaseRefuses: GoProxy is operator configuration,
// and a spelling that cannot become a request must be reported as
// such. This is the branch that separates "the operator misconfigured
// the proxy" from "the registry does not serve this package" — the
// second is a clean unknown, and reporting the first that way would
// turn every dependency into unevaluated and the misconfiguration into
// silence.
func TestUnreadableProxyBaseRefuses(t *testing.T) {
	t.Parallel()

	c := &pkgtime.Client{GoProxy: "http://proxy\x7f.invalid", HTTP: http.DefaultClient}

	_, ok, err := c.Published("pkg:golang/example.com/mod@v1.0.0")
	if err == nil || ok {
		t.Fatalf("Published = %v, %v — an unusable proxy base must refuse", ok, err)
	}
}

// TestUnreachableProxyRefuses: the registry being down is not the
// registry saying no. An ingestion interval that could not be measured
// must reach the judge as an error, never as a zero time a requirement
// could read as "published at the epoch".
func TestUnreachableProxyRefuses(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	c := &pkgtime.Client{GoProxy: srv.URL, HTTP: srv.Client()}
	srv.Close()

	when, ok, err := c.Published("pkg:golang/example.com/mod@v1.0.0")
	if err == nil || ok || !when.IsZero() {
		t.Fatalf("Published = %v, %v, %v — an unreachable proxy must refuse", when, ok, err)
	}
}

// TestTruncatedProxyResponseRefuses: a body that stops mid-flight
// decodes to nothing useful, and the read is where that shows. The
// answer must be a refusal rather than the zero time.
func TestTruncatedProxyResponseRefuses(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// More promised than delivered: the server closes the connection
		// short, and the client's read fails rather than completing.
		w.Header().Set("Content-Length", "4096")

		if _, err := w.Write([]byte(`{"Version":"v1.0.0"`)); err != nil {
			return
		}
	}))
	t.Cleanup(srv.Close)

	c := &pkgtime.Client{GoProxy: srv.URL, HTTP: srv.Client()}

	_, ok, err := c.Published("pkg:golang/example.com/mod@v1.0.0")
	if err == nil || ok {
		t.Fatalf("Published = %v, %v — a truncated body must refuse", ok, err)
	}
}

// TestUndecodableModulePathIsAnotherEcosystem: a purl whose module
// carries a broken percent escape names no module this resolver can
// address. That is the same clean unknown as an npm package, not an
// error — the purl came from somebody else's SBOM, and this package
// does not get to fail a walk over a document it merely could not
// read.
func TestUndecodableModulePathIsAnotherEcosystem(t *testing.T) {
	t.Parallel()

	c := serve(t, http.StatusOK, `{}`)

	when, ok, err := c.Published("pkg:golang/example.com/m%zzd@v1.0.0")
	if ok || err != nil || !when.IsZero() {
		t.Fatalf("Published = %v, %v, %v — want a clean unknown", when, ok, err)
	}
}
