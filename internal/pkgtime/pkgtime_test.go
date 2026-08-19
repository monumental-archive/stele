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
