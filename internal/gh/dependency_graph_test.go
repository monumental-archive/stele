package gh_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/sbom"
)

// The recorded response is the forge's real export for a repository
// with no manifest (monumental-archive/.github, read 2026-11-17): the
// envelope as served, the SPDX document under its one key.
const recordedGraph = "testdata/dependency-graph-sbom.json"

func graphServer(t *testing.T, body string, status int) *gh.Client {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/widget/dependency-graph/sbom", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)

		if _, err := w.Write([]byte(body)); err != nil {
			t.Error(err)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.New("test-token")
	ownTransport(c, srv)
	c.Base = srv.URL

	return c
}

// TestDependencyGraphSBOM: the recorded export reads as the SPDX
// document it carries and is admissible; every other answer refuses
// by name.
func TestDependencyGraphSBOM(t *testing.T) {
	t.Parallel()

	recorded, err := os.ReadFile(recordedGraph)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("the recorded export", func(t *testing.T) {
		t.Parallel()

		doc, err := graphServer(t, string(recorded), http.StatusOK).DependencyGraphSBOM("acme", "widget")
		if err != nil {
			t.Fatalf("DependencyGraphSBOM = %v", err)
		}

		parsed, err := sbom.AdmitBytes(doc)
		if err != nil {
			t.Fatalf("the recorded export is not admissible: %v", err)
		}

		if parsed.Name != "com.github.monumental-archive/.github" || len(parsed.Packages) == 0 {
			t.Errorf("read %q with %d packages, want the recorded document", parsed.Name, len(parsed.Packages))
		}

		if _, err := jsonx.Value(doc); err != nil {
			t.Errorf("the document is not one JSON value: %v", err)
		}
	})

	tests := []struct {
		name   string
		body   string
		status int
		want   string
	}{
		{"no graph", `{"message": "Not Found"}`, http.StatusNotFound, "gh: acme/widget has no dependency graph to export"},
		{"an envelope with no sbom", `{}`, http.StatusOK, "gh: dependency graph of acme/widget carries no sbom"},
		{"a null sbom", `{"sbom": null}`, http.StatusOK, "gh: dependency graph of acme/widget carries no sbom"},
		{"not JSON", `<html>`, http.StatusOK, "gh: dependency graph of acme/widget: jsonx: decode"},
		{"a refused read", `{"message": "Forbidden"}`, http.StatusForbidden, "403"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := graphServer(t, tt.body, tt.status).DependencyGraphSBOM("acme", "widget")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("DependencyGraphSBOM error = %v\nwant it to carry %q", err, tt.want)
			}
		})
	}
}
