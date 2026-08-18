// The repository-metadata reads (stele#40).
//
// The rows that matter are the forge's several ways of saying "I
// found no licence". Detection is a heuristic reading of one file, so
// it answers NOASSERTION, NONE or OTHER as readily as it answers an
// id — and every one of those must arrive as ABSENT rather than
// become the string a release publishes as its licence.

package gh_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
)

// metaServer scripts the metadata endpoints, keyed by the ref so one
// server can answer several rows.
func metaServer(t *testing.T, byRef map[string]string, description string) *gh.Client {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/repos/acme/widget/license", func(w http.ResponseWriter, r *http.Request) {
		body, ok := byRef[r.URL.Query().Get("ref")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		writeBody(w, []byte(body))
	})

	mux.HandleFunc("/repos/acme/widget", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(description))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &gh.Client{Base: srv.URL, Download: srv.URL, HTTP: srv.Client()}
}

func TestLicenceDetection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string
		ok   bool
	}{
		{"a detected id", `{"license": {"spdx_id": "Apache-2.0"}}`, "Apache-2.0", true},
		{"NOASSERTION is not a licence", `{"license": {"spdx_id": "NOASSERTION"}}`, "", false},
		{"NONE is not a licence", `{"license": {"spdx_id": "NONE"}}`, "", false},
		{"OTHER is not a licence", `{"license": {"spdx_id": "OTHER"}}`, "", false},
		{"an empty id is not a licence", `{"license": {"spdx_id": ""}}`, "", false},
		{"a null licence object", `{"license": null}`, "", false},
		{"a response with no licence key", `{}`, "", false},
		{"a null spdx_id", `{"license": {"spdx_id": null}}`, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := metaServer(t, map[string]string{"deadbeef": tt.body}, `{}`)

			id, ok, err := client.Licence("acme", "widget", "deadbeef")
			if err != nil {
				t.Fatalf("Licence = %v", err)
			}

			if id != tt.want || ok != tt.ok {
				t.Fatalf("Licence = %q, %v; want %q, %v", id, ok, tt.want, tt.ok)
			}
		})
	}
}

// A repository the credential cannot see is absent, not an error: the
// caller decides whether an underivable licence is fatal.
func TestLicenceAbsentRef(t *testing.T) {
	t.Parallel()

	client := metaServer(t, map[string]string{"known": `{"license": {"spdx_id": "MIT"}}`}, `{}`)

	if _, ok, err := client.Licence("acme", "widget", "unknown"); err != nil || ok {
		t.Fatalf("Licence for an unknown ref = %v, %v; want absent and no error", ok, err)
	}
}

// A body that is not the shape the endpoint documents is an error,
// never an empty answer — the CLI this replaces printed the error
// body to stdout, so a failed request could be read as a licence.
func TestLicenceRefusesGarbage(t *testing.T) {
	t.Parallel()

	client := metaServer(t, map[string]string{"x": `not json at all`}, `{}`)

	if _, _, err := client.Licence("acme", "widget", "x"); err == nil {
		t.Fatal("Licence accepted a body that is not JSON")
	}
}

func TestDescription(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string
	}{
		{"a description", `{"description": "a widget"}`, "a widget"},
		{"an explicit null", `{"description": null}`, ""},
		{"no key at all", `{}`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := metaServer(t, map[string]string{}, tt.body)

			got, err := client.Description("acme", "widget")
			if err != nil {
				t.Fatalf("Description = %v", err)
			}

			if got != tt.want {
				t.Fatalf("Description = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDescriptionRefusesGarbage(t *testing.T) {
	t.Parallel()

	client := metaServer(t, map[string]string{}, `{`)

	if _, err := client.Description("acme", "widget"); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("Description = %v, want a decode failure", err)
	}
}
