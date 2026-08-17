// The live client against a scripted HTTP server: pagination, the
// archived/fork and draft filters, the raw-vs-envelope contents read,
// the typed absences (404 answer, 403 sentinel), and the audit-posture
// store read where empty is an answer.

package gh_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
)

// writeBody writes a scripted response; a test server that cannot
// write its script is a broken test, so it panics.
func writeBody(w http.ResponseWriter, b []byte) {
	if _, err := w.Write(b); err != nil {
		panic(err)
	}
}

const testHex = "1111111111111111111111111111111111111111111111111111111111111111"

// testServer scripts the REST surface the client reads.
func testServer(t *testing.T) *gh.Client {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/orgs/acme/repos", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			// widget survives; the archive and the fork are filtered.
			writeBody(w, []byte(`[
			  {"name": "widget", "archived": false, "fork": false},
			  {"name": "old", "archived": true, "fork": false},
			  {"name": "copy", "archived": false, "fork": true}]`))

			return
		}

		writeBody(w, []byte(`[]`))
	})

	mux.HandleFunc("/repos/acme/widget/releases", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			writeBody(w, []byte(`[
			  {"tag_name": "v1.0.0", "draft": false, "assets": []},
			  {"tag_name": "v1.1.0-draft", "draft": true, "assets": []}]`))

			return
		}

		writeBody(w, []byte(`[]`))
	})

	mux.HandleFunc("/repos/acme/widget/releases/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`{"tag_name": "v1.0.0", "draft": false,
		  "assets": [{"name": "checksums.txt"}, {"name": "app.spdx.json"}]}`))
	})

	mux.HandleFunc("/acme/widget/releases/download/v1.0.0/checksums.txt",
		func(w http.ResponseWriter, _ *http.Request) {
			writeBody(w, []byte("digest  name\n"))
		})

	mux.HandleFunc("/repos/acme/widget/contents/raw.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte("jobs: {}\n"))
	})

	mux.HandleFunc("/repos/acme/widget/contents/enveloped.yml", func(w http.ResponseWriter, _ *http.Request) {
		// The JSON envelope a proxy that strips the raw accept serves.
		writeBody(w, []byte(`{"content": "am9iczoge30K", "encoding": "base64"}`))
	})

	mux.HandleFunc("/repos/acme/widget/attestations/sha256:"+testHex,
		func(w http.ResponseWriter, _ *http.Request) {
			writeBody(w, []byte(`{"attestations": [{"bundle": {"x": 1}}]}`))
		})

	mux.HandleFunc("/repos/acme/widget/actions/runs", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`{"workflow_runs": [
		  {"conclusion": "failure"}, {"conclusion": "success"}, {"conclusion": "failure"}]}`))
	})

	mux.HandleFunc("/repos/acme/locked/releases", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.New("test-token")
	c.Base = srv.URL
	c.Download = srv.URL

	return c
}

func TestClientReads(t *testing.T) {
	t.Parallel()

	c := testServer(t)

	repos, err := c.Repos("acme")
	if err != nil || len(repos) != 1 || repos[0] != "widget" {
		t.Fatalf("Repos = %v, %v — archived and forks must be filtered", repos, err)
	}

	tags, err := c.ReleaseTags("acme", "widget")
	if err != nil || len(tags) != 1 || tags[0] != "v1.0.0" {
		t.Fatalf("ReleaseTags = %v, %v — drafts must be filtered", tags, err)
	}

	assets, err := c.ReleaseAssets("acme", "widget", "v1.0.0")
	if err != nil || len(assets) != 2 {
		t.Fatalf("ReleaseAssets = %v, %v", assets, err)
	}

	body, err := c.Asset("acme", "widget", "v1.0.0", "checksums.txt")
	if err != nil || string(body) != "digest  name\n" {
		t.Fatalf("Asset = %q, %v", body, err)
	}

	stored, err := c.Attestations("acme", "widget", testHex)
	if err != nil || len(stored) != 1 {
		t.Fatalf("Attestations = %v, %v", stored, err)
	}

	empty, err := c.Attestations("acme", "widget", strings.Repeat("2", 64))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty store = %v, %v — a 404 store is an answer", empty, err)
	}

	failed, err := c.FailedRuns("acme", "widget", "v1.0.0")
	if err != nil || failed != 2 {
		t.Fatalf("FailedRuns = %d, %v", failed, err)
	}
}

func TestClientFileAt(t *testing.T) {
	t.Parallel()

	c := testServer(t)

	raw, ok, err := c.FileAt("acme", "widget", "raw.yml", "v1.0.0")
	if err != nil || !ok || string(raw) != "jobs: {}\n" {
		t.Fatalf("raw FileAt = %q, %v, %v", raw, ok, err)
	}

	env, ok, err := c.FileAt("acme", "widget", "enveloped.yml", "v1.0.0")
	if err != nil || !ok || string(env) != "jobs: {}\n" {
		t.Fatalf("enveloped FileAt = %q, %v, %v — the base64 envelope must decode", env, ok, err)
	}

	if _, ok, err := c.FileAt("acme", "widget", "absent.yml", "v1.0.0"); ok || err != nil {
		t.Fatalf("absent FileAt: ok=%v err=%v — a 404 is an answer", ok, err)
	}
}

func TestClientTypedRefusals(t *testing.T) {
	t.Parallel()

	c := testServer(t)

	// A 403 is the sentinel, never an empty answer.
	if _, err := c.ReleaseTags("acme", "locked"); !isForbidden(err) {
		t.Fatalf("403 error = %v, want ErrForbidden", err)
	}

	// A 404 on a listing endpoint is an error: the population source
	// itself is missing, which is not an empty population.
	if _, err := c.Repos("ghost"); err == nil {
		t.Fatal("a missing org listing did not refuse")
	}

	if _, err := c.ReleaseAssets("acme", "widget", "v9.9.9"); err == nil {
		t.Fatal("a missing release did not refuse")
	}

	if _, err := c.Asset("acme", "widget", "v1.0.0", "absent.bin"); err == nil {
		t.Fatal("a missing asset download did not refuse")
	}
}

func isForbidden(err error) bool {
	return err != nil && strings.Contains(err.Error(), "cannot read this")
}
