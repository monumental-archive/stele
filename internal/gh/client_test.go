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
	"time"

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
		  {"name": "publish", "conclusion": "failure"},
		  {"name": "ci", "conclusion": "success"},
		  {"name": "scorecard", "conclusion": "failure"}]}`))
	})

	mux.HandleFunc("/repos/acme/locked/releases", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	mux.HandleFunc("/orgs/acme/packages/container/widget/versions", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "1" {
			writeBody(w, []byte(`[]`))

			return
		}

		// A tag-named version and a stale digest come first: only the
		// digest carrying the rolling tag counts.
		writeBody(w, []byte(`[
		  {"name": "latest", "metadata": {"container": {"tags": ["latest"]}}},
		  {"name": "sha256:`+strings.Repeat("b", 64)+`", "metadata": {"container": {"tags": ["v1"]}}},
		  {"name": "sha256:`+testHex+`", "metadata": {"container": {"tags": ["latest", "v2"]}}}]`))
	})

	mux.HandleFunc("/repos/acme/widget/contents/.github/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`[{"name": "ci.yml", "type": "file"}, {"name": "nested", "type": "dir"}]`))
	})

	mux.HandleFunc("/repos/acme/widget/contents/.github/workflows/ci.yml",
		func(w http.ResponseWriter, _ *http.Request) {
			writeBody(w, []byte("jobs: {}\n"))
		})

	mux.HandleFunc("/repos/acme/widget/git/ref/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		// An annotated tag: the ref names the tag OBJECT, which must be
		// dereferenced to the commit — the annotated-tag pin trap.
		writeBody(w, []byte(`{"object": {"type": "tag", "sha": "tagobj"}}`))
	})

	mux.HandleFunc("/repos/acme/widget/git/tags/tagobj", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`{"object": {"type": "commit", "sha": "`+strings.Repeat("c", 40)+`"}}`))
	})

	mux.HandleFunc("/repos/acme/widget/git/ref/tags/v0.9.0", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`{"object": {"type": "commit", "sha": "`+strings.Repeat("d", 40)+`"}}`))
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
	if err != nil || len(failed) != 2 || failed[0] != "publish" {
		t.Fatalf("FailedRuns = %v, %v — names, and only the failures", failed, err)
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

// flakyServer answers with `fails` transient statuses before serving
// the real body, counting attempts. Returns the client and a pointer to the attempt count.
//
//nolint:gocritic // unnamedResult: client, attempt counter
func flakyServer(t *testing.T, status, fails int) (*gh.Client, *int) {
	t.Helper()

	seen := 0
	mux := http.NewServeMux()

	mux.HandleFunc("/orgs/acme/repos", func(w http.ResponseWriter, r *http.Request) {
		seen++
		if seen <= fails {
			w.WriteHeader(status)

			return
		}

		if r.URL.Query().Get("page") != "1" {
			writeBody(w, []byte(`[]`))

			return
		}

		writeBody(w, []byte(`[{"name": "widget", "archived": false, "fork": false}]`))
	})

	mux.HandleFunc("/acme/widget/releases/download/v1.0.0/app.bin", func(w http.ResponseWriter, _ *http.Request) {
		seen++
		if seen <= fails {
			w.WriteHeader(status)

			return
		}

		writeBody(w, []byte("asset bytes"))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.New("test-token")
	c.Base = srv.URL
	c.Download = srv.URL
	c.Sleep = func(time.Duration) {} // no wall time in tests

	return c, &seen
}

// TestTransientRetry pins the ladder: a status that says nothing
// about the subject (5xx, 429) is retried; the walk survives the
// kind of outage that killed the first live run.
func TestTransientRetry(t *testing.T) {
	t.Parallel()

	for _, status := range []int{
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusTooManyRequests,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()

			c, seen := flakyServer(t, status, 2)

			repos, err := c.Repos("acme")
			if err != nil || len(repos) != 1 {
				t.Fatalf("Repos = %v, %v — a transient status must not end the walk", repos, err)
			}

			// Two transient attempts and the answering page: that page
			// is short, which ends the walk (#154) — nothing asks for
			// the empty page after it.
			if *seen != 3 {
				t.Fatalf("attempts = %d, want 3 (two transient, one short answering page)", *seen)
			}
		})
	}
}

// TestTransientExhausted pins the bound: a host that never recovers
// ends the walk with a named error rather than hanging forever.
func TestTransientExhausted(t *testing.T) {
	t.Parallel()

	c, seen := flakyServer(t, http.StatusServiceUnavailable, 99)

	if _, err := c.Repos("acme"); err == nil || !strings.Contains(err.Error(), "after 4 attempts") {
		t.Fatalf("err = %v, want the bounded refusal", err)
	}

	if *seen != 4 {
		t.Fatalf("attempts = %d, want the 4-attempt bound", *seen)
	}
}

// TestAnswersAreNotRetried pins the other half of the rule: a 404 and
// a 403 are FACTS about the subject and must be returned at once —
// retrying an answer away turns a real absence into a timeout and
// hides a narrowed credential behind noise.
func TestAnswersAreNotRetried(t *testing.T) {
	t.Parallel()

	seen := 0
	mux := http.NewServeMux()

	mux.HandleFunc("/repos/acme/widget/contents/gone.yml", func(w http.ResponseWriter, _ *http.Request) {
		seen++
		w.WriteHeader(http.StatusNotFound)
	})

	mux.HandleFunc("/repos/acme/locked/releases", func(w http.ResponseWriter, _ *http.Request) {
		seen++
		w.WriteHeader(http.StatusForbidden)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.New("")
	c.Base = srv.URL
	c.Sleep = func(time.Duration) {}

	if _, ok, err := c.FileAt("acme", "widget", "gone.yml", "v1"); ok || err != nil {
		t.Fatalf("404: ok=%v err=%v, want the recorded absence", ok, err)
	}

	if seen != 1 {
		t.Fatalf("404 took %d attempts — an answer must not be retried", seen)
	}

	seen = 0

	if _, err := c.ReleaseTags("acme", "locked"); !isForbidden(err) {
		t.Fatalf("403 err = %v, want ErrForbidden", err)
	}

	if seen != 1 {
		t.Fatalf("403 took %d attempts — an answer must not be retried", seen)
	}
}

// TestAssetTransientRetry pins the same ladder on the download host,
// where the outage's 429s actually landed.
func TestAssetTransientRetry(t *testing.T) {
	t.Parallel()

	c, seen := flakyServer(t, http.StatusTooManyRequests, 1)

	body, err := c.Asset("acme", "widget", "v1.0.0", "app.bin")
	if err != nil || string(body) != "asset bytes" {
		t.Fatalf("Asset = %q, %v", body, err)
	}

	if *seen != 2 {
		t.Fatalf("attempts = %d, want 2", *seen)
	}
}

// TestPackageAndWorkflowReads pins the two reads the store halves
// need: only a DIGEST version carrying the rolling tag counts (a
// tag-named version is not a digest), and workflow listing skips
// directories.
func TestPackageAndWorkflowReads(t *testing.T) {
	t.Parallel()

	c := testServer(t)

	digest, err := c.PackageVersionDigest("acme", "widget", "latest")
	if err != nil || digest != "sha256:"+testHex {
		t.Fatalf("PackageVersionDigest = %q, %v — want the digest carrying the tag", digest, err)
	}

	absent, err := c.PackageVersionDigest("acme", "widget", "no-such-tag")
	if err != nil || absent != "" {
		t.Fatalf("absent tag = %q, %v — a rolling tag pointing at nothing is an answer", absent, err)
	}

	contents, err := c.WorkflowContents("acme", "widget")
	if err != nil || len(contents) != 1 || string(contents[0]) != "jobs: {}\n" {
		t.Fatalf("WorkflowContents = %q, %v — directories must be skipped", contents, err)
	}

	none, err := c.WorkflowContents("acme", "ghost")
	if err != nil || none != nil {
		t.Fatalf("missing workflows dir = %v, %v — absence is an answer", none, err)
	}
}

func TestClientTagCommit(t *testing.T) {
	t.Parallel()

	c := testServer(t)

	annotated, err := c.TagCommit("acme", "widget", "v1.0.0")
	if err != nil || annotated != strings.Repeat("c", 40) {
		t.Fatalf("TagCommit annotated = %q, %v — the tag object must be dereferenced to its commit", annotated, err)
	}

	light, err := c.TagCommit("acme", "widget", "v0.9.0")
	if err != nil || light != strings.Repeat("d", 40) {
		t.Fatalf("TagCommit lightweight = %q, %v", light, err)
	}

	if _, err := c.TagCommit("acme", "widget", "v9.9.9"); err == nil {
		t.Fatal("TagCommit invented a commit for a tag that does not exist")
	}
}
