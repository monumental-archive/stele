// The two reads the signer-certificate watch makes (stele#387): a run
// by id and a repository's default branch, each against a scripted
// server — the answer decoded, the 404 typed apart, and every other
// refusal and every malformed answer named.

package gh_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
)

// scriptedClient is a live client against one scripted answer, with
// no wall time spent on its ladder.
func scriptedClient(t *testing.T, path string, status int, body string) *gh.Client {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		writeBody(w, []byte(body))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.New("")
	c.Base = srv.URL
	c.Sleep = func(time.Duration) {}
	ownTransport(c, srv)

	return c
}

const runPath = "/repos/acme/widget/actions/runs/43671235061"

const runBody = `{"id": 43671235061, "path": ".github/workflows/self-publish.yml",
  "head_sha": "ebce3d46ea3130824b827cbbe383e16dfc64b17c", "event": "push",
  "html_url": "https://github.com/acme/widget/actions/runs/43671235061",
  "repository": {"full_name": "acme/widget", "id": 1},
  "referenced_workflows": [
    {"path": "acme/.github/.github/workflows/publish.yml@refs/tags/v1",
     "sha": "ebce3d46ea3130824b827cbbe383e16dfc64b17c", "ref": "refs/tags/v1"},
    {"path": "acme/signer/.github/workflows/sign.yml@cffec9441210d46f237099d8785098aacf5b8273",
     "sha": "cffec9441210d46f237099d8785098aacf5b8273"}]}`

// TestWorkflowRun: a run decoded, the 404 an answer, every refusal and
// malformed answer an error naming the read.
func TestWorkflowRun(t *testing.T) {
	t.Parallel()

	full := &gh.WorkflowRun{
		Repository: "acme/widget",
		Path:       ".github/workflows/self-publish.yml",
		HeadSHA:    "ebce3d46ea3130824b827cbbe383e16dfc64b17c",
		HTMLURL:    "https://github.com/acme/widget/actions/runs/43671235061",
		Event:      "push",
		Referenced: []gh.ReferencedWorkflow{
			{Path: "acme/.github/.github/workflows/publish.yml@refs/tags/v1", SHA: "ebce3d46ea3130824b827cbbe383e16dfc64b17c"},
			{
				Path: "acme/signer/.github/workflows/sign.yml@cffec9441210d46f237099d8785098aacf5b8273",
				SHA:  "cffec9441210d46f237099d8785098aacf5b8273",
			},
		},
	}

	bare := *full
	bare.Referenced = nil

	cases := []struct {
		name   string
		status int
		body   string
		run    *gh.WorkflowRun
		found  bool
		want   string
		is     error
	}{
		{name: "a run", status: http.StatusOK, body: runBody, run: full, found: true},
		{
			name: "a run that called nothing, as null", status: http.StatusOK,
			body: strings.Replace(runBody, runBody[strings.Index(runBody, `"referenced_workflows"`):len(runBody)-1],
				`"referenced_workflows": null`, 1),
			run: &bare, found: true,
		},
		{
			name: "a run that called nothing, absent", status: http.StatusOK,
			body: strings.Replace(runBody, ",\n  "+runBody[strings.Index(runBody, `"referenced_workflows"`):len(runBody)-1],
				"", 1),
			run: &bare, found: true,
		},
		{name: "a run the forge never heard of", status: http.StatusNotFound, body: `{"message": "Not Found"}`},
		{
			name: "a run this credential may not read", status: http.StatusForbidden, body: `{}`,
			want: "gh: " + runPath + ": HTTP 403: gh: the credential cannot read this", is: gh.ErrForbidden,
		},
		{
			name: "a forge that keeps failing", status: http.StatusBadGateway, body: `{}`,
			want: "HTTP 502",
		},
		{
			name: "an answer that is not JSON", status: http.StatusOK, body: `<html>`,
			want: "gh: " + runPath + ": jsonx: decode",
		},
		{
			name: "a run without its path", status: http.StatusOK,
			body: strings.Replace(runBody, `"path": ".github/workflows/self-publish.yml",`, ``, 1),
			want: "gh: " + runPath + ": the run lacks path, head_sha, html_url, event or repository.full_name",
		},
		{
			name: "a run without its repository's name", status: http.StatusOK,
			body: strings.Replace(runBody, `"full_name": "acme/widget", `, ``, 1),
			want: "the run lacks path, head_sha, html_url, event or repository.full_name",
		},
		{
			name: "a referenced workflow without its commit", status: http.StatusOK,
			body: strings.Replace(runBody, `,
     "sha": "cffec9441210d46f237099d8785098aacf5b8273"`, ``, 1),
			want: "gh: " + runPath + ": referenced_workflows[1] lacks path or sha",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := scriptedClient(t, runPath, tc.status, tc.body)

			run, found, err := c.WorkflowRun("acme", "widget", 43671235061)

			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("err = %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			case tc.is != nil && !errors.Is(err, tc.is):
				t.Fatalf("err = %v, want it to wrap %v", err, tc.is)
			}

			if found != tc.found || !reflect.DeepEqual(run, tc.run) {
				t.Fatalf("WorkflowRun = %+v, %v; want %+v, %v", run, found, tc.run, tc.found)
			}
		})
	}
}

// TestDefaultBranch: the branch decoded, the 404 an answer, and a
// repository naming none refused rather than read as an empty name.
func TestDefaultBranch(t *testing.T) {
	t.Parallel()

	const repoPath = "/repos/acme/widget"

	cases := []struct {
		name   string
		status int
		body   string
		branch string
		found  bool
		want   string
		is     error
	}{
		{
			name: "a repository", status: http.StatusOK, body: `{"name": "widget", "default_branch": "main"}`,
			branch: "main", found: true,
		},
		{name: "a repository absent or unseen", status: http.StatusNotFound, body: `{}`},
		{
			name: "a repository this credential may not read", status: http.StatusUnauthorized, body: `{}`,
			want: "gh: " + repoPath + ": HTTP 401", is: gh.ErrForbidden,
		},
		{name: "an answer that is not JSON", status: http.StatusOK, body: `[`, want: "gh: " + repoPath + ": jsonx: decode"},
		{
			name: "a repository naming no default branch", status: http.StatusOK, body: `{"name": "widget"}`,
			want: "gh: " + repoPath + ": the repository names no default_branch",
		},
		{
			name: "a repository naming an empty one", status: http.StatusOK, body: `{"default_branch": ""}`,
			want: "the repository names no default_branch",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := scriptedClient(t, repoPath, tc.status, tc.body)

			branch, found, err := c.DefaultBranch("acme", "widget")

			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("err = %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			case tc.is != nil && !errors.Is(err, tc.is):
				t.Fatalf("err = %v, want it to wrap %v", err, tc.is)
			}

			if branch != tc.branch || found != tc.found {
				t.Fatalf("DefaultBranch = %q, %v; want %q, %v", branch, found, tc.branch, tc.found)
			}
		})
	}
}
