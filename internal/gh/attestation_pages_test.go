// The attestation listing read every page deep (stele#439): the store
// answers an object holding an `attestations` array, one page at a
// time, and a subject past one page was read as its first hundred.
// The forge states the next page by a Link header rel="next" — a
// cursor on a different path form, recorded live on the issue — so
// these servers link their pages the same way.

package gh_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
)

const attestedDigest = "1111111111111111111111111111111111111111111111111111111111111111"

// pageOf is one listing page holding the named bundles.
func pageOf(bundles ...string) string {
	parts := make([]string, 0, len(bundles))
	for _, b := range bundles {
		parts = append(parts, `{"bundle": {"id": "`+b+`"}, "repository_id": 1}`)
	}

	return `{"attestations": [` + strings.Join(parts, ", ") + `]}`
}

// pagedStore serves pages by cursor: page i links to page i+1 the way
// the forge does, on the /repositories/<id>/ path form, plus a second
// Link entry the walk must not mistake for the next page.
func pagedStore(t *testing.T, pages []string, status map[int]int) (*gh.Client, *atomic.Int32) {
	t.Helper()

	var calls atomic.Int32

	var srv *httptest.Server

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)

		page := 1
		if after := r.URL.Query().Get("after"); after != "" {
			page = len(after) + 1 // the cursor's length is the page it follows
		}

		if code, ok := status[page]; ok {
			http.Error(w, "server prose", code)

			return
		}

		if page < len(pages) {
			next := srv.URL + "/repositories/9/attestations/sha256:" + attestedDigest + "?per_page=100&after=" +
				strings.Repeat("x", page)
			w.Header().Add("Link", "<"+next+`>; rel="next", <https://docs.github.com/api-versions>; rel="deprecation"`)
		}

		w.Write([]byte(pages[page-1])) //nolint:errcheck,gosec // test server write
	}))
	t.Cleanup(srv.Close)

	return &gh.Client{Base: srv.URL, HTTP: srv.Client(), Sleep: func(time.Duration) {}}, &calls
}

func TestAttestationsFollowsTheNextPage(t *testing.T) {
	t.Parallel()

	c, calls := pagedStore(t, []string{pageOf("a", "b"), pageOf("c"), pageOf("d")}, nil)

	got, err := c.Attestations("acme", "widget", attestedDigest)
	if err != nil {
		t.Fatal(err)
	}

	var ids []string
	for _, b := range got {
		ids = append(ids, string(b))
	}

	want := `{"id": "a"},{"id": "b"},{"id": "c"},{"id": "d"}`
	if strings.Join(ids, ",") != want {
		t.Errorf("bundles = %s, want every page in order: %s", strings.Join(ids, ","), want)
	}

	if calls.Load() != 3 {
		t.Errorf("requests = %d, want one per page", calls.Load())
	}
}

func TestAttestationPagesNamesThePageEachBundleCameFrom(t *testing.T) {
	t.Parallel()

	c, _ := pagedStore(t, []string{pageOf("a"), pageOf("b")}, nil)

	got, found, err := c.AttestationPages("/repos/acme/widget/attestations/sha256:" + attestedDigest)
	if err != nil || !found || len(got) != 2 {
		t.Fatalf("AttestationPages = %v, %t, %v", got, found, err)
	}

	if !strings.HasSuffix(got[0].Page, "/repos/acme/widget/attestations/sha256:"+attestedDigest+"?per_page=100") {
		t.Errorf("page 1 = %s", got[0].Page)
	}

	if !strings.Contains(got[1].Page, "/repositories/9/attestations/") || !strings.Contains(got[1].Page, "after=x") {
		t.Errorf("page 2 = %s, want the forge's own next link, as written", got[1].Page)
	}
}

// An empty store is an answer on the first page; the same 404 on a
// page the forge itself linked to is a partial read, refused.
func TestAttestationsNotFound(t *testing.T) {
	t.Parallel()

	c, _ := pagedStore(t, []string{pageOf("a")}, map[int]int{1: http.StatusNotFound})

	got, err := c.Attestations("acme", "widget", attestedDigest)
	if err != nil || got != nil {
		t.Errorf("Attestations = %v, %v, want an empty answer", got, err)
	}
}

func TestAttestationPagesRefusals(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		client func(t *testing.T) *gh.Client
		path   string
		want   string
	}{
		{
			name: "a next link off the API's origin",
			client: func(t *testing.T) *gh.Client {
				t.Helper()

				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Link", `<https://elsewhere.example/attestations?after=1>; rel="next"`)
					w.Write([]byte(pageOf("a"))) //nolint:errcheck,gosec // test server write
				}))
				t.Cleanup(srv.Close)

				return &gh.Client{Base: srv.URL, HTTP: srv.Client(), Sleep: func(time.Duration) {}}
			},
			want: "page 1 links its next page off the API origin",
		},
		{
			name: "a second page that answers 500",
			client: func(t *testing.T) *gh.Client {
				t.Helper()

				c, _ := pagedStore(t, []string{pageOf("a"), pageOf("b")}, map[int]int{2: http.StatusInternalServerError})

				return c
			},
			want: "HTTP 500",
		},
		{
			name: "a second page that answers 404",
			client: func(t *testing.T) *gh.Client {
				t.Helper()

				c, _ := pagedStore(t, []string{pageOf("a"), pageOf("b")}, map[int]int{2: http.StatusNotFound})

				return c
			},
			want: "page 2, linked by page 1, answered not found — a partial listing is not the listing",
		},
		{
			name: "a circular link",
			client: func(t *testing.T) *gh.Client {
				t.Helper()

				var srv *httptest.Server

				srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Link", "<"+srv.URL+r.URL.Path+`?per_page=100&after=again>; rel="next"`)
					w.Write([]byte(pageOf("a"))) //nolint:errcheck,gosec // test server write
				}))
				t.Cleanup(srv.Close)

				return &gh.Client{Base: srv.URL, HTTP: srv.Client(), Sleep: func(time.Duration) {}}
			},
			want: "pagination did not converge in 50 pages",
		},
		{
			name: "a page that is not the listing's envelope",
			client: func(t *testing.T) *gh.Client {
				t.Helper()

				c, _ := pagedStore(t, []string{pageOf("a"), `["an array"]`}, nil)

				return c
			},
			want: "page 2: jsonx: decode",
		},
		{
			name: "a path carrying its own query",
			client: func(*testing.T) *gh.Client {
				return &gh.Client{Base: "http://127.0.0.1:1"}
			},
			path: "/repos/acme/widget/attestations/sha256:" + attestedDigest + "?per_page=10",
			want: "the path carries its own query; the walk owns the query string",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := tc.path
			if path == "" {
				path = "/repos/acme/widget/attestations/sha256:" + attestedDigest
			}

			got, _, err := tc.client(t).AttestationPages(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("AttestationPages = %v, want %q", err, tc.want)
			}

			// A partial store is never returned as the store.
			if got != nil {
				t.Errorf("a refused read returned %d bundle(s)", len(got))
			}
		})
	}
}

// Attempts bounds the transient ladder: one attempt hands a 500 back
// at once, for a caller whose own ladder does the waiting.
func TestAttemptsBoundsTheTransientLadder(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		attempts int
		want     int32
	}{{1, 1}, {0, 4}} {
		c, calls := pagedStore(t, []string{pageOf("a")}, map[int]int{1: http.StatusInternalServerError})
		c.Attempts = tc.attempts

		if _, err := c.Attestations("acme", "widget", attestedDigest); err == nil {
			t.Fatal("a 500 read as a store")
		}

		if calls.Load() != tc.want {
			t.Errorf("Attempts %d: requests = %d, want %d", tc.attempts, calls.Load(), tc.want)
		}
	}
}
