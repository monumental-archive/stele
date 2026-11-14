// The pagination contract, tested where it lives (#106).
//
// paged is unexported and the guard is about the PATH it is handed,
// so this cannot be reached from outside the package: every exported
// caller escapes its path segments, which is why a smuggled query
// never gets that far through them. The contract still has to hold
// for the next call site somebody writes.

package gh

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestPagedRefusesAPathCarryingItsOwnQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			"a pre-formatted filter is refused rather than mangled",
			"/repos/acme/widget/rulesets?includes_parents=true",
			"carries its own query",
		},
		{
			"even a bare question mark, since the forge parses the whole thing as one name",
			"/orgs/acme/repos?",
			"carries its own query",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := &Client{Base: "http://127.0.0.1:1"}

			_, err := c.paged(tt.path)
			if err == nil {
				t.Fatal("paged = nil error, want the contract refusal")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("paged = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// The refusal fires BEFORE any request: a mangled listing must not
// reach the network at all, or a caller learns about it as a
// confusing 404 rather than as its own mistake.
func TestPagedRefusesBeforeRequesting(t *testing.T) {
	t.Parallel()

	// Base points at a closed port, so any request would error with a
	// connection failure instead of the contract message.
	c := &Client{Base: "http://127.0.0.1:1"}

	_, err := c.paged("/repos/acme/widget/rulesets?includes_parents=true")
	if err == nil || !strings.Contains(err.Error(), "carries its own query") {
		t.Fatalf("paged = %v, want the contract refusal rather than a transport error", err)
	}
}

// The positive half of the contract: a filtered call builds exactly
// one query string, pagination and filter together. A guard that only
// refuses proves the broken form is unspellable; this proves the
// working form is what actually reaches the forge.
func TestPagedBuildsOneQueryStringWithFilters(t *testing.T) {
	t.Parallel()

	var seen []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RequestURI())

		if _, err := w.Write([]byte(`[]`)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)

	c := &Client{Base: srv.URL, HTTP: srv.Client()}

	if _, err := c.paged("/repos/acme/widget/rulesets", "includes_parents=true"); err != nil {
		t.Fatalf("paged = %v", err)
	}

	if len(seen) != 1 {
		t.Fatalf("requested %d times, want 1 (the empty page ends the walk)", len(seen))
	}

	got := seen[0]

	if n := strings.Count(got, "?"); n != 1 {
		t.Fatalf("%s carries %d question marks, want exactly 1", got, n)
	}

	for _, want := range []string{"per_page=100", "page=1", "includes_parents=true"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%s lost %q", got, want)
		}
	}

	// The filter must be a sibling of the pagination parameters, not a
	// suffix of one of them.
	if !strings.Contains(got, "&includes_parents=true") {
		t.Fatalf("%s does not join the filter with &", got)
	}
}

// Several filters compose, each its own parameter.
func TestPagedJoinsEveryFilter(t *testing.T) {
	t.Parallel()

	var seen string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.RequestURI()

		if _, err := w.Write([]byte(`[]`)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)

	c := &Client{Base: srv.URL, HTTP: srv.Client()}

	if _, err := c.paged("/x", "a=1", "b=2"); err != nil {
		t.Fatalf("paged = %v", err)
	}

	if strings.Count(seen, "?") != 1 || !strings.Contains(seen, "&a=1") || !strings.Contains(seen, "&b=2") {
		t.Fatalf("%s does not carry both filters as siblings of one query", seen)
	}
}

// answer is one scripted response: a body and the Link header's next
// target, where "{self}" and "{page N}" are filled in against the
// request.
type answer struct {
	body string
	link string
}

// linkServer serves answer for every request, writing the Link header
// GitHub's way, and counts the requests.
func linkServer(t *testing.T, script func(*http.Request) answer) *linkFake {
	t.Helper()

	f := &linkFake{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reqs++
		f.mu.Unlock()

		a := script(r)

		if a.link != "" {
			target := a.link

			switch {
			case target == "{self}":
				target = "http://" + r.Host + r.URL.RequestURI()
			case strings.HasPrefix(target, "{page "):
				target = "http://" + r.Host + r.URL.Path + "?per_page=100&page=" +
					strings.TrimSuffix(strings.TrimPrefix(target, "{page "), "}")
			}

			w.Header().Set("Link", "<"+target+`>; rel="next", <http://`+r.Host+`/last>; rel="last"`)
		}

		if _, werr := w.Write([]byte(a.body)); werr != nil {
			t.Error(werr)
		}
	}))
	t.Cleanup(srv.Close)

	f.srv = srv

	return f
}

// linkFake is a running linkServer and its request count.
type linkFake struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs int
}

func (f *linkFake) requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.reqs
}

// joinPages renders a walk's pages for one comparison.
func joinPages(pages [][]byte) string {
	got := make([]string, len(pages))
	for i, p := range pages {
		got[i] = string(p)
	}

	return strings.Join(got, "|")
}

// The termination contract (#322): the walk follows the forge's own
// pagination statement, the Link header, and never infers the end from
// content. The rows are the issue's measurements: an endpoint that
// ignores page and answers the same full array with no Link (the canon
// with 124 tags, `git/matching-refs/tags/`), a three-page walk by Link,
// and a Link that names itself forever.
func TestPagedFollowsTheLinkHeader(t *testing.T) {
	t.Parallel()

	// entries renders an array of n objects, each carrying its index so
	// the order of the returned pages is visible.
	entries := func(from, n int) string {
		items := make([]string, n)
		for i := range items {
			items[i] = `{"id":` + strconv.Itoa(from+i) + `}`
		}

		return "[" + strings.Join(items, ",") + "]"
	}

	tests := []struct {
		name      string
		answer    func(r *http.Request) answer
		wantReqs  int
		wantPages []string
		wantErr   []string
	}{
		{
			name: "an endpoint that ignores page and sends no Link is one page (the matching-refs shape)",
			answer: func(*http.Request) answer {
				return answer{body: entries(0, 124)}
			},
			wantReqs:  1,
			wantPages: []string{entries(0, 124)},
		},
		{
			name: "three pages by Link come back all three, in order",
			answer: func(r *http.Request) answer {
				switch r.URL.Query().Get("page") {
				case "":
					return answer{body: entries(0, 2), link: "{page 2}"}
				case "2":
					return answer{body: entries(2, 2), link: "{page 3}"}
				default:
					return answer{body: entries(4, 1)}
				}
			},
			wantReqs:  3,
			wantPages: []string{entries(0, 2), entries(2, 2), entries(4, 1)},
		},
		{
			name: "a Link that always names itself meets the bound, which names the path",
			answer: func(*http.Request) answer {
				return answer{body: entries(0, 1), link: "{self}"}
			},
			wantReqs: 50,
			wantErr:  []string{"/x", "did not converge in 50 pages"},
		},
		{
			name: "a next link off the API origin refuses rather than carrying the credential there",
			answer: func(*http.Request) answer {
				return answer{body: entries(0, 1), link: "https://elsewhere.example/x?page=2"}
			},
			wantReqs: 1,
			wantErr:  []string{"/x", "off the API origin"},
		},
		{
			name: "a body that is not a JSON array refuses by name",
			answer: func(*http.Request) answer {
				return answer{body: `{"message":"moved"}`}
			},
			wantReqs: 1,
			wantErr:  []string{"is not a JSON array"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fake := linkServer(t, tt.answer)

			c := &Client{Base: fake.srv.URL, HTTP: fake.srv.Client()}

			pages, err := c.paged("/x")

			if len(tt.wantErr) == 0 && err != nil {
				t.Fatalf("paged = %v, want a completed walk", err)
			}

			for _, want := range tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("paged = %v, want it to mention %q", err, want)
				}
			}

			if n := fake.requests(); n != tt.wantReqs {
				t.Errorf("requested %d times, want %d", n, tt.wantReqs)
			}

			if len(tt.wantErr) > 0 && pages != nil {
				t.Errorf("returned %d pages beside a refusal, want none", len(pages))
			}

			if got := joinPages(pages); len(tt.wantErr) == 0 && got != strings.Join(tt.wantPages, "|") {
				t.Errorf("pages = %s, want %v", got, tt.wantPages)
			}
		})
	}
}

// A next URL is requested exactly as the forge wrote it: the filters
// and per_page ride the first request only, and the second carries
// what the Link said and nothing this walk added.
func TestPagedUsesTheNextURLVerbatim(t *testing.T) {
	t.Parallel()

	var seen []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RequestURI())

		if len(seen) == 1 {
			w.Header().Set("Link", "<http://"+r.Host+`/repositories/9/x?cursor=abc>; rel="next"`)
		}

		if _, err := w.Write([]byte(`[]`)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)

	c := &Client{Base: srv.URL, HTTP: srv.Client()}

	if _, err := c.paged("/x", "includes_parents=true"); err != nil {
		t.Fatalf("paged = %v", err)
	}

	want := []string{"/x?per_page=100&includes_parents=true", "/repositories/9/x?cursor=abc"}
	if strings.Join(seen, " ") != strings.Join(want, " ") {
		t.Fatalf("requested %v, want %v", seen, want)
	}
}

// nextLink reads RFC 8288's shapes, not one spelling of them.
func TestNextLink(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{"no header", nil, ""},
		{
			"GitHub's shape",
			[]string{`<https://a/x?page=2>; rel="next", <https://a/x?page=5>; rel="last"`},
			"https://a/x?page=2",
		},
		{
			"next listed last",
			[]string{`<https://a/x?page=1>; rel="prev", <https://a/x?page=3>; rel="next"`},
			"https://a/x?page=3",
		},
		{"a bare rel", []string{`<https://a/n>; rel=next`}, "https://a/n"},
		{"rel among several types", []string{`<https://a/n>; rel="prefetch next"`}, "https://a/n"},
		{"rel case does not matter", []string{`<https://a/n>; REL="Next"`}, "https://a/n"},
		{"a comma inside the URL", []string{`<https://a/x?ids=1,2>; rel="next"`}, "https://a/x?ids=1,2"},
		{"split across header lines", []string{`<https://a/l>; rel="last"`, `<https://a/n>; rel="next"`}, "https://a/n"},
		{"only last and first", []string{`<https://a/l>; rel="last", <https://a/f>; rel="first"`}, ""},
		{"a next with no rel parameter", []string{`<https://a/n>; title="next"`}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := http.Header{}
			for _, v := range tt.values {
				h.Add("Link", v)
			}

			if got := nextLink(h); got != tt.want {
				t.Errorf("nextLink = %q, want %q", got, tt.want)
			}
		})
	}
}
