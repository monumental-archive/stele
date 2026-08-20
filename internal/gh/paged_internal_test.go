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

// The termination contract (#154). A walk that ends only on the
// empty array literal is guessing at content: `matching-refs/tags/`
// ignores `page` and answers every page with the same full array, so
// a repository with tags walked to the bound and refused —
// CANNOT_JUDGE on a healthy forge. Termination is arithmetic here: a
// page shorter than the size asked for is the last one.
func TestPagedTerminatesOnTheShortPage(t *testing.T) {
	t.Parallel()

	// entries renders an array of n indistinguishable objects: the
	// count is the only thing the rule reads, which is the point —
	// the rule is schema-agnostic.
	entries := func(n int) string {
		items := make([]string, n)
		for i := range items {
			items[i] = `{"id":1}`
		}

		return "[" + strings.Join(items, ",") + "]"
	}

	const full = 100

	tests := []struct {
		name      string
		body      func(page int) string
		wantReqs  int
		wantPages int
		wantErr   string
	}{
		{
			name:      "a full page then a short one: the short page ends the walk",
			body:      func(page int) string { return entries(map[bool]int{true: full, false: 3}[page == 1]) },
			wantReqs:  2,
			wantPages: 2,
		},
		{
			name:      "a short first page ends the walk at once",
			body:      func(int) string { return entries(7) },
			wantReqs:  1,
			wantPages: 1,
		},
		{
			name:      "an empty first page is the degenerate short page, not a separate rule",
			body:      func(int) string { return entries(0) },
			wantReqs:  1,
			wantPages: 1,
		},
		{
			name:      "an endpoint that ignores page terminates by arithmetic (the release-lab shape)",
			body:      func(int) string { return entries(59) },
			wantReqs:  1,
			wantPages: 1,
		},
		{
			name:     "a forge answering full pages forever still meets the bound",
			body:     func(int) string { return entries(full) },
			wantReqs: 50,
			wantErr:  "did not converge in 50 pages",
		},
		{
			name:     "a body that is not a JSON array refuses by name rather than miscounting",
			body:     func(int) string { return `{"message":"moved"}` },
			wantReqs: 1,
			wantErr:  "is not a JSON array",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var reqs int

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reqs++

				page, err := strconv.Atoi(r.URL.Query().Get("page"))
				if err != nil {
					t.Errorf("page parameter: %v", err)
				}

				if _, werr := w.Write([]byte(tt.body(page))); werr != nil {
					t.Error(werr)
				}
			}))
			t.Cleanup(srv.Close)

			c := &Client{Base: srv.URL, HTTP: srv.Client()}

			pages, err := c.paged("/x")

			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("paged = %v, want a completed walk", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("paged = nil error, want it to mention %q", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("paged = %v, want it to mention %q", err, tt.wantErr)
			}

			if reqs != tt.wantReqs {
				t.Errorf("requested %d times, want %d", reqs, tt.wantReqs)
			}

			if tt.wantErr == "" && len(pages) != tt.wantPages {
				t.Errorf("returned %d pages, want %d", len(pages), tt.wantPages)
			}

			if tt.wantErr != "" && pages != nil {
				t.Errorf("returned %d pages beside a refusal, want none", len(pages))
			}
		})
	}
}
