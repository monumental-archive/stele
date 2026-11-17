package ctlog_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/ctlog"
	"github.com/monumental-archive/stele/internal/gh"
)

// clock moves only when the reader waits.
type clock struct {
	mu    sync.Mutex
	now   time.Time
	slept []time.Duration
}

func newClock() *clock { return &clock{now: time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *clock) Sleep(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.slept = append(c.slept, d)
	c.now = c.now.Add(d)
}

// answer is one scripted response.
type answer struct {
	status int
	header map[string]string
	body   string
}

// scripted serves its answers in order, repeating the last, and
// records what it was asked.
type scripted struct {
	mu      sync.Mutex
	answers []answer
	asked   []*http.Request
}

func (s *scripted) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a := s.answers[min(len(s.asked), len(s.answers)-1)]
	s.asked = append(s.asked, r)

	for k, v := range a.header {
		w.Header().Set(k, v)
	}

	w.WriteHeader(a.status)

	if _, err := io.WriteString(w, a.body); err != nil {
		panic(err)
	}
}

// client is a reader of a log answering with the script, on a fresh
// clock, with the given budget.
func client(t *testing.T, budget time.Duration, answers ...answer) (*ctlog.Client, *scripted, *clock) {
	t.Helper()

	s := &scripted{answers: answers}
	srv := httptest.NewTLSServer(s)
	t.Cleanup(srv.Close)

	c := newClock()

	return &ctlog.Client{
		URL: srv.URL, HTTP: srv.Client(), Clock: c, Deadline: c.Now().Add(budget), UserAgent: "stele-test",
	}, s, c
}

const goodTreeHead = `{"tree_size": 5, "timestamp": 1794930319775, ` +
	`"sha256_root_hash": "u0YV2ESvJeMovY8f2ScbMNlhPDT88X9A4QWMWfR/dXE=", "tree_head_signature": "BAMARzBF"}`

func ok(body string) answer { return answer{status: http.StatusOK, body: body} }

// TestTreeHeadDecodes reads a real head's shape, and refuses every way
// an answer can lack one.
func TestTreeHeadDecodes(t *testing.T) {
	t.Parallel()

	c, s, _ := client(t, time.Minute, ok(goodTreeHead))

	head, err := c.TreeHead(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if head.TreeSize != 5 || len(head.RootHash) != 32 || head.Time().Format(time.RFC3339) != "2026-11-17T15:45:19Z" {
		t.Fatalf("head = %+v at %s", head, head.Time())
	}

	r := s.asked[0]
	if r.URL.Path != "/ct/v1/get-sth" || r.Header.Get("User-Agent") != "stele-test" ||
		r.Header.Get("Accept") != "application/json" {
		t.Fatalf("asked %s with headers %v", r.URL, r.Header)
	}

	cases := []struct{ name, body, want string }{
		{"not JSON", `<html>`, "ctlog: get-sth: jsonx: decode"},
		{
			"a field absent", `{"tree_size": 5, "timestamp": 1, "sha256_root_hash": "AA=="}`,
			"lacks tree_size, timestamp, sha256_root_hash or tree_head_signature",
		},
		{
			"a root hash that is not base64", strings.Replace(goodTreeHead, `"u0YV`, `"!!!!`, 1),
			"sha256_root_hash is not a base64 SHA-256 digest",
		},
		{"a root hash that is not SHA-256 long", strings.Replace(goodTreeHead,
			"u0YV2ESvJeMovY8f2ScbMNlhPDT88X9A4QWMWfR/dXE=", "AAAA", 1), "is not a base64 SHA-256 digest"},
		{
			"a signature that is not base64", strings.Replace(goodTreeHead, "BAMARzBF", "!!", 1),
			"tree_head_signature is not base64",
		},
		{
			"an empty signature", strings.Replace(goodTreeHead, "BAMARzBF", "", 1),
			"tree_head_signature is not base64",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, _, _ := client(t, time.Minute, ok(tc.body))
			if _, err := c.TreeHead(context.Background()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}
}

// TestConsistencyDecodes reads a proof and refuses an answer without
// one.
func TestConsistencyDecodes(t *testing.T) {
	t.Parallel()

	c, s, _ := client(t, time.Minute, ok(`{"consistency": ["AAEC", "AwQF"]}`))

	proof, err := c.Consistency(context.Background(), 3, 7)
	if err != nil {
		t.Fatal(err)
	}

	if len(proof) != 2 || proof[1][2] != 5 {
		t.Fatalf("proof = %v", proof)
	}

	if got := s.asked[0].URL.RawQuery; got != "first=3&second=7" {
		t.Fatalf("asked %q", got)
	}

	cases := []struct{ name, body, want string }{
		{"not JSON", `[`, "get-sth-consistency 3..7: jsonx: decode"},
		{"no array", `{}`, "get-sth-consistency 3..7: the answer carries no consistency array"},
		{"a node that is not base64", `{"consistency": ["!!"]}`, "node 0 is not base64"},
	}

	t.Run("a proof the log will not serve", func(t *testing.T) {
		t.Parallel()

		c, _, _ := client(t, time.Minute, answer{status: http.StatusBadRequest})
		if _, err := c.Consistency(context.Background(), 3, 7); err == nil ||
			err.Error() != "ctlog: get-sth-consistency 3..7: HTTP 400" {
			t.Fatalf("err = %v", err)
		}
	})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, _, _ := client(t, time.Minute, ok(tc.body))
			if _, err := c.Consistency(context.Background(), 3, 7); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}
}

// TestEntriesDecodes reads one page, and refuses a page that is not
// one: empty before the end, longer than asked, or carrying a leaf
// that is not there.
func TestEntriesDecodes(t *testing.T) {
	t.Parallel()

	c, s, _ := client(t, time.Minute, ok(`{"entries": [{"leaf_input": "AAE=", "extra_data": "AA=="}]}`))

	page, err := c.Entries(context.Background(), 40, 44)
	if err != nil {
		t.Fatal(err)
	}

	if len(page) != 1 || page[0].Index != 40 || len(page[0].LeafInput) != 2 || c.Stats().Entries != 1 {
		t.Fatalf("page = %+v, stats %+v", page, c.Stats())
	}

	if got := s.asked[0].URL.RawQuery; got != "start=40&end=44" {
		t.Fatalf("asked %q", got)
	}

	cases := []struct{ name, body, want string }{
		{"not JSON", `{`, "get-entries 40..41: jsonx: decode"},
		{
			"empty before the end", `{"entries": []}`,
			"the log answered get-entries with no entries before the end of the range: get-entries 40..41",
		},
		{"no entries array", `{}`, "no entries before the end of the range"},
		{
			"more than asked", `{"entries": [{"leaf_input": "AA=="}, {"leaf_input": "AA=="}, {"leaf_input": "AA=="}]}`,
			"the log returned 3 entries, more than the 2 asked for",
		},
		{
			"a leaf absent", `{"entries": [{"leaf_input": "AA=="}, {"extra_data": "AA=="}]}`,
			"entry 41 carries no leaf_input",
		},
		{"a leaf that is not base64", `{"entries": [{"leaf_input": "!!"}]}`, "entry 40: leaf_input is not base64"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, _, _ := client(t, time.Minute, ok(tc.body))
			if _, err := c.Entries(context.Background(), 40, 41); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}

	t.Run("a page the log will not serve", func(t *testing.T) {
		t.Parallel()

		c, _, _ := client(t, time.Minute, answer{status: http.StatusBadRequest})
		if _, err := c.Entries(context.Background(), 1, 2); err == nil ||
			err.Error() != "ctlog: get-entries 1..2: HTTP 400" {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("an empty page is ErrEmptyPage", func(t *testing.T) {
		t.Parallel()

		c, _, _ := client(t, time.Minute, ok(`{"entries": []}`))
		if _, err := c.Entries(context.Background(), 1, 2); !errors.Is(err, ctlog.ErrEmptyPage) {
			t.Fatalf("err = %v, want ErrEmptyPage", err)
		}
	})

	t.Run("an inverted range asks nothing", func(t *testing.T) {
		t.Parallel()

		c, s, _ := client(t, time.Minute, ok(`{}`))
		if _, err := c.Entries(context.Background(), 5, 4); err == nil ||
			!strings.Contains(err.Error(), "get-entries 5..4 is an empty range") || len(s.asked) != 0 {
			t.Fatalf("err = %v after %d requests", err, len(s.asked))
		}
	})
}

// TestTheLadder: what is retried, how long each wait is, and what
// ends the climb — the budget, never a count.
func TestTheLadder(t *testing.T) {
	t.Parallel()

	throttled := answer{status: http.StatusTooManyRequests}

	cases := []struct {
		name    string
		budget  time.Duration
		answers []answer
		slept   []time.Duration
		stats   ctlog.Stats
		want    string
		is      []error
	}{
		{
			name:    "a 429 is waited out, backing off from five seconds",
			budget:  time.Hour,
			answers: []answer{throttled, throttled, throttled, ok(goodTreeHead)},
			slept:   []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second},
			stats:   ctlog.Stats{Requests: 4, Throttled: 3},
		},
		{
			name:   "the backoff doubles to a minute and stays there",
			budget: time.Hour,
			answers: []answer{
				throttled, throttled, throttled, throttled, throttled, throttled, throttled, ok(goodTreeHead),
			},
			slept: []time.Duration{
				5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second,
				time.Minute, time.Minute, time.Minute,
			},
			stats: ctlog.Stats{Requests: 8, Throttled: 7},
		},
		{
			name:   "a 429's named wait is honoured",
			budget: time.Hour,
			answers: []answer{
				{status: http.StatusTooManyRequests, header: map[string]string{"Retry-After": "7"}},
				ok(goodTreeHead),
			},
			slept: []time.Duration{7 * time.Second},
			stats: ctlog.Stats{Requests: 2, Throttled: 1},
		},
		{
			name:   "a 503 naming a wait is the host failing, not a throttle — and its wait is still honoured",
			budget: time.Hour,
			answers: []answer{
				{status: http.StatusServiceUnavailable, header: map[string]string{"Retry-After": "7"}},
				ok(goodTreeHead),
			},
			slept: []time.Duration{7 * time.Second},
			stats: ctlog.Stats{Requests: 2, Unavailable: 1},
		},
		{
			name:   "a named wait past two minutes is held to two minutes",
			budget: time.Hour,
			answers: []answer{
				{status: http.StatusTooManyRequests, header: map[string]string{"Retry-After": "86400"}},
				ok(goodTreeHead),
			},
			slept: []time.Duration{2 * time.Minute},
			stats: ctlog.Stats{Requests: 2, Throttled: 1},
		},
		{
			name:   "a wait that will not parse still marks the throttle; the ladder backs off on its own",
			budget: time.Hour,
			answers: []answer{
				{status: http.StatusTooManyRequests, header: map[string]string{"Retry-After": "soon"}},
				{status: http.StatusTooManyRequests, header: map[string]string{"Retry-After": "-3"}},
				ok(goodTreeHead),
			},
			slept: []time.Duration{5 * time.Second, 10 * time.Second},
			stats: ctlog.Stats{Requests: 3, Throttled: 2},
		},
		{
			name:    "a 5xx is retried on the same ladder, and counted apart",
			budget:  time.Hour,
			answers: []answer{{status: http.StatusBadGateway}, ok(goodTreeHead)},
			slept:   []time.Duration{5 * time.Second},
			stats:   ctlog.Stats{Requests: 2, Unavailable: 1},
		},
		{
			name:   "a 403 in the forge's throttle shape is a throttle, by the shared definition",
			budget: time.Hour,
			answers: []answer{
				{status: http.StatusForbidden, header: map[string]string{"X-Ratelimit-Remaining": "0"}},
				ok(goodTreeHead),
			},
			slept: []time.Duration{5 * time.Second},
			stats: ctlog.Stats{Requests: 2, Throttled: 1},
		},
		{
			name:    "a plain 403 is the log's answer and is not asked again",
			budget:  time.Hour,
			answers: []answer{{status: http.StatusForbidden}},
			stats:   ctlog.Stats{Requests: 1},
			want:    "ctlog: get-sth: HTTP 403",
		},
		{
			name:    "a 4xx is the log's answer and is not asked again",
			budget:  time.Hour,
			answers: []answer{{status: http.StatusNotFound}},
			stats:   ctlog.Stats{Requests: 1},
			want:    "ctlog: get-sth: HTTP 404",
		},
		{
			name:    "a throttle that outlasts the budget ends the climb, naming the throttle",
			budget:  30 * time.Second,
			answers: []answer{throttled},
			slept:   []time.Duration{5 * time.Second, 10 * time.Second},
			stats:   ctlog.Stats{Requests: 3, Throttled: 3},
			want: "ctlog: the run's budget ended waiting 20s on ctlog: get-sth: HTTP 429: " +
				"the host throttled this walk, which says nothing about the subject " +
				"[marker: http-429; x-ratelimit-remaining: absent; x-ratelimit-reset: absent; " +
				"x-ratelimit-resource: absent; retry-after: absent]",
			is: []error{ctlog.ErrBudget, gh.ErrThrottled},
		},
		{
			name:    "an unavailable log that outlasts the budget says so",
			budget:  10 * time.Second,
			answers: []answer{{status: http.StatusInternalServerError}},
			slept:   []time.Duration{5 * time.Second},
			stats:   ctlog.Stats{Requests: 2, Unavailable: 2},
			want: "ctlog: the run's budget ended waiting 10s on ctlog: get-sth: HTTP 500: " +
				"the log or the transport failed, which says nothing about its entries",
			is: []error{ctlog.ErrBudget},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, _, clk := client(t, tc.budget, tc.answers...)

			_, err := c.TreeHead(context.Background())

			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("err = %v", err)
			case tc.want != "" && (err == nil || err.Error() != tc.want):
				t.Fatalf("err = %v\nwant %s", err, tc.want)
			}

			for _, target := range tc.is {
				if !errors.Is(err, target) {
					t.Errorf("err does not wrap %v", target)
				}
			}

			if !slices.Equal(clk.slept, tc.slept) {
				t.Errorf("waits = %v, want %v", clk.slept, tc.slept)
			}

			if c.Stats() != tc.stats {
				t.Errorf("stats = %+v, want %+v", c.Stats(), tc.stats)
			}
		})
	}
}

// failingDoer is a transport that never reaches the log, or reaches it
// and loses the body.
type failingDoer struct {
	err  error
	body bool
}

func (d failingDoer) Do(*http.Request) (*http.Response, error) {
	if d.body {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(errReader{}), Header: http.Header{}}, nil
	}

	return nil, d.err
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset mid-body") }

// TestTheTransport: a request that cannot be built, a transport that
// fails, a body that is lost and one that is too large — and a budget
// already spent, which asks nothing.
func TestTheTransport(t *testing.T) {
	t.Parallel()

	newC := func(url string, d ctlog.Doer, budget time.Duration) (*ctlog.Client, *clock) {
		c := newClock()

		return &ctlog.Client{URL: url, HTTP: d, Clock: c, Deadline: c.Now().Add(budget)}, c
	}

	t.Run("a URL no request can be built from", func(t *testing.T) {
		t.Parallel()

		c, _ := newC("://no-scheme", failingDoer{}, time.Minute)
		if _, err := c.TreeHead(context.Background()); err == nil || !strings.HasPrefix(err.Error(), "ctlog: get-sth: ") ||
			c.Stats().Requests != 0 {
			t.Fatalf("err = %v, %d requests", err, c.Stats().Requests)
		}
	})

	t.Run("a transport that fails is retried until the budget", func(t *testing.T) {
		t.Parallel()

		c, clk := newC("https://ct.example", failingDoer{err: errors.New("dial tcp: no route")}, 8*time.Second)

		_, err := c.TreeHead(context.Background())
		if err == nil || !strings.Contains(err.Error(), "dial tcp: no route") || !errors.Is(err, ctlog.ErrBudget) ||
			c.Stats().Unavailable != 2 || !slices.Equal(clk.slept, []time.Duration{5 * time.Second}) {
			t.Fatalf("err = %v, stats %+v, waits %v", err, c.Stats(), clk.slept)
		}
	})

	t.Run("a body lost mid-read is the transport failing", func(t *testing.T) {
		t.Parallel()

		c, _ := newC("https://ct.example", failingDoer{body: true}, time.Second)

		_, err := c.TreeHead(context.Background())
		if err == nil || !strings.Contains(err.Error(), "connection reset mid-body") || c.Stats().Unavailable != 1 {
			t.Fatalf("err = %v, stats %+v", err, c.Stats())
		}
	})

	t.Run("a body past the bound is refused, not retried", func(t *testing.T) {
		t.Parallel()

		big := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if _, err := io.CopyN(w, zeros{}, 64<<20+1); err != nil {
				return
			}
		}))
		t.Cleanup(big.Close)

		c, _ := newC(big.URL, big.Client(), time.Minute)

		_, err := c.TreeHead(context.Background())
		if err == nil || !strings.Contains(err.Error(), "the answer is larger than 67108864 bytes") ||
			c.Stats().Requests != 1 {
			t.Fatalf("err = %v, stats %+v", err, c.Stats())
		}
	})

	t.Run("a budget already spent asks nothing", func(t *testing.T) {
		t.Parallel()

		c, _ := newC("https://ct.example", failingDoer{}, 0)

		_, err := c.TreeHead(context.Background())
		if !errors.Is(err, ctlog.ErrBudget) || err.Error() != "ctlog: the run's budget ended before get-sth" ||
			c.Stats().Requests != 0 {
			t.Fatalf("err = %v, stats %+v", err, c.Stats())
		}
	})
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)

	return len(p), nil
}

// TestWallClock: the real clock is the real clock.
func TestWallClock(t *testing.T) {
	t.Parallel()

	var c ctlog.WallClock

	before := c.Now()
	c.Sleep(time.Millisecond)

	if !c.Now().After(before) {
		t.Fatal("the wall clock did not move")
	}
}
