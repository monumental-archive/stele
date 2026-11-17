// The published-bytes ladder against a scripted server. The first four
// rows are the canon's release/test_verify_fetch.py (.github#1204),
// carried over whole: each asserts the outcome, the number of requests,
// the exact naps the schedule asked for, and the message that tells the
// two halves of the rule apart. No row sleeps: the Fetcher's Sleep
// records each nap instead of taking it, so the ten-minute row runs in
// milliseconds and asserts the whole schedule.

package published_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/published"
)

// body is what the stub serves on a 2xx.
var body = []byte("published bytes\n")

// bodyDigest is body's sha256, the digest a successful fetch returns.
func bodyDigest() string {
	sum := sha256.Sum256(body)

	return hex.EncodeToString(sum[:])
}

// reply is one scripted answer: a status and the headers beside it.
type reply struct {
	status int
	header map[string]string
	body   string
}

// stub answers a scripted sequence, one reply per request, repeating
// the last.
type stub struct {
	mu       sync.Mutex
	replies  []reply
	requests int
	agents   []string
}

func (s *stub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	rep := s.replies[min(s.requests, len(s.replies)-1)]
	s.requests++
	s.agents = append(s.agents, r.Header.Get("User-Agent"))
	s.mu.Unlock()

	for k, v := range rep.header {
		w.Header().Set(k, v)
	}

	payload := []byte(rep.body)
	if rep.status/100 == 2 && rep.body == "" {
		payload = body
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(rep.status)
	write(w, payload)
}

// write sends a scripted body; a stub that cannot is a broken test.
func write(w http.ResponseWriter, b []byte) {
	if _, err := w.Write(b); err != nil {
		panic(err)
	}
}

// statuses scripts bare statuses.
func statuses(codes ...int) []reply {
	out := make([]reply, 0, len(codes))
	for _, c := range codes {
		out = append(out, reply{status: c})
	}

	return out
}

// seconds renders naps as whole seconds, the schedule's own unit.
func seconds(naps []time.Duration) []int {
	out := make([]int, 0, len(naps))
	for _, n := range naps {
		out = append(out, int(n/time.Second))
	}

	return out
}

// fetcher builds a Fetcher whose naps and log lines are recorded, on
// a connection pool of its own (stele#243): the shared default pool is
// flushed by every sibling server's Close, which can break a
// connection this row is reusing mid-ladder. srv is nil for a row that
// never reaches a server; it still takes a private pool.
func fetcher(srv *httptest.Server) (*published.Fetcher, *[]time.Duration, *[]string) {
	var (
		naps []time.Duration
		logs []string
	)

	f := published.New("stele-test")

	f.HTTP.Transport = &http.Transport{}
	if srv != nil {
		f.HTTP.Transport = srv.Client().Transport
	}

	f.Sleep = func(d time.Duration) { naps = append(naps, d) }
	f.Log = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }

	return f, &naps, &logs
}

const subject = "pkg-1.0.0.tgz"

func TestFetchSchedule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		replies  []reply
		requests int
		naps     []int
		refusal  string // "" for a served file
		logs     []string
	}{
		{
			// test_404_three_times_then_200_passes
			name:     "the propagation window: three 404s, then the bytes",
			replies:  statuses(404, 404, 404, 200),
			requests: 4,
			naps:     []int{10, 20, 30},
			logs: []string{
				subject + ": not served yet (404, attempt 1), retrying in 10s",
				subject + ": not served yet (404, attempt 2), retrying in 20s",
				subject + ": not served yet (404, attempt 3), retrying in 30s",
			},
		},
		{
			// stele#392 Done when: a subject served after two 404s.
			name:     "served after two 404s",
			replies:  statuses(404, 404, 200),
			requests: 3,
			naps:     []int{10, 20},
		},
		{
			// test_404_for_the_whole_budget_fails_not_served, and the
			// Done-when row: never served within the budget, named.
			name:     "ten minutes of 404s, capped at 60s a nap, then named",
			replies:  statuses(404),
			requests: 14,
			naps:     []int{10, 20, 30, 40, 50, 60, 60, 60, 60, 60, 60, 60, 30},
			refusal:  subject + ": not served after 10 minutes",
		},
		{
			// test_503_fails_after_three_tries_naming_the_status
			name:     "a registry that is down is not waited on for ten minutes",
			replies:  statuses(503),
			requests: 3,
			naps:     []int{10, 20},
			refusal:  subject + ": failed with HTTP 503",
			logs: []string{
				subject + ": failed with HTTP 503 (try 1 of 3), retrying in 10s",
				subject + ": failed with HTTP 503 (try 2 of 3), retrying in 20s",
			},
		},
		{
			// stele#392 Done when: a 500 three times, named.
			name:     "a 500 three times",
			replies:  statuses(500),
			requests: 3,
			naps:     []int{10, 20},
			refusal:  subject + ": failed with HTTP 500",
		},
		{
			name:     "a failure that clears on the third try is served",
			replies:  statuses(502, 502, 200),
			requests: 3,
			naps:     []int{10, 20},
		},
		{
			name:     "an unclassified 4xx is a failure, not a propagation window",
			replies:  statuses(410),
			requests: 3,
			naps:     []int{10, 20},
			refusal:  subject + ": failed with HTTP 410",
		},
		{
			name: "a throttle naming its wait is honoured, and counts as a try",
			replies: []reply{
				{status: 429, header: map[string]string{"Retry-After": "45"}},
				{status: 200},
			},
			requests: 2,
			naps:     []int{45},
		},
		{
			name:     "a throttle naming no wait takes the ladder's own nap",
			replies:  []reply{{status: 429}},
			requests: 3,
			naps:     []int{10, 20},
			refusal: subject + ": failed with HTTP 429: the host throttled this walk, which says nothing about" +
				" the subject [marker: http-429;",
		},
		{
			name: "the forge's 403 secondary limit is a throttle, by the one classifier",
			replies: []reply{
				{status: 403, body: `{"message": "You have exceeded a secondary rate limit."}`},
			},
			requests: 3,
			naps:     []int{10, 20},
			refusal:  "[marker: secondary-limit-body;",
		},
		{
			name:     "a 403 with no throttle marker is the status alone",
			replies:  statuses(403),
			requests: 3,
			naps:     []int{10, 20},
			refusal:  subject + ": failed with HTTP 403",
		},
		{
			name:     "naps of both kinds spend one budget, and a 404 after failures still waits",
			replies:  statuses(503, 404, 404, 200),
			requests: 4,
			naps:     []int{10, 20, 30},
		},
		{
			name:     "the budget is shared: failures spent before the 404s shorten the window",
			replies:  append(statuses(503, 503), statuses(404)...),
			requests: 14,
			// 10+20 of failures, then 404 naps from attempt 3: 30,40,50,60…
			naps:    []int{10, 20, 30, 40, 50, 60, 60, 60, 60, 60, 60, 60, 30},
			refusal: subject + ": not served after 10 minutes",
		},
		{
			name:     "any 2xx is served",
			replies:  statuses(203),
			requests: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := &stub{replies: tt.replies}
			srv := httptest.NewServer(s)
			t.Cleanup(srv.Close)

			f, naps, logs := fetcher(srv)

			digest, err := f.Fetch(subject, srv.URL+"/pkg/-/pkg-1.0.0.tgz")
			checkOutcome(t, digest, err, tt.refusal)

			if s.requests != tt.requests {
				t.Errorf("requests = %d, want %d", s.requests, tt.requests)
			}

			if got := seconds(*naps); !slices.Equal(got, tt.naps) {
				t.Errorf("naps = %v, want %v", got, tt.naps)
			}

			for _, want := range tt.logs {
				if !slices.Contains(*logs, want) {
					t.Errorf("log %q missing from %q", want, *logs)
				}
			}

			for _, agent := range s.agents {
				if agent != "stele-test" {
					t.Errorf("User-Agent = %q, want the caller's", agent)
				}
			}
		})
	}
}

// checkOutcome holds one fetch's result to the row: the served
// digest, or the refusal by its message. The two halves of the rule
// never speak in each other's words — a failure that ran out never
// says the file was not served.
func checkOutcome(t *testing.T, digest string, err error, refusal string) {
	t.Helper()

	switch {
	case refusal == "" && err != nil:
		t.Fatalf("Fetch = %v, want the bytes", err)
	case refusal == "" && digest != bodyDigest():
		t.Fatalf("Fetch = %s, want %s", digest, bodyDigest())
	case refusal == "":
		return
	case err == nil:
		t.Fatalf("Fetch = %s, want a refusal containing %q", digest, refusal)
	case !strings.Contains(err.Error(), refusal):
		t.Fatalf("Fetch refused with\n  %v\nwant it to contain\n  %s", err, refusal)
	case strings.Contains(refusal, "failed with") && strings.Contains(err.Error(), "not served after"):
		t.Fatalf("a failure named itself a propagation window: %v", err)
	}
}

// TestFetchScheduleSumsToTheBudget holds the arithmetic the schedule
// is stated in: the 404 naps of a never-served file add up to exactly
// the budget, no more.
func TestFetchScheduleSumsToTheBudget(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(&stub{replies: statuses(404)})
	t.Cleanup(srv.Close)

	f, naps, _ := fetcher(srv)

	if _, err := f.Fetch(subject, srv.URL); err == nil {
		t.Fatal("a never-served file was served")
	}

	var total time.Duration
	for _, n := range *naps {
		total += n
	}

	if total != published.NotServedBudget {
		t.Fatalf("the naps sum to %s, want the budget %s", total, published.NotServedBudget)
	}
}

// TestFetchRefusedConnection is test_refused_connection_fails_after_
// three_tries: no server at all is a failure with no HTTP status, not a
// 404.
func TestFetchRefusedConnection(t *testing.T) {
	t.Parallel()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	addr := ln.Addr().String()
	if cerr := ln.Close(); cerr != nil {
		t.Fatal(cerr)
	}

	f, naps, _ := fetcher(nil)

	_, err = f.Fetch(subject, "http://"+addr+"/pkg-1.0.0.tgz")
	if err == nil {
		t.Fatal("a refused connection was served")
	}

	if got := seconds(*naps); !slices.Equal(got, []int{10, 20}) {
		t.Errorf("naps = %v, want [10 20]", got)
	}

	if !strings.Contains(err.Error(), subject+": failed with no HTTP status (") ||
		!strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("refusal = %v, want a failure with no HTTP status naming the refused connection", err)
	}
}

// TestFetchBrokenBody holds the read guards: a 200 whose body breaks
// off is a failure on the ladder, never a digest of half a file; and a
// refusal whose body breaks off is still a failure naming its status.
func TestFetchBrokenBody(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", "1000")
				w.WriteHeader(status)
				write(w, []byte("short"))
			}))
			t.Cleanup(srv.Close)

			f, naps, _ := fetcher(srv)

			want := fmt.Sprintf("%s: failed with HTTP %d, and the body broke off (", subject, status)

			_, err := f.Fetch(subject, srv.URL)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("Fetch = %v, want %q", err, want)
			}

			if len(*naps) != published.FailureTries-1 {
				t.Fatalf("naps = %v, want the failure ladder", *naps)
			}
		})
	}
}

// TestFetchMalformedURL holds the request guard: a URL no request can
// be built from is a failure with no HTTP status.
func TestFetchMalformedURL(t *testing.T) {
	t.Parallel()

	f, _, _ := fetcher(nil)

	_, err := f.Fetch(subject, "http://[::1]:namedport/x")
	if err == nil || !strings.Contains(err.Error(), subject+": failed with no HTTP status (") {
		t.Fatalf("Fetch = %v, want a failure with no HTTP status", err)
	}
}

// TestFetchTooLarge holds the size guard, with the bound lowered so
// the row does not have to send gigabytes: the refusal is immediate,
// because asking again is served the same file.
func TestFetchTooLarge(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(&stub{replies: statuses(200)})
	t.Cleanup(srv.Close)

	f, naps, _ := fetcher(srv)
	f.MaxBytes = int64(len(body) - 1)

	_, err := f.Fetch(subject, srv.URL)
	if err == nil || !strings.Contains(err.Error(), "larger than a released artifact may be") {
		t.Fatalf("Fetch = %v, want the size refusal", err)
	}

	if len(*naps) != 0 {
		t.Fatalf("an answer that will not change was retried: naps %v", *naps)
	}
}
