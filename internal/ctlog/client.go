// Package ctlog reads one certificate transparency log over the
// RFC 6962 HTTP API: its signed tree head, a consistency proof between
// two heads, and its entries a page at a time (stele#387). It judges
// nothing — the signer walk in internal/assert decides what an entry
// means; this package only says what the log served, and whether the
// log's own signature and its own history vouch for it.
//
// Three behaviours of a real log are the reason this reader exists
// rather than a library call, each measured against ctfe.sigstore.dev
// (stele#387, .github#1237):
//
//   - A get-entries response is capped by the server and the cap is
//     not the request: on 2026-11-17 a request for 2,001 entries from
//     447,842,897 returned 103, one from 447,843,000 returned 1,000
//     and one from 447,843,500 returned 500 — the log serves at most
//     a thousand entries, aligned to multiples of a thousand. A
//     reader that takes one response for the range it asked misses
//     everything past the first page, silently; this one advances by
//     the count each response actually carried.
//   - A response with no entries before the end is not progress. A
//     loop that re-asks would spin; it is an error, by name.
//   - The log answers a long read with 429. That says nothing about
//     any certificate: it is classified by the shared definition of a
//     throttle (gh.HostThrottle) and typed as the forge's are, its
//     evidence printed, its named wait honoured, else a backoff from
//     five seconds doubling to a minute — and the run's budget bounds
//     the ladder, so a throttle costs time, never a verdict.
package ctlog

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// The RFC 6962 endpoints this reader asks, relative to the log's base
// URL. A spec fact, the same class as a forge's REST paths.
const (
	pathTreeHead    = "/ct/v1/get-sth"
	pathConsistency = "/ct/v1/get-sth-consistency"
	pathEntries     = "/ct/v1/get-entries"
)

// The ladder a refused read climbs: the named wait when the log names
// one, else a backoff from firstBackoff doubling to maxBackoff. The
// numbers are the issue's (stele#387); what ends the ladder is the
// run's budget, never a count of attempts, because a throttle is the
// log's pace and a backlog is a normal state.
const (
	firstBackoff  = 5 * time.Second
	backoffFactor = 2
	maxBackoff    = 60 * time.Second
)

// requestTimeout bounds one request end to end. A thousand entries are
// about five megabytes and took 2.5 to 5.5 seconds on 2026-11-17; a
// minute is the transport failing, not the log being slow.
const requestTimeout = 60 * time.Second

// maxBody bounds one response read: a page of a thousand certificates
// measured 4,961,433 bytes, so this is a dozen pages' worth and a log
// that sends more than that is not answering get-entries.
const maxBody = 64 << 20

// ErrBudget reports that the run's budget ended before the read did.
// It is the expected end of a run over a backlog — the walk stops at
// its last done chunk and reports the rest as outstanding.
var ErrBudget = errors.New("ctlog: the run's budget ended")

// ErrEmptyPage reports a get-entries response that carried no entry
// although the range it was asked for was not finished. Asking again
// would ask the same question; a reader that loops on it spins until
// its budget ends and calls that a throttle.
var ErrEmptyPage = errors.New("ctlog: the log answered get-entries with no entries before the end of the range")

// errUnavailable marks a refusal that says nothing about the log's
// contents — a 5xx, or a transport that failed. Retried on the same
// ladder as a throttle, but named apart from it: a run that ran out of
// budget must say which of the two it ran out on.
var errUnavailable = errors.New("the log or the transport failed, which says nothing about its entries")

// Doer performs one HTTP request: *http.Client in a run.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Clock is the reader's time: what the budget is measured against,
// and how a wait is spent. A seam because a ladder of minute-long
// waits is otherwise untestable.
type Clock interface {
	Now() time.Time
	Sleep(d time.Duration)
}

// WallClock is the real clock.
type WallClock struct{}

// Now implements Clock.
func (WallClock) Now() time.Time { return time.Now() }

// Sleep implements Clock.
func (WallClock) Sleep(d time.Duration) { time.Sleep(d) }

// Stats counts what one client asked and what it was refused, for the
// report's facts: a run over a backlog is tuned from these, never
// judged by them.
type Stats struct {
	Requests    int
	Entries     int
	Throttled   int
	Unavailable int
}

// Client reads one log. Its zero value is not usable: URL, HTTP and
// Clock are required, and Deadline bounds everything it does.
type Client struct {
	// URL is the log's base URL, exactly as the trusted root names it.
	URL string
	// HTTP performs each request.
	HTTP Doer
	// Clock measures the budget and spends the waits.
	Clock Clock
	// Deadline is the moment the run's budget ends. No request starts
	// after it, and no wait is taken that would end after it.
	Deadline time.Time
	// UserAgent names the caller to the log operator. Empty sends
	// none of our own.
	UserAgent string

	stats Stats
}

// Stats reports what this client has asked so far.
func (c *Client) Stats() Stats { return c.stats }

// TreeHead is one signed tree head as the log served it — not yet
// verified. Verifier.VerifyTreeHead is the door between the two.
type TreeHead struct {
	TreeSize  uint64
	Timestamp uint64
	RootHash  []byte
	Signature []byte
}

// Time is the head's timestamp: the log's own milliseconds since the
// epoch.
func (h *TreeHead) Time() time.Time {
	return time.UnixMilli(int64(h.Timestamp)).UTC() //nolint:gosec // a CT timestamp is milliseconds since 1970; it fits
}

// treeHeadResponse is get-sth's answer (RFC 6962 §4.3).
type treeHeadResponse struct {
	TreeSize          *uint64 `json:"tree_size"`
	Timestamp         *uint64 `json:"timestamp"`
	SHA256RootHash    *string `json:"sha256_root_hash"`
	TreeHeadSignature *string `json:"tree_head_signature"`
}

// sha256Size is the length of a SHA-256 digest, the hash RFC 6962's
// Merkle tree is built with.
const sha256Size = 32

// TreeHead reads the log's current signed tree head.
func (c *Client) TreeHead(ctx context.Context) (*TreeHead, error) {
	body, err := c.get(ctx, pathTreeHead, "get-sth")
	if err != nil {
		return nil, err
	}

	r, err := jsonx.DecodeForeign[treeHeadResponse](body)
	if err != nil {
		return nil, fmt.Errorf("ctlog: get-sth: %w", err)
	}

	switch {
	case r.TreeSize == nil, r.Timestamp == nil, r.SHA256RootHash == nil, r.TreeHeadSignature == nil:
		return nil, errors.New(
			"ctlog: get-sth: the answer lacks tree_size, timestamp, sha256_root_hash or tree_head_signature",
		)
	}

	root, err := base64.StdEncoding.DecodeString(*r.SHA256RootHash)
	if err != nil || len(root) != sha256Size {
		return nil, fmt.Errorf("ctlog: get-sth: sha256_root_hash is not a base64 SHA-256 digest: %q", *r.SHA256RootHash)
	}

	sig, err := base64.StdEncoding.DecodeString(*r.TreeHeadSignature)
	if err != nil || len(sig) == 0 {
		return nil, fmt.Errorf("ctlog: get-sth: tree_head_signature is not base64: %q", *r.TreeHeadSignature)
	}

	return &TreeHead{TreeSize: *r.TreeSize, Timestamp: *r.Timestamp, RootHash: root, Signature: sig}, nil
}

// consistencyResponse is get-sth-consistency's answer (RFC 6962 §4.4).
type consistencyResponse struct {
	Consistency []string `json:"consistency"`
}

// Consistency reads the proof that the tree of size first is a prefix
// of the tree of size second.
func (c *Client) Consistency(ctx context.Context, first, second uint64) ([][]byte, error) {
	what := fmt.Sprintf("get-sth-consistency %d..%d", first, second)

	body, err := c.get(ctx, fmt.Sprintf("%s?first=%d&second=%d", pathConsistency, first, second), what)
	if err != nil {
		return nil, err
	}

	r, err := jsonx.DecodeForeign[consistencyResponse](body)
	if err != nil {
		return nil, fmt.Errorf("ctlog: %s: %w", what, err)
	}

	if r.Consistency == nil {
		return nil, fmt.Errorf("ctlog: %s: the answer carries no consistency array", what)
	}

	proof := make([][]byte, 0, len(r.Consistency))

	for i, node := range r.Consistency {
		b, derr := base64.StdEncoding.DecodeString(node)
		if derr != nil {
			return nil, fmt.Errorf("ctlog: %s: node %d is not base64: %w", what, i, derr)
		}

		proof = append(proof, b)
	}

	return proof, nil
}

// Entry is one log entry: its index and the Merkle tree leaf the log
// committed to. The unsigned extra data (the chain a submitter sent)
// is dropped on purpose — nothing in it is covered by the tree head,
// so nothing a judgment reads may come from it.
type Entry struct {
	Index     uint64
	LeafInput []byte
}

// entriesResponse is get-entries' answer (RFC 6962 §4.6).
type entriesResponse struct {
	Entries []entryResponse `json:"entries"`
}

type entryResponse struct {
	LeafInput *string `json:"leaf_input"`
}

// Entries reads ONE page of the inclusive range [start, end]: as many
// entries from start as the log chose to return, never zero and never
// more than were asked for. The caller advances by len(result).
func (c *Client) Entries(ctx context.Context, start, end uint64) ([]Entry, error) {
	if end < start {
		return nil, fmt.Errorf("ctlog: get-entries %d..%d is an empty range", start, end)
	}

	what := fmt.Sprintf("get-entries %d..%d", start, end)

	body, err := c.get(ctx, fmt.Sprintf("%s?start=%d&end=%d", pathEntries, start, end), what)
	if err != nil {
		return nil, err
	}

	r, err := jsonx.DecodeForeign[entriesResponse](body)
	if err != nil {
		return nil, fmt.Errorf("ctlog: %s: %w", what, err)
	}

	switch n := uint64(len(r.Entries)); {
	case n == 0:
		return nil, fmt.Errorf("%w: %s", ErrEmptyPage, what)
	case n > end-start+1:
		return nil, fmt.Errorf("ctlog: %s: the log returned %d entries, more than the %d asked for", what, n, end-start+1)
	}

	out := make([]Entry, 0, len(r.Entries))

	for i, e := range r.Entries {
		if e.LeafInput == nil {
			return nil, fmt.Errorf("ctlog: %s: entry %d carries no leaf_input", what, start+uint64(i))
		}

		leaf, derr := base64.StdEncoding.DecodeString(*e.LeafInput)
		if derr != nil {
			return nil, fmt.Errorf("ctlog: %s: entry %d: leaf_input is not base64: %w", what, start+uint64(i), derr)
		}

		out = append(out, Entry{Index: start + uint64(i), LeafInput: leaf})
	}

	c.stats.Entries += len(out)

	return out, nil
}

// get reads one path, climbing the ladder on every refusal that says
// nothing about the log's contents, until the budget would end.
func (c *Client) get(ctx context.Context, path, what string) ([]byte, error) {
	backoff := firstBackoff

	for {
		body, err := c.once(ctx, path, what)
		if err == nil {
			return body, nil
		}

		if !retryable(err) {
			return nil, err
		}

		// A wait that would reach the deadline is not taken: the read
		// after it could not start, and the cause worth naming is the
		// refusal, not the clock.
		wait := waitFor(err, backoff)
		if !c.Clock.Now().Add(wait).Before(c.Deadline) {
			return nil, fmt.Errorf("%w waiting %s on %w", ErrBudget, wait, err)
		}

		c.Clock.Sleep(wait)

		backoff = min(backoff*backoffFactor, maxBackoff)
	}
}

// retryable is the ladder's membership: a throttle or an unavailable
// log. Anything else — a 4xx, an answer too large — is the log saying
// something this reader cannot use, and asking again would not change
// it.
func retryable(err error) bool {
	return errors.Is(err, gh.ErrThrottled) || errors.Is(err, errUnavailable)
}

// once is one request, classified.
func (c *Client) once(ctx context.Context, path, what string) ([]byte, error) {
	now := c.Clock.Now()
	if !now.Before(c.Deadline) {
		return nil, fmt.Errorf("%w before %s", ErrBudget, what)
	}

	ctx, cancel := context.WithTimeout(ctx, min(requestTimeout, c.Deadline.Sub(now)))
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+path, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("ctlog: %s: %w", what, err)
	}

	req.Header.Set("Accept", "application/json")

	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	c.stats.Requests++

	resp, err := c.HTTP.Do(req)
	if err != nil {
		c.stats.Unavailable++

		return nil, transportFailed(what, err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only close

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		c.stats.Unavailable++

		return nil, transportFailed(what, err)
	}

	return c.classify(resp, body, what)
}

// classify reads one response's status into the reader's vocabulary,
// through the shared definition of what a throttle is (gh.HostThrottle,
// stele#383): a 429 — or the forge's own 403 markers — is the host
// pacing this run. A 5xx is the host failing, retried on the same
// ladder and counted apart; a Retry-After it carries is still the wait
// the host asked for, read through the one reading of that header
// (gh.RetryAfter). Anything else is the log's answer.
func (c *Client) classify(resp *http.Response, body []byte, what string) ([]byte, error) {
	switch {
	case len(body) > maxBody:
		return nil, fmt.Errorf("ctlog: %s: the answer is larger than %d bytes", what, maxBody)
	case resp.StatusCode == http.StatusOK:
		return body, nil
	}

	label := fmt.Sprintf("ctlog: %s: HTTP %d", what, resp.StatusCode)

	if err := gh.HostThrottle(label, resp.StatusCode, resp.Header, body); err != nil {
		c.stats.Throttled++

		return nil, err
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		c.stats.Unavailable++

		return nil, &unavailableError{msg: label + ": " + errUnavailable.Error(), wait: gh.RetryAfter(resp.Header)}
	}

	return nil, errors.New(label)
}

// unavailableError is a refusal that says nothing about the log's
// contents, carrying the wait the host named, if it named one.
type unavailableError struct {
	msg   string
	wait  time.Duration
	cause error
}

func (e *unavailableError) Error() string { return e.msg }

func (e *unavailableError) Unwrap() []error {
	if e.cause == nil {
		return []error{errUnavailable}
	}

	return []error{errUnavailable, e.cause}
}

// transportFailed is the refusal a request that never completed
// returns: the transport failed, which says nothing about the log.
func transportFailed(what string, err error) error {
	return &unavailableError{msg: fmt.Sprintf("ctlog: %s: %v: %v", what, errUnavailable, err), cause: err}
}

// waitFor is how long the ladder pauses after one refusal: the wait
// the host named — on a throttle, through the forge's own reading; on
// an unavailable host, the Retry-After it sent — else the backoff.
func waitFor(err error, backoff time.Duration) time.Duration {
	var u *unavailableError
	if errors.As(err, &u) && u.wait > 0 {
		return u.wait
	}

	return gh.RetryWait(err, backoff)
}
