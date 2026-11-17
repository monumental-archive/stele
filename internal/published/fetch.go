// Package published pulls a released file back from the store that
// serves it and reports the digest of the bytes it was served — the
// half of a release proof that says what SHIPPED, as opposed to what
// was built (stele#392).
//
// A store answers 404 for a while after it accepted a publish:
// release-lab v0.28.2's npm tarball was still a 404 nine seconds after
// npm's own timestamp for the version, past a 75-second budget, and the
// release stopped after npm already had the package (.github#1204). So
// a 404 is "not served yet" and is waited on, for a stated budget; and
// anything else — a 5xx, a throttle, a refused connection — is the host
// failing, given a stated number of tries and then named. A store that
// is down is not waited on for the 404's budget.
//
// The classification is internal/gh's, never a second reading of the
// same response: a throttle is gh.HostThrottle's (a 429, or the forge's
// own 403 markers, since a release asset is served from the forge's
// estate), its evidence printed, and the wait the host named honoured
// through gh.RetryWait — the same answer every other reader of a host
// gets. What is this package's own is the schedule, which is the
// release proof's and nobody else's.
package published

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
)

// The waiting rule (.github#1204, carried over whole): a 404 waits
// min(attempt × NotServedStep, NotServedMaxNap), never past the budget
// in all; anything else gets FailureTries tries, napping
// failure × FailureStep between them unless the host named its own
// wait. Both naps count against the budget, which only the 404 reads.
const (
	NotServedBudget = 10 * time.Minute
	NotServedStep   = 10 * time.Second
	NotServedMaxNap = 60 * time.Second
	FailureTries    = 3
	FailureStep     = 10 * time.Second
)

// MaxBytes bounds one download. A released artifact is a file a
// consumer installs, and an answer past this size is a fault, not an
// artifact; it is refused rather than hashed for as long as a host
// cares to keep sending.
const MaxBytes = 4 << 30

// httpTimeout bounds one request end to end, body included.
const httpTimeout = 10 * time.Minute

// maxErrorBody bounds what is read of a refusal's body: enough for the
// forge's secondary-limit message, which is all it is asked.
const maxErrorBody = 64 << 10

// Fetcher pulls published files. Anonymous by construction: the proof
// is what a stranger is served, and no credential is ever handed to a
// registry that has no business holding one.
type Fetcher struct {
	HTTP *http.Client
	// UserAgent names the caller to the host; empty sends Go's own.
	UserAgent string
	// Sleep spends a nap. Injected, so the schedule is asserted
	// without a test taking the ten minutes it describes.
	Sleep func(time.Duration)
	// Log receives each retry's account of itself; nil discards it.
	Log func(format string, args ...any)
	// MaxBytes bounds one download; zero means the package's MaxBytes.
	MaxBytes int64
}

// New builds a Fetcher on the wall clock.
func New(userAgent string) *Fetcher {
	return &Fetcher{
		HTTP:      &http.Client{Timeout: httpTimeout},
		UserAgent: userAgent,
		Sleep:     time.Sleep,
	}
}

// errNotServed marks the one status that is a propagation window
// rather than an answer about the file: the store has not served it
// YET.
var errNotServed = errors.New("not served yet")

// errTooLarge marks an answer that will not change on asking again.
var errTooLarge = errors.New("larger than a released artifact may be")

// Fetch downloads url and returns the sha256 of the bytes served,
// lowercase hex. name is the subject the refusals and the log speak
// of. Two refusals end the ladder, each saying which half of the rule
// ran out:
//
//	<name>: not served after 10 minutes
//	<name>: failed with HTTP 503
func (f *Fetcher) Fetch(name, url string) (string, error) {
	var (
		attempt, failures int
		waited            time.Duration
	)

	for {
		attempt++

		digest, err := f.once(url)

		var nap time.Duration

		switch {
		case err == nil:
			return digest, nil
		case errors.Is(err, errTooLarge):
			return "", fmt.Errorf("%s: %w", name, err)
		case errors.Is(err, errNotServed):
			if waited >= NotServedBudget {
				return "", fmt.Errorf("%s: not served after %d minutes", name, int(NotServedBudget/time.Minute))
			}

			nap = min(time.Duration(attempt)*NotServedStep, NotServedMaxNap, NotServedBudget-waited)
			f.logf("%s: not served yet (404, attempt %d), retrying in %s", name, attempt, nap)
		default:
			failures++
			if failures >= FailureTries {
				return "", fmt.Errorf("%s: failed with %w", name, err)
			}

			// The host's own number wins when it named one — a throttle's
			// Retry-After, read through the one reading of that header.
			nap = gh.RetryWait(err, time.Duration(failures)*FailureStep)
			f.logf("%s: failed with %v (try %d of %d), retrying in %s", name, err, failures, FailureTries, nap)
		}

		f.Sleep(nap)
		waited += nap
	}
}

// once is one request, classified: the digest of a served file, the
// not-yet-served 404, or a failure that names its status.
func (f *Fetcher) once(url string) (string, error) {
	//nolint:noctx // the CLI has no cancellation surface; the client carries the timeout
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("no HTTP status (%w)", err)
	}

	if f.UserAgent != "" {
		req.Header.Set("User-Agent", f.UserAgent)
	}

	resp, err := f.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("no HTTP status (%w)", err)
	}
	defer resp.Body.Close() //nolint:errcheck // a read-only body close has nothing to report

	label := fmt.Sprintf("HTTP %d", resp.StatusCode)

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return "", errNotServed
	case resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices:
		// A throttle is classified where every host's is, so it prints
		// its evidence and carries the wait it named. The body is read
		// only for that one documented question, and only so far.
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		if rerr != nil {
			return "", fmt.Errorf("%s, and the body broke off (%w)", label, rerr)
		}

		if throttle := gh.HostThrottle(label, resp.StatusCode, resp.Header, body); throttle != nil {
			return "", throttle
		}

		// The status alone: the body is server-controlled prose.
		return "", errors.New(label)
	}

	limit := f.MaxBytes
	if limit <= 0 {
		limit = MaxBytes
	}

	h := sha256.New()

	n, err := io.Copy(h, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return "", fmt.Errorf("%s, and the body broke off (%w)", label, err)
	}

	if n > limit {
		return "", fmt.Errorf("%w: the host served more than %d bytes", errTooLarge, limit)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func (f *Fetcher) logf(format string, args ...any) {
	if f.Log != nil {
		f.Log(format, args...)
	}
}
