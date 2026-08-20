// Package ghstore implements the verify engine's Store over the
// GitHub attestations API — the same endpoint a stranger queries,
// which is what makes a fetch here also a proof that the attestation
// was persisted where the runbook's consumer recipe reads. The API's
// response envelope is somebody else's schema and decodes leniently
// (jsonx.DecodeForeign); every bundle inside it is evidence and is
// judged strictly downstream.
package ghstore

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/verify"
)

// maxBody bounds one API response read: the endpoint serves bundle
// lists, and a response past this size is a fault, not evidence.
const maxBody = 64 << 20

// DefaultAttempts and the growing backoff mirror the original
// workflow stance: the store is often read moments after the signer
// wrote, and HTTP 404 is also the just-published propagation signal.
// An auditor verifying history wants the opposite — fail fast — so
// the attempt budget is a field, not a constant.
const (
	DefaultAttempts = 5
	backoffStep     = 5 * time.Second
)

// Client fetches attestation bundles. Token is optional — public
// repositories serve anonymously — but rate limits make it
// advisable; Sleep is injectable so retry tests need no clock.
type Client struct {
	Base  string
	Token string
	HTTP  *http.Client
	Sleep func(time.Duration)
	// Attempts is the propagation retry budget; 1 means fail fast.
	Attempts int
}

// httpTimeout bounds one API call end to end.
const httpTimeout = 60 * time.Second

// New builds a client against the public GitHub API.
func New(token string) *Client {
	return &Client{
		Base:     "https://api.github.com",
		Token:    token,
		HTTP:     &http.Client{Timeout: httpTimeout},
		Sleep:    time.Sleep,
		Attempts: DefaultAttempts,
	}
}

// response is the API envelope — foreign schema, lenient decode.
type response struct {
	Attestations []struct {
		Bundle jsonx.Raw `json:"bundle"`
	} `json:"attestations"`
}

// Bundles fetches every attestation bundle stored for one artifact
// digest, retrying while a just-published attestation propagates.
// An empty store after all retries is an error: this API is where
// the evidence must live, and nothing there is a finding.
//
// A throttled read is the one refusal that is NOT such a finding: the
// budget ran out on the host's pace, not on this digest's evidence, so
// the refusal names the throttle and the caller reads "the run could
// not see" rather than "the evidence is absent" (stele#209).
func (c *Client) Bundles(slug, sha256Hex string) ([]verify.StoredBundle, error) {
	url := fmt.Sprintf("%s/repos/%s/attestations/sha256:%s?per_page=100", c.Base, slug, sha256Hex)

	// A zero value means the caller never chose: the default ladder,
	// so a hand-built client keeps the documented stance.
	budget := c.Attempts
	if budget <= 0 {
		budget = DefaultAttempts
	}

	var lastErr error

	for attempt := 1; attempt <= budget; attempt++ {
		if attempt > 1 {
			// The host's own number wins over this ladder's when it named
			// one: waiting out a propagation and waiting out a throttle
			// are different waits, and only one of them the host knows.
			c.Sleep(gh.RetryWait(lastErr, time.Duration(attempt)*backoffStep))
		}

		bundles, err := c.fetch(url)
		if err == nil && len(bundles) > 0 {
			return bundles, nil
		}

		if err == nil {
			err = errors.New("the store holds no attestations for this digest")
		}

		lastErr = err
	}

	return nil, fmt.Errorf("ghstore: %s after %d attempt(s): %w", url, budget, lastErr)
}

func (c *Client) fetch(url string) ([]verify.StoredBundle, error) {
	//nolint:noctx // the CLI has no cancellation surface; the client carries the timeout
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-Github-Api-Version", "2022-11-28")

	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // a read-only body close has nothing to report

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// The one non-200 that is not about this digest at all: the host
		// throttling THIS caller. Classified through internal/gh's one
		// function rather than a second reading of the same headers
		// (stele#209) — two GitHub readers that disagreed about what a
		// throttle looks like would report the same outage two ways, and
		// this leg's way would be "the evidence is not there".
		if wait, ok := gh.Throttled(resp.StatusCode, resp.Header, body); ok {
			return nil, gh.ThrottleRefusal(fmt.Sprintf("HTTP %d", resp.StatusCode), wait)
		}

		// The status alone: the body is server-controlled prose.
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	decoded, err := jsonx.DecodeForeign[response](body)
	if err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}

	out := make([]verify.StoredBundle, 0, len(decoded.Attestations))
	for _, a := range decoded.Attestations {
		out = append(out, verify.StoredBundle{URI: url, Bundle: a.Bundle})
	}

	return out, nil
}
