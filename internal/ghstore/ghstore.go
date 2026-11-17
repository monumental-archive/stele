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
	"net/http"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/verify"
)

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

// Bundles fetches every attestation bundle stored for one artifact
// digest, retrying while a just-published attestation propagates.
// An empty store after all retries is an error: this API is where
// the evidence must live, and nothing there is a finding.
//
// Every page is read (stele#439): the listing is internal/gh's one
// page walk, which follows the forge's own next link and fails the
// whole read when any page after the first fails. The verdict reader
// downstream is specified to walk the store WHOLE, and a store read one
// page deep reads a verdict on page two as absent.
//
// A throttled read is the one refusal that is NOT such a finding: the
// budget ran out on the host's pace, not on this digest's evidence, so
// the refusal names the throttle and the caller reads "the run could
// not see" rather than "the evidence is absent" (stele#209).
//
// A store the credential cannot read is the third fact, and the ladder
// is not its answer: a 403 or a 401 returns gh.ErrForbidden after one
// attempt (stele#216). Only the 404 is the propagation signal.
func (c *Client) Bundles(slug, sha256Hex string) ([]verify.StoredBundle, error) {
	path := fmt.Sprintf("/repos/%s/attestations/sha256:%s", slug, sha256Hex)

	// This ladder is the one that waits: the forge client below makes one
	// attempt per read, so a transient failure lands here once and the
	// two never multiply.
	forge := &gh.Client{Base: c.Base, Token: c.Token, HTTP: c.HTTP, Sleep: c.Sleep, Attempts: 1}

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

		bundles, err := read(forge, path)
		if err == nil && len(bundles) > 0 {
			return bundles, nil
		}

		// An unreadable store is not a propagating one: the ladder exists
		// because a just-published attestation 404s, and no wait turns a
		// refused credential into a permitted one. Leave at once, in the
		// refusal's own vocabulary (stele#216).
		if errors.Is(err, gh.ErrForbidden) {
			return nil, fmt.Errorf("ghstore: %s: %w", c.Base+path, err)
		}

		if err == nil {
			err = errors.New("the store holds no attestations for this digest")
		}

		lastErr = err
	}

	return nil, fmt.Errorf("ghstore: %s after %d attempt(s): %w", c.Base+path, budget, lastErr)
}

// errNotYet is the first page answering 404: the propagation signal a
// just-published attestation gives, which the ladder waits on.
var errNotYet = errors.New("HTTP 404: the store does not list this digest yet")

// read walks every page of the listing once. A first page that answers
// 404 is an empty store — the propagation signal the ladder waits on —
// and each bundle carries the page that served it.
func read(forge *gh.Client, path string) ([]verify.StoredBundle, error) {
	listed, found, err := forge.AttestationPages(path)
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, errNotYet
	}

	out := make([]verify.StoredBundle, 0, len(listed))
	for _, a := range listed {
		out = append(out, verify.StoredBundle{URI: a.Page, Bundle: a.Bundle})
	}

	return out, nil
}
