// Package gh is the forge read seam: every GitHub read the assert
// engine makes goes through one interface with three lives — the
// live REST API, a recorded snapshot, and test fixtures. The seam
// exists because assert is the first verb reading MUTABLE state:
// shadow runs must feed both legs identical bytes (a snapshot), and
// a degraded read must be typed — a 404, a 403 and an empty listing
// are three different facts, and an engine that cannot tell them
// apart manufactures the impression of coverage.
//
// The same distinction decides what is retried: a 404 or a 403 is a
// FACT about the subject and is returned at once, while a 5xx or a
// 429 is the host or the transport failing and says nothing about
// the subject, so it is retried on a bounded ladder. Retrying an
// answer away would turn a real absence into a timeout and hide a
// narrowed credential behind noise.
package gh

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// ErrForbidden reports a read the credential could not make. Distinct
// from absent: an unreadable population is unchecked, never clean.
var ErrForbidden = errors.New("gh: the credential cannot read this")

// errTransient marks a status that says nothing about the subject —
// the host or the transport failed. Retried, never surfaced.
var errTransient = errors.New("gh: transient")

// The transient retry ladder: bounded, so a walk against a genuinely
// broken host still ends and reports CANNOT_JUDGE rather than hanging.
const (
	transientAttempts = 4
	transientBackoff  = 3 * time.Second
)

// Forge is the read surface the evidence walk judges through.
type Forge interface {
	// Repos lists the org's repositories, archived and forks excluded.
	Repos(org string) ([]string, error)
	// ReleaseTags lists the non-draft release tags of one repository.
	ReleaseTags(owner, repo string) ([]string, error)
	// ReleaseAssets lists the asset names of one release.
	ReleaseAssets(owner, repo, tag string) ([]string, error)
	// Asset downloads one release asset's bytes.
	Asset(owner, repo, tag, name string) ([]byte, error)
	// FileAt reads a repository file at a ref; ok=false means the file
	// (or the ref) does not exist there — absence is an answer, not an
	// error.
	FileAt(owner, repo, path, ref string) (content []byte, ok bool, err error)
	// Attestations returns the raw attestation bundles stored for one
	// digest — the audit posture: an empty store is an ANSWER (this
	// walk judges history, not a just-published artifact), so no
	// propagation ladder waits for one to appear. Transport failures
	// are still retried, like every read here.
	Attestations(owner, repo, sha256Hex string) ([]jsonx.Raw, error)
	// FailedRuns reports how many workflow runs on one branch (a tag
	// name, for release runs) concluded in failure.
	FailedRuns(owner, repo, branch string) (int, error)
}

// maxBody bounds one response read.
const maxBody = 64 << 20

// httpTimeout bounds one API call end to end.
const httpTimeout = 60 * time.Second

// Client is the live Forge over the GitHub REST API. Download is the
// release-asset host — the address a stranger pulls.
type Client struct {
	Base     string
	Download string
	Token    string
	HTTP     *http.Client
	// Sleep is the retry clock; nil means time.Sleep.
	Sleep func(time.Duration)
}

// New builds a live client against the public GitHub API.
func New(token string) *Client {
	return &Client{
		Base:     "https://api.github.com",
		Download: "https://github.com",
		Token:    token,
		HTTP:     &http.Client{Timeout: httpTimeout},
	}
}

type repoEntry struct {
	Name     string `json:"name"`
	Archived bool   `json:"archived"`
	Fork     bool   `json:"fork"`
}

// Repos implements Forge.
func (c *Client) Repos(org string) ([]string, error) {
	pages, err := c.paged("/orgs/" + url.PathEscape(org) + "/repos")
	if err != nil {
		return nil, err
	}

	var out []string

	for _, page := range pages {
		entries, err := jsonx.DecodeForeign[[]repoEntry](page)
		if err != nil {
			return nil, fmt.Errorf("gh: repos of %s: %w", org, err)
		}

		for _, e := range *entries {
			if !e.Archived && !e.Fork {
				out = append(out, e.Name)
			}
		}
	}

	return out, nil
}

type releaseEntry struct {
	TagName string `json:"tag_name"`
	Draft   bool   `json:"draft"`
	Assets  []struct {
		Name string `json:"name"`
	} `json:"assets"`
}

// ReleaseTags implements Forge.
func (c *Client) ReleaseTags(owner, repo string) ([]string, error) {
	rels, err := c.releases(owner, repo)
	if err != nil {
		return nil, err
	}

	var out []string

	for _, r := range rels {
		if !r.Draft {
			out = append(out, r.TagName)
		}
	}

	return out, nil
}

// ReleaseAssets implements Forge.
func (c *Client) ReleaseAssets(owner, repo, tag string) ([]string, error) {
	body, ok, err := c.get(
		"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/releases/tags/"+url.PathEscape(tag),
		"application/vnd.github+json")
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("gh: release %s/%s@%s: not found", owner, repo, tag)
	}

	rel, err := jsonx.DecodeForeign[releaseEntry](body)
	if err != nil {
		return nil, fmt.Errorf("gh: release %s/%s@%s: %w", owner, repo, tag, err)
	}

	out := make([]string, 0, len(rel.Assets))
	for _, a := range rel.Assets {
		out = append(out, a.Name)
	}

	return out, nil
}

// Asset implements Forge, downloading through the public release URL
// — the address a stranger pulls — under the same transient ladder as
// the API reads.
func (c *Client) Asset(owner, repo, tag, name string) ([]byte, error) {
	var lastErr error

	for attempt := 1; attempt <= transientAttempts; attempt++ {
		if attempt > 1 {
			c.sleep(time.Duration(attempt-1) * transientBackoff)
		}

		body, err := c.asset(owner, repo, tag, name)
		if !errors.Is(err, errTransient) {
			return body, err
		}

		lastErr = err
	}

	return nil, fmt.Errorf("gh: asset %s@%s/%s: after %d attempts: %w", repo, tag, name, transientAttempts, lastErr)
}

type contentsResponse struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

// FileAt implements Forge.
//
//nolint:gocritic // unnamedResult: the Forge interface documents the results
func (c *Client) FileAt(owner, repo, path, ref string) ([]byte, bool, error) {
	body, found, err := c.get(
		"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/contents/"+path+"?ref="+url.QueryEscape(ref),
		"application/vnd.github.raw+json")
	if err != nil || !found {
		return nil, false, err
	}

	// With the raw accept type the body IS the file; the JSON envelope
	// arrives only when a proxy strips the accept header — detect the
	// envelope by decoding, fall back to raw bytes.
	if env, derr := jsonx.DecodeForeign[contentsResponse](body); derr == nil && env.Encoding == "base64" {
		decoded, berr := decodeBase64Lenient(env.Content)
		if berr != nil {
			return nil, false, fmt.Errorf("gh: contents of %s/%s:%s: %w", owner, repo, path, berr)
		}

		return decoded, true, nil
	}

	return body, true, nil
}

type attestationsResponse struct {
	Attestations []struct {
		Bundle jsonx.Raw `json:"bundle"`
	} `json:"attestations"`
}

// Attestations implements Forge.
func (c *Client) Attestations(owner, repo, sha256Hex string) ([]jsonx.Raw, error) {
	body, ok, err := c.get(
		"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/attestations/sha256:"+sha256Hex+"?per_page=100",
		"application/vnd.github+json")
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil // an empty store is an answer here
	}

	decoded, err := jsonx.DecodeForeign[attestationsResponse](body)
	if err != nil {
		return nil, fmt.Errorf("gh: attestations of sha256:%s: %w", sha256Hex, err)
	}

	out := make([]jsonx.Raw, 0, len(decoded.Attestations))
	for _, a := range decoded.Attestations {
		out = append(out, a.Bundle)
	}

	return out, nil
}

type runsResponse struct {
	WorkflowRuns []struct {
		Conclusion string `json:"conclusion"`
	} `json:"workflow_runs"`
}

// FailedRuns implements Forge.
func (c *Client) FailedRuns(owner, repo, branch string) (int, error) {
	body, ok, err := c.get(
		"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/actions/runs?branch="+url.QueryEscape(branch)+
			"&per_page=100",
		"application/vnd.github+json")
	if err != nil {
		return 0, err
	}

	if !ok {
		return 0, nil
	}

	decoded, err := jsonx.DecodeForeign[runsResponse](body)
	if err != nil {
		return 0, fmt.Errorf("gh: runs of %s/%s@%s: %w", owner, repo, branch, err)
	}

	n := 0

	for _, r := range decoded.WorkflowRuns {
		if r.Conclusion == "failure" {
			n++
		}
	}

	return n, nil
}

func (c *Client) asset(owner, repo, tag, name string) ([]byte, error) {
	u := fmt.Sprintf("%s/%s/%s/releases/download/%s/%s", c.Download,
		url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(tag), url.PathEscape(name))

	//nolint:noctx // the CLI has no cancellation surface; the client carries the timeout
	req, err := http.NewRequest(http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("gh: build request: %w", err)
	}

	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gh: asset %s: %w", u, err)
	}
	defer resp.Body.Close() //nolint:errcheck // a read-only body close has nothing to report

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("gh: asset %s: read: %w", u, err)
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
			return nil, fmt.Errorf("gh: asset %s: HTTP %d: %w", u, resp.StatusCode, errTransient)
		}

		return nil, fmt.Errorf("gh: asset %s: HTTP %d", u, resp.StatusCode)
	}

	return body, nil
}

// get reads one API path, retrying only what is not an answer.
// A 5xx or a 429 is the transport or the host failing, never a fact
// about the subject, so it is retried on a growing backoff; a 404 and
// a 403 ARE facts (absent, unreadable) and are returned immediately —
// retrying an answer away is how a walk turns a real absence into a
// timeout, and how it hides a narrowed credential behind noise.
// Measured against the 2026-08-17 GitHub outage, where the first live
// walk died on a single 504 mid-population.
func (c *Client) get(path, accept string) ([]byte, bool, error) { //nolint:gocritic // unnamedResult: body, found, error
	var lastErr error

	for attempt := 1; attempt <= transientAttempts; attempt++ {
		if attempt > 1 {
			c.sleep(time.Duration(attempt-1) * transientBackoff)
		}

		body, ok, err := c.once(path, accept)
		if !errors.Is(err, errTransient) {
			return body, ok, err
		}

		lastErr = err
	}

	return nil, false, fmt.Errorf("gh: %s: after %d attempts: %w", path, transientAttempts, lastErr)
}

// sleep is the injectable clock — retry tests need no wall time.
func (c *Client) sleep(d time.Duration) {
	if c.Sleep != nil {
		c.Sleep(d)

		return
	}

	time.Sleep(d)
}

// once performs one API read. 404 returns (nil, false, nil); 403/401
// return ErrForbidden — the two absences the engine must never
// conflate; 5xx and 429 wrap errTransient for the retry above.
//
//nolint:gocritic // unnamedResult: body, found, error
func (c *Client) once(path, accept string) ([]byte, bool, error) {
	//nolint:noctx // the CLI has no cancellation surface; the client carries the timeout
	req, err := http.NewRequest(http.MethodGet, c.Base+path, http.NoBody)
	if err != nil {
		return nil, false, fmt.Errorf("gh: build request: %w", err)
	}

	req.Header.Set("Accept", accept)
	req.Header.Set("X-Github-Api-Version", "2022-11-28")

	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("gh: %s: %w", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // a read-only body close has nothing to report

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, false, fmt.Errorf("gh: %s: read: %w", path, err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return body, true, nil
	case http.StatusNotFound:
		return nil, false, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, false, fmt.Errorf("gh: %s: HTTP %d: %w", path, resp.StatusCode, ErrForbidden)
	case http.StatusTooManyRequests:
		return nil, false, fmt.Errorf("gh: %s: HTTP %d: %w", path, resp.StatusCode, errTransient)
	default:
		// The status alone: the body is server-controlled prose.
		if resp.StatusCode >= http.StatusInternalServerError {
			return nil, false, fmt.Errorf("gh: %s: HTTP %d: %w", path, resp.StatusCode, errTransient)
		}

		return nil, false, fmt.Errorf("gh: %s: HTTP %d", path, resp.StatusCode)
	}
}

// paged reads every page of a listing endpoint (per_page=100), up to
// a sane page bound.
func (c *Client) paged(path string) ([][]byte, error) {
	const maxPages = 50
	// emptyPageLen is the API's empty array literal, the last page.
	const emptyPageLen = 2

	var pages [][]byte

	for page := 1; page <= maxPages; page++ {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}

		body, ok, err := c.get(fmt.Sprintf("%s%sper_page=100&page=%d", path, sep, page), "application/vnd.github+json")
		if err != nil {
			return nil, err
		}

		if !ok {
			return nil, fmt.Errorf("gh: %s: not found", path)
		}

		pages = append(pages, body)

		// A short page ends the walk; counting entries needs the
		// caller's schema, so the caller re-slices — here the heuristic
		// is the API's own: an empty array literal is the last page.
		if len(body) <= emptyPageLen {
			break
		}

		if page == maxPages {
			return nil, fmt.Errorf("gh: %s: pagination did not converge in %d pages", path, maxPages)
		}
	}

	return pages, nil
}

func (c *Client) releases(owner, repo string) ([]releaseEntry, error) {
	pages, err := c.paged("/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/releases")
	if err != nil {
		return nil, err
	}

	var out []releaseEntry

	for _, page := range pages {
		entries, err := jsonx.DecodeForeign[[]releaseEntry](page)
		if err != nil {
			return nil, fmt.Errorf("gh: releases of %s/%s: %w", owner, repo, err)
		}

		out = append(out, *entries...)
	}

	return out, nil
}
