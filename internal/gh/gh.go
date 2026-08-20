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
//
// The one 403 that is NOT a fact about the subject is GitHub's
// SECONDARY rate limit, which the forge spells with the same status
// (stele#196). That is the host throttling THIS CALLER, so it is
// classified on the response rather than on the status code and
// joins the retry ladder — a throttled walk that reported its
// subjects as forbidden would be the wrong-refusal class the ladder
// exists to prevent.
package gh

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/workflow"
)

// ErrForbidden reports a read the credential could not make. Distinct
// from absent: an unreadable population is unchecked, never clean.
var ErrForbidden = errors.New("gh: the credential cannot read this")

// errTransient marks a status that says nothing about the subject —
// the host or the transport failed. Retried, never surfaced.
var errTransient = errors.New("gh: transient")

// errThrottled marks the host refusing this walk for its RATE. Named
// apart from errTransient although both ride the same ladder, because
// an exhausted ladder must say which of the two it ran out of — and
// named apart from ErrForbidden because the two arrive with the same
// status and mean opposite things: one is about this caller's pace,
// the other about this subject's permissions.
var errThrottled = errors.New("gh: the host throttled this walk, which says nothing about the subject")

// retryable reports whether an error is one the ladder may run again.
// Both members say nothing about the subject: the transport or host
// failed, or the host throttled this caller.
func retryable(err error) bool {
	return errors.Is(err, errTransient) || errors.Is(err, errThrottled)
}

// secondaryLimitRE matches the message GitHub answers a secondary
// rate limit with, and the fragment its documentation_url ends in.
var secondaryLimitRE = regexp.MustCompile(`(?i)secondary[ -]rate[ -]limit`)

// secondaryRateLimit reports whether a 403 is GitHub's SECONDARY rate
// limit — the host throttling this caller — rather than a refusal of
// the credential.
//
// The forge documents two signals, and this reads both because each
// travels without the other: a `retry-after` header naming the wait,
// and a body whose message names the limit —
//
//	retry-after: 60
//	{"message": "You have exceeded a secondary rate limit.
//	             Please wait a few minutes before you try again.",
//	 "documentation_url": "https://docs.github.com/rest/overview/
//	                       rate-limits-for-the-rest-api#about-secondary-rate-limits"}
//
// GitHub sends the header only when it has a wait to name, and a
// truncating proxy can drop the body while the header survives.
//
// The primary budget cannot stand in for either: measured 2026-08-20,
// an org-wide walk took this 403 with x-ratelimit-remaining at
// 4799/5000 — by the primary counter, nothing was wrong.
//
// Reading a server-controlled body is the narrow exception to this
// file's rule that only the status is trusted: it is asked one
// documented question about ONE status, and its only power is to move
// a refusal onto the retry ladder, never off one.
func secondaryRateLimit(header http.Header, body []byte) bool {
	if strings.TrimSpace(header.Get("Retry-After")) != "" {
		return true
	}

	return secondaryLimitRE.Match(body)
}

// The transient retry ladder: bounded, so a walk against a genuinely
// broken host still ends and reports CANNOT_JUDGE rather than hanging.
const (
	transientAttempts = 4
	transientBackoff  = 3 * time.Second
)

// Forge is the read surface the evidence walk judges through.
//
// It is wide because a forge is wide: every method here is one read a
// judgment needs, and splitting them into narrower interfaces would
// give each caller a different partial view of one service — which is
// how two callers come to disagree about what the forge said.
//
// Enumerating a population is deliberately NOT on this interface: it
// is RepoLister's, which internal/population alone holds (stele#153).
// A walk that could list an org from the same handle it reads with
// would be a second population beside the declared one, and the two
// disagree in exactly the degraded states the population rule exists
// to catch.
type Forge interface {
	// ReleaseTags lists the non-draft release tags of one repository.
	ReleaseTags(owner, repo string) ([]string, error)
	// ReleaseAssets lists the asset names of one release.
	ReleaseAssets(owner, repo, tag string) ([]string, error)
	// Asset downloads one release asset's bytes.
	Asset(owner, repo, tag, name string) ([]byte, error)
	// ReleaseDate reports when one release was published — the moment
	// its dependencies were taken, which is what an ingestion interval
	// is measured against.
	ReleaseDate(owner, repo, tag string) (time.Time, error)
	// TagCommit resolves a tag to the commit it points at,
	// dereferencing annotated tag objects — the commit is the pin the
	// full-depth leg verifies identities against, and an annotated
	// tag's own object id is never that commit.
	TagCommit(owner, repo, tag string) (string, error)
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
	// PackageVersionDigest returns the container digest carrying the
	// given tag for one org package, or "" when the package has no
	// such version — a rolling tag that points at nothing is an
	// answer, not an error.
	PackageVersionDigest(org, pkg, tag string) (string, error)
	// Workflows returns every workflow file at the repository's default
	// branch, each with the name its repository knows it by. The names
	// travel with the bytes because a repository's workflows are a flat
	// namespace keyed by file name, which is how one workflow's call on
	// another is spelled — and a finding that cannot name the file it
	// is about is a finding nobody can act on.
	Workflows(owner, repo string) ([]workflow.File, error)
	// FailedRuns reports the names of the workflow runs on one branch
	// (a tag name, for release runs) that concluded in failure. Names,
	// not a count: whether a failure is the PUBLISHING one decides
	// whether a release is burned, and a count cannot answer that.
	FailedRuns(owner, repo, branch string) ([]string, error)
}

// Repo is one repository as the forge reports it: its name and the
// two facts a membership rule reads. The FACTS travel, not a verdict
// about them — deciding that an archived repository owes no evidence
// is a policy call, and a listing that had already made it would have
// put one organisation's convention inside the forge seam where no
// policy could reach it (stele#153).
type Repo struct {
	Name     string `json:"name"`
	Archived bool   `json:"archived"`
	Fork     bool   `json:"fork"`
}

// RepoLister is the org-listing seam, separate from Forge on purpose:
// enumerating a population is internal/population's job alone, and a
// walk holding a Forge structurally cannot do it. The lint rule beside
// this (.golangci.yml, forbidigo) closes the remaining door — a caller
// that asserts its way to this method is refused by name.
type RepoLister interface {
	// ListRepos lists an organisation's repositories, verdict-free.
	ListRepos(org string) ([]Repo, error)
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
	return NewForServer("https://github.com", token)
}

// NewForServer builds a live client against the forge a caller NAMED.
// The REST endpoint is derived from the server URL by the forge's own
// convention — api.github.com for github.com, <server>/api/v3 for a
// GitHub Enterprise host, the same mapping Actions publishes as
// github.api_url beside github.server_url.
//
// Derived, not a second flag, because the two are one fact: a caller
// that names one forge in its signed output while this client reads
// another would fold a stranger's repository metadata into evidence
// about its own — the exact silent divergence a required --server-url
// exists to prevent.
func NewForServer(serverURL, token string) *Client {
	server := strings.TrimSuffix(serverURL, "/")

	base := server + "/api/v3"
	if server == "https://github.com" {
		base = "https://api.github.com"
	}

	return &Client{
		Base:     base,
		Download: server,
		Token:    token,
		HTTP:     &http.Client{Timeout: httpTimeout},
	}
}

type repoEntry struct {
	Name     string `json:"name"`
	Archived bool   `json:"archived"`
	Fork     bool   `json:"fork"`
}

// ListRepos implements RepoLister.
func (c *Client) ListRepos(org string) ([]Repo, error) {
	pages, err := c.paged("/orgs/" + url.PathEscape(org) + "/repos")
	if err != nil {
		return nil, err
	}

	var out []Repo

	for _, page := range pages {
		entries, err := jsonx.DecodeForeign[[]repoEntry](page)
		if err != nil {
			return nil, fmt.Errorf("gh: repos of %s: %w", org, err)
		}

		for _, e := range *entries {
			out = append(out, Repo(e))
		}
	}

	return out, nil
}

type releaseEntry struct {
	TagName     string `json:"tag_name"` //nolint:tagliatelle // the forge's own field name
	Draft       bool   `json:"draft"`
	PublishedAt string `json:"published_at"` //nolint:tagliatelle // the forge's own field name
	Assets      []struct {
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

// ReleaseDate implements Forge.
func (c *Client) ReleaseDate(owner, repo, tag string) (time.Time, error) {
	body, ok, err := c.get(
		"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/releases/tags/"+url.PathEscape(tag),
		"application/vnd.github+json")
	if err != nil {
		return time.Time{}, err
	}

	if !ok {
		return time.Time{}, fmt.Errorf("gh: release %s/%s@%s: not found", owner, repo, tag)
	}

	rel, err := jsonx.DecodeForeign[releaseEntry](body)
	if err != nil {
		return time.Time{}, fmt.Errorf("gh: release %s/%s@%s: %w", owner, repo, tag, err)
	}

	if rel.PublishedAt == "" {
		return time.Time{}, fmt.Errorf("gh: release %s/%s@%s carries no publication date", owner, repo, tag)
	}

	when, err := time.Parse(time.RFC3339, rel.PublishedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("gh: release %s/%s@%s: %w", owner, repo, tag, err)
	}

	return when, nil
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
		if !retryable(err) {
			return body, err
		}

		lastErr = err
	}

	return nil, fmt.Errorf("gh: asset %s@%s/%s: after %d attempts: %w", repo, tag, name, transientAttempts, lastErr)
}

type refObject struct {
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
	} `json:"object"`
}

// TagCommit implements Forge.
func (c *Client) TagCommit(owner, repo, tag string) (string, error) {
	base := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)

	body, found, err := c.get(base+"/git/ref/tags/"+url.PathEscape(tag), "application/vnd.github+json")
	if err != nil {
		return "", err
	}

	if !found {
		return "", fmt.Errorf("gh: tag %s/%s@%s does not exist", owner, repo, tag)
	}

	ref, err := jsonx.DecodeForeign[refObject](body)
	if err != nil {
		return "", fmt.Errorf("gh: ref of %s/%s@%s: %w", owner, repo, tag, err)
	}

	// A lightweight tag's ref names the commit; an annotated tag's
	// names the tag OBJECT, which must be dereferenced — pinning the
	// tag object id where a commit is expected is the annotated-tag
	// trap, and it verifies nothing.
	if ref.Object.Type != "tag" {
		return ref.Object.SHA, nil
	}

	body, found, err = c.get(base+"/git/tags/"+url.PathEscape(ref.Object.SHA), "application/vnd.github+json")
	if err != nil || !found {
		return "", fmt.Errorf("gh: tag object %s of %s/%s@%s: %w", ref.Object.SHA, owner, repo, tag, err)
	}

	deref, err := jsonx.DecodeForeign[refObject](body)
	if err != nil {
		return "", fmt.Errorf("gh: tag object of %s/%s@%s: %w", owner, repo, tag, err)
	}

	return deref.Object.SHA, nil
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

type packageVersion struct {
	Name     string `json:"name"`
	Metadata struct {
		Container struct {
			Tags []string `json:"tags"`
		} `json:"container"`
	} `json:"metadata"`
}

// PackageVersionDigest implements Forge.
func (c *Client) PackageVersionDigest(org, pkg, tag string) (string, error) {
	pages, err := c.paged("/orgs/" + url.PathEscape(org) + "/packages/container/" + url.PathEscape(pkg) + "/versions")
	if err != nil {
		return "", err
	}

	for _, page := range pages {
		versions, derr := jsonx.DecodeForeign[[]packageVersion](page)
		if derr != nil {
			return "", fmt.Errorf("gh: package versions of %s/%s: %w", org, pkg, derr)
		}

		for _, v := range *versions {
			for _, t := range v.Metadata.Container.Tags {
				if t == tag && digestRE.MatchString(v.Name) {
					return v.Name, nil
				}
			}
		}
	}

	return "", nil
}

// digestRE is the shape a container version name must have to be a
// digest — a tag-named version is not one.
var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type dirEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// WorkflowDir is where the platform keeps a repository's workflows.
// A forge fact rather than an org convention: the platform reads
// workflows from this directory and nowhere else, so a caller
// resolving a workflow path resolves it here.
const WorkflowDir = ".github/workflows"

// Workflows implements Forge.
func (c *Client) Workflows(owner, repo string) ([]workflow.File, error) {
	body, ok, err := c.get(
		"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/contents/"+WorkflowDir,
		"application/vnd.github+json")
	if err != nil || !ok {
		return nil, err
	}

	entries, err := jsonx.DecodeForeign[[]dirEntry](body)
	if err != nil {
		return nil, fmt.Errorf("gh: workflows of %s/%s: %w", owner, repo, err)
	}

	var out []workflow.File

	for _, e := range *entries {
		if e.Type != "file" {
			continue
		}

		content, found, ferr := c.FileAt(owner, repo, WorkflowDir+"/"+e.Name, "HEAD")
		if ferr != nil {
			return nil, ferr
		}

		if found {
			out = append(out, workflow.File{Name: e.Name, Content: content})
		}
	}

	return out, nil
}

type runsResponse struct {
	WorkflowRuns []struct {
		Name       string `json:"name"`
		Conclusion string `json:"conclusion"`
	} `json:"workflow_runs"`
}

// FailedRuns implements Forge.
func (c *Client) FailedRuns(owner, repo, branch string) ([]string, error) {
	body, ok, err := c.get(
		"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/actions/runs?branch="+url.QueryEscape(branch)+
			"&per_page=100",
		"application/vnd.github+json")
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil
	}

	decoded, err := jsonx.DecodeForeign[runsResponse](body)
	if err != nil {
		return nil, fmt.Errorf("gh: runs of %s/%s@%s: %w", owner, repo, branch, err)
	}

	var out []string

	for _, r := range decoded.WorkflowRuns {
		if r.Conclusion == "failure" {
			out = append(out, r.Name)
		}
	}

	return out, nil
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

		// The download host throttles with the same 403 the API does,
		// through the one classifier — a walk pulling many assets is
		// exactly the pace that earns one.
		if resp.StatusCode == http.StatusForbidden && secondaryRateLimit(resp.Header, body) {
			return nil, fmt.Errorf("gh: asset %s: HTTP %d: %w", u, resp.StatusCode, errThrottled)
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
//
// The exception is the 403 that secondaryRateLimit classifies as the
// host throttling this caller: that one is no answer about the
// subject at all, so it rides this ladder with the same backoff.
func (c *Client) get(path, accept string) ([]byte, bool, error) { //nolint:gocritic // unnamedResult: body, found, error
	var lastErr error

	for attempt := 1; attempt <= transientAttempts; attempt++ {
		if attempt > 1 {
			c.sleep(time.Duration(attempt-1) * transientBackoff)
		}

		body, ok, err := c.once(path, accept)
		if !retryable(err) {
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
// conflate; 5xx and 429 wrap errTransient for the retry above, and so
// does the 403 that carries the forge's secondary-rate-limit signals.
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
	case http.StatusForbidden:
		if secondaryRateLimit(resp.Header, body) {
			return nil, false, fmt.Errorf("gh: %s: HTTP %d: %w", path, resp.StatusCode, errThrottled)
		}

		return nil, false, fmt.Errorf("gh: %s: HTTP %d: %w", path, resp.StatusCode, ErrForbidden)
	case http.StatusUnauthorized:
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
// a sane page bound. path carries no query of its own — the
// pagination parameters ARE the query string — and a caller needing a
// filter passes it here rather than pre-formatting it into the path.
//
// That is a parameter and not a separator branch on purpose (#106,
// which deleted the branch and wrote this contract in its place). A
// path that pre-formatted its own filter would produce
// "?a=1?per_page=100", which the forge reads as one opaque parameter
// name: the filter is dropped and the listing answers as though it
// were never asked for. The rules listing is the first call site that
// needs a filter, and it must ask for inherited rulesets — where
// org-level controls live — so getting this wrong would under-claim
// silently.
//
// Enforced rather than documented, because a comment is not a guard
// and silently-wrong is this codebase's worst failure mode: a path
// carrying a query refuses by name.
//
// Termination is arithmetic and not a content guess (#154). The walk
// ends on the SHORT-PAGE rule: a page carrying fewer entries than the
// size asked for is the last one, and the empty page is that rule's
// degenerate case rather than its only case. The empty literal alone
// was not enough — `git/matching-refs/tags/` ignores `page` entirely
// and answers every page with the same full array, so a repository
// with tags walked to the bound and refused. maxPages stays as the
// backstop, reachable now only when a forge genuinely misbehaves.
func (c *Client) paged(path string, filters ...string) ([][]byte, error) {
	const maxPages = 50
	// perPage is both the page size asked for and the short-page
	// rule's yardstick — one constant, because a walk whose request
	// and whose termination test disagreed about the size would run
	// forever or stop early.
	const perPage = 100

	if strings.Contains(path, "?") {
		return nil, fmt.Errorf("gh: %s: the path carries its own query; pass filters as arguments so"+
			" pagination owns the query string", path)
	}

	var pages [][]byte

	for page := 1; page <= maxPages; page++ {
		query := fmt.Sprintf("%s?per_page=%d&page=%d", path, perPage, page)
		if len(filters) > 0 {
			query += "&" + strings.Join(filters, "&")
		}

		body, ok, err := c.get(query, "application/vnd.github+json")
		if err != nil {
			return nil, err
		}

		if !ok {
			return nil, fmt.Errorf("gh: %s: not found", path)
		}

		// Counting entries needs no schema: every paginated endpoint
		// here answers with a JSON array, so the page decodes as
		// deferred values and the caller still re-slices it under its
		// own type. A body that is not an array is a refusal by name
		// rather than a walk that cannot count.
		entries, derr := jsonx.DecodeForeign[[]jsonx.Raw](body)
		if derr != nil {
			return nil, fmt.Errorf("gh: %s: page %d is not a JSON array: %w", path, page, derr)
		}

		pages = append(pages, body)

		if len(*entries) < perPage {
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
