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
// The one 403 that is NOT a fact about the subject is the forge rate
// limiting THIS CALLER, which it spells with the same status
// (stele#196, stele#209). That is the host throttling this walk, so
// it is classified on the response rather than on the status code and
// joins the retry ladder — a throttled walk that reported its
// subjects as forbidden would be the wrong-refusal class the ladder
// exists to prevent.
//
// That classification is the one thing in this package a leg outside
// it needs: internal/ghstore reads the same forge over the same
// statuses, so it asks Throttled rather than growing a second answer
// (stele#209). Two GitHub readers disagreeing about what a throttle
// looks like is the shape the share-the-definition rule forbids.
package gh

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
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

// ErrThrottled marks the host refusing this walk for its RATE. Named
// apart from errTransient although both ride the same ladder, because
// an exhausted ladder must say which of the two it ran out of — and
// named apart from ErrForbidden because the two arrive with the same
// status and mean opposite things: one is about this caller's pace,
// the other about this subject's permissions.
//
// Exported, unlike errTransient, because it is the vocabulary a
// SECOND forge reader types its own throttles with: the sentence a
// walk prints for a throttle must not depend on which package read
// the response. It carries no package prefix for the same reason —
// each reader names its own context in front of it.
var ErrThrottled = errors.New("the host throttled this walk, which says nothing about the subject")

// Retryable reports whether an error is one the ladder may run again.
// Both members say nothing about the subject: the transport or host
// failed, or the host throttled this caller.
//
// Exported because a walk outside this package asks the same question
// of a read the ladder gave up on (stele#339): an exhausted transient
// read and a throttle are both "the run could not see", never a fact
// about the subject. One predicate, so the two cannot disagree about
// which refusals those are.
func Retryable(err error) bool {
	return errors.Is(err, errTransient) || errors.Is(err, ErrThrottled)
}

// secondaryLimitRE matches the message GitHub answers a secondary
// rate limit with, and the fragment its documentation_url ends in.
var secondaryLimitRE = regexp.MustCompile(`(?i)secondary[ -]rate[ -]limit`)

// maxNamedWait bounds the wait one header may impose. A ladder is
// bounded so a walk against a broken host still ends, and a host that
// could name any wait it liked could hand back that bound — past this
// point a Retry-After has stopped being a wait and become a hang. The
// forge's documented secondary-limit wait is a minute; twice that is
// honoured in full.
const (
	maxNamedWaitSeconds = 120
	maxNamedWait        = maxNamedWaitSeconds * time.Second
)

// Throttled reports whether one forge response is the host throttling
// THIS CALLER rather than refusing THIS SUBJECT, and the evidence that
// says so: the wait the host named (zero when it named none), every
// marker the response carried, and its rate headers (stele#383).
//
// This is the ONE place that question is answered, for every leg that
// reads GitHub (stele#209): the status test lives here too, so no
// caller re-spells "only a 403 can be this" beside its own copy of the
// markers.
//
// Three markers, read because each travels without the others:
//
//	retry-after: 60                       ← the host names a wait
//	x-ratelimit-remaining: 0              ← this response's own budget
//	{"message": "You have exceeded a secondary rate limit. …",
//	 "documentation_url": "https://docs.github.com/rest/overview/
//	   rate-limits-for-the-rest-api#about-secondary-rate-limits"}
//
// GitHub sends the header only when it has a wait to name; a
// truncating proxy can drop the body while the header survives; and a
// primary budget spent to zero is refused with neither.
//
// The remaining counter is read off THIS response, which is what makes
// it evidence rather than a guess: the counters are per resource, and
// the response carries the one for the resource it answered. A
// NEIGHBOURING counter proves nothing in either direction — measured
// 2026-08-20, an org-wide walk took a secondary-limit 403 with
// x-ratelimit-remaining at 4799/5000, so a healthy budget is no proof
// of a healthy walk, and only exhaustion is a marker here.
//
// Reading a server-controlled body is the narrow exception to this
// file's rule that only the status is trusted: it is asked one
// documented question about ONE status, and its only power is to move
// a refusal onto the retry ladder, never off one.
func Throttled(status int, header http.Header, body []byte) (Throttle, bool) {
	if status != http.StatusForbidden {
		return Throttle{}, false
	}

	// Every marker is read, never the first that matches: which ones
	// the host sent together is the evidence a person tuning a
	// schedule needs (stele#383), and stopping at the first would
	// print a refusal with its second cause missing.
	var markers []string

	if strings.TrimSpace(header.Get("Retry-After")) != "" {
		markers = append(markers, MarkerRetryAfter)
	}

	// Exhaustion is the marker; anything else the counter says is not
	// one, and a counter that will not parse is no counter at all.
	if n, err := strconv.Atoi(strings.TrimSpace(header.Get("X-Ratelimit-Remaining"))); err == nil && n <= 0 {
		markers = append(markers, MarkerRemainingZero)
	}

	if secondaryLimitRE.Match(body) {
		markers = append(markers, MarkerSecondaryBody)
	}

	if len(markers) == 0 {
		return Throttle{}, false
	}

	t := ThrottleEvidence(header, markers...)
	t.Wait = RetryAfter(header)

	return t, true
}

// The markers a throttle is classified on, by the names its refusal
// prints them under. The first three are the forge's 403 markers;
// the last is the status the HTTP standard names a throttle with
// (RFC 6585), which HostThrottle reads for every other host.
const (
	MarkerRetryAfter      = "retry-after"
	MarkerRemainingZero   = "ratelimit-remaining-0"
	MarkerSecondaryBody   = "secondary-limit-body"
	MarkerTooManyRequests = "http-429"
)

// HostThrottle is the typed throttle refusal one response from a host
// OTHER than the forge's REST API amounts to, or nil when the response
// is no throttle (stele#383). what names the read, as it does for
// ThrottleRefusal.
//
// Two shapes classify, and each is read through the one place it is
// already defined:
//
//   - a 429, the standard's own word for a throttle. Its marker is the
//     status; a Retry-After beside it is the wait, read by RetryAfter
//     with the forge's clamp, and printed as evidence;
//   - a 403 carrying the forge's markers, through Throttled, because a
//     host on the forge's estate throttles in the forge's shape.
//
// Nothing else is a throttle here — a 503 with a Retry-After is the
// host failing, not the host pacing this caller — and a host that
// sends no rate headers gets every field printed absent. The refusal
// wraps ErrThrottled and carries its wait for RetryWait, exactly as
// the forge's does.
//
// The forge's own reads do NOT come through here: there a 429 stays
// transient, the class it has always had (stele#217), and only the
// 403 is a throttle. This entry is for the hosts beside the forge.
func HostThrottle(what string, status int, header http.Header, body []byte) error {
	if status == http.StatusTooManyRequests {
		t := ThrottleEvidence(header, MarkerTooManyRequests)
		t.Wait = RetryAfter(header)

		return ThrottleRefusal(what, &t)
	}

	if t, ok := Throttled(status, header, body); ok {
		return ThrottleRefusal(what, &t)
	}

	return nil
}

// absent is how a header the response did not carry is printed: said
// outright, so an empty field cannot be read as a header sent empty.
const absent = "absent"

// Throttle is one throttle refusal's evidence: the wait the host
// named, which markers classified the response, and the rate headers
// as the response carried them (stele#383). A CANNOT_JUDGE from a
// throttle must be diagnosable from the run's own log — whether the
// hourly budget was spent or a secondary limit tripped is the
// difference between moving a schedule and splitting a walk.
//
// Exported because every host stele throttles on types its refusals
// with this one shape — the forge's REST API, and any other reader
// beside it — and a host with no rate headers simply has them absent.
// Only these four headers are ever copied out of a response, so no
// credential a request or response carries can reach the message.
type Throttle struct {
	// Wait is the pause the host named, zero when it named none.
	Wait time.Duration
	// Markers names what classified the response, in the order
	// Throttled reads them.
	Markers []string
	// The rate headers, raw, "" when the response did not carry one.
	Remaining, Reset, Resource, RetryAfter string
}

// ThrottleEvidence reads a response's rate headers into a Throttle
// classified by the named markers. Throttled is its caller for the
// forge; a reader whose host signals a throttle some other way names
// its own markers and passes what headers it has (none, for a host
// that sends none).
func ThrottleEvidence(header http.Header, markers ...string) Throttle {
	return Throttle{
		Markers:    markers,
		Remaining:  strings.TrimSpace(header.Get("X-Ratelimit-Remaining")),
		Reset:      strings.TrimSpace(header.Get("X-Ratelimit-Reset")),
		Resource:   strings.TrimSpace(header.Get("X-Ratelimit-Resource")),
		RetryAfter: strings.TrimSpace(header.Get("Retry-After")),
	}
}

// String renders the evidence as the refusal prints it. Header values
// are server-controlled, so each is quoted: a value cannot break the
// line it is printed on or pose as a neighbouring field.
func (t Throttle) String() string {
	markers := absent
	if len(t.Markers) > 0 {
		markers = strings.Join(t.Markers, ", ")
	}

	reset := quoted(t.Reset)
	// The reset is epoch seconds; the same instant in UTC is what a
	// person reading a log compares against the run's timestamps.
	if secs, err := strconv.ParseInt(t.Reset, 10, 64); err == nil {
		reset += " (" + time.Unix(secs, 0).UTC().Format(time.RFC3339) + ")"
	}

	return fmt.Sprintf("marker: %s; x-ratelimit-remaining: %s; x-ratelimit-reset: %s;"+
		" x-ratelimit-resource: %s; retry-after: %s",
		markers, quoted(t.Remaining), reset, quoted(t.Resource), quoted(t.RetryAfter))
}

// quoted prints one header value: absent by name, otherwise quoted.
func quoted(v string) string {
	if v == "" {
		return absent
	}

	return strconv.Quote(v)
}

// RetryAfter is the wait a response's Retry-After names, zero when it
// names none. The ONE reading of that header for every status that can
// carry it: a 429 says unambiguously what a 403 has to be classified
// into, but the number both name is the same number, read and clamped
// here alone (stele#217).
//
// Exported for every host stele reads, not only the forge (stele#383):
// a reader of another host that honoured a different clamp would let
// that host hold a walk longer than the forge may.
func RetryAfter(header http.Header) time.Duration {
	return namedWait(strings.TrimSpace(header.Get("Retry-After")))
}

// namedWait reads the wait a Retry-After names, in the delta-seconds
// form the forge sends. A header that will not parse still MARKED the
// throttle — its presence is the marker — but names no wait, so the
// ladder falls back to its own backoff rather than inventing a number
// and lending it the host's authority.
func namedWait(raw string) time.Duration {
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		return 0
	}

	// Clamped in seconds, before the multiply: a wait long enough to
	// overflow the duration would come back NEGATIVE and turn the
	// ladder's pause into no pause at all.
	if secs > maxNamedWaitSeconds {
		return maxNamedWait
	}

	return time.Duration(secs) * time.Second
}

// waitError is a refusal carrying the wait the host named. The wait
// travels WITH the refusal because the classification and the wait are
// one reading of one response: a ladder that had to ask the response
// again would hold a second derivation of the same fact, and by then
// the response is gone.
//
// It carries its own sentinel because two different refusals earn a
// named wait and MEAN different things — the throttle and the 429 the
// forge answers a rate limit with — while the pause they earn is the
// host's either way (stele#217).
type waitError struct {
	what string
	wait time.Duration
	kind error
	// evidence is what classified the refusal, printed after the
	// sentence; "" for a refusal that needed no classifying.
	evidence string
}

func (t *waitError) Error() string {
	if t.evidence == "" {
		return t.what + ": " + t.kind.Error()
	}

	return t.what + ": " + t.kind.Error() + " [" + t.evidence + "]"
}

func (t *waitError) Unwrap() error { return t.kind }

// ThrottleRefusal builds the error a throttled read returns: what was
// being read, then the one sentence every leg says for a throttle, then
// the evidence that classified it (stele#383). The sentinel is
// unchanged — errors.Is(err, ErrThrottled) and the ladder read it
// exactly as before; the evidence is for the person reading the log.
func ThrottleRefusal(what string, t *Throttle) error {
	return &waitError{what: what, wait: t.Wait, kind: ErrThrottled, evidence: t.String()}
}

// transientRefusal builds the error a 429 returns: still transient —
// what a 429 MEANS is unchanged — but carrying the wait the host named,
// so the ladder pauses for the minute it was asked for rather than
// burning its budget in eighteen seconds.
func transientRefusal(what string, wait time.Duration) error {
	return &waitError{what: what, wait: wait, kind: errTransient}
}

// RetryWait is how long a ladder pauses before its next attempt: the
// wait the host NAMED when the previous refusal carried one — whichever
// refusal that was — and the caller's own backoff otherwise.
//
// Shared so the two forge readers cannot come to honour the forge's
// own number differently, while each keeps its own budget — the ladders
// mean different things (one waits out a transient, the other waits out
// a propagation) and only the host's number is common to both.
func RetryWait(prev error, fallback time.Duration) time.Duration {
	var t *waitError
	if errors.As(prev, &t) && t.wait > 0 {
		return t.wait
	}

	return fallback
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

// ghJSON is the REST accept type the JSON reads ask for.
const ghJSON = "application/vnd.github+json"

// DefaultServer is the public forge — the server a caller that names
// none reads, and whose git remotes a fetch reaches.
const DefaultServer = "https://github.com"

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
	return NewForServer(DefaultServer, token)
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
	if server == DefaultServer {
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
	ID          int64  `json:"id"`
	TagName     string `json:"tag_name"` //nolint:tagliatelle // the forge's own field name
	Name        string `json:"name"`
	HTMLURL     string `json:"html_url"` //nolint:tagliatelle // the forge's own field name
	Draft       bool   `json:"draft"`
	PublishedAt string `json:"published_at"` //nolint:tagliatelle // the forge's own field name
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"` //nolint:tagliatelle // the forge's own field name
	} `json:"assets"`
}

// Release is one published release, decoded to what a caller can act
// on: its identity, and the addresses its artifacts are served from.
// The tag is deliberately not echoed back — the caller named it, and
// a second copy of one fact is a pair that can disagree.
type Release struct {
	ID     int64
	Name   string
	URL    string
	Assets []ReleaseAsset
}

// ReleaseAsset is one published artifact and where it is served from.
type ReleaseAsset struct {
	Name string
	URL  string
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

// ReleaseByTag reads the release hanging on one tag, decoded. An
// absent release is reported, never raised: a tag carrying no release
// is exactly what an imported repository's history is full of, and
// the caller deciding what a previous release is needs to tell that
// apart from a forge it could not read.
func (c *Client) ReleaseByTag(owner, repo, tag string) (*Release, bool, error) {
	rel, ok, err := c.releaseAt(owner, repo, tag)
	if err != nil || !ok {
		return nil, false, err
	}

	out := &Release{
		ID: rel.ID, Name: rel.Name, URL: rel.HTMLURL,
		Assets: make([]ReleaseAsset, 0, len(rel.Assets)),
	}

	for _, a := range rel.Assets {
		out.Assets = append(out.Assets, ReleaseAsset{Name: a.Name, URL: a.URL})
	}

	return out, true, nil
}

// ReleaseDate implements Forge.
func (c *Client) ReleaseDate(owner, repo, tag string) (time.Time, error) {
	rel, ok, err := c.releaseAt(owner, repo, tag)
	if err != nil {
		return time.Time{}, err
	}

	if !ok {
		return time.Time{}, fmt.Errorf("gh: release %s/%s@%s: not found", owner, repo, tag)
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
	rel, ok, err := c.releaseAt(owner, repo, tag)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("gh: release %s/%s@%s: not found", owner, repo, tag)
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
			c.sleep(RetryWait(lastErr, time.Duration(attempt-1)*transientBackoff))
		}

		body, err := c.asset(owner, repo, tag, name)
		if !Retryable(err) {
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
	body, _, found, err := c.get(
		"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/contents/"+path+"?ref="+url.QueryEscape(ref),
		"application/vnd.github.raw+json",
	)
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
	body, _, ok, err := c.get(
		"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/attestations/sha256:"+sha256Hex+"?per_page=100",
		"application/vnd.github+json",
	)
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
	body, _, ok, err := c.get(
		"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/contents/"+WorkflowDir,
		"application/vnd.github+json",
	)
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
	body, _, ok, err := c.get(
		"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/actions/runs?branch="+url.QueryEscape(branch)+
			"&per_page=100",
		"application/vnd.github+json",
	)
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
		// The download host throttles with the same 403 the API does,
		// through the one classifier — a walk pulling many assets is
		// exactly the pace that earns one.
		if t, ok := Throttled(resp.StatusCode, resp.Header, body); ok {
			return nil, ThrottleRefusal(fmt.Sprintf("gh: asset %s: HTTP %d", u, resp.StatusCode), &t)
		}

		// The 429 the download host answers a rate limit with names its
		// own wait, read through the same one place the 403's is.
		if resp.StatusCode == http.StatusTooManyRequests {
			return nil, transientRefusal(
				fmt.Sprintf("gh: asset %s: HTTP %d", u, resp.StatusCode), RetryAfter(resp.Header),
			)
		}

		if resp.StatusCode >= http.StatusInternalServerError {
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
//
// The exception is the 403 that Throttled classifies as the host
// throttling this caller: that one is no answer about the subject at
// all, so it rides this ladder — pausing for the wait the host itself
// named, and for this ladder's own backoff when it named none.
//
// A 429 rides it on the same terms (stele#217): it needs no
// classifying, but it carries the same Retry-After, and a ladder that
// read the host's number for the ambiguous status and ignored it for
// the unambiguous one would end a walk in eighteen seconds against a
// host that asked for sixty.
//
// Beside the body it returns the forge's own pagination statement: the
// URL the response's Link header names as rel="next", or "" when it
// names none (stele#322). Only paged reads it; every other read is one
// document and ignores it.
//
//nolint:gocritic // unnamedResult: body, next, found, error
func (c *Client) get(path, accept string) ([]byte, string, bool, error) {
	return c.fetch(c.Base+path, path, accept)
}

// fetch is get's ladder over a whole URL: what names the read in its
// refusals. Split from get because a Link header's next URL is used as
// given, never rebuilt from a path.
//
//nolint:gocritic // unnamedResult: body, next, found, error
func (c *Client) fetch(target, what, accept string) ([]byte, string, bool, error) {
	var lastErr error

	for attempt := 1; attempt <= transientAttempts; attempt++ {
		if attempt > 1 {
			c.sleep(RetryWait(lastErr, time.Duration(attempt-1)*transientBackoff))
		}

		body, next, ok, err := c.once(target, what, accept)
		if !Retryable(err) {
			return body, next, ok, err
		}

		lastErr = err
	}

	return nil, "", false, fmt.Errorf("gh: %s: after %d attempts: %w", what, transientAttempts, lastErr)
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
// conflate; 5xx and 429 wrap errTransient for the retry above, and the
// 403 the classifier reads as a throttle wraps ErrThrottled for the
// same retry. A 429 stays transient and additionally carries the wait
// it named, which RetryWait hands the ladder. An answer also carries
// the Link header's next URL, "" when there is none.
//
//nolint:gocritic // unnamedResult: body, next, found, error
func (c *Client) once(target, path, accept string) ([]byte, string, bool, error) {
	//nolint:noctx // the CLI has no cancellation surface; the client carries the timeout
	req, err := http.NewRequest(http.MethodGet, target, http.NoBody)
	if err != nil {
		return nil, "", false, fmt.Errorf("gh: build request: %w", err)
	}

	req.Header.Set("Accept", accept)
	req.Header.Set("X-Github-Api-Version", "2022-11-28")

	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("gh: %s: %w", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // a read-only body close has nothing to report

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, "", false, fmt.Errorf("gh: %s: read: %w", path, err)
	}

	// Asked before the status vocabulary below, because the throttle is
	// the one refusal the status cannot name: the classifier owns which
	// statuses can carry it, so no case here restates that rule.
	if t, ok := Throttled(resp.StatusCode, resp.Header, body); ok {
		return nil, "", false, ThrottleRefusal(fmt.Sprintf("gh: %s: HTTP %d", path, resp.StatusCode), &t)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return body, nextLink(resp.Header), true, nil
	case http.StatusNotFound:
		return nil, "", false, nil
	case http.StatusForbidden, http.StatusUnauthorized:
		return nil, "", false, fmt.Errorf("gh: %s: HTTP %d: %w", path, resp.StatusCode, ErrForbidden)
	case http.StatusTooManyRequests:
		return nil, "", false, transientRefusal(
			fmt.Sprintf("gh: %s: HTTP %d", path, resp.StatusCode), RetryAfter(resp.Header),
		)
	default:
		// The status alone: the body is server-controlled prose.
		if resp.StatusCode >= http.StatusInternalServerError {
			return nil, "", false, fmt.Errorf("gh: %s: HTTP %d: %w", path, resp.StatusCode, errTransient)
		}

		return nil, "", false, fmt.Errorf("gh: %s: HTTP %d", path, resp.StatusCode)
	}
}

// paged reads every page of a listing endpoint, following the forge's
// own pagination statement. path carries no query of its own — the
// first request's query is per_page and the filters — and a caller
// needing a filter passes it here rather than pre-formatting it into
// the path.
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
// Termination is the forge's statement, never an inference (#322).
// Each response's Link header either names the rel="next" page — which
// is requested exactly as given, filters and all, because the forge
// wrote it — or names none, and then the walk is complete. Two earlier
// rules inferred the end from content: the empty array, then the short
// page (#154). Both assumed an endpoint that honours page, and
// `git/matching-refs/tags/` does not: it answers every request with
// the same full array, so a repository with 100 or more tags never
// served a short page and walked to the bound. The forge sends no
// next link there, which is the whole answer.
//
// maxPages is the backstop against a forge that links in a circle. A
// next URL off the API's own origin refuses: the request carries the
// credential, and a link is not a reason to hand it to another host.
func (c *Client) paged(path string, filters ...string) ([][]byte, error) {
	const maxPages = 50
	// perPage is the page size asked for on the first request. The
	// forge carries it into the next links it writes.
	const perPage = 100

	if strings.Contains(path, "?") {
		return nil, fmt.Errorf("gh: %s: the path carries its own query; pass filters as arguments so"+
			" pagination owns the query string", path)
	}

	query := fmt.Sprintf("%s?per_page=%d", path, perPage)
	if len(filters) > 0 {
		query += "&" + strings.Join(filters, "&")
	}

	target, what := c.Base+query, query

	var pages [][]byte

	for page := 1; ; page++ {
		if page > maxPages {
			return nil, fmt.Errorf("gh: %s: pagination did not converge in %d pages", path, maxPages)
		}

		body, next, ok, err := c.fetch(target, what, "application/vnd.github+json")
		if err != nil {
			return nil, err
		}

		if !ok {
			return nil, fmt.Errorf("gh: %s: not found", path)
		}

		// Every paginated endpoint here answers with a JSON array; a body
		// that is not one is a refusal by name, never a page handed to a
		// caller that will misread it.
		if _, derr := jsonx.DecodeForeign[[]jsonx.Raw](body); derr != nil {
			return nil, fmt.Errorf("gh: %s: page %d is not a JSON array: %w", path, page, derr)
		}

		pages = append(pages, body)

		if next == "" {
			return pages, nil
		}

		if !sameOrigin(next, c.Base) {
			return nil, fmt.Errorf("gh: %s: page %d links its next page off the API origin %s", path, page, c.Base)
		}

		target, what = next, next
	}
}

// linkEntry is one <URL>; params entry of a Link header (RFC 8288).
var linkEntry = regexp.MustCompile(`<([^>]*)>([^,<]*)`)

// relParam is a rel parameter, quoted or bare.
var relParam = regexp.MustCompile(`(?i);\s*rel\s*=\s*(?:"([^"]*)"|([^\s;,]+))`)

// nextLink returns the URL a response's Link headers name as
// rel="next", or "" when none does. A rel may carry several
// space-separated relation types.
func nextLink(header http.Header) string {
	for _, value := range header.Values("Link") {
		for _, entry := range linkEntry.FindAllStringSubmatch(value, -1) {
			for _, rel := range relParam.FindAllStringSubmatch(entry[2], -1) {
				for kind := range strings.FieldsSeq(rel[1] + " " + rel[2]) {
					if strings.EqualFold(kind, "next") {
						return entry[1]
					}
				}
			}
		}
	}

	return ""
}

// sameOrigin reports whether link shares base's scheme and host.
func sameOrigin(link, base string) bool {
	l, lerr := url.Parse(link)
	b, berr := url.Parse(base)

	return lerr == nil && berr == nil && l.Scheme == b.Scheme && l.Host == b.Host
}

// releaseAt reads the release hanging on one tag. The bool is "the
// forge has one": a bare tag with nothing published on it is a state
// a caller may act on, and the callers for which it IS a failure say
// so themselves.
//
// One fetch, one decode, three readers — the publication date, the
// asset names, and the whole decoded release. Which release hangs on
// a tag is one question, so it has one answer; three copies of this
// endpoint could drift apart on field spellings or on what an absent
// release means, and the two nobody was reading at the time would
// drift silently.
//
// Drafts do not arrive here, and not by a filter of ours: the forge's
// by-tag read serves published releases only. That is the answer this
// caller wants — a draft's assets are not fetchable by a stranger, so
// a caller asking where artifacts live must never be handed one.
func (c *Client) releaseAt(owner, repo, tag string) (*releaseEntry, bool, error) {
	body, _, ok, err := c.get(
		"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/releases/tags/"+url.PathEscape(tag),
		"application/vnd.github+json",
	)
	if err != nil {
		return nil, false, err
	}

	if !ok {
		return nil, false, nil
	}

	rel, err := jsonx.DecodeForeign[releaseEntry](body)
	if err != nil {
		return nil, false, fmt.Errorf("gh: release %s/%s@%s: %w", owner, repo, tag, err)
	}

	return rel, true, nil
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
