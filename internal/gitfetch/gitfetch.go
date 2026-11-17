// Package gitfetch fetches the git objects a walk judges (stele#384):
// a temporary bare repository, filled with ONE fetch of what the walk
// needs, read through internal/gitrepo, and removed when the walk
// ends. Git is the only way stele reads git objects; this package is
// the one place that brings them down, and internal/gitrepo stays a
// reader that never networks on its own.
//
// What is fetched is the walk's question and nothing more: branches
// and tags commits-only (`--filter=tree:0`), the notes ref whole — its
// tip's tree holds every note, and fetching it at any depth would mark
// the repository shallow, which every history read refuses. No source
// tree or blob is ever requested: the only blobs are notes.
//
// The credential never reaches a command line or a file. It travels as
// an http.extraheader through git's environment configuration, no
// credential helper or prompt may run, and a public repository is
// fetched with no credential at all.
package gitfetch

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/gitrepo"
)

// MinVersion is the oldest git stele reads git objects with: the
// release that added GIT_NO_LAZY_FETCH. Over a commits-only fetch,
// ordinary reads reach for withheld trees, and only that switch stops
// git fetching them on demand (measured, stele#384) — an older git
// would quietly download source no walk asked for. Protocol v2 with
// filters is older still, so this one floor carries both.
const MinVersion = "2.44.0"

// ErrFetch marks a fetch that did not complete. The walk could not see
// the repository's history, which says nothing about the subject: a
// caller reads it as "could not judge", never as a finding.
var ErrFetch = errors.New("the repository's history could not be fetched, which says nothing about the subject")

// ErrGit marks a machine whose git cannot do this job — absent, or
// older than MinVersion. A refusal by name, never a verdict and never
// a fallback: there is no second reader of git objects to fall back to.
var ErrGit = errors.New("stele reads git objects with git " + MinVersion + " or newer")

// filterIgnoredRE is what git prints when the remote does not honour
// the filter it was asked for. The walk stays correct — git fetches the
// unfiltered objects instead — but the download is larger, so it is
// repeated and counted rather than swallowed.
var filterIgnoredRE = regexp.MustCompile(`(?i)filtering not recognized by server`)

// httpStatusRE finds the HTTP status git reports for a refused request,
// in either of the two forms it prints.
var httpStatusRE = regexp.MustCompile(`(?:returned error:|RPC failed; HTTP) (\d{3})`)

// The retry ladder: bounded, like every other host read's, so a walk
// against a broken host still ends.
const (
	attempts = 4
	backoff  = 3 * time.Second
)

// Want names what one walk needs from one repository.
type Want struct {
	// Branches are fully qualified branch refs, fetched commits-only. A
	// branch the remote does not have is not fetched; a read of it then
	// refuses, as a read of any absent ref does.
	Branches []string
	// Heads fetches every branch, commits-only — for a walk whose
	// policy names no branch but whose ledger annotates them.
	Heads bool
	// NotesRef is the ledger, fetched whole when the remote has it. A
	// remote without it is an empty ledger: an answer, not a failure.
	NotesRef string
	// Tags fetches every tag, commits-only.
	Tags bool
	// Shallow fetches branches and tags at depth one: a walk that only
	// resolves a tag to its target needs no history behind it.
	Shallow bool
}

// Fetcher runs the fetches. The zero value uses the git on PATH.
type Fetcher struct {
	// Git is the git executable; "" means "git".
	Git string
	// Sleep is the retry clock; nil means time.Sleep.
	Sleep func(time.Duration)
}

// Fetched is one fetched repository, open for reading until Close.
type Fetched struct {
	// Repo reads the fetched objects; it never networks.
	Repo *gitrepo.Repo
	// FilterIgnored reports that the remote ignored the commits-only
	// filter: the objects are correct, the download was larger.
	FilterIgnored bool
	dir           string
}

// Close removes the repository: nothing is left behind.
func (f *Fetched) Close() error {
	if err := os.RemoveAll(f.dir); err != nil {
		return fmt.Errorf("gitfetch: removing %s: %w", f.dir, err)
	}

	return nil
}

// Check refuses a machine whose git cannot do this job, by name.
func (f *Fetcher) Check() error {
	//nolint:gosec,noctx // the configured git executable, a fixed argument; no cancellation surface
	out, err := exec.Command(f.git(), "version").Output()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("gitfetch: git is not installed — %w", ErrGit)
		}

		return fmt.Errorf("gitfetch: running %s version: %w — %w", f.git(), err, ErrGit)
	}

	have, ok := parseVersion(string(out))
	if !ok {
		return fmt.Errorf("gitfetch: `git version` answered %q, which names no version — %w",
			strings.TrimSpace(string(out)), ErrGit)
	}

	if older(have, minVersion()) {
		return fmt.Errorf("gitfetch: git %d.%d.%d is too old — %w", have[0], have[1], have[2], ErrGit)
	}

	return nil
}

// parseVersion reads "git version 2.50.1 (Apple Git-155)" or
// "git version 2.44.0.windows.1" as its three leading numbers.
func parseVersion(out string) ([3]int, bool) {
	var v [3]int

	rest, found := strings.CutPrefix(strings.TrimSpace(out), "git version ")
	if !found {
		return v, false
	}

	fields := strings.SplitN(strings.Fields(rest + " ")[0], ".", len(v)+1)
	if len(fields) < len(v) {
		return v, false
	}

	for i := range v {
		n, err := strconv.Atoi(fields[i])
		if err != nil || n < 0 {
			return v, false
		}

		v[i] = n
	}

	return v, true
}

// minVersion is MinVersion as numbers — read from the one spelling of
// it, so the floor named in a refusal and the floor enforced are one.
func minVersion() [3]int {
	v, _ := parseVersion("git version " + MinVersion)

	return v
}

// older reports whether a precedes b.
func older(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}

	return false
}

// Fetch brings down what want names from remote into a temporary bare
// repository and opens it. The caller closes it when the walk ends.
//
// token is "" for a public repository: nothing is sent at all.
func (f *Fetcher) Fetch(remote, token string, want Want) (*Fetched, error) {
	if err := validate(want); err != nil {
		return nil, err
	}

	if err := f.Check(); err != nil {
		return nil, err
	}

	dir, err := os.MkdirTemp("", "stele-git-")
	if err != nil {
		return nil, fmt.Errorf("gitfetch: %w", err)
	}

	fetched, err := f.fill(dir, remote, token, want)
	if err != nil {
		_ = os.RemoveAll(dir) //nolint:errcheck // the fetch failed; its refusal is the one to report

		return nil, err
	}

	return fetched, nil
}

func (f *Fetcher) git() string {
	if f.Git == "" {
		return "git"
	}

	return f.Git
}

func (f *Fetcher) sleep(d time.Duration) {
	if f.Sleep != nil {
		f.Sleep(d)

		return
	}

	time.Sleep(d)
}

// validate refuses a want that is not refs: every value here reaches
// git's argument vector, and a value that is not a ref has no business
// there.
func validate(want Want) error {
	for _, b := range want.Branches {
		if !strings.HasPrefix(b, "refs/heads/") || strings.ContainsAny(b, "*: ") {
			return fmt.Errorf("gitfetch: %q is not a fully qualified branch ref", b)
		}
	}

	if want.NotesRef != "" && (!strings.HasPrefix(want.NotesRef, "refs/") || strings.ContainsAny(want.NotesRef, "*: ")) {
		return fmt.Errorf("gitfetch: notes ref %q is not fully qualified", want.NotesRef)
	}

	if len(want.Branches) == 0 && !want.Heads && !want.Tags {
		return errors.New("gitfetch: the want names no branch and no tag — nothing to fetch history for")
	}

	return nil
}

func (f *Fetcher) fill(dir, remote, token string, want Want) (*Fetched, error) {
	// The remote is a promisor: a filtered fetch needs it named in
	// config, and git records the filter beside it. The URL carries no
	// credential, so the config holds none.
	if err := f.run("init", "-q", "--bare", dir); err != nil {
		return nil, fmt.Errorf("gitfetch: preparing %s: %w", dir, err)
	}

	for _, kv := range [][2]string{
		{"remote.origin.url", remote},
		{"remote.origin.promisor", "true"},
		{"extensions.partialClone", "origin"},
	} {
		if err := f.run("-C", dir, "config", kv[0], kv[1]); err != nil {
			return nil, fmt.Errorf("gitfetch: preparing %s: %w", dir, err)
		}
	}

	env := gitrepo.AuthEnv(remote, token)

	present, err := f.present(dir, remote, env, want)
	if err != nil {
		return nil, err
	}

	fetched := &Fetched{dir: dir}

	if specs := commitSpecs(want, present); len(specs) > 0 {
		args := []string{"-C", dir, "fetch", "-q", "--no-tags", "--filter=tree:0"}
		if want.Shallow {
			args = append(args, "--depth=1")
		}

		_, stderr, ferr := f.network(env, remote, append(append(args, "origin"), specs...)...)
		if ferr != nil {
			return nil, ferr
		}

		fetched.FilterIgnored = filterIgnoredRE.Match(stderr)
	}

	if want.NotesRef != "" && present[want.NotesRef] {
		spec := "+" + want.NotesRef + ":" + want.NotesRef
		_, stderr, ferr := f.network(env, remote, "-C", dir, "fetch", "-q", "--no-tags", "--no-filter", "origin", spec)
		if ferr != nil {
			return nil, ferr
		}

		fetched.FilterIgnored = fetched.FilterIgnored || filterIgnoredRE.Match(stderr)
	}

	if want.NotesRef == "" {
		fetched.Repo, err = gitrepo.OpenObjects(dir)
	} else {
		fetched.Repo, err = gitrepo.Open(dir, want.NotesRef)
	}

	if err != nil {
		return nil, fmt.Errorf("gitfetch: %w", err)
	}

	return fetched, nil
}

// present asks the remote which of the exact refs the want names it
// has — one round trip, so an absent branch or ledger is an answer
// rather than a failed fetch.
func (f *Fetcher) present(dir, remote string, env []string, want Want) (map[string]bool, error) {
	exact := append([]string{}, want.Branches...)
	if want.NotesRef != "" {
		exact = append(exact, want.NotesRef)
	}

	present := map[string]bool{}
	if len(exact) == 0 {
		return present, nil
	}

	out, _, err := f.network(env, remote, append([]string{"-C", dir, "ls-remote", "--refs", "origin"}, exact...)...)
	if err != nil {
		return nil, err
	}

	for line := range strings.Lines(string(out)) {
		if _, ref, found := strings.Cut(strings.TrimSpace(line), "\t"); found {
			present[ref] = true
		}
	}

	return present, nil
}

// commitSpecs are the refspecs fetched commits-only.
func commitSpecs(want Want, present map[string]bool) []string {
	var specs []string

	for _, b := range want.Branches {
		if present[b] {
			specs = append(specs, "+"+b+":"+b)
		}
	}

	if want.Heads {
		specs = append(specs, "+refs/heads/*:refs/heads/*")
	}

	if want.Tags {
		specs = append(specs, "+refs/tags/*:refs/tags/*")
	}

	return specs
}

// network runs one command that reaches the remote, on the ladder: a
// throttle or a failing host is retried, anything else refuses at
// once. Every refusal names the remote and wraps ErrFetch.
//
//nolint:gocritic // unnamedResult: stdout, stderr, error
func (f *Fetcher) network(env []string, remote string, args ...string) ([]byte, []byte, error) {
	var lastErr error

	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			f.sleep(gh.RetryWait(lastErr, time.Duration(attempt-1)*backoff))
		}

		stdout, stderr, err := f.runEnv(env, args...)
		if err == nil {
			return stdout, stderr, nil
		}

		lastErr = classify(stderr, err)
		if !retryable(lastErr) {
			return nil, nil, fmt.Errorf("gitfetch: %s: %w: %w", remote, ErrFetch, lastErr)
		}
	}

	return nil, nil, fmt.Errorf("gitfetch: %s: %w: after %d attempts: %w", remote, ErrFetch, attempts, lastErr)
}

// errTransient marks a host failing rather than refusing: retried.
var errTransient = errors.New("the host failed")

func retryable(err error) bool {
	return errors.Is(err, gh.ErrThrottled) || errors.Is(err, errTransient)
}

// classify types one failed network command from what git printed. A
// status the HTTP standard names a throttle is one, through the same
// shape every host's throttle takes (stele#383) — git surfaces no rate
// headers, so they print absent. A server error is the host failing.
// Anything else is git's own last word, kept for the person reading.
func classify(stderr []byte, err error) error {
	what := lastLine(stderr)

	if m := httpStatusRE.FindSubmatch(stderr); m != nil {
		status, _ := strconv.Atoi(string(m[1])) //nolint:errcheck // three digits, by the pattern

		if throttle := gh.HostThrottle(fmt.Sprintf("HTTP %d", status), status, nil, nil); throttle != nil {
			return throttle
		}

		if status >= http.StatusInternalServerError {
			return fmt.Errorf("HTTP %d: %s: %w", status, what, errTransient)
		}

		return fmt.Errorf("HTTP %d: %s", status, what)
	}

	if what == "" {
		return fmt.Errorf("git: %w", err)
	}

	return fmt.Errorf("git: %s", what)
}

// lastLine is git's own statement of why it stopped: its first fatal
// line — what follows it is advice — else its first error, else the
// last line it wrote.
func lastLine(stderr []byte) string {
	lines := strings.Split(strings.TrimSpace(string(stderr)), "\n")

	for _, prefix := range []string{"fatal:", "error:"} {
		for _, line := range lines {
			if line = strings.TrimSpace(line); strings.HasPrefix(line, prefix) {
				return line
			}
		}
	}

	return strings.TrimSpace(lines[len(lines)-1])
}

// run is runEnv with no extra environment, for the local commands that
// prepare the repository. Their arguments carry no credential, so the
// refusal may name them.
func (f *Fetcher) run(args ...string) error {
	if _, stderr, err := f.runEnv(nil, args...); err != nil {
		return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, lastLine(stderr))
	}

	return nil
}

// runEnv runs one git command under the hermetic environment plus the
// extras given.
//
//nolint:gocritic // unnamedResult: stdout, stderr, error
func (f *Fetcher) runEnv(extra []string, args ...string) ([]byte, []byte, error) {
	//nolint:gosec,noctx // the configured git executable, args built from validated refs; no cancellation surface
	cmd := exec.Command(f.git(), args...)
	cmd.Env = gitrepo.Env(extra...)

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	return stdout.Bytes(), stderr.Bytes(), err
}
