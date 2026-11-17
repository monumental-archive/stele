package assert_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/ctlog"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/population"
	"github.com/monumental-archive/stele/internal/report"
)

// The issuer every captured certificate names.
const githubIssuer = "https://token.actions.githubusercontent.com"

// The roster the capture's org declares: the canon, the signer and
// this repository.
var captureRoster = []string{".github", "signer", "stele"}

// oneSigner is the canon's watch: sign.yml, called through the canon.
var oneSigner = fmt.Sprintf(`[{"workflow": %q, "callers": [%q]}]`, captureSignYML, captureCanon)

// signersPolicy is an assert policy declaring the watch over logURL,
// with a population of the roster's names.
func signersPolicy(t *testing.T, logURL, issuer, signers string, roster []string) *assert.Policy {
	t.Helper()

	repos := make([]string, 0, len(roster))
	for _, r := range roster {
		repos = append(repos, fmt.Sprintf(`{"repo": %q}`, r))
	}

	return signersPolicyOver(t, logURL, issuer, signers, `{"repositories": [`+strings.Join(repos, ", ")+`]}`)
}

// signersPolicyOver is the same policy over any population section.
func signersPolicyOver(t *testing.T, logURL, issuer, signers, pop string) *assert.Policy {
	t.Helper()

	doc := fmt.Sprintf(`{
  "schema": 8,
  "issuer": %q,
  "population": %s,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "classes": {"go-binary": {"bundles": ["attestations.intoto.jsonl"]}}
  },
  "signerCertificates": {"log": %q, "signers": %s}
}`, issuer, pop, logURL, signers)

	pol, err := assert.LoadPolicy(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	return pol
}

// rosterLister lists exactly the names it holds, so a closed roster
// over the same names reconciles.
type rosterLister []string

func (l rosterLister) ListRepos(string) ([]gh.Repo, error) {
	out := make([]gh.Repo, 0, len(l))
	for _, name := range l {
		out = append(out, gh.Repo{Name: name})
	}

	return out, nil
}

// harness is one watch over a fake log and the capture's forge, with
// its checkpoint in a file and every save recorded.
type harness struct {
	t      *testing.T
	log    *fakeLog
	forge  *captureForge
	clock  *fakeClock
	pol    *assert.Policy
	cpPath string
	chunk  uint64
	budget time.Duration
	// listing, when set, is what the forge lists instead of the roster.
	listing []string
	// failSavesAfter, when positive, fails every save after that many.
	failSavesAfter int
	// trusted, when set, is the trusted material instead of the log's.
	trusted ctlog.LogSource

	mu       sync.Mutex
	saves    []uint64
	progress []string
}

func newHarness(t *testing.T, leaves [][]byte) *harness {
	t.Helper()

	log := newFakeLog(t, leaves)

	return &harness{
		t:      t,
		log:    log,
		forge:  newCaptureForge(t),
		clock:  newFakeClock(),
		pol:    signersPolicy(t, log.url(), githubIssuer, oneSigner, captureRoster),
		cpPath: filepath.Join(t.TempDir(), "checkpoint.json"),
		chunk:  1000,
		budget: 20 * time.Minute,
	}
}

// lastSaved is the next the checkpoint file was last written with.
func (h *harness) lastSaved() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.saves) == 0 {
		h.t.Fatal("nothing was saved")
	}

	return h.saves[len(h.saves)-1]
}

// run is one invocation: from the checkpoint file when it exists,
// else founding at startAt.
func (h *harness) run(startAt uint64) (*report.Report, error) {
	h.t.Helper()

	cp, err := ctlog.ReadCheckpoint(h.cpPath)
	if err != nil && !errors.Is(err, ctlog.ErrNoCheckpoint) {
		h.t.Fatal(err)
	}

	trusted := h.trusted
	if trusted == nil {
		trusted = h.log.logs()
	}

	verifier, err := ctlog.NewVerifier(trusted, h.log.url())
	if err != nil {
		h.t.Fatal(err)
	}

	listing := h.listing
	if listing == nil {
		listing = rosterOf(h.pol)
	}

	pop, err := population.Scope{Org: captureOwner}.Resolve(rosterLister(listing), h.pol.Population)
	if err != nil {
		h.t.Fatal(err)
	}

	w := &assert.SignerWatch{
		Policy:     h.pol,
		Population: pop,
		Server:     "https://github.com",
		Log:        h.log.client(h.clock, h.budget),
		Verifier:   verifier,
		Forge:      h.forge,
		Checkpoint: cp,
		StartAt:    startAt,
		Save: func(next *ctlog.Checkpoint) error {
			h.mu.Lock()
			if h.failSavesAfter > 0 && len(h.saves) >= h.failSavesAfter {
				h.mu.Unlock()

				return errors.New("the disk is full")
			}

			h.saves = append(h.saves, next.Next)
			h.mu.Unlock()

			return ctlog.WriteCheckpoint(h.cpPath, next)
		},
		Chunk: h.chunk,
		Progress: func(format string, args ...any) {
			h.mu.Lock()
			defer h.mu.Unlock()

			h.progress = append(h.progress, fmt.Sprintf(format, args...))
		},
	}

	return assert.SignerCertificates(context.Background(), w, report.NewJournal())
}

func rosterOf(pol *assert.Policy) []string {
	var out []string
	for _, e := range pol.Population.Repositories {
		out = append(out, *e.Repo)
	}

	return out
}

// fact reads one named fact off a report.
func fact(t *testing.T, rep *report.Report, name string) string {
	t.Helper()

	var buf strings.Builder
	if err := rep.Encode(&buf); err != nil {
		t.Fatal(err)
	}

	doc := buf.String()

	key := fmt.Sprintf(`{"name":%q,"value":`, name)

	i := strings.Index(doc, key)
	if i < 0 {
		t.Fatalf("the report carries no %s fact: %s", name, doc)
	}

	rest := doc[i+len(key):]

	value, err := strconv.QuotedPrefix(rest)
	if err != nil {
		t.Fatal(err)
	}

	out, err := strconv.Unquote(value)
	if err != nil {
		t.Fatal(err)
	}

	return out
}

// entryRequests are the get-entries requests a log saw, as ranges.
func entryRequests(reqs []string) []string {
	var out []string

	for _, r := range reqs {
		if strings.HasPrefix(r, "entries ") {
			out = append(out, r)
		}
	}

	return out
}

// startOf is the start index of an "entries a..b" request.
func startOf(t *testing.T, req string) uint64 {
	t.Helper()

	a, _, _ := strings.Cut(strings.TrimPrefix(req, "entries "), "..")

	n, err := strconv.ParseUint(a, 10, 64)
	if err != nil {
		t.Fatal(err)
	}

	return n
}

// withLeaf is leaves with one entry replaced.
func withLeaf(leaves [][]byte, at int, leaf []byte) [][]byte {
	out := slices.Clone(leaves)
	out[at] = leaf

	return out
}

// TestSignerWatchFollowsCappedPagesToTheEnd: the log caps each answer
// at the next multiple of a hundred, as ctfe.sigstore.dev caps at a
// thousand. The reader advances by what each answer carried, ends at
// tree_size-1, never asks past it, and checkpoints after every chunk.
func TestSignerWatchFollowsCappedPagesToTheEnd(t *testing.T) {
	t.Parallel()

	const size, start, at = 2345, 17, 1500

	h := newHarness(t, withLeaf(fillerLeaves(size), at, capturedLeaf(t, releaseIndex)))
	h.log.align = 100

	rep, err := h.run(start)
	if err != nil {
		t.Fatal(err)
	}

	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, findings %+v", rep.Verdict(), rep.Findings())
	}

	reqs := entryRequests(h.log.seen())

	// Each request starts where the last answer ended, and asks to the
	// end of its chunk: 17 → 100 → … → 1000 is the first chunk's
	// end at 1017, so the next request starts at 1000 and stops at 1016.
	var want []string

	for pos := uint64(start); pos < size; {
		chunkEnd := min(start+((pos-start)/h.chunk+1)*h.chunk, size)
		want = append(want, entriesRange(pos, chunkEnd-1))
		pos = min((pos/100+1)*100, chunkEnd)
	}

	if !slices.Equal(reqs, want) {
		t.Fatalf("get-entries requests:\n got %q\nwant %q", reqs, want)
	}

	if last := reqs[len(reqs)-1]; !strings.HasSuffix(last, fmt.Sprintf("..%d", size-1)) {
		t.Fatalf("the last request %q does not end at tree_size-1", last)
	}

	if !slices.Equal(h.saves, []uint64{start, 1017, 2017, size}) {
		t.Fatalf("checkpoint saves = %v, want the founding and one per chunk", h.saves)
	}

	for name, want := range map[string]string{
		"judged":      fmt.Sprintf("%d..%d", start, size-1),
		"outstanding": "none",
		"entriesRead": strconv.Itoa(size - start),
		"matches":     "1",
		"reconciled":  "1",
	} {
		if got := fact(t, rep, name); got != want {
			t.Errorf("fact %s = %q, want %q", name, got, want)
		}
	}
}

// TestSignerWatchRefusesAnEmptyPage: an answer with no entries before
// the end is an error, never a loop — asked once, and the run stops at
// its last done chunk.
func TestSignerWatchRefusesAnEmptyPage(t *testing.T) {
	t.Parallel()

	h := newHarness(t, fillerLeaves(3000))
	h.log.align = 500
	h.log.hook = func(w http.ResponseWriter, kind string, before int) bool {
		if kind != "entries" || before != 3 {
			return false
		}

		h.log.sendJSON(w, struct {
			Entries []entryDoc `json:"entries"`
		}{Entries: []entryDoc{}})

		return true
	}

	rep, err := h.run(0)
	if err != nil {
		t.Fatal(err)
	}

	if rep.Verdict() != report.VerdictCannotJudge {
		t.Fatalf("verdict = %s, want CANNOT_JUDGE", rep.Verdict())
	}

	// Requests 0..999 (two pages), 1000..1999 (two pages); the fourth,
	// 1500..1999, answered empty.
	reqs := entryRequests(h.log.seen())
	if want := []string{
		entriesRange(0, 999), entriesRange(500, 999), entriesRange(1000, 1999), entriesRange(1500, 1999),
	}; !slices.Equal(reqs, want) {
		t.Fatalf("get-entries requests = %q, want %q (the empty page asked once)", reqs, want)
	}

	if h.lastSaved() != 1000 {
		t.Fatalf("the checkpoint is at %d, want 1000: the chunk holding the empty page is not done", h.lastSaved())
	}

	stopped := fact(t, rep, "stopped")
	if !strings.HasPrefix(stopped, "incomplete: ") || !strings.Contains(stopped,
		"the log answered get-entries with no entries before the end of the range: get-entries 1500..1999") {
		t.Fatalf("stopped = %q, want the empty page named with its range", stopped)
	}

	if got := fact(t, rep, "outstanding"); got != "1000..2999" {
		t.Fatalf("outstanding = %q, want 1000..2999", got)
	}
}

// TestSignerWatchThrottled: a 429 after k pages is waited out on the
// ladder until the budget ends; the checkpoint stays at the last done
// chunk, and the run is CANNOT_JUDGE — never a judgment of anything.
func TestSignerWatchThrottled(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		retryAfter string
		slept      []time.Duration
		throttled  string
		evidence   string
	}{
		{
			name: "no wait named: the ladder backs off from 5s, doubling to a minute",
			evidence: "[marker: http-429; x-ratelimit-remaining: absent; x-ratelimit-reset: absent; " +
				"x-ratelimit-resource: absent; retry-after: absent]",
			slept: []time.Duration{
				5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second,
				60 * time.Second, 60 * time.Second, 60 * time.Second,
			},
			throttled: "8",
		},
		{
			name:       "a named wait is honoured",
			retryAfter: "30",
			evidence: `[marker: http-429; x-ratelimit-remaining: absent; x-ratelimit-reset: absent; ` +
				`x-ratelimit-resource: absent; retry-after: "30"]`,
			slept:     slices.Repeat([]time.Duration{30 * time.Second}, 9),
			throttled: "10",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, fillerLeaves(4000))
			h.log.align = 500
			h.budget = 5 * time.Minute
			h.log.hook = throttleAfter(5, tc.retryAfter)

			rep, err := h.run(0)
			if err != nil {
				t.Fatal(err)
			}

			if rep.Verdict() != report.VerdictCannotJudge {
				t.Fatalf("verdict = %s, want CANNOT_JUDGE", rep.Verdict())
			}

			// Five pages are two whole chunks and half of the third.
			if h.lastSaved() != 2000 {
				t.Fatalf("the checkpoint is at %d, want 2000 — the last done chunk", h.lastSaved())
			}

			if got := h.clock.Slept(); !slices.Equal(got, tc.slept) {
				t.Fatalf("waits = %v, want %v", got, tc.slept)
			}

			stopped := fact(t, rep, "stopped")
			for _, want := range []string{
				"budget: ctlog: the run's budget ended waiting",
				"get-entries 2500..2999: HTTP 429: the host throttled this walk, which says nothing about the subject",
				tc.evidence,
			} {
				if !strings.Contains(stopped, want) {
					t.Errorf("stopped = %q, want it to say %q", stopped, want)
				}
			}

			if got := fact(t, rep, "throttled"); got != tc.throttled {
				t.Errorf("throttled = %s, want %s", got, tc.throttled)
			}

			if got := fact(t, rep, "outstanding"); got != "2000..3999" {
				t.Errorf("outstanding = %q, want 2000..3999", got)
			}

			if len(rep.Findings()) != 0 {
				t.Errorf("a throttle produced findings: %+v", rep.Findings())
			}
		})
	}
}

// TestSignerWatchResumesAtNext: the run after a throttled one resumes
// at the checkpoint's next, proves the grown log consistent with the
// head it recorded, and re-reads nothing before next.
func TestSignerWatchResumesAtNext(t *testing.T) {
	t.Parallel()

	leaves := withLeaf(fillerLeaves(3200), 2100, capturedLeaf(t, releaseIndex))

	h := newHarness(t, leaves)
	h.log.align = 500
	h.log.grow(2500)
	h.log.hook = throttleAfter(2, "")
	h.budget = time.Minute

	first, err := h.run(0)
	if err != nil {
		t.Fatal(err)
	}

	if first.Verdict() != report.VerdictCannotJudge || h.lastSaved() != 1000 {
		t.Fatalf("first run: verdict %s, checkpoint %d — want CANNOT_JUDGE at 1000", first.Verdict(), h.lastSaved())
	}

	h.log.hook = nil
	h.log.grow(3200)
	h.log.mu.Lock()
	h.log.requests = nil
	h.log.mu.Unlock()

	second, err := h.run(0)
	if err != nil {
		t.Fatal(err)
	}

	if second.Verdict() != report.VerdictPass {
		t.Fatalf("second run: verdict %s, findings %+v", second.Verdict(), second.Findings())
	}

	reqs := h.log.seen()
	if reqs[0] != "sth" || reqs[1] != "consistency 2500..3200" {
		t.Fatalf("the second run began %q, want the head and its consistency with the checkpoint's", reqs[:2])
	}

	entries := entryRequests(reqs)
	if startOf(t, entries[0]) != 1000 {
		t.Fatalf("the second run's first read is %q, want it to start at next, 1000", entries[0])
	}

	for _, r := range entries {
		if startOf(t, r) < 1000 {
			t.Fatalf("the second run re-read %q, before next", r)
		}
	}

	if got := fact(t, second, "judged"); got != "1000..3199" {
		t.Fatalf("judged = %q, want 1000..3199", got)
	}
}

// TestSignerWatchRefusesAnInconsistentTreeHead: a head that does not
// extend the checkpoint's is refused by name, before any entry is read
// and without touching the checkpoint.
func TestSignerWatchRefusesAnInconsistentTreeHead(t *testing.T) {
	t.Parallel()

	forked := fillerLeaves(1500)
	forked[500] = []byte("a rewritten entry")

	cases := []struct {
		name string
		edit func(l *fakeLog)
		want string
	}{
		{
			name: "a forked history",
			edit: func(l *fakeLog) { l.forked = treeOf(forked); l.size = 1500 },
			want: "the proof from size 1000 to 1500 does not verify",
		},
		{
			name: "a tree of the same size with another root",
			edit: func(l *fakeLog) { l.forked = treeOf(forked) },
			want: "two trees of size 1000 with different root hashes",
		},
		{
			name: "a log that shrank",
			edit: func(l *fakeLog) { l.size = 900 },
			want: "the log's tree of size 900 is smaller than the checkpoint's 1000",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, fillerLeaves(1500))
			h.log.grow(1000)

			if _, err := h.run(1000); err != nil {
				t.Fatal(err)
			}

			saves := len(h.saves)

			h.log.mu.Lock()
			tc.edit(h.log)
			h.log.requests = nil
			h.log.mu.Unlock()

			_, err := h.run(0)
			if !errors.Is(err, ctlog.ErrInconsistent) {
				t.Fatalf("err = %v, want ErrInconsistent", err)
			}

			for _, want := range []string{"is not consistent with the checkpoint's", tc.want} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("err = %q, want it to say %q", err, want)
				}
			}

			if len(entryRequests(h.log.seen())) != 0 || len(h.saves) != saves {
				t.Fatalf("an inconsistent head read %q and saved %v", h.log.seen(), h.saves[saves:])
			}
		})
	}
}

// TestSignerWatchHoldsOneChunk reads 100,000 entries in chunks of
// 10,000 and asserts, at every page the log sends, that what the
// reader has been sent but not yet judged — sent, minus what the
// checkpoint has moved past — is never more than one chunk. A counter
// in the fake log's seam, not a memory measurement.
func TestSignerWatchHoldsOneChunk(t *testing.T) {
	t.Parallel()

	const size, chunk = 100_000, 10_000

	if assert.SignerChunk != chunk {
		t.Fatalf("SignerChunk = %d, want the issue's %d", assert.SignerChunk, chunk)
	}

	h := newHarness(t, fillerLeaves(size))
	h.log.align = 1000
	h.chunk = 0 // the production chunk, not a test's

	var held, most uint64

	h.log.onEntriesSent = func(served uint64) {
		h.mu.Lock()
		defer h.mu.Unlock()

		judged := uint64(0)
		if len(h.saves) > 0 {
			judged = h.saves[len(h.saves)-1]
		}

		held = served - judged
		most = max(most, held)
	}

	rep, err := h.run(0)
	if err != nil {
		t.Fatal(err)
	}

	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s", rep.Verdict())
	}

	if most != chunk {
		t.Fatalf("the reader held at most %d unjudged entries, want exactly one chunk (%d)", most, chunk)
	}

	if n := len(entryRequests(h.log.seen())); n != size/1000 {
		t.Fatalf("%d get-entries requests, want %d — one per thousand-entry page", n, size/1000)
	}

	if len(h.saves) != 1+size/chunk {
		t.Fatalf("%d checkpoint saves, want the founding and one per chunk", len(h.saves))
	}
}
