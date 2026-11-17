package assert_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"

	"github.com/monumental-archive/stele/internal/ctlog"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// fakeLog is an RFC 6962 log in a test: a real Merkle tree over its
// leaves, tree heads signed with its own key, get-entries capped and
// aligned the way ctfe.sigstore.dev was measured to cap and align them
// (a response ends at the next multiple of align), and a hook that
// scripts the refusals a real log answers with. Nothing here decides
// what the reader does with an answer; it only answers.
type fakeLog struct {
	t   *testing.T
	srv *httptest.Server
	key *ecdsa.PrivateKey

	mu     sync.Mutex
	leaves [][]byte
	tree   *testonly.Tree
	// size is the tree head this log serves now; it grows between runs,
	// through grow.
	size uint64
	// align caps a response at the next multiple of align past start;
	// zero serves everything asked for.
	align uint64
	// forked, when set, is the tree the head is computed over instead
	// of the real one — a log that rewrote its history.
	forked *testonly.Tree
	// hook may answer a request itself: it sees the request kind
	// ("sth", "consistency", "entries") and how many get-entries
	// requests came before this one.
	hook func(w http.ResponseWriter, kind string, entriesBefore int) bool

	requests      []string
	entriesAsked  int
	served        uint64
	onEntriesSent func(served uint64)
}

// fakeLogTime is the moment every tree head this log signs carries.
var fakeLogTime = time.Date(2026, 11, 17, 13, 21, 0, 0, time.UTC)

// newFakeLog starts a log over leaves, serving all of them.
func newFakeLog(t *testing.T, leaves [][]byte) *fakeLog {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	l := &fakeLog{t: t, key: key, leaves: leaves, tree: treeOf(leaves), size: uint64(len(leaves))}
	l.srv = httptest.NewTLSServer(http.HandlerFunc(l.serve))
	t.Cleanup(l.srv.Close)

	return l
}

func treeOf(leaves [][]byte) *testonly.Tree {
	tree := testonly.New(rfc6962.DefaultHasher)
	tree.AppendData(leaves...)

	return tree
}

// fillerLeaves are n leaves that are no certificate at all: the scan
// finds no signer's subject in them, so it never parses them.
func fillerLeaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte("filler entry " + strconv.Itoa(i))
	}

	return out
}

// url is the log's base URL.
func (l *fakeLog) url() string { return l.srv.URL }

// logs is the trusted material naming this log's key.
func (l *fakeLog) logs() logSource {
	return logSource{"fake": {
		BaseURL:             l.srv.URL,
		ID:                  []byte("fake"),
		ValidityPeriodStart: fakeLogTime.Add(-time.Hour),
		PublicKey:           l.key.Public(),
	}}
}

type logSource map[string]*root.TransparencyLog

func (s logSource) CTLogs() map[string]*root.TransparencyLog { return s }

// The setters below are the only way a test changes what the log
// serves (stele#417): every field the handler reads is written under
// mu, never assigned by a test, so a change made while the server is
// up cannot race a request it is answering.

// setAlign caps every get-entries answer at the next multiple of n
// past its start; zero serves everything asked for.
func (l *fakeLog) setAlign(n uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.align = n
}

// setHook installs the hook that may answer a request itself; nil
// removes it.
func (l *fakeLog) setHook(hook func(w http.ResponseWriter, kind string, entriesBefore int) bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.hook = hook
}

// setOnEntriesSent installs the callback told how many entries the log
// has served after each get-entries answer.
func (l *fakeLog) setOnEntriesSent(sent func(served uint64)) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.onEntriesSent = sent
}

// rewrite edits the log's history under its lock: the forked tree a
// head is computed over, and the size it serves.
func (l *fakeLog) rewrite(edit func(l *fakeLog)) {
	l.mu.Lock()
	defer l.mu.Unlock()

	edit(l)
}

// forget clears the record of requests seen so far.
func (l *fakeLog) forget() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.requests = nil
}

// grow serves a larger head; the leaves must already exist.
func (l *fakeLog) grow(size uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.size = size
}

// seen reports every request, in order, as "kind args".
func (l *fakeLog) seen() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), l.requests...)
}

func (l *fakeLog) serve(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()

	q := r.URL.Query()

	switch r.URL.Path {
	case "/ct/v1/get-sth":
		l.requests = append(l.requests, "sth")
		if l.hook != nil && l.hook(w, "sth", l.entriesAsked) {
			return
		}

		l.sendJSON(w, l.treeHead())
	case "/ct/v1/get-sth-consistency":
		l.requests = append(l.requests, "consistency "+q.Get("first")+".."+q.Get("second"))
		if l.hook != nil && l.hook(w, "consistency", l.entriesAsked) {
			return
		}

		l.consistency(w, q.Get("first"), q.Get("second"))
	case "/ct/v1/get-entries":
		l.requests = append(l.requests, "entries "+q.Get("start")+".."+q.Get("end"))
		before := l.entriesAsked
		l.entriesAsked++

		if l.hook != nil && l.hook(w, "entries", before) {
			return
		}

		l.entries(w, q.Get("start"), q.Get("end"))
	default:
		http.NotFound(w, r)
	}
}

type sthDoc struct {
	TreeSize          uint64 `json:"tree_size"`
	Timestamp         uint64 `json:"timestamp"`
	SHA256RootHash    string `json:"sha256_root_hash"`
	TreeHeadSignature string `json:"tree_head_signature"`
}

// treeHead signs the head this log serves now.
func (l *fakeLog) treeHead() sthDoc {
	tree := l.tree
	if l.forked != nil {
		tree = l.forked
	}

	rootHash := tree.HashAt(l.size)
	sth := ct.SignedTreeHead{
		Version:        ct.V1,
		TreeSize:       l.size,
		Timestamp:      uint64(fakeLogTime.UnixMilli()),
		SHA256RootHash: ct.SHA256Hash(rootHash),
	}

	input, err := ct.SerializeSTHSignatureInput(sth)
	if err != nil {
		l.t.Fatal(err)
	}

	sig, err := cttls.CreateSignature(*l.key, cttls.SHA256, input)
	if err != nil {
		l.t.Fatal(err)
	}

	raw, err := cttls.Marshal(sig)
	if err != nil {
		l.t.Fatal(err)
	}

	return sthDoc{
		TreeSize:          l.size,
		Timestamp:         sth.Timestamp,
		SHA256RootHash:    base64.StdEncoding.EncodeToString(rootHash),
		TreeHeadSignature: base64.StdEncoding.EncodeToString(raw),
	}
}

func (l *fakeLog) consistency(w http.ResponseWriter, first, second string) {
	a, aerr := strconv.ParseUint(first, 10, 64)
	b, berr := strconv.ParseUint(second, 10, 64)

	if aerr != nil || berr != nil || a > b || b > l.tree.Size() {
		http.Error(w, "bad range", http.StatusBadRequest)

		return
	}

	nodes, err := l.tree.ConsistencyProof(a, b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	out := struct {
		Consistency []string `json:"consistency"`
	}{Consistency: []string{}}

	for _, n := range nodes {
		out.Consistency = append(out.Consistency, base64.StdEncoding.EncodeToString(n))
	}

	l.sendJSON(w, out)
}

type entryDoc struct {
	LeafInput string `json:"leaf_input"`
	ExtraData string `json:"extra_data"`
}

func (l *fakeLog) entries(w http.ResponseWriter, first, last string) {
	start, serr := strconv.ParseUint(first, 10, 64)
	end, eerr := strconv.ParseUint(last, 10, 64)

	// The real log answers an index beyond its head with 400; so does
	// this one, which is what catches a reader asking for tree_size.
	if serr != nil || eerr != nil || start > end || end >= l.size {
		http.Error(w, "bad range", http.StatusBadRequest)

		return
	}

	stop := end + 1
	if l.align > 0 {
		stop = min(stop, (start/l.align+1)*l.align)
	}

	out := struct {
		Entries []entryDoc `json:"entries"`
	}{}

	for i := start; i < stop; i++ {
		out.Entries = append(out.Entries, entryDoc{LeafInput: base64.StdEncoding.EncodeToString(l.leaves[i])})
	}

	l.served += stop - start
	if l.onEntriesSent != nil {
		l.onEntriesSent(l.served)
	}

	l.sendJSON(w, out)
}

func (l *fakeLog) sendJSON(w http.ResponseWriter, v any) {
	var buf bytes.Buffer

	if err := jsonx.Encode(&buf, v); err != nil {
		l.t.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/json")

	if _, err := w.Write(buf.Bytes()); err != nil {
		l.t.Error(err)
	}
}

// throttleAfter answers every get-entries request after the first k
// with a 429, naming a wait when retryAfter is not empty.
func throttleAfter(k int, retryAfter string) func(http.ResponseWriter, string, int) bool {
	return func(w http.ResponseWriter, kind string, before int) bool {
		if kind != "entries" || before < k {
			return false
		}

		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}

		http.Error(w, "too many requests", http.StatusTooManyRequests)

		return true
	}
}

// fakeClock is the run's time: it moves only when the reader waits.
type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	slept []time.Duration
}

func newFakeClock() *fakeClock { return &fakeClock{now: fakeLogTime.Add(time.Minute)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *fakeClock) Sleep(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.slept = append(c.slept, d)
	c.now = c.now.Add(d)
}

func (c *fakeClock) Slept() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]time.Duration(nil), c.slept...)
}

// client is a reader of this log on the given clock and budget.
func (l *fakeLog) client(clock ctlog.Clock, budget time.Duration) *ctlog.Client {
	return &ctlog.Client{
		URL:      l.srv.URL,
		HTTP:     l.srv.Client(),
		Clock:    clock,
		Deadline: clock.Now().Add(budget),
	}
}

// entriesRange renders a get-entries request the way seen records
// it.
func entriesRange(start, end uint64) string { return fmt.Sprintf("entries %d..%d", start, end) }
