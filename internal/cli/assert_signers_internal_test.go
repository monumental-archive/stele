package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/ctlog"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/gitfetch"
	"github.com/monumental-archive/stele/internal/gittest"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// signerLog is the smallest honest RFC 6962 log: a real tree, signed
// heads, consistency proofs, and get-entries that may be throttled.
type signerLog struct {
	t      *testing.T
	srv    *httptest.Server
	key    *ecdsa.PrivateKey
	leaves [][]byte
	tree   *testonly.Tree

	mu        sync.Mutex
	size      uint64
	throttled bool
}

func newSignerLog(t *testing.T, leaves [][]byte) *signerLog {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tree := testonly.New(rfc6962.DefaultHasher)
	tree.AppendData(leaves...)

	l := &signerLog{t: t, key: key, leaves: leaves, tree: tree, size: uint64(len(leaves))}
	l.srv = httptest.NewTLSServer(http.HandlerFunc(l.serve))
	t.Cleanup(l.srv.Close)

	return l
}

// resize serves a head of n entries. Like throttle, it is the only way
// a test changes what the log serves (stele#417): the handler reads
// both fields under mu, so a test writes them under mu too, never by
// assigning the field.
func (l *signerLog) resize(n uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.size = n
}

// throttle makes every get-entries read answer 429, or stops it.
func (l *signerLog) throttle(on bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.throttled = on
}

func (l *signerLog) send(w http.ResponseWriter, v any) {
	var buf bytes.Buffer
	if err := jsonx.Encode(&buf, v); err != nil {
		l.t.Fatal(err)
	}

	if _, err := w.Write(buf.Bytes()); err != nil {
		l.t.Error(err)
	}
}

func (l *signerLog) serve(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()

	q := r.URL.Query()

	switch r.URL.Path {
	case "/ct/v1/get-sth":
		l.send(w, l.head())
	case "/ct/v1/get-sth-consistency":
		a, _ := strconv.ParseUint(q.Get("first"), 10, 64)  //nolint:errcheck // the reader under test spells them
		b, _ := strconv.ParseUint(q.Get("second"), 10, 64) //nolint:errcheck // the reader under test spells them

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

		l.send(w, out)
	case "/ct/v1/get-entries":
		if l.throttled {
			http.Error(w, "slow down", http.StatusTooManyRequests)

			return
		}

		start, _ := strconv.ParseUint(q.Get("start"), 10, 64) //nolint:errcheck // the reader under test spells them
		end, _ := strconv.ParseUint(q.Get("end"), 10, 64)     //nolint:errcheck // the reader under test spells them

		type entry struct {
			LeafInput string `json:"leaf_input"`
		}

		out := struct {
			Entries []entry `json:"entries"`
		}{}

		for i := start; i <= end && i < l.size; i++ {
			out.Entries = append(out.Entries, entry{LeafInput: base64.StdEncoding.EncodeToString(l.leaves[i])})
		}

		l.send(w, out)
	default:
		http.NotFound(w, r)
	}
}

var signerLogTime = time.Date(2026, 11, 17, 13, 21, 0, 0, time.UTC)

func (l *signerLog) head() any {
	rootHash := l.tree.HashAt(l.size)
	sth := ct.SignedTreeHead{
		Version: ct.V1, TreeSize: l.size, SHA256RootHash: ct.SHA256Hash(rootHash),
		Timestamp: uint64(signerLogTime.UnixMilli()),
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

	return struct {
		TreeSize          uint64 `json:"tree_size"`
		Timestamp         uint64 `json:"timestamp"`
		SHA256RootHash    string `json:"sha256_root_hash"`
		TreeHeadSignature string `json:"tree_head_signature"`
	}{l.size, sth.Timestamp, base64.StdEncoding.EncodeToString(rootHash), base64.StdEncoding.EncodeToString(raw)}
}

// trustedRoot writes a Sigstore trusted-root document naming this
// log's key at its URL — the offline origin, the same one a stranger
// may hand any verb.
func (l *signerLog) trustedRoot(t *testing.T) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(l.key.Public())
	if err != nil {
		t.Fatal(err)
	}

	id := sha256.Sum256(der)

	doc := fmt.Sprintf(`{
  "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
  "tlogs": [],
  "certificateAuthorities": [],
  "ctlogs": [{
    "baseUrl": %q,
    "hashAlgorithm": "SHA2_256",
    "publicKey": {"rawBytes": %q, "keyDetails": "PKIX_ECDSA_P256_SHA_256",
      "validFor": {"start": "2026-01-01T00:00:00Z"}},
    "logId": {"keyId": %q}
  }],
  "timestampAuthorities": []
}`, l.srv.URL, base64.StdEncoding.EncodeToString(der), base64.StdEncoding.EncodeToString(id[:]))

	path := filepath.Join(t.TempDir(), "trusted-root.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// signerClock is the run's clock: still until the reader waits.
type signerClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *signerClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *signerClock) Sleep(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

// signerForgeStub answers every run with a 404 and every commit as on
// its default branch; asked counts what it was asked.
type signerForgeStub struct {
	mu    sync.Mutex
	asked []string
}

func (s *signerForgeStub) WorkflowRun(owner, repo string, id uint64) (*gh.WorkflowRun, bool, error) {
	s.ask(fmt.Sprintf("run %s/%s#%d", owner, repo, id))

	return nil, false, nil
}

//nolint:gocritic // unnamedResult: assert.SignerForge's shape, which a fake implements as declared
func (s *signerForgeStub) FileAt(owner, repo, path, ref string) ([]byte, bool, error) {
	s.ask("file " + owner + "/" + repo + "/" + path + "@" + ref)

	return nil, false, nil
}

func (s *signerForgeStub) OnDefaultBranch(owner, repo, sha string) (bool, error) {
	s.ask("branch " + owner + "/" + repo + "@" + sha)

	return true, nil
}

func (s *signerForgeStub) ask(what string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.asked = append(s.asked, what)
}

// releaseLeaf is the real certificate behind the canon's v1.67.0
// release, from the capture internal/assert's tests read.
func releaseLeaf(t *testing.T) []byte {
	t.Helper()

	b, err := os.ReadFile("../assert/testdata/signer-certificates/ct-443908396.json")
	if err != nil {
		t.Fatal(err)
	}

	doc, err := jsonx.DecodeForeign[struct {
		Entries []struct {
			LeafInput string `json:"leaf_input"`
		} `json:"entries"`
	}](b)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := base64.StdEncoding.DecodeString(doc.Entries[0].LeafInput)
	if err != nil {
		t.Fatal(err)
	}

	return leaf
}

func signerFillers(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte("filler " + strconv.Itoa(i))
	}

	return out
}

// signerPolicyFile writes an assert policy watching logURL.
func signerPolicyFile(t *testing.T, logURL string) string {
	t.Helper()

	doc := fmt.Sprintf(`{"schema": 8, "issuer": "https://token.actions.githubusercontent.com",
  "population": {"repositories": [{"repo": ".github"}, {"repo": "signer"}]},
  "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt", "umbrellaBundle": "u.jsonl",
    "manifestAsset": "m.json", "classes": {"a": {"bundles": ["b"]}}},
  "signerCertificates": {"log": %q, "signers": [
    {"workflow": "monumental-archive/signer/.github/workflows/sign.yml", "callers": ["monumental-archive/.github"]}]}}`,
		logURL)

	path := filepath.Join(t.TempDir(), "assert-policy.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// signerSeams installs the log's transport and a still clock, the
// population's listing and the reconciliation's forge, for one test.
func signerSeams(t *testing.T, l *signerLog, sf assert.SignerForge, sfErr error) {
	t.Helper()

	origHTTP, origClock, origSigner := newLogHTTP, newLogClock, newSignerForge

	newLogHTTP = func() ctlog.Doer { return l.srv.Client() }
	newLogClock = func() ctlog.Clock { return &signerClock{now: signerLogTime.Add(time.Minute)} }
	newSignerForge = func(gh.Forge, *gitfetch.Session) (assert.SignerForge, string, error) {
		return sf, "https://github.com", sfErr
	}

	swapForge(t, &levelForge{repos: []string{".github", "signer"}})

	t.Cleanup(func() { newLogHTTP, newLogClock, newSignerForge = origHTTP, origClock, origSigner })
}

// TestAssertSignerCertificatesExits: the three verdicts, each with its
// exit code, end to end through the binary's own argument surface.
func TestAssertSignerCertificatesExits(t *testing.T) {
	cases := []struct {
		name      string
		leaves    func(t *testing.T) [][]byte
		throttled bool
		code      int
		says      []string
	}{
		{
			name:   "a range with no certificate for the signer passes",
			leaves: func(*testing.T) [][]byte { return signerFillers(40) },
			code:   exitOK,
			says:   []string{"assert: PASS"},
		},
		{
			name: "a certificate whose run the forge never heard of fails",
			leaves: func(t *testing.T) [][]byte {
				t.Helper()

				leaves := signerFillers(40)
				leaves[9] = releaseLeaf(t)

				return leaves
			},
			code: exitRefused,
			says: []string{
				"assert: CT index 9: run: run 43671235061 does not exist in monumental-archive/.github " +
					"(never existed, or deleted)",
				"assert: FAIL",
			},
		},
		{
			name:      "a log that throttles every read cannot be judged",
			leaves:    func(*testing.T) [][]byte { return signerFillers(40) },
			throttled: true,
			code:      exitBlind,
			says:      []string{"stopped at 0: ctlog: the run's budget ended", "assert: CANNOT_JUDGE"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := newSignerLog(t, tc.leaves(t))
			l.throttle(tc.throttled)
			signerSeams(t, l, &signerForgeStub{}, nil)

			cp := filepath.Join(t.TempDir(), "checkpoint.json")

			var out, errs bytes.Buffer

			code := Run([]string{
				"assert", "signer-certificates", "--policy", signerPolicyFile(t, l.srv.URL),
				"--checkpoint", cp, "--start-at", "0", "--budget", "1m",
				"--org", "monumental-archive", "--trusted-root", l.trustedRoot(t),
			}, &out, &errs)

			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.code, out.String(), errs.String())
			}

			for _, want := range tc.says {
				if !strings.Contains(out.String(), want) {
					t.Errorf("stdout does not say %q:\n%s", want, out.String())
				}
			}

			if _, err := ctlog.ReadCheckpoint(cp); err != nil {
				t.Fatalf("the run left no checkpoint: %v", err)
			}
		})
	}
}

// TestAssertSignerCertificatesResumes: a second run reads the file the
// first wrote and judges only what the log grew by, as a JSON report.
func TestAssertSignerCertificatesResumes(t *testing.T) {
	l := newSignerLog(t, signerFillers(60))
	l.resize(40)
	signerSeams(t, l, &signerForgeStub{}, nil)

	cp := filepath.Join(t.TempDir(), "checkpoint.json")
	policy, root := signerPolicyFile(t, l.srv.URL), l.trustedRoot(t)

	args := []string{
		"assert", "signer-certificates", "--policy", policy, "--checkpoint", cp,
		"--org", "monumental-archive", "--trusted-root", root, "--json",
	}

	var out, errs bytes.Buffer

	if code := Run(append(args, "--start-at", "10"), &out, &errs); code != exitOK {
		t.Fatalf("founding run: exit %d\n%s", code, errs.String())
	}

	l.resize(60)

	out.Reset()
	errs.Reset()

	if code := Run(args, &out, &errs); code != exitOK {
		t.Fatalf("resuming run: exit %d\n%s", code, errs.String())
	}

	for _, want := range []string{
		`"target":"assert signer-certificates"`, `"verdict":"PASS"`,
		`{"name":"judged","value":"40..59"}`, `{"name":"outstanding","value":"none"}`,
		`{"name":"checkpointNext","value":"60"}`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the JSON report does not carry %s:\n%s", want, out.String())
		}
	}

	if !strings.Contains(errs.String(), "judging 40..59") {
		t.Errorf("progress did not move to stderr under --json:\n%s", errs.String())
	}
}

// TestAssertSignerCertificatesRefusals: every way an invocation is
// refused before a log or a forge is read, each by name.
func TestAssertSignerCertificatesRefusals(t *testing.T) {
	l := newSignerLog(t, signerFillers(10))
	signerSeams(t, l, &signerForgeStub{}, nil)

	policy, root := signerPolicyFile(t, l.srv.URL), l.trustedRoot(t)
	dir := t.TempDir()

	existing := filepath.Join(dir, "existing.json")
	if err := ctlog.WriteCheckpoint(existing, &ctlog.Checkpoint{
		Log: l.srv.URL, TreeHead: ctlog.TreeHead{TreeSize: 5, RootHash: make([]byte, 32), Signature: []byte{1}}, Next: 3,
	}); err != nil {
		t.Fatal(err)
	}

	elsewhere := filepath.Join(dir, "elsewhere.json")
	if err := ctlog.WriteCheckpoint(elsewhere, &ctlog.Checkpoint{
		Log: "https://other.example/log", TreeHead: ctlog.TreeHead{
			TreeSize: 5, RootHash: make([]byte, 32),
			Signature: []byte{1},
		}, Next: 3,
	}); err != nil {
		t.Fatal(err)
	}

	corrupt := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(corrupt, []byte(`{"schema": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	noSection := filepath.Join(dir, "no-section.json")
	if err := os.WriteFile(noSection, []byte(`{"schema": 8, "evidence": {"sbomSuffix": ".spdx.json",
	  "checksums": "c.txt", "umbrellaBundle": "u.jsonl", "manifestAsset": "m.json",
	  "classes": {"a": {"bundles": ["b"]}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	otherLog := signerPolicyFile(t, "https://other.example/log")
	fresh := filepath.Join(dir, "fresh.json")

	base := func(extra ...string) []string {
		return append([]string{
			"--policy", policy, "--checkpoint", fresh, "--org", "monumental-archive",
			"--trusted-root", root,
		}, extra...)
	}

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no policy", []string{"--checkpoint", fresh, "--org", "a"}, "--policy is required"},
		{
			"no checkpoint",
			[]string{"--policy", policy, "--org", "a"},
			"--checkpoint is required: where the judged prefix is kept is the caller's to say",
		},
		{"no population", []string{"--policy", policy, "--checkpoint", fresh}, "--org or --repo is required"},
		{"two populations", base("--repo", "a/b"), "--org and --repo are exclusive"},
		{
			"a repository that is not owner/name",
			[]string{"--policy", policy, "--checkpoint", fresh, "--repo", "b"},
			"--repo must be owner/name",
		},
		{"a budget of nothing", base("--budget", "0s"), "--budget must be a positive duration"},
		{"a start that is not a size", base("--start-at", "head"), "--start-at takes a tree size"},
		{"an argument that names nothing", append(base(), "extra"), "extra arguments name nothing"},
		{"a policy that is not there", []string{
			"--policy", filepath.Join(dir, "none.json"), "--checkpoint", fresh,
			"--org", "a",
		}, "no such file or directory"},
		{
			"a policy that does not load",
			[]string{"--policy", corrupt, "--checkpoint", fresh, "--org", "a"},
			"assert: policy:",
		},
		{
			"a policy declaring no watch",
			[]string{"--policy", noSection, "--checkpoint", fresh, "--org", "a"},
			"the policy declares no signerCertificates section",
		},
		{"no checkpoint and no start", base(), "no checkpoint at " + fresh + " and no --start-at: starting is a " +
			"decision a person makes, never one a missing file makes — pass --start-at <tree size> to found one"},
		{"a start over an existing checkpoint", []string{
			"--policy", policy, "--checkpoint", existing, "--org", "a",
			"--start-at", "0",
		}, "--start-at founds a new checkpoint and " + existing + " already holds one (next 3)"},
		{
			"a checkpoint that does not read",
			[]string{"--policy", policy, "--checkpoint", corrupt, "--org", "a"},
			"ctlog: checkpoint " + corrupt + ": log is absent or empty",
		},
		{
			"another log's checkpoint",
			[]string{"--policy", policy, "--checkpoint", elsewhere, "--org", "a"},
			"the checkpoint at " + elsewhere + " is https://other.example/log's and the policy reads " + l.srv.URL,
		},
		{"a trusted root that is not there", []string{
			"--policy", policy, "--checkpoint", fresh, "--org", "a",
			"--start-at", "0", "--trusted-root", filepath.Join(dir, "none.json"),
		}, "trust: read trusted root: "},
		{"a trusted root that does not load", []string{
			"--policy", policy, "--checkpoint", fresh, "--org", "a",
			"--start-at", "0", "--trusted-root", corrupt,
		}, "trust: parse trusted root: "},
		{
			"a trusted root without the log",
			[]string{
				"--policy", otherLog, "--checkpoint", fresh, "--org", "a",
				"--start-at", "0", "--trusted-root", root,
			},
			"the trusted root names no certificate transparency log at https://other.example/log",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errs bytes.Buffer

			code := Run(append([]string{"assert", "signer-certificates"}, tc.args...), &out, &errs)
			if code != exitUsage || !strings.Contains(errs.String(), tc.want) {
				t.Fatalf("exit %d, stderr:\n%s\nwant exit %d saying %q", code, errs.String(), exitUsage, tc.want)
			}

			if _, err := os.Stat(fresh); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a refused run wrote %s", fresh)
			}
		})
	}
}

// TestAssertSignerCertificatesCannotStart: a population that will not
// resolve, a forge that cannot be built, and a head that does not
// extend the checkpoint's each seal CANNOT_JUDGE naming why.
func TestAssertSignerCertificatesCannotStart(t *testing.T) {
	t.Run("a population the listing contradicts", func(t *testing.T) {
		l := newSignerLog(t, signerFillers(10))
		signerSeams(t, l, &signerForgeStub{}, nil)
		swapForge(t, &levelForge{repos: []string{".github"}})

		var out, errs bytes.Buffer

		code := Run([]string{
			"assert", "signer-certificates", "--policy", signerPolicyFile(t, l.srv.URL),
			"--checkpoint", filepath.Join(t.TempDir(), "cp.json"), "--start-at", "0",
			"--org", "monumental-archive", "--trusted-root", l.trustedRoot(t),
		}, &out, &errs)

		if code != exitBlind || !strings.Contains(errs.String(),
			"the declared population names signer, which the listing does not show") {
			t.Fatalf("exit %d, stderr:\n%s", code, errs.String())
		}
	})

	t.Run("a forge that cannot be built", func(t *testing.T) {
		l := newSignerLog(t, signerFillers(10))
		signerSeams(t, l, nil, errors.New("no forge for this server"))

		var out, errs bytes.Buffer

		code := Run([]string{
			"assert", "signer-certificates", "--policy", signerPolicyFile(t, l.srv.URL),
			"--checkpoint", filepath.Join(t.TempDir(), "cp.json"), "--start-at", "0",
			"--org", "monumental-archive", "--trusted-root", l.trustedRoot(t),
		}, &out, &errs)

		if code != exitBlind || !strings.Contains(errs.String(), "no forge for this server") {
			t.Fatalf("exit %d, stderr:\n%s", code, errs.String())
		}
	})

	t.Run("a head that does not extend the checkpoint's", func(t *testing.T) {
		l := newSignerLog(t, signerFillers(20))
		signerSeams(t, l, &signerForgeStub{}, nil)

		cp := filepath.Join(t.TempDir(), "cp.json")
		policy, root := signerPolicyFile(t, l.srv.URL), l.trustedRoot(t)
		args := []string{
			"assert", "signer-certificates", "--policy", policy, "--checkpoint", cp,
			"--org", "monumental-archive", "--trusted-root", root,
		}

		var out, errs bytes.Buffer
		if code := Run(append(args, "--start-at", "0"), &out, &errs); code != exitOK {
			t.Fatalf("founding run: exit %d\n%s", code, errs.String())
		}

		before, err := os.ReadFile(cp) //nolint:gosec // a path this test just wrote
		if err != nil {
			t.Fatal(err)
		}

		l.resize(10)

		out.Reset()
		errs.Reset()

		code := Run(args, &out, &errs)
		if code != exitBlind || !strings.Contains(errs.String(),
			"the log's tree head is not consistent with the checkpoint's: the log's tree of size 10 is smaller") {
			t.Fatalf("exit %d, stderr:\n%s", code, errs.String())
		}

		after, rerr := os.ReadFile(cp) //nolint:gosec // a path this test just wrote
		if rerr != nil || !bytes.Equal(before, after) {
			t.Fatalf("a refused head moved the checkpoint (%v)", rerr)
		}
	})
}

// TestAssertSignerCertificatesStreams: a debt file that does not parse
// refuses, and a sink that fails is an I/O failure — never a verdict.
func TestAssertSignerCertificatesStreams(t *testing.T) {
	l := newSignerLog(t, signerFillers(10))
	signerSeams(t, l, &signerForgeStub{}, nil)

	debt := filepath.Join(t.TempDir(), "debt.txt")
	if err := os.WriteFile(debt, []byte("not a debt line\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	args := func() []string {
		return []string{
			"assert", "signer-certificates", "--policy", signerPolicyFile(t, l.srv.URL),
			"--checkpoint", filepath.Join(t.TempDir(), "cp.json"), "--start-at", "0",
			"--org", "monumental-archive", "--trusted-root", l.trustedRoot(t),
		}
	}

	var out, errs bytes.Buffer
	if code := Run(append(args(), "--debt", debt), &out, &errs); code != exitUsage ||
		!strings.Contains(errs.String(), "is not subject(assertion)") {
		t.Fatalf("exit %d, stderr:\n%s", code, errs.String())
	}

	if code := Run(args(), failWriterI{}, failWriterI{}); code != exitIO {
		t.Fatalf("exit %d, want %d", code, exitIO)
	}
}

// TestLiveSignerForge: the live adapter over a scripted forge for the
// default branch and a real repository for the history. A commit on
// the default branch, one on another branch, one the fetched history
// does not hold (its branch deleted after the push), a repository the
// forge answers 404 for, and a forge that is not the live client.
func TestLiveSignerForge(t *testing.T) {
	t.Parallel()

	r := gittest.New(t)
	onSHA := r.Commit("feat: on the default branch")
	r.Git("checkout", "-q", "-b", "side")
	sideSHA := r.Commit("feat: on another branch")
	r.Git("checkout", "-q", "-b", "gone")
	goneSHA := r.Commit("feat: on a branch deleted after the push")
	r.Git("checkout", "-q", "main")
	r.Git("branch", "-q", "-D", "gone")

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/signer", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`{"default_branch": "main"}`)); err != nil {
			t.Error(err)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.NewForServer("https://forge.example/", "")
	c.Base = srv.URL
	c.HTTP = srv.Client()

	git := &gitfetch.Session{
		Remote: func(_, _ string) string { return r.URL() },
		Want:   gitfetch.Want{Heads: true},
	}
	t.Cleanup(func() {
		if err := git.Close(); err != nil {
			t.Error(err)
		}
	})

	sf, server, err := signerForgeOf(c, git)
	if err != nil || server != "https://forge.example" {
		t.Fatalf("signerForgeOf = %q, %v", server, err)
	}

	// The fetched history holds every branch at full depth, so a commit
	// it does not hold — its branch deleted after the push — is on no
	// branch: false, an answer, exactly as a commit held off the branch.
	for sha, want := range map[string]bool{onSHA: true, sideSHA: false, goneSHA: false} {
		on, oerr := sf.OnDefaultBranch("acme", "signer", sha)
		if oerr != nil || on != want {
			t.Errorf("OnDefaultBranch(%s) = %v, %v; want %v", sha, on, oerr, want)
		}
	}

	if _, oerr := sf.OnDefaultBranch("acme", "gone", onSHA); oerr == nil ||
		oerr.Error() != "the forge answers 404 for acme/gone: absent, or not visible to this credential" {
		t.Errorf("a repository the forge answers 404 for: err = %v", oerr)
	}

	if _, _, ferr := newSignerForge(&levelForge{}, git); ferr == nil ||
		ferr.Error() != "this forge cannot read workflow runs" {
		t.Errorf("a forge that is not the live client: err = %v", ferr)
	}

	if f, s, ferr := newSignerForge(gh.New(""), git); ferr != nil || f == nil || s != gh.DefaultServer {
		t.Errorf("the live client: %v, %q, %v", f, s, ferr)
	}
}

// TestAssertSignerCertificatesNeedsGit: a machine whose git cannot read
// the fetched history is refused by name before the log is read.
func TestAssertSignerCertificatesNeedsGit(t *testing.T) {
	l := newSignerLog(t, signerFillers(10))
	signerSeams(t, l, &signerForgeStub{}, nil)

	orig := newGitSession
	newGitSession = func(want gitfetch.Want, log func(string, ...any)) *gitfetch.Session {
		return &gitfetch.Session{
			Fetcher: &gitfetch.Fetcher{Git: filepath.Join(t.TempDir(), "no-git")}, Want: want, Log: log,
		}
	}

	t.Cleanup(func() { newGitSession = orig })

	cp := filepath.Join(t.TempDir(), "cp.json")

	var out, errs bytes.Buffer

	code := Run([]string{
		"assert", "signer-certificates", "--policy", signerPolicyFile(t, l.srv.URL),
		"--checkpoint", cp, "--start-at", "0", "--org", "monumental-archive", "--trusted-root", l.trustedRoot(t),
	}, &out, &errs)

	if code != exitUsage || !strings.Contains(errs.String(), "gitfetch: git is not installed") {
		t.Fatalf("exit %d, stderr:\n%s", code, errs.String())
	}

	if _, err := os.Stat(cp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a run refused for its git founded a checkpoint")
	}
}

// syntheticSignerLeaf is an RFC 6962 X.509 entry for a certificate the
// signer watch reads: the subject, the issuer, the Build Signer Digest
// and the Run Invocation URI, nothing else.
func syntheticSignerLeaf(t *testing.T, san, digest, runURI string) []byte {
	t.Helper()

	utf8 := func(oid asn1.ObjectIdentifier, v string) pkix.Extension {
		der, err := asn1.MarshalWithParams(v, "utf8")
		if err != nil {
			t.Fatal(err)
		}

		return pkix.Extension{Id: oid, Value: der}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(san)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    signerLogTime,
		NotAfter:     signerLogTime.Add(10 * time.Minute),
		URIs:         []*url.URL{u},
		ExtraExtensions: []pkix.Extension{
			utf8(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, "https://token.actions.githubusercontent.com"),
			utf8(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 10}, digest),
			utf8(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 21}, runURI),
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := cttls.Marshal(ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: uint64(signerLogTime.UnixMilli()),
			EntryType: ct.X509LogEntryType,
			X509Entry: &ct.ASN1Cert{Data: der},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	return leaf
}

// signingForge is the forge's REST surface for one signing run: the
// listing, the run, its files and the repositories' default branches.
func signingForge(t *testing.T, run, publish, release string) *gh.Client {
	t.Helper()

	serve := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			if _, err := w.Write([]byte(body)); err != nil {
				t.Error(err)
			}
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/acme/repos", serve(`[{"name": ".github"}, {"name": "signer"}, {"name": "widget"}]`))
	mux.HandleFunc("/repos/acme/widget/actions/runs/7", serve(run))
	mux.HandleFunc("/repos/acme/.github/contents/.github/workflows/publish.yml", serve(publish))
	mux.HandleFunc("/repos/acme/widget/contents/.github/workflows/release.yml", serve(release))
	mux.HandleFunc("/repos/acme/signer", serve(`{"default_branch": "main"}`))
	mux.HandleFunc("/repos/acme/.github", serve(`{"default_branch": "main"}`))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.New("")
	c.Base = srv.URL
	c.HTTP = srv.Client()

	return c
}

// TestAssertSignerCertificatesDeletedBranch is the fail-before/pass-
// after row of stele#387's absent-commit fork: a commit whose branch
// was deleted after the push is held by no branch of the fetched
// history. Before, git refused to answer for it, the chunk was never
// done and the run exited 4 with no finding — the forgery this watch
// exists for, stalled at one index forever. Now it is the finding,
// with the chunk done and the checkpoint past it; and a git that
// cannot fetch still leaves the chunk undone.
func TestAssertSignerCertificatesDeletedBranch(t *testing.T) {
	cases := []struct {
		name string
		// deleteSigner and deleteCaller put the signer commit D, and the
		// caller workflow's commit C, on a branch deleted after the push.
		deleteSigner, deleteCaller bool
		unreachable                bool
		code                       int
		finding                    string
		next                       uint64
	}{
		{
			name: "the signer commit on a deleted branch", deleteSigner: true,
			code: exitRefused, finding: "assert: CT index 5: signer-branch: signer commit %[1]s is not on acme/signer's " +
				"default branch", next: 12,
		},
		{
			name: "the caller workflow's commit on a deleted branch", deleteCaller: true,
			code: exitRefused, finding: "assert: CT index 5: caller-branch: acme/.github/.github/workflows/publish.yml at " +
				"%[2]s is not on acme/.github's default branch", next: 12,
		},
		{
			name: "both on their default branches", code: exitOK, next: 12,
		},
		{
			name: "a signer repository git cannot fetch", unreachable: true,
			code: exitBlind, next: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, root, d, c := signingWorld(t, tc.deleteSigner, tc.deleteCaller, tc.unreachable)

			cp := filepath.Join(t.TempDir(), "checkpoint.json")

			var out, errs bytes.Buffer

			code := Run([]string{
				"assert", "signer-certificates", "--policy", policy, "--checkpoint", cp, "--start-at", "0",
				"--org", "acme", "--trusted-root", root,
			}, &out, &errs)

			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.code, out.String(), errs.String())
			}

			if tc.finding != "" {
				if want := fmt.Sprintf(tc.finding, d, c); !strings.Contains(out.String(), want) {
					t.Errorf("stdout does not carry the finding %q:\n%s", want, out.String())
				}

				if n := strings.Count(out.String(), "assert: CT index "); n != 1 {
					t.Errorf("%d findings, want exactly one:\n%s", n, out.String())
				}
			}

			got, err := ctlog.ReadCheckpoint(cp)
			if err != nil {
				t.Fatal(err)
			}

			if got.Next != tc.next {
				t.Fatalf("the checkpoint is at %d, want %d", got.Next, tc.next)
			}
		})
	}
}

// signingWorld is one signing, end to end: the signer and canon
// repositories as real git, the signer commit D and the caller
// workflow's commit C each on main or on a branch deleted after the
// push, the forge's REST answers for the run and its files, and a log
// holding the certificate at index 5 of 12. It returns the policy, the
// trusted root, D and C.
//
//nolint:gocritic // unnamedResult: the policy and trusted-root paths, then the two commits
func signingWorld(t *testing.T, deleteSigner, deleteCaller, unreachable bool) (string, string, string, string) {
	t.Helper()

	commitOn := func(r *gittest.Repo, deleted bool, msg string) string {
		if !deleted {
			return r.Commit(msg)
		}

		r.Git("checkout", "-q", "-b", "pushed-then-deleted")
		sha := r.Commit(msg)
		r.Git("checkout", "-q", "main")
		r.Git("branch", "-q", "-D", "pushed-then-deleted")

		return sha
	}

	signer := gittest.New(t)
	signer.Commit("feat: the signer")
	d := commitOn(signer, deleteSigner, "feat: the signing workflow at D")

	canon := gittest.New(t)
	canon.Commit("feat: the canon")
	c := commitOn(canon, deleteCaller, "feat: publish.yml at C")

	repos := map[string]*gittest.Repo{"acme/signer": signer, "acme/.github": canon}
	if unreachable {
		delete(repos, "acme/signer")
	}

	swapGitRemotes(t, repos)

	const w = "1111111111111111111111111111111111111111"

	run := fmt.Sprintf(`{"path": ".github/workflows/release.yml", "head_sha": %q, "event": "push",
	  "html_url": "https://github.com/acme/widget/actions/runs/7", "repository": {"full_name": "acme/widget"},
	  "referenced_workflows": [
	    {"path": "acme/.github/.github/workflows/publish.yml@%[2]s", "sha": %[2]q},
	    {"path": "acme/signer/.github/workflows/sign.yml@%[3]s", "sha": %[3]q}]}`, w, c, d)
	publish := "on: workflow_call\njobs:\n  sign:\n    uses: acme/signer/.github/workflows/sign.yml@" + d + "\n"
	release := "on: push\njobs:\n  publish:\n    uses: acme/.github/.github/workflows/publish.yml@" + c + "\n"

	leaves := signerFillers(12)
	leaves[5] = syntheticSignerLeaf(t, "https://github.com/acme/signer/.github/workflows/sign.yml@"+d, d,
		"https://github.com/acme/widget/actions/runs/7/attempts/1")

	l := newSignerLog(t, leaves)

	origHTTP, origClock := newLogHTTP, newLogClock
	newLogHTTP = func() ctlog.Doer { return l.srv.Client() }
	newLogClock = func() ctlog.Clock { return &signerClock{now: signerLogTime.Add(time.Minute)} }

	t.Cleanup(func() { newLogHTTP, newLogClock = origHTTP, origClock })

	swapForge(t, signingForge(t, run, publish, release))

	policy := filepath.Join(t.TempDir(), "assert-policy.json")
	if err := os.WriteFile(policy, []byte(fmt.Sprintf(`{"schema": 8,
	  "issuer": "https://token.actions.githubusercontent.com",
	  "population": {"repositories": [{"repo": ".github"}, {"repo": "signer"}, {"repo": "widget"}]},
	  "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt", "umbrellaBundle": "u.jsonl",
	    "manifestAsset": "m.json", "classes": {"a": {"bundles": ["b"]}}},
	  "signerCertificates": {"log": %q, "signers": [
	    {"workflow": "acme/signer/.github/workflows/sign.yml", "callers": ["acme/.github"]}]}}`,
		l.srv.URL)), 0o600); err != nil {
		t.Fatal(err)
	}

	return policy, l.trustedRoot(t), d, c
}
