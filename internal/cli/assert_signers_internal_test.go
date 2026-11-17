package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	newSignerForge = func(gh.Forge) (assert.SignerForge, string, error) { return sf, "https://github.com", sfErr }

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
			l.throttled = tc.throttled
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
	l.size = 40
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

	l.mu.Lock()
	l.size = 60
	l.mu.Unlock()

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

		l.mu.Lock()
		l.size = 10
		l.mu.Unlock()

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

// TestLiveSignerForge: the live adapter over a scripted forge — a
// commit on the default branch, one off it, a repository the forge
// answers 404 for (a read that could not complete, never "off its
// branch"), and a forge that is not the live client.
func TestLiveSignerForge(t *testing.T) {
	t.Parallel()

	const onSHA, offSHA = "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222"

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/signer", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`{"default_branch": "trunk"}`)); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("/repos/acme/signer/compare/"+onSHA+"...trunk", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`{"status": "ahead"}`)); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("/repos/acme/signer/compare/"+offSHA+"...trunk", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`{"status": "diverged"}`)); err != nil {
			t.Error(err)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.NewForServer("https://forge.example/", "")
	c.Base = srv.URL
	c.HTTP = srv.Client()

	sf, server, err := signerForgeOf(c)
	if err != nil || server != "https://forge.example" {
		t.Fatalf("signerForgeOf = %q, %v", server, err)
	}

	for sha, want := range map[string]bool{onSHA: true, offSHA: false} {
		on, oerr := sf.OnDefaultBranch("acme", "signer", sha)
		if oerr != nil || on != want {
			t.Errorf("OnDefaultBranch(%s) = %v, %v; want %v", sha, on, oerr, want)
		}
	}

	if _, oerr := sf.OnDefaultBranch("acme", "gone", onSHA); oerr == nil ||
		oerr.Error() != "the forge answers 404 for acme/gone: absent, or not visible to this credential" {
		t.Errorf("a repository the forge answers 404 for: err = %v", oerr)
	}

	if _, _, ferr := newSignerForge(&levelForge{}); ferr == nil || ferr.Error() != "this forge cannot read workflow runs" {
		t.Errorf("a forge that is not the live client: err = %v", ferr)
	}

	if f, s, ferr := newSignerForge(gh.New("")); ferr != nil || f == nil || s != "https://github.com" {
		t.Errorf("the live client: %v, %q, %v", f, s, ferr)
	}
}
