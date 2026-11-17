package ctlog_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"

	"github.com/monumental-archive/stele/internal/ctlog"
)

const logURL = "https://ct.example/2026"

type logs map[string]*root.TransparencyLog

func (l logs) CTLogs() map[string]*root.TransparencyLog { return l }

var headTime = time.Date(2026, 11, 17, 13, 21, 0, 0, time.UTC)

// signedHead is a head of the given tree at size, signed by key.
func signedHead(t *testing.T, key *ecdsa.PrivateKey, tree *testonly.Tree, size uint64) *ctlog.TreeHead {
	t.Helper()

	rootHash := tree.HashAt(size)
	sth := ct.SignedTreeHead{
		Version: ct.V1, TreeSize: size, SHA256RootHash: ct.SHA256Hash(rootHash),
		Timestamp: uint64(headTime.UnixMilli()),
	}

	input, err := ct.SerializeSTHSignatureInput(sth)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := cttls.CreateSignature(*key, cttls.SHA256, input)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := cttls.Marshal(sig)
	if err != nil {
		t.Fatal(err)
	}

	return &ctlog.TreeHead{TreeSize: size, Timestamp: sth.Timestamp, RootHash: rootHash, Signature: raw}
}

func tree(n int) *testonly.Tree {
	tr := testonly.New(rfc6962.DefaultHasher)
	for i := range n {
		tr.AppendData([]byte{byte(i), byte(i >> 8)})
	}

	return tr
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

// TestVerifyTreeHead: a head is taken only when a key the trusted root
// holds for this log, valid at the head's moment, signed it.
func TestVerifyTreeHead(t *testing.T) {
	t.Parallel()

	key, other := newKey(t), newKey(t)
	tr := tree(10)

	valid := func(pub any) *root.TransparencyLog {
		return &root.TransparencyLog{
			BaseURL: logURL, ID: []byte{1}, PublicKey: pub,
			ValidityPeriodStart: headTime.Add(-time.Hour),
		}
	}

	good := signedHead(t, key, tr, 10)

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		keys logs
		head func() *ctlog.TreeHead
		want string
	}{
		{name: "signed by the log's key", keys: logs{"a": valid(key.Public())}, head: func() *ctlog.TreeHead { return good }},
		{
			name: "the log's key among others for the same URL",
			keys: logs{"a": valid(other.Public()), "b": valid(key.Public())},
			head: func() *ctlog.TreeHead { return good },
		},
		{
			name: "signed by another key",
			keys: logs{"a": valid(other.Public())},
			head: func() *ctlog.TreeHead { return good },
			want: "the tree head of size 10 is not signed by a key the trusted root holds",
		},
		{
			name: "a key not yet valid at the head's moment",
			keys: logs{"a": {
				BaseURL: logURL, ID: []byte{1}, PublicKey: key.Public(),
				ValidityPeriodStart: headTime.Add(time.Hour),
			}},
			head: func() *ctlog.TreeHead { return good },
			want: "is not valid at 2026-11-17T13:21:00Z",
		},
		{
			name: "a key retired before the head's moment",
			keys: logs{"a": {
				BaseURL: logURL, ID: []byte{1}, PublicKey: key.Public(),
				ValidityPeriodStart: headTime.Add(-2 * time.Hour), ValidityPeriodEnd: headTime.Add(-time.Hour),
			}},
			head: func() *ctlog.TreeHead { return good },
			want: "is not valid at",
		},
		{
			name: "a key of a type certificate transparency does not sign with",
			keys: logs{"a": valid(edPub)},
			head: func() *ctlog.TreeHead { return good },
			want: "is not signed by a key the trusted root holds",
		},
		{
			name: "a root hash that is not a SHA-256 digest",
			keys: logs{"a": valid(key.Public())},
			head: func() *ctlog.TreeHead { h := *good; h.RootHash = []byte{1, 2, 3}; return &h },
			want: "the tree head's root hash is 3 bytes, not a SHA-256 digest",
		},
		{
			name: "a signature that does not parse",
			keys: logs{"a": valid(key.Public())},
			head: func() *ctlog.TreeHead { h := *good; h.Signature = []byte{4}; return &h },
			want: "the tree head signature does not parse",
		},
		{
			name: "a signature with bytes after it",
			keys: logs{"a": valid(key.Public())},
			head: func() *ctlog.TreeHead {
				h := *good
				h.Signature = append(append([]byte{}, good.Signature...), 0)

				return &h
			},
			want: "the tree head signature carries 1 trailing bytes",
		},
		{
			name: "a head whose size was changed after signing",
			keys: logs{"a": valid(key.Public())},
			head: func() *ctlog.TreeHead { h := *good; h.TreeSize = 11; return &h },
			want: "the tree head of size 11 is not signed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			v, err := ctlog.NewVerifier(tc.keys, logURL)
			if err != nil {
				t.Fatal(err)
			}

			err = v.VerifyTreeHead(tc.head())

			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("err = %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}
}

// TestNewVerifierNeedsTheLog: a URL the trusted root does not name has
// no key, and is refused rather than read unverified.
func TestNewVerifierNeedsTheLog(t *testing.T) {
	t.Parallel()

	_, err := ctlog.NewVerifier(logs{"a": {BaseURL: logURL + "/"}}, logURL)
	if err == nil || err.Error() != "ctlog: the trusted root names no certificate transparency log at "+logURL {
		t.Fatalf("err = %v", err)
	}
}

// proofs serves the consistency proofs of one tree, or a refusal.
type proofs struct {
	tree  *testonly.Tree
	err   error
	asked int
}

func (p *proofs) Consistency(_ context.Context, first, second uint64) ([][]byte, error) {
	p.asked++

	if p.err != nil {
		return nil, p.err
	}

	nodes, err := p.tree.ConsistencyProof(first, second)
	if err != nil {
		return nil, fmt.Errorf("proof %d..%d: %w", first, second, err)
	}

	return nodes, nil
}

// TestVerifyConsistency: a head extends a checkpoint's only when the
// log's proof says so — and a tree no larger needs no proof at all.
func TestVerifyConsistency(t *testing.T) {
	t.Parallel()

	key := newKey(t)
	honest := tree(20)

	forked := testonly.New(rfc6962.DefaultHasher)
	for i := range 20 {
		forked.AppendData([]byte{byte(i), byte(i >> 8), 'x'})
	}

	cases := []struct {
		name       string
		prev, next *ctlog.TreeHead
		read       *proofs
		asked      int
		want       string
	}{
		{
			name: "a grown tree", prev: signedHead(t, key, honest, 7), next: signedHead(t, key, honest, 20),
			read: &proofs{tree: honest}, asked: 1,
		},
		{
			name: "the same tree", prev: signedHead(t, key, honest, 7), next: signedHead(t, key, honest, 7),
			read: &proofs{tree: honest},
		},
		{
			name: "from the empty tree, which needs no proof", prev: signedHead(t, key, honest, 0),
			next: signedHead(t, key, honest, 20), read: &proofs{tree: honest},
		},
		{
			name: "a forked tree", prev: signedHead(t, key, honest, 7), next: signedHead(t, key, forked, 20),
			read: &proofs{tree: honest}, asked: 1, want: "the proof from size 7 to 20 does not verify",
		},
		{
			name: "a rewritten tree of the same size", prev: signedHead(t, key, honest, 7),
			next: signedHead(t, key, forked, 7), read: &proofs{tree: honest},
			want: "two trees of size 7 with different root hashes",
		},
		{
			name: "a shrunken tree", prev: signedHead(t, key, honest, 7), next: signedHead(t, key, honest, 6),
			read: &proofs{tree: honest}, want: "the log's tree of size 6 is smaller than the checkpoint's 7",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ctlog.VerifyConsistency(context.Background(), tc.prev, tc.next, tc.read)

			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("err = %v", err)
			case tc.want != "" && (!errors.Is(err, ctlog.ErrInconsistent) || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want ErrInconsistent saying %q", err, tc.want)
			}

			if tc.read.asked != tc.asked {
				t.Fatalf("asked for %d proofs, want %d", tc.read.asked, tc.asked)
			}
		})
	}

	t.Run("a proof the log will not serve is not an inconsistency", func(t *testing.T) {
		t.Parallel()

		read := &proofs{err: errors.New("HTTP 400")}

		prev, next := signedHead(t, key, honest, 7), signedHead(t, key, honest, 20)

		err := ctlog.VerifyConsistency(context.Background(), prev, next, read)
		if err == nil || errors.Is(err, ctlog.ErrInconsistent) || err.Error() != "HTTP 400" {
			t.Fatalf("err = %v", err)
		}
	})
}
