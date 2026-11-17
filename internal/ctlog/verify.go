// The log's own word about itself: a tree head signed by a key the
// trusted root names, and a proof that today's tree extends the one a
// checkpoint recorded. Entries are NOT proven against the head, one
// by one — the rejected alternative on stele#387: one request per
// entry against a log growing by about 69,000 an hour. get-entries
// content is the log operator's word, and the log operator is the
// certificate authority's operator.

package ctlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// ErrInconsistent reports a tree head that does not extend the one a
// checkpoint recorded: a log that shrank, rewrote a tree of the same
// size, or served a proof that does not verify. Either the log forked
// its history or the checkpoint is not this log's — both are refused
// by name, never judged past.
var ErrInconsistent = errors.New("ctlog: the log's tree head is not consistent with the checkpoint's")

// Verifier holds the keys the trusted root names for one log URL.
type Verifier struct {
	url  string
	keys []*root.TransparencyLog
}

// LogSource is the part of the trusted material a verifier reads:
// root.TrustedMaterial in a run.
type LogSource interface {
	CTLogs() map[string]*root.TransparencyLog
}

// NewVerifier selects the trusted root's keys for one log, matched by
// the base URL exactly as the root spells it. No key is a refusal: a
// tree head nobody can verify is a head this reader does not take.
func NewVerifier(trusted LogSource, url string) (*Verifier, error) {
	var keys []*root.TransparencyLog

	for _, l := range trusted.CTLogs() {
		if l.BaseURL == url {
			keys = append(keys, l)
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("ctlog: the trusted root names no certificate transparency log at %s", url)
	}

	return &Verifier{url: url, keys: keys}, nil
}

// VerifyTreeHead checks the head's signature against a key the trusted
// root holds for this log and that was valid at the head's own
// timestamp.
func (v *Verifier) VerifyTreeHead(h *TreeHead) error {
	if len(h.RootHash) != sha256Size {
		return fmt.Errorf("ctlog: %s: the tree head's root hash is %d bytes, not a SHA-256 digest", v.url, len(h.RootHash))
	}

	var sig ct.DigitallySigned

	rest, err := cttls.Unmarshal(h.Signature, (*cttls.DigitallySigned)(&sig))
	if err != nil {
		return fmt.Errorf("ctlog: %s: the tree head signature does not parse: %w", v.url, err)
	}

	if len(rest) > 0 {
		return fmt.Errorf("ctlog: %s: the tree head signature carries %d trailing bytes", v.url, len(rest))
	}

	sth := ct.SignedTreeHead{
		Version:           ct.V1,
		TreeSize:          h.TreeSize,
		Timestamp:         h.Timestamp,
		SHA256RootHash:    ct.SHA256Hash(h.RootHash),
		TreeHeadSignature: sig,
	}

	at := h.Time()

	var errs []error

	for _, k := range v.keys {
		if !validAt(k, at) {
			errs = append(errs, fmt.Errorf("key %x is not valid at %s", k.ID, at.Format(time.RFC3339)))

			continue
		}

		sv, kerr := ct.NewSignatureVerifier(k.PublicKey)
		if kerr != nil {
			errs = append(errs, fmt.Errorf("key %x: %w", k.ID, kerr))

			continue
		}

		if verr := sv.VerifySTHSignature(sth); verr != nil {
			errs = append(errs, fmt.Errorf("key %x: %w", k.ID, verr))

			continue
		}

		return nil
	}

	return fmt.Errorf("ctlog: %s: the tree head of size %d is not signed by a key the trusted root holds: %w",
		v.url, h.TreeSize, errors.Join(errs...))
}

// validAt reports whether a key's validity period covers a moment. A
// zero end is an open period, the shape a log still in service has.
func validAt(k *root.TransparencyLog, at time.Time) bool {
	if !k.ValidityPeriodStart.IsZero() && at.Before(k.ValidityPeriodStart) {
		return false
	}

	return k.ValidityPeriodEnd.IsZero() || !at.After(k.ValidityPeriodEnd)
}

// ConsistencyReader is the one read VerifyConsistency may need:
// *Client in a run.
type ConsistencyReader interface {
	Consistency(ctx context.Context, first, second uint64) ([][]byte, error)
}

// VerifyConsistency proves that next extends prev. Both heads must
// already be verified: this checks history, not signatures. A tree no
// larger than prev needs no request and is judged on its own bytes.
func VerifyConsistency(ctx context.Context, prev, next *TreeHead, read ConsistencyReader) error {
	switch {
	case next.TreeSize < prev.TreeSize:
		return fmt.Errorf("%w: the log's tree of size %d is smaller than the checkpoint's %d",
			ErrInconsistent, next.TreeSize, prev.TreeSize)
	case next.TreeSize == prev.TreeSize:
		if !bytes.Equal(next.RootHash, prev.RootHash) {
			return fmt.Errorf("%w: two trees of size %d with different root hashes", ErrInconsistent, next.TreeSize)
		}

		return nil
	case prev.TreeSize == 0:
		// The empty tree is a prefix of every tree; RFC 6962 defines no
		// proof for it.
		return nil
	}

	nodes, err := read.Consistency(ctx, prev.TreeSize, next.TreeSize)
	if err != nil {
		return err
	}

	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, prev.TreeSize, next.TreeSize, nodes,
		prev.RootHash, next.RootHash); err != nil {
		return fmt.Errorf("%w: the proof from size %d to %d does not verify: %w",
			ErrInconsistent, prev.TreeSize, next.TreeSize, err)
	}

	return nil
}
