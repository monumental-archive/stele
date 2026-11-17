// The checkpoint: stele's own record of how far a log has been judged
// (stele#387). Three facts and a version — the log it belongs to, the
// last tree head this reader verified, and `next`, the first index not
// yet judged. Where the file is kept between runs is the caller's
// business; this package only reads it, writes it whole, and refuses
// to invent one.
//
// It carries its OWN version number, not the live-read epoch
// (docs/versioning.md): the file persists between runs, so tying it to
// the epoch would orphan every watch's checkpoint at each policy key
// change and force a re-founding by --start-at.

package ctlog

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// CheckpointSchema is the checkpoint's own version: a reader of
// another refuses it as a version, never as an unknown field.
const CheckpointSchema = 1

// ErrNoCheckpoint reports that no checkpoint file exists where one
// was named. Starting is a decision a person makes (--start-at),
// never something a missing file decides: a watch that starts itself
// from the head has silently skipped everything since its last run
// (.github#1145, measured 2026-11-13).
var ErrNoCheckpoint = errors.New("ctlog: no checkpoint")

// Checkpoint is one log's judged prefix.
type Checkpoint struct {
	// Log is the log's base URL, as the policy and the trusted root
	// spell it.
	Log string
	// TreeHead is the last tree head this reader verified.
	TreeHead TreeHead
	// Next is the first index not yet judged: everything below it was.
	Next uint64
}

// checkpointDoc is the file's shape. Pointer fields: absent and zero
// are different facts, and a zero `next` is a real position.
type checkpointDoc struct {
	Schema   *int         `json:"schema"`
	Log      *string      `json:"log"`
	TreeHead *treeHeadDoc `json:"treeHead"`
	Next     *uint64      `json:"next"`
}

type treeHeadDoc struct {
	TreeSize  *uint64 `json:"treeSize"`
	Timestamp *uint64 `json:"timestamp"`
	RootHash  *string `json:"rootHash"`
	Signature *string `json:"signature"`
}

// ReadCheckpoint reads the checkpoint at path. A file that is not
// there is ErrNoCheckpoint; a file that is there and does not read is
// an error naming it — never a reason to start over.
func ReadCheckpoint(path string) (*Checkpoint, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the checkpoint path is operator-supplied by design
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w at %s", ErrNoCheckpoint, path)
	}

	if err != nil {
		return nil, fmt.Errorf("ctlog: checkpoint: %w", err)
	}

	cp, err := decodeCheckpoint(b)
	if err != nil {
		return nil, fmt.Errorf("ctlog: checkpoint %s: %w", path, err)
	}

	return cp, nil
}

func decodeCheckpoint(b []byte) (*Checkpoint, error) {
	d, err := jsonx.DecodeVersioned[checkpointDoc](bytes.NewReader(b), CheckpointSchema)
	if err != nil {
		return nil, err
	}

	switch {
	case d.Log == nil || *d.Log == "":
		return nil, errors.New("log is absent or empty")
	case d.TreeHead == nil:
		return nil, errors.New("treeHead is absent")
	case d.Next == nil:
		return nil, errors.New("next is absent")
	}

	th, err := d.TreeHead.decode()
	if err != nil {
		return nil, err
	}

	// A judged prefix longer than the tree it was judged against is a
	// file nobody wrote through this package — and the gap it claims
	// was never read.
	if *d.Next > th.TreeSize {
		return nil, fmt.Errorf("next %d is beyond the tree head's size %d", *d.Next, th.TreeSize)
	}

	return &Checkpoint{Log: *d.Log, TreeHead: *th, Next: *d.Next}, nil
}

func (d *treeHeadDoc) decode() (*TreeHead, error) {
	if d.TreeSize == nil || d.Timestamp == nil || d.RootHash == nil || d.Signature == nil {
		return nil, errors.New("treeHead lacks treeSize, timestamp, rootHash or signature")
	}

	root, err := base64.StdEncoding.DecodeString(*d.RootHash)
	if err != nil || len(root) != sha256Size {
		return nil, fmt.Errorf("treeHead.rootHash is not a base64 SHA-256 digest: %q", *d.RootHash)
	}

	sig, err := base64.StdEncoding.DecodeString(*d.Signature)
	if err != nil || len(sig) == 0 {
		return nil, fmt.Errorf("treeHead.signature is not base64: %q", *d.Signature)
	}

	return &TreeHead{TreeSize: *d.TreeSize, Timestamp: *d.Timestamp, RootHash: root, Signature: sig}, nil
}

// WriteCheckpoint writes the checkpoint whole and atomically: a
// temporary file beside the target, then a rename. A run killed at any
// instant leaves either the previous checkpoint or this one, never a
// torn file that the next run would have to refuse.
func WriteCheckpoint(path string, cp *Checkpoint) error {
	schema := CheckpointSchema
	root := base64.StdEncoding.EncodeToString(cp.TreeHead.RootHash)
	sig := base64.StdEncoding.EncodeToString(cp.TreeHead.Signature)

	var buf bytes.Buffer

	if err := jsonx.Encode(&buf, checkpointDoc{
		Schema: &schema,
		Log:    &cp.Log,
		TreeHead: &treeHeadDoc{
			TreeSize:  &cp.TreeHead.TreeSize,
			Timestamp: &cp.TreeHead.Timestamp,
			RootHash:  &root,
			Signature: &sig,
		},
		Next: &cp.Next,
	}); err != nil {
		return fmt.Errorf("ctlog: checkpoint: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("ctlog: checkpoint: %w", err)
	}

	// Removing the temporary file after a successful rename fails with
	// not-exist, which is the success case.
	defer os.Remove(tmp.Name()) //nolint:errcheck // cleanup of a file that is renamed away on success

	if err := fill(tmp, buf.Bytes()); err != nil {
		return fmt.Errorf("ctlog: checkpoint: %w", err)
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("ctlog: checkpoint: %w", err)
	}

	return nil
}

// fill writes, syncs and closes the temporary file, closing it
// whatever happened before: a rename of a file still open, or of one
// whose bytes never reached the disk, would publish a checkpoint the
// next run cannot trust.
func fill(f *os.File, b []byte) error {
	_, err := f.Write(b)
	if err == nil {
		err = f.Sync()
	}

	return errors.Join(err, f.Close())
}

// HeadTime renders the checkpoint's tree head time the way a report
// names it.
func (cp *Checkpoint) HeadTime() string {
	return cp.TreeHead.Time().Format(time.RFC3339)
}
