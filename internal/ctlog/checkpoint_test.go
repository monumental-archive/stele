package ctlog_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/ctlog"
)

const goodCheckpoint = `{"schema": 1, "log": "https://ct.example/2026", ` +
	`"treeHead": {"treeSize": 447703932, "timestamp": 1794921660000, ` +
	`"rootHash": "u0YV2ESvJeMovY8f2ScbMNlhPDT88X9A4QWMWfR/dXE=", "signature": "BAMARzBF"}, "next": 445241315}`

func writeFile(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// TestCheckpointRoundTrip: what is written is what is read, and the
// write leaves no temporary file behind.
func TestCheckpointRoundTrip(t *testing.T) {
	t.Parallel()

	cp, err := ctlog.ReadCheckpoint(writeFile(t, goodCheckpoint))
	if err != nil {
		t.Fatal(err)
	}

	if cp.Log != "https://ct.example/2026" || cp.Next != 445241315 || cp.TreeHead.TreeSize != 447703932 ||
		cp.HeadTime() != "2026-11-17T13:21:00Z" {
		t.Fatalf("checkpoint = %+v at %s", cp, cp.HeadTime())
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "cp.json")

	if werr := ctlog.WriteCheckpoint(path, cp); werr != nil {
		t.Fatal(werr)
	}

	again, err := ctlog.ReadCheckpoint(path)
	if err != nil {
		t.Fatal(err)
	}

	if again.Log != cp.Log || again.Next != cp.Next || again.TreeHead.Timestamp != cp.TreeHead.Timestamp ||
		!bytes.Equal(again.TreeHead.RootHash, cp.TreeHead.RootHash) ||
		!bytes.Equal(again.TreeHead.Signature, cp.TreeHead.Signature) {
		t.Fatalf("read back %+v, wrote %+v", again, cp)
	}

	// Overwriting is the steady state: every done chunk rewrites it.
	cp.Next++
	if werr := ctlog.WriteCheckpoint(path, cp); werr != nil {
		t.Fatal(werr)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 1 || entries[0].Name() != "cp.json" {
		t.Fatalf("the directory holds %v, want the checkpoint alone", entries)
	}
}

// TestReadCheckpointRefusals: absent is ErrNoCheckpoint — a person's
// decision waiting to be made — and every other shape is refused by
// name, never read as a reason to start over.
func TestReadCheckpointRefusals(t *testing.T) {
	t.Parallel()

	t.Run("absent", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "none.json")

		_, err := ctlog.ReadCheckpoint(path)
		if !errors.Is(err, ctlog.ErrNoCheckpoint) || !strings.Contains(err.Error(), path) {
			t.Fatalf("err = %v, want ErrNoCheckpoint naming %s", err, path)
		}
	})

	t.Run("unreadable", func(t *testing.T) {
		t.Parallel()

		_, err := ctlog.ReadCheckpoint(t.TempDir())
		if err == nil || errors.Is(err, ctlog.ErrNoCheckpoint) || !strings.HasPrefix(err.Error(), "ctlog: checkpoint: ") {
			t.Fatalf("err = %v", err)
		}
	})

	cases := []struct{ name, from, to, want string }{
		{"another version", `"schema": 1`, `"schema": 2`, "schema 2 is not the implemented schema 1"},
		{"no version", `"schema": 1, `, ``, "schema is absent"},
		{"an unknown field", `"next"`, `"nxt"`, `unknown field "nxt"`},
		{"no log", `"log": "https://ct.example/2026", `, ``, "log is absent or empty"},
		{"an empty log", `"log": "https://ct.example/2026"`, `"log": ""`, "log is absent or empty"},
		{
			"no tree head", `"treeHead": {"treeSize": 447703932, "timestamp": 1794921660000, ` +
				`"rootHash": "u0YV2ESvJeMovY8f2ScbMNlhPDT88X9A4QWMWfR/dXE=", "signature": "BAMARzBF"}, `, ``,
			"treeHead is absent",
		},
		{"no next", `, "next": 445241315`, ``, "next is absent"},
		{
			"a tree head field absent", `"timestamp": 1794921660000, `, ``,
			"treeHead lacks treeSize, timestamp, rootHash or signature",
		},
		{
			"a root hash that is not one", `"rootHash": "u0YV`, `"rootHash": "!!!`,
			"treeHead.rootHash is not a base64 SHA-256 digest",
		},
		{
			"a signature that is not base64", `"signature": "BAMARzBF"`, `"signature": "!!"`,
			"treeHead.signature is not base64",
		},
		{"an empty signature", `"signature": "BAMARzBF"`, `"signature": ""`, "treeHead.signature is not base64"},
		{
			"a next past the head", `"next": 445241315`, `"next": 447703933`,
			"next 447703933 is beyond the tree head's size 447703932",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc := strings.Replace(goodCheckpoint, tc.from, tc.to, 1)
			if doc == goodCheckpoint {
				t.Fatalf("the row's edit %q matched nothing", tc.from)
			}

			path := writeFile(t, doc)

			_, err := ctlog.ReadCheckpoint(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), path) {
				t.Fatalf("err = %v, want it to name %s and say %q", err, path, tc.want)
			}
		})
	}
}

// TestWriteCheckpointRefusals: a write that cannot land says so, and
// never leaves a torn file where the checkpoint was.
func TestWriteCheckpointRefusals(t *testing.T) {
	t.Parallel()

	cp, err := ctlog.ReadCheckpoint(writeFile(t, goodCheckpoint))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("a directory that is not there", func(t *testing.T) {
		t.Parallel()

		err := ctlog.WriteCheckpoint(filepath.Join(t.TempDir(), "missing", "cp.json"), cp)
		if err == nil || !strings.HasPrefix(err.Error(), "ctlog: checkpoint: ") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("a target the rename cannot replace", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		target := filepath.Join(dir, "cp.json")

		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(target, "keep"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}

		err := ctlog.WriteCheckpoint(target, cp)
		if err == nil || !strings.HasPrefix(err.Error(), "ctlog: checkpoint: rename ") {
			t.Fatalf("err = %v", err)
		}

		entries, rerr := os.ReadDir(dir)
		if rerr != nil {
			t.Fatal(rerr)
		}

		if len(entries) != 1 {
			t.Fatalf("a failed write left %v behind", entries)
		}
	})
}
