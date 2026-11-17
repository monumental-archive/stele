package gitrepo

import (
	"bufio"
	"strings"
	"testing"
)

// The parse guards git itself never trips: each refuses a shape a
// healthy store does not produce, so each is driven here from the
// bytes alone (the table-test-per-guard rule).

const (
	oidA = "1111111111111111111111111111111111111111"
	oidB = "2222222222222222222222222222222222222222"
)

func TestParseTagRefsRefusals(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, out string }{
		{name: "too few fields", out: "tag " + oidA + "\n"},
		{name: "not an object id", out: "tag abc refs/tags/v1\n"},
		{name: "not under refs/tags", out: "tag " + oidA + " refs/heads/main\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := parseTagRefs([]byte(tc.out)); err == nil ||
				!strings.Contains(err.Error(), "is not the requested format") {
				t.Fatalf("parseTagRefs = %v, want the format refusal", err)
			}
		})
	}
}

func TestParseTagObject(t *testing.T) {
	t.Parallel()

	const head = "object " + oidA + "\ntype commit\ntag v1\n"

	for _, tc := range []struct {
		name, raw, says string
		signed          bool
	}{
		{name: "no tagger", raw: head + "\nmessage\n", says: "missing tagger or target"},
		{name: "a tagger with no address", raw: head + "tagger nobody\n\nm\n", says: "missing tagger or target"},
		{name: "no target", raw: "type commit\ntag v1\ntagger a <a@b> 1 +0000\n\nm\n", says: "missing tagger or target"},
		{name: "a short target", raw: "object abc\ntagger a <a@b> 1 +0000\n\nm\n", says: "missing tagger or target"},
		{name: "unsigned", raw: head + "tagger a <a@b> 1 +0000\n\nm\n"},
		{
			// The LAST opening line starts the block: a marker quoted in
			// the message body is message, not signature.
			name: "a marker in the message before the real block",
			raw: head + "tagger a <a@b> 1 +0000\n\n-----BEGIN PGP SIGNATURE----- quoted\n" +
				"-----BEGIN SSH SIGNATURE-----\nsig\n-----END SSH SIGNATURE-----\n",
			signed: true,
		},
		{
			name:   "a block with no trailing newline",
			raw:    head + "tagger a <a@b> 1 +0000\n\nm\n-----BEGIN PGP MESSAGE-----",
			signed: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			obj, err := parseTagObject(oidB, []byte(tc.raw))
			if tc.says != "" {
				if err == nil || !strings.Contains(err.Error(), tc.says) {
					t.Fatalf("parseTagObject = %v, want %q", err, tc.says)
				}

				return
			}

			if err != nil {
				t.Fatalf("parseTagObject = %v", err)
			}

			if (obj.Signature != nil) != tc.signed || string(obj.Payload)+string(obj.Signature) != tc.raw && tc.signed {
				t.Fatalf("parseTagObject = payload %q signature %q", obj.Payload, obj.Signature)
			}

			if tc.signed && !strings.HasPrefix(string(obj.Signature), "-----BEGIN") {
				t.Fatalf("signature = %q, want it to start at the last opening line", obj.Signature)
			}

			if tc.signed && strings.Contains(string(obj.Signature), "quoted") {
				t.Fatalf("signature = %q, took the quoted marker as the block", obj.Signature)
			}
		})
	}
}

func TestParseNotesListRefusals(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, out string }{
		{name: "one column", out: oidA + "\n"},
		{name: "a short blob", out: "abc " + oidA + "\n"},
		{name: "a short revision", out: oidA + " abc\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, _, err := parseNotesList([]byte(tc.out)); err == nil ||
				!strings.Contains(err.Error(), "is not a blob and a revision") {
				t.Fatalf("parseNotesList = %v, want the format refusal", err)
			}
		})
	}
}

func TestBatchEntryRefusals(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, out, says string }{
		{name: "an empty batch", out: "", says: "the batch ended early"},
		{name: "a missing object", out: oidA + " missing\n", says: "the store answered"},
		{name: "another object first", out: oidB + " blob 1\nx\n", says: "the store answered"},
		{name: "not a blob", out: oidA + " tree 1\nx\n", says: "the store answered"},
		{name: "an unreadable size", out: oidA + " blob many\nx\n", says: "size"},
		{name: "a negative size", out: oidA + " blob -1\nx\n", says: "size"},
		{name: "content cut short", out: oidA + " blob 9\nx\n", says: "the batch ended early"},
		{name: "an unterminated record", out: oidA + " blob 1\nxy", says: "is not terminated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := batchEntry(bufio.NewReader(strings.NewReader(tc.out)), oidA)
			if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("batchEntry = %v, want %q", err, tc.says)
			}
		})
	}

	got, err := batchEntry(bufio.NewReader(strings.NewReader(oidA+" blob 3\na\nb\n")), oidA)
	if err != nil || string(got) != "a\nb" {
		t.Fatalf("batchEntry = %q, %v — the content is read by size, newlines and all", got, err)
	}
}

func TestParseCommit(t *testing.T) {
	t.Parallel()

	const tree = "tree " + oidA + "\n"

	for _, tc := range []struct {
		name, raw, says, subject string
		epoch                    int64
		parents                  int
	}{
		{name: "no committer", raw: tree + "author a <a@b> 1 +0000\n\nm\n", says: "carries no committer"},
		{name: "a committer naming no time", raw: tree + "committer a\n\nm\n", says: "names no time"},
		{name: "an unreadable time", raw: tree + "committer a <a@b> soon +0000\n\nm\n", says: "time \"soon\""},
		{
			// A signature header's continuation lines carry no key and
			// are passed over, never read as a parent or a committer.
			name: "a signed merge",
			raw: tree + "parent " + oidA + "\nparent " + oidB + "\nauthor a <a@b> 5 +0000\n" +
				"committer c <c@d> 7 +0100\ngpgsig -----BEGIN SSH SIGNATURE-----\n parent " + oidB +
				"\n -----END SSH SIGNATURE-----\n\nmerge: two lines\nof subject\n\nbody\n",
			subject: "merge: two lines", epoch: 7, parents: 2,
		},
		{name: "an empty message", raw: tree + "committer c <c@d> 9 +0000\n", epoch: 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			meta, err := parseCommit(oidB, []byte(tc.raw))
			if tc.says != "" {
				if err == nil || !strings.Contains(err.Error(), tc.says) {
					t.Fatalf("parseCommit = %v, want %q", err, tc.says)
				}

				return
			}

			if err != nil || meta.Subject != tc.subject || meta.CommitEpoch != tc.epoch || len(meta.Parents) != tc.parents {
				t.Fatalf("parseCommit = %+v, %v", meta, err)
			}
		})
	}
}
