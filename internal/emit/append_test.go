package emit_test

import (
	"bytes"
	"encoding/base64"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/emit"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
)

// signHalf runs the signing half against a COPY of g's ledger at rev
// and returns the links it hands out — the bytes the copy stored, as
// the CLI reads them back out of a staged ledger. g itself is left
// untouched, as the append half's repository must be.
func (w *world) signHalf(t *testing.T, rev string, genesis bool, now func() time.Time) []emit.LinkFile {
	t.Helper()

	signer := *w.g
	signer.notes = cloneNotes(w.g.notes)
	signer.remote = cloneNotes(w.g.remote)

	in := w.in
	in.Rev, in.Genesis = rev, genesis

	revs, err := emit.ChainLinks(w.p, &in, &signer, w.s, fakeBV{}, now, discardLog)
	if err != nil {
		t.Fatalf("ChainLinks = %v", err)
	}

	links := make([]emit.LinkFile, 0, len(revs))
	for _, r := range revs {
		links = append(links, emit.LinkFile{Rev: r, Note: signer.notes[r]})
	}

	return links
}

func (w *world) appendInputs(links []emit.LinkFile) *emit.AppendInputs {
	return &emit.AppendInputs{Owner: "acme", Repo: "widget", Ref: "refs/heads/main", Links: links}
}

// TestAppendMatchesChainInOnePiece: the two halves, run in order
// against identical ledgers, publish exactly the notes Chain in one
// piece publishes — a heal included, so the second link's predecessor
// hash is the first link's stored bytes on both paths.
func TestAppendMatchesChainInOnePiece(t *testing.T) {
	t.Parallel()

	whole := newWorld(t)
	whole.found(t)

	if err := whole.emit(t); err != nil {
		t.Fatalf("Chain = %v", err)
	}

	split := newWorld(t)
	split.found(t)

	links := split.signHalf(t, rev4, false, fixedNow)
	if len(links) != 3 {
		t.Fatalf("signing half linked %d revision(s), want 3 (two holes and the pushed revision)", len(links))
	}

	if !maps.EqualFunc(split.g.notes, split.g.remote, bytes.Equal) || len(split.g.notes) != 1 {
		t.Fatal("the signing half wrote to the append half's ledger")
	}

	if err := emit.Append(split.p, split.appendInputs(links), split.g, fakeBV{}, discardLog); err != nil {
		t.Fatalf("Append = %v", err)
	}

	if !maps.EqualFunc(whole.g.remote, split.g.remote, bytes.Equal) {
		t.Fatal("the halves published a different ledger than Chain in one piece")
	}

	split.walk(t)
}

// TestAppendGenesis: the signing half founds, the append half writes
// the founding link, and the result walks clean.
func TestAppendGenesis(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	links := w.signHalf(t, rev1, true, fixedNow)

	if err := emit.Append(w.p, w.appendInputs(links), w.g, fakeBV{}, discardLog); err != nil {
		t.Fatalf("Append = %v", err)
	}

	if w.g.pushes != 1 || w.g.remote[rev1] == nil {
		t.Fatalf("genesis was not pushed: %d push(es)", w.g.pushes)
	}
}

// TestAppendNothingToAppend: an empty hand-off — the signing half
// found every revision linked — appends and pushes nothing.
func TestAppendNothingToAppend(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.found(t)

	if err := emit.Append(w.p, w.appendInputs(nil), w.g, fakeBV{}, discardLog); err != nil {
		t.Fatalf("Append = %v", err)
	}

	if w.g.pushes != 1 { // the founding push only
		t.Fatalf("an empty hand-off pushed: %d push(es)", w.g.pushes)
	}
}

// appendGit wraps the fake with the two failures its tables cannot
// script: a parent lookup that tears, and a read-back that tears
// only after the note was written.
type appendGit struct {
	*fakeGit

	failParent string
	tornRead   bool
	added      bool
}

func (g *appendGit) Parent(rev string) (string, error) {
	if rev == g.failParent {
		return "", fakeError("parent torn")
	}

	return g.fakeGit.Parent(rev)
}

func (g *appendGit) AddNote(rev string, note []byte) error {
	g.added = true

	return g.fakeGit.AddNote(rev, note)
}

func (g *appendGit) Note(rev string) ([]byte, error) {
	if g.tornRead && g.added {
		return nil, fakeError("read-back torn")
	}

	return g.fakeGit.Note(rev)
}

// tamperBundle swaps the provenance half's bundle for one covering a
// different digest — a link file edited after signing.
func tamperBundle(t *testing.T, note []byte) []byte {
	t.Helper()

	link, err := jsonx.DecodeBytes[chain.Note](note)
	if err != nil {
		t.Fatal(err)
	}

	link.Provenance.Bundle = mustJSON(t, fakeBundle{SAN: identity, Issuer: issuer, Digests: []string{"00"}})

	out, err := jsonx.Marshal(link)
	if err != nil {
		t.Fatal(err)
	}

	return append(out, '\n')
}

// restate replaces the provenance half's statement bytes.
func restate(t *testing.T, note []byte, statement string) []byte {
	t.Helper()

	link, err := jsonx.DecodeBytes[chain.Note](note)
	if err != nil {
		t.Fatal(err)
	}

	enc := base64.StdEncoding.EncodeToString([]byte(statement))
	link.Provenance.Statement = &enc

	out, err := jsonx.Marshal(link)
	if err != nil {
		t.Fatal(err)
	}

	return append(out, '\n')
}

// TestAppendOverScaffolding: a revision carrying a note that is not a
// link (scaffolding) is a hole, not a link — the append replaces it,
// as Chain in one piece does.
func TestAppendOverScaffolding(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.found(t)

	links := w.signHalf(t, rev2, false, fixedNow)
	w.g.notes[rev2] = []byte("scaffolding\n")

	if err := emit.Append(w.p, w.appendInputs(links), w.g, fakeBV{}, discardLog); err != nil {
		t.Fatalf("Append = %v", err)
	}

	if !bytes.Equal(w.g.remote[rev2], links[0].Note) {
		t.Fatal("the scaffolding note was not replaced by the link")
	}
}

// TestAppendRefusals: every guard branch, each asserting its message
// and that nothing was pushed — the remote ledger is exactly the one
// the founding left.
func TestAppendRefusals(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		// arrange returns the links to append and may reshape the world.
		arrange func(t *testing.T, w *world, g *appendGit) []emit.LinkFile
		policy  func(t *testing.T) *policy.Policy
		in      func(in *emit.AppendInputs)
		want    string
	}{
		{
			name: "no source section",
			arrange: func(t *testing.T, w *world, _ *appendGit) []emit.LinkFile {
				t.Helper()

				return w.signHalf(t, rev2, false, fixedNow)
			},
			policy: func(*testing.T) *policy.Policy { return &policy.Policy{} },
			want:   "declares no source section",
		},
		{
			name: "implausible repository",
			arrange: func(t *testing.T, w *world, _ *appendGit) []emit.LinkFile {
				t.Helper()

				return w.signHalf(t, rev2, false, fixedNow)
			},
			in:   func(in *emit.AppendInputs) { in.Owner = "ac me" },
			want: "is not a plausible repository",
		},
		{
			name: "unqualified ref",
			arrange: func(t *testing.T, w *world, _ *appendGit) []emit.LinkFile {
				t.Helper()

				return w.signHalf(t, rev2, false, fixedNow)
			},
			in:   func(in *emit.AppendInputs) { in.Ref = "main" },
			want: `ref "main" is not fully qualified`,
		},
		{
			name: "not a chain link",
			arrange: func(*testing.T, *world, *appendGit) []emit.LinkFile {
				return []emit.LinkFile{{Rev: rev2, Note: []byte("not a link\n")}}
			},
			want: "the link file for " + rev2 + " is not a chain link",
		},
		{
			name: "the file names another revision than the link attests",
			arrange: func(t *testing.T, w *world, _ *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)
				links[0].Rev = rev3

				return links
			},
			want: "the link file for " + rev3 + ": the link attests a different revision than its file names",
		},
		{
			name: "revision not on the branch",
			arrange: func(t *testing.T, w *world, g *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)
				g.order = []string{rev1}

				return links
			},
			want: "names a revision not on refs/heads/main",
		},
		{
			name: "branch membership unreadable",
			arrange: func(t *testing.T, w *world, g *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)
				g.ref = "refs/heads/elsewhere"

				return links
			},
			want: "unknown ref refs/heads/main",
		},
		{
			name: "the revision's own note unreadable",
			arrange: func(t *testing.T, w *world, g *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)
				g.readErr = map[string]error{"Note:" + rev2: fakeError("torn")}

				return links
			},
			want: "note for " + rev2 + ": torn",
		},
		{
			name: "the revision already carries a link",
			arrange: func(t *testing.T, w *world, g *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)
				g.notes[rev2] = g.notes[rev1]

				return links
			},
			want: "the ledger moved under this run — " + rev2 + " already carries a link; re-run the signing job",
		},
		{
			name: "genesis onto a founded history",
			arrange: func(t *testing.T, w *world, _ *appendGit) []emit.LinkFile {
				t.Helper()

				fresh := newWorld(t)
				fresh.s = w.s

				return fresh.signHalf(t, rev2, true, fixedNow)
			},
			want: "genesis refused — a chain link already exists on this history (at " + rev1 + ")",
		},
		{
			name: "a predecessor on a history that carries no link",
			arrange: func(t *testing.T, w *world, g *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)
				delete(g.notes, rev1)

				return links
			},
			want: "names predecessor " + rev1 + ", but no link exists on its history — the ledger moved under this run",
		},
		{
			name: "the chain's tip is not the predecessor named",
			arrange: func(t *testing.T, w *world, g *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)

				// The ledger was re-founded after signing: same
				// revision, different stored bytes.
				refounded := newWorld(t)
				refounded.s = w.s
				later := func() time.Time { return fixedNow().Add(time.Hour) }
				in := refounded.in
				in.Rev, in.Genesis = rev1, true

				if err := emit.Chain(refounded.p, &in, refounded.g, refounded.s, fakeBV{}, later, discardLog); err != nil {
					t.Fatal(err)
				}

				g.notes = cloneNotes(refounded.g.notes)
				g.remote = cloneNotes(refounded.g.remote)

				return links
			},
			want: "the ledger moved under this run — the link for " + rev2 + " names predecessor " + rev1,
		},
		{
			name: "the walk to the chain's tip cannot read a parent",
			arrange: func(t *testing.T, w *world, g *appendGit) []emit.LinkFile {
				t.Helper()

				// The pushed revision's link alone: its parent carries
				// no link, so the walk must read one parent further.
				links := w.signHalf(t, rev3, false, fixedNow)[1:]
				g.failParent = rev2

				return links
			},
			want: "parent of " + rev2 + ": parent torn",
		},
		{
			name: "the revision's parent cannot be read",
			arrange: func(t *testing.T, w *world, g *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)
				g.failParent = rev2

				return links
			},
			want: "parent of " + rev2 + ": parent torn",
		},
		{
			name: "the walk to the chain's tip cannot read a note",
			arrange: func(t *testing.T, w *world, g *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)
				g.readErr = map[string]error{"Note:" + rev1: fakeError("torn")}

				return links
			},
			want: "note for " + rev1 + ": torn",
		},
		{
			name: "the provenance statement is not a statement",
			arrange: func(t *testing.T, w *world, _ *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)
				links[0].Note = restate(t, links[0].Note, "not json")

				return links
			},
			want: "the link file for " + rev2 + ": provenance statement",
		},
		{
			name: "the provenance predicate is not a chain predicate",
			arrange: func(t *testing.T, w *world, _ *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)
				links[0].Note = restate(t, links[0].Note, `{"_type":"https://in-toto.io/Statement/v1",`+
					`"subject":[{"uri":"x","digest":{"gitCommit":"`+rev2+`"}}],"predicateType":"x","predicate":5}`)

				return links
			},
			want: "the link file for " + rev2 + ": predicate",
		},
		{
			name: "the ledger cannot be listed for the walk",
			arrange: func(t *testing.T, w *world, g *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)
				g.readErr = map[string]error{"Noted": fakeError("torn listing")}

				return links
			},
			want: "the chain it would extend does not verify",
		},
		{
			name: "a tampered link file",
			arrange: func(t *testing.T, w *world, _ *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)
				links[0].Note = tamperBundle(t, links[0].Note)

				return links
			},
			want: "the link file for " + rev2 + " is refused — the chain it would extend does not verify",
		},
		{
			name: "the note write fails",
			arrange: func(t *testing.T, w *world, g *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)
				g.readErr = map[string]error{"AddNote": fakeError("store full")}

				return links
			},
			want: "store full",
		},
		{
			name: "the read-back tears",
			arrange: func(t *testing.T, w *world, g *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)
				g.tornRead = true

				return links
			},
			want: "reading back the note for " + rev2 + ": read-back torn",
		},
		{
			name: "git stores other bytes than the file carries",
			arrange: func(t *testing.T, w *world, _ *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)
				links[0].Note = bytes.TrimRight(links[0].Note, "\n")

				return links
			},
			want: "git stored the link for " + rev2 + " as different bytes than the file carries",
		},
		{
			name: "the push is rejected",
			arrange: func(t *testing.T, w *world, g *appendGit) []emit.LinkFile {
				t.Helper()

				links := w.signHalf(t, rev2, false, fixedNow)
				g.onPush = func(*fakeGit) error { return fakeError("non-fast-forward") }

				return links
			},
			want: "notes push rejected — the ledger moved under this run; re-run it from the signing job",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newWorld(t)
			w.found(t)

			g := &appendGit{fakeGit: w.g}
			links := tt.arrange(t, w, g)
			remote := cloneNotes(g.remote)
			pushes := g.pushes

			p := w.p
			if tt.policy != nil {
				p = tt.policy(t)
			}

			in := w.appendInputs(links)
			if tt.in != nil {
				tt.in(in)
			}

			err := emit.Append(p, in, g, fakeBV{}, discardLog)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Append = %v, want it to mention %q", err, tt.want)
			}

			if !maps.EqualFunc(g.remote, remote, bytes.Equal) {
				t.Fatal("a refused append changed the published ledger")
			}

			if tt.name != "the push is rejected" && g.pushes != pushes {
				t.Fatalf("a refused append pushed: %d push(es) after the founding's %d", g.pushes, pushes)
			}
		})
	}
}

// TestLinkFilesRoundTrip: what WriteLinks places, ReadLinks reads
// back whole and in order.
func TestLinkFilesRoundTrip(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "links")
	want := []emit.LinkFile{{Rev: rev2, Note: []byte("two\n")}, {Rev: rev3, Note: []byte("three\n")}}

	if err := emit.WriteLinks(dir, want); err != nil {
		t.Fatalf("WriteLinks = %v", err)
	}

	got, err := emit.ReadLinks(dir)
	if err != nil {
		t.Fatalf("ReadLinks = %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("ReadLinks = %d link(s), want %d", len(got), len(want))
	}

	for i := range want {
		if got[i].Rev != want[i].Rev || !bytes.Equal(got[i].Note, want[i].Note) {
			t.Fatalf("link %d = %s %q, want %s %q", i, got[i].Rev, got[i].Note, want[i].Rev, want[i].Note)
		}
	}
}

// TestLinkFilesRefusals: every guard branch of the hand-off.
func TestLinkFilesRefusals(t *testing.T) {
	t.Parallel()

	link := []emit.LinkFile{{Rev: rev2, Note: []byte("two\n")}}

	write := func(t *testing.T, dir, name, content string, mode os.FileMode) {
		t.Helper()

		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}

	readOnly := func(t *testing.T, dir string, mode os.FileMode) {
		t.Helper()

		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() {
			_ = os.Chmod(dir, 0o700) //nolint:gosec,errcheck // G302: restoring a test directory; best-effort
		})
	}

	for _, tt := range []struct {
		name  string
		write bool
		// arrange returns the directory the operation runs on.
		arrange func(t *testing.T) string
		want    string
	}{
		{
			name:  "write: the directory cannot be created",
			write: true,
			arrange: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				write(t, dir, "file", "", 0o600)

				return filepath.Join(dir, "file", "links")
			},
			want: "link directory",
		},
		{
			name:  "write: the directory cannot be listed",
			write: true,
			arrange: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				readOnly(t, dir, 0o300)

				return dir
			},
			want: "permission denied",
		},
		{
			name:  "write: the directory already holds something",
			write: true,
			arrange: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				write(t, dir, "0001-"+rev1+".json", "stale", 0o600)

				return dir
			},
			want: "is not empty — links from another run would be appended as this run's",
		},
		{
			name:  "write: a link cannot be written",
			write: true,
			arrange: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				readOnly(t, dir, 0o500)

				return dir
			},
			want: "writing link",
		},
		{
			name: "read: the directory is missing",
			arrange: func(t *testing.T) string {
				t.Helper()

				return filepath.Join(t.TempDir(), "absent")
			},
			want: "link directory",
		},
		{
			name: "read: an entry is not a link file",
			arrange: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				write(t, dir, "notes.txt", "", 0o600)

				return dir
			},
			want: "notes.txt in the link directory is not a link file",
		},
		{
			name: "read: a directory named like a link",
			arrange: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				if err := os.Mkdir(filepath.Join(dir, "0001-"+rev2+".json"), 0o700); err != nil {
					t.Fatal(err)
				}

				return dir
			},
			want: "is not a link file",
		},
		{
			name: "read: a link file is missing from the sequence",
			arrange: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				write(t, dir, "0001-"+rev2+".json", "two", 0o600)
				write(t, dir, "0003-"+rev4+".json", "four", 0o600)

				return dir
			},
			want: "link file 0003-" + rev4 + ".json is out of sequence — expected position 0002; a link file is missing",
		},
		{
			name: "read: a link file cannot be read",
			arrange: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				write(t, dir, "0001-"+rev2+".json", "two", 0o000)

				return dir
			},
			want: "link file 0001-" + rev2 + ".json",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := tt.arrange(t)

			var err error
			if tt.write {
				err = emit.WriteLinks(dir, link)
			} else {
				_, err = emit.ReadLinks(dir)
			}

			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want it to mention %q", err, tt.want)
			}
		})
	}
}
