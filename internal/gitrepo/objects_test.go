package gitrepo_test

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gitrepo"
	"github.com/monumental-archive/stele/internal/gittest"
)

// tagWorld is a repository carrying every shape a tag walk reads: a
// signed and an unsigned annotated tag, a lightweight one, a merge, and
// a ledger holding a link and a scaffolding note.
type tagWorld struct {
	repo                   *gittest.Repo
	root, side, merge, tip string
	signedRaw              []byte
	signedSHA, unsignedSHA string
	linkNote, scaffoldNote []byte
}

func newTagWorld(t *testing.T) tagWorld {
	t.Helper()

	r := gittest.New(t)
	w := tagWorld{repo: r}

	w.root = r.Commit("feat: the first commit\n\nwith a body")
	r.Git("checkout", "-q", "-b", "side")
	w.side = r.Commit("fix: on the side")
	r.Git("checkout", "-q", "main")
	r.Commit("chore: on main")
	r.Git("merge", "-q", "--no-ff", "-m", "merge the side", "side")
	w.merge = r.Git("rev-parse", "HEAD")
	w.tip = r.Commit("docs: the tip")

	w.signedRaw, w.signedSHA = r.Annotated("v1.0.0", w.merge, "tag-mint[bot]", true)
	_, w.unsignedSHA = r.Annotated("v0.9.0", w.root, "someone", false)
	r.Lightweight("v0.1.0", w.root)

	w.linkNote = []byte(`{"version": 3, "provenance": {"bundle": {}}}`)
	w.scaffoldNote = []byte("scaffolding, not a link\n")
	r.Note(notesRef, w.tip, w.linkNote)
	r.Note(notesRef, w.root, w.scaffoldNote)

	return w
}

func openAt(t *testing.T, dir string) *gitrepo.Repo {
	t.Helper()

	r, err := gitrepo.Open(dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	return r
}

func TestTagRefsListsEveryTagWithItsKind(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)

	got, err := openAt(t, w.repo.Dir).TagRefs()
	if err != nil {
		t.Fatalf("TagRefs = %v", err)
	}

	want := []gitrepo.TagRef{
		{Name: "v0.1.0", ObjectSHA: w.root, Annotated: false},
		{Name: "v0.9.0", ObjectSHA: w.unsignedSHA, Annotated: true},
		{Name: "v1.0.0", ObjectSHA: w.signedSHA, Annotated: true},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("TagRefs =\n%+v\nwant\n%+v", got, want)
	}
}

func TestTagRefsOfAnUntaggedRepositoryIsEmpty(t *testing.T) {
	t.Parallel()

	r := gittest.New(t)
	r.Commit("feat: one")

	got, err := openAt(t, r.Dir).TagRefs()
	if err != nil || len(got) != 0 {
		t.Fatalf("TagRefs = %v, %v — no tags is an answer", got, err)
	}
}

// TestTagObjectSplitsTheSignatureAsGitDoes: the payload is every byte
// before the signature block and the block is the rest, so the two
// rejoin into the stored object exactly.
func TestTagObjectSplitsTheSignatureAsGitDoes(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)
	r := openAt(t, w.repo.Dir)

	signed, err := r.TagObject(w.signedSHA)
	if err != nil {
		t.Fatalf("TagObject = %v", err)
	}

	if signed.Tagger != "tag-mint[bot]" || signed.Target != w.merge {
		t.Fatalf("TagObject = %+v, want the mint's tag on the merge", signed)
	}

	if string(signed.Signature) != gittest.Signature {
		t.Fatalf("Signature = %q, want the block alone", signed.Signature)
	}

	if !bytes.Equal(append(slices.Clone(signed.Payload), signed.Signature...), w.signedRaw) {
		t.Fatalf("payload + signature does not rejoin into the stored object:\n%q", signed.Payload)
	}

	unsigned, err := r.TagObject(w.unsignedSHA)
	if err != nil {
		t.Fatalf("TagObject = %v", err)
	}

	if unsigned.Payload != nil || unsigned.Signature != nil || unsigned.Target != w.root {
		t.Fatalf("unsigned = %+v, want no signature material and the root as target", unsigned)
	}
}

func TestTagObjectRefusals(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)
	r := openAt(t, w.repo.Dir)

	for _, tc := range []struct{ name, sha, says string }{
		{name: "an abbreviated id", sha: w.signedSHA[:12], says: "is not a full object id"},
		{name: "an object that is not a tag", sha: w.root, says: "gitrepo: tag object " + w.root},
		{name: "an absent object", sha: strings.Repeat("0", 40), says: "gitrepo: tag object " + strings.Repeat("0", 40)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := r.TagObject(tc.sha); err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("TagObject(%s) = %v, want it to say %q", tc.sha, err, tc.says)
			}
		})
	}
}

// TestResolveTagIsTheOneResolution: both kinds of tag resolve to their
// target through one function, and TagCommit asks the same one.
func TestResolveTagIsTheOneResolution(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)
	r := openAt(t, w.repo.Dir)

	refs, err := r.TagRefs()
	if err != nil {
		t.Fatalf("TagRefs = %v", err)
	}

	want := map[string]string{"v0.1.0": w.root, "v0.9.0": w.root, "v1.0.0": w.merge}

	for _, ref := range refs {
		target, obj, rerr := r.ResolveTag(ref)
		if rerr != nil || target != want[ref.Name] || (obj == nil) == ref.Annotated {
			t.Fatalf("ResolveTag(%s) = %s, %+v, %v", ref.Name, target, obj, rerr)
		}

		commit, cerr := r.TagCommit(ref.Name)
		if cerr != nil || commit != target {
			t.Fatalf("TagCommit(%s) = %s, %v, want %s", ref.Name, commit, cerr, target)
		}
	}

	if _, err := r.TagCommit("v9.9.9"); err == nil || !strings.Contains(err.Error(), "no tag v9.9.9") {
		t.Fatalf("TagCommit(absent) = %v, want the absence named", err)
	}

	broken := gitrepo.TagRef{Name: "v0.0.1", ObjectSHA: w.root, Annotated: true}
	if _, _, err := r.ResolveTag(broken); err == nil {
		t.Fatal("ResolveTag read a commit as a tag object")
	}
}

// TestChainNotesReadsTheLedgerWhole: every note with the revision it
// annotates, bytes exactly as stored — scaffolding included, since
// deciding what is a link is the consumer's.
func TestChainNotesReadsTheLedgerWhole(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)
	r := openAt(t, w.repo.Dir)

	got, err := r.ChainNotes()
	if err != nil {
		t.Fatalf("ChainNotes = %v", err)
	}

	byRev := map[string][]byte{}
	for _, n := range got {
		byRev[n.Rev] = n.Note
	}

	if len(got) != 2 || len(byRev) != 2 {
		t.Fatalf("ChainNotes = %d notes, want 2", len(got))
	}

	// The same bytes Note reads one at a time — one reading, two doors.
	for rev, note := range byRev {
		one, nerr := r.Note(rev)
		if nerr != nil || !bytes.Equal(one, note) {
			t.Fatalf("Note(%s) = %q, %v; ChainNotes said %q", rev, one, nerr, note)
		}
	}

	if !bytes.HasPrefix(byRev[w.tip], w.linkNote) || !bytes.HasPrefix(byRev[w.root], w.scaffoldNote) {
		t.Fatalf("ChainNotes = %q", byRev)
	}
}

func TestChainNotesWithoutALedgerIsEmpty(t *testing.T) {
	t.Parallel()

	r := gittest.New(t)
	r.Commit("feat: one")

	got, err := openAt(t, r.Dir).ChainNotes()
	if err != nil || got != nil {
		t.Fatalf("ChainNotes = %v, %v — an absent notes ref is an empty chain", got, err)
	}
}

func TestCommitMetaReadsTheObject(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)
	r := openAt(t, w.repo.Dir)

	root, err := r.CommitMeta(w.root)
	if err != nil {
		t.Fatalf("CommitMeta = %v", err)
	}

	// The first LINE, never the first paragraph: a body does not leak in.
	if len(root.Parents) != 0 || root.CommitEpoch != gittest.Epoch || root.Subject != "feat: the first commit" {
		t.Fatalf("CommitMeta(root) = %+v", root)
	}

	merge, err := r.CommitMeta(w.merge)
	if err != nil {
		t.Fatalf("CommitMeta = %v", err)
	}

	if len(merge.Parents) != 2 || merge.Parents[1] != w.side || merge.Subject != "merge the side" {
		t.Fatalf("CommitMeta(merge) = %+v, want both parents, first-parent first", merge)
	}

	if _, err := r.CommitMeta(strings.Repeat("0", 40)); err == nil {
		t.Fatal("CommitMeta invented an absent commit")
	}
}

// TestObjectsOnlyRepositoryHasNoLedger: a repository opened for its
// objects reads tags and commits, and refuses every ledger read by
// name rather than reading git's default notes ref.
func TestObjectsOnlyRepositoryHasNoLedger(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)

	r, err := gitrepo.OpenObjects(w.repo.Dir)
	if err != nil {
		t.Fatalf("OpenObjects = %v", err)
	}

	if got, terr := r.TagCommit("v1.0.0"); terr != nil || got != w.merge {
		t.Fatalf("TagCommit = %s, %v", got, terr)
	}

	for name, read := range map[string]func() error{
		"Note":       func() error { _, nerr := r.Note(w.tip); return nerr },
		"Noted":      func() error { _, nerr := r.Noted(); return nerr },
		"ChainNotes": func() error { _, nerr := r.ChainNotes(); return nerr },
	} {
		if rerr := read(); rerr == nil || !strings.Contains(rerr.Error(), "opened with no notes ref") {
			t.Errorf("%s = %v, want the missing ledger named", name, rerr)
		}
	}

	_, err = gitrepo.OpenObjects(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "is not a git repository") {
		t.Fatalf("OpenObjects(empty dir) = %v, want a refusal", err)
	}
}
