package gh_test

import (
	"errors"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// historyReader is a scripted forge history: the notes ref's blobs,
// each commit's parents and subject, and the refs it can resolve.
type historyReader struct {
	refs    map[string]string
	notes   []gh.ChainNote
	commits map[string]*gh.CommitMeta
	err     error
	reads   int
}

func (h *historyReader) TagRefs(_, _ string) ([]gh.TagRef, error) { return nil, nil }

func (h *historyReader) TagObject(_, _, _ string) (*gh.TagObject, error) {
	return nil, errNoTagObject
}

var errNoTagObject = errors.New("this fixture serves no tag objects")

func (h *historyReader) ChainNotes(_, _, _ string) ([]gh.ChainNote, error) {
	h.reads++

	return h.notes, h.err
}

func (h *historyReader) CommitMeta(_, _, rev string) (*gh.CommitMeta, error) {
	h.reads++

	got, ok := h.commits[rev]
	if !ok {
		return nil, errors.New("no such commit")
	}

	return got, nil
}

func (h *historyReader) IsAncestor(_, _, _, _ string) (bool, error) { return false, nil }

func (h *historyReader) Ref(_, _, ref string) (string, error) {
	got, ok := h.refs[ref]
	if !ok {
		return "", errors.New("no such ref")
	}

	return got, nil
}

const (
	revOne = "1111111111111111111111111111111111111111"
	revTwo = "2222222222222222222222222222222222222222"
)

func world() *historyReader {
	return &historyReader{
		refs:  map[string]string{"refs/heads/main": revTwo},
		notes: []gh.ChainNote{{Rev: revTwo, Note: jsonx.Raw(`{"version":3}`)}},
		commits: map[string]*gh.CommitMeta{
			revTwo: {Parents: []string{revOne}, CommitEpoch: 1_800_000_000, Subject: "feat: two"},
			revOne: {CommitEpoch: 1_700_000_000, Subject: "feat: one"},
		},
	}
}

func history(r gh.TagReader) *gh.History {
	return &gh.History{Reader: r, Owner: "acme", Repo: "widget", NotesRef: "refs/notes/commits"}
}

// TestHistoryReadsTheForge: the walk's whole surface, served without a
// clone. Requiring a local checkout made the tool something you set up
// before it would answer.
func TestHistoryReadsTheForge(t *testing.T) {
	t.Parallel()

	h := history(world())

	tip, err := h.Tip("refs/heads/main")
	if err != nil || tip != revTwo {
		t.Fatalf("Tip = %q, %v", tip, err)
	}

	parent, err := h.Parent(revTwo)
	if err != nil || parent != revOne {
		t.Errorf("Parent = %q, %v, want the first parent", parent, err)
	}

	// A root commit has no parent, and the empty string is the walk's
	// sentinel for it — never an error.
	root, err := h.Parent(revOne)
	if err != nil || root != "" {
		t.Errorf("Parent of a root = %q, %v, want the empty sentinel", root, err)
	}

	note, err := h.Note(revTwo)
	if err != nil || string(note) != `{"version":3}` {
		t.Errorf("Note = %q, %v", note, err)
	}

	// A revision with no note is nil, not an error: most revisions in a
	// repository carry none.
	unnoted, uerr := h.Note(revOne)
	if uerr != nil || unnoted != nil {
		t.Errorf("Note of an unnoted revision = %q, %v", unnoted, uerr)
	}

	noted, err := h.Noted()
	if err != nil || len(noted) != 1 || noted[0] != revTwo {
		t.Errorf("Noted = %v, %v", noted, err)
	}
}

// TestHistoryFetchesTheNotesOnce: a walk asks about many revisions, and
// a request per revision would turn one read into hundreds.
func TestHistoryFetchesTheNotesOnce(t *testing.T) {
	t.Parallel()

	r := world()
	h := history(r)

	for range 5 {
		if _, err := h.Note(revTwo); err != nil {
			t.Fatalf("Note = %v", err)
		}
	}

	if r.reads != 1 {
		t.Errorf("notes read %d times, want once", r.reads)
	}
}

// TestHistoryRevisionsWindow: the continuity window an evaluator
// judges, newest first, stopping at the start it was given.
func TestHistoryRevisionsWindow(t *testing.T) {
	t.Parallel()

	h := history(world())

	all, err := h.Revisions("refs/heads/main", time.Time{})
	if err != nil || len(all) != 2 {
		t.Fatalf("Revisions = %d, %v, want the whole branch", len(all), err)
	}

	if all[0].ID != revTwo || all[0].Subject != "feat: two" || all[0].Parents != 1 {
		t.Errorf("newest = %+v, want the tip with its parent count", all[0])
	}

	// A start after the older revision excludes it.
	since := time.Unix(1_750_000_000, 0)

	window, err := h.Revisions("refs/heads/main", since)
	if err != nil || len(window) != 1 || window[0].ID != revTwo {
		t.Errorf("Revisions since = %v, %v, want only the tip", window, err)
	}
}

// TestHistoryRefusals: every read can fail, and each failure is its
// own answer rather than an empty result that reads as clean.
func TestHistoryRefusals(t *testing.T) {
	t.Parallel()

	h := history(world())

	if _, err := h.Tip("refs/heads/missing"); err == nil {
		t.Error("Tip resolved a ref that does not exist")
	}

	if _, err := h.Parent("3333333333333333333333333333333333333333"); err == nil {
		t.Error("Parent read a commit that does not exist")
	}

	if _, err := h.Revisions("refs/heads/missing", time.Time{}); err == nil {
		t.Error("Revisions walked a ref that does not exist")
	}

	broken := history(&historyReader{err: errors.New("the forge is down"), refs: map[string]string{}})
	if _, err := broken.Note(revTwo); err == nil {
		t.Error("Note reported nothing where the notes ref could not be read")
	}

	if _, err := broken.Noted(); err == nil {
		t.Error("Noted reported an empty ledger where it could not be read")
	}
}

// TestHistoryWithoutARefResolver: a reader that cannot resolve refs
// says so by name rather than panicking mid-walk.
func TestHistoryWithoutARefResolver(t *testing.T) {
	t.Parallel()

	h := &gh.History{Reader: &noRefReader{}, Owner: "acme", Repo: "widget", NotesRef: "refs/notes/commits"}

	if _, err := h.Tip("refs/heads/main"); err == nil {
		t.Error("Tip did not refuse a reader with no ref surface")
	}
}

type noRefReader struct{ historyReader }

func (*noRefReader) ChainNotes(_, _, _ string) ([]gh.ChainNote, error) { return nil, nil }
