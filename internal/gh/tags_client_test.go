// The tag-audit client reads (stele#83): each REST endpoint scripted
// by httptest, one fact broken per refusal row, and the
// capture-then-replay roundtrip over the whole TagReader surface.

package gh_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
)

const (
	noteRev  = "2222222222222222222222222222222222222222"
	tagObjID = "3333333333333333333333333333333333333333"
)

// tagServer scripts the tag-audit REST surface.
func tagServer(t *testing.T) *gh.Client {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/repos/acme/widget/git/matching-refs/tags/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			writeBody(w, []byte(`[
			  {"ref": "refs/tags/v1.0.0", "object": {"type": "tag", "sha": "`+tagObjID+`"}},
			  {"ref": "refs/tags/light", "object": {"type": "commit", "sha": "`+noteRev+`"}}]`))

			return
		}

		writeBody(w, []byte(`[]`))
	})

	mux.HandleFunc("/repos/acme/widget/git/tags/"+tagObjID, func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`{
		  "tagger": {"name": "release-mint[bot]"},
		  "object": {"sha": "`+noteRev+`"},
		  "verification": {"payload": "object x\n", "signature": "-----BEGIN SIGNED MESSAGE-----\n"}
		}`))
	})

	mux.HandleFunc("/repos/acme/widget/git/ref/notes/commits", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`{"ref": "refs/notes/commits", "object": {"type": "commit", "sha": "`+noteRev+`"}}`))
	})

	mux.HandleFunc("/repos/acme/widget/git/commits/"+noteRev, func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`{
		  "tree": {"sha": "treesha"},
		  "parents": [{"sha": "`+tagObjID+`"}],
		  "committer": {"date": "2026-08-01T00:00:00Z"}
		}`))
	})

	mux.HandleFunc("/repos/acme/widget/git/trees/treesha", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`{"truncated": false, "tree": [
		  {"path": "22/22222222222222222222222222222222222222", "type": "blob", "sha": "blobsha"},
		  {"path": "README", "type": "blob", "sha": "junk"}]}`))
	})

	mux.HandleFunc("/repos/acme/widget/git/blobs/blobsha", func(w http.ResponseWriter, _ *http.Request) {
		content := base64.StdEncoding.EncodeToString([]byte(`{"version": 2}`))
		writeBody(w, []byte(`{"encoding": "base64", "content": "`+content+`"}`))
	})

	mux.HandleFunc("/repos/acme/widget/compare/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "..."+noteRev) {
			writeBody(w, []byte(`{"status": "ahead"}`))

			return
		}

		writeBody(w, []byte(`{"status": "diverged"}`))
	})

	// bare repo: no notes ref, empty tag listing
	mux.HandleFunc("/repos/acme/bare/git/matching-refs/tags/", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`[]`))
	})
	mux.HandleFunc("/repos/acme/bare/git/ref/notes/commits", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.New("")
	c.Base = srv.URL
	c.Sleep = func(_ time.Duration) {}

	return c
}

func TestTagReaderClient(t *testing.T) {
	t.Parallel()

	c := tagServer(t)

	refs, err := c.TagRefs("acme", "widget")
	if err != nil {
		t.Fatalf("TagRefs: %v", err)
	}

	want := []gh.TagRef{
		{Name: "v1.0.0", ObjectSHA: tagObjID, Annotated: true},
		{Name: "light", ObjectSHA: noteRev, Annotated: false},
	}

	if len(refs) != 2 || refs[0] != want[0] || refs[1] != want[1] {
		t.Fatalf("refs = %+v, want %+v", refs, want)
	}

	obj, err := c.TagObject("acme", "widget", tagObjID)
	if err != nil {
		t.Fatalf("TagObject: %v", err)
	}

	if obj.Tagger != "release-mint[bot]" || obj.Target != noteRev ||
		string(obj.Payload) != "object x\n" || len(obj.Signature) == 0 {
		t.Fatalf("obj = %+v", obj)
	}

	notes, err := c.ChainNotes("acme", "widget", "refs/notes/commits")
	if err != nil {
		t.Fatalf("ChainNotes: %v", err)
	}

	// The README scaffolding entry is skipped; the fanout path
	// collapses to the revision.
	if len(notes) != 1 || notes[0].Rev != noteRev || string(notes[0].Note) != `{"version": 2}` {
		t.Fatalf("notes = %+v", notes)
	}

	meta, err := c.CommitMeta("acme", "widget", noteRev)
	if err != nil {
		t.Fatalf("CommitMeta: %v", err)
	}

	if len(meta.Parents) != 1 || meta.Parents[0] != tagObjID || meta.CommitEpoch == 0 {
		t.Fatalf("meta = %+v", meta)
	}

	ahead, err := c.IsAncestor("acme", "widget", tagObjID, noteRev)
	if err != nil || !ahead {
		t.Fatalf("IsAncestor(ahead) = %v, %v", ahead, err)
	}

	diverged, err := c.IsAncestor("acme", "widget", noteRev, tagObjID)
	if err != nil || diverged {
		t.Fatalf("IsAncestor(diverged) = %v, %v", diverged, err)
	}
}

func TestTagReaderAbsences(t *testing.T) {
	t.Parallel()

	c := tagServer(t)

	notes, err := c.ChainNotes("acme", "bare", "refs/notes/commits")
	if err != nil || notes != nil {
		t.Fatalf("ChainNotes(bare) = %+v, %v — an absent notes ref is an empty chain", notes, err)
	}

	refs, err := c.TagRefs("acme", "bare")
	if err != nil || len(refs) != 0 {
		t.Fatalf("TagRefs(bare) = %+v, %v", refs, err)
	}
}

func TestTagReaderCaptureThenReplay(t *testing.T) {
	t.Parallel()

	live := tagServer(t)
	dir := t.TempDir()
	rec := gh.Capture{Live: live, Dir: dir}

	if _, err := rec.TagRefs("acme", "widget"); err != nil {
		t.Fatal(err)
	}

	if _, err := rec.TagObject("acme", "widget", tagObjID); err != nil {
		t.Fatal(err)
	}

	if _, err := rec.ChainNotes("acme", "widget", "refs/notes/commits"); err != nil {
		t.Fatal(err)
	}

	if notes, err := rec.ChainNotes("acme", "bare", "refs/notes/commits"); err != nil || notes != nil {
		t.Fatalf("capture of an empty chain = %+v, %v", notes, err)
	}

	if _, err := rec.CommitMeta("acme", "widget", noteRev); err != nil {
		t.Fatal(err)
	}

	if _, err := rec.IsAncestor("acme", "widget", tagObjID, noteRev); err != nil {
		t.Fatal(err)
	}

	snap := gh.Snapshot{Dir: dir}

	refs, err := snap.TagRefs("acme", "widget")
	if err != nil || len(refs) != 2 {
		t.Fatalf("replay TagRefs = %+v, %v", refs, err)
	}

	obj, err := snap.TagObject("acme", "widget", tagObjID)
	if err != nil || obj.Target != noteRev {
		t.Fatalf("replay TagObject = %+v, %v", obj, err)
	}

	notes, err := snap.ChainNotes("acme", "widget", "refs/notes/commits")
	if err != nil || len(notes) != 1 {
		t.Fatalf("replay ChainNotes = %+v, %v", notes, err)
	}

	if empty, rerr := snap.ChainNotes("acme", "bare", "refs/notes/commits"); rerr != nil || empty != nil {
		t.Fatalf("replay of an empty chain = %+v, %v", empty, rerr)
	}

	meta, err := snap.CommitMeta("acme", "widget", noteRev)
	if err != nil || meta.Parents[0] != tagObjID {
		t.Fatalf("replay CommitMeta = %+v, %v", meta, err)
	}

	ahead, err := snap.IsAncestor("acme", "widget", tagObjID, noteRev)
	if err != nil || !ahead {
		t.Fatalf("replay IsAncestor = %v, %v", ahead, err)
	}
}

// hostileTagServer scripts one malformed answer per endpoint so each
// refusal branch is exercised by name.
func hostileTagServer(t *testing.T) *gh.Client {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/repos/acme/broken/git/matching-refs/tags/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			writeBody(w, []byte(`[{"ref": "refs/tags/v1.0.0", "object": null}]`))

			return
		}

		writeBody(w, []byte(`[]`))
	})

	mux.HandleFunc("/repos/acme/broken/git/tags/gone", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	mux.HandleFunc("/repos/acme/broken/git/tags/headless", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`{"object": {"sha": "x"}}`))
	})

	mux.HandleFunc("/repos/acme/broken/git/ref/notes/commits", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`{"ref": "refs/notes/commits", "object": {"type": "commit", "sha": "notesha"}}`))
	})

	mux.HandleFunc("/repos/acme/broken/git/commits/notesha", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`{"tree": {"sha": "trunctree"}, "parents": [], "committer": {"date": "not-a-date"}}`))
	})

	mux.HandleFunc("/repos/acme/broken/git/trees/trunctree", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`{"truncated": true, "tree": []}`))
	})

	mux.HandleFunc("/repos/acme/broken/compare/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.New("")
	c.Base = srv.URL
	c.Sleep = func(_ time.Duration) {}

	return c
}

func TestTagReaderRefusals(t *testing.T) {
	t.Parallel()

	c := hostileTagServer(t)

	if _, err := c.TagRefs("acme", "broken"); err == nil ||
		!strings.Contains(err.Error(), "missing ref, type or sha") {
		t.Fatalf("TagRefs = %v, want the malformed-entry refusal", err)
	}

	if _, err := c.TagObject("acme", "broken", "gone"); err == nil ||
		!strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("TagObject(gone) = %v", err)
	}

	if _, err := c.TagObject("acme", "broken", "headless"); err == nil ||
		!strings.Contains(err.Error(), "missing tagger or target") {
		t.Fatalf("TagObject(headless) = %v", err)
	}

	if _, err := c.ChainNotes("acme", "broken", "refs/notes/commits"); err == nil ||
		!strings.Contains(err.Error(), "truncated") {
		t.Fatalf("ChainNotes = %v, want the truncation refusal", err)
	}

	if _, err := c.CommitMeta("acme", "broken", "notesha"); err == nil ||
		!strings.Contains(err.Error(), "committer date") {
		t.Fatalf("CommitMeta = %v, want the date refusal", err)
	}

	// Unrelated histories compare as not-found: an answer, not an
	// error — the tag simply does not descend from genesis.
	unrelated, err := c.IsAncestor("acme", "broken", "aaa", "bbb")
	if err != nil || unrelated {
		t.Fatalf("IsAncestor(unrelated) = %v, %v", unrelated, err)
	}
}
