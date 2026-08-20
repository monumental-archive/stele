// The seam exists so a degraded read is TYPED: a 404, a 403, a
// malformed body and a dead socket are four different facts, and an
// engine that cannot tell them apart manufactures the impression of
// coverage out of an outage. So these tables walk the WHOLE read
// surface rather than one representative read — a refusal only some
// reads make is exactly the shape that ships a green walk over an
// unreadable forge.

package gh_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
)

// read is one named read on the client, reduced to whether it
// answered and how it failed, so one table can state each read's
// documented stance on an absence.
type read struct {
	name string
	call func(*gh.Client) (bool, error)
	// absentIsAnswer records the reads whose 404 is a fact about the
	// subject ("no such file", "no attestations") rather than a
	// missing population source.
	absentIsAnswer bool
	// decodes records the reads that parse the body; the two that do
	// not carry opaque bytes through by design.
	decodes bool
}

// everyRead is the whole Forge plus TagReader surface, once each.
//
//nolint:funlen // one row per read is the point: a short list is an incomplete walk
func everyRead() []read {
	return []read{
		{name: "ListRepos", decodes: true, call: func(c *gh.Client) (bool, error) {
			out, err := c.ListRepos("acme")

			return len(out) > 0, err
		}},
		{name: "ReleaseTags", decodes: true, call: func(c *gh.Client) (bool, error) {
			out, err := c.ReleaseTags("acme", "widget")

			return len(out) > 0, err
		}},
		{name: "ReleaseAssets", decodes: true, call: func(c *gh.Client) (bool, error) {
			out, err := c.ReleaseAssets("acme", "widget", "v1.0.0")

			return len(out) > 0, err
		}},
		{name: "Asset", call: func(c *gh.Client) (bool, error) {
			out, err := c.Asset("acme", "widget", "v1.0.0", "app.bin")

			return len(out) > 0, err
		}},
		{name: "TagCommit", decodes: true, call: func(c *gh.Client) (bool, error) {
			out, err := c.TagCommit("acme", "widget", "v1.0.0")

			return out != "", err
		}},
		{name: "FileAt", absentIsAnswer: true, call: func(c *gh.Client) (bool, error) {
			_, ok, err := c.FileAt("acme", "widget", "ci.yml", "v1.0.0")

			return ok, err
		}},
		{name: "Attestations", absentIsAnswer: true, decodes: true, call: func(c *gh.Client) (bool, error) {
			out, err := c.Attestations("acme", "widget", testHex)

			return len(out) > 0, err
		}},
		{name: "PackageVersionDigest", decodes: true, call: func(c *gh.Client) (bool, error) {
			out, err := c.PackageVersionDigest("acme", "widget", "latest")

			return out != "", err
		}},
		{name: "Workflows", absentIsAnswer: true, decodes: true, call: func(c *gh.Client) (bool, error) {
			out, err := c.Workflows("acme", "widget")

			return len(out) > 0, err
		}},
		{name: "FailedRuns", absentIsAnswer: true, decodes: true, call: func(c *gh.Client) (bool, error) {
			out, err := c.FailedRuns("acme", "widget", "v1.0.0")

			return len(out) > 0, err
		}},
		{name: "TagRefs", decodes: true, call: func(c *gh.Client) (bool, error) {
			out, err := c.TagRefs("acme", "widget")

			return len(out) > 0, err
		}},
		{name: "TagObject", decodes: true, call: func(c *gh.Client) (bool, error) {
			out, err := c.TagObject("acme", "widget", tagObjID)

			return out != nil, err
		}},
		{name: "ChainNotes", absentIsAnswer: true, decodes: true, call: func(c *gh.Client) (bool, error) {
			out, err := c.ChainNotes("acme", "widget", "refs/notes/commits")

			return len(out) > 0, err
		}},
		{name: "CommitMeta", decodes: true, call: func(c *gh.Client) (bool, error) {
			out, err := c.CommitMeta("acme", "widget", noteRev)

			return out != nil, err
		}},
		{name: "IsAncestor", absentIsAnswer: true, decodes: true, call: func(c *gh.Client) (bool, error) {
			out, err := c.IsAncestor("acme", "widget", tagObjID, noteRev)

			return out, err
		}},
	}
}

// everyPath answers every request with one scripted status and body.
// When the script is a 200, pages after the first answer with the
// API's empty array so pagination converges — the fault under test is
// the first page's, never the page bound.
func everyPath(t *testing.T, status int, body string) *gh.Client {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if page := r.URL.Query().Get("page"); status == http.StatusOK && page != "" && page != "1" {
			writeBody(w, []byte(`[]`))

			return
		}

		w.WriteHeader(status)
		writeBody(w, []byte(body))
	}))
	t.Cleanup(srv.Close)

	c := gh.New("")
	c.Base = srv.URL
	c.Download = srv.URL
	c.Sleep = func(time.Duration) {}

	return c
}

// TestEveryReadRefusesAnUnreadableForge: a credential that cannot
// read must refuse from EVERY read. The reads whose absence is an
// answer are the dangerous ones here — a 403 swallowed as "nothing
// recorded" is a clean verdict over evidence nobody looked at.
func TestEveryReadRefusesAnUnreadableForge(t *testing.T) {
	t.Parallel()

	c := everyPath(t, http.StatusForbidden, "")

	for _, r := range everyRead() {
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()

			answered, err := r.call(c)
			if err == nil {
				t.Fatalf("%s answered %v over a forbidden forge — unreadable is not empty", r.name, answered)
			}
		})
	}
}

// TestAbsenceIsAnswerOrRefusal pins the other half by name: a 404 is
// a FACT for the reads that document it (no such file, no
// attestations, no notes ref) and a missing population source for the
// rest. Both halves in one table, because the whole point is that the
// two are told apart.
func TestAbsenceIsAnswerOrRefusal(t *testing.T) {
	t.Parallel()

	c := everyPath(t, http.StatusNotFound, "")

	for _, r := range everyRead() {
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()

			answered, err := r.call(c)

			if !r.absentIsAnswer {
				if err == nil {
					t.Fatalf("%s answered %v over a missing population source", r.name, answered)
				}

				return
			}

			if err != nil {
				t.Fatalf("%s = %v, want the recorded absence as an answer", r.name, err)
			}

			if answered {
				t.Fatalf("%s answered from a 404 — an absence carries nothing", r.name)
			}
		})
	}
}

// TestDecodingReadsRefuseGarbage: a body that parses as nothing is a
// fault, never an empty answer. The two reads that do not decode
// carry the bytes through — an asset is opaque, and a file read falls
// back to raw bytes when the JSON envelope is absent, which is the
// documented behaviour behind a proxy that strips the accept header.
func TestDecodingReadsRefuseGarbage(t *testing.T) {
	t.Parallel()

	c := everyPath(t, http.StatusOK, "not json")

	for _, r := range everyRead() {
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()

			answered, err := r.call(c)

			if r.decodes {
				if err == nil {
					t.Fatalf("%s answered %v over an unparsable body", r.name, answered)
				}

				return
			}

			if err != nil || !answered {
				t.Fatalf("%s = %v, %v — opaque bytes pass through", r.name, answered, err)
			}
		})
	}
}

// TestStatusClasses pins the three ways one status is read: 401 is
// the same unreadable sentinel as 403, a 4xx that is neither is a
// plain refusal naming only the status, and the server's prose never
// travels with it.
func TestStatusClasses(t *testing.T) {
	t.Parallel()

	t.Run("401 is the unreadable sentinel", func(t *testing.T) {
		t.Parallel()

		_, err := everyPath(t, http.StatusUnauthorized, "").ListRepos("acme")
		if !errors.Is(err, gh.ErrForbidden) {
			t.Fatalf("401 = %v, want ErrForbidden", err)
		}
	})

	t.Run("an unclassified 4xx names the status alone", func(t *testing.T) {
		t.Parallel()

		_, err := everyPath(t, http.StatusBadRequest, "server-controlled prose").ListRepos("acme")
		if err == nil || !strings.Contains(err.Error(), "HTTP 400") {
			t.Fatalf("400 = %v, want the status", err)
		}

		if strings.Contains(err.Error(), "prose") {
			t.Fatal("the server-controlled body leaked into the error")
		}
	})
}

// TestTransportFaults covers the three ways a read fails before any
// status exists — the URL never becomes a request, the connection
// never happens, the body never finishes — on both hosts, because the
// API and the download host are separate addresses with separate
// failure modes.
func TestTransportFaults(t *testing.T) {
	t.Parallel()

	// DEL is a control character net/url refuses, so the request never
	// exists to be sent.
	const unbuildable = "http://example\x7f.invalid"

	t.Run("an unbuildable API URL", func(t *testing.T) {
		t.Parallel()

		c := gh.New("")
		c.Base = unbuildable
		c.Sleep = func(time.Duration) {}

		if _, err := c.ListRepos("acme"); err == nil || !strings.Contains(err.Error(), "build request") {
			t.Fatalf("Repos = %v, want the build-request refusal", err)
		}
	})

	t.Run("an unbuildable download URL", func(t *testing.T) {
		t.Parallel()

		c := gh.New("")
		c.Download = unbuildable
		c.Sleep = func(time.Duration) {}

		if _, err := c.Asset("acme", "widget", "v1.0.0", "app.bin"); err == nil ||
			!strings.Contains(err.Error(), "build request") {
			t.Fatalf("Asset = %v, want the build-request refusal", err)
		}
	})

	t.Run("a dead host", func(t *testing.T) {
		t.Parallel()

		c := everyPath(t, http.StatusOK, "")
		dead := deadServer(t)
		c.Base, c.Download = dead, dead

		if _, err := c.ListRepos("acme"); err == nil {
			t.Error("Repos over a dead API host did not refuse")
		}

		if _, err := c.Asset("acme", "widget", "v1.0.0", "app.bin"); err == nil {
			t.Error("Asset over a dead download host did not refuse")
		}
	})

	t.Run("a truncated body", func(t *testing.T) {
		t.Parallel()

		c := truncatingServer(t)

		if _, err := c.ListRepos("acme"); err == nil || !strings.Contains(err.Error(), "read") {
			t.Errorf("Repos = %v, want the read refusal", err)
		}

		if _, err := c.Asset("acme", "widget", "v1.0.0", "app.bin"); err == nil ||
			!strings.Contains(err.Error(), "read") {
			t.Errorf("Asset = %v, want the read refusal", err)
		}
	})
}

// deadServer returns the address of a server that has stopped
// listening, so a dial fails rather than a status arriving.
func deadServer(t *testing.T) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close()

	return srv.URL
}

// truncatingServer promises more bytes than it delivers on every
// path, so the read fails mid-body.
func truncatingServer(t *testing.T) *gh.Client {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("the test server's ResponseWriter cannot be hijacked")

			return
		}

		conn, _, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)

			return
		}
		defer conn.Close() //nolint:errcheck // the test server's socket

		//nolint:errcheck,gosec // test server write
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n[{\"name\":"))
	}))
	t.Cleanup(srv.Close)

	c := gh.New("")
	c.Base = srv.URL
	c.Download = srv.URL
	c.Sleep = func(time.Duration) {}

	return c
}

// TestPaginationBound pins the walk's other end: a listing that never
// serves a short page is a broken host, and the read must end with a
// named refusal rather than paging forever. Every page here is FULL
// — under the short-page rule (#154) that is what a host must do to
// reach the bound at all, and a host repeating a SHORT page is a
// healthy answer this walk now terminates on.
func TestPaginationBound(t *testing.T) {
	t.Parallel()

	page := []byte("[" + strings.Repeat(`{"name": "widget", "archived": false, "fork": false},`, 99) +
		`{"name": "gadget", "archived": false, "fork": false}]`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, page)
	}))
	t.Cleanup(srv.Close)

	c := gh.New("")
	c.Base = srv.URL
	c.Sleep = func(time.Duration) {}

	if _, err := c.ListRepos("acme"); err == nil || !strings.Contains(err.Error(), "did not converge") {
		t.Fatalf("Repos = %v, want the pagination bound", err)
	}
}

// TestAssetRetryExhausted pins the download ladder's end: a host that
// only ever answers 429 ends the read with a named refusal after the
// attempt budget, not with empty bytes.
func TestAssetRetryExhausted(t *testing.T) {
	t.Parallel()

	c, seen := flakyServer(t, http.StatusTooManyRequests, 99)

	if _, err := c.Asset("acme", "widget", "v1.0.0", "app.bin"); err == nil ||
		!strings.Contains(err.Error(), "after 4 attempts") {
		t.Fatalf("Asset = %v, want the bounded refusal", err)
	}

	if *seen != 4 {
		t.Fatalf("attempts = %d, want the 4-attempt bound", *seen)
	}
}

// crookedServer scripts one half-answered read per path: the map IS
// the script, and anything absent from it answers 404 — which is
// itself one of the faults under test. Each entry breaks exactly one
// link of a two-step read, which is where a seam that reads "the
// first hop worked, so the answer is good" goes wrong.
func crookedServer(t *testing.T) *gh.Client {
	t.Helper()

	bodies := map[string]string{
		// An annotated tag whose tag OBJECT is gone, and one whose tag
		// object will not parse: the ref resolved, the commit did not.
		"/repos/acme/widget/git/ref/tags/orphan":  `{"object": {"type": "tag", "sha": "absent"}}`,
		"/repos/acme/widget/git/ref/tags/mangled": `{"object": {"type": "tag", "sha": "mangled"}}`,
		"/repos/acme/widget/git/tags/mangled":     `not json`,

		// A contents envelope that declares base64 and is not.
		"/repos/acme/widget/contents/badb64.yml": `{"content": "!! not base64 !!", "encoding": "base64"}`,

		// A workflow directory listing whose one file cannot be read.
		"/repos/acme/widget/contents/.github/workflows": `[{"name": "locked.yml", "type": "file"}]`,

		// The notes chain is a four-hop read — ref, commit, tree, blob
		// — and every hop can answer while the next one does not. One
		// notes ref per broken hop, named for the hop it breaks.
		"/repos/acme/notes/git/ref/notes/nocommit": `{"object": {"sha": "absentcommit"}}`,

		"/repos/acme/notes/git/ref/notes/treeless": `{"object": {"sha": "treeless"}}`,
		"/repos/acme/notes/git/commits/treeless":   `{"parents": []}`,

		"/repos/acme/notes/git/ref/notes/notree": `{"object": {"sha": "notree"}}`,
		"/repos/acme/notes/git/commits/notree":   `{"tree": {"sha": "absenttree"}}`,

		"/repos/acme/notes/git/ref/notes/junktree": `{"object": {"sha": "junktree"}}`,
		"/repos/acme/notes/git/commits/junktree":   `{"tree": {"sha": "junktree"}}`,
		"/repos/acme/notes/git/trees/junktree":     `not json`,

		"/repos/acme/notes/git/ref/notes/skipped": `{"object": {"sha": "skipped"}}`,
		"/repos/acme/notes/git/commits/skipped":   `{"tree": {"sha": "skiptree"}}`,
		"/repos/acme/notes/git/trees/skiptree": `{"truncated": false, "tree": [
		  {"path": "sub", "type": "tree", "sha": "s"}, {"type": "blob", "sha": "z"}]}`,

		"/repos/acme/notes/git/ref/notes/noblob": `{"object": {"sha": "noblob"}}`,
		"/repos/acme/notes/git/commits/noblob":   `{"tree": {"sha": "noblobtree"}}`,
		"/repos/acme/notes/git/trees/noblobtree": `{"truncated": false, "tree": [
		  {"path": "22/` + noteRev[2:] + `", "type": "blob", "sha": "absentblob"}]}`,

		"/repos/acme/notes/git/ref/notes/rawblob": `{"object": {"sha": "rawblob"}}`,
		"/repos/acme/notes/git/commits/rawblob":   `{"tree": {"sha": "rawblobtree"}}`,
		"/repos/acme/notes/git/trees/rawblobtree": `{"truncated": false, "tree": [
		  {"path": "22/` + noteRev[2:] + `", "type": "blob", "sha": "rawblob"}]}`,
		"/repos/acme/notes/git/blobs/rawblob": `{"encoding": "utf-8", "content": "x"}`,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/acme/widget/contents/.github/workflows/locked.yml" {
			w.WriteHeader(http.StatusForbidden)

			return
		}

		body, ok := bodies[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		writeBody(w, []byte(body))
	}))
	t.Cleanup(srv.Close)

	c := gh.New("")
	c.Base = srv.URL
	c.Sleep = func(time.Duration) {}

	return c
}

// TestHalfAnsweredReads: every read here resolves in two hops, and a
// first hop that succeeded says nothing about the second. Each row
// names the hop that broke.
func TestHalfAnsweredReads(t *testing.T) {
	t.Parallel()

	c := crookedServer(t)

	t.Run("an annotated tag whose object is gone", func(t *testing.T) {
		t.Parallel()

		if _, err := c.TagCommit("acme", "widget", "orphan"); err == nil ||
			!strings.Contains(err.Error(), "tag object absent") {
			t.Fatalf("TagCommit = %v, want the dereference refusal", err)
		}
	})

	t.Run("an annotated tag whose object will not parse", func(t *testing.T) {
		t.Parallel()

		if _, err := c.TagCommit("acme", "widget", "mangled"); err == nil ||
			!strings.Contains(err.Error(), "tag object of") {
			t.Fatalf("TagCommit = %v, want the decode refusal", err)
		}
	})

	t.Run("an envelope that declares base64 and is not", func(t *testing.T) {
		t.Parallel()

		if _, _, err := c.FileAt("acme", "widget", "badb64.yml", "v1"); err == nil ||
			!strings.Contains(err.Error(), "base64") {
			t.Fatalf("FileAt = %v, want the base64 refusal", err)
		}
	})

	t.Run("a listed workflow the credential cannot read", func(t *testing.T) {
		t.Parallel()

		out, err := c.Workflows("acme", "widget")
		if !errors.Is(err, gh.ErrForbidden) {
			t.Fatalf("Workflows = %v, %v — an unreadable member is not a shorter list", out, err)
		}
	})
}

// TestHalfAnsweredNotesChain walks the notes read hop by hop: ref,
// commit, tree, blob. A chain read that stopped early must refuse —
// a short chain and a broken chain look identical to every caller
// downstream, and only one of them is a fact.
func TestHalfAnsweredNotesChain(t *testing.T) {
	t.Parallel()

	c := crookedServer(t)

	refusals := []struct {
		ref  string
		want string
	}{
		{"refs/notes/nocommit", "notes commit"},
		{"refs/notes/treeless", "notes commit"},
		{"refs/notes/notree", "notes tree"},
		{"refs/notes/junktree", "notes tree"},
		{"refs/notes/noblob", "blob absentblob"},
		{"refs/notes/rawblob", "not base64 content"},
	}

	for _, tc := range refusals {
		t.Run(tc.ref, func(t *testing.T) {
			t.Parallel()

			out, err := c.ChainNotes("acme", "notes", tc.ref)
			if err == nil {
				t.Fatalf("ChainNotes(%s) = %+v, want a refusal naming %q", tc.ref, out, tc.want)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ChainNotes(%s) = %v, want it to name %q", tc.ref, err, tc.want)
			}
		})
	}

	// The skip rules are not refusals: a tree holds git's own
	// scaffolding beside the notes, and an entry that is not a blob on
	// a revision-shaped path is not a note.
	t.Run("non-note tree entries are skipped, not refused", func(t *testing.T) {
		t.Parallel()

		notes, err := c.ChainNotes("acme", "notes", "refs/notes/skipped")
		if err != nil || len(notes) != 0 {
			t.Fatalf("ChainNotes = %+v, %v — a tree of scaffolding is an empty chain", notes, err)
		}
	})
}
