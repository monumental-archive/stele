package gitfetch

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	//nolint:gosec // G504 is httpoxy, fixed in Go 1.6.3; the toolchain is pinned far past it, and this serves a test's own git
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/gitrepo"
	"github.com/monumental-archive/stele/internal/gittest"
)

const notesRef = "refs/notes/commits"

// world is a source repository carrying every shape a walk reads, and
// a source file the fetch must never bring down.
type world struct {
	src                      *gittest.Repo
	root, source, merge, tip string
	signedSHA, unsignedSHA   string
	link                     []byte
}

func newWorld(t *testing.T) world {
	t.Helper()

	r := gittest.New(t)
	w := world{src: r}

	w.root = r.Commit("feat: the root")
	w.source = r.File("src/main.go", "package main // source the fetch must never bring down\n", "feat: some source")
	r.Git("checkout", "-q", "-b", "side")
	r.Commit("fix: on the side")
	r.Git("checkout", "-q", "main")
	r.Git("merge", "-q", "--no-ff", "-m", "merge the side", "side")
	w.merge = r.Git("rev-parse", "HEAD")
	w.tip = r.Commit("docs: the tip")

	_, w.signedSHA = r.Annotated("v1.0.0", w.merge, "tag-mint[bot]", true)
	_, w.unsignedSHA = r.Annotated("v0.9.0", w.root, "someone", false)
	r.Lightweight("v0.1.0", w.root)

	w.link = []byte(`{"version": 3, "provenance": {"bundle": {}}}`)
	r.Note(notesRef, w.tip, w.link)
	r.Note(notesRef, w.root, []byte("scaffolding\n"))

	return w
}

var everything = Want{Branches: []string{"refs/heads/main"}, NotesRef: notesRef, Tags: true}

func fetch(t *testing.T, f *Fetcher, remote, token string, want Want) *Fetched {
	t.Helper()

	got, err := f.Fetch(remote, token, want)
	if err != nil {
		t.Fatalf("Fetch = %v", err)
	}

	t.Cleanup(func() { _ = got.Close() }) //nolint:errcheck // the test's own scratch

	return got
}

// TestFetchedHistoryAnswersAsTheSourceDoes is the History contract run
// over the fetcher (stele#384): every read a walk makes — the branch
// tip and its parents, the ledger, the tags and what they resolve to,
// commit facts, ancestry, the revision window — answers from the
// fetched repository exactly as from the repository it came from.
func TestFetchedHistoryAnswersAsTheSourceDoes(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	got := fetch(t, &Fetcher{}, w.src.URL(), "", everything).Repo

	want, err := gitrepo.Open(w.src.Dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	same := func(name string, read func(r *gitrepo.Repo) (any, error)) {
		t.Helper()

		a, aerr := read(want)
		b, berr := read(got)

		if aerr != nil || berr != nil {
			t.Fatalf("%s: source %v, fetched %v", name, aerr, berr)
		}

		if !equal(a, b) {
			t.Fatalf("%s: source %+v, fetched %+v", name, a, b)
		}
	}

	same("Tip", func(r *gitrepo.Repo) (any, error) { return r.Tip("refs/heads/main") })
	same("Noted", func(r *gitrepo.Repo) (any, error) { return r.Noted() })
	same("ChainNotes", func(r *gitrepo.Repo) (any, error) { return r.ChainNotes() })
	same("TagRefs", func(r *gitrepo.Repo) (any, error) { return r.TagRefs() })
	same("Revisions", func(r *gitrepo.Repo) (any, error) { return r.Revisions("refs/heads/main", time.Time{}) })

	for _, rev := range []string{w.root, w.source, w.merge, w.tip} {
		same("Parent "+rev, func(r *gitrepo.Repo) (any, error) { return r.Parent(rev) })
		same("Note "+rev, func(r *gitrepo.Repo) (any, error) { return r.Note(rev) })
		same("CommitMeta "+rev, func(r *gitrepo.Repo) (any, error) { return r.CommitMeta(rev) })
		same("IsAncestor "+rev, func(r *gitrepo.Repo) (any, error) { return r.IsAncestor(w.root, rev) })
		same("IsAncestor back "+rev, func(r *gitrepo.Repo) (any, error) { return r.IsAncestor(rev, w.root) })
	}

	for _, tag := range []string{"v0.1.0", "v0.9.0", "v1.0.0"} {
		same("TagCommit "+tag, func(r *gitrepo.Repo) (any, error) { return r.TagCommit(tag) })
	}

	for _, sha := range []string{w.signedSHA, w.unsignedSHA} {
		same("TagObject "+sha, func(r *gitrepo.Repo) (any, error) { return r.TagObject(sha) })
	}
}

func equal(a, b any) bool {
	switch x := a.(type) {
	case []gitrepo.ChainNote:
		y, ok := b.([]gitrepo.ChainNote)

		return ok && slices.EqualFunc(x, y, func(p, q gitrepo.ChainNote) bool {
			return p.Rev == q.Rev && bytes.Equal(p.Note, q.Note)
		})
	case []byte:
		y, ok := b.([]byte)

		return ok && bytes.Equal(x, y)
	case *gitrepo.TagObject:
		y, ok := b.(*gitrepo.TagObject)

		return ok && x.Tagger == y.Tagger && x.Target == y.Target &&
			bytes.Equal(x.Payload, y.Payload) && bytes.Equal(x.Signature, y.Signature)
	case *gitrepo.CommitMeta:
		y, ok := b.(*gitrepo.CommitMeta)

		return ok && x.CommitEpoch == y.CommitEpoch && x.Subject == y.Subject && slices.Equal(x.Parents, y.Parents)
	case []gitrepo.TagRef:
		y, ok := b.([]gitrepo.TagRef)

		return ok && slices.Equal(x, y)
	case []gitrepo.Revision:
		y, ok := b.([]gitrepo.Revision)

		return ok && slices.Equal(x, y)
	case []string:
		y, ok := b.([]string)

		return ok && slices.Equal(x, y)
	default:
		return a == b
	}
}

// objects lists every object in a repository's store, by type.
func objects(t *testing.T, dir string) map[string][]string {
	t.Helper()

	cmd := exec.Command("git", "-C", dir, //nolint:gosec,noctx // fixed executable, test-owned args
		"cat-file", "--batch-all-objects", "--batch-check=%(objecttype) %(objectname)")
	cmd.Env = gitrepo.Env()

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("listing objects: %v", err)
	}

	byType := map[string][]string{}

	for line := range strings.Lines(string(out)) {
		kind, oid, _ := strings.Cut(strings.TrimSpace(line), " ")
		byType[kind] = append(byType[kind], oid)
	}

	return byType
}

// TestBranchFetchBringsNoSource asserts the design condition on the
// object list itself: after a fetch, every tree is a tree of the
// ledger and every blob is a note — no source tree, no source blob.
func TestBranchFetchBringsNoSource(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	f := fetch(t, &Fetcher{}, w.src.URL(), "", everything)

	// The ledger is fetched whole, so every tree and blob of its own
	// history may come down — and nothing else may, but the empty tree,
	// which an empty commit names and which holds nothing at all.
	ledger := map[string]bool{emptyTree: true}

	for line := range strings.Lines(w.src.Git("rev-list", "--objects", notesRef)) {
		oid, _, _ := strings.Cut(strings.TrimSpace(line), " ")
		ledger[oid] = true
	}

	got := objects(t, f.dir)

	for _, tree := range got["tree"] {
		if !ledger[tree] {
			t.Errorf("tree %s is not the ledger's — the fetch brought down a source tree", tree)
		}
	}

	notes := 0

	for _, blob := range got["blob"] {
		if !ledger[blob] {
			t.Errorf("blob %s is not a note — the fetch brought down source", blob)
		}

		notes++
	}

	if notes == 0 || len(got["commit"]) == 0 {
		t.Fatalf("objects = %v, want the notes and the commits", got)
	}

	// The source blob, named outright: it exists in the source and must
	// not here.
	sourceBlob := w.src.Git("rev-parse", w.source+":src/main.go")
	if slices.Contains(got["blob"], sourceBlob) {
		t.Fatalf("the source blob %s came down", sourceBlob)
	}
}

// emptyTree is git's tree of nothing.
const emptyTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

// TestFetchedRepositoryIsNotShallow: the ledger is fetched whole,
// because a shallow notes fetch marks the repository shallow and every
// history read refuses a shallow repository (measured, stele#384).
func TestFetchedRepositoryIsNotShallow(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	f := fetch(t, &Fetcher{}, w.src.URL(), "", everything)

	cmd := exec.Command("git", "-C", f.dir, "rev-parse", "--is-shallow-repository") //nolint:gosec,noctx // test-owned
	cmd.Env = gitrepo.Env()

	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != "false" {
		t.Fatalf("is-shallow-repository = %q, %v — want false", out, err)
	}

	if _, err := f.Repo.Revisions("refs/heads/main", time.Time{}); err != nil {
		t.Fatalf("Revisions = %v — the history read refused the fetched repository", err)
	}
}

// TestFetchedReadsNeverNetwork: once fetched, every read answers with
// the remote gone — the reader never networks on its own, even over a
// repository missing the trees a porcelain command reaches for.
func TestFetchedReadsNeverNetwork(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	f := fetch(t, &Fetcher{}, w.src.URL(), "", everything)

	if err := os.RemoveAll(w.src.Dir); err != nil {
		t.Fatal(err)
	}

	r := f.Repo

	if _, err := r.Revisions("refs/heads/main", time.Time{}); err != nil {
		t.Fatalf("Revisions = %v", err)
	}

	if _, err := r.ChainNotes(); err != nil {
		t.Fatalf("ChainNotes = %v", err)
	}

	if _, err := r.TagCommit("v1.0.0"); err != nil {
		t.Fatalf("TagCommit = %v", err)
	}

	if _, err := r.CommitMeta(w.tip); err != nil {
		t.Fatalf("CommitMeta = %v", err)
	}

	// A read that needs a withheld object refuses rather than fetching
	// it: the source tree is not there, and nothing goes to get it.
	if _, err := r.Tip(w.source + "^{tree}"); err == nil {
		t.Fatal("a source tree answered from a commits-only fetch")
	}
}

// TestCloseLeavesNothingBehind: the fetched repository lives exactly
// as long as the walk that asked for it.
func TestCloseLeavesNothingBehind(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	f, err := (&Fetcher{}).Fetch(w.src.URL(), "", everything)
	if err != nil {
		t.Fatalf("Fetch = %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}

	if _, err := os.Stat(f.dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat(%s) = %v — the fetched repository outlived the walk", f.dir, err)
	}
}

// TestAbsentRefsAreAnswers: a remote without the ledger is an empty
// chain, and a branch it does not have is not fetched — reading it
// refuses as a read of any absent ref does, never as a failed fetch.
func TestAbsentRefsAreAnswers(t *testing.T) {
	t.Parallel()

	r := gittest.New(t)
	r.Commit("feat: one")

	f := fetch(t, &Fetcher{}, r.URL(), "", Want{
		Branches: []string{"refs/heads/main", "refs/heads/release"}, NotesRef: notesRef,
	})

	if notes, err := f.Repo.ChainNotes(); err != nil || notes != nil {
		t.Fatalf("ChainNotes = %v, %v — an absent ledger is an empty chain", notes, err)
	}

	if _, err := f.Repo.Tip("refs/heads/release"); err == nil {
		t.Fatal("Tip invented a branch the remote does not have")
	}

	if _, err := f.Repo.Tip("refs/heads/main"); err != nil {
		t.Fatalf("Tip(main) = %v", err)
	}
}

// TestShallowWantFetchesTheTagAlone: the pin resolver asks a tag for
// its target and nothing behind it.
func TestShallowWantFetchesTheTagAlone(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	f := fetch(t, &Fetcher{}, w.src.URL(), "", Want{Tags: true, Shallow: true})

	if got, err := f.Repo.TagCommit("v1.0.0"); err != nil || got != w.merge {
		t.Fatalf("TagCommit = %s, %v", got, err)
	}

	if _, err := f.Repo.Noted(); err == nil {
		t.Fatal("a fetch with no ledger read one")
	}

	if got := objects(t, f.dir); len(got["commit"]) != 2 || len(got["tag"]) != 2 {
		t.Fatalf("objects = %v, want the two annotated tags and the two commits they name", got)
	}
}

func TestWantRefusals(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		want Want
		says string
	}{
		{
			name: "a short branch", want: Want{Branches: []string{"main"}},
			says: `"main" is not a fully qualified branch ref`,
		},
		{
			name: "a branch glob", want: Want{Branches: []string{"refs/heads/*"}},
			says: "is not a fully qualified branch ref",
		},
		{
			name: "an option in disguise", want: Want{Branches: []string{"refs/heads/x --upload-pack=y"}},
			says: "is not a fully qualified",
		},
		{
			name: "a short notes ref", want: Want{Tags: true, NotesRef: "commits"},
			says: `notes ref "commits" is not fully qualified`,
		},
		{name: "a ledger alone", want: Want{NotesRef: notesRef}, says: "names no branch and no tag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := (&Fetcher{}).Fetch("file:///nowhere", "", tc.want)
			if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("Fetch = %v, want %q", err, tc.says)
			}
		})
	}
}

// fakeGit writes an executable standing in for git.
func fakeGit(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "git")

	//nolint:gosec // G306: an executable by design, in the test's own directory
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	return path
}

// TestGitMissingOrTooOldIsARefusalByName: a machine whose git cannot
// do this job refuses before any fetch, naming the floor — never a
// verdict, and never a fallback to some other reader.
func TestGitMissingOrTooOldIsARefusalByName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, git, says string }{
		{
			name: "git absent",
			git:  filepath.Join(t.TempDir(), "no-git-here"),
			says: "gitfetch: git is not installed — stele reads git objects with git 2.44.0 or newer",
		},
		{
			name: "git too old",
			git:  fakeGit(t, `echo "git version 2.43.7"`),
			says: "gitfetch: git 2.43.7 is too old — stele reads git objects with git 2.44.0 or newer",
		},
		{
			name: "a version that names nothing",
			git:  fakeGit(t, `echo "hello"`),
			says: "gitfetch: `git version` answered \"hello\", which names no version — stele reads git objects" +
				" with git 2.44.0 or newer",
		},
		{
			name: "git that fails",
			git:  fakeGit(t, `exit 3`),
			says: "exit status 3 — stele reads git objects with git 2.44.0 or newer",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := (&Fetcher{Git: tc.git}).Fetch("file:///nowhere", "", everything)
			if err == nil || !strings.Contains(err.Error(), tc.says) || !errors.Is(err, ErrGit) {
				t.Fatalf("Fetch = %v, want %q", err, tc.says)
			}

			if errors.Is(err, ErrFetch) {
				t.Fatal("a missing git is not a failed fetch: it is a refusal to start")
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		out  string
		want [3]int
		ok   bool
	}{
		{out: "git version 2.50.1 (Apple Git-155)\n", want: [3]int{2, 50, 1}, ok: true},
		{out: "git version 2.44.0.windows.1", want: [3]int{2, 44, 0}, ok: true},
		{out: "git version 2.44", ok: false},
		{out: "git version two.44.0", ok: false},
		{out: "git version 2.-1.0", ok: false},
		{out: "version 2.44.0", ok: false},
	} {
		got, ok := parseVersion(tc.out)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("parseVersion(%q) = %v, %v; want %v, %v", tc.out, got, ok, tc.want, tc.ok)
		}
	}

	if older([3]int{2, 44, 0}, minVersion()) || !older([3]int{2, 43, 9}, minVersion()) ||
		older([3]int{3, 0, 0}, minVersion()) {
		t.Fatal("older orders versions wrongly")
	}
}

// TestARemoteIgnoringTheFilterIsReported: the walk is still correct —
// git fetches the unfiltered objects — but the run says so.
func TestARemoteIgnoringTheFilterIsReported(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.src.Git("config", "uploadpack.allowFilter", "false")

	f := fetch(t, &Fetcher{}, w.src.URL(), "", everything)
	if !f.FilterIgnored {
		t.Fatal("FilterIgnored = false, want the ignored filter reported")
	}

	if got, err := f.Repo.TagCommit("v1.0.0"); err != nil || got != w.merge {
		t.Fatalf("TagCommit = %s, %v — the walk must still be correct", got, err)
	}
}

// TestAFailedFetchCannotJudge: a remote that is not there is a fetch
// that did not complete — ErrFetch, named, not retried, and never a
// judgment about the subject.
func TestAFailedFetchCannotJudge(t *testing.T) {
	t.Parallel()

	var slept []time.Duration

	remote := "file://" + filepath.Join(t.TempDir(), "absent.git")
	f := &Fetcher{Sleep: func(d time.Duration) { slept = append(slept, d) }}

	_, err := f.Fetch(remote, "", everything)
	if err == nil || !errors.Is(err, ErrFetch) || errors.Is(err, gh.ErrThrottled) {
		t.Fatalf("Fetch = %v, want a failed fetch", err)
	}

	want := "gitfetch: " + remote + ": the repository's history could not be fetched, which says nothing about" +
		" the subject: git: fatal: '" + strings.TrimPrefix(remote, "file://") + "' does not appear to be a git repository"
	if err.Error() != want {
		t.Fatalf("err =\n%s\nwant\n%s", err, want)
	}

	if len(slept) != 0 {
		t.Fatalf("slept %v — an absent repository is not retried", slept)
	}
}

// gitServer serves bare repositories over smart HTTP through git's own
// http-backend, so the fetch is exercised against real git on the
// wire, with a scripted refusal in front of it when a test wants one.
type gitServer struct {
	*httptest.Server

	mu      sync.Mutex
	auth    []string
	refuse  func(http.ResponseWriter, *http.Request) bool
	queries int
}

func serveGit(t *testing.T, w *world) *gitServer {
	t.Helper()

	root := t.TempDir()
	w.src.Git("clone", "-q", "--bare", w.src.Dir, filepath.Join(root, "repo.git"))

	cmd := exec.Command("git", "-C", filepath.Join(root, "repo.git"), //nolint:gosec,noctx // test-owned
		"fetch", "-q", w.src.Dir, "+refs/notes/*:refs/notes/*", "+refs/tags/*:refs/tags/*")
	cmd.Env = gitrepo.Env()

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("copying the ledger: %v: %s", err, out)
	}

	for _, kv := range [][2]string{{"uploadpack.allowFilter", "true"}, {"http.receivepack", "false"}} {
		//nolint:gosec,noctx // fixed executable, test-owned args
		c := exec.Command("git", "-C", filepath.Join(root, "repo.git"), "config", kv[0], kv[1])
		c.Env = gitrepo.Env()

		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("config: %v: %s", err, out)
		}
	}

	execPath, err := exec.Command("git", "--exec-path").Output() //nolint:noctx // test-owned
	if err != nil {
		t.Fatalf("git --exec-path: %v", err)
	}

	backend := &cgi.Handler{
		Path: filepath.Join(strings.TrimSpace(string(execPath)), "git-http-backend"),
		Env:  []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_GLOBAL=/dev/null"},
	}

	s := &gitServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.queries++
		s.auth = append(s.auth, r.Header.Get("Authorization"))
		refuse := s.refuse
		s.mu.Unlock()

		if refuse != nil && refuse(rw, r) {
			return
		}

		backend.ServeHTTP(rw, r)
	}))
	t.Cleanup(s.Close)

	return s
}

func (s *gitServer) remote() string { return s.URL + "/repo.git" }

// TestTheCredentialTravelsAsAHeaderAndNowhereElse: over real HTTP the
// token reaches the server as the basic credential the forge expects —
// and never the argument list nor any file in the fetched repository
// (both read, stele#384 item 4).
func TestTheCredentialTravelsAsAHeaderAndNowhereElse(t *testing.T) {
	const token = "ghs_THE-TOKEN-UNDER-TEST" //nolint:gosec // G101: a made-up value, the one this test proves never leaks

	w := newWorld(t)
	srv := serveGit(t, &w)

	argv := filepath.Join(t.TempDir(), "argv.log")
	wrapper := fakeGit(t, `printf '%s\n' "$*" >> '`+argv+`'`+"\n"+`exec git "$@"`)

	f := fetch(t, &Fetcher{Git: wrapper}, srv.remote(), token, everything)

	if got, err := f.Repo.TagCommit("v1.0.0"); err != nil || got != w.merge {
		t.Fatalf("TagCommit over HTTP = %s, %v", got, err)
	}

	encoded := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))

	srv.mu.Lock()
	seen := slices.Clone(srv.auth)
	srv.mu.Unlock()

	if len(seen) == 0 || !slices.Contains(seen, "basic "+encoded) {
		t.Fatalf("Authorization headers = %q, want the basic credential", seen)
	}

	logged, err := os.ReadFile(argv) //nolint:gosec // test-owned path
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(logged), "fetch") {
		t.Fatalf("the wrapper saw no fetch:\n%s", logged)
	}

	secrets := []string{token, encoded}

	for _, secret := range secrets {
		if strings.Contains(string(logged), secret) {
			t.Fatalf("an argument list carried the credential:\n%s", logged)
		}
	}

	walkErr := filepath.WalkDir(f.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		content, rerr := os.ReadFile(path) //nolint:gosec // the fetched repository's own files
		if rerr != nil {
			return fmt.Errorf("reading %s: %w", path, rerr)
		}

		for _, secret := range secrets {
			if bytes.Contains(content, []byte(secret)) {
				t.Errorf("%s carries the credential", path)
			}
		}

		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}

	config, err := os.ReadFile(filepath.Join(f.dir, "config"))
	if err != nil || !strings.Contains(string(config), srv.remote()) {
		t.Fatalf("config = %q, %v — read, and naming the remote", config, err)
	}
}

// TestAPublicFetchSendsNoCredential: with no token, nothing at all is
// sent — not an empty header, not a probe.
func TestAPublicFetchSendsNoCredential(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	srv := serveGit(t, &w)

	fetch(t, &Fetcher{}, srv.remote(), "", everything)

	srv.mu.Lock()
	defer srv.mu.Unlock()

	for _, a := range srv.auth {
		if a != "" {
			t.Fatalf("Authorization = %q on a public fetch", a)
		}
	}
}

// TestNoHelperAndNoPromptRuns: a remote that demands a credential the
// fetch was not given ends the fetch — no credential helper is asked
// (an inherited one, or Apple's built-in osxkeychain) and no prompt
// opens, whatever the operator's environment set up.
func TestNoHelperAndNoPromptRuns(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "asked")
	asker := fakeGit(t, `touch '`+marker+`'; echo secret`)

	t.Setenv("GIT_ASKPASS", asker)
	t.Setenv("SSH_ASKPASS", asker)
	t.Setenv("GIT_CONFIG_PARAMETERS", "'credential.helper'='"+asker+"'")

	w := newWorld(t)
	srv := serveGit(t, &w)
	srv.refuse = func(rw http.ResponseWriter, _ *http.Request) bool {
		rw.Header().Set("WWW-Authenticate", `Basic realm="git"`)
		rw.WriteHeader(http.StatusUnauthorized)

		return true
	}

	_, err := (&Fetcher{}).Fetch(srv.remote(), "", everything)
	if err == nil || !errors.Is(err, ErrFetch) {
		t.Fatalf("Fetch = %v, want the refused fetch", err)
	}

	if !strings.Contains(err.Error(), "terminal prompts disabled") {
		t.Fatalf("Fetch = %v, want git's own statement that it would not prompt", err)
	}

	if _, serr := os.Stat(marker); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatal("a credential helper or askpass program ran")
	}
}

// TestAThrottledFetchIsTypedAndRetried: a 429 is the host throttling
// this walk — typed in the one throttle shape (stele#383), with every
// rate field absent because git surfaces none, retried on the ladder,
// and ending the fetch as could-not-judge, never as a judgment.
func TestAThrottledFetchIsTypedAndRetried(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	srv := serveGit(t, &w)
	srv.refuse = func(rw http.ResponseWriter, _ *http.Request) bool {
		rw.Header().Set("Retry-After", "30")
		rw.WriteHeader(http.StatusTooManyRequests)

		return true
	}

	var slept []time.Duration

	_, err := (&Fetcher{Sleep: func(d time.Duration) { slept = append(slept, d) }}).Fetch(srv.remote(), "", everything)
	if err == nil || !errors.Is(err, gh.ErrThrottled) || !errors.Is(err, ErrFetch) {
		t.Fatalf("Fetch = %v, want a throttled, failed fetch", err)
	}

	want := "gitfetch: " + srv.remote() + ": the repository's history could not be fetched, which says nothing" +
		" about the subject: after 4 attempts: HTTP 429: the host throttled this walk, which says nothing about the" +
		" subject [marker: http-429; x-ratelimit-remaining: absent; x-ratelimit-reset: absent;" +
		" x-ratelimit-resource: absent; retry-after: absent]"
	if err.Error() != want {
		t.Fatalf("err =\n%s\nwant\n%s", err, want)
	}

	if !slices.Equal(slept, []time.Duration{3 * time.Second, 6 * time.Second, 9 * time.Second}) {
		t.Fatalf("slept %v, want the ladder's own backoff — git names no wait", slept)
	}
}

// TestAFailingHostIsRetriedAndARefusalIsNot: a 5xx is the host failing
// and rides the ladder; a 403 is an answer and refuses at once. Both
// end as could-not-judge.
func TestAFailingHostIsRetriedAndARefusalIsNot(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		status int
		slept  int
		says   string
	}{
		{name: "a failing host", status: http.StatusBadGateway, slept: 3, says: "after 4 attempts: HTTP 502: "},
		{name: "a refusal", status: http.StatusForbidden, slept: 0, says: "subject: HTTP 403: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newWorld(t)
			srv := serveGit(t, &w)
			srv.refuse = func(rw http.ResponseWriter, _ *http.Request) bool {
				rw.WriteHeader(tc.status)

				return true
			}

			var slept []time.Duration

			f := &Fetcher{Sleep: func(d time.Duration) { slept = append(slept, d) }}

			_, err := f.Fetch(srv.remote(), "", everything)
			if err == nil || !errors.Is(err, ErrFetch) || errors.Is(err, gh.ErrThrottled) {
				t.Fatalf("Fetch = %v, want a failed fetch that is not a throttle", err)
			}

			if !strings.Contains(err.Error(), tc.says) || len(slept) != tc.slept {
				t.Fatalf("Fetch = %v after %v; want %q after %d waits", err, slept, tc.says, tc.slept)
			}
		})
	}
}
