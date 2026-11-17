package gitrepo_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gitrepo"
	"github.com/monumental-archive/stele/internal/gittest"
)

// commitsOnly is a commits-only partial clone of src, as the fetch
// makes one (stele#384): every branch and tag, no tree and no blob.
func commitsOnly(t *testing.T, src *gittest.Repo) string {
	t.Helper()

	dir := t.TempDir()

	for _, args := range [][]string{
		{"init", "-q", "--bare", dir},
		{"-C", dir, "config", "remote.origin.url", src.URL()},
		{"-C", dir, "config", "remote.origin.promisor", "true"},
		{"-C", dir, "config", "extensions.partialClone", "origin"},
		{
			"-C", dir, "fetch", "-q", "--no-tags", "--filter=tree:0", "origin",
			"+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*",
		},
	} {
		cmd := exec.Command("git", args...) //nolint:gosec,noctx // fixed executable, test-owned args
		cmd.Env = gitrepo.Env()

		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}

	return dir
}

// TestHasCommit: the store's answer, typed — a commit held, a commit
// not held (absent from every fetched ref, or never existing), and
// every other answer an error by name.
func TestHasCommit(t *testing.T) {
	t.Parallel()

	src := gittest.New(t)
	held := src.Commit("feat: on main")
	_, tagSHA := src.Annotated("v1.0.0", held, "release-mint[bot]", false)
	src.Git("checkout", "-q", "-b", "gone")
	gone := src.Commit("feat: on a branch deleted before the fetch")
	src.Git("checkout", "-q", "main")
	src.Git("branch", "-q", "-D", "gone")

	dir := commitsOnly(t, src)

	r, err := gitrepo.OpenObjects(dir)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("git", "-C", dir, "hash-object", "-w", "--stdin") //nolint:gosec,noctx // test-owned args
	cmd.Env = gitrepo.Env()
	cmd.Stdin = bytes.NewReader([]byte("a blob\n"))

	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}

	blob := strings.TrimSpace(string(out))

	cases := []struct {
		name string
		oid  string
		held bool
		want string
	}{
		{name: "a commit the store holds", oid: held, held: true},
		{name: "a commit whose branch was deleted before the fetch", oid: gone},
		{name: "a full-length id the store never held", oid: "0123456789abcdef0123456789abcdef01234567"},
		{name: "a tag object", oid: tagSHA, want: "gitrepo: " + tagSHA + " is a tag, not a commit"},
		{name: "a blob", oid: blob, want: "gitrepo: " + blob + " is a blob, not a commit"},
		{name: "a branch name", oid: "main", want: `gitrepo: "main" is not a full hex object id`},
		{name: "a ref", oid: "refs/heads/main", want: "is not a full hex object id"},
		{name: "an abbreviation", oid: held[:12], want: "is not a full hex object id"},
		{name: "upper-case hex", oid: strings.ToUpper(held), want: "is not a full hex object id"},
		{name: "one digit too many", oid: held + "0", want: "is not a full hex object id"},
		{
			name: "a full-length SHA-256 id in a SHA-1 store", oid: strings.Repeat("ab", 32),
			want: "gitrepo: is " + strings.Repeat("ab", 32) + " held: git cat-file -e: exit status 128",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := r.HasCommit(tc.oid)

			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("err = %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			}

			if got != tc.held {
				t.Fatalf("HasCommit(%s) = %v, want %v", tc.oid, got, tc.held)
			}
		})
	}
}

// TestHasCommitOnAStoreGitCannotRead: a store that stopped being one
// is git failing, never "not held".
func TestHasCommitOnAStoreGitCannotRead(t *testing.T) {
	t.Parallel()

	src := gittest.New(t)
	held := src.Commit("feat: on main")
	dir := commitsOnly(t, src)

	r, err := gitrepo.OpenObjects(dir)
	if err != nil {
		t.Fatal(err)
	}

	if rerr := os.RemoveAll(filepath.Join(dir, "objects")); rerr != nil {
		t.Fatal(rerr)
	}

	got, err := r.HasCommit(held)
	if got || err == nil || !strings.Contains(err.Error(), "gitrepo: is "+held+" held: git cat-file -e: exit status 128") {
		t.Fatalf("HasCommit = %v, %v; want the failure named, never an absence", got, err)
	}
}
