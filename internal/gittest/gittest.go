// Package gittest builds real git repositories for tests: branches,
// merges, notes and annotated, signed and lightweight tags, served to
// a fetch over file://. Real git is the point — the readers under test
// ARE the git boundary, and a scripted git would leave the seam they
// sit on untested.
//
// Imported only by tests; nothing in the binary reaches it.
package gittest

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gitrepo"
)

// Epoch is the committer time of a repository's first commit; each
// commit after it lands one minute later, so commit times are
// deterministic and strictly ordered.
const Epoch = 1_700_000_000

// Signature is the block a signed tag built here carries: shaped as
// the X.509 (gitsign) form git recognises. Its bytes are never
// verified by anything that reads them here — readers split it off,
// they do not judge it.
const Signature = "-----BEGIN SIGNED MESSAGE-----\n" +
	"MIIBc2lnbmF0dXJlIGJ5dGVzIGZvciBhIHRlc3Q=\n" +
	"-----END SIGNED MESSAGE-----\n"

// Repo is one scratch repository with a checked-out main branch.
type Repo struct {
	t    testing.TB
	Dir  string
	tick int
}

// New initialises a repository on main whose upload side honours the
// commits-only filter, as the forge's does.
func New(tb testing.TB) *Repo {
	tb.Helper()

	r := &Repo{t: tb, Dir: tb.TempDir()}
	r.Git("init", "-q", "-b", "main")
	r.Git("config", "user.name", "t")
	r.Git("config", "user.email", "t@example.com")
	r.Git("config", "uploadpack.allowFilter", "true")

	return r
}

// URL is the repository as a fetch names it.
func (r *Repo) URL() string { return "file://" + r.Dir }

// Git runs one git command in the repository and returns its trimmed
// output; a failure fails the test.
func (r *Repo) Git(args ...string) string {
	r.t.Helper()

	return r.GitIn(nil, args...)
}

// GitIn is Git with bytes on stdin.
func (r *Repo) GitIn(stdin []byte, args ...string) string {
	r.t.Helper()

	when := fmt.Sprintf("@%d +0000", Epoch+r.tick*int(time.Minute/time.Second))

	cmd := exec.Command("git", //nolint:gosec,noctx // fixed executable, test-owned args
		append([]string{"-C", r.Dir}, args...)...)
	cmd.Env = gitrepo.Env(
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_AUTHOR_DATE="+when, "GIT_COMMITTER_DATE="+when,
	)

	var out, errs bytes.Buffer

	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	cmd.Stdout = &out
	cmd.Stderr = &errs

	if err := cmd.Run(); err != nil {
		r.t.Fatalf("git %v: %v: %s", args, err, errs.String())
	}

	return strings.TrimSpace(out.String())
}

// Commit records an empty commit with the given message on the
// checked-out branch and returns it.
func (r *Repo) Commit(message string) string {
	r.t.Helper()

	r.Git("commit", "-q", "--allow-empty", "-m", message)
	r.tick++

	return r.Git("rev-parse", "HEAD")
}

// File commits one file with the given content — source the fetch must
// never bring down — and returns the commit.
func (r *Repo) File(path, content, message string) string {
	r.t.Helper()

	blob := r.GitIn([]byte(content), "hash-object", "-w", "--stdin")
	r.Git("update-index", "--add", "--cacheinfo", "100644,"+blob+","+path)
	r.Git("commit", "-q", "-m", message)
	r.tick++

	return r.Git("rev-parse", "HEAD")
}

// Note adds (or replaces) rev's note on ref with exactly these bytes.
func (r *Repo) Note(ref, rev string, note []byte) {
	r.t.Helper()

	r.GitIn(note, "notes", "--ref", ref, "add", "-f", "-F", "-", rev)
}

// Lightweight points a lightweight tag at target.
func (r *Repo) Lightweight(name, target string) {
	r.t.Helper()

	r.Git("tag", name, target)
}

// Annotated writes an annotated tag object on target, signed with
// Signature when signed is true, points refs/tags/<name> at it, and
// returns the raw object and its id.
//
//nolint:gocritic // unnamedResult: the raw object, then its id
func (r *Repo) Annotated(name, target, tagger string, signed bool) ([]byte, string) {
	r.t.Helper()

	object := fmt.Sprintf("object %s\ntype commit\ntag %s\ntagger %s <%s@example.com> %d +0000\n\n%s\n",
		target, name, tagger, "tagger", Epoch, name)
	if signed {
		object += Signature
	}

	sha := r.GitIn([]byte(object), "mktag")
	r.Git("update-ref", "refs/tags/"+name, sha)

	return []byte(object), sha
}
