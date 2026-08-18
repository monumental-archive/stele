// Git behaving in ways this package must refuse rather than misread.
// Every world here is a real repository in a real degraded state — a
// SHA-256 object format, a corrupt object store, a clone that vanished
// mid-run, an identity git will not guess — because this package IS
// the git boundary, and a stand-in git would leave the boundary
// untested.

package gitrepo_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gitrepo"
)

// sha256Repo builds a repository whose object format is SHA-256, so
// every object id is 64 hex characters instead of 40.
func sha256Repo(t *testing.T) fixture {
	t.Helper()

	dir := t.TempDir()
	git := gitCmd(t, dir)

	git("init", "-q", "-b", "main", "--object-format=sha256")
	git("config", "user.name", "t")
	git("config", "user.email", "t@example.com")

	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}

	git("add", "f")
	git("commit", "-q", "-m", "one")

	tip := git("rev-parse", "HEAD")
	git("notes", "add", "-m", `{"the":"note"}`, tip)

	return fixture{dir: dir, tip: tip, root: tip}
}

// TestSHA256RepositoryIsRefusedByName: the ledger's revisions and note
// digests are 40-hex by contract, and a SHA-256 repository's ids are
// not. Every read that returns an object id must refuse rather than
// hand a 64-hex string onward as if it were a revision — silently
// carrying it would put unresolvable pointers in a chain.
func TestSHA256RepositoryIsRefusedByName(t *testing.T) {
	t.Parallel()

	fx := sha256Repo(t)

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	if len(fx.tip) != 64 {
		t.Fatalf("tip = %q, want a 64-hex SHA-256 object id", fx.tip)
	}

	if _, err := r.Tip("refs/heads/main"); err == nil || !strings.Contains(err.Error(), "not a commit") {
		t.Errorf("Tip = %v, want the non-revision refusal", err)
	}

	if _, err := r.Note(fx.tip); err == nil || !strings.Contains(err.Error(), "not a blob id") {
		t.Errorf("Note = %v, want the non-blob refusal", err)
	}

	if _, err := r.Commits("", fx.tip); err == nil || !strings.Contains(err.Error(), "not a revision") {
		t.Errorf("Commits = %v, want the non-revision refusal", err)
	}
}

// TestParentReadsRequireAFullRevision: rev-list echoes the revision it
// resolved, and both parent reads check that echo against what they
// were asked for. A symbolic or abbreviated name resolves to something
// else, and a ledger keyed by "HEAD" points at nothing.
func TestParentReadsRequireAFullRevision(t *testing.T) {
	t.Parallel()

	fx := repo(t)

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	for _, name := range []string{"HEAD", fx.tip[:8]} {
		if _, err := r.Parent(name); err == nil || !strings.Contains(err.Error(), "rev-list for") {
			t.Errorf("Parent(%q) = %v, want the echo refusal", name, err)
		}

		if _, err := r.Parents(name); err == nil || !strings.Contains(err.Error(), "rev-list for") {
			t.Errorf("Parents(%q) = %v, want the echo refusal", name, err)
		}
	}
}

// TestNoteRefusesACorruptObjectStore: the note is listed but its blob
// is gone. Reading that as "no note" would report an unattested
// revision as attested-by-nothing, so the read must refuse.
func TestNoteRefusesACorruptObjectStore(t *testing.T) {
	t.Parallel()

	fx := repo(t)
	git := gitCmd(t, fx.dir)

	blob := git("notes", "list", fx.tip)

	// The freshly written note is a loose object; removing it leaves
	// the notes tree pointing at nothing.
	loose := filepath.Join(fx.dir, ".git", "objects", blob[:2], blob[2:])
	if err := os.Remove(loose); err != nil {
		t.Fatalf("removing the note blob: %v", err)
	}

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	if _, err := r.Note(fx.tip); err == nil || !strings.Contains(err.Error(), "cat-file") {
		t.Fatalf("Note = %v, want the cat-file refusal", err)
	}
}

// TestNotedRefusesANotesRefThatIsNotOne: the ref resolves — so the
// absence shortcut does not fire — but it names a blob, not a notes
// commit. An empty ledger and an unreadable one are different facts.
func TestNotedRefusesANotesRefThatIsNotOne(t *testing.T) {
	t.Parallel()

	fx := repo(t)
	git := gitCmd(t, fx.dir)

	blob := git("notes", "list", fx.tip)
	git("update-ref", notesRef, blob)

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	if _, err := r.Noted(); err == nil || !strings.Contains(err.Error(), "notes list") {
		t.Fatalf("Noted = %v, want the listing refusal", err)
	}
}

// TestCommitterIdentRefusesWhenGitWillNotGuess: the ledger commit
// needs an identity from the repository's own config, and
// user.useConfigOnly is git's own switch for "do not invent one". The
// refusal must be named here rather than an exit 128 mid-append.
func TestCommitterIdentRefusesWhenGitWillNotGuess(t *testing.T) {
	// Not parallel: the identity also comes from the environment, and
	// clearing it is process-wide.
	for _, key := range []string{
		"GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL",
		"GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "EMAIL",
	} {
		t.Setenv(key, "")
	}

	fx := repo(t)
	git := gitCmd(t, fx.dir)

	git("config", "--unset", "user.name")
	git("config", "--unset", "user.email")
	git("config", "user.useConfigOnly", "true")

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	if err := r.CommitterIdent(); err == nil || !strings.Contains(err.Error(), "no usable committer identity") {
		t.Fatalf("CommitterIdent = %v, want the named refusal", err)
	}
}

// TestDryRunPushRefusals: the push proof has two prerequisites — a
// notes ref to advance and a revision to annotate — and each missing
// one is refused before anything irreversible happens.
func TestDryRunPushRefusals(t *testing.T) {
	t.Parallel()

	t.Run("no notes ref to prove against", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		git := gitCmd(t, dir)
		git("init", "-q", "-b", "main")
		git("config", "user.name", "t")
		git("config", "user.email", "t@example.com")
		git("commit", "-q", "--allow-empty", "-m", "one")

		r, err := gitrepo.Open(dir, notesRef)
		if err != nil {
			t.Fatalf("Open = %v", err)
		}

		if err := r.DryRunPushNotes("origin", "", "HEAD"); err == nil ||
			!strings.Contains(err.Error(), "nothing to prove a push against") {
			t.Fatalf("DryRunPushNotes = %v, want the absent-ref refusal", err)
		}
	})

	t.Run("no such revision to annotate", func(t *testing.T) {
		t.Parallel()

		fx := repo(t)

		r, err := gitrepo.Open(fx.dir, notesRef)
		if err != nil {
			t.Fatalf("Open = %v", err)
		}

		if err := r.DryRunPushNotes("origin", "", "not-a-valid-object"); err == nil ||
			!strings.Contains(err.Error(), "could not annotate") {
			t.Fatalf("DryRunPushNotes = %v, want the annotate refusal", err)
		}
	})
}

// TestNetworkRefusals: both network reads name the ref they could not
// move, and the token path is exercised on the same call — the header
// is attached for a remote that does not exist just as it would be for
// one that does.
func TestNetworkRefusals(t *testing.T) {
	t.Parallel()

	fx := repo(t)

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	if err := r.FetchNotes("no-such-remote", ""); err == nil ||
		!strings.Contains(err.Error(), "fetch "+notesRef) {
		t.Fatalf("FetchNotes = %v, want the fetch refusal", err)
	}

	if err := r.FetchNotes("no-such-remote", "a-token"); err == nil {
		t.Fatal("FetchNotes with a token accepted a remote that does not exist")
	}
}

// TestTokenTravelsToTheRemote: with a token the header is attached, and
// the push still has to land. A file-protocol remote ignores the
// header, which is the point — the token path must not break the
// non-HTTP remotes the tests and mirrors use.
func TestTokenTravelsToTheRemote(t *testing.T) {
	t.Parallel()

	fx := repo(t)
	remoteDir := t.TempDir()

	gitCmd(t, remoteDir)("init", "-q", "--bare")

	local := gitCmd(t, fx.dir)
	local("remote", "add", "origin", remoteDir)
	local("push", "-q", "origin", "main")

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	if err := r.PushNotes("origin", "a-token"); err != nil {
		t.Fatalf("PushNotes with a token = %v", err)
	}

	if err := r.FetchNotes("origin", "a-token"); err != nil {
		t.Fatalf("FetchNotes with a token = %v", err)
	}
}

// TestHistoryRefusesAVanishedClone: the depth probe runs before every
// history read precisely so a repository that cannot answer refuses
// instead of reporting "nothing released".
func TestHistoryRefusesAVanishedClone(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	git := gitCmd(t, dir)
	git("init", "-q", "-b", "main")
	git("config", "user.name", "t")
	git("config", "user.email", "t@example.com")
	git("commit", "-q", "--allow-empty", "-m", "one")

	r, err := gitrepo.Open(dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("removing the clone: %v", err)
	}

	if _, err := r.Tags("HEAD"); err == nil || !strings.Contains(err.Error(), "checking clone depth") {
		t.Fatalf("Tags = %v, want the depth-probe refusal", err)
	}
}

// TestTagsRefusesARefThatIsNotOne: reachability is the question Tags
// asks, so a ref nothing can be measured from is a refusal — never the
// empty list a project that has never released gets.
func TestTagsRefusesARefThatIsNotOne(t *testing.T) {
	t.Parallel()

	fx := repo(t)

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	if _, err := r.Tags("refs/heads/no-such-branch"); err == nil ||
		!strings.Contains(err.Error(), "listing tags reachable from") {
		t.Fatalf("Tags = %v, want the listing refusal", err)
	}
}
