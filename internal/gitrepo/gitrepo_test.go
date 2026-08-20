package gitrepo_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gitrepo"
)

const notesRef = "refs/notes/commits"

// fixture is one built repository: its directory, the tip commit,
// and the root commit.
type fixture struct {
	dir, tip, root string
}

// repo builds a real repository: two commits on main, a note on the
// tip. Real git is the point — this package IS the git boundary, and
// faking git here would leave the actual seam untested.
func repo(t *testing.T) fixture {
	t.Helper()

	dir := t.TempDir()

	git := func(args ...string) string {
		t.Helper()

		cmd := exec.Command("git", //nolint:gosec,noctx // fixed executable, test-owned args
			append([]string{"-C", dir}, args...)...)
		cmd.Env = gitrepo.Env(
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		)

		var out bytes.Buffer

		cmd.Stdout = &out
		cmd.Stderr = &out

		if err := cmd.Run(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out.String())
		}

		return strings.TrimSpace(out.String())
	}

	git("init", "-q", "-b", "main")
	// The note committer identity is repo-local config by contract:
	// the caller prepares the clone, this package only writes.
	git("config", "user.name", "t")
	git("config", "user.email", "t@example.com")

	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}

	git("add", "f")
	git("commit", "-q", "-m", "one")
	root := git("rev-parse", "HEAD")

	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}

	git("add", "f")
	git("commit", "-q", "-m", "two")
	tip := git("rev-parse", "HEAD")

	git("notes", "add", "-m", `{"the":"note"}`, tip)

	return fixture{dir: dir, tip: tip, root: root}
}

// The ledger digest is SHA-256 over the note blob bytes exactly as
// git stores them — trailing newline included. The known answers are
// computed OUTSIDE this module (`printf '{"the":"note"}\n' |
// sha256sum`), because a golden value the implementation computes for
// itself lets both legs drift together: the canon's bash emitter and
// walker each hashed their own reading of the blob, a formatting pass
// rewrote one into command substitution (which strips the trailing
// newline), and every link emitted since points at bytes that exist
// nowhere (.github#434). The stripped-form digest is asserted as the
// named wrong answer so that exact regression has a face here.
const (
	noteRawSHA256      = "e5baf7a0b5edb3dfa1876c1ffdefe15c42fec3a9b941a70b0be5d0cbf2fc7843"
	noteStrippedSHA256 = "09a4e09c68a0c8fd0a304b99f34488f89af722dd639528d2ef938a83554e3b0f"
)

func TestNoteDigestKnownAnswer(t *testing.T) {
	t.Parallel()

	fx := repo(t)

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	note, err := r.Note(fx.tip)
	if err != nil {
		t.Fatalf("Note = %v", err)
	}

	got := fmt.Sprintf("%x", sha256.Sum256(note))
	if got == noteStrippedSHA256 {
		t.Fatalf("Note digest = %s — the newline-stripped form: a string round-trip ate the trailing newline (.github#434)",
			got)
	}

	if got != noteRawSHA256 {
		t.Fatalf("Note digest = %s, want %s (sha256 over the stored blob bytes, trailing newline included)",
			got, noteRawSHA256)
	}
}

func TestRepo(t *testing.T) {
	t.Parallel()

	fx := repo(t)

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	got, err := r.Tip("refs/heads/main")
	if err != nil || got != fx.tip {
		t.Errorf("Tip = %q, %v — want %q", got, err, fx.tip)
	}

	parent, err := r.Parent(fx.tip)
	if err != nil || parent != fx.root {
		t.Errorf("Parent(tip) = %q, %v — want %q", parent, err, fx.root)
	}

	atRoot, err := r.Parent(fx.root)
	if err != nil || atRoot != "" {
		t.Errorf(`Parent(root) = %q, %v — want "" at a root commit`, atRoot, err)
	}

	note, err := r.Note(fx.tip)
	if err != nil || string(note) != `{"the":"note"}`+"\n" {
		t.Errorf("Note(tip) = %q, %v — want the raw blob bytes", note, err)
	}

	absent, err := r.Note(fx.root)
	if err != nil || absent != nil {
		t.Errorf("Note(root) = %q, %v — want nil for an unannotated commit", absent, err)
	}

	noted, err := r.Noted()
	if err != nil || len(noted) != 1 || noted[0] != fx.tip {
		t.Errorf("Noted = %v, %v — want exactly the tip", noted, err)
	}
}

func TestRepoRefusals(t *testing.T) {
	t.Parallel()

	fx := repo(t)

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	t.Run("open on a non-repository", func(t *testing.T) {
		t.Parallel()

		if _, err := gitrepo.Open(t.TempDir(), notesRef); err == nil {
			t.Error("Open accepted a directory git does not recognise")
		}
	})

	t.Run("open with an unqualified notes ref", func(t *testing.T) {
		t.Parallel()

		if _, err := gitrepo.Open(fx.dir, "notes"); err == nil {
			t.Error("Open accepted an unqualified notes ref")
		}
	})

	t.Run("tip of a missing ref", func(t *testing.T) {
		t.Parallel()

		if _, err := r.Tip("refs/heads/absent"); err == nil {
			t.Error("Tip resolved a ref that does not exist")
		}
	})

	t.Run("parent of a garbage revision", func(t *testing.T) {
		t.Parallel()

		if _, err := r.Parent("0000000000000000000000000000000000000000"); err == nil {
			t.Error("Parent accepted a revision the object store does not hold")
		}
	})

	t.Run("note for a garbage revision", func(t *testing.T) {
		t.Parallel()

		if _, err := r.Note("not-a-revision"); err == nil {
			t.Error("Note accepted an implausible revision")
		}
	})

	t.Run("noted with no notes ref", func(t *testing.T) {
		t.Parallel()

		empty, err := gitrepo.Open(repo(t).dir, "refs/notes/absent")
		if err != nil {
			t.Fatalf("Open = %v", err)
		}

		noted, err := empty.Noted()
		if err != nil || noted != nil {
			t.Errorf("Noted = %v, %v — want empty for a repository with no ledger", noted, err)
		}
	})
}

// TestEmitSurface covers the write half: parents, commit time,
// ancestry, the note write (stripspace included — the read-back rule
// exists because stored bytes differ from written bytes), and the
// notes fetch/push pair against a real file-protocol remote,
// including the non-fast-forward rejection that is the append's
// compare-and-swap.
func TestEmitSurface(t *testing.T) {
	t.Parallel()

	fx := repo(t)

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	parents, err := r.Parents(fx.tip)
	if err != nil || len(parents) != 1 || parents[0] != fx.root {
		t.Errorf("Parents(tip) = %v, %v — want exactly the root", parents, err)
	}

	rootParents, err := r.Parents(fx.root)
	if err != nil || len(rootParents) != 0 {
		t.Errorf("Parents(root) = %v, %v — want none", rootParents, err)
	}

	if _, perr := r.Parents("0000000000000000000000000000000000000000"); perr == nil {
		t.Error("Parents accepted a revision the object store does not hold")
	}

	ct, err := r.CommitTime(fx.tip)
	if err != nil {
		t.Fatalf("CommitTime = %v", err)
	}

	if _, perr := time.Parse(time.RFC3339, ct); perr != nil {
		t.Errorf("CommitTime = %q, not strict ISO 8601: %v", ct, perr)
	}

	if _, cerr := r.CommitTime("not-a-revision"); cerr == nil {
		t.Error("CommitTime accepted an implausible revision")
	}

	ancestor, err := r.IsAncestor(fx.root, "refs/heads/main")
	if err != nil || !ancestor {
		t.Errorf("IsAncestor(root, main) = %v, %v — want true", ancestor, err)
	}
}

func TestIsAncestorFalseAndError(t *testing.T) {
	t.Parallel()

	fx := repo(t)

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	// A commit on a side branch is not an ancestor of main.
	git := gitCmd(t, fx.dir)
	git("checkout", "-q", "-b", "side", fx.root)

	if werr := os.WriteFile(filepath.Join(fx.dir, "s"), []byte("side"), 0o600); werr != nil {
		t.Fatal(werr)
	}

	git("add", "s")
	git("commit", "-q", "-m", "side")
	side := git("rev-parse", "HEAD")

	ancestor, err := r.IsAncestor(side, "refs/heads/main")
	if err != nil || ancestor {
		t.Errorf("IsAncestor(side, main) = %v, %v — want false without error", ancestor, err)
	}

	if _, aerr := r.IsAncestor("0000000000000000000000000000000000000000", "refs/heads/main"); aerr == nil {
		t.Error("IsAncestor accepted a revision the object store does not hold")
	}
}

// TestAddNoteStoresStripspaced pins the storage semantics the
// read-back rule exists for: `git notes add` normalises the blob, so
// the stored bytes are NOT the written bytes — writing without a
// trailing newline still stores one, and the digest of what Note
// returns is the raw known answer, never the stripped one.
func TestAddNoteStoresStripspaced(t *testing.T) {
	t.Parallel()

	fx := repo(t)

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	if aerr := r.AddNote(fx.root, []byte(`{"the":"note"}`)); aerr != nil { // no trailing newline on purpose
		t.Fatalf("AddNote = %v", aerr)
	}

	stored, err := r.Note(fx.root)
	if err != nil {
		t.Fatalf("Note = %v", err)
	}

	if string(stored) != `{"the":"note"}`+"\n" {
		t.Fatalf("stored note = %q — git's stripspace contract changed", stored)
	}

	if got := fmt.Sprintf("%x", sha256.Sum256(stored)); got != noteRawSHA256 {
		t.Errorf("stored digest = %s, want the raw known answer %s", got, noteRawSHA256)
	}

	if aerr := r.AddNote("not-a-revision", []byte("x")); aerr == nil {
		t.Error("AddNote accepted an implausible revision")
	}
}

// TestCloneMaterializesTheScratchTree pins the fix for the org-wide
// source-attest outage at the canon v1.41.0 cutover: --clone owns the
// whole scratch-tree lifecycle, so Clone must create the directory
// itself — every command here runs `git -C dir`, which chdirs before
// init could create anything, and the caller pre-creating the path is
// exactly the restated preparation --clone removed from the action.
func TestCloneMaterializesTheScratchTree(t *testing.T) {
	t.Parallel()

	fx := repo(t)
	remoteDir := t.TempDir()
	remote := gitCmd(t, remoteDir)
	remote("init", "-q", "--bare")

	local := gitCmd(t, fx.dir)
	local("remote", "add", "origin", remoteDir)
	local("push", "-q", "origin", "main")
	local("notes", "add", "-f", "-m", `{"seed":"note"}`, "HEAD")
	local("push", "-q", "origin", notesRef+":"+notesRef)

	// The scratch path does not exist — not even its parent.
	scratch := filepath.Join(t.TempDir(), "work", "repo")

	r, err := gitrepo.Clone(scratch, remoteDir, "",
		"source-attest", "source-attest@example.invalid",
		"refs/heads/main", notesRef)
	if err != nil {
		t.Fatalf("Clone into a nonexistent path = %v", err)
	}

	git := gitCmd(t, scratch)
	for _, ref := range []string{"refs/heads/main", notesRef} {
		if got := git("rev-parse", "--verify", ref); got == "" {
			t.Errorf("Clone did not fetch %s", ref)
		}
	}

	if err := r.SetNotesRef(notesRef); err != nil {
		t.Fatalf("SetNotesRef = %v", err)
	}
}

// TestCloneOfAnUnfoundedChain pins the genesis half of the fetch
// split: a remote WITHOUT the ledger ref is a repository whose chain
// has not been founded yet — data the engine judges, never a fetch
// failure. A strict fetch over both refs hard-fails here, which
// would make genesis-with---clone impossible on every fresh repo.
func TestCloneOfAnUnfoundedChain(t *testing.T) {
	t.Parallel()

	fx := repo(t)
	remoteDir := t.TempDir()
	remote := gitCmd(t, remoteDir)
	remote("init", "-q", "--bare")

	local := gitCmd(t, fx.dir)
	local("remote", "add", "origin", remoteDir)
	local("push", "-q", "origin", "main")
	// Deliberately NO notes push: the ledger does not exist yet.

	scratch := filepath.Join(t.TempDir(), "repo")

	r, err := gitrepo.Clone(scratch, remoteDir, "",
		"source-attest", "source-attest@example.invalid",
		"refs/heads/main", notesRef)
	if err != nil {
		t.Fatalf("Clone of an unfounded chain = %v, want the empty-ledger success", err)
	}

	if serr := r.SetNotesRef(notesRef); serr != nil {
		t.Fatalf("SetNotesRef = %v", serr)
	}

	noted, nerr := r.Noted()
	if nerr != nil || noted != nil {
		t.Fatalf("Noted = %v, %v — want the empty ledger", noted, nerr)
	}

	// The branch fetch stays strict: a branch the remote does not
	// have is an error in its own right, never an empty anything.
	if _, err := gitrepo.Clone(filepath.Join(t.TempDir(), "repo"), remoteDir, "",
		"source-attest", "source-attest@example.invalid",
		"refs/heads/absent", notesRef); err == nil {
		t.Fatal("Clone fetched a branch the remote does not have")
	}
}

// TestCloneRefusals: every argument guard, one row each — a clone
// that cannot say who it writes as or what it brings down is refused
// before anything touches the filesystem.
func TestCloneRefusals(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, remote, committer, email, branch, notes, want string
	}{
		{"no remote", "", "n", "e", "refs/heads/main", "refs/notes/x", "a remote is required"},
		{"no committer", "r", "", "e", "refs/heads/main", "refs/notes/x", "committer name and email"},
		{"no email", "r", "n", "", "refs/heads/main", "refs/notes/x", "committer name and email"},
		{"unqualified branch", "r", "n", "e", "main", "refs/notes/x", "not fully qualified"},
		{"unqualified notes ref", "r", "n", "e", "refs/heads/main", "commits", "not fully qualified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := gitrepo.Clone(filepath.Join(t.TempDir(), "repo"),
				tc.remote, "", tc.committer, tc.email, tc.branch, tc.notes)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Clone = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestCloneRefusalsThatNeedARemote: the refusals above are answered
// before anything is created, so they never reach the scratch tree.
// These do, and each is a different failure the clone must not confuse
// with the one thing it is allowed to shrug at — a ledger the remote
// simply does not have yet.
func TestCloneRefusalsThatNeedARemote(t *testing.T) {
	t.Parallel()

	t.Run("a scratch path that cannot be created", func(t *testing.T) {
		t.Parallel()

		// A file where the scratch tree's parent belongs.
		blocked := filepath.Join(t.TempDir(), "occupied")
		if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}

		_, err := gitrepo.Clone(filepath.Join(blocked, "repo"),
			"file:///nowhere", "", "n", "e@x", "refs/heads/main", "refs/notes/commits")
		if err == nil || !strings.Contains(err.Error(), "scratch dir") {
			t.Fatalf("Clone = %v, want the scratch-dir refusal", err)
		}
	})

	t.Run("a remote that is not there", func(t *testing.T) {
		t.Parallel()

		_, err := gitrepo.Clone(filepath.Join(t.TempDir(), "repo"),
			"file://"+filepath.Join(t.TempDir(), "absent"), "", "n", "e@x",
			"refs/heads/main", "refs/notes/commits")
		if err == nil || !strings.Contains(err.Error(), "fetching refs/heads/main") {
			t.Fatalf("Clone = %v, want the branch fetch to refuse by name", err)
		}
	})

	t.Run("a branch the remote does not have", func(t *testing.T) {
		t.Parallel()

		// The branch fetch is strict on purpose: a branch that is not
		// there is an error in its own right, never an empty history.
		remote := t.TempDir()
		git := gitCmd(t, remote)
		git("init", "-q", "--bare")

		_, err := gitrepo.Clone(filepath.Join(t.TempDir(), "repo"),
			"file://"+remote, "", "n", "e@x", "refs/heads/absent", "refs/notes/commits")
		if err == nil || !strings.Contains(err.Error(), "fetching refs/heads/absent") {
			t.Fatalf("Clone = %v, want a refusal naming the branch", err)
		}
	})
}

// TestSetNotesRefRefusesAnUnqualifiedRef: a bare "commits" is not a
// ref, and binding one would write the ledger to a name git resolves
// somewhere else entirely.
func TestSetNotesRefRefusesAnUnqualifiedRef(t *testing.T) {
	t.Parallel()

	fx := repo(t)

	r, err := gitrepo.Open(fx.dir, "refs/notes/commits")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := r.SetNotesRef("commits"); err == nil {
		t.Fatal("SetNotesRef accepted an unqualified ref")
	}

	if err := r.SetNotesRef("refs/notes/commits"); err != nil {
		t.Fatalf("SetNotesRef(qualified) = %v", err)
	}
}

func TestNotesPushAndFetch(t *testing.T) {
	t.Parallel()

	fx := repo(t)
	remoteDir := t.TempDir()
	git := gitCmd(t, remoteDir)
	git("init", "-q", "--bare")

	local := gitCmd(t, fx.dir)
	local("remote", "add", "origin", remoteDir)
	local("push", "-q", "origin", "main")

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	if err := r.PushNotes("origin", ""); err != nil {
		t.Fatalf("PushNotes = %v", err)
	}

	// A second clone moves the remote notes ref; the stale first
	// clone's push must be REJECTED (the compare-and-swap), and after
	// a fetch it fast-forwards.
	otherDir := t.TempDir()
	other := gitCmd(t, otherDir)
	other("clone", "-q", "-b", "main", remoteDir, ".")
	other("fetch", "-q", "origin", "+"+notesRef+":"+notesRef)
	other("notes", "add", "-f", "-m", `{"other":"note"}`, "HEAD~1")
	other("push", "-q", "origin", notesRef+":"+notesRef)

	if err := r.AddNote(fx.tip, []byte(`{"mine":"note"}`)); err != nil {
		t.Fatalf("AddNote = %v", err)
	}

	if err := r.PushNotes("origin", ""); err == nil {
		t.Fatal("PushNotes fast-forwarded over a moved remote — the compare-and-swap is gone")
	}

	if err := r.FetchNotes("origin", ""); err != nil {
		t.Fatalf("FetchNotes = %v", err)
	}

	if err := r.AddNote(fx.tip, []byte(`{"mine":"note"}`)); err != nil {
		t.Fatalf("AddNote after fetch = %v", err)
	}

	if err := r.PushNotes("origin", ""); err != nil {
		t.Fatalf("PushNotes after fetch = %v", err)
	}
}

// gitCmd is the fixture runner rebound to any directory.
func gitCmd(t *testing.T, dir string) func(args ...string) string {
	t.Helper()

	return func(args ...string) string {
		t.Helper()

		cmd := exec.Command("git", //nolint:gosec,noctx // fixed executable, test-owned args
			append([]string{"-C", dir}, args...)...)
		cmd.Env = gitrepo.Env(
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		)

		var out bytes.Buffer

		cmd.Stdout = &out
		cmd.Stderr = &out

		if err := cmd.Run(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out.String())
		}

		return strings.TrimSpace(out.String())
	}
}

// TestPreflightProofs pins the two engine preflight primitives: the
// committer identity probe, and the push proof — which must actually
// prove something (a throwaway note advances the ref so the dry-run
// exercises auth and fast-forward), never move the remote, and
// restore the local ref exactly.
func TestPreflightProofs(t *testing.T) {
	t.Parallel()

	fx := repo(t)
	remoteDir := t.TempDir()
	remote := gitCmd(t, remoteDir)
	remote("init", "-q", "--bare")

	local := gitCmd(t, fx.dir)
	local("remote", "add", "origin", remoteDir)
	local("push", "-q", "origin", "main")

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	if cerr := r.CommitterIdent(); cerr != nil {
		t.Fatalf("CommitterIdent = %v", cerr)
	}

	if aerr := r.AddNote(fx.root, []byte(`{"seed":"note"}`)); aerr != nil {
		t.Fatalf("AddNote = %v", aerr)
	}

	if perr := r.PushNotes("origin", ""); perr != nil {
		t.Fatalf("PushNotes = %v", perr)
	}

	before := local("rev-parse", notesRef)

	if derr := r.DryRunPushNotes("origin", "", fx.tip); derr != nil {
		t.Fatalf("DryRunPushNotes = %v", derr)
	}

	if after := local("rev-parse", notesRef); after != before {
		t.Fatalf("the push proof left the local ref moved: %s → %s", before, after)
	}

	remoteRef := remote("rev-parse", notesRef)
	if remoteRef != before {
		t.Fatalf("the push proof moved the REMOTE: %s, want %s", remoteRef, before)
	}

	// A remote that moved underneath the run rejects the proof — the
	// same compare-and-swap posture as the real push.
	otherDir := t.TempDir()
	other := gitCmd(t, otherDir)
	other("clone", "-q", "-b", "main", remoteDir, ".")
	other("fetch", "-q", "origin", "+"+notesRef+":"+notesRef)
	other("notes", "add", "-f", "-m", `{"other":"note"}`, "HEAD~1")
	other("push", "-q", "origin", notesRef+":"+notesRef)

	if derr := r.DryRunPushNotes("origin", "", fx.tip); derr == nil {
		t.Fatal("the push proof fast-forwarded over a moved remote")
	}

	// With no notes ref at all there is nothing to prove against.
	if bare, oerr := gitrepo.Open(t.TempDir(), notesRef); oerr == nil {
		if perr := bare.DryRunPushNotes("origin", "", fx.tip); perr == nil {
			t.Fatal("a repository with no notes ref proved a push")
		}
	}
}

// TestEnvScrubsRepoLocators pins the hook-safety guarantee: every
// environment variable through which git resolves a repository
// independently of `-C dir` is removed, one table row per variable.
// A git hook exports GIT_DIR, and the belt's pre-push runs this
// suite — an inherited locator silently redirects every fixture
// command into the REAL repository (observed live: fixture commits
// landing on a work branch during push, stele#101's PR).
func TestEnvScrubsRepoLocators(t *testing.T) {
	locators := []string{
		"GIT_DIR",
		"GIT_WORK_TREE",
		"GIT_INDEX_FILE",
		"GIT_OBJECT_DIRECTORY",
		"GIT_ALTERNATE_OBJECT_DIRECTORIES",
		"GIT_COMMON_DIR",
		"GIT_NAMESPACE",
		"GIT_PREFIX",
	}

	for _, name := range locators {
		t.Run(name, func(t *testing.T) { //nolint:paralleltest // t.Setenv forbids parallel
			t.Setenv(name, "/decoy")

			for _, kv := range gitrepo.Env() {
				if strings.HasPrefix(kv, name+"=") {
					t.Fatalf("Env() carries %s — a hook's repository would hijack -C", kv)
				}
			}
		})
	}
}

// TestEnvExtrasAndPins proves the config pins survive and extras
// append after them, so a caller's override wins.
func TestEnvExtrasAndPins(t *testing.T) {
	t.Parallel()

	env := gitrepo.Env("GIT_AUTHOR_NAME=t")

	for _, want := range []string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_AUTHOR_NAME=t"} {
		if !slices.Contains(env, want) {
			t.Errorf("Env() lacks %s", want)
		}
	}
}

// TestEnvHookedGitStaysInDir is the behavioural half: with GIT_DIR
// pointing at a decoy repository (a hook's environment), a fixture
// git still operates on the -C directory and the decoy stays empty.
func TestEnvHookedGitStaysInDir(t *testing.T) { //nolint:paralleltest // t.Setenv forbids parallel
	decoy := t.TempDir()
	fx := repo(t)

	t.Setenv("GIT_DIR", filepath.Join(decoy, ".git"))

	git := gitCmd(t, fx.dir)
	git("commit", "-q", "--allow-empty", "-m", "chore: stay home")

	tip := strings.TrimSpace(git("rev-parse", "HEAD"))
	if strings.TrimSpace(git("log", "-1", "--format=%s")) != "chore: stay home" || tip == fx.tip {
		t.Fatal("the commit did not land in the -C repository")
	}

	if _, err := os.Stat(filepath.Join(decoy, ".git")); err == nil {
		t.Fatal("the decoy GIT_DIR was written — the hook's repository would have been vandalised")
	}
}
