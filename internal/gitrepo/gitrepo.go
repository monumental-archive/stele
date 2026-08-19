// Package gitrepo implements the verify engine's History over a
// local git directory by shelling out to git — the one tool that
// already owns the object store, in a repository the CALLER fetched:
// which refs exist locally is orchestration (the workflow's fetch,
// the audit's clone), and this package refuses to network on its
// own. Note bytes come from cat-file on the note blob, never from
// `git notes show`, because the ledger's noteSha256 covers the blob
// exactly as stored.
package gitrepo

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// repoLocators are the environment variables through which git
// resolves a repository INDEPENDENTLY of `-C dir` — GIT_DIR and its
// companions override the directory argument outright. A git hook
// exports GIT_DIR, so a child git spawned under a hook (the belt's
// pre-push runs this package's tests) would silently operate on the
// hook's repository, not the directory it was pointed at. Every git
// this package or its tests spawn scrubs them via Env; nothing else
// builds a git environment.
func repoLocators() []string {
	return []string{
		"GIT_DIR=",
		"GIT_WORK_TREE=",
		"GIT_INDEX_FILE=",
		"GIT_OBJECT_DIRECTORY=",
		"GIT_ALTERNATE_OBJECT_DIRECTORIES=",
		"GIT_COMMON_DIR=",
		"GIT_NAMESPACE=",
		"GIT_PREFIX=",
	}
}

// Env renders the environment for a spawned git: the process
// environment minus every repo-locating GIT_* variable (so `-C dir`
// is the ONE way a child git finds its repository), with global and
// system config pinned to /dev/null, plus the caller's extras.
func Env(extra ...string) []string {
	out := make([]string, 0, len(os.Environ())+2+len(extra))

	for _, kv := range os.Environ() {
		scrubbed := false

		for _, loc := range repoLocators() {
			if strings.HasPrefix(kv, loc) {
				scrubbed = true

				break
			}
		}

		if !scrubbed {
			out = append(out, kv)
		}
	}

	out = append(out, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")

	return append(out, extra...)
}

// Repo is one local git directory and the notes ref chain links
// live under.
type Repo struct {
	dir      string
	notesRef string
}

var revRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Open validates that dir is a git repository and returns a Repo
// reading notes from notesRef. It refuses a directory git does not
// recognise — a walk over nothing must not report an empty chain.
func Open(dir, notesRef string) (*Repo, error) {
	if !strings.HasPrefix(notesRef, "refs/") {
		return nil, fmt.Errorf("gitrepo: notes ref %q is not fully qualified", notesRef)
	}

	r := &Repo{dir: dir, notesRef: notesRef}
	if _, err := r.git("rev-parse", "--git-dir"); err != nil {
		return nil, fmt.Errorf("gitrepo: %s is not a git repository: %w", dir, err)
	}

	return r, nil
}

// Tip resolves a fully qualified ref to its commit.
func (r *Repo) Tip(ref string) (string, error) {
	out, err := r.git("rev-parse", "--verify", ref+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("gitrepo: resolve %s: %w", ref, err)
	}

	rev := strings.TrimSpace(string(out))
	if !revRE.MatchString(rev) {
		return "", fmt.Errorf("gitrepo: %s resolved to %q, not a commit", ref, rev)
	}

	return rev, nil
}

// Parent returns the first parent, or "" at a root commit — read
// from rev-list so an object-store error and a root are different
// answers.
func (r *Repo) Parent(rev string) (string, error) {
	out, err := r.git("rev-list", "--parents", "-n1", rev)
	if err != nil {
		return "", fmt.Errorf("gitrepo: parents of %s: %w", rev, err)
	}

	fields := strings.Fields(string(out))
	if len(fields) == 0 || fields[0] != rev {
		return "", fmt.Errorf("gitrepo: rev-list for %s returned %q", rev, out)
	}

	// One field is the commit alone: a root. The second field, when
	// present, is the first parent — rev-list's documented layout.
	if len(fields) == 1 {
		return "", nil
	}

	return fields[1], nil
}

// Note returns the raw note blob bytes for rev, or nil when no note
// exists there. The blob is read with cat-file so the bytes hashed
// are the bytes stored — `notes show` output is close but not
// contractually identical.
func (r *Repo) Note(rev string) ([]byte, error) {
	out, err := r.git("notes", "--ref", r.notesRef, "list", rev)
	if err != nil {
		// `notes list <obj>` exits 1 with "no note found" — absence,
		// not failure. Anything else is a real error.
		if strings.Contains(err.Error(), "no note found") {
			return nil, nil
		}

		return nil, fmt.Errorf("gitrepo: notes list %s: %w", rev, err)
	}

	blob := strings.TrimSpace(string(out))
	if !revRE.MatchString(blob) {
		return nil, fmt.Errorf("gitrepo: notes list %s returned %q, not a blob id", rev, blob)
	}

	note, err := r.git("cat-file", "blob", blob)
	if err != nil {
		return nil, fmt.Errorf("gitrepo: cat-file %s: %w", blob, err)
	}

	return note, nil
}

// Noted lists every revision carrying a note under the notes ref.
// A repository with no notes ref at all has an empty ledger, which
// the engine judges — absence here is data, not an error.
func (r *Repo) Noted() ([]string, error) {
	// The ref not existing is absence-of-ledger, not failure — the
	// deliberate nil-on-error the engine's members walk expects.
	if _, err := r.git("rev-parse", "--verify", "--quiet", r.notesRef); err != nil {
		return nil, nil //nolint:nilerr // an absent notes ref is an empty ledger, judged by the engine
	}

	out, err := r.git("notes", "--ref", r.notesRef, "list")
	if err != nil {
		return nil, fmt.Errorf("gitrepo: notes list: %w", err)
	}

	var revs []string

	for line := range strings.Lines(string(out)) {
		// `notes list` prints "<note blob> <annotated object>".
		const listColumns = 2

		fields := strings.Fields(line)
		if len(fields) != listColumns {
			continue
		}

		revs = append(revs, fields[1])
	}

	return revs, nil
}

// IsAncestor reports whether rev is an ancestor of (or equal to) the
// commit ref names. git's exit status 1 is the false answer; any
// other failure is a real error, kept distinct so an object-store
// problem can never read as "not on the branch".
func (r *Repo) IsAncestor(rev, ref string) (bool, error) {
	_, err := r.git("merge-base", "--is-ancestor", rev, ref)
	if err == nil {
		return true, nil
	}

	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false, nil
	}

	return false, fmt.Errorf("gitrepo: ancestry of %s in %s: %w", rev, ref, err)
}

// Parents returns every parent of rev, first-parent first — the
// provenance predicate records full ancestry, not just the walk edge.
func (r *Repo) Parents(rev string) ([]string, error) {
	out, err := r.git("rev-list", "--parents", "-n1", rev)
	if err != nil {
		return nil, fmt.Errorf("gitrepo: parents of %s: %w", rev, err)
	}

	fields := strings.Fields(string(out))
	if len(fields) == 0 || fields[0] != rev {
		return nil, fmt.Errorf("gitrepo: rev-list for %s returned %q", rev, out)
	}

	return fields[1:], nil
}

// CommitTime returns rev's committer time in strict ISO 8601 — the
// contemporaneity fact the provenance records.
func (r *Repo) CommitTime(rev string) (string, error) {
	out, err := r.git("show", "-s", "--format=%cI", rev+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("gitrepo: commit time of %s: %w", rev, err)
	}

	return strings.TrimSpace(string(out)), nil
}

// AddNote writes note bytes as rev's note, replacing any existing
// one. The bytes STORED are whatever git keeps (`notes add` applies
// stripspace: a trailing newline is normalised on) — which is exactly
// why callers must never hash what they passed in here, only what
// Note reads back out of the object store (.github#434 rule 2). The
// committer identity comes from the repository's local config: who
// signs the ledger commit is the caller's storage contract, not this
// package's.
func (r *Repo) AddNote(rev string, note []byte) error {
	if _, err := r.gitIn(note, "notes", "--ref", r.notesRef, "add", "-f", "-F", "-", rev); err != nil {
		return fmt.Errorf("gitrepo: notes add %s: %w", rev, err)
	}

	return nil
}

// CommitterIdent proves a usable committer identity exists in the
// repository's local config — the storage contract chain links are
// committed under. Named refusal, not a bare exit 128 downstream.
func (r *Repo) CommitterIdent() error {
	if _, err := r.git("var", "GIT_COMMITTER_IDENT"); err != nil {
		return fmt.Errorf("gitrepo: no usable committer identity in the repository config: %w", err)
	}

	return nil
}

// DryRunPushNotes proves the notes push CAN land before anything
// irreversible happens (the #236 contract): a dry-run of an unchanged
// ref is "Everything up-to-date" and proves nothing, so a throwaway
// note is added first (exercising the committer identity on the exact
// code path AddNote uses), the advanced ref is dry-run pushed
// (exercising auth and fast-forward server-side), and the ref is
// restored. --dry-run never updates the remote.
func (r *Repo) DryRunPushNotes(remote, token, rev string) error {
	orig, err := r.git("rev-parse", r.notesRef)
	if err != nil {
		return fmt.Errorf("gitrepo: %s is absent — nothing to prove a push against: %w", r.notesRef, err)
	}

	if _, err := r.gitIn([]byte("stele preflight — never pushed"),
		"notes", "--ref", r.notesRef, "add", "-f", "-F", "-", rev); err != nil {
		return fmt.Errorf("gitrepo: could not annotate %s for the push proof: %w", rev, err)
	}

	_, pushErr := r.gitAuth(token, "push", "-q", "--dry-run", remote, r.notesRef+":"+r.notesRef)

	if _, rerr := r.git("update-ref", r.notesRef, strings.TrimSpace(string(orig))); rerr != nil {
		return fmt.Errorf("gitrepo: restoring %s after the push proof: %w", r.notesRef, rerr)
	}

	if pushErr != nil {
		return fmt.Errorf("gitrepo: notes push dry-run rejected — the token cannot write %s or the ref moved: %w",
			r.notesRef, pushErr)
	}

	return nil
}

// FetchNotes force-updates the local notes ref from the remote — the
// refetch half of the append's compare-and-swap loop.
func (r *Repo) FetchNotes(remote, token string) error {
	if _, err := r.gitAuth(token, "fetch", "-q", remote, "+"+r.notesRef+":"+r.notesRef); err != nil {
		return fmt.Errorf("gitrepo: fetch %s: %w", r.notesRef, err)
	}

	return nil
}

// PushNotes pushes the local notes ref to the remote WITHOUT force —
// the fast-forward requirement is the compare-and-swap: a push that
// lands proves the predecessor this run hashed was still the tail.
func (r *Repo) PushNotes(remote, token string) error {
	if _, err := r.gitAuth(token, "push", "-q", remote, r.notesRef+":"+r.notesRef); err != nil {
		return fmt.Errorf("gitrepo: push %s: %w", r.notesRef, err)
	}

	return nil
}

// Clone prepares a scratch repository at dir and fetches exactly
// the refs named, from remote, under the committer identity given.
//
// This exists so the refs a run needs are derived from the POLICY
// that names them rather than restated by whoever prepared the tree.
// A caller that hardcodes a notes ref in a fetch refspec has written
// a second copy of a value the engine already reads, and the two go
// out of step silently: the emitter looks for a ledger the fetch
// never brought down, and founds a new chain instead of extending
// one.
//
// The identity is a parameter for the same reason it is not a
// default. Every note this run writes lands in a world-readable
// ledger permanently, so who authored it is a decision, and a
// scratch tree has no ambient identity to inherit.
//
// Networking is never implicit: this is the one entry point that
// reaches a remote, and a run that does not call it does not network.
func Clone(dir, remote, token, name, email string, refs ...string) (*Repo, error) {
	switch {
	case remote == "":
		return nil, errors.New("gitrepo: a remote is required to clone")
	case name == "" || email == "":
		return nil, errors.New("gitrepo: a committer name and email are required — every note this writes" +
			" carries its author into a permanent ledger")
	case len(refs) == 0:
		return nil, errors.New("gitrepo: no refs to fetch — a clone that brings nothing down is not a clone")
	}

	// The scratch repository is the engine's to materialize: every
	// command this package runs is `git -C dir`, which chdirs before
	// init could create anything, and a caller-made directory would be
	// the same restated preparation --clone exists to remove. It is
	// BARE because nothing here reads a checkout — every read is
	// plumbing against the object store — and with no checked-out
	// branch, git's refusal to fetch into the current branch has
	// nothing to collide with, whatever the policy names.
	// Group-traversable, world-closed — the same posture as every
	// directory this module creates.
	const scratchDirPerm = 0o750

	if err := os.MkdirAll(dir, scratchDirPerm); err != nil {
		return nil, fmt.Errorf("gitrepo: creating scratch dir %s: %w", dir, err)
	}

	r := &Repo{dir: dir}
	if _, err := r.git("init", "-q", "--bare", dir); err != nil {
		return nil, fmt.Errorf("gitrepo: init %s: %w", dir, err)
	}

	for _, cfg := range [][2]string{{"user.name", name}, {"user.email", email}} {
		if _, err := r.git("config", cfg[0], cfg[1]); err != nil {
			return nil, fmt.Errorf("gitrepo: config %s: %w", cfg[0], err)
		}
	}

	// Forced refspecs: the scratch tree is disposable, so a fetch that
	// would not fast-forward is not a conflict to resolve but a stale
	// local ref to overwrite.
	// fetch, -q and the remote precede one refspec per ref.
	const fetchArgc = 3

	spec := make([]string, 0, len(refs)+fetchArgc)
	spec = append(spec, "fetch", "-q", remote)

	for _, ref := range refs {
		if !strings.HasPrefix(ref, "refs/") {
			return nil, fmt.Errorf("gitrepo: fetch ref %q is not fully qualified", ref)
		}

		spec = append(spec, "+"+ref+":"+ref)
	}

	if _, err := r.gitAuth(token, spec...); err != nil {
		return nil, fmt.Errorf("gitrepo: fetching %v from %s: %w", refs, remote, err)
	}

	return r, nil
}

// SetNotesRef binds a prepared repository to the ledger it will read
// and write. Separate from Clone because the fetch is orchestration
// and the ledger is policy; a caller that fetched by hand still names
// the ref once.
func (r *Repo) SetNotesRef(notesRef string) error {
	if !strings.HasPrefix(notesRef, "refs/") {
		return fmt.Errorf("gitrepo: notes ref %q is not fully qualified", notesRef)
	}

	r.notesRef = notesRef

	return nil
}

// gitAuth runs one network subcommand, attaching the token as a basic
// auth header when one is given — the same header shape GitHub's own
// checkout uses; anonymous when empty (file-protocol remotes, tests).
func (r *Repo) gitAuth(token string, args ...string) ([]byte, error) {
	if token == "" {
		return r.git(args...)
	}

	header := "AUTHORIZATION: basic " +
		base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))

	return r.git(append([]string{"-c", "http.extraheader=" + header}, args...)...)
}

// git runs one subcommand against the repository with a hermetic
// environment: no user config, no system config — a verifier's read
// of the object store must not vary with the operator's dotfiles.
func (r *Repo) git(args ...string) ([]byte, error) {
	return r.gitIn(nil, args...)
}

// gitIn is git with bytes on stdin — how note content reaches
// `notes add -F -` without ever transiting a string variable that
// could normalise it.
func (r *Repo) gitIn(stdin []byte, args ...string) ([]byte, error) {
	full := append([]string{"-C", r.dir}, args...)

	// The argument vector is built from validated inputs and this
	// package's own literals; git is the fixed executable. gosec's
	// G204 fires on any variable argv — the rule is doing its job,
	// and this is the reviewed exception.
	//nolint:gosec,noctx // fixed executable, validated args; local read, no cancellation surface
	cmd := exec.Command("git", full...)
	cmd.Env = Env()

	var stdout, stderr bytes.Buffer

	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}

	return stdout.Bytes(), nil
}
