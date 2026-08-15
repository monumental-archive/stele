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
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

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

// git runs one subcommand against the repository with a hermetic
// environment: no user config, no system config — a verifier's read
// of the object store must not vary with the operator's dotfiles.
func (r *Repo) git(args ...string) ([]byte, error) {
	full := append([]string{"-C", r.dir}, args...)

	// The argument vector is built from validated inputs and this
	// package's own literals; git is the fixed executable. gosec's
	// G204 fires on any variable argv — the rule is doing its job,
	// and this is the reviewed exception.
	//nolint:gosec,noctx // fixed executable, validated args; local read, no cancellation surface
	cmd := exec.Command("git", full...)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	)

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}

	return stdout.Bytes(), nil
}
