package gitrepo

import (
	"fmt"
	"strings"
	"time"
)

// The reads a version derivation needs: which releases exist, which
// commits landed since one, and what each of them said.
//
// Every one of them is a question about HISTORY, and history is the one
// thing a clone can be missing while looking complete. Truncated clones
// are the CI default rather than the unlucky case — GitHub's checkout
// action fetches depth 1 and no tags unless told otherwise, and other
// forges have their own version of the same setting. Such a clone
// answers "no releases yet, and one commit ever" for a repository with
// fifty tags, and nothing about that answer looks wrong. A derivation
// that trusts it starts from the wrong base and mints a version number
// that is already published, and published version numbers are
// immutable.
//
// So the shallow check is not a courtesy: it is the guard that makes
// every other read in this file meaningful, and it fires before them
// rather than beside them.

// ShallowError is returned when the repository cannot answer questions
// about its own history.
//
// The remedy is stated in git's own terms, not any one CI system's. What
// truncated the clone differs per forge — a depth setting, a mirror
// option, a cache — and naming one of them here would tell every other
// caller to change a setting they do not have. `git fetch` is the answer
// everywhere.
type ShallowError struct{ dir string }

func (e *ShallowError) Error() string {
	return fmt.Sprintf("gitrepo: %s is a shallow clone — it cannot be asked what has been released; "+
		"fetch the full history and tags first (git fetch --unshallow --tags)", e.dir)
}

// requireFullHistory refuses a repository whose history is truncated.
func (r *Repo) requireFullHistory() error {
	out, err := r.git("rev-parse", "--is-shallow-repository")
	if err != nil {
		return fmt.Errorf("gitrepo: checking clone depth: %w", err)
	}

	if strings.TrimSpace(string(out)) == "true" {
		return &ShallowError{dir: r.dir}
	}

	return nil
}

// Tags lists the tags REACHABLE FROM ref, unqualified — "v1.2.3", never
// "refs/tags/v1.2.3". Selecting a namespace out of them belongs to the
// caller that knows which component it is releasing.
//
// Reachability is not a refinement, it is the question. A repository
// maintaining 1.x after 2.0.0 shipped has v2.0.0 as its newest tag and
// v1.4.2 as the newest one on the branch being released; measuring the
// range from the newest tag ANYWHERE derives 2.0.1 from a 1.x branch and
// publishes it. The tag must be an ancestor of what is being released,
// or it describes a different line of history.
//
// A ref with no tags behind it returns an empty list and no error: a
// project that has never released is a fact, not a failure. That is
// exactly why the shallow guard runs first — without it, "no tags" would
// also be what a truncated fetch says.
func (r *Repo) Tags(ref string) ([]string, error) {
	if err := r.requireFullHistory(); err != nil {
		return nil, err
	}

	out, err := r.git("for-each-ref", "--merged="+ref, "--format=%(refname:strip=2)", "refs/tags")
	if err != nil {
		return nil, fmt.Errorf("gitrepo: listing tags reachable from %s: %w", ref, err)
	}

	var tags []string

	for line := range strings.Lines(string(out)) {
		if tag := strings.TrimSpace(line); tag != "" {
			tags = append(tags, tag)
		}
	}

	return tags, nil
}

// AllTags lists every tag in the repository, unqualified, reachability
// deliberately ignored.
//
// The opposite question from Tags, and the reason both exist: measuring
// a RANGE asks which release this line of history descends from, where
// a tag on another branch describes a different line; minting a NEW
// name asks which names the repository has already taken, where a tag
// on another branch has taken one just as firmly. A 1.x maintenance
// branch bases at v1.4.2 with v2.0.0 published elsewhere — reachability
// is right for the first question and blind for the second.
func (r *Repo) AllTags() ([]string, error) {
	if err := r.requireFullHistory(); err != nil {
		return nil, err
	}

	out, err := r.git("for-each-ref", "--format=%(refname:strip=2)", "refs/tags")
	if err != nil {
		return nil, fmt.Errorf("gitrepo: listing tags: %w", err)
	}

	var tags []string

	for line := range strings.Lines(string(out)) {
		if tag := strings.TrimSpace(line); tag != "" {
			tags = append(tags, tag)
		}
	}

	return tags, nil
}

// Message returns rev's full commit message — subject, body and
// trailers — as the author wrote it.
//
// %B and not %s: the subject alone loses the body, and a BREAKING CHANGE
// footer lives in the body. A reader given only subjects cannot see half
// of the two ways Conventional Commits declares a break.
func (r *Repo) Message(rev string) (string, error) {
	out, err := r.git("show", "-s", "--format=%B", rev+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("gitrepo: message of %s: %w", rev, err)
	}

	// git terminates the message with a newline of its own; the message
	// itself does not include it.
	return strings.TrimRight(string(out), "\n"), nil
}

// Commits lists the revisions reachable from `to` but not from `from`,
// oldest first — the range a release covers. An empty `from` means the
// whole history, which is the first release of a project that has never
// tagged.
//
// paths, when given, narrow the range to commits that touched them. In a
// repository releasing several components from one history this is not a
// convenience, it is the other half of the question: a tag namespace
// says WHICH component is being released, and the paths say which
// commits changed it. Without them every component in the monorepo
// derives the same version from the same commits, and a change to one
// crate raises the version of six others that nobody touched.
//
// Merges are NOT filtered out. A merge commit's subject is rarely
// conventional and will simply not parse, which the caller counts and
// reports; dropping them here would instead hide a break declared in a
// merge body, and hide it in the one place nobody would look.
//
// That guarantee needs stating twice because a pathspec quietly breaks
// it: rev-list's default history simplification drops TREESAME commits,
// and a merge is TREESAME to the parent it took the path's content from
// — so plain `rev-list <span> -- <paths>` loses every merge, and with
// them the one place a break hides. --full-history is what turns the
// simplification off, and it is passed exactly when a pathspec is.
func (r *Repo) Commits(from, to string, paths ...string) ([]string, error) {
	if err := r.requireFullHistory(); err != nil {
		return nil, err
	}

	span := to
	if from != "" {
		span = from + ".." + to
	}

	args := []string{"rev-list", "--reverse", span}
	if len(paths) > 0 {
		args = append(args, "--full-history", "--")
		args = append(args, paths...)
	}

	out, err := r.git(args...)
	if err != nil {
		return nil, fmt.Errorf("gitrepo: listing commits over %s: %w", span, err)
	}

	var revs []string

	for line := range strings.Lines(string(out)) {
		rev := strings.TrimSpace(line)
		if rev == "" {
			continue
		}

		if !revRE.MatchString(rev) {
			return nil, fmt.Errorf("gitrepo: rev-list over %s returned %q, not a revision", span, rev)
		}

		revs = append(revs, rev)
	}

	return revs, nil
}

// Revision is one revision as a property evaluator reads it: enough
// to judge the SHAPE of a history and nothing about its contents.
type Revision struct {
	// ID is the full revision identifier.
	ID string
	// Subject is the first line of the commit message.
	Subject string
	// Parents is how many parents the revision has — one for a
	// squashed or rebased commit, two or more for a merge.
	Parents int
	// Time is the commit time.
	Time time.Time
}

// Revisions lists ref's revisions from the tip back to the oldest one
// at or after since, newest first.
//
// The walk is first-parent, which is the branch's own line of
// development, but the PARENT COUNT is read from the full parent list:
// a merge commit must be visible AS a merge here, and a first-parent
// walk that also reported one parent per commit would hide exactly the
// property an evaluator is looking for.
func (r *Repo) Revisions(ref string, since time.Time) ([]Revision, error) {
	if err := r.requireFullHistory(); err != nil {
		return nil, err
	}

	const sep = "\x1f"

	out, err := r.git("log", "--first-parent", "--format=%H"+sep+"%P"+sep+"%cI"+sep+"%s", ref)
	if err != nil {
		return nil, fmt.Errorf("gitrepo: reading revisions of %s: %w", ref, err)
	}

	var revs []Revision

	for line := range strings.SplitSeq(strings.TrimRight(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}

		rev, perr := parseRevision(line, sep)
		if perr != nil {
			return nil, perr
		}

		// The log is newest first, so the first revision older than the
		// continuity start ends the window — everything beyond it is
		// outside the claim.
		if rev.Time.Before(since) {
			break
		}

		revs = append(revs, rev)
	}

	return revs, nil
}

// parseRevision reads one log line into a Revision.
func parseRevision(line, sep string) (Revision, error) {
	const fields = 4

	parts := strings.SplitN(line, sep, fields)
	if len(parts) != fields {
		return Revision{}, fmt.Errorf("gitrepo: revision line %q is not the requested format", line)
	}

	when, err := time.Parse(time.RFC3339, parts[2])
	if err != nil {
		return Revision{}, fmt.Errorf("gitrepo: revision %.12s commit time: %w", parts[0], err)
	}

	// A root commit has no parents, so the field is empty and Fields
	// reports zero — which is the true count, not a parse failure.
	return Revision{ID: parts[0], Subject: parts[3], Parents: len(strings.Fields(parts[1])), Time: when}, nil
}
