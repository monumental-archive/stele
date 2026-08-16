package gitrepo

import (
	"fmt"
	"strings"
)

// The reads a version derivation needs: which releases exist, which
// commits landed since one, and what each of them said.
//
// Every one of them is a question about HISTORY, and history is the one
// thing a clone can be missing while looking complete. `actions/checkout`
// defaults to `fetch-depth: 1` and fetches no tags at all — so the
// common CI checkout answers "no releases yet, and one commit ever" for
// a repository with fifty tags. Nothing about that answer looks wrong.
// A derivation that trusts it starts from the wrong base and mints a
// version number that is already published, and published version
// numbers are immutable.
//
// So the shallow check is not a courtesy: it is the guard that makes
// every other read in this file meaningful, and it fires before them
// rather than beside them.

// ShallowError is returned when the repository cannot answer questions
// about its own history. The remedy belongs in the message because the
// caller is nearly always a workflow author who has to change one line
// of YAML.
type ShallowError struct{ dir string }

func (e *ShallowError) Error() string {
	return fmt.Sprintf("gitrepo: %s is a shallow clone — it cannot be asked what has been released "+
		"(checkout with fetch-depth: 0 and fetch-tags: true)", e.dir)
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

// Tags lists every tag name in the repository, unqualified — "v1.2.3",
// never "refs/tags/v1.2.3". Selecting a namespace out of them belongs to
// the caller that knows which component it is releasing.
//
// A repository with no tags returns an empty list and no error: a
// project that has never released is a fact, not a failure. That is
// exactly why the shallow guard runs first — without it, "no tags" would
// also be what a truncated fetch says.
func (r *Repo) Tags() ([]string, error) {
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
// Merges are NOT filtered out. A merge commit's subject is rarely
// conventional and will simply not parse, which the caller counts and
// reports; dropping them here would instead hide a break declared in a
// merge body, and hide it in the one place nobody would look.
func (r *Repo) Commits(from, to string) ([]string, error) {
	if err := r.requireFullHistory(); err != nil {
		return nil, err
	}

	span := to
	if from != "" {
		span = from + ".." + to
	}

	out, err := r.git("rev-list", "--reverse", span)
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
