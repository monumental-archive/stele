package workflow

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// commitRE is the platform's spelling of a pin by commit: the full
// object name, lowercase hex. A short name, a tag or a branch moves or
// may move, and a reference that may move pins nothing.
var commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Call is one job-level `uses:` that reaches a named reusable
// workflow: the file and job it was read from, and the reference as
// the platform parses it.
type Call struct {
	File string
	Job  string
	Ref  Ref
}

// CallsTo lists every job-level call in files to target — a remote
// reusable workflow spelled owner/repo/path, the platform's grammar —
// in file order, then document order within each file.
//
// Read through Parse and ParseRef, never a pattern over the bytes: a
// comment naming the target, a step's `uses:` and a string inside a
// `run:` block are not calls, and a pattern sees all three. Owner and
// repository compare without case, because the platform resolves
// them that way; the path compares exactly, because it is a path.
//
// A file this reader cannot understand refuses by name, and so does
// a job-level `uses:` it cannot parse: the platform runs neither, and
// a tree whose calls cannot be read is not a tree that makes none.
func CallsTo(files []File, target string) ([]Call, error) {
	want, err := ParseRef(target + "@x")
	if err != nil || want.Local {
		return nil, fmt.Errorf("workflow: %q is not owner/repo/path", target)
	}

	var calls []Call

	for _, f := range files {
		doc, err := Parse(f.Content)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}

		for _, job := range doc.Jobs {
			if job.Uses == "" {
				continue
			}

			ref, err := ParseRef(job.Uses)
			if err != nil {
				return nil, fmt.Errorf("%s: jobs.%s.uses: %w", f.Name, job.Name, err)
			}

			if ref.Local || !strings.EqualFold(ref.Owner, want.Owner) ||
				!strings.EqualFold(ref.Repo, want.Repo) || ref.Path != want.Path {
				continue
			}

			calls = append(calls, Call{File: f.Name, Job: job.Name, Ref: ref})
		}
	}

	return calls, nil
}

// PinnedCommit is the ONE commit files call target at (.github#314):
// the tree states a trusted workflow once, by the `uses:` line the
// platform runs, so the digest a verifier pins is derived from that
// line and no second copy exists to drift.
//
// subject names what files are — a directory, a file at a commit — and
// opens every refusal, which keeps the two messages the derivation has
// always printed:
//
//	<subject> pins no <name> uses: — nothing to derive the signer digest from
//	<subject> pins <name> at more than one digest — a tree states the
//	  trusted signer once: <pin> <pin>
//
// A call at a reference that is not a commit refuses too, naming it: a
// branch or a tag names no digest, and skipping it would let the
// derivation answer from the rest of the tree as though it agreed.
func PinnedCommit(files []File, target, subject string) (string, error) {
	calls, err := CallsTo(files, target)
	if err != nil {
		return "", err
	}

	name := Ref{Path: target}.Name()
	pins := map[string]bool{}

	for _, c := range calls {
		if !commitRE.MatchString(c.Ref.Version) {
			return "", fmt.Errorf("%s calls %s at %q (%s, jobs.%s), which is not a commit — "+
				"a tree pins the trusted signer by its full commit", subject, name, c.Ref.Version, c.File, c.Job)
		}

		pins[c.Ref.Version] = true
	}

	sorted := make([]string, 0, len(pins))
	for pin := range pins {
		sorted = append(sorted, pin)
	}

	sort.Strings(sorted)

	switch len(sorted) {
	case 0:
		return "", fmt.Errorf("%s pins no %s uses: — nothing to derive the signer digest from", subject, name)
	case 1:
		return sorted[0], nil
	}

	return "", fmt.Errorf("%s pins %s at more than one digest — a tree states the trusted signer once: %s",
		subject, name, strings.Join(sorted, " "))
}
