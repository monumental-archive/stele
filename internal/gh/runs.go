// Two reads the signer-certificate watch makes of the forge (stele#387):
// one workflow run by id, and a repository's default branch. Both are
// forge records over REST, not git objects — a run and a repository's
// settings exist only in the forge's database, so there is no history
// to fetch them from.
//
// A 404 is an ANSWER, typed apart from every failure, the way FileAt
// types it: for a run, deleted cannot be told from never existed, and
// the reconciliation judges that as a finding; for a repository, it is
// absent or invisible to this credential. Every other refusal comes
// back as the error get already typed — a throttle, a 403, a transient
// failure — and none of them is a fact about the subject.

package gh

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// WorkflowRun is one workflow run, decoded to what a reconciliation of
// a signer certificate reads.
type WorkflowRun struct {
	// Repository is the run's owner/name, as the forge names it.
	Repository string
	// Path is the run's top-level workflow, repository-relative.
	Path    string
	HeadSHA string
	HTMLURL string
	Event   string
	// Referenced are the reusable workflows the run called.
	Referenced []ReferencedWorkflow
}

// ReferencedWorkflow is one reusable workflow a run called: its path
// as owner/repo/path@ref, and the commit the ref resolved to.
type ReferencedWorkflow struct {
	Path string
	SHA  string
}

// runEntry is the run object's decode shape (REST "Get a workflow
// run"). Pointer fields: a run missing one of these is an answer this
// reader cannot use, never a run with empty fields.
type runEntry struct {
	Path       *string `json:"path"`
	HeadSHA    *string `json:"head_sha"` //nolint:tagliatelle // the forge's own field name
	HTMLURL    *string `json:"html_url"` //nolint:tagliatelle // the forge's own field name
	Event      *string `json:"event"`
	Repository *struct {
		FullName *string `json:"full_name"` //nolint:tagliatelle // the forge's own field name
	} `json:"repository"`
	// The forge's schema makes this nullable: a run that called no
	// reusable workflow may carry null, and null is none.
	Referenced []referencedEntry `json:"referenced_workflows"` //nolint:tagliatelle // the forge's own field name
}

type referencedEntry struct {
	Path *string `json:"path"`
	SHA  *string `json:"sha"`
}

// WorkflowRun reads one workflow run. found=false is the forge's 404.
func (c *Client) WorkflowRun(owner, repo string, id uint64) (*WorkflowRun, bool, error) {
	path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) +
		"/actions/runs/" + strconv.FormatUint(id, 10)

	body, _, ok, err := c.get(path, ghJSON)
	if err != nil || !ok {
		return nil, false, err
	}

	e, err := jsonx.DecodeForeign[runEntry](body)
	if err != nil {
		return nil, false, fmt.Errorf("gh: %s: %w", path, err)
	}

	if e.Path == nil || e.HeadSHA == nil || e.HTMLURL == nil || e.Event == nil ||
		e.Repository == nil || e.Repository.FullName == nil {
		return nil, false, fmt.Errorf(
			"gh: %s: the run lacks path, head_sha, html_url, event or repository.full_name", path,
		)
	}

	run := &WorkflowRun{
		Repository: *e.Repository.FullName,
		Path:       *e.Path,
		HeadSHA:    *e.HeadSHA,
		HTMLURL:    *e.HTMLURL,
		Event:      *e.Event,
	}

	for i, r := range e.Referenced {
		if r.Path == nil || r.SHA == nil {
			return nil, false, fmt.Errorf("gh: %s: referenced_workflows[%d] lacks path or sha", path, i)
		}

		run.Referenced = append(run.Referenced, ReferencedWorkflow{Path: *r.Path, SHA: *r.SHA})
	}

	return run, true, nil
}

type defaultBranchEntry struct {
	DefaultBranch *string `json:"default_branch"` //nolint:tagliatelle // the forge's own field name
}

// DefaultBranch reads a repository's default branch. found=false is
// the forge's 404: the repository is absent, or this credential cannot
// see it — the forge answers both the same way.
//
//nolint:gocritic // unnamedResult: FileAt's shape — the answer, whether the forge had one, a read that failed
func (c *Client) DefaultBranch(owner, repo string) (string, bool, error) {
	path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)

	body, _, ok, err := c.get(path, ghJSON)
	if err != nil || !ok {
		return "", false, err
	}

	e, err := jsonx.DecodeForeign[defaultBranchEntry](body)
	if err != nil {
		return "", false, fmt.Errorf("gh: %s: %w", path, err)
	}

	if e.DefaultBranch == nil || *e.DefaultBranch == "" {
		return "", false, fmt.Errorf("gh: %s: the repository names no default_branch", path)
	}

	return *e.DefaultBranch, true, nil
}
