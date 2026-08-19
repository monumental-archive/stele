// The approvals read: how many distinct trusted persons agreed to the
// change that produced one revision.
//
// This is platform-served history — the forge's own stored record of
// who reviewed what — not a claim the repository emits about itself,
// which is what makes it admissible to the source track's two-party
// judgment. The counting rule is the specification's: "two or more
// trusted persons", so the author is one and each distinct approving
// reviewer who is not the author is another.

package gh

import (
	"fmt"
	"net/url"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// ApprovalsReader is the review-history surface the source track's
// two-party judgment reads through. Its own interface, like TagReader
// and RulesReader, and for the same reason: a fake that scripts
// approvals should not have to script releases.
type ApprovalsReader interface {
	// Approvals reports how many distinct trusted persons agreed to
	// the change that produced rev. found is false when the forge
	// holds no change record for the revision at all — which is an
	// absence of sight, never a count of zero.
	Approvals(owner, repo, rev string) (parties int, found bool, err error)
}

// associatedPull is the part of a pull-request listing this read
// needs: which pull produced the revision, and who authored it.
type associatedPull struct {
	Number         *int    `json:"number"`
	MergeCommitSHA *string `json:"merge_commit_sha"`
	User           *struct {
		Login *string `json:"login"`
	} `json:"user"`
}

// pullReview is one review on a pull request.
type pullReview struct {
	State *string `json:"state"`
	User  *struct {
		Login *string `json:"login"`
	} `json:"user"`
}

// Approvals implements ApprovalsReader over the live forge.
//
// The change that PRODUCED a revision is the pull request whose merge
// commit is that revision. A revision no pull request produced was
// pushed directly: the forge's record of who agreed to it is exactly
// one person, which is an answer, not an absence.
//
//nolint:gocritic // unnamedResult: parties, found, error — the ApprovalsReader contract
func (c *Client) Approvals(owner, repo, rev string) (int, bool, error) {
	base := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)

	body, ok, err := c.get(base+"/commits/"+url.PathEscape(rev)+"/pulls", ghJSON)
	if err != nil {
		return 0, false, err
	}

	if !ok {
		return 0, false, nil
	}

	pulls, err := jsonx.DecodeForeign[[]associatedPull](body)
	if err != nil {
		return 0, false, fmt.Errorf("gh: pulls for %s: %w", rev, err)
	}

	producing := findProducingPull(*pulls, rev)
	if producing == nil {
		// Associated with no producing pull: a direct push, agreed to
		// by its pusher alone.
		return 1, true, nil
	}

	if producing.Number == nil {
		return 0, false, fmt.Errorf("gh: the pull producing %s carries no number", rev)
	}

	author := ""
	if producing.User != nil && producing.User.Login != nil {
		author = *producing.User.Login
	}

	return c.countParties(base, *producing.Number, author)
}

// findProducingPull selects the pull whose merge produced rev.
func findProducingPull(pulls []associatedPull, rev string) *associatedPull {
	for i := range pulls {
		p := &pulls[i]
		if p.MergeCommitSHA != nil && *p.MergeCommitSHA == rev {
			return p
		}
	}

	return nil
}

// countParties reads one pull's reviews and counts the persons who
// agreed: the author, plus each distinct approving reviewer who is
// not the author.
//
//nolint:gocritic // unnamedResult: parties, found, error — the ApprovalsReader contract
func (c *Client) countParties(base string, number int, author string) (int, bool, error) {
	pages, err := c.paged(fmt.Sprintf("%s/pulls/%d/reviews", base, number))
	if err != nil {
		return 0, false, err
	}

	approvers := map[string]bool{}

	for _, page := range pages {
		reviews, derr := jsonx.DecodeForeign[[]pullReview](page)
		if derr != nil {
			return 0, false, fmt.Errorf("gh: reviews for pull %d: %w", number, derr)
		}

		for _, r := range *reviews {
			if r.State == nil || *r.State != "APPROVED" || r.User == nil || r.User.Login == nil {
				continue
			}

			if *r.User.Login != author {
				approvers[*r.User.Login] = true
			}
		}
	}

	return 1 + len(approvers), true, nil
}
