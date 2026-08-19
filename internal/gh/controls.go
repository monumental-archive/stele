// The typed controls read the level judge corroborates against.
//
// rules.go serves raw bytes on purpose: the claims engine matches a
// policy-declared table against exactly what the forge said. This file
// is the opposite case — the judge needs the FORGE's facts in the
// domain's vocabulary, and which rule type means "force pushes are
// blocked" is GitHub knowledge that must not leak past this adapter.
// One statement of that mapping, here, so a caller cannot acquire its
// own private reading of a GitHub rule type.

package gh

import (
	"fmt"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/level"
)

// The GitHub rule types this mapping interprets. Any effective rule
// restricts something on the branch — that is what makes it a rule —
// so restrictiveness needs no vocabulary; these two carry meanings the
// judge names specifically.
const (
	ruleNonFastForward = "non_fast_forward"
	rulePullRequest    = "pull_request"
)

// branchRule is the part of one effective rule this read needs: its
// type, and for review rules the approval count the forge demands.
type branchRule struct {
	Type       *string `json:"type"`
	Parameters *struct {
		RequiredApprovingReviewCount *int `json:"required_approving_review_count"`
	} `json:"parameters"`
}

// EnforcedControls reads the forge's own effective rules for one
// branch and folds them into the facts the level judge corroborates
// subject-issued records against. The answer is the platform's, about
// now; whether now is the revision under judgment is the judge's
// question, not this read's.
func EnforcedControls(r RulesReader, owner, repo, branch string) (*level.LiveRules, error) {
	raw, err := r.BranchRules(owner, repo, branch)
	if err != nil {
		return nil, err
	}

	rules, err := jsonx.DecodeForeign[[]branchRule](raw)
	if err != nil {
		return nil, fmt.Errorf("gh: effective rules for %s: %w", branch, err)
	}

	live := &level.LiveRules{Restrictive: len(*rules) > 0}

	for _, rule := range *rules {
		if rule.Type == nil {
			continue
		}

		switch *rule.Type {
		case ruleNonFastForward:
			live.ForcePushBlocked = true
		case rulePullRequest:
			if rule.Parameters != nil && rule.Parameters.RequiredApprovingReviewCount != nil {
				live.RequiredApprovals = *rule.Parameters.RequiredApprovingReviewCount
			}
		}
	}

	return live, nil
}
