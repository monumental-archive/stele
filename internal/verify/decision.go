// This file: the release decision's reader, one definition for both
// sides of it. The release verdict reads a decision it found in the
// store through it, and `stele emit decision` reads the record it is
// about to hand the signer back through it (stele#399) — so a record
// the verdict would refuse can never be written, and the two cannot
// disagree about what a decision is.

package verify

import (
	"errors"
	"fmt"

	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
)

// decodeDecision reads one release-decision statement: a valid
// in-toto statement, of the type the policy names, whose predicate
// decodes strictly as the decision's documented field set.
func decodeDecision(payload []byte, p *policy.Policy) (*intoto.Statement, *decisionPredicate, error) {
	stmt, err := jsonx.DecodeBytes[intoto.Statement](payload)
	if err != nil {
		return nil, nil, fmt.Errorf("verified payload is not a statement: %w", err)
	}

	if verr := stmt.Validate(); verr != nil {
		return nil, nil, verr
	}

	if *stmt.PredicateType != *p.Trust.Decision.PredicateType {
		return nil, nil, errors.New("verified payload is not a release decision")
	}

	pred, err := jsonx.DecodeBytes[decisionPredicate](stmt.Predicate)
	if err != nil {
		return nil, nil, fmt.Errorf("decision predicate: %w", err)
	}

	return stmt, pred, nil
}

// decisionHolds is what makes a decision the one the policy requires:
// the required conclusion, and the tag it decides. An empty tag is a
// stream — a publish with no version — whose decision must name none,
// since inventing one would manufacture the version surface a stream
// exists without.
func decisionHolds(pred *decisionPredicate, p *policy.Policy, tag string) error {
	want := *p.Trust.Decision.RequiredConclusion
	if pred.Conclusion == nil || *pred.Conclusion != want {
		return fmt.Errorf("the release decision does not name conclusion %s", want)
	}

	if tag == "" {
		if pred.Tag != nil {
			return fmt.Errorf("the stream decision names tag %s — a stream has none", *pred.Tag)
		}

		return nil
	}

	if pred.Tag == nil || *pred.Tag != tag {
		return fmt.Errorf("the release decision does not name tag %s", tag)
	}

	return nil
}

// ReadDecision reads a release-decision statement exactly as the
// release verdict reads one, for the release tag (or, empty, for a
// stream), and returns its subjects as sha256sum lines read back out
// of the statement — what the decision covers, in the verifier's own
// spelling.
func ReadDecision(p *policy.Policy, statement []byte, tag string) ([]string, error) {
	if p.Trust == nil || p.Trust.Decision == nil {
		return nil, errors.New("verify: the policy declares no trust.decision — there is no decision to read")
	}

	stmt, pred, err := decodeDecision(statement, p)
	if err != nil {
		return nil, fmt.Errorf("verify: release decision: %w", err)
	}

	if herr := decisionHolds(pred, p, tag); herr != nil {
		return nil, fmt.Errorf("verify: %w", herr)
	}

	lines := make([]string, 0, len(stmt.Subject))

	for _, sub := range stmt.Subject {
		line, lerr := subjectLine(sub)
		if lerr != nil {
			return nil, fmt.Errorf("verify: release decision: %w", lerr)
		}

		lines = append(lines, line)
	}

	return lines, nil
}
