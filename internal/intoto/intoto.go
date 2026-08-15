// Package intoto implements the in-toto Statement v1 — the layer
// every attestation this tool reads or writes shares. Spec:
// in-toto/attestation spec/v1. The predicate is carried raw and
// deferred: which predicate types exist is the caller's business,
// and decoding one is a second, separately validated step.
package intoto

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// StatementType is the one _type a v1 statement carries.
const StatementType = "https://in-toto.io/Statement/v1"

// Digest algorithm names this tool understands well enough to check
// the value shape. The in-toto set is open; an algorithm not named
// here passes through with a non-empty value only.
const (
	AlgSHA256    = "sha256"
	AlgGitCommit = "gitCommit"
)

// Statement is the in-toto Statement, decoded strictly. Predicate
// stays raw: a statement is valid or not independent of whether its
// predicate type is known.
type Statement struct {
	Type          *string              `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType *string              `json:"predicateType"`
	Predicate     jsonx.Raw            `json:"predicate"`
}

// ResourceDescriptor is the spec's full field set — all optional but
// constrained: at least one of name, uri or digest must identify the
// resource, and a statement subject additionally requires digest.
type ResourceDescriptor struct {
	Name             *string           `json:"name"`
	URI              *string           `json:"uri"`
	Digest           map[string]string `json:"digest"`
	Content          *string           `json:"content"`
	DownloadLocation *string           `json:"downloadLocation"`
	MediaType        *string           `json:"mediaType"`
	Annotations      jsonx.Raw         `json:"annotations"`
}

var (
	sha256RE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	gitCommitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Validate refuses a statement whose envelope-level facts are wrong:
// a foreign _type, no subject, a subject without a digest, a
// malformed digest value, or an absent predicateType. The predicate
// is deliberately not judged here.
func (s *Statement) Validate() error {
	switch {
	case s.Type == nil:
		return errors.New("intoto: _type is absent")
	case *s.Type != StatementType:
		return fmt.Errorf("intoto: _type %q is not %s", *s.Type, StatementType)
	}

	if len(s.Subject) == 0 {
		return errors.New("intoto: subject is absent or empty — a statement about nothing states nothing")
	}

	for i, sub := range s.Subject {
		if len(sub.Digest) == 0 {
			return fmt.Errorf("intoto: subject[%d] has no digest — subjects are matched by digest alone", i)
		}

		if err := validateDigest(sub.Digest); err != nil {
			return fmt.Errorf("intoto: subject[%d]: %w", i, err)
		}
	}

	if s.PredicateType == nil || !strings.HasPrefix(*s.PredicateType, "https://") {
		return errors.New("intoto: predicateType must be present and an https URI")
	}

	return nil
}

// validateDigest checks every algorithm/value pair: known algorithms
// must carry their exact shape, unknown ones at least a value. A
// digest set is all-or-nothing — one malformed entry poisons the
// match semantics of the whole set.
func validateDigest(d map[string]string) error {
	for alg, val := range d {
		switch alg {
		case AlgSHA256:
			if !sha256RE.MatchString(val) {
				return fmt.Errorf("digest %s is not 64 lowercase hex", alg)
			}
		case AlgGitCommit:
			if !gitCommitRE.MatchString(val) {
				return fmt.Errorf("digest %s is not 40 lowercase hex", alg)
			}
		default:
			if val == "" {
				return fmt.Errorf("digest %s carries an empty value", alg)
			}
		}
	}

	return nil
}
