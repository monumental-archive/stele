// Package chain implements the source-track chain link — the git
// note format and the source-provenance predicate it carries. The
// format is the org's documented one (the canon's
// docs/source-provenance.md, the SLSA v1.2 source track's required
// SCS documentation); it lives in code typed to that documentation
// because a policy cannot make an undocumented format verifiable.
// Which predicate type URI names it, and which identity signs it,
// stay in the policy.
package chain

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/monumental-archive/stele/internal/dsse"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// The two note versions readers accept. Version 1 carries `prev`,
// one pointer holding two meanings (ledger order and git ancestry)
// at once — the overload that made pre-v2 heals fork the ledger.
// Version 2 splits them: `ledgerPrev` is emission order, and git
// ancestry travels separately in `revisionParent` and `parents`.
const (
	NoteV1 = 1
	NoteV2 = 2
)

// Note is one chain link: a git note on the attested revision.
// Statements travel base64 so the signed bytes survive any JSON
// re-encoding of the note.
type Note struct {
	Version    *int      `json:"version"`
	Provenance *Envelope `json:"provenance"`
	VSA        *Envelope `json:"vsa"`
}

// Envelope pairs a base64 statement with its Sigstore bundle. The
// bundle stays raw: its verification belongs to the trust layer, and
// its exact shape belongs to Sigstore.
type Envelope struct {
	Statement *string   `json:"statement"`
	Bundle    jsonx.Raw `json:"bundle"`
}

// Pointer is a ledger step: the previous emitted note's revision and
// the SHA-256 of that note's raw blob bytes, so any re-encoding of
// the predecessor is detectable.
type Pointer struct {
	Revision   *string `json:"revision"`
	NoteSHA256 *string `json:"noteSha256"`
}

// Actor is who triggered the emitting run. For a healed link this is
// the healer, not the original pusher — the documented honest value.
type Actor struct {
	Login *string   `json:"login"`
	ID    jsonx.Raw `json:"id"`
}

// Control is one live rule property and the rule content proving it.
type Control struct {
	Property *string   `json:"property"`
	Evidence jsonx.Raw `json:"evidence"`
}

// Repaired marks a healed link: the moment the late link was
// emitted. Its presence is the deviation marker consumers gate on.
type Repaired struct {
	At *string `json:"at"`
}

// Predicate is the source-provenance predicate. LedgerPrev and Prev
// are version-gated: exactly one of them is PRESENT (v2 and v1
// respectively), and genesis is that key present AND null — which is
// why both are jsonx.Raw first and interpreted by Ledger below: the
// stdlib's absent and null both decode a pointer to nil, and this
// format makes that exact distinction load-bearing.
type Predicate struct {
	Repository     *string   `json:"repository"`
	Ref            *string   `json:"ref"`
	Parents        []string  `json:"parents"`
	Actor          *Actor    `json:"actor"`
	CommitTime     *string   `json:"commitTime"`
	RulesReadAt    *string   `json:"rulesReadAt"`
	Controls       []Control `json:"controls"`
	LedgerPrev     jsonx.Raw `json:"ledgerPrev"`
	RevisionParent *string   `json:"revisionParent"`
	Prev           jsonx.Raw `json:"prev"`
	CanonRef       *string   `json:"canonRef"`
	Repaired       *Repaired `json:"repaired"`
}

var (
	revisionRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256RE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Validate refuses a note whose structure is wrong: an unknown
// version, a missing half (a link is provenance AND summary), or a
// statement that is not decodable base64.
func (n *Note) Validate() error {
	switch {
	case n.Version == nil:
		return errors.New("chain: version is absent")
	case *n.Version != NoteV1 && *n.Version != NoteV2:
		return fmt.Errorf("chain: version %d is neither %d nor %d", *n.Version, NoteV1, NoteV2)
	}

	for _, half := range []struct {
		name string
		env  *Envelope
	}{{"provenance", n.Provenance}, {"vsa", n.VSA}} {
		if half.env == nil {
			return fmt.Errorf("chain: %s is absent — a link is provenance and summary, never one alone", half.name)
		}

		if half.env.Statement == nil || *half.env.Statement == "" {
			return fmt.Errorf("chain: %s.statement is absent or empty", half.name)
		}

		if _, err := dsse.DecodeBase64(*half.env.Statement); err != nil {
			return fmt.Errorf("chain: %s.statement: %w", half.name, err)
		}

		if len(half.env.Bundle) == 0 {
			return fmt.Errorf("chain: %s.bundle is absent", half.name)
		}
	}

	return nil
}

// Ledger interprets the version-gated pointer of a validated note's
// predicate: the ledger step for the walk, or genesis. The rules are
// the documented ones — a v2 predicate carries ledgerPrev PRESENT
// (null exactly at genesis) and no prev; a v1 predicate the reverse.
// A predicate carrying both, neither, or the wrong key for its
// version is refused: the audit's lesson (#349 S3) is that testing
// bare null ends the walk at the first v2 link and calls the
// truncation clean, so presence and nullness are judged separately.
// Genesis is its own return, never a nil pointer a caller could
// mistake for one more step.
func (p *Predicate) Ledger(version int) (*Pointer, bool, error) {
	var key string

	var raw jsonx.Raw

	switch version {
	case NoteV1:
		if p.LedgerPrev != nil {
			return nil, false, errors.New("chain: a version-1 predicate must not carry ledgerPrev")
		}

		key, raw = "prev", p.Prev
	case NoteV2:
		if p.Prev != nil {
			return nil, false, errors.New("chain: a version-2 predicate must not carry prev")
		}

		key, raw = "ledgerPrev", p.LedgerPrev
	default:
		return nil, false, fmt.Errorf("chain: version %d is neither %d nor %d", version, NoteV1, NoteV2)
	}

	if raw == nil {
		return nil, false, fmt.Errorf("chain: %s is absent — absent and genesis-null are different facts", key)
	}

	if string(raw) == "null" {
		return nil, true, nil // genesis: the key is present and null, exactly once per history
	}

	ptr, err := jsonx.DecodeBytes[Pointer](raw)
	if err != nil {
		return nil, false, fmt.Errorf("chain: %s: %w", key, err)
	}

	if ptr.Revision == nil || !revisionRE.MatchString(*ptr.Revision) {
		return nil, false, fmt.Errorf("chain: %s.revision must be the full 40-hex identifier", key)
	}

	if ptr.NoteSHA256 == nil || !sha256RE.MatchString(*ptr.NoteSHA256) {
		return nil, false, fmt.Errorf("chain: %s.noteSha256 must be 64 lowercase hex", key)
	}

	return ptr, false, nil
}
