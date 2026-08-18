// Package chain implements the source-track chain link — the git
// note format and the source-provenance predicate it carries. The
// format's specification is docs/chain-format.md (the SLSA v1.2
// source track's required SCS documentation), whose examples this
// package's doc test validates — the spec and the implementation
// cannot disagree silently. Which predicate type URI names it, and
// which identity signs it, stay in the policy; which refs an org
// attests stays in that org's narrative docs.
package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"github.com/monumental-archive/stele/internal/dsse"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// SHA256Hex is THE digest rendering of this format: 64 lowercase hex
// over exactly the bytes given. Every ledger noteSha256 and every
// statement digest renders through this one function — the emit leg
// and the verify walk both call it, because two copies of "the"
// digest is how the bash legs drifted apart (.github#434: one copy
// hashed the stored blob, the other a newline-stripped string, and no
// test compared them).
func SHA256Hex(b []byte) string {
	d := sha256.Sum256(b)

	return hex.EncodeToString(d[:])
}

// NoteV3 is the ONE note version this implementation reads and
// writes. v3 = the v2 ledger semantics (`ledgerPrev` is emission
// order; git ancestry travels in `revisionParent` and `parents`)
// plus DSSE payload-type authentication: each half's bundle signs
// PAE(payloadType, statement), never the bare statement bytes, so a
// signed statement cannot be replayed as a different document type.
// Earlier versions are not read: the ledgers are re-emitted whole at
// the format bump (the #434 healing precedent) — nothing external
// consumes the old bytes, so dual-version reading would be dead
// weight, not compatibility.
const NoteV3 = 3

// StatementType is the DSSE payload type every half carries — the
// in-toto statement media type.
const StatementType = "application/vnd.in-toto+json"

// Note is one chain link: a git note on the attested revision.
// Statements travel base64 so the signed bytes survive any JSON
// re-encoding of the note.
type Note struct {
	Version    *int      `json:"version"`
	Provenance *Envelope `json:"provenance"`
	VSA        *Envelope `json:"vsa"`
}

// Envelope pairs a base64 statement with its payload type and its
// Sigstore bundle. The bundle's signature covers
// PAE(payloadType, statement); the bundle stays raw because its
// verification belongs to the trust layer and its exact shape to
// Sigstore.
type Envelope struct {
	PayloadType *string   `json:"payloadType"`
	Statement   *string   `json:"statement"`
	Bundle      jsonx.Raw `json:"bundle"`
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

// Predicate is the source-provenance predicate. LedgerPrev is
// jsonx.Raw because absent and genesis-null are different facts: the
// key is PRESENT on every link, null exactly at genesis — the
// stdlib's absent and null both decode a pointer to nil, and this
// format makes that exact distinction load-bearing (interpreted by
// Ledger below). LedgerPrev deliberately has NO omitempty — the key
// travels even at genesis; repaired is present exactly on healed
// links.
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
	// MachineryRef pins the policy tree the link was emitted under.
	MachineryRef *string   `json:"machineryRef"`
	Repaired     *Repaired `json:"repaired,omitempty"`
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
	case *n.Version != NoteV3:
		return fmt.Errorf("chain: version %d is not %d — earlier formats were retired whole with their ledgers",
			*n.Version, NoteV3)
	}

	for _, half := range []struct {
		name string
		env  *Envelope
	}{{"provenance", n.Provenance}, {"vsa", n.VSA}} {
		if half.env == nil {
			return fmt.Errorf("chain: %s is absent — a link is provenance and summary, never one alone", half.name)
		}

		if half.env.PayloadType == nil || *half.env.PayloadType != StatementType {
			return fmt.Errorf("chain: %s.payloadType is not %s", half.name, StatementType)
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

// Ledger interprets a validated predicate's ledger pointer: the
// step for the walk, or genesis. ledgerPrev must be PRESENT (null
// exactly at genesis): the audit's lesson (#349 S3) is that testing
// bare null ends the walk at the first link and calls the truncation
// clean, so presence and nullness are judged separately. Genesis is
// its own return, never a nil pointer a caller could mistake for one
// more step.
func (p *Predicate) Ledger() (*Pointer, bool, error) {
	raw := p.LedgerPrev

	if raw == nil {
		return nil, false, errors.New("chain: ledgerPrev is absent — absent and genesis-null are different facts")
	}

	if string(raw) == "null" {
		return nil, true, nil // genesis: the key is present and null, exactly once per history
	}

	ptr, err := jsonx.DecodeBytes[Pointer](raw)
	if err != nil {
		return nil, false, fmt.Errorf("chain: ledgerPrev: %w", err)
	}

	if ptr.Revision == nil || !revisionRE.MatchString(*ptr.Revision) {
		return nil, false, errors.New("chain: ledgerPrev.revision must be the full 40-hex identifier")
	}

	if ptr.NoteSHA256 == nil || !sha256RE.MatchString(*ptr.NoteSHA256) {
		return nil, false, errors.New("chain: ledgerPrev.noteSha256 must be 64 lowercase hex")
	}

	return ptr, false, nil
}
