// The measurement walk: the source chain read with no policy at all.
//
// Chain (the gating walk) proves a branch against expectations an
// organization declared — the identity its links must carry, the
// predicate type, the resource. That is the right question for a gate,
// and the wrong one for a measurement, because being handed the answer
// is how a measurement becomes a restatement of the claim.
//
// This walk asserts nothing. It proves each link cryptographically,
// reads WHO signed from the certificate, and reports what it found.
// The note format it reads is this tool's own (docs/chain-format.md),
// so no declaration is needed to parse it, and a stranger pointing at
// a repository gets an answer without writing anything down first.

package verify

import (
	"errors"
	"fmt"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/dsse"
	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/vsa"
)

// Measurer proves a bundle cryptographically without asserting an
// identity, and reports the identity it found. Separate from
// BundleVerifier so a gating caller cannot reach it by accident.
type Measurer interface {
	// MeasureBlob proves a message-signature bundle over the given
	// digest and returns the certificate facts, including who signed.
	MeasureBlob(bundleJSON []byte, sha256Hex string) (*trust.Verified, error)
	// MeasureAttestation proves a DSSE bundle over the given digest and
	// returns the signed statement alongside those facts.
	MeasureAttestation(bundleJSON []byte, sha256Hex string) (*trust.Verified, error)
}

// Measured is what the measurement walk found: the chain as it exists,
// with no expectation applied. Constructor: MeasureChain, alone.
type Measured struct {
	links     int
	genesis   bool
	tip       *TipFacts
	signers   []string
	holes     []string
	predicate string
	lapse     string
}

// Links reports how many links the walk proved.
func (m *Measured) Links() int { return m.links }

// ReachedGenesis reports whether the chain runs back to its founding
// link. A chain that does not is a partial record.
func (m *Measured) ReachedGenesis() bool { return m.genesis }

// Tip returns the tip link's verified facts.
func (m *Measured) Tip() (*TipFacts, bool) {
	if m.tip == nil {
		return nil, false
	}

	return m.tip, true
}

// Signers lists the distinct certificate identities that signed this
// chain's links, oldest occurrence first. A measurement REPORTS these
// rather than demanding them; a consumer deciding whether to trust
// them is doing a different job.
func (m *Measured) Signers() []string {
	out := make([]string, len(m.signers))
	copy(out, m.signers)

	return out
}

// Holes lists revisions between links that carry no link — the gaps
// that break a continuity claim.
func (m *Measured) Holes() []string {
	out := make([]string, len(m.holes))
	copy(out, m.holes)

	return out
}

// LastLapse is the newest revision whose link records a repair — the
// revision continuity restarted from. Empty when no link in the chain
// records one, which is an unbroken chain.
//
// The specification's continuity rule is that a lapse resets a
// control's continuity from a NEW revision, so a chain that lapsed and
// then ran clean is not permanently diminished: it is continuous since
// the restart, and this is the date that says since when.
func (m *Measured) LastLapse() string { return m.lapse }

// PredicateType is the provenance predicate type the links carry,
// recorded rather than required.
func (m *Measured) PredicateType() string { return m.predicate }

// MeasureChain walks a branch's source chain from tip to genesis,
// proving every link and asserting nothing.
func MeasureChain(c Coords, ref string, h History, m Measurer, log Logf) (*Measured, error) {
	if err := validateCoords(c, false); err != nil {
		return nil, err
	}

	if !refRE.MatchString(ref) {
		return nil, fmt.Errorf("verify: ref %q is not a fully qualified branch ref", ref)
	}

	rev, err := h.Tip(ref)
	if err != nil {
		return nil, fmt.Errorf("verify: %s: %w", ref, err)
	}

	out := &Measured{}
	seen := map[string]bool{}

	for rev != "" {
		note, nerr := h.Note(rev)
		if nerr != nil {
			return nil, fmt.Errorf("verify: note for %s: %w", rev, nerr)
		}

		link, isLink := decodeLink(note)

		switch {
		case isLink:
			facts, genesis, lerr := measureLink(rev, link, m, out, seen)
			if lerr != nil {
				return nil, lerr
			}

			out.links++

			if out.tip == nil {
				out.tip = facts
			}

			// The walk runs newest first, so the first repair it meets
			// is the newest one: the revision continuity restarted from.
			if facts.repaired && out.lapse == "" {
				out.lapse = rev
			}

			log("verify: measured link at %s", rev[:12])

			if genesis {
				out.genesis = true

				return out, nil
			}
		case out.links > 0:
			// A revision between links carrying none: the gap a
			// continuity claim has to answer for.
			out.holes = append(out.holes, rev)
		}

		next, perr := h.Parent(rev)
		if perr != nil {
			return nil, fmt.Errorf("verify: parent of %s: %w", rev, perr)
		}

		rev = next
	}

	if out.links == 0 {
		return nil, fmt.Errorf("verify: %w — this branch carries no source attestations", ErrNoChain)
	}

	// Walked to a root commit without meeting a genesis link: the
	// record exists but does not reach its own founding.
	return out, nil
}

// measureLink proves one link's two halves and reads what they say.
func measureLink(
	rev string, link *chain.Note, m Measurer, out *Measured, seen map[string]bool,
) (*TipFacts, bool, error) {
	provStmt, signer, err := measureHalf(rev, "provenance", link.Provenance, m)
	if err != nil {
		return nil, false, err
	}

	recordSigner(out, seen, signer)

	if serr := subjectNamesRevision(provStmt, rev); serr != nil {
		return nil, false, fmt.Errorf("verify: link at %s: %w", rev, serr)
	}

	vsaStmt, vsaSigner, err := measureHalf(rev, "vsa", link.VSA, m)
	if err != nil {
		return nil, false, err
	}

	recordSigner(out, seen, vsaSigner)

	if *vsaStmt.PredicateType != vsa.PredicateType {
		return nil, false, fmt.Errorf("verify: link at %s: the summary half is not a verification summary", rev)
	}

	vsaPred, err := jsonx.DecodeBytes[vsa.Predicate](vsaStmt.Predicate)
	if err != nil {
		return nil, false, fmt.Errorf("verify: link at %s: vsa predicate: %w", rev, err)
	}

	if verr := vsaPred.Validate(); verr != nil {
		return nil, false, fmt.Errorf("verify: link at %s: %w", rev, verr)
	}

	pred, err := jsonx.DecodeBytes[chain.Predicate](provStmt.Predicate)
	if err != nil {
		return nil, false, fmt.Errorf("verify: link at %s: predicate: %w", rev, err)
	}

	_, genesis, err := pred.Ledger()
	if err != nil {
		return nil, false, fmt.Errorf("verify: link at %s: %w", rev, err)
	}

	out.predicate = *provStmt.PredicateType

	facts := &TipFacts{
		revision:   rev,
		properties: map[string]bool{},
		repaired:   pred.Repaired != nil,
		vsaLevels:  vsaPred.VerifiedLevels,
	}

	if pred.CommitTime != nil {
		facts.commitTime = *pred.CommitTime
	}

	for _, ctl := range pred.Controls {
		if ctl.Property != nil {
			facts.properties[*ctl.Property] = true
		}
	}

	return facts, genesis, nil
}

// measureHalf proves one half's signature over the DSSE
// pre-authentication encoding of its exact statement bytes, and
// returns the statement plus the identity that signed it.
func measureHalf(rev, name string, env *chain.Envelope, m Measurer) (*intoto.Statement, string, error) {
	if env == nil || env.Statement == nil || env.PayloadType == nil {
		return nil, "", fmt.Errorf("verify: link at %s: the %s half is incomplete", rev, name)
	}

	stmtBytes, err := dsse.DecodeBase64(*env.Statement)
	if err != nil {
		return nil, "", fmt.Errorf("verify: link at %s: %s statement: %w", rev, name, err)
	}

	verified, err := m.MeasureBlob(env.Bundle, sha256Hex(dsse.PAE(*env.PayloadType, stmtBytes)))
	if err != nil {
		return nil, "", fmt.Errorf("verify: link at %s: %s did not verify: %w", rev, name, err)
	}

	stmt, err := jsonx.DecodeBytes[intoto.Statement](stmtBytes)
	if err != nil {
		return nil, "", fmt.Errorf("verify: link at %s: %s statement: %w", rev, name, err)
	}

	if verr := stmt.Validate(); verr != nil {
		return nil, "", fmt.Errorf("verify: link at %s: %s: %w", rev, name, verr)
	}

	return stmt, verified.SAN, nil
}

// recordSigner keeps the distinct identities in encounter order.
func recordSigner(out *Measured, seen map[string]bool, san string) {
	if san == "" || seen[san] {
		return
	}

	seen[san] = true
	out.signers = append(out.signers, san)
}

// ErrNoMeasurement reports that a measurement could not be attempted.
var ErrNoMeasurement = errors.New("no measurement was possible")
