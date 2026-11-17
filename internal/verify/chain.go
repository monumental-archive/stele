// This file: the chain walk — coverage and linkage as two independent
// properties, exactly as the source track's audit proved they must
// be (#349 S3). Coverage walks the BRANCH first-parent from tip to
// the genesis link and refuses unattested revisions between links;
// linkage walks the LEDGER via its own pointers, proving each
// step's noteSha256 against the target's raw bytes. A truncated
// ledger, a forked v2 ledger, and a hole in coverage are three
// different defects and each is named as itself.

package verify

import (
	"errors"
	"fmt"
	"slices"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/dsse"
	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/vsa"
)

// ErrNoChain reports that the walk completed and found no chain
// founded on this branch. A sentinel rather than a message because
// the level judge must tell it apart from every other refusal: the
// spec is explicit that a revision with no source VSA is Source Level
// 0, which is a JUDGMENT, while a walk that could not run at all is
// an absence of sight. Conflating them would turn "we have no source
// track" into "we could not check", or worse, the reverse.
var ErrNoChain = errors.New("no chain founded on this branch")

// History is the git-side surface the walk reads: a branch tip, the
// first-parent relation, and raw note blob bytes — raw because the
// ledger's noteSha256 covers the blob exactly as stored.
type History interface {
	// Tip resolves a fully qualified ref to its commit.
	Tip(ref string) (string, error)
	// Parent returns the first parent, or "" at a root commit — a
	// revision is never the empty string, so the sentinel is safe.
	Parent(rev string) (string, error)
	// Note returns the raw note blob bytes for rev, or nil when no
	// note exists there — a stored note is never zero bytes.
	Note(rev string) ([]byte, error)
	// Noted lists every revision carrying a note.
	Noted() ([]string, error)
}

// ChainVerdict proves one branch's chain walked clean: coverage from
// tip to genesis and a ledger whose every member is reachable (or
// enumerated legacy). Constructor: Chain, alone.
type ChainVerdict struct {
	links       int
	changedAt   string
	ledgerSteps int
	ledgerTotal int
	tip         *TipFacts
	// verified holds every link coverage verified, by revision — the
	// facts a per-commit verdict reads (stele#391). The tip is one of
	// them; nothing else may enter.
	verified map[string]*TipFacts
}

// Links reports how many chain links coverage verified.
func (v *ChainVerdict) Links() int { return v.links }

// IdentityChangedAt is the revision of the first link signed under
// source.identity when earlier links were signed under
// source.legacyIdentity — where the chain changed its signer. Empty
// when the chain never changed (stele#389).
func (v *ChainVerdict) IdentityChangedAt() string { return v.changedAt }

// TipFacts carries the tip link's verified content onward for the
// level computation — read only from verified statements. Fields stay
// unexported and there is no constructor outside this walk: the #208
// law applied to facts, so internal/level cannot hold a tip the walk
// never proved.
type TipFacts struct {
	revision   string
	commitTime string
	properties map[string]bool
	repaired   bool
	vsaLevels  []string
	halves     []Ref
}

// Revision is the tip link's revision.
func (f *TipFacts) Revision() string { return f.revision }

// CommitTime is the revision's commit time, as the link recorded it.
func (f *TipFacts) CommitTime() string { return f.commitTime }

// HasProperty reports whether the link's controls claim one property.
func (f *TipFacts) HasProperty(name string) bool { return f.properties[name] }

// Properties lists the control properties the link claims, sorted so
// a report reads the same way twice.
func (f *TipFacts) Properties() []string {
	out := make([]string, 0, len(f.properties))
	for name := range f.properties {
		out = append(out, name)
	}

	slices.Sort(out)

	return out
}

// Repaired reports whether the link carries the healed-continuity
// marker.
func (f *TipFacts) Repaired() bool { return f.repaired }

// VSALevels lists the levels the link's own summary half claimed —
// track levels and the org property values that ride beside them.
func (f *TipFacts) VSALevels() []string {
	out := make([]string, len(f.vsaLevels))
	copy(out, f.vsaLevels)

	return out
}

// Halves names the link's two signed halves — provenance, then the
// summary — by the ledger address they were read from and the sha256
// of each half's signature bundle: the evidence a verdict copying this
// link's level rests on, in the inputAttestations shape.
func (f *TipFacts) Halves() []Ref {
	out := make([]Ref, len(f.halves))
	copy(out, f.halves)

	return out
}

// Link returns the verified facts of the link on one revision of the
// walked branch. ok=false means this walk verified no link there —
// the revision is off the walked first-parent history, or carries
// none — never that a link failed: a failing link refused the walk.
func (v *ChainVerdict) Link(rev string) (*TipFacts, bool) {
	facts, ok := v.verified[rev]

	return facts, ok
}

// Tip returns the verified tip link's facts. ok=false means the walk
// retained no tip, which is not a level of zero but an absence of
// sight — the caller must distinguish them.
func (v *ChainVerdict) Tip() (*TipFacts, bool) {
	if v.tip == nil {
		return nil, false
	}

	return v.tip, true
}

// Chain verifies one repository branch's source chain. Every link's
// two halves must verify under one source-signing identity over the
// exact statement bytes the note carries, the identities in the order
// SourceSigning permits; every revision since genesis must carry a
// link; the ledger must reach every member.
func Chain(p *policy.Policy, c Coords, ref string, h History, bv BundleVerifier, log Logf) (*ChainVerdict, error) {
	if p.Source == nil {
		return nil, errors.New("verify: the policy declares no source section — the chain walk needs one")
	}

	if err := validateCoords(c, false); err != nil {
		return nil, err
	}

	if !refRE.MatchString(ref) {
		return nil, fmt.Errorf("verify: ref %q is not a fully qualified branch ref", ref)
	}

	w := &walker{
		p:    p,
		c:    c,
		bv:   bv,
		sign: NewSourceSigning(p, c, bv),
	}

	verdict, err := w.coverage(ref, h, log)
	if err != nil {
		return nil, err
	}

	if err := w.linkage(verdict, h, log); err != nil {
		return nil, err
	}

	if verdict.changedAt != "" {
		log("verify: chain %s: source signing identity changed at %s", c.Slug(), verdict.changedAt)
	}

	log("verify: chain %s: %d link(s) verified, ledger walk %d/%d",
		c.Slug(), verdict.links, verdict.ledgerSteps, verdict.ledgerTotal)

	return verdict, nil
}

type walker struct {
	p      *policy.Policy
	c      Coords
	bv     BundleVerifier
	sign   *SourceSigning
	lstart string
	// signings is every verified link's classification, TIP FIRST —
	// the coverage walk's order; judged genesis first at its end.
	signings []Signing
}

// coverage walks first-parent from the tip. The genesis link ends
// the walk; revisions between links are the holes this walk refuses.
func (w *walker) coverage(ref string, h History, log Logf) (*ChainVerdict, error) {
	rev, err := h.Tip(ref)
	if err != nil {
		return nil, fmt.Errorf("verify: %s: %w", ref, err)
	}

	verdict := &ChainVerdict{verified: map[string]*TipFacts{}}

	var holes []string

	for rev != "" {
		note, err := h.Note(rev)
		if err != nil {
			return nil, fmt.Errorf("verify: note for %s: %w", rev, err)
		}

		link, isLink := decodeLink(note)

		switch {
		case isLink:
			facts, signing, genesis, lerr := w.verifyLink(rev, link)
			if lerr != nil {
				return nil, lerr
			}

			verdict.links++
			w.signings = append(w.signings, signing)
			verdict.verified[rev] = facts

			if w.lstart == "" {
				w.lstart = rev
				verdict.tip = facts
			}

			log("verify: link at %s verified", rev[:12])

			if genesis {
				if err := refuseHoles(holes); err != nil {
					return nil, err
				}

				genesisFirst := slices.Clone(w.signings)
				slices.Reverse(genesisFirst)

				changedAt, oerr := w.sign.Order(genesisFirst)
				if oerr != nil {
					return nil, fmt.Errorf("verify: %w", oerr)
				}

				verdict.changedAt = changedAt

				return verdict, nil
			}
		case verdict.links > 0:
			// Only chain-link notes are ledger members: scaffolding
			// (the seeded activation note) is not a link — but a
			// revision BETWEEN links carrying none is a hole.
			holes = append(holes, rev)
		}

		next, perr := h.Parent(rev)
		if perr != nil {
			return nil, fmt.Errorf("verify: parent of %s: %w", rev, perr)
		}

		rev = next // "" at a root commit ends the walk
	}

	if verdict.links == 0 {
		return nil, fmt.Errorf("verify: %w — an unactivated repository is silent by construction", ErrNoChain)
	}

	return nil, errors.New("verify: the walk ended before a genesis link — the chain does not reach its founding")
}

// refuseHoles turns accumulated coverage gaps into the refusal they
// are. A hole is a revision the emitter lapsed on — the audit
// cadence exists to find exactly these.
func refuseHoles(holes []string) error {
	if len(holes) == 0 {
		return nil
	}

	return fmt.Errorf("verify: %d unattested revision(s) since genesis: %v", len(holes), holes)
}

// decodeLink reports whether note bytes are a chain link. Non-JSON
// and foreign shapes are scaffolding, not links — but this is the
// ONLY lenient read in the walk: once something decodes as a link,
// every subsequent defect refuses.
func decodeLink(note []byte) (*chain.Note, bool) {
	if note == nil {
		return nil, false
	}

	link, err := jsonx.DecodeBytes[chain.Note](note)
	if err != nil {
		return nil, false
	}

	if err := link.Validate(); err != nil {
		return nil, false
	}

	return link, true
}

// verifyLink proves one link: which source-signing identity signed
// its provenance half (SourceSigning.Classify), both halves'
// signatures under that one identity over the exact statement bytes,
// the provenance statement's subject naming this revision, predicate
// types, the source resource — and returns the classification, the
// ledger interpretation and the facts the level computation reads.
func (w *walker) verifyLink(rev string, link *chain.Note) (*TipFacts, Signing, bool, error) {
	stmtBytes, digest, err := decodeHalf(rev, "provenance", link.Provenance)
	if err != nil {
		return nil, Signing{}, false, err
	}

	signing, err := w.sign.Classify(rev, link.Provenance.Bundle, digest)
	if err != nil {
		return nil, Signing{}, false, fmt.Errorf("verify: link at %s: provenance refused: %w", rev, err)
	}

	provStmt, err := parseHalf(rev, "provenance", stmtBytes)
	if err != nil {
		return nil, Signing{}, false, err
	}

	facts, genesis, err := w.judgeLink(rev, link, provStmt, signing.Identity())

	return facts, signing, genesis, err
}

// judgeLink proves the rest of a link once its signer is known.
func (w *walker) judgeLink(
	rev string, link *chain.Note, provStmt *intoto.Statement, id trust.Identity,
) (*TipFacts, bool, error) {
	if *provStmt.PredicateType != *w.p.Source.ProvenancePredicateType {
		return nil, false, fmt.Errorf("verify: link at %s: provenance predicate type %q is not the policy's",
			rev, *provStmt.PredicateType)
	}

	if serr := subjectNamesRevision(provStmt, rev); serr != nil {
		return nil, false, fmt.Errorf("verify: link at %s: %w", rev, serr)
	}

	vsaStmt, err := w.verifyHalf(rev, "vsa", link.VSA, id)
	if err != nil {
		return nil, false, err
	}

	levels, err := w.judgeLinkVSA(rev, vsaStmt, id)
	if err != nil {
		return nil, false, err
	}

	pred, err := jsonx.DecodeBytes[chain.Predicate](provStmt.Predicate)
	if err != nil {
		return nil, false, fmt.Errorf("verify: link at %s: predicate: %w", rev, err)
	}

	_, genesis, err := pred.Ledger()
	if err != nil {
		return nil, false, fmt.Errorf("verify: link at %s: %w", rev, err)
	}

	facts := &TipFacts{
		revision:   rev,
		properties: map[string]bool{},
		repaired:   pred.Repaired != nil,
		vsaLevels:  levels,
		halves:     []Ref{w.halfRef(rev, "provenance", link.Provenance), w.halfRef(rev, "vsa", link.VSA)},
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

// halfRef addresses one verified half: the ledger it lives in, the
// revision its note annotates and which half it is, with the sha256
// of the bundle that signed it — the bytes this walk verified. The
// address is stele's own convention, built on the policy's declared
// source resource rather than a host written here:
// <source.resourceUri>@<notesRef>#<revision>/<half>.
func (w *walker) halfRef(rev, name string, env *chain.Envelope) Ref {
	uri := expand(*w.p.Source.ResourceURI, w.c) + "@" + *w.p.Source.NotesRef + "#" + rev + "/" + name

	return Ref{URI: uri, SHA256: sha256Hex(env.Bundle)}
}

// verifyHalf proves one half's signature over the DSSE
// pre-authentication encoding of its exact statement bytes and
// returns the validated statement. The payload type is inside the
// signed encoding: a statement re-labelled as another document kind
// fails here, not in a consumer's assumption.
func (w *walker) verifyHalf(rev, name string, env *chain.Envelope, id trust.Identity) (*intoto.Statement, error) {
	stmtBytes, digest, err := decodeHalf(rev, name, env)
	if err != nil {
		return nil, err
	}

	if _, verr := w.bv.Blob(env.Bundle, id, digest); verr != nil {
		return nil, fmt.Errorf("verify: link at %s: %s refused: %w", rev, name, verr)
	}

	return parseHalf(rev, name, stmtBytes)
}

// decodeHalf reads one half's exact statement bytes and the digest
// its signature covers: the DSSE pre-authentication encoding.
//
//nolint:gocritic // unnamedResult: the pair is documented above — the statement bytes and the covered digest
func decodeHalf(rev, name string, env *chain.Envelope) ([]byte, string, error) {
	stmtBytes, err := dsse.DecodeBase64(*env.Statement)
	if err != nil {
		return nil, "", fmt.Errorf("verify: link at %s: %s statement: %w", rev, name, err)
	}

	return stmtBytes, sha256Hex(dsse.PAE(*env.PayloadType, stmtBytes)), nil
}

// parseHalf decodes and validates a half's statement — called only
// after its signature verified.
func parseHalf(rev, name string, stmtBytes []byte) (*intoto.Statement, error) {
	stmt, err := jsonx.DecodeBytes[intoto.Statement](stmtBytes)
	if err != nil {
		return nil, fmt.Errorf("verify: link at %s: %s statement: %w", rev, name, err)
	}

	if verr := stmt.Validate(); verr != nil {
		return nil, fmt.Errorf("verify: link at %s: %s: %w", rev, name, verr)
	}

	return stmt, nil
}

// judgeLinkVSA validates the summary half's predicate and its
// resource. Levels are carried onward; whether they are HONEST is
// the level computation's comparison, not the walk's.
func (w *walker) judgeLinkVSA(rev string, stmt *intoto.Statement, id trust.Identity) ([]string, error) {
	if *stmt.PredicateType != vsa.PredicateType {
		return nil, fmt.Errorf("verify: link at %s: summary predicate type is not the VSA type", rev)
	}

	pred, err := jsonx.DecodeBytes[vsa.Predicate](stmt.Predicate)
	if err != nil {
		return nil, fmt.Errorf("verify: link at %s: vsa predicate: %w", rev, err)
	}

	if err := pred.Validate(); err != nil {
		return nil, fmt.Errorf("verify: link at %s: %w", rev, err)
	}

	// The VSA spec's step 4, the release leg's #264 rule applied to
	// links: verifier.id must BE the identity that signed this half.
	// The emitter guarantees the tautology; without this the consumer
	// would let a future emitter drift unnoticed (#19 item 2).
	if *pred.Verifier.ID != id.SAN {
		return nil, fmt.Errorf("verify: link at %s: verifier.id %q is not the link signing identity %q",
			rev, *pred.Verifier.ID, id.SAN)
	}

	if want := expand(*w.p.Source.ResourceURI, w.c); *pred.ResourceURI != want {
		return nil, fmt.Errorf("verify: link at %s: vsa names resource %q, expected %q", rev, *pred.ResourceURI, want)
	}

	return pred.VerifiedLevels, nil
}

// subjectNamesRevision requires the statement to attest exactly this
// revision: at least one subject carries a gitCommit digest, and
// every one that does names rev — content judged, never position
// (the same rule as provenance.SourceRevision).
func subjectNamesRevision(stmt *intoto.Statement, rev string) error {
	found := false

	for i, sub := range stmt.Subject {
		got, ok := sub.Digest[intoto.AlgGitCommit]
		if !ok {
			continue
		}

		if got != rev {
			return fmt.Errorf("subject[%d] attests revision %s, the note sits on %s", i, got, rev)
		}

		found = true
	}

	if !found {
		return errors.New("no subject carries a gitCommit digest — the link attests no revision")
	}

	return nil
}

// linkage walks the LEDGER from the tip-most link via its own
// pointers — independent of coverage, the property nothing checked
// before #349 S3. Every member must be reachable; an unreachable
// note is accepted only as an enumerated legacy leaf, and a
// version-2 leaf is always a refusal: the v2 ledger must not fork.
func (w *walker) linkage(verdict *ChainVerdict, h History, log Logf) error {
	members, err := w.members(h)
	if err != nil {
		return err
	}

	verdict.ledgerTotal = len(members)

	visited := map[string]bool{}
	cur := w.lstart

	for cur != "" {
		if visited[cur] {
			return fmt.Errorf("verify: ledger cycle at %s", cur)
		}

		visited[cur] = true
		verdict.ledgerSteps++

		next, err := w.step(cur, h)
		if err != nil {
			return err
		}

		cur = next
	}

	return w.leaves(members, visited, log)
}

// members collects every chain-link note — the ledger's population.
// Scaffolding notes are not members and never count as reachable or
// leaked.
func (w *walker) members(h History) (map[string]int, error) {
	noted, err := h.Noted()
	if err != nil {
		return nil, fmt.Errorf("verify: listing notes: %w", err)
	}

	members := map[string]int{}

	for _, rev := range noted {
		note, err := h.Note(rev)
		if err != nil {
			return nil, fmt.Errorf("verify: note for %s: %w", rev, err)
		}

		if link, isLink := decodeLink(note); isLink {
			members[rev] = *link.Version
		}
	}

	return members, nil
}

// step reads one ledger pointer and proves it: the named note must
// exist and hash to exactly the recorded noteSha256, so any
// re-encoding of a predecessor is detectable.
func (w *walker) step(cur string, h History) (string, error) {
	note, err := h.Note(cur)
	if err != nil {
		return "", fmt.Errorf("verify: note for %s: %w", cur, err)
	}

	link, isLink := decodeLink(note)
	if !isLink {
		return "", fmt.Errorf("verify: ledger names %s but no link exists there", cur)
	}

	stmtBytes, err := dsse.DecodeBase64(*link.Provenance.Statement)
	if err != nil {
		return "", fmt.Errorf("verify: link at %s: statement: %w", cur, err)
	}

	stmt, err := jsonx.DecodeBytes[intoto.Statement](stmtBytes)
	if err != nil {
		return "", fmt.Errorf("verify: link at %s: statement: %w", cur, err)
	}

	pred, err := jsonx.DecodeBytes[chain.Predicate](stmt.Predicate)
	if err != nil {
		return "", fmt.Errorf("verify: link at %s: predicate: %w", cur, err)
	}

	ptr, genesis, err := pred.Ledger()
	if err != nil {
		return "", fmt.Errorf("verify: link at %s: %w", cur, err)
	}

	if genesis {
		return "", nil
	}

	target, err := h.Note(*ptr.Revision)
	if err != nil {
		return "", fmt.Errorf("verify: note for %s: %w", *ptr.Revision, err)
	}

	if target == nil {
		return "", fmt.Errorf("verify: ledger step %s names %s, which has no note", cur, *ptr.Revision)
	}

	if got := sha256Hex(target); got != *ptr.NoteSHA256 {
		return "", fmt.Errorf("verify: ledger hash mismatch: %s names %s at %s, note is %s",
			cur, *ptr.Revision, *ptr.NoteSHA256, got)
	}

	return *ptr.Revision, nil
}

// leaves judges unreachable members: an exception to a cryptographic
// walk is itself named cryptographically (docs/policy-schema.md), so
// an off-ledger link must be enumerated in legacyLeaves or the walk
// refuses — the ledger must not fork silently.
func (w *walker) leaves(members map[string]int, visited map[string]bool, log Logf) error {
	for rev := range members {
		if visited[rev] {
			continue
		}

		if !w.enumeratedLeaf(rev) {
			return fmt.Errorf("verify: link at %s is off the ledger and not enumerated in source.legacyLeaves", rev)
		}

		log("verify: link at %s is off the ledger — enumerated legacy leaf", rev[:12])
	}

	return nil
}

func (w *walker) enumeratedLeaf(rev string) bool {
	for _, leaf := range w.p.Source.LegacyLeaves {
		if *leaf.Repository == w.c.Slug() && *leaf.Revision == rev {
			return true
		}
	}

	return false
}
