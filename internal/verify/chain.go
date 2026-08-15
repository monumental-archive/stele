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
	"time"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/dsse"
	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/vsa"
)

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
	ledgerSteps int
	ledgerTotal int
	tip         *linkFacts
}

// Links reports how many chain links coverage verified.
func (v *ChainVerdict) Links() int { return v.links }

// linkFacts carries the tip link's verified content onward for the
// level computation — read only from verified statements.
type linkFacts struct {
	revision   string
	commitTime string
	properties map[string]bool
	repaired   bool
	vsaLevels  []string
}

// Chain verifies one repository branch's source chain. Every link's
// two halves must verify under the policy's link identity over the
// exact statement bytes the note carries; every revision since
// genesis must carry a link; the ledger must reach every member.
func Chain(p *policy.Policy, c Coords, ref string, h History, bv BundleVerifier, log Logf) (*ChainVerdict, error) {
	if err := validateCoords(c, false); err != nil {
		return nil, err
	}

	if !refRE.MatchString(ref) {
		return nil, fmt.Errorf("verify: ref %q is not a fully qualified branch ref", ref)
	}

	w := &walker{
		p:  p,
		c:  c,
		bv: bv,
		id: trust.Identity{SAN: expand(*p.Source.Identity, c), Issuer: *p.Issuer},
	}

	verdict, err := w.coverage(ref, h, log)
	if err != nil {
		return nil, err
	}

	if err := w.linkage(verdict, h, log); err != nil {
		return nil, err
	}

	log("verify: chain %s: %d link(s) verified, ledger walk %d/%d",
		c.Slug(), verdict.links, verdict.ledgerSteps, verdict.ledgerTotal)

	return verdict, nil
}

type walker struct {
	p      *policy.Policy
	c      Coords
	bv     BundleVerifier
	id     trust.Identity
	lstart string
}

// coverage walks first-parent from the tip. The genesis link ends
// the walk; revisions between links are the holes this walk refuses.
func (w *walker) coverage(ref string, h History, log Logf) (*ChainVerdict, error) {
	rev, err := h.Tip(ref)
	if err != nil {
		return nil, fmt.Errorf("verify: %s: %w", ref, err)
	}

	verdict := &ChainVerdict{}

	var holes []string

	for rev != "" {
		note, err := h.Note(rev)
		if err != nil {
			return nil, fmt.Errorf("verify: note for %s: %w", rev, err)
		}

		link, isLink := decodeLink(note)

		switch {
		case isLink:
			facts, genesis, lerr := w.verifyLink(rev, link)
			if lerr != nil {
				return nil, lerr
			}

			verdict.links++
			if w.lstart == "" {
				w.lstart = rev
				verdict.tip = facts
			}

			log("verify: link at %s verified", rev[:12])

			if genesis {
				if err := refuseHoles(holes); err != nil {
					return nil, err
				}

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
		return nil, errors.New(
			"verify: no chain founded on this branch — an unactivated repository is silent by construction")
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

// verifyLink proves one link: both halves' signatures over the exact
// statement bytes, the provenance statement's subject naming this
// revision, predicate types, the source resource — and returns the
// ledger interpretation and the facts the level computation reads.
func (w *walker) verifyLink(rev string, link *chain.Note) (*linkFacts, bool, error) {
	provStmt, err := w.verifyHalf(rev, "provenance", link.Provenance)
	if err != nil {
		return nil, false, err
	}

	if *provStmt.PredicateType != *w.p.Source.ProvenancePredicateType {
		return nil, false, fmt.Errorf("verify: link at %s: provenance predicate type %q is not the policy's",
			rev, *provStmt.PredicateType)
	}

	if serr := subjectNamesRevision(provStmt, rev); serr != nil {
		return nil, false, fmt.Errorf("verify: link at %s: %w", rev, serr)
	}

	vsaStmt, err := w.verifyHalf(rev, "vsa", link.VSA)
	if err != nil {
		return nil, false, err
	}

	levels, err := w.judgeLinkVSA(rev, vsaStmt)
	if err != nil {
		return nil, false, err
	}

	pred, err := jsonx.DecodeBytes[chain.Predicate](provStmt.Predicate)
	if err != nil {
		return nil, false, fmt.Errorf("verify: link at %s: predicate: %w", rev, err)
	}

	_, genesis, err := pred.Ledger(*link.Version)
	if err != nil {
		return nil, false, fmt.Errorf("verify: link at %s: %w", rev, err)
	}

	facts := &linkFacts{
		revision:   rev,
		properties: map[string]bool{},
		repaired:   pred.Repaired != nil,
		vsaLevels:  levels,
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

// verifyHalf proves one half's blob signature over its exact
// statement bytes and returns the validated statement.
func (w *walker) verifyHalf(rev, name string, env *chain.Envelope) (*intoto.Statement, error) {
	stmtBytes, err := dsse.DecodeBase64(*env.Statement)
	if err != nil {
		return nil, fmt.Errorf("verify: link at %s: %s statement: %w", rev, name, err)
	}

	if _, verr := w.bv.Blob(env.Bundle, w.id, sha256Hex(stmtBytes)); verr != nil {
		return nil, fmt.Errorf("verify: link at %s: %s refused: %w", rev, name, verr)
	}

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
func (w *walker) judgeLinkVSA(rev string, stmt *intoto.Statement) ([]string, error) {
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

	ptr, genesis, err := pred.Ledger(*link.Version)
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

// leaves judges unreachable members. The bash accepted ANY v1 leaf
// as the known pre-v2 fork; the policy's rule is stricter and
// spec-shaped — an exception to a cryptographic walk is itself named
// cryptographically (docs/policy-schema.md), so a leaf must be
// enumerated in legacyLeaves or it refuses, v1 and v2 alike, with
// v2 named as the fork it is. Logged as a disagreement for shadow.
func (w *walker) leaves(members map[string]int, visited map[string]bool, log Logf) error {
	for rev, version := range members {
		if visited[rev] {
			continue
		}

		if version != chain.NoteV1 {
			return fmt.Errorf("verify: v%d link at %s is unreachable from the ledger — the v2 ledger must not fork",
				version, rev)
		}

		if !w.enumeratedLeaf(rev) {
			return fmt.Errorf("verify: v1 link at %s is off the ledger and not enumerated in source.legacyLeaves", rev)
		}

		log("verify: v1 link at %s is off the ledger — enumerated legacy leaf", rev[:12])
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

// SourceLevel computes the branch's honest source level from the tip
// link's verified evidence: the policy's required properties (those
// whose continuity start predates the commit) against the link's
// controls, the healed-continuity stance, and agreement with the
// level the link's own VSA claimed — an overclaiming link is a
// refusal, not a rounding.
func (v *ChainVerdict) SourceLevel(p *policy.Policy, branch string) (string, error) {
	if v.tip == nil {
		return "", errors.New("verify: the walk retained no tip link — nothing to compute a level from")
	}

	var pb *policy.ProtectedBranch

	for i := range p.Source.ProtectedBranches {
		if *p.Source.ProtectedBranches[i].Name == branch {
			pb = &p.Source.ProtectedBranches[i]

			break
		}
	}

	if pb == nil {
		return "", fmt.Errorf("verify: branch %q is not a protected branch in the policy", branch)
	}

	commitTime, err := time.Parse(time.RFC3339, v.tip.commitTime)
	if err != nil {
		return "", fmt.Errorf("verify: tip link commitTime: %w", err)
	}

	level := *pb.TargetLevel

	for _, rp := range pb.RequiredProperties {
		since, err := time.Parse(time.RFC3339, *rp.Since)
		if err != nil {
			return "", fmt.Errorf("verify: policy since for %s: %w", *rp.Name, err)
		}

		if since.After(commitTime) {
			continue // the property was not yet required when this commit landed
		}

		if !v.tip.properties[*rp.Name] {
			level = *p.Source.UnderclaimLevel

			break
		}
	}

	if v.tip.repaired && !*p.Source.HealedContinuity {
		level = *p.Source.UnderclaimLevel
	}

	if err := agreeWithClaim(v.tip.vsaLevels, level); err != nil {
		return "", err
	}

	return level, nil
}

// agreeWithClaim compares the computed level with what the tip
// link's VSA claimed for the SOURCE track. Disagreement in either
// direction is a finding: an overclaim is dishonest evidence, an
// underclaim means the policy and the emitter have diverged.
func agreeWithClaim(claimed []string, computed string) error {
	if slices.Contains(claimed, computed) {
		return nil
	}

	return fmt.Errorf("verify: the tip link claims %v but the policy computes %s — the emitter and the policy disagree",
		claimed, computed)
}
