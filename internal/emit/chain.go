// This file: the chain leg — per push, walk first-parent from the
// pushed revision, emit a link for it and for every hole earlier
// lapses left (each marked repaired), and append the ledger with a
// compare-and-swap push. The provenance predicate is the org's
// documented format (internal/chain); the summary half is the spec's
// VSA, derived from the just-signed-and-verified provenance only —
// the L2+ requirement that a VSA summarise SCS-issued provenance.

package emit

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/dsse"
	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/vsa"
)

// pushAttempts bounds the compare-and-swap loop. Same-repo runs are
// serialized by the workflow's concurrency group, so more than a
// couple of rejections means something is genuinely wrong.
const pushAttempts = 3

// ChainInputs is everything one chain emission needs beyond the
// engine's seams. Actor identifies who triggered the emitting run —
// for a healed link that is the healer, the documented honest value.
type ChainInputs struct {
	Owner, Repo string
	Ref         string // the protected branch's fully qualified ref
	Rev         string // the pushed revision
	Genesis     bool
	ActorLogin  string
	ActorID     string
	CanonRef    string // the commit the canon policy tree is pinned at
	PolicyURI   string // where a stranger reads the policy at that pin
	Claims      *Claims
}

// Chain runs one emission: discovery, per-revision link assembly and
// signing, the local note writes, and the compare-and-swap push. A
// rejected push refetches the notes ref and rebuilds every link —
// the predecessor hash is recomputed against the state that wins,
// which is what closes the lost-update window structurally
// (.github#434 rule 3).
func Chain(
	p *policy.Policy, in *ChainInputs,
	g Git, s Signer, bv BlobVerifier, now func() time.Time, log Logf,
) error {
	if in == nil {
		return errors.New("emit: no inputs")
	}

	pb, err := validateChainInputs(p, in)
	if err != nil {
		return err
	}

	onBranch, err := g.IsAncestor(in.Rev, in.Ref)
	if err != nil {
		return err
	}

	if !onBranch {
		return fmt.Errorf("emit: %s is not on %s — the emitter attests protected-ref revisions only", in.Rev, in.Ref)
	}

	e := &chainRun{
		p: p, pb: pb, in: in, g: g, s: s, bv: bv, now: now, log: log,
		id: trust.Identity{SAN: expand(*p.Source.Identity, in.Owner, in.Repo), Issuer: *p.Issuer},
	}

	for attempt := 1; attempt <= pushAttempts; attempt++ {
		if attempt > 1 {
			if ferr := g.FetchNotes(); ferr != nil {
				return fmt.Errorf("emit: refetching the notes ref: %w", ferr)
			}
		}

		emitted, err := e.once()
		if err != nil {
			return err
		}

		if emitted == 0 {
			log("emit: every revision since genesis already carries a link — nothing to emit")

			return nil
		}

		if err := g.PushNotes(); err == nil {
			log("emit: %d chain link(s) pushed (attempt %d)", emitted, attempt)

			return nil
		}

		log("emit: notes push rejected (attempt %d) — refetching and rebuilding against the moved ledger", attempt)
	}

	return fmt.Errorf("emit: the notes ref would not fast-forward after %d attempts", pushAttempts)
}

// validateChainInputs refuses inputs that could not name an honest
// emission, and resolves the protected branch the policy governs.
func validateChainInputs(p *policy.Policy, in *ChainInputs) (*policy.ProtectedBranch, error) {
	switch {
	case !nameRE.MatchString(in.Owner) || !nameRE.MatchString(in.Repo):
		return nil, fmt.Errorf("emit: owner/repo %q/%q is not a plausible repository", in.Owner, in.Repo)
	case !revRE.MatchString(in.Rev):
		return nil, fmt.Errorf("emit: revision %q is not a full commit digest", in.Rev)
	case !refRE.MatchString(in.Ref):
		return nil, fmt.Errorf("emit: ref %q is not fully qualified", in.Ref)
	case !revRE.MatchString(in.CanonRef):
		return nil, fmt.Errorf(
			"emit: canon ref %q is not a commit digest — the policy tree must be pinned by full SHA so the VSA can carry"+
				" its digest", in.CanonRef)
	case in.PolicyURI == "":
		return nil, errors.New("emit: a policy URI is required — a signed verdict naming no policy must never recur")
	case in.ActorLogin == "" || in.ActorID == "":
		return nil, errors.New("emit: the triggering actor is required — the History requirement records who")
	case in.Claims == nil:
		return nil, errors.New("emit: a claims payload is required")
	}

	if err := in.Claims.Validate(); err != nil {
		return nil, err
	}

	branch := branchName(in.Ref)
	for i := range p.Source.ProtectedBranches {
		if *p.Source.ProtectedBranches[i].Name == branch {
			return &p.Source.ProtectedBranches[i], nil
		}
	}

	return nil, fmt.Errorf("emit: branch %q is not a protected branch in the policy", branch)
}

// branchName maps a fully qualified ref to the branch the policy
// names — the final segment, the same rule the verify verb applies.
// The ref passed refRE, so a slash is always present.
func branchName(ref string) string {
	return ref[strings.LastIndex(ref, "/")+1:]
}

// chainRun is one emission attempt's state.
type chainRun struct {
	p   *policy.Policy
	pb  *policy.ProtectedBranch
	in  *ChainInputs
	g   Git
	s   Signer
	bv  BlobVerifier
	now func() time.Time
	log Logf
	id  trust.Identity
}

// once discovers what needs a link against the CURRENT local ledger
// state and emits it: build, sign, self-verify, write. Returns how
// many links were written; zero means the ledger already covers
// everything and there is nothing to push.
func (e *chainRun) once() (int, error) {
	heal, tail, err := e.discover()
	if err != nil {
		return 0, err
	}

	if len(heal) == 0 {
		return 0, nil
	}

	if tail != "" {
		if err := e.verifyTail(tail); err != nil {
			return 0, err
		}
	}

	for _, rev := range heal {
		if err := e.link(rev, tail); err != nil {
			return 0, err
		}

		tail = rev
	}

	return len(heal), nil
}

// discover walks first-parent from the pushed revision toward the
// root, collecting unlinked revisions until the genesis link ends the
// walk. It returns the heal list oldest-first and the ledger tail —
// the nearest linked first-parent ancestor of the pushed revision,
// the newest pre-run emission. Genesis founds instead: it requires a
// history bearing no link at all and heals exactly the pushed
// revision; a gap is debt, never a reason to re-found.
//
//nolint:gocritic // unnamedResult: the pair is documented above — the heal list and the ledger tail
func (e *chainRun) discover() ([]string, string, error) {
	var holes []string

	var tail string

	sawLink, genesisFound := false, false

	for c := e.in.Rev; c != ""; {
		note, err := e.g.Note(c)
		if err != nil {
			return nil, "", fmt.Errorf("emit: note for %s: %w", c, err)
		}

		link, isLink := decodeLink(note)
		if isLink {
			sawLink = true

			if tail == "" && c != e.in.Rev {
				tail = c
			}

			genesis, gerr := linkIsGenesis(link)
			if gerr != nil {
				return nil, "", fmt.Errorf("emit: link at %s: %w", c, gerr)
			}

			if genesis {
				genesisFound = true

				break
			}
		} else {
			holes = append(holes, c)
		}

		next, perr := e.g.Parent(c)
		if perr != nil {
			return nil, "", fmt.Errorf("emit: parent of %s: %w", c, perr)
		}

		c = next
	}

	if e.in.Genesis {
		if sawLink {
			return nil, "", errors.New(
				"emit: genesis refused — a chain link already exists on this history; a gap is debt, not a new founding")
		}

		e.log("emit: genesis: founding the chain at %s", e.in.Rev)

		return []string{e.in.Rev}, "", nil
	}

	if !genesisFound {
		return nil, "", errors.New(
			"emit: no genesis link on this history — found the chain first with a genesis dispatch")
	}

	// A walk that found genesis and left holes necessarily passed a
	// link other than the pushed revision (genesis itself at the
	// least), so tail is set whenever heal is non-empty.

	// Oldest first: healing in order keeps every emitted link's
	// ledger predecessor already written by the time its turn comes.
	heal := make([]string, 0, len(holes))
	for _, hole := range slices.Backward(holes) {
		heal = append(heal, hole)
	}

	if len(heal) > 1 {
		e.log("emit: healing %d unattested revision(s) left by earlier lapses — see their repaired markers", len(heal)-1)
	}

	return heal, tail, nil
}

// decodeLink reports whether note bytes are a chain link — the same
// deliberately lenient read as the verify walk: scaffolding notes are
// not links, but once something decodes as a link every subsequent
// defect refuses.
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

// linkIsGenesis reads a validated link's ledger interpretation.
func linkIsGenesis(link *chain.Note) (bool, error) {
	stmtBytes, err := dsse.DecodeBase64(*link.Provenance.Statement)
	if err != nil {
		return false, fmt.Errorf("provenance statement: %w", err)
	}

	stmt, err := jsonx.DecodeBytes[intoto.Statement](stmtBytes)
	if err != nil {
		return false, fmt.Errorf("provenance statement: %w", err)
	}

	pred, err := jsonx.DecodeBytes[chain.Predicate](stmt.Predicate)
	if err != nil {
		return false, fmt.Errorf("predicate: %w", err)
	}

	_, genesis, err := pred.Ledger(*link.Version)
	if err != nil {
		return false, err
	}

	return genesis, nil
}

// verifyTail proves the pre-existing link this run signs on top of,
// with exactly a stranger's inputs: the published identity over the
// exact statement bytes, and a subject naming the revision the note
// sits on. Extending a chain past a link that fails the published
// contract is never a fallback.
func (e *chainRun) verifyTail(rev string) error {
	note, err := e.g.Note(rev)
	if err != nil {
		return fmt.Errorf("emit: note for %s: %w", rev, err)
	}

	link, isLink := decodeLink(note)
	if !isLink {
		return fmt.Errorf("emit: the ledger tail at %s is not a chain link", rev)
	}

	stmtBytes, err := dsse.DecodeBase64(*link.Provenance.Statement)
	if err != nil {
		return fmt.Errorf("emit: tail at %s: statement: %w", rev, err)
	}

	if _, verr := e.bv.Blob(link.Provenance.Bundle, e.id, chain.SHA256Hex(stmtBytes)); verr != nil {
		return fmt.Errorf(
			"emit: link at %s does not verify against %s — refusing to extend a chain that fails the published root"+
				" of trust: %w", rev, e.id.SAN, verr)
	}

	stmt, err := jsonx.DecodeBytes[intoto.Statement](stmtBytes)
	if err != nil {
		return fmt.Errorf("emit: tail at %s: statement: %w", rev, err)
	}

	if err := subjectNamesRevision(stmt, rev); err != nil {
		return fmt.Errorf("emit: link at %s attests a different revision than the commit it annotates: %w", rev, err)
	}

	return nil
}

// subjectNamesRevision requires the statement to attest exactly this
// revision — content judged, never position.
func subjectNamesRevision(stmt *intoto.Statement, rev string) error {
	found := false

	for i, sub := range stmt.Subject {
		got, ok := sub.Digest[intoto.AlgGitCommit]
		if !ok {
			continue
		}

		if got != rev {
			return fmt.Errorf("subject[%d] attests %s", i, got)
		}

		found = true
	}

	if !found {
		return errors.New("no subject carries a gitCommit digest")
	}

	return nil
}

// link emits one chain link: the provenance statement, its signature,
// the self-verification with a stranger's inputs, the level computed
// from the VERIFIED statement, the VSA derived from it, and the note
// written to the object store.
func (e *chainRun) link(rev, tail string) error {
	prov, err := e.provenance(rev, tail)
	if err != nil {
		return err
	}

	provBundle, err := e.signAndProve(prov.bytes)
	if err != nil {
		return fmt.Errorf("emit: provenance for %s: %w", rev, err)
	}

	lvl, err := level(e.p, e.pb, e.in.Claims, prov.commitTime, prov.healed, e.log)
	if err != nil {
		return err
	}

	vsaBytes, err := e.summary(rev, lvl)
	if err != nil {
		return err
	}

	vsaBundle, err := e.signAndProve(vsaBytes)
	if err != nil {
		return fmt.Errorf("emit: vsa for %s: %w", rev, err)
	}

	note, err := assembleNote(prov.bytes, provBundle, vsaBytes, vsaBundle)
	if err != nil {
		return fmt.Errorf("emit: note for %s: %w", rev, err)
	}

	if aerr := e.g.AddNote(rev, note); aerr != nil {
		return aerr
	}

	// Read back what git actually stored (stripspace included) and
	// require it to still be this link: the bytes the NEXT link's
	// ledgerPrev will hash are the stored bytes, nothing else
	// (.github#434 rule 2), so storage mangling the note into
	// something else must refuse here, not verify red later.
	stored, err := e.g.Note(rev)
	if err != nil {
		return fmt.Errorf("emit: reading back the note for %s: %w", rev, err)
	}

	if _, isLink := decodeLink(stored); !isLink {
		return fmt.Errorf("emit: the stored note for %s no longer decodes as a link — refusing to extend it", rev)
	}

	marker := ""
	if prov.healed {
		marker = " (healed)"
	}

	e.log("emit: emitted %s for %s%s", lvl, rev, marker)

	return nil
}

// provDoc is one rendered provenance: the statement bytes and the two
// facts the level computation judges.
type provDoc struct {
	bytes      []byte
	healed     bool
	commitTime time.Time
}

// provenance renders the provenance statement for one revision.
func (e *chainRun) provenance(rev, tail string) (*provDoc, error) {
	parents, err := e.g.Parents(rev)
	if err != nil {
		return nil, err
	}

	ctStr, err := e.g.CommitTime(rev)
	if err != nil {
		return nil, err
	}

	commitTime, err := time.Parse(time.RFC3339, ctStr)
	if err != nil {
		return nil, fmt.Errorf("emit: commit time of %s: %w", rev, err)
	}

	ledgerPrev, err := e.ledgerPrev(tail)
	if err != nil {
		return nil, err
	}

	actorID, err := jsonx.Marshal(e.in.ActorID)
	if err != nil {
		return nil, fmt.Errorf("emit: actor id: %w", err)
	}

	repository := serverURL + "/" + e.in.Owner + "/" + e.in.Repo

	pred := chain.Predicate{
		Repository:  &repository,
		Ref:         &e.in.Ref,
		Parents:     parents,
		Actor:       &chain.Actor{Login: &e.in.ActorLogin, ID: actorID},
		CommitTime:  &ctStr,
		RulesReadAt: e.in.Claims.RulesReadAt,
		Controls:    *e.in.Claims.Controls,
		LedgerPrev:  ledgerPrev,
		CanonRef:    &e.in.CanonRef,
	}

	if len(parents) > 0 {
		pred.RevisionParent = &parents[0]
	}

	healed := rev != e.in.Rev
	if healed {
		at := e.nowUTC()
		pred.Repaired = &chain.Repaired{At: &at}
	}

	if pred.Parents == nil {
		pred.Parents = []string{}
	}

	if pred.Controls == nil {
		pred.Controls = []chain.Control{}
	}

	stmt, err := e.statement(rev, *e.p.Source.ProvenancePredicateType, pred)
	if err != nil {
		return nil, err
	}

	return &provDoc{bytes: stmt, healed: healed, commitTime: commitTime}, nil
}

// ledgerPrev renders the ledger pointer: null exactly at genesis,
// otherwise the tail revision and the SHA-256 of its note blob as
// read back OUT of the object store — never bytes this process wrote
// (.github#434 rule 2), and through the same digest function the
// verify walk proves against (rule 1).
func (e *chainRun) ledgerPrev(tail string) (jsonx.Raw, error) {
	if tail == "" {
		return jsonx.Raw("null"), nil
	}

	stored, err := e.g.Note(tail)
	if err != nil {
		return nil, fmt.Errorf("emit: note for %s: %w", tail, err)
	}

	if stored == nil {
		return nil, fmt.Errorf("emit: the ledger tail %s has no note — the chain has no tail to extend", tail)
	}

	sha := chain.SHA256Hex(stored)

	return jsonx.Marshal(chain.Pointer{Revision: &tail, NoteSHA256: &sha})
}

// summary renders the VSA statement for one revision from the level
// and properties of its just-verified provenance — through the one
// predicate assembler both of the org's VSA kinds share.
func (e *chainRun) summary(rev, lvl string) ([]byte, error) {
	levels := []string{lvl}
	for _, ctl := range *e.in.Claims.Controls {
		levels = append(levels, *ctl.Property)
	}

	pred, err := vsa.New(
		e.id.SAN,
		e.nowUTC(),
		expand(*e.p.Source.ResourceURI, e.in.Owner, e.in.Repo),
		e.in.PolicyURI, e.in.CanonRef,
		vsa.ResultPassed,
		levels,
	)
	if err != nil {
		return nil, fmt.Errorf("emit: vsa for %s: %w", rev, err)
	}

	return e.statement(rev, vsa.PredicateType, pred)
}

// statement wraps one predicate in the in-toto statement the chain
// carries: the revision as subject, addressed by commit URI and
// gitCommit digest, annotated with the source ref — validated through
// the same consumer types the verify walk decodes with, so an emitted
// statement the walk would refuse is unrepresentable.
func (e *chainRun) statement(rev, predicateType string, pred any) ([]byte, error) {
	predRaw, err := jsonx.Marshal(pred)
	if err != nil {
		return nil, fmt.Errorf("emit: predicate for %s: %w", rev, err)
	}

	annotations, err := jsonx.Marshal(map[string][]string{"sourceRefs": {e.in.Ref}})
	if err != nil {
		return nil, fmt.Errorf("emit: annotations for %s: %w", rev, err)
	}

	uri := serverURL + "/" + e.in.Owner + "/" + e.in.Repo + "/commit/" + rev
	stype := intoto.StatementType
	stmt := intoto.Statement{
		Type: &stype,
		Subject: []intoto.ResourceDescriptor{{
			URI:         &uri,
			Digest:      map[string]string{intoto.AlgGitCommit: rev},
			Annotations: annotations,
		}},
		PredicateType: &predicateType,
		Predicate:     predRaw,
	}

	if err := stmt.Validate(); err != nil {
		return nil, fmt.Errorf("emit: statement for %s: %w", rev, err)
	}

	return jsonx.Marshal(stmt)
}

// signAndProve signs one statement and immediately verifies the
// returned bundle with exactly the stranger's inputs — the published
// identity and the statement digest, nothing this run knows that a
// consumer does not. A signature that does not verify against the
// published contract refuses the run.
func (e *chainRun) signAndProve(stmtBytes []byte) (jsonx.Raw, error) {
	bundle, err := e.s.Sign(stmtBytes)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	if _, verr := e.bv.Blob(bundle, e.id, chain.SHA256Hex(stmtBytes)); verr != nil {
		return nil, fmt.Errorf(
			"the bundle just signed does not verify against %s — the certificate identity is not the published"+
				" contract: %w", e.id.SAN, verr)
	}

	return bundle, nil
}

// assembleNote renders the version-2 chain link: statements base64 so
// the signed bytes survive any JSON re-encoding of the note, bundles
// as JSON for tooling — validated through the consumer type before a
// byte is written.
func assembleNote(provBytes, provBundle, vsaBytes, vsaBundle []byte) ([]byte, error) {
	version := chain.NoteV2
	provStmt := base64.StdEncoding.EncodeToString(provBytes)
	vsaStmt := base64.StdEncoding.EncodeToString(vsaBytes)

	note := chain.Note{
		Version:    &version,
		Provenance: &chain.Envelope{Statement: &provStmt, Bundle: provBundle},
		VSA:        &chain.Envelope{Statement: &vsaStmt, Bundle: vsaBundle},
	}

	if err := note.Validate(); err != nil {
		return nil, err
	}

	return jsonx.Marshal(note)
}

// nowUTC renders the engine clock as the second-granular UTC moment
// evidence records.
func (e *chainRun) nowUTC() string {
	return e.now().UTC().Truncate(time.Second).Format(time.RFC3339)
}
