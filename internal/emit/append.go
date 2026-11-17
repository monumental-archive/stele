// This file: the chain leg's two halves when they run in different
// jobs (stele#390). ChainLinks signs and stops; WriteLinks hands the
// stored note bytes out as files; ReadLinks and Append take them back
// in a job that holds no signing identity, judge every one as a
// stranger would, and append by the same compare-and-swap push. The
// split exists because the job that signs must not hold the grant a
// push needs: a link signed as the source authority is never written
// to the repository by the same job.

package emit

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/dsse"
	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/verify"
)

// linkDirMode and linkFileMode are the modes the signing half writes
// its hand-off under: the files carry nothing secret, but nothing
// else on the runner has a reason to write them.
const (
	linkDirMode  = 0o700
	linkFileMode = 0o600
)

// linkNameRE is the one spelling of a link file: its position in the
// append order, then the revision the link must annotate. The name
// is the ORDER, never the trust — the revision is read again from
// the signed statement and the two must agree.
var linkNameRE = regexp.MustCompile(`^(\d{4})-([0-9a-f]{40})\.json$`)

// LinkFile is one signed link on its way from the signing half to the
// append half: the note bytes exactly as git stored them (the format
// docs/chain-format.md specifies, no wrapper) and the revision they
// annotate.
type LinkFile struct {
	Rev  string
	Note []byte
}

// linkName renders the file name for the link at 1-based position
// seq — the definition WriteLinks and ReadLinks share.
func linkName(seq int, rev string) string {
	return fmt.Sprintf("%04d-%s.json", seq, rev)
}

// WriteLinks places the signing half's links in dir, oldest first. The
// directory is created when absent and refused when it already holds
// anything: a stale link from another run beside this run's would be
// appended as if this run signed it.
func WriteLinks(dir string, links []LinkFile) error {
	if err := os.MkdirAll(dir, linkDirMode); err != nil {
		return fmt.Errorf("emit: link directory %s: %w", dir, err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("emit: link directory %s: %w", dir, err)
	}

	if len(entries) > 0 {
		return fmt.Errorf("emit: link directory %s is not empty — links from another run would be appended as this"+
			" run's", dir)
	}

	for i, l := range links {
		path := filepath.Join(dir, linkName(i+1, l.Rev))
		if err := os.WriteFile(path, l.Note, linkFileMode); err != nil {
			return fmt.Errorf("emit: writing link %s: %w", path, err)
		}
	}

	return nil
}

// ReadLinks reads a signing half's hand-off back, in order. Every
// entry must be a link file and the sequence must run from 0001
// without a gap: a missing file is named as missing here, not
// discovered later as a predecessor that does not match.
func ReadLinks(dir string) ([]LinkFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("emit: link directory: %w", err)
	}

	links := make([]LinkFile, 0, len(entries))

	for i, ent := range entries {
		m := linkNameRE.FindStringSubmatch(ent.Name())
		if m == nil || !ent.Type().IsRegular() {
			return nil, fmt.Errorf("emit: %s in the link directory is not a link file (NNNN-<revision>.json)",
				ent.Name())
		}

		// os.ReadDir sorts by name, so the zero-padded sequence is
		// the read order; the regexp admits only digits.
		seq, _ := strconv.Atoi(m[1]) //nolint:errcheck // four digits, matched above
		if seq != i+1 {
			return nil, fmt.Errorf("emit: link file %s is out of sequence — expected position %04d; a link file is"+
				" missing", ent.Name(), i+1)
		}

		note, rerr := os.ReadFile(filepath.Join(dir, ent.Name())) //nolint:gosec // G304: the operator's hand-off directory
		if rerr != nil {
			return nil, fmt.Errorf("emit: link file %s: %w", ent.Name(), rerr)
		}

		links = append(links, LinkFile{Rev: m[2], Note: note})
	}

	return links, nil
}

// LedgerGit is the surface the append half needs: the verify walk's
// history, the branch membership check, and the ledger write and push.
// It holds no signer and needs none.
type LedgerGit interface {
	verify.History
	IsAncestor(rev, ref string) (bool, error)
	AddNote(rev string, note []byte) error
	PushNotes() error
}

// AppendInputs names what the append half judges the links against.
type AppendInputs struct {
	Owner, Repo string
	Ref         string // the protected branch's fully qualified ref
	Links       []LinkFile
}

// Append is the push half (stele#390). For each link, in order, it
// trusts nothing because of where the bytes came from: the link must
// sit on a revision of the branch that carries no link yet; the
// predecessor it names must be the current ledger tip for that
// revision's chain (genesis: there must be none); the chain as it
// would stand with the link appended must pass the verify walk
// exactly as `stele verify chain` runs it; and git must store the
// bytes unchanged. Then the notes ref is pushed by the same
// compare-and-swap Chain uses — and a rejection is a refusal, never a
// rebuild, because the half that could re-sign is another job.
func Append(p *policy.Policy, in *AppendInputs, g LedgerGit, bv verify.BundleVerifier, log Logf) error {
	if p.Source == nil {
		return errors.New("emit: the policy declares no source section — the chain append needs one")
	}

	switch {
	case !nameRE.MatchString(in.Owner) || !nameRE.MatchString(in.Repo):
		return fmt.Errorf("emit: owner/repo %q/%q is not a plausible repository", in.Owner, in.Repo)
	case !refRE.MatchString(in.Ref):
		return fmt.Errorf("emit: ref %q is not fully qualified", in.Ref)
	}

	if len(in.Links) == 0 {
		log("emit: no links to append — the signing half found every revision already linked")

		return nil
	}

	coords := verify.Coords{Owner: in.Owner, Repo: in.Repo}

	for _, l := range in.Links {
		if err := appendOne(p, coords, in.Ref, l, g, bv, log); err != nil {
			return err
		}
	}

	if err := g.PushNotes(); err != nil {
		return fmt.Errorf(
			"emit: notes push rejected — the ledger moved under this run; re-run it from the signing job (the append"+
				" half never re-signs): %w", err,
		)
	}

	log("emit: %d chain link(s) appended and pushed", len(in.Links))

	return nil
}

// appendOne judges one link and writes it to the local ledger.
func appendOne(
	p *policy.Policy, c verify.Coords, ref string, l LinkFile, g LedgerGit, bv verify.BundleVerifier, log Logf,
) error {
	link, isLink := decodeLink(l.Note)
	if !isLink {
		return fmt.Errorf("emit: the link file for %s is not a chain link", l.Rev)
	}

	ptr, genesis, err := linkLedger(link, l.Rev)
	if err != nil {
		return fmt.Errorf("emit: the link file for %s: %w", l.Rev, err)
	}

	onBranch, err := g.IsAncestor(l.Rev, ref)
	if err != nil {
		return err
	}

	if !onBranch {
		return fmt.Errorf("emit: the link file for %s names a revision not on %s", l.Rev, ref)
	}

	if perr := requirePredecessor(g, l.Rev, ptr, genesis); perr != nil {
		return perr
	}

	pending := &pendingLink{History: g, rev: l.Rev, note: l.Note}
	if _, verr := verify.Chain(p, c, ref, pending, bv, verify.Logf(log)); verr != nil {
		return fmt.Errorf("emit: the link file for %s is refused — the chain it would extend does not verify: %w",
			l.Rev, verr)
	}

	if aerr := g.AddNote(l.Rev, l.Note); aerr != nil {
		return aerr
	}

	stored, err := g.Note(l.Rev)
	if err != nil {
		return fmt.Errorf("emit: reading back the note for %s: %w", l.Rev, err)
	}

	if !bytes.Equal(stored, l.Note) {
		return fmt.Errorf("emit: git stored the link for %s as different bytes than the file carries — the file is"+
			" not the note as signed and stored; nothing is pushed", l.Rev)
	}

	log("emit: link for %s verified and appended locally", l.Rev)

	return nil
}

// linkLedger reads a link's ledger pointer, after requiring the
// provenance statement to attest exactly the revision the file is
// named for — the name orders, the signed content decides.
func linkLedger(link *chain.Note, rev string) (*chain.Pointer, bool, error) {
	stmtBytes, err := dsse.DecodeBase64(*link.Provenance.Statement)
	if err != nil {
		return nil, false, fmt.Errorf("provenance statement: %w", err)
	}

	stmt, err := jsonx.DecodeBytes[intoto.Statement](stmtBytes)
	if err != nil {
		return nil, false, fmt.Errorf("provenance statement: %w", err)
	}

	if serr := subjectNamesRevision(stmt, rev); serr != nil {
		return nil, false, fmt.Errorf("the link attests a different revision than its file names: %w", serr)
	}

	pred, err := jsonx.DecodeBytes[chain.Predicate](stmt.Predicate)
	if err != nil {
		return nil, false, fmt.Errorf("predicate: %w", err)
	}

	return pred.Ledger()
}

// requirePredecessor proves the link was signed against the ledger as
// it stands NOW: the revision carries no link yet, and the nearest
// linked first-parent ancestor — the tip of that revision's chain —
// is the predecessor the link names, by revision and by the hash of
// its stored note. A genesis link requires there be no link at all on
// its history. Anything else means the ledger moved after the signing
// half read it, and only a fresh signing run can answer that.
func requirePredecessor(g LedgerGit, rev string, ptr *chain.Pointer, genesis bool) error {
	own, err := g.Note(rev)
	if err != nil {
		return fmt.Errorf("emit: note for %s: %w", rev, err)
	}

	if _, isLink := decodeLink(own); isLink {
		return fmt.Errorf("emit: the ledger moved under this run — %s already carries a link; re-run the signing job",
			rev)
	}

	tail, tailNote, err := ledgerTip(g, rev)
	if err != nil {
		return err
	}

	if genesis {
		if tail != "" {
			return fmt.Errorf("emit: genesis refused — a chain link already exists on this history (at %s); a gap is"+
				" debt, not a new founding", tail)
		}

		return nil
	}

	if tail == "" {
		return fmt.Errorf("emit: the link for %s names predecessor %s, but no link exists on its history — the ledger"+
			" moved under this run; re-run the signing job", rev, *ptr.Revision)
	}

	if got := chain.SHA256Hex(tailNote); *ptr.Revision != tail || *ptr.NoteSHA256 != got {
		return fmt.Errorf("emit: the ledger moved under this run — the link for %s names predecessor %s (note %s),"+
			" but the tip of its chain is %s (note %s); re-run the signing job",
			rev, *ptr.Revision, *ptr.NoteSHA256, tail, got)
	}

	return nil
}

// ledgerTip walks first-parent from rev's parent to the nearest
// revision carrying a link, returning it and its stored note, or ""
// when the history carries none.
//
//nolint:gocritic // unnamedResult: the revision, its stored note, and the refusal
func ledgerTip(g LedgerGit, rev string) (string, []byte, error) {
	c, err := g.Parent(rev)
	if err != nil {
		return "", nil, fmt.Errorf("emit: parent of %s: %w", rev, err)
	}

	for c != "" {
		note, nerr := g.Note(c)
		if nerr != nil {
			return "", nil, fmt.Errorf("emit: note for %s: %w", c, nerr)
		}

		if _, isLink := decodeLink(note); isLink {
			return c, note, nil
		}

		next, perr := g.Parent(c)
		if perr != nil {
			return "", nil, fmt.Errorf("emit: parent of %s: %w", c, perr)
		}

		c = next
	}

	return "", nil, nil
}

// pendingLink is the ledger as it would stand with one more link: the
// verify walk reads it exactly as it reads a repository, from the
// revision being appended as the branch's tip. Nothing is written
// until the walk has passed over it.
type pendingLink struct {
	verify.History

	rev  string
	note []byte
}

// Tip answers the one ref this walk is asked about with the revision
// being appended: the walk judges the chain the append would leave,
// whether or not the branch has moved past it since.
func (h *pendingLink) Tip(string) (string, error) {
	return h.rev, nil
}

func (h *pendingLink) Note(rev string) ([]byte, error) {
	if rev == h.rev {
		return h.note, nil
	}

	return h.History.Note(rev)
}

func (h *pendingLink) Noted() ([]string, error) {
	noted, err := h.History.Noted()
	if err != nil {
		return nil, err
	}

	if slices.Contains(noted, h.rev) {
		return noted, nil
	}

	return append(noted, h.rev), nil
}
