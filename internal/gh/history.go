// A source history read from the forge, with no clone.
//
// The chain walk and the property evaluators both need a branch's
// revisions and the notes hanging off them. Requiring a local clone to
// get them makes the tool something you set up before you can use;
// every fact here is already served by the forge's own API, to anyone,
// so the tool fetches them itself.
//
// The type satisfies the walk's History surface structurally — this
// package deliberately does not import the engine, because a forge
// client that knew about verdicts would be a layer inversion.

package gh

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// History reads one repository's branch and notes from the forge.
// Notes are fetched once and indexed: a walk asks about many
// revisions, and a request per revision would turn one read into
// hundreds.
type History struct {
	Reader   TagReader
	Owner    string
	Repo     string
	NotesRef string

	notes   map[string][]byte
	commits map[string]*CommitMeta
}

// RefResolver resolves a fully qualified ref to the commit it names.
// Separate from TagReader because a branch tip is not a tag read, and
// widening the tag surface to carry it would make every tag consumer
// depend on branches.
type RefResolver interface {
	Ref(owner, repo, ref string) (string, error)
}

// Ref implements RefResolver: any fully qualified ref to its commit.
func (c *Client) Ref(owner, repo, ref string) (string, error) {
	refPath := strings.TrimPrefix(ref, "refs/")

	body, ok, err := c.get(fmt.Sprintf("/repos/%s/%s/git/ref/%s", owner, repo, refPath), ghJSON)
	if err != nil {
		return "", err
	}

	if !ok {
		return "", fmt.Errorf("gh: %s/%s has no ref %s", owner, repo, ref)
	}

	entry, err := jsonx.DecodeForeign[refEntry](body)
	if err != nil || entry.Object == nil || entry.Object.SHA == nil {
		return "", fmt.Errorf("gh: ref %s of %s/%s: %w", ref, owner, repo, err)
	}

	return *entry.Object.SHA, nil
}

// Tip resolves a fully qualified ref to its commit.
func (h *History) Tip(ref string) (string, error) {
	resolver, ok := h.Reader.(RefResolver)
	if !ok {
		return "", fmt.Errorf("gh: this reader cannot resolve %s — no ref surface", ref)
	}

	return resolver.Ref(h.Owner, h.Repo, ref)
}

// Parent returns the first parent, or "" at a root commit.
func (h *History) Parent(rev string) (string, error) {
	meta, err := h.commit(rev)
	if err != nil {
		return "", err
	}

	if len(meta.Parents) == 0 {
		return "", nil
	}

	return meta.Parents[0], nil
}

// Note returns the raw note blob bytes for rev, or nil when none
// exists there.
//
// Raw matters: the ledger's noteSha256 covers the blob exactly as
// stored, so a byte the transport adds or strips is a broken chain
// rather than a cosmetic difference. The forge serves blob content
// verbatim; that equality is the one thing to re-measure against a
// live ledger before trusting this path.
func (h *History) Note(rev string) ([]byte, error) {
	if err := h.loadNotes(); err != nil {
		return nil, err
	}

	return h.notes[rev], nil
}

// Noted lists every revision carrying a note.
func (h *History) Noted() ([]string, error) {
	if err := h.loadNotes(); err != nil {
		return nil, err
	}

	out := make([]string, 0, len(h.notes))
	for rev := range h.notes {
		out = append(out, rev)
	}

	sort.Strings(out)

	return out, nil
}

// Revisions lists the branch's revisions from the tip back to the
// oldest one at or after since, newest first — the continuity window
// a property evaluator judges.
//
// The parent COUNT is reported from the full parent list even though
// the walk follows first parents: a merge commit must be visible as a
// merge, since that is the property an evaluator is looking for.
func (h *History) Revisions(ref string, since time.Time) ([]Revision, error) {
	rev, err := h.Tip(ref)
	if err != nil {
		return nil, err
	}

	var out []Revision

	for rev != "" {
		meta, merr := h.commit(rev)
		if merr != nil {
			return nil, merr
		}

		when := time.Unix(meta.CommitEpoch, 0).UTC()
		if when.Before(since) {
			break // outside the window this claim covers
		}

		out = append(out, Revision{
			ID: rev, Subject: meta.Subject, Parents: len(meta.Parents), Time: when,
		})

		if len(meta.Parents) == 0 {
			break
		}

		rev = meta.Parents[0]
	}

	return out, nil
}

// Revision is one revision as an evaluator reads it.
type Revision struct {
	ID      string
	Subject string
	Parents int
	Time    time.Time
}

// commit reads one commit's metadata, once.
func (h *History) commit(rev string) (*CommitMeta, error) {
	if h.commits == nil {
		h.commits = map[string]*CommitMeta{}
	}

	if got, ok := h.commits[rev]; ok {
		return got, nil
	}

	meta, err := h.Reader.CommitMeta(h.Owner, h.Repo, rev)
	if err != nil {
		return nil, err
	}

	h.commits[rev] = meta

	return meta, nil
}

// loadNotes fetches the whole notes ref once and indexes it.
func (h *History) loadNotes() error {
	if h.notes != nil {
		return nil
	}

	notes, err := h.Reader.ChainNotes(h.Owner, h.Repo, h.NotesRef)
	if err != nil {
		return err
	}

	h.notes = make(map[string][]byte, len(notes))
	for _, n := range notes {
		h.notes[n.Rev] = n.Note
	}

	return nil
}
