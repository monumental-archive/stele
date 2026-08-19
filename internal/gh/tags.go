// The tag-audit read surface (stele#83): tag refs, tag objects with
// their signature material, the chain notes tree, commit metadata and
// ancestry. A separate interface from Forge — the evidence walk does
// not need it, and a fake that scripts tags should not have to script
// releases.

package gh

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// ghJSON is the REST accept type every read here asks for.
const ghJSON = "application/vnd.github+json"

// revHex40RE is a full git revision identifier.
var revHex40RE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// TagRef is one tag ref: its short name, the object it points at,
// and whether that object is an annotated tag.
type TagRef struct {
	Name      string
	ObjectSHA string
	Annotated bool
}

// TagObject is one annotated tag's substance: the tagger name, the
// commit it targets, and the signature material — Payload is the tag
// object with the signature block removed, Signature the PEM block,
// nil when the tag is unsigned.
type TagObject struct {
	Tagger    string
	Target    string
	Payload   []byte
	Signature []byte
}

// ChainNote is one note blob keyed by the revision it annotates.
type ChainNote struct {
	Rev  string
	Note jsonx.Raw
}

// CommitMeta is what genesis derivation needs of one commit: its
// parents and its committer time.
type CommitMeta struct {
	Parents     []string
	CommitEpoch int64
	// Subject is the first line of the commit message — what a
	// history-shape evaluator judges. Read here rather than in a
	// second call: the commit object already carries it.
	Subject string
}

// TagReader is the read surface the tag audit judges through.
type TagReader interface {
	// TagRefs lists every tag ref of one repository.
	TagRefs(owner, repo string) ([]TagRef, error)
	// TagObject reads one annotated tag object.
	TagObject(owner, repo, sha string) (*TagObject, error)
	// ChainNotes reads every note blob on the given notes ref. An
	// absent ref is an empty chain — an answer, not an error.
	ChainNotes(owner, repo, notesRef string) ([]ChainNote, error)
	// CommitMeta reads one commit's parents and committer time.
	CommitMeta(owner, repo, rev string) (*CommitMeta, error)
	// IsAncestor reports whether base is an ancestor of head.
	IsAncestor(owner, repo, base, head string) (bool, error)
}

type refEntry struct {
	Ref    *string `json:"ref"`
	Object *struct {
		Type *string `json:"type"`
		SHA  *string `json:"sha"`
	} `json:"object"`
}

// TagRefs implements TagReader.
func (c *Client) TagRefs(owner, repo string) ([]TagRef, error) {
	pages, err := c.paged(fmt.Sprintf("/repos/%s/%s/git/matching-refs/tags/", owner, repo))
	if err != nil {
		return nil, err
	}

	var out []TagRef

	for _, page := range pages {
		entries, derr := jsonx.DecodeForeign[[]refEntry](page)
		if derr != nil {
			return nil, fmt.Errorf("gh: tag refs of %s/%s: %w", owner, repo, derr)
		}

		for _, e := range *entries {
			if e.Ref == nil || e.Object == nil || e.Object.SHA == nil || e.Object.Type == nil {
				return nil, fmt.Errorf("gh: tag refs of %s/%s: entry missing ref, type or sha", owner, repo)
			}

			out = append(out, TagRef{
				Name:      strings.TrimPrefix(*e.Ref, "refs/tags/"),
				ObjectSHA: *e.Object.SHA,
				Annotated: *e.Object.Type == "tag",
			})
		}
	}

	return out, nil
}

type tagObjectEntry struct {
	Tagger *struct {
		Name *string `json:"name"`
	} `json:"tagger"`
	Object *struct {
		SHA *string `json:"sha"`
	} `json:"object"`
	Verification *struct {
		Payload   *string `json:"payload"`
		Signature *string `json:"signature"`
	} `json:"verification"`
}

// TagObject implements TagReader.
func (c *Client) TagObject(owner, repo, sha string) (*TagObject, error) {
	body, ok, err := c.get(fmt.Sprintf("/repos/%s/%s/git/tags/%s", owner, repo, sha), ghJSON)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("gh: tag object %s of %s/%s does not exist", sha, owner, repo)
	}

	entry, err := jsonx.DecodeForeign[tagObjectEntry](body)
	if err != nil {
		return nil, fmt.Errorf("gh: tag object %s of %s/%s: %w", sha, owner, repo, err)
	}

	if entry.Tagger == nil || entry.Tagger.Name == nil || entry.Object == nil || entry.Object.SHA == nil {
		return nil, fmt.Errorf("gh: tag object %s of %s/%s: missing tagger or target", sha, owner, repo)
	}

	out := &TagObject{Tagger: *entry.Tagger.Name, Target: *entry.Object.SHA}

	if v := entry.Verification; v != nil {
		if v.Payload != nil {
			out.Payload = []byte(*v.Payload)
		}

		if v.Signature != nil {
			out.Signature = []byte(*v.Signature)
		}
	}

	return out, nil
}

// ChainNotes implements TagReader: the notes ref resolved to its
// tree, every blob fetched, keyed by the revision its path names
// (fanout directories collapse — git shards note paths by hex
// prefix).
func (c *Client) ChainNotes(owner, repo, notesRef string) ([]ChainNote, error) {
	refPath := strings.TrimPrefix(notesRef, "refs/")

	body, ok, err := c.get(fmt.Sprintf("/repos/%s/%s/git/ref/%s", owner, repo, refPath), ghJSON)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, nil // no notes ref: an empty chain is an answer
	}

	ref, err := jsonx.DecodeForeign[refEntry](body)
	if err != nil || ref.Object == nil || ref.Object.SHA == nil {
		return nil, fmt.Errorf("gh: notes ref of %s/%s: %w", owner, repo, err)
	}

	return c.notesTree(owner, repo, *ref.Object.SHA)
}

type commitEntry struct {
	Message *string `json:"message"`
	Tree    *struct {
		SHA *string `json:"sha"`
	} `json:"tree"`
	Parents []struct {
		SHA *string `json:"sha"`
	} `json:"parents"`
	Committer *struct {
		Date *string `json:"date"`
	} `json:"committer"`
}

type treeEntry struct {
	Tree []struct {
		Path *string `json:"path"`
		Type *string `json:"type"`
		SHA  *string `json:"sha"`
	} `json:"tree"`
	Truncated *bool `json:"truncated"`
}

type blobEntry struct {
	Content  *string `json:"content"`
	Encoding *string `json:"encoding"`
}

// notesTree walks the notes commit's tree and fetches each blob.
func (c *Client) notesTree(owner, repo, commitSHA string) ([]ChainNote, error) {
	body, ok, err := c.get(fmt.Sprintf("/repos/%s/%s/git/commits/%s", owner, repo, commitSHA), ghJSON)
	if err != nil || !ok {
		return nil, fmt.Errorf("gh: notes commit of %s/%s: %w", owner, repo, err)
	}

	commit, err := jsonx.DecodeForeign[commitEntry](body)
	if err != nil || commit.Tree == nil || commit.Tree.SHA == nil {
		return nil, fmt.Errorf("gh: notes commit of %s/%s: %w", owner, repo, err)
	}

	body, ok, err = c.get(
		fmt.Sprintf("/repos/%s/%s/git/trees/%s?recursive=1", owner, repo, *commit.Tree.SHA), ghJSON)
	if err != nil || !ok {
		return nil, fmt.Errorf("gh: notes tree of %s/%s: %w", owner, repo, err)
	}

	tree, err := jsonx.DecodeForeign[treeEntry](body)
	if err != nil {
		return nil, fmt.Errorf("gh: notes tree of %s/%s: %w", owner, repo, err)
	}

	if tree.Truncated != nil && *tree.Truncated {
		return nil, fmt.Errorf("gh: notes tree of %s/%s is truncated — the chain cannot be read whole", owner, repo)
	}

	var out []ChainNote

	for _, e := range tree.Tree {
		if e.Path == nil || e.Type == nil || e.SHA == nil || *e.Type != "blob" {
			continue
		}

		rev := strings.ReplaceAll(*e.Path, "/", "")
		if !revHex40RE.MatchString(rev) {
			continue // scaffolding entries are not notes on revisions
		}

		note, nerr := c.blob(owner, repo, *e.SHA)
		if nerr != nil {
			return nil, nerr
		}

		out = append(out, ChainNote{Rev: rev, Note: note})
	}

	return out, nil
}

func (c *Client) blob(owner, repo, sha string) ([]byte, error) {
	body, ok, err := c.get(fmt.Sprintf("/repos/%s/%s/git/blobs/%s", owner, repo, sha), ghJSON)
	if err != nil || !ok {
		return nil, fmt.Errorf("gh: blob %s of %s/%s: %w", sha, owner, repo, err)
	}

	entry, err := jsonx.DecodeForeign[blobEntry](body)
	if err != nil || entry.Content == nil || entry.Encoding == nil || *entry.Encoding != "base64" {
		return nil, fmt.Errorf("gh: blob %s of %s/%s: not base64 content: %w", sha, owner, repo, err)
	}

	return decodeBase64Lenient(*entry.Content)
}

// CommitMeta implements TagReader.
func (c *Client) CommitMeta(owner, repo, rev string) (*CommitMeta, error) {
	body, ok, err := c.get(fmt.Sprintf("/repos/%s/%s/git/commits/%s", owner, repo, rev), ghJSON)
	if err != nil || !ok {
		return nil, fmt.Errorf("gh: commit %s of %s/%s: %w", rev, owner, repo, err)
	}

	entry, err := jsonx.DecodeForeign[commitEntry](body)
	if err != nil {
		return nil, fmt.Errorf("gh: commit %s of %s/%s: %w", rev, owner, repo, err)
	}

	out := &CommitMeta{}

	for _, p := range entry.Parents {
		if p.SHA != nil {
			out.Parents = append(out.Parents, *p.SHA)
		}
	}

	if entry.Message != nil {
		out.Subject, _, _ = strings.Cut(*entry.Message, "\n")
	}

	if entry.Committer != nil && entry.Committer.Date != nil {
		t, terr := time.Parse(time.RFC3339, *entry.Committer.Date)
		if terr != nil {
			return nil, fmt.Errorf("gh: commit %s of %s/%s: committer date: %w", rev, owner, repo, terr)
		}

		out.CommitEpoch = t.Unix()
	}

	return out, nil
}

type compareEntry struct {
	Status *string `json:"status"`
}

// IsAncestor implements TagReader via the compare API: base is an
// ancestor of head exactly when head is ahead of (or identical to)
// base.
func (c *Client) IsAncestor(owner, repo, base, head string) (bool, error) {
	body, ok, err := c.get(fmt.Sprintf("/repos/%s/%s/compare/%s...%s", owner, repo, base, head), ghJSON)
	if err != nil {
		return false, err
	}

	if !ok {
		return false, nil // unrelated histories compare as not-found
	}

	entry, err := jsonx.DecodeForeign[compareEntry](body)
	if err != nil || entry.Status == nil {
		return false, fmt.Errorf("gh: compare %s...%s of %s/%s: %w", base, head, owner, repo, err)
	}

	return *entry.Status == "ahead" || *entry.Status == "identical", nil
}
