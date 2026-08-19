// The snapshot leg of the seam: Capture wraps the live Forge and
// records every answer to a directory; Snapshot replays that
// directory as a Forge. Shadow runs feed the bash and Go legs the
// SAME captured bytes — with a live API, the two legs can genuinely
// see different states between reads, and divergence investigation
// chases phantoms. The layout is human-readable on purpose: a
// snapshot is also a test fixture and a fuzz corpus.

package gh

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// Snapshot file modes: a snapshot is shareable evidence, owner-writable.
const (
	dirPerm  = 0o750
	filePerm = 0o600
)

func decodeBase64Lenient(s string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(s, "\n", ""))
	if err != nil {
		return nil, fmt.Errorf("gh: base64: %w", err)
	}

	return decoded, nil
}

// Snapshot replays a captured directory as a Forge. A file absent
// from the snapshot is the recorded absence: capture is walk-driven,
// so the snapshot covers exactly what the walk read.
type Snapshot struct {
	Dir string
}

// seg escapes one path segment for the filesystem.
func seg(s string) string { return url.PathEscape(s) }

// decodeInto adapts the generic decode to a pointer target.
func decodeInto(raw jsonx.Raw, into any) error {
	switch t := into.(type) {
	case *[]string:
		v, err := jsonx.DecodeBytes[[]string](raw)
		if err != nil {
			return err
		}

		*t = *v
	case *string:
		v, err := jsonx.DecodeBytes[string](raw)
		if err != nil {
			return err
		}

		*t = *v
	case *[]jsonx.Raw:
		v, err := jsonx.DecodeBytes[[]jsonx.Raw](raw)
		if err != nil {
			return err
		}

		*t = *v
	case *[]TagRef:
		v, err := jsonx.DecodeBytes[[]TagRef](raw)
		if err != nil {
			return err
		}

		*t = *v
	case *TagObject:
		v, err := jsonx.DecodeBytes[TagObject](raw)
		if err != nil {
			return err
		}

		*t = *v
	case *[]ChainNote:
		v, err := jsonx.DecodeBytes[[]ChainNote](raw)
		if err != nil {
			return err
		}

		*t = *v
	case *CommitMeta:
		v, err := jsonx.DecodeBytes[CommitMeta](raw)
		if err != nil {
			return err
		}

		*t = *v
	case *bool:
		v, err := jsonx.DecodeBytes[bool](raw)
		if err != nil {
			return err
		}

		*t = *v
	default:
		return errors.New("unsupported snapshot decode target")
	}

	return nil
}

// Repos implements Forge.
func (s Snapshot) Repos(org string) ([]string, error) {
	var out []string
	if err := s.readJSON(filepath.Join(seg(org), "repos.json"), &out); err != nil {
		return nil, err
	}

	return out, nil
}

// ReleaseTags implements Forge.
func (s Snapshot) ReleaseTags(owner, repo string) ([]string, error) {
	var out []string
	if err := s.readJSON(filepath.Join(seg(owner), seg(repo), "tags.json"), &out); err != nil {
		return nil, err
	}

	return out, nil
}

// ReleaseAssets implements Forge.
func (s Snapshot) ReleaseAssets(owner, repo, tag string) ([]string, error) {
	var out []string
	if err := s.readJSON(filepath.Join(seg(owner), seg(repo), "releases", seg(tag), "assets.json"), &out); err != nil {
		return nil, err
	}

	return out, nil
}

// ReleaseDate implements Forge.
func (s Snapshot) ReleaseDate(owner, repo, tag string) (time.Time, error) {
	var stamped string
	if err := s.readJSON(filepath.Join(seg(owner), seg(repo), "releases", seg(tag), "published.json"),
		&stamped); err != nil {
		return time.Time{}, err
	}

	when, err := time.Parse(time.RFC3339, stamped)
	if err != nil {
		return time.Time{}, fmt.Errorf("gh: snapshot release %s/%s@%s: %w", owner, repo, tag, err)
	}

	return when, nil
}

// Asset implements Forge.
func (s Snapshot) Asset(owner, repo, tag, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, seg(owner), seg(repo), "releases", seg(tag), "assets", seg(name))) //nolint:lll // the nolint itself is what passes 120 columns
	if err != nil {
		return nil, fmt.Errorf("gh: snapshot asset %s@%s/%s: %w", repo, tag, name, err)
	}

	return b, nil
}

// FileAt implements Forge. Absence is recorded as a missing file.
//
//nolint:gocritic // unnamedResult: the Forge interface documents the results
func (s Snapshot) FileAt(owner, repo, path, ref string) ([]byte, bool, error) {
	b, rerr := os.ReadFile(filepath.Join(s.Dir, seg(owner), seg(repo), "files", seg(ref), seg(path))) //nolint:lll // the nolint itself is what passes 120 columns
	if errors.Is(rerr, fs.ErrNotExist) {
		return nil, false, nil
	}

	if rerr != nil {
		return nil, false, fmt.Errorf("gh: snapshot file %s:%s: %w", ref, path, rerr)
	}

	return b, true, nil
}

// Attestations implements Forge.
func (s Snapshot) Attestations(owner, repo, sha256Hex string) ([]jsonx.Raw, error) {
	p := filepath.Join(seg(owner), seg(repo), "attestations", sha256Hex+".json")
	if _, err := os.Stat(filepath.Join(s.Dir, p)); errors.Is(err, fs.ErrNotExist) {
		return nil, nil // recorded empty store
	}

	var out []jsonx.Raw
	if err := s.readJSON(p, &out); err != nil {
		return nil, err
	}

	return out, nil
}

// TagCommit implements Forge.
func (s Snapshot) TagCommit(owner, repo, tag string) (string, error) {
	var out string
	if err := s.readJSON(filepath.Join(seg(owner), seg(repo), "tagcommits", seg(tag)+".json"), &out); err != nil {
		return "", err
	}

	return out, nil
}

// PackageVersionDigest implements Forge.
func (s Snapshot) PackageVersionDigest(org, pkg, tag string) (string, error) {
	p := filepath.Join(seg(org), "packages", seg(pkg), seg(tag)+".json")
	if _, err := os.Stat(filepath.Join(s.Dir, p)); errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}

	var out string
	if err := s.readJSON(p, &out); err != nil {
		return "", err
	}

	return out, nil
}

// WorkflowContents implements Forge.
func (s Snapshot) WorkflowContents(owner, repo string) ([][]byte, error) {
	dir := filepath.Join(s.Dir, seg(owner), seg(repo), "workflows")

	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("gh: snapshot workflows of %s/%s: %w", owner, repo, err)
	}

	var out [][]byte

	for _, e := range entries {
		b, rerr := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // the snapshot dir is operator-supplied
		if rerr != nil {
			return nil, fmt.Errorf("gh: snapshot workflow %s: %w", e.Name(), rerr)
		}

		out = append(out, b)
	}

	return out, nil
}

// FailedRuns implements Forge.
func (s Snapshot) FailedRuns(owner, repo, branch string) ([]string, error) {
	p := filepath.Join(seg(owner), seg(repo), "runs", seg(branch)+".json")
	if _, err := os.Stat(filepath.Join(s.Dir, p)); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}

	var out []string
	if err := s.readJSON(p, &out); err != nil {
		return nil, err
	}

	return out, nil
}

// Capture wraps a live Forge and records every successful answer
// under Dir, so one run produces the snapshot both shadow legs then
// replay. Failures are not recorded: a snapshot holds facts, and a
// failed read is not a fact about the subject.
type Capture struct {
	Live Forge
	Dir  string
}

// Repos implements Forge.
func (c Capture) Repos(org string) ([]string, error) {
	out, err := c.Live.Repos(org)
	if err != nil {
		return nil, err
	}

	if err := c.writeJSON(filepath.Join(seg(org), "repos.json"), out); err != nil {
		return nil, err
	}

	return out, nil
}

// ReleaseTags implements Forge.
func (c Capture) ReleaseTags(owner, repo string) ([]string, error) {
	out, err := c.Live.ReleaseTags(owner, repo)
	if err != nil {
		return nil, err
	}

	if err := c.writeJSON(filepath.Join(seg(owner), seg(repo), "tags.json"), out); err != nil {
		return nil, err
	}

	return out, nil
}

// ReleaseAssets implements Forge.
func (c Capture) ReleaseAssets(owner, repo, tag string) ([]string, error) {
	out, err := c.Live.ReleaseAssets(owner, repo, tag)
	if err != nil {
		return nil, err
	}

	if err := c.writeJSON(filepath.Join(seg(owner), seg(repo), "releases", seg(tag), "assets.json"), out); err != nil {
		return nil, err
	}

	return out, nil
}

// ReleaseDate implements Forge.
func (c Capture) ReleaseDate(owner, repo, tag string) (time.Time, error) {
	out, err := c.Live.ReleaseDate(owner, repo, tag)
	if err != nil {
		return time.Time{}, err
	}

	if err := c.writeJSON(filepath.Join(seg(owner), seg(repo), "releases", seg(tag), "published.json"),
		out.Format(time.RFC3339)); err != nil {
		return time.Time{}, err
	}

	return out, nil
}

// Asset implements Forge.
func (c Capture) Asset(owner, repo, tag, name string) ([]byte, error) {
	out, err := c.Live.Asset(owner, repo, tag, name)
	if err != nil {
		return nil, err
	}

	dest := filepath.Join(seg(owner), seg(repo), "releases", seg(tag), "assets", seg(name))
	if err := c.writeFile(dest, out); err != nil {
		return nil, err
	}

	return out, nil
}

// FileAt implements Forge. Only presence is recorded; replay treats a
// missing file as the recorded absence.
//
//nolint:gocritic // unnamedResult: the Forge interface documents the results
func (c Capture) FileAt(owner, repo, path, ref string) ([]byte, bool, error) {
	out, found, err := c.Live.FileAt(owner, repo, path, ref)
	if err != nil || !found {
		return out, found, err
	}

	if werr := c.writeFile(filepath.Join(seg(owner), seg(repo), "files", seg(ref), seg(path)), out); werr != nil {
		return nil, false, werr
	}

	return out, true, nil
}

// Attestations implements Forge.
func (c Capture) Attestations(owner, repo, sha256Hex string) ([]jsonx.Raw, error) {
	out, err := c.Live.Attestations(owner, repo, sha256Hex)
	if err != nil {
		return nil, err
	}

	if len(out) == 0 {
		return out, nil // replay reads a missing file as the empty store
	}

	if err := c.writeJSON(filepath.Join(seg(owner), seg(repo), "attestations", sha256Hex+".json"), out); err != nil {
		return nil, err
	}

	return out, nil
}

// TagCommit implements Forge.
func (c Capture) TagCommit(owner, repo, tag string) (string, error) {
	out, err := c.Live.TagCommit(owner, repo, tag)
	if err != nil {
		return "", err
	}

	if werr := c.writeJSON(filepath.Join(seg(owner), seg(repo), "tagcommits", seg(tag)+".json"), out); werr != nil {
		return "", werr
	}

	return out, nil
}

// PackageVersionDigest implements Forge.
func (c Capture) PackageVersionDigest(org, pkg, tag string) (string, error) {
	out, err := c.Live.PackageVersionDigest(org, pkg, tag)
	if err != nil || out == "" {
		return out, err
	}

	if werr := c.writeJSON(filepath.Join(seg(org), "packages", seg(pkg), seg(tag)+".json"), out); werr != nil {
		return "", werr
	}

	return out, nil
}

// WorkflowContents implements Forge.
func (c Capture) WorkflowContents(owner, repo string) ([][]byte, error) {
	out, err := c.Live.WorkflowContents(owner, repo)
	if err != nil {
		return nil, err
	}

	for i, b := range out {
		name := fmt.Sprintf("%03d.yml", i)
		if werr := c.writeFile(filepath.Join(seg(owner), seg(repo), "workflows", name), b); werr != nil {
			return nil, werr
		}
	}

	return out, nil
}

// FailedRuns implements Forge.
func (c Capture) FailedRuns(owner, repo, branch string) ([]string, error) {
	out, err := c.Live.FailedRuns(owner, repo, branch)
	if err != nil {
		return nil, err
	}

	if err := c.writeJSON(filepath.Join(seg(owner), seg(repo), "runs", seg(branch)+".json"), out); err != nil {
		return nil, err
	}

	return out, nil
}

// --- TagReader snapshot/replay (stele#83) ---

// TagRefs implements TagReader.
func (s Snapshot) TagRefs(owner, repo string) ([]TagRef, error) {
	var out []TagRef
	if err := s.readJSON(filepath.Join(seg(owner), seg(repo), "tagrefs.json"), &out); err != nil {
		return nil, err
	}

	return out, nil
}

// TagObject implements TagReader.
func (s Snapshot) TagObject(owner, repo, sha string) (*TagObject, error) {
	out := &TagObject{}
	if err := s.readJSON(filepath.Join(seg(owner), seg(repo), "tagobjects", seg(sha)+".json"), out); err != nil {
		return nil, err
	}

	return out, nil
}

// ChainNotes implements TagReader.
func (s Snapshot) ChainNotes(owner, repo, notesRef string) ([]ChainNote, error) {
	p := filepath.Join(seg(owner), seg(repo), "notes", seg(notesRef)+".json")
	if _, err := os.Stat(filepath.Join(s.Dir, p)); errors.Is(err, fs.ErrNotExist) {
		return nil, nil // recorded empty chain
	}

	var out []ChainNote
	if err := s.readJSON(p, &out); err != nil {
		return nil, err
	}

	return out, nil
}

// CommitMeta implements TagReader.
func (s Snapshot) CommitMeta(owner, repo, rev string) (*CommitMeta, error) {
	out := &CommitMeta{}
	if err := s.readJSON(filepath.Join(seg(owner), seg(repo), "commits", seg(rev)+".json"), out); err != nil {
		return nil, err
	}

	return out, nil
}

// IsAncestor implements TagReader.
func (s Snapshot) IsAncestor(owner, repo, base, head string) (bool, error) {
	var out bool

	dest := filepath.Join(seg(owner), seg(repo), "ancestry", seg(base+"..."+head)+".json")
	if err := s.readJSON(dest, &out); err != nil {
		return false, err
	}

	return out, nil
}

// TagRefs implements TagReader.
func (c Capture) TagRefs(owner, repo string) ([]TagRef, error) {
	out, err := c.tagLive().TagRefs(owner, repo)
	if err != nil {
		return nil, err
	}

	if err := c.writeJSON(filepath.Join(seg(owner), seg(repo), "tagrefs.json"), out); err != nil {
		return nil, err
	}

	return out, nil
}

// TagObject implements TagReader.
func (c Capture) TagObject(owner, repo, sha string) (*TagObject, error) {
	out, err := c.tagLive().TagObject(owner, repo, sha)
	if err != nil {
		return nil, err
	}

	if err := c.writeJSON(filepath.Join(seg(owner), seg(repo), "tagobjects", seg(sha)+".json"), out); err != nil {
		return nil, err
	}

	return out, nil
}

// ChainNotes implements TagReader.
func (c Capture) ChainNotes(owner, repo, notesRef string) ([]ChainNote, error) {
	out, err := c.tagLive().ChainNotes(owner, repo, notesRef)
	if err != nil {
		return nil, err
	}

	if out == nil {
		return nil, nil // recorded absence: no file, like FileAt
	}

	if err := c.writeJSON(filepath.Join(seg(owner), seg(repo), "notes", seg(notesRef)+".json"), out); err != nil {
		return nil, err
	}

	return out, nil
}

// CommitMeta implements TagReader.
func (c Capture) CommitMeta(owner, repo, rev string) (*CommitMeta, error) {
	out, err := c.tagLive().CommitMeta(owner, repo, rev)
	if err != nil {
		return nil, err
	}

	if err := c.writeJSON(filepath.Join(seg(owner), seg(repo), "commits", seg(rev)+".json"), out); err != nil {
		return nil, err
	}

	return out, nil
}

// IsAncestor implements TagReader.
func (c Capture) IsAncestor(owner, repo, base, head string) (bool, error) {
	out, err := c.tagLive().IsAncestor(owner, repo, base, head)
	if err != nil {
		return false, err
	}

	dest := filepath.Join(seg(owner), seg(repo), "ancestry", seg(base+"..."+head)+".json")
	if err := c.writeJSON(dest, out); err != nil {
		return false, err
	}

	return out, nil
}

// Ref implements RefResolver over the snapshot. A ref never captured
// replays as the error the live client reports for a missing ref —
// capture records facts, and a resolve that failed recorded nothing.
func (s Snapshot) Ref(owner, repo, ref string) (string, error) {
	var out string
	if err := s.readJSON(filepath.Join(seg(owner), seg(repo), "refs", seg(ref)+".json"), &out); err != nil {
		return "", err
	}

	return out, nil
}

// Ref implements RefResolver, recording through.
func (c Capture) Ref(owner, repo, ref string) (string, error) {
	resolver, ok := c.Live.(RefResolver)
	if !ok {
		return "", errors.New("gh: capture wraps a Forge that is not a RefResolver")
	}

	out, err := resolver.Ref(owner, repo, ref)
	if err != nil {
		return "", err
	}

	if werr := c.writeJSON(filepath.Join(seg(owner), seg(repo), "refs", seg(ref)+".json"), out); werr != nil {
		return "", werr
	}

	return out, nil
}

// tagLive asserts the wrapped Forge also reads tags — the live
// client does; a capture over anything else is a wiring defect and
// refuses by name.
//
//nolint:ireturn // the reader seam is the point
func (c Capture) tagLive() TagReader {
	tr, ok := c.Live.(TagReader)
	if !ok {
		return failingTagReader{}
	}

	return tr
}

// failingTagReader refuses every read: the capture was wired over a
// Forge that cannot read tags.
type failingTagReader struct{}

var errNotTagReader = errors.New("gh: capture wraps a Forge that is not a TagReader")

func (failingTagReader) TagRefs(string, string) ([]TagRef, error) { return nil, errNotTagReader }

func (failingTagReader) TagObject(string, string, string) (*TagObject, error) {
	return nil, errNotTagReader
}

func (failingTagReader) ChainNotes(string, string, string) ([]ChainNote, error) {
	return nil, errNotTagReader
}

func (failingTagReader) CommitMeta(string, string, string) (*CommitMeta, error) {
	return nil, errNotTagReader
}

func (failingTagReader) IsAncestor(string, string, string, string) (bool, error) {
	return false, errNotTagReader
}

func (s Snapshot) readJSON(path string, into any) error {
	b, err := os.ReadFile(filepath.Join(s.Dir, path)) //nolint:gosec // the snapshot dir is operator-supplied by design
	if err != nil {
		return fmt.Errorf("gh: snapshot %s: %w", path, err)
	}

	decoded, err := jsonx.DecodeBytes[jsonx.Raw](b)
	if err != nil {
		return fmt.Errorf("gh: snapshot %s: %w", path, err)
	}

	if err := decodeInto(*decoded, into); err != nil {
		return fmt.Errorf("gh: snapshot %s: %w", path, err)
	}

	return nil
}

func (c Capture) writeJSON(path string, v any) error {
	raw, err := jsonx.Marshal(v)
	if err != nil {
		return fmt.Errorf("gh: capture %s: %w", path, err)
	}

	return c.writeFile(path, raw)
}

func (c Capture) writeFile(path string, b []byte) error {
	full := filepath.Join(c.Dir, path)

	if err := os.MkdirAll(filepath.Dir(full), dirPerm); err != nil {
		return fmt.Errorf("gh: capture %s: %w", path, err)
	}

	if err := os.WriteFile(full, b, filePerm); err != nil {
		return fmt.Errorf("gh: capture %s: %w", path, err)
	}

	return nil
}
