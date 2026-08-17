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
	case *[]jsonx.Raw:
		v, err := jsonx.DecodeBytes[[]jsonx.Raw](raw)
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
