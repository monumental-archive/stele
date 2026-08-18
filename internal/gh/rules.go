// The rules read surface (stele#40): the effective enforcement state
// a claims derivation is built from. A separate interface from Forge
// and from TagReader, for the reason both of those are separate —
// the evidence walk does not read rules, and a fake that scripts
// rules should not have to script releases.
//
// Everything here returns RAW BYTES rather than a decoded shape, and
// that is deliberate. The claims engine matches a policy-declared
// tree against whatever the forge actually serves; a Go type in the
// middle would be a third statement of the rules schema (beside the
// forge's and the org's frozen table) and the one most likely to be
// stale. The seam's job is to fetch honestly and to say which of
// found / forbidden / broken happened — not to interpret.

package gh

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// RulesReader is the enforcement-state surface a claims derivation
// reads through.
type RulesReader interface {
	// BranchRules returns the effective rules for one branch, every
	// contributing ruleset already merged by the forge.
	BranchRules(owner, repo, branch string) ([]byte, error)
	// Rulesets lists the repository's rulesets, inherited ones
	// included.
	Rulesets(owner, repo string) ([]byte, error)
	// Ruleset returns one ruleset's full detail.
	Ruleset(owner, repo string, id int64) ([]byte, error)
}

// rulesBase is the path prefix every read below shares.
func rulesBase(owner, repo string) string {
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)
}

// BranchRules implements RulesReader.
//
// A branch under no rules answers 200 with an empty array, so a 404
// here is the repository or the branch not existing — a failure, not
// an empty rule set. Conflating them is exactly what the claims
// engine's blindness guard exists to prevent, and the distinction has
// to survive this far down to be available up there.
func (c *Client) BranchRules(owner, repo, branch string) ([]byte, error) {
	path := rulesBase(owner, repo) + "/rules/branches/" + url.PathEscape(branch)

	pages, err := c.paged(path)
	if err != nil {
		return nil, err
	}

	return mergeArrays(path, pages)
}

// Rulesets implements RulesReader. includes_parents brings in the
// org-level rulesets, which is where the tag controls live.
func (c *Client) Rulesets(owner, repo string) ([]byte, error) {
	path := rulesBase(owner, repo) + "/rulesets"

	pages, err := c.paged(path, "includes_parents=true")
	if err != nil {
		return nil, err
	}

	return mergeArrays(path, pages)
}

// Ruleset implements RulesReader. Listed-but-unreadable is an error,
// never an empty answer: it means the credential cannot see org-level
// ruleset content, and a derivation that read that as absence would
// drop exactly the controls it could not see.
func (c *Client) Ruleset(owner, repo string, id int64) ([]byte, error) {
	path := rulesBase(owner, repo) + "/rulesets/" + strconv.FormatInt(id, 10)

	body, ok, err := c.get(path, ghJSON)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("gh: %s: not found", path)
	}

	return body, nil
}

// mergeArrays folds a paginated listing into one JSON array. The
// pages are the forge's; the concatenation is ours, so it is done by
// decoding and re-encoding rather than by splicing bytes.
func mergeArrays(path string, pages [][]byte) ([]byte, error) {
	all := []any{}

	for _, page := range pages {
		v, err := jsonx.Value(page)
		if err != nil {
			return nil, fmt.Errorf("gh: %s: %w", path, err)
		}

		entries, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("gh: %s: a page is not a list", path)
		}

		all = append(all, entries...)
	}

	merged, err := jsonx.Marshal(all)
	if err != nil {
		return nil, fmt.Errorf("gh: %s: %w", path, err)
	}

	return merged, nil
}

// --- RulesReader snapshot/replay (stele#40) ---
//
// Raw bytes on both legs: the claims engine matches against exactly
// what the forge served, so a snapshot that re-rendered the JSON
// would be replaying a paraphrase. What is written is what was read.

// rulesPath names one recorded rules read.
func rulesPath(owner, repo string, parts ...string) string {
	return filepath.Join(append([]string{seg(owner), seg(repo), "rules"}, parts...)...)
}

// BranchRules implements RulesReader.
func (s Snapshot) BranchRules(owner, repo, branch string) ([]byte, error) {
	return s.readRaw(rulesPath(owner, repo, "branches", seg(branch)+".json"))
}

// Rulesets implements RulesReader.
func (s Snapshot) Rulesets(owner, repo string) ([]byte, error) {
	return s.readRaw(rulesPath(owner, repo, "rulesets.json"))
}

// Ruleset implements RulesReader.
func (s Snapshot) Ruleset(owner, repo string, id int64) ([]byte, error) {
	return s.readRaw(rulesPath(owner, repo, "rulesets", strconv.FormatInt(id, 10)+".json"))
}

// readRaw replays one recorded rules read.
func (s Snapshot) readRaw(path string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, path)) //nolint:gosec // the snapshot dir is operator-supplied by design
	if err != nil {
		return nil, fmt.Errorf("gh: snapshot %s: %w", path, err)
	}

	return b, nil
}

// BranchRules implements RulesReader.
func (c Capture) BranchRules(owner, repo, branch string) ([]byte, error) {
	return c.captureRaw(rulesPath(owner, repo, "branches", seg(branch)+".json"),
		func(r RulesReader) ([]byte, error) { return r.BranchRules(owner, repo, branch) })
}

// Rulesets implements RulesReader.
func (c Capture) Rulesets(owner, repo string) ([]byte, error) {
	return c.captureRaw(rulesPath(owner, repo, "rulesets.json"),
		func(r RulesReader) ([]byte, error) { return r.Rulesets(owner, repo) })
}

// Ruleset implements RulesReader.
func (c Capture) Ruleset(owner, repo string, id int64) ([]byte, error) {
	return c.captureRaw(rulesPath(owner, repo, "rulesets", strconv.FormatInt(id, 10)+".json"),
		func(r RulesReader) ([]byte, error) { return r.Ruleset(owner, repo, id) })
}

// captureRaw performs one live rules read and records its bytes.
func (c Capture) captureRaw(path string, read func(RulesReader) ([]byte, error)) ([]byte, error) {
	body, err := read(c.rulesLive())
	if err != nil {
		return nil, err
	}

	if err := c.writeFile(path, body); err != nil {
		return nil, err
	}

	return body, nil
}

// rulesLive asserts the wrapped Forge also reads rules — the live
// client does; a capture over anything else is a wiring defect and
// refuses by name, like tagLive.
//
//nolint:ireturn // the reader seam is the point
func (c Capture) rulesLive() RulesReader {
	rr, ok := c.Live.(RulesReader)
	if !ok {
		return failingRulesReader{}
	}

	return rr
}

// failingRulesReader refuses every read: the capture was wired over a
// Forge that cannot read rules.
type failingRulesReader struct{}

var errNotRulesReader = errors.New("gh: capture wraps a Forge that is not a RulesReader")

func (failingRulesReader) BranchRules(string, string, string) ([]byte, error) {
	return nil, errNotRulesReader
}

func (failingRulesReader) Rulesets(string, string) ([]byte, error) { return nil, errNotRulesReader }

func (failingRulesReader) Ruleset(string, string, int64) ([]byte, error) {
	return nil, errNotRulesReader
}
