// The evidence contract: which classes a release owes. The general
// mechanism is DECLARED data — a release carries its own manifest,
// attested and immutable at the tag. The workflow adapter below is
// the quarantined org-convention fallback for history: releases
// published before the manifest existed declared their classes only
// in the caller's publish workflow at the tag, so that read survives
// as one ContractSource with a sunset, never as the shape of the
// tool.

package assert

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// Contract is what one release owes.
type Contract struct {
	// Classes are the evidence classes the release declared.
	Classes []string
	// StoreVSA reports whether verdicts live in the attestation store
	// (as opposed to legacy VSA bundle assets on the release).
	StoreVSA bool
	// Origin names where the contract was read from, for the report.
	Origin string
}

// ContractSource resolves one release's contract. ok=false means the
// source has no contract for this release — the caller may fall
// through to the next source, and a release no source can speak for
// is legacy.
type ContractSource interface {
	Contract(owner, repo, tag string) (c *Contract, ok bool, err error)
}

// manifestDoc is the release evidence manifest — stele's own format,
// decoded strictly (docs/assert-policy-schema.md).
type manifestDoc struct {
	Schema   *int     `json:"schema"`
	Classes  []string `json:"classes"`
	StoreVSA *bool    `json:"storeVsa"`
}

// ManifestSource reads the release's own evidence manifest asset.
type ManifestSource struct {
	Forge gh.Forge
	Asset string
}

// Contract implements ContractSource.
func (m ManifestSource) Contract(owner, repo, tag string) (*Contract, bool, error) {
	assets, err := m.Forge.ReleaseAssets(owner, repo, tag)
	if err != nil {
		return nil, false, fmt.Errorf("assert: contract of %s/%s@%s: %w", owner, repo, tag, err)
	}

	found := slices.Contains(assets, m.Asset)

	if !found {
		return nil, false, nil
	}

	raw, err := m.Forge.Asset(owner, repo, tag, m.Asset)
	if err != nil {
		return nil, false, fmt.Errorf("assert: manifest of %s/%s@%s: %w", owner, repo, tag, err)
	}

	doc, err := jsonx.DecodeBytes[manifestDoc](raw)
	if err != nil {
		return nil, false, fmt.Errorf("assert: manifest of %s/%s@%s: %w", owner, repo, tag, err)
	}

	if doc.Schema == nil || *doc.Schema != 1 || len(doc.Classes) == 0 || doc.StoreVSA == nil {
		return nil, false, fmt.Errorf(
			"assert: manifest of %s/%s@%s: schema, classes and storeVsa are all required", owner, repo, tag)
	}

	return &Contract{Classes: doc.Classes, StoreVSA: *doc.StoreVSA, Origin: "manifest " + m.Asset}, true, nil
}

// WorkflowSource is the GitHub-workflow-convention adapter: the
// classes a release owes are read from the caller's publish workflow
// AT THE TAG — the only honest source for releases that predate the
// manifest. The parsing mirrors what the callers actually wrote
// (a `classes:` input line; the canon's own publish.yml is a
// reusable, so its caller stub is self-publish.yml), and the canon
// version comes from the pin comment on the uses: line, the tag
// itself for the canon repo.
type WorkflowSource struct {
	Forge  gh.Forge
	Policy *EvidencePolicy
}

var (
	workflowCallRE = regexp.MustCompile(`(?m)^\s*workflow_call:`)
	classesRE      = regexp.MustCompile(`(?m)^[^#\n]*classes:\s*(.+)$`)
	pinCommentRE   = regexp.MustCompile(`uses:.*(?:publish|release)\.ya?ml@[^#\n]*#\s*v(\d+\.\d+\.\d+)`)
)

// Contract implements ContractSource.
func (w WorkflowSource) Contract(owner, repo, tag string) (*Contract, bool, error) {
	wf, ok, err := w.Forge.FileAt(owner, repo, ".github/workflows/publish.yml", tag)
	if err != nil {
		return nil, false, fmt.Errorf("assert: workflow contract of %s/%s@%s: %w", owner, repo, tag, err)
	}

	if !ok {
		return nil, false, nil
	}

	if workflowCallRE.Match(wf) {
		wf, ok, err = w.Forge.FileAt(owner, repo, ".github/workflows/self-publish.yml", tag)
		if err != nil {
			return nil, false, fmt.Errorf("assert: workflow contract of %s/%s@%s: %w", owner, repo, tag, err)
		}

		if !ok {
			return nil, false, nil
		}
	}

	m := classesRE.FindSubmatch(wf)
	if m == nil {
		return nil, false, nil
	}

	classes := splitClasses(string(m[1]))
	if len(classes) == 0 {
		return nil, false, nil
	}

	// The canon version pinned at the tag decides the verdict
	// obligation's shape; the canon's own stub uses a local reference,
	// so its version is the tag itself.
	canonVersion := strings.TrimPrefix(tag, "v")
	if pm := pinCommentRE.FindSubmatch(wf); pm != nil {
		canonVersion = string(pm[1])
	}

	return &Contract{
		Classes:  classes,
		StoreVSA: w.Policy.storeVSA(canonVersion),
		Origin:   "publish workflow at " + tag,
	}, true, nil
}

// splitClasses reads the workflow input's class list. The separator
// is a COMMA (the canon writes `classes: rust-binary,oci-image,…`,
// and the bash matched it as `case ",${classes// /}," in *",X,"*`);
// splitting on whitespace instead takes the whole list as one class
// name, which the first live shadow run against the org caught on 17
// releases. Surrounding quotes and spaces are noise either way.
func splitClasses(raw string) []string {
	var out []string

	for part := range strings.SplitSeq(strings.Trim(strings.TrimSpace(raw), `"'`), ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}

	return out
}

// Sources tries each source in order; the first that speaks for the
// release wins. No source speaking means legacy.
type Sources []ContractSource

// Contract implements ContractSource.
func (s Sources) Contract(owner, repo, tag string) (*Contract, bool, error) {
	for _, src := range s {
		c, ok, err := src.Contract(owner, repo, tag)
		if err != nil {
			return nil, false, err
		}

		if ok {
			return c, true, nil
		}
	}

	return nil, false, nil
}
