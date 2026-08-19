// The evidence contract: which classes a release owes. The general
// mechanism is DECLARED data — a release carries its own manifest,
// attested and immutable at the tag, and that is the whole story for
// any adopter starting now. The workflow adapter below is the
// quarantined fallback for the FIRST consumer's history: releases
// published before the manifest existed declared their classes only
// in the caller's publish workflow at the tag, so that read survives
// as one ContractSource with a sunset, never as the shape of the
// tool. An adopter without that convention never meets it — a
// release neither source speaks for is legacy, owed nothing, named
// in the report.

package assert

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/monumental-archive/stele/internal/evidence"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/verify"
)

// Contract is what one release owes.
type Contract struct {
	// Classes are the evidence classes the release declared.
	Classes []string
	// StoreVSA reports whether verdicts live in the attestation store
	// (as opposed to legacy VSA bundle assets on the release).
	StoreVSA bool
	// Decision reports whether the release owes a verifiable release
	// decision — false only for releases whose machinery version predates
	// the decision epoch (grandfathered history).
	Decision bool
	// Enrichment reports whether the release owes a build-enrichment
	// claim — same epoch semantics as Decision (stele#109). Carried on
	// the contract for the deep walk's verify leg (#86) to consume.
	Enrichment bool
	// MachineryVersion is the version every epoch above was judged
	// against, carried so obligations that live per-class rather than
	// top-level (assetPrefixes' owedFrom, stele#128) can be judged
	// where the class list joins the policy — the semantics stay in
	// the one owedFrom definition, never a second reading here.
	MachineryVersion string
	// Origin names where the contract was read from, for the report.
	Origin string
}

// EnrichmentDemand derives what this release owes its enrichment
// claim from its declared classes — the ONE derivation (stele#122),
// written where the two things it joins already live. nil when the
// contract says the obligation is not owed (pre-epoch history). The
// union is sorted and deduplicated: what a release owes is a set,
// and a set has one spelling, so the demand is independent of class
// declaration order.
func (e *EvidencePolicy) EnrichmentDemand(c *Contract) *verify.EnrichmentDemand {
	if !c.Enrichment {
		return nil
	}

	var names []string

	for _, class := range c.Classes {
		names = append(names, e.Classes[class].Enrichment...)
	}

	slices.Sort(names)

	return &verify.EnrichmentDemand{AlsoRequired: slices.Compact(names)}
}

// ContractSource resolves one release's contract. ok=false means the
// source has no contract for this release — the caller may fall
// through to the next source, and a release no source can speak for
// is legacy.
type ContractSource interface {
	Contract(owner, repo, tag string) (c *Contract, ok bool, err error)
}

// ManifestSource reads the release's own evidence manifest asset.
// The policy supplies the obligation epochs: the manifest declares
// facts (classes, layout, the machinery version that published it),
// never obligations — those are always derived, through the same
// epoch semantics the workflow adapter uses (stele#109).
type ManifestSource struct {
	Forge  gh.Forge
	Policy *EvidencePolicy
	Asset  string
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

	// Decoded through the ONE manifest definition — the same package
	// the writer renders through, so a manifest the writer can produce
	// and a manifest this reader admits cannot drift apart
	// (internal/evidence).
	doc, err := evidence.Parse(raw)
	if err != nil {
		return nil, false, fmt.Errorf("assert: manifest of %s/%s@%s: %w", owner, repo, tag, err)
	}

	// The declared machinery version is the attested spelling of the
	// fact the workflow adapter regexes out of a pin comment, and the
	// obligations are DERIVED from it through the shared epochs —
	// never asserted here. "Manifest-era releases postdate every
	// epoch" was true of every epoch already in the past and false
	// for any epoch still in the future, which is exactly the class
	// of defect the epochs exist to remove (stele#109).
	return &Contract{
		Classes:          doc.Classes,
		StoreVSA:         *doc.StoreVSA,
		Decision:         m.Policy.decision(*doc.MachineryVersion),
		Enrichment:       m.Policy.enrichment(*doc.MachineryVersion),
		MachineryVersion: *doc.MachineryVersion,
		Origin:           "manifest " + m.Asset,
	}, true, nil
}

// WorkflowSource is the GitHub-workflow-convention adapter: the
// classes a release owes are read from the caller's publish workflow
// AT THE TAG — the only honest source for releases that predate the
// manifest. The parsing mirrors what the callers actually wrote
// (a `classes:` input line; the machinery repo's own publish.yml is
// a reusable, so its caller stub is self-publish.yml), and the repo
// version comes from the pin comment on the uses: line, the tag
// itself for the machinery repo.
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

	// The machinery version pinned at the tag decides the verdict
	// obligation's shape; a repository carrying its own machinery uses
	// a local reference, so its version is the tag itself.
	machineryVersion := strings.TrimPrefix(tag, "v")
	if pm := pinCommentRE.FindSubmatch(wf); pm != nil {
		machineryVersion = string(pm[1])
	}

	return &Contract{
		Classes:          classes,
		StoreVSA:         w.Policy.storeVSA(machineryVersion),
		Decision:         w.Policy.decision(machineryVersion),
		Enrichment:       w.Policy.enrichment(machineryVersion),
		MachineryVersion: machineryVersion,
		Origin:           "publish workflow at " + tag,
	}, true, nil
}

// splitClasses reads the workflow input's class list. The separator
// is a COMMA (the org writes `classes: rust-binary,oci-image,…`,
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
