// Package triage is the shared advisory derivation: scan an
// inventory, classify every finding, and join it against the recorded
// decisions. One derivation, three consumers — the blast-radius walk
// asking whether history ever shipped an affected package, the VEX
// leg deriving a release's own coverage document, and the affected-
// release resolution behind a signed decision.
//
// It exists because those three must agree. Two of them classifying
// findings separately is the .github#434 defect class in a different
// costume: not two implementations of a check, but two implementations
// of what a finding IS, which drift into disagreeing about whether a
// release was ever covered.
//
// What is code and what is policy, stated once:
//
//   - That a finding with no published fix cannot be gated is CODE.
//     It is not an org preference — you cannot require a remediation
//     that does not exist, and a gate on one is a gate nobody can
//     pass. Every adopter inherits it.
//   - WHICH ecosystems are base layers whose upgrades arrive by
//     rebuild rather than by lockfile is POLICY. That depends on how
//     an org builds, and the list carries no meaning this package
//     can derive.
//   - That a decision matches a finding by exactly (advisory,
//     package, version) is CODE, and lives in internal/vexjoin: it
//     is what makes coverage derived rather than stored, so a bumped
//     dependency matches nothing and surfaces for fresh judgment.
package triage

import (
	"fmt"
	"sort"
	"strings"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

// Class is what a finding can be asked of a release.
type Class string

// The two classes. A third would need a third remediation story, and
// there are only two: upgrade the dependency, or rebuild on a fresher
// base.
const (
	// ClassGate is a finding a release can act on: an ecosystem
	// package, or an OS package whose fix has shipped.
	ClassGate Class = "gate"
	// ClassRebuild is an OS-layer finding with no published fix
	// anywhere. Its remediation is the next build on a refreshed base
	// digest, so a per-advisory decision would decide nothing.
	ClassRebuild Class = "rebuild"
)

// Finding is one advisory against one package, classified.
type Finding struct {
	Key       vexjoin.Key
	Ecosystem string
	// Fixable reports whether any published version fixes it.
	Fixable bool
	Class   Class
}

// String renders the finding the way a report names it.
func (f Finding) String() string {
	return f.Key.Advisory + ":" + f.Key.Package + "@" + f.Key.Version
}

// Policy is the only org-shaped input: which ecosystems are base
// layers. Everything else about classification is derived.
type Policy struct {
	// BaseEcosystems are matched as lowercase substrings of the
	// scanner's ecosystem name. Empty means the org declares no base
	// layer, so every finding is actionable — a legitimate answer for
	// an org that ships no images.
	BaseEcosystems []string
}

// scanReport is the scanner's output shape. Foreign — somebody else's
// evolving schema — so it is read leniently, but every field the
// classification needs is read explicitly rather than inferred.
type scanReport struct {
	Results []struct {
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []vulnerability `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

type vulnerability struct {
	ID       string `json:"id"`
	Affected []struct {
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// fixable reports whether the advisory names any version that fixes
// it. A `fixed` event anywhere in any affected range is a published
// remediation; its absence everywhere means there is nothing to
// upgrade to.
func (v vulnerability) fixable() bool {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return true
				}
			}
		}
	}

	return false
}

// Findings decodes one scanner report and classifies everything in
// it, deduplicated and ordered so two runs over one inventory produce
// the same list.
func (p *Policy) Findings(report []byte) ([]Finding, error) {
	decoded, err := jsonx.DecodeForeign[scanReport](report)
	if err != nil {
		return nil, fmt.Errorf("triage: scanner report: %w", err)
	}

	seen := map[vexjoin.Key]bool{}

	var out []Finding

	for _, res := range decoded.Results {
		for _, pkg := range res.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				key := vexjoin.Key{
					Advisory: vuln.ID, Package: pkg.Package.Name, Version: pkg.Package.Version,
				}
				if key.Advisory == "" || seen[key] {
					continue
				}

				seen[key] = true

				fix := vuln.fixable()
				out = append(out, Finding{
					Key:       key,
					Ecosystem: pkg.Package.Ecosystem,
					Fixable:   fix,
					Class:     p.classify(pkg.Package.Ecosystem, fix),
				})
			}
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })

	return out, nil
}

// Split is one inventory's findings after the join: those a decision
// covers, those that are gateable and undecided, and the base-layer
// background.
//
// The three are exhaustive and disjoint by construction, so a caller
// cannot mislay a finding between them — which is what an inventory
// walked with two independent filters does.
type Split struct {
	Decided   []Decided
	Undecided []Finding
	Rebuild   []Finding
}

// Decided pairs a finding with the decision that covers it.
type Decided struct {
	Finding  Finding
	Decision vexjoin.Decision
}

// Join splits findings against the recorded decisions. A decision
// covers a finding only on the exact triple; anything else is
// undecided, which is how a bumped dependency surfaces for a fresh
// judgment instead of inheriting the old one.
func Join(findings []Finding, decisions *vexjoin.Decisions) Split {
	var split Split

	for i := range findings {
		f := findings[i]

		switch {
		case decisions.Has(f.Key):
			split.Decided = append(split.Decided, Decided{Finding: f, Decision: decisionFor(decisions, f.Key)})
		case f.Class == ClassRebuild:
			split.Rebuild = append(split.Rebuild, f)
		default:
			split.Undecided = append(split.Undecided, f)
		}
	}

	return split
}

// decisionFor recovers the decision covering one key.
func decisionFor(decisions *vexjoin.Decisions, key vexjoin.Key) vexjoin.Decision {
	all := decisions.All()
	for i := range all {
		if all[i].Key == key {
			return all[i]
		}
	}

	return vexjoin.Decision{Key: key}
}

// Stale lists decisions that matched nothing in this inventory —
// retirement candidates, named rather than silently carried.
func Stale(findings []Finding, decisions *vexjoin.Decisions) []vexjoin.Decision {
	live := make(map[vexjoin.Key]bool, len(findings))
	for i := range findings {
		live[findings[i].Key] = true
	}

	var out []vexjoin.Decision

	all := decisions.All()
	for i := range all {
		if !live[all[i].Key] {
			out = append(out, all[i])
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Key.Advisory+out[i].Key.Package < out[j].Key.Advisory+out[j].Key.Package
	})

	return out
}

// classify decides one finding's class. The rule is total: a finding
// is gateable unless it is both base-layer and unfixable.
func (p *Policy) classify(ecosystem string, fixable bool) Class {
	if fixable || !p.isBase(ecosystem) {
		return ClassGate
	}

	return ClassRebuild
}

func (p *Policy) isBase(ecosystem string) bool {
	lower := strings.ToLower(ecosystem)
	for _, e := range p.BaseEcosystems {
		if e != "" && strings.Contains(lower, strings.ToLower(e)) {
			return true
		}
	}

	return false
}
