// This file: the pre-publish plans judgment (.github#544's
// structural half). The build legs emit inventory plans — the
// artifact-to-package mapping as data, stated once where it is
// certain — and the policy's planned assetPrefixes declare which
// release documents those plans must produce. Until this judgment
// existed, nothing joined the two before the evidence walk: a plan
// could name a document no class owes (.github#544's
// `sbom-cargo-lab-wasm` against an owed `sbom-npm-`), the release
// published green, and the walk found the hole after the fact.
//
// The judgment is bidirectional, because that defect reads two ways:
// an owed planned prefix no plan satisfies is a release that will red
// on the walk, and a plan document no owed planned prefix claims is a
// misnamed obligation-bearer or an undeclared obligation — drift
// either way. Both legs judge through the one obligation list and the
// one owedFrom semantics the evidence walk reads, so the pre-publish
// guard and the post-publish walk cannot disagree about what is owed.

package assert

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/report"
)

// The assertion vocabulary for plans findings.
const (
	assertPlanShape    = "plan-shape"
	assertPlanConflict = "plan-conflict"
	assertPlanned      = "planned-obligation"
	assertPlanOrphan   = "plan-orphan"
	assertPlanClass    = "class"
)

// The plans originate on build legs that execute caller code, so
// every field is charset-guarded before the sbom job puts it on a
// command line. Names, not shell-safety folklore: each pattern admits
// exactly the vocabulary its consumer defines.
var (
	planDocRE      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	planPackageRE  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]*$`)
	planFeatureRE  = regexp.MustCompile(`^[A-Za-z0-9_+.-]+$`)
	planArtifactRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
)

// PlanEntry is one planned inventory document: the document name the
// release will carry and the closure that produces it. Strict decode:
// this format is stele's own (docs/assert-policy-schema.md), so an
// unknown field is a version skew, never something to skip.
type PlanEntry struct {
	// Doc names the release document, version- and suffix-less: the
	// asset becomes <doc>-<version><sbomSuffix>, so the policy's
	// planned prefixes match Doc directly.
	Doc *string `json:"doc"`
	// CargoPackage is the cargo package whose closure the document
	// inventories.
	CargoPackage *string `json:"cargoPackage"`
	// Features and NoDefaultFeatures narrow the closure to what was
	// actually compiled.
	Features          []string `json:"features,omitempty"`
	NoDefaultFeatures *bool    `json:"noDefaultFeatures,omitempty"`
	// Artifact, when set, names the shipped file the document
	// describes.
	Artifact *string `json:"artifact,omitempty"`
}

// PlanFile pairs one plan document's bytes with the name the caller
// knows it by, so a finding can point at the leg that emitted it.
type PlanFile struct {
	Name    string
	Content []byte
}

// Plans judges the build legs' inventory plans against the policy's
// planned obligations for the requested classes, pre-publish. It
// returns a sealed report and no error: every input is already in
// hand, so there is no "could not look" — a plan that will not parse
// is a defective build leg, which is a finding, not blindness.
func Plans(pol *Policy, classes []string, machineryVersion string, files []PlanFile, log Logf) *report.Report {
	findings, entries := parsePlans(files)

	seen := map[string]bool{}
	subjects := 0

	for _, class := range classes {
		if class == "" || seen[class] {
			continue
		}

		seen[class] = true
		subjects++

		cp, ok := pol.Evidence.Classes[class]
		if !ok {
			findings = append(findings, report.Finding{
				Subject: class, Assertion: assertPlanClass,
				Detail: "requested class is not declared in the policy — an undeclared class owes unknowable evidence",
			})

			continue
		}

		owed := cp.owedPlannedPrefixes(machineryVersion)
		for _, prefix := range owed {
			if !anyDocHasPrefix(entries, prefix) {
				findings = append(findings, report.Finding{
					Subject: class, Assertion: assertPlanned, Expected: prefix,
					Detail: fmt.Sprintf(
						"no plan names a document under %q — the release would publish and then red on the evidence walk",
						prefix),
				})
			}
		}

		log("assert: plans: class %s: %d planned obligation(s) judged", class, len(owed))
	}

	findings = append(findings, orphanFindings(pol, entries, seen, machineryVersion)...)

	pop := report.PopulationFromEvidence(subjects, "requested evidence classes")

	return report.Seal("assert plans", strings.Join(sortedSet(seen), ","), pop, findings, nil, report.NoCanary())
}

// parsePlans decodes and merges every plan file: identical entries
// collapse (matrix legs restate the same mapping), and one document
// claimed by two DIFFERENT entries is legs disagreeing about what
// was built — a finding, never last-writer-wins.
func parsePlans(files []PlanFile) ([]report.Finding, []PlanEntry) {
	var (
		findings []report.Finding
		entries  []PlanEntry
	)

	byDoc := map[string]string{}
	kept := map[string]bool{}

	for _, f := range files {
		decoded, err := jsonx.DecodeBytes[[]PlanEntry](f.Content)
		if err != nil {
			findings = append(findings, report.Finding{
				Subject: f.Name, Assertion: assertPlanShape,
				Detail: fmt.Sprintf("plan does not decode: %v", err),
			})

			continue
		}

		for i, e := range *decoded {
			if ferr := e.validate(); ferr != nil {
				findings = append(findings, report.Finding{
					Subject: f.Name, Assertion: assertPlanShape,
					Detail: fmt.Sprintf("entry %d: %v", i, ferr),
				})

				continue
			}

			key := e.key()
			if kept[key] {
				continue
			}

			if prior, ok := byDoc[*e.Doc]; ok {
				findings = append(findings, report.Finding{
					Subject: f.Name, Assertion: assertPlanConflict,
					Expected: prior, Actual: key,
					Detail: fmt.Sprintf(
						"document %q is claimed by two different plans — the legs disagree about what was built", *e.Doc),
				})

				continue
			}

			byDoc[*e.Doc] = key
			kept[key] = true
			entries = append(entries, e)
		}
	}

	return findings, entries
}

// validate refuses an entry whose required fields are absent or whose
// values step outside the declared vocabulary.
func (e *PlanEntry) validate() error {
	switch {
	case e.Doc == nil || *e.Doc == "":
		return errors.New("doc is absent or empty")
	case !planDocRE.MatchString(*e.Doc):
		return fmt.Errorf("doc %q steps outside the document-name vocabulary", *e.Doc)
	case e.CargoPackage == nil || *e.CargoPackage == "":
		return errors.New("cargoPackage is absent or empty")
	case !planPackageRE.MatchString(*e.CargoPackage):
		return fmt.Errorf("cargoPackage %q steps outside the package-name vocabulary", *e.CargoPackage)
	}

	for _, f := range e.Features {
		if !planFeatureRE.MatchString(f) {
			return fmt.Errorf("feature %q steps outside the feature-name vocabulary", f)
		}
	}

	if e.Artifact != nil && !planArtifactRE.MatchString(*e.Artifact) {
		return fmt.Errorf("artifact %q steps outside the artifact-name vocabulary", *e.Artifact)
	}

	return nil
}

// key renders the entry's whole content canonically, so "identical
// restatement" and "different claim on one document" are decided by
// comparison, never by field-by-field folklore.
func (e *PlanEntry) key() string {
	ndf := false
	if e.NoDefaultFeatures != nil {
		ndf = *e.NoDefaultFeatures
	}

	artifact := ""
	if e.Artifact != nil {
		artifact = *e.Artifact
	}

	return fmt.Sprintf("doc=%s package=%s features=%s noDefaultFeatures=%t artifact=%s",
		*e.Doc, *e.CargoPackage, strings.Join(e.Features, ","), ndf, artifact)
}

// anyDocHasPrefix reports whether some plan document satisfies the
// prefix obligation.
func anyDocHasPrefix(entries []PlanEntry, prefix string) bool {
	for _, e := range entries {
		if strings.HasPrefix(*e.Doc, prefix) {
			return true
		}
	}

	return false
}

// orphanFindings names every plan document no owed planned prefix of
// the requested classes claims: a misnamed obligation-bearer (canon
// #544's shape) or an obligation the policy never declared — drift
// either way, and exactly the drift that used to surface only
// post-publish.
func orphanFindings(
	pol *Policy, entries []PlanEntry, classes map[string]bool, machineryVersion string,
) []report.Finding {
	var owed []string

	for class := range classes {
		if cp, ok := pol.Evidence.Classes[class]; ok {
			owed = append(owed, cp.owedPlannedPrefixes(machineryVersion)...)
		}
	}

	var out []report.Finding

	for _, e := range entries {
		claimed := false

		for _, prefix := range owed {
			if strings.HasPrefix(*e.Doc, prefix) {
				claimed = true

				break
			}
		}

		if !claimed {
			out = append(out, report.Finding{
				Subject: *e.Doc, Assertion: assertPlanOrphan,
				Detail: "no owed planned prefix of the requested classes claims this document — " +
					"a misnamed obligation-bearer or an undeclared obligation",
			})
		}
	}

	return out
}

// sortedSet renders a string set deterministically.
func sortedSet(s map[string]bool) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}
