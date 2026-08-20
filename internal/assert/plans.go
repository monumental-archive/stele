// This file: the pre-publish plans judgment (.github#544's
// structural half). The build legs emit inventory plans — the
// artifact-to-document mapping as data, stated once where it is
// certain — and the policy's planned assetPrefixes declare which
// release documents those plans must produce. Until this judgment
// existed, nothing joined the two before the evidence walk: a plan
// could name a document no class owes (.github#544's
// `sbom-cargo-lab-wasm` against an owed `sbom-npm-`), the release
// published green, and the walk found the hole after the fact.
//
// The judgment is bidirectional, because that defect reads two ways —
// an owed planned prefix no plan satisfies is a release that will red
// on the walk, and a plan document its class's declared vocabulary
// does not claim is a misnamed obligation-bearer or an undeclared
// obligation. The two directions ask two DIFFERENT questions
// (stele#143): whether an obligation is owed is a time question,
// judged through the one owedFrom semantics the evidence walk reads;
// whether a document is in a class's vocabulary is a naming question,
// judged against every prefix the class declares with no epoch in
// sight. Conflating them was the #143 defect — a pre-epoch release
// emitting a perfectly correct plan was refused as an orphan because
// nothing was owed YET. Each plan entry names its class, so both
// questions are answered against the one class that emitted the plan,
// never against an epoch-filtered union where class A's plan can
// satisfy class B's obligation by prefix coincidence.

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
	assertPlanDrift    = "plan-drift"
	assertPlanClass    = "class"
)

// The plans originate on build legs that execute caller code, so
// every value is charset-guarded before the sbom job puts it on a
// command line. Names, not shell-safety folklore: each pattern admits
// exactly the vocabulary its consumer defines — and params, whose
// consumers are the ecosystem-specific downstream legs this judgment
// deliberately does not know, admit no shell metacharacter at all.
var (
	planClassRE      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	planDocRE        = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	planArtifactRE   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	planParamKeyRE   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]*$`)
	planParamValueRE = regexp.MustCompile(`^[A-Za-z0-9_+.,:=@/-]*$`)
)

// PlanEntry is one planned inventory document: which class's leg
// emitted it, the document name the release will carry, and the
// closure that produces it. Strict decode: this format is stele's own
// (docs/assert-policy-schema.md), so an unknown field is a version
// skew, never something to skip.
type PlanEntry struct {
	// Class names the evidence class whose build leg emitted this
	// entry — stated where it is certain, because the leg IS the
	// class. It is the judgment's join key: the entry is judged
	// against this one class's declared vocabulary and satisfies this
	// one class's obligations, never another's by prefix coincidence.
	Class *string `json:"class"`
	// Doc names the release document, version- and suffix-less: the
	// asset becomes <doc>-<version><sbomSuffix>, so the policy's
	// planned prefixes match Doc directly.
	Doc *string `json:"doc"`
	// Artifact, when set, names the shipped file the document
	// describes.
	Artifact *string `json:"artifact,omitempty"`
	// Params is the ecosystem-specific closure description — which
	// package, which features, whatever the class's deriver needs.
	// Opaque to this judgment by design: which ecosystems exist is
	// each adopter's fact, not this tool's, so the judgment guards
	// the charset and canonicalises for comparison, and only the
	// downstream leg that derives the document reads the content.
	Params jsonx.Raw `json:"params,omitempty"`
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
func Plans(
	pol *Policy, classes []string, machineryVersion string, files []PlanFile, j *report.Journal, log Logf,
) *report.Report {
	entries := parsePlans(j, files)

	seen := map[string]bool{}
	subjects := 0

	for _, class := range classes {
		if class == "" || seen[class] {
			continue
		}

		seen[class] = true
		subjects++

		cp, ok := pol.Evidence.Classes[class]
		if c := j.Check(class, assertPlanClass); !ok {
			c.Diverged(
				"requested class is not declared in the policy — an undeclared class owes unknowable evidence")

			continue
		}

		owed := cp.owedPlannedPrefixes(machineryVersion)
		for _, prefix := range owed {
			if c := j.Check(class, assertPlanned); !classPlansPrefix(entries, class, prefix) {
				c.DivergedFrom(prefix, "", fmt.Sprintf(
					"no plan of this class names a document under %q — the release would publish and then red on the evidence walk",
					prefix))
			}
		}

		log("assert: plans: class %s: %d planned obligation(s) judged", class, len(owed))
	}

	vocabularyChecks(j, pol, entries, seen)

	pop := report.PopulationFromEvidence(subjects, "requested evidence classes")

	return report.Seal("assert plans", strings.Join(sortedSet(seen), ","), pop, j, report.NoCanary())
}

// parsePlans decodes and merges every plan file: identical entries
// collapse (matrix legs restate the same mapping), and one document
// claimed by two DIFFERENT entries is legs disagreeing about what
// was built — a finding, never last-writer-wins.
func parsePlans(j *report.Journal, files []PlanFile) []PlanEntry {
	var entries []PlanEntry

	byDoc := map[string]string{}
	kept := map[string]bool{}

	for _, f := range files {
		shape := j.Check(f.Name, assertPlanShape)

		decoded, err := jsonx.DecodeBytes[[]PlanEntry](f.Content)
		if err != nil {
			shape.Diverged(fmt.Sprintf("plan does not decode: %v", err))

			continue
		}

		for i, e := range *decoded {
			key, ferr := e.validate()
			if ferr != nil {
				shape.Diverged(fmt.Sprintf("entry %d: %v", i, ferr))

				continue
			}

			if kept[key] {
				continue
			}

			if prior, ok := byDoc[*e.Doc]; ok {
				j.Check(f.Name, assertPlanConflict).DivergedFrom(prior, key, fmt.Sprintf(
					"document %q is claimed by two different plans — the legs disagree about what was built", *e.Doc))

				continue
			}

			byDoc[*e.Doc] = key
			kept[key] = true
			entries = append(entries, e)
		}
	}

	return entries
}

// validate refuses an entry whose required fields are absent or whose
// values step outside the declared vocabulary, and returns the
// entry's canonical rendering, so "identical restatement" and
// "different claim on one document" are decided by comparison, never
// by field-by-field folklore.
func (e *PlanEntry) validate() (string, error) {
	switch {
	case e.Class == nil || *e.Class == "":
		return "", errors.New("class is absent or empty")
	case !planClassRE.MatchString(*e.Class):
		return "", fmt.Errorf("class %q steps outside the class-name vocabulary", *e.Class)
	case e.Doc == nil || *e.Doc == "":
		return "", errors.New("doc is absent or empty")
	case !planDocRE.MatchString(*e.Doc):
		return "", fmt.Errorf("doc %q steps outside the document-name vocabulary", *e.Doc)
	case e.Artifact != nil && !planArtifactRE.MatchString(*e.Artifact):
		return "", fmt.Errorf("artifact %q steps outside the artifact-name vocabulary", *e.Artifact)
	}

	params, err := e.canonicalParams()
	if err != nil {
		return "", err
	}

	artifact := ""
	if e.Artifact != nil {
		artifact = *e.Artifact
	}

	return fmt.Sprintf("class=%s doc=%s artifact=%s params=%s", *e.Class, *e.Doc, artifact, params), nil
}

// canonicalParams charset-guards the opaque closure description and
// renders it canonically (sorted keys, source-spelled numbers): two
// matrix legs restating one closure compare equal whatever their
// emitters' whitespace, and no value can smuggle a shell
// metacharacter toward the downstream leg's command line.
func (e *PlanEntry) canonicalParams() (string, error) {
	if len(e.Params) == 0 {
		return "", nil
	}

	v, err := jsonx.Value(e.Params)
	if err != nil {
		return "", fmt.Errorf("params do not decode: %w", err)
	}

	if _, ok := v.(map[string]any); !ok {
		return "", errors.New("params is not an object — the closure description is key-value by definition")
	}

	if gerr := guardParams(v); gerr != nil {
		return "", gerr
	}

	canon, err := jsonx.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("params do not re-render: %w", err)
	}

	return string(canon), nil
}

// guardParams walks the params value: every key and every string leaf
// must stay inside the params vocabulary. Numbers, booleans and null
// carry no charset to escape.
func guardParams(v any) error {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if !planParamKeyRE.MatchString(k) {
				return fmt.Errorf("params key %q steps outside the params-key vocabulary", k)
			}

			if err := guardParams(val); err != nil {
				return err
			}
		}
	case []any:
		for _, val := range t {
			if err := guardParams(val); err != nil {
				return err
			}
		}
	case string:
		if !planParamValueRE.MatchString(t) {
			return fmt.Errorf("params value %q steps outside the params-value vocabulary", t)
		}
	}

	return nil
}

// classPlansPrefix reports whether some plan OF THIS CLASS names a
// document satisfying the prefix obligation — the class is the join,
// so another class's plan can never satisfy this one's obligation by
// prefix coincidence.
func classPlansPrefix(entries []PlanEntry, class, prefix string) bool {
	for _, e := range entries {
		if *e.Class == class && strings.HasPrefix(*e.Doc, prefix) {
			return true
		}
	}

	return false
}

// vocabularyChecks judges every plan entry against its own class's
// declared vocabulary — the naming question, with no epoch in sight
// (stele#143): whether a document is one a class could ever owe has
// nothing to do with when the obligation comes online, so a pre-epoch
// release emitting a correct plan is silent here by construction.
//
//   - a plan naming a class this release does not declare is drift: a
//     leg ran for a class the release did not;
//   - a plan whose document no prefix its class DECLARES as planned
//     claims — at any epoch — is a misnamed obligation-bearer or an
//     undeclared obligation (.github#544's shape);
//   - a class declaring no planned prefixes has declared no
//     vocabulary, so there is nothing to step outside of: absent, not
//     refused.
func vocabularyChecks(j *report.Journal, pol *Policy, entries []PlanEntry, requested map[string]bool) {
	for _, e := range entries {
		class := *e.Class

		if c := j.Check(*e.Doc, assertPlanDrift); !requested[class] {
			c.DivergedFrom("", class, fmt.Sprintf(
				"the plan names class %q, which this release does not declare — a leg ran for an undeclared class",
				class))

			continue
		}

		cp, ok := pol.Evidence.Classes[class]
		if !ok {
			// The requested-class loop already refused the class by
			// name; a second finding per entry would be the same
			// defect counted twice.
			continue
		}

		vocabulary := cp.plannedPrefixes()
		if len(vocabulary) == 0 {
			continue
		}

		if c := j.Check(*e.Doc, assertPlanOrphan); !docInVocabulary(*e.Doc, vocabulary) {
			c.DivergedFrom("", class, fmt.Sprintf(
				"no planned prefix class %q declares claims this document — "+
					"a misnamed obligation-bearer or an undeclared obligation", class))
		}
	}
}

// docInVocabulary reports whether some declared planned prefix claims
// the document.
func docInVocabulary(doc string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(doc, prefix) {
			return true
		}
	}

	return false
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
