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
	"github.com/monumental-archive/stele/internal/workflow"
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
	// Attributed reports whether the source can say WHICH class built
	// each artifact. Carried as its own fact rather than inferred from
	// an empty ArtifactClasses: a release that attributes and shipped
	// no artifact, and a release that cannot attribute at all, are
	// different facts, and only the second may narrow an obligation.
	Attributed bool
	// ArtifactClasses maps a build subject's asset name to the class
	// that built it — meaningful only where Attributed.
	ArtifactClasses map[string]string
	// ManifestSchema is the schema the manifest declared, 0 when no
	// manifest spoke for the release. It says WHY attribution is
	// missing, so a narrowing states its own cause instead of asserting
	// a schema number the release may never have carried.
	ManifestSchema int
	// Origin names where the contract was read from, for the report.
	Origin string
}

// ArtifactNote is one thing the demand derivation had to say about one
// artifact: an excusal (loud, never silent) or a defect. Both name the
// artifact, because "some artifact was narrowed" is not a statement
// anyone can audit.
type ArtifactNote struct {
	Artifact string
	Detail   string
}

// ArtifactDemand is what one release's artifacts owe their enrichment
// claims, together with everything deriving it must state out loud.
// Excused and Defects are deliberately separate vocabularies: an
// excusal is a narrowing this walk performed and stated, a defect is a
// finding the walk reds on. Conflating them would let a broken
// manifest read as an excused one.
type ArtifactDemand struct {
	// Demand is the per-artifact demand handed to the verify engine,
	// nil when the obligation is not owed at all.
	Demand *verify.EnrichmentDemand
	// Excused are artifacts narrowed because their class is unknowable,
	// each carrying the names not asked of it.
	Excused []ArtifactNote
	// Defects are artifacts a manifest that COULD attribute failed to,
	// which is broken derived state and never a narrowing.
	Defects []ArtifactNote
}

// EnrichmentDemand derives what each of a release's artifacts owes its
// enrichment claim — the ONE derivation (stele#122), written where the
// two things it joins already live. A nil Demand means the obligation
// is not owed at all (pre-epoch history), which is a different fact
// from owing nothing extra.
//
// The demand is PER ARTIFACT because the obligation is (stele#206). A
// release's classes are a set of what it shipped, not a property of
// every artifact in it: asking a rust binary for the pgrx tarball's
// base-image claims is asking one artifact to answer for another's
// build. Where the manifest attributes each artifact to its class, the
// artifact owes exactly that class's names, in full.
//
// Where the manifest CANNOT attribute — a schema below the class split,
// or no manifest at all — the fallback is to owe nothing
// class-specific, never to owe everything: the never-overclaim rule the
// manifest epoch itself applies. Those artifacts stay held to the
// verify policy's universal required set in full; only the per-class
// half is excused, and every excused name is named.
//
// Where the manifest could attribute and did not, the artifact is a
// DEFECT, not a narrowing, and it stays held to the whole declared set
// — omission must not buy the leniency that only structural silence
// earns.
func (e *EvidencePolicy) EnrichmentDemand(c *Contract, subjects []verify.Subject) *ArtifactDemand {
	if !c.Enrichment {
		return &ArtifactDemand{}
	}

	declared := e.declaredEnrichment(c)

	if !c.Attributed {
		return &ArtifactDemand{Demand: &verify.EnrichmentDemand{}, Excused: excusals(c, subjects, declared)}
	}

	out := &ArtifactDemand{Demand: &verify.EnrichmentDemand{ByArtifact: map[string][]string{}}}

	for _, s := range subjects {
		owed, defect := e.artifactOwes(c, s.Name, declared)

		if defect != "" {
			out.Defects = append(out.Defects, ArtifactNote{Artifact: s.Name, Detail: defect})
		}

		if len(owed) > 0 {
			out.Demand.ByArtifact[s.Name] = owed
		}
	}

	return out
}

// artifactOwes answers for ONE artifact of an attributing manifest:
// what its class owes, and — where the attribution is broken — what to
// say about it. A defective attribution falls back to the whole
// declared set, never to nothing: the fallback for "the manifest could
// not say" is leniency, and the fallback for "the manifest did not
// say" must not be, or a manifest earns leniency by omitting the field
// that would have cost it.
// It returns what the artifact owes and, where the attribution is
// broken, the defect to report; an empty defect means the attribution
// held.
//
//nolint:gocritic // unnamedResult: what it owes, then the defect — named in the doc
func (e *EvidencePolicy) artifactOwes(c *Contract, artifact string, declared []string) ([]string, string) {
	class, named := c.ArtifactClasses[artifact]

	switch {
	case !named:
		// The checksum manifest pins this artifact and the evidence
		// manifest attributes it to nothing: two documents the same
		// publisher wrote in the same breath, disagreeing about what the
		// release shipped.
		return declared, fmt.Sprintf(
			"schema %d attributes every artifact to a class and this one to none%s",
			c.ManifestSchema, heldTo(declared))
	case !e.definesClass(class):
		return declared, fmt.Sprintf(
			"built by class %q, which the policy does not define%s", class, heldTo(declared))
	}

	// Sorted for the same reason the union is: what one artifact owes is
	// a set, and a set has one spelling — so which unmet name a refusal
	// reports does not depend on the order the policy happened to list
	// them in.
	owed := slices.Clone(e.Classes[class].Enrichment)
	slices.Sort(owed)

	return owed, ""
}

// heldTo names the set a broken attribution leaves an artifact held
// to, and says nothing when there is nothing to name — a clause
// naming an empty set reads as an obligation when it is the absence of
// one.
func heldTo(declared []string) string {
	if len(declared) == 0 {
		return ""
	}

	return fmt.Sprintf(" — held to the whole declared set (%s)", strings.Join(declared, ", "))
}

// declaredEnrichment is the union of what every class this release
// declared owes — the whole set, sorted and deduplicated, because what
// a release declares is a set and a set has one spelling. It is the
// strict fallback, never the per-artifact answer.
func (e *EvidencePolicy) declaredEnrichment(c *Contract) []string {
	var names []string

	for _, class := range c.Classes {
		names = append(names, e.Classes[class].Enrichment...)
	}

	slices.Sort(names)

	return slices.Compact(names)
}

// definesClass reports whether the policy declares this class at all.
func (e *EvidencePolicy) definesClass(class string) bool {
	_, ok := e.Classes[class]

	return ok
}

// excusals states one narrowing per artifact. A release whose declared
// classes owe nothing class-specific narrows nothing, so it says
// nothing: an excusal naming no obligation is noise wearing the
// vocabulary of an exception.
func excusals(c *Contract, subjects []verify.Subject, declared []string) []ArtifactNote {
	if len(declared) == 0 {
		return nil
	}

	cause := fmt.Sprintf("class unknowable under schema %d", c.ManifestSchema)
	if c.ManifestSchema == 0 {
		cause = "class unknowable: no manifest attributes this release's artifacts"
	}

	out := make([]ArtifactNote, 0, len(subjects))

	for _, s := range subjects {
		out = append(out, ArtifactNote{
			Artifact: s.Name,
			Detail:   fmt.Sprintf("%s — excused: %s", cause, strings.Join(declared, ", ")),
		})
	}

	return out
}

// PlannedInventories selects, from a release's SBOM assets, the
// documents its inventory plan named — the denominator the release
// decision is measured against (stele#158), derived HERE for the same
// reason EnrichmentDemand is: the obligation is per-class, and the
// class list joins the policy only in the walk.
//
// The plan itself is a build-leg artifact that no longer exists by
// the time history is walked, so what a release planned is recovered
// through the one vocabulary that outlives it: the planned prefix
// obligations its classes owed at ITS machinery version (stele#142's
// `planned: true`, through the one owedFrom semantics). A release
// whose classes owed no planned prefix planned no inventories — which
// is every release published before per-artifact inventories existed,
// and the whole-release decision invariant is exactly what those
// releases were published under.
//
// Never epoch-free: whether a document is one a class could EVER owe
// is a naming question, but whether the release owed it is a time
// question (stele#143), and this is the time one — measuring a 2026
// obligation against a 2025 release would demand a decision over a
// document that machinery could not yet write.
func (e *EvidencePolicy) PlannedInventories(c *Contract, sboms []verify.Subject) []verify.Subject {
	var prefixes []string

	for _, class := range c.Classes {
		cp, ok := e.Classes[class]
		if !ok {
			// A class no policy declares owes unknowable evidence; the
			// walk's own class check speaks for it, and inventing an
			// obligation here would be this reader answering that.
			continue
		}

		prefixes = append(prefixes, cp.owedPlannedPrefixes(c.MachineryVersion)...)
	}

	var planned []verify.Subject

	for _, s := range sboms {
		for _, prefix := range prefixes {
			if strings.HasPrefix(s.Name, prefix) {
				planned = append(planned, s)

				break
			}
		}
	}

	return planned
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
//
// The manifest's own SCHEMA is judged through an epoch too
// (stele#185). A published release asset is immutable and attested by
// digest at its tag, so a manifest written under an older schema
// cannot be re-emitted the way a mutable note can — and a walk that
// refused it stopped at the first one and judged nothing at all. What
// an older manifest promised, it still says; what it could not say,
// this walk never asked it for, because the assets a release
// published are classified from the vocabulary the policy declares
// (Classify) and read from the checksum manifest, not from entries.
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

	origin := "manifest " + m.Asset

	// A manifest below the schema this build writes is history, and
	// history is admitted by the declared epoch or not at all. Inside
	// the epoch's range it is a present-tense defect — machinery that
	// owed the current schema wrote an old one — and refuses; before
	// it, the release is read for what it declared and named in the
	// report as what it is, so nothing is quietly rewritten to look
	// newer than it is.
	if !doc.Current() {
		if m.Policy.manifestSchema(*doc.MachineryVersion) {
			return nil, false, fmt.Errorf(
				"assert: manifest of %s/%s@%s: schema %d, but machinery %s owes schema %d",
				owner, repo, tag, *doc.Schema, *doc.MachineryVersion, evidence.Schema)
		}

		origin = fmt.Sprintf("%s (schema %d, before the schema epoch)", origin, *doc.Schema)
	}

	// The declared machinery version is the attested spelling of the
	// fact the workflow adapter regexes out of a pin comment, and the
	// obligations are DERIVED from it through the shared epochs —
	// never asserted here. "Manifest-era releases postdate every
	// epoch" was true of every epoch already in the past and false
	// for any epoch still in the future, which is exactly the class
	// of defect the epochs exist to remove (stele#109).
	// Which class built which artifact is READ from the manifest's own
	// attribution, never inferred: a name or a checksum pattern that
	// looked like one class's output would be a guess wearing a
	// judgment, and the manifest's silence is itself the fact
	// (stele#206).
	artifactClasses, attributed := doc.ArtifactClasses()

	return &Contract{
		Classes:          doc.Classes,
		StoreVSA:         *doc.StoreVSA,
		Decision:         m.Policy.decision(*doc.MachineryVersion),
		Enrichment:       m.Policy.enrichment(*doc.MachineryVersion),
		MachineryVersion: *doc.MachineryVersion,
		Attributed:       attributed,
		ArtifactClasses:  artifactClasses,
		ManifestSchema:   *doc.Schema,
		Origin:           origin,
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
	classesRE    = regexp.MustCompile(`(?m)^[^#\n]*classes:\s*(.+)$`)
	pinCommentRE = regexp.MustCompile(`uses:.*(?:publish|release)\.ya?ml@[^#\n]*#\s*v(\d+\.\d+\.\d+)`)
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

	if callable(wf) {
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

	// A workflow input names the classes the release SHIPPED and could
	// never say which artifact each one built — the releases this
	// adapter speaks for predate the manifest entirely. Attribution is
	// therefore absent, not empty, and the demand narrows accordingly.
	return &Contract{
		Classes:          classes,
		StoreVSA:         w.Policy.storeVSA(machineryVersion),
		Decision:         w.Policy.decision(machineryVersion),
		Enrichment:       w.Policy.enrichment(machineryVersion),
		MachineryVersion: machineryVersion,
		Origin:           "publish workflow at " + tag,
	}, true, nil
}

// callable answers "may anything call this workflow" through the ONE
// workflow parser (internal/workflow), so this legacy adapter and the
// permissions join cannot hold two definitions of what a
// workflow_call trigger IS.
//
// Bytes that will not parse are not a callable workflow. This
// adapter's whole shape is fall-through — a file that does not speak
// for the release hands the question to the next source — and a file
// nothing can read does not speak for it either. The two regexes
// above stay where they are: they mine a literal an author wrote (a
// class list in an input, a version in a pin comment) out of
// history's spelling of it, which is a different question from what
// the format says, and one this adapter's sunset carries away.
func callable(content []byte) bool {
	doc, err := workflow.Parse(content)

	return err == nil && doc.Reusable
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
