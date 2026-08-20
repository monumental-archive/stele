// Package report is the shared verdict document every judging verb
// speaks — `verify --json` today, `assert` next, `level` after that.
// Its design rule is the verify engine's #208 made general: a Report
// has unexported fields and exactly one constructor, Seal, which
// computes the verdict — so a green report that skipped the coverage
// question is unrepresentable. The four laws the canon's audit bash
// re-proved script by script live here once, in types:
//
//   - a walk that judged zero subjects cannot pass (the population
//     rule): Seal returns CANNOT_JUDGE, never PASS, for an empty or
//     short population;
//   - a declared canary the walk did not reproduce means the walk
//     cannot see, which is CANNOT_JUDGE, not PASS and not FAIL;
//   - an exception is either DECLARED by a human in a committed file
//     or DERIVED by engine logic from evidence — the constructors are
//     asymmetric, so a hand-written "burned" is unrepresentable, and
//     a declared exception matching no finding is reported rather
//     than silently carried;
//   - what that unmatched exception is reported AS follows from
//     coverage, never from a naming convention (#147): a run that
//     performed the check and found it clean reports the excuse
//     STALE, a run that never performed it reports it UNEXERCISED.
//     Staleness is a retirement claim, and a claim needs sight — so
//     walks record every check through the Journal, not only the
//     checks that failed.
package report

import (
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// Verdict is the tri-state outcome. FAIL and CANNOT_JUDGE are
// deliberately distinct: "I found divergence" and "I could not look"
// must never be conflated by a caller.
type Verdict string

// The three verdicts Seal can compute.
const (
	VerdictPass        Verdict = "PASS"
	VerdictFail        Verdict = "FAIL"
	VerdictCannotJudge Verdict = "CANNOT_JUDGE"
)

// Population records what a run covered AND how the subject set was
// obtained — provenance travels with the count, so "what a narrowed
// token happened to show" is structurally distinguishable from "the
// declared population". Constructors below, alone.
type Population struct {
	size     int
	expected *int
	source   string
	detail   string
}

// PopulationFromEvidence sizes the population by what the evidence
// itself enumerated (release subjects, chain links, branch refs).
func PopulationFromEvidence(size int, detail string) Population {
	return Population{size: size, source: "evidence", detail: detail}
}

// PopulationFromListing sizes the population from a live listing (an
// org's repositories, a release index) — coverage is only as wide as
// the listing credential could see, which is why the source is named.
func PopulationFromListing(size int, detail string) Population {
	return Population{size: size, source: "listing", detail: detail}
}

// PopulationAgainstDeclared pairs an observed size with a declared
// expectation from committed policy. A mismatch in either direction
// is CANNOT_JUDGE: an unseen subject is unchecked, not clean, and a
// surplus subject means the declaration is stale.
func PopulationAgainstDeclared(size, expected int, detail string) Population {
	return Population{size: size, expected: &expected, source: "declared", detail: detail}
}

// covered reports whether this population supports a judgment at all.
func (p Population) covered() bool {
	if p.size <= 0 {
		return false
	}

	return p.expected == nil || *p.expected == p.size
}

// Exception excuses findings on one subject. The two kinds are the
// asymmetry that makes this type worth having: Declared is parsed
// from a committed file a human edited under review; Derived is
// produced only by engine logic from evidence it names. There is no
// third constructor and no way to build a derived exception from
// file content.
type Exception struct {
	kind      string
	subject   string
	assertion string
	origin    string
}

// The two exception kinds.
const (
	kindDeclared = "declared"
	kindDerived  = "derived"
)

// Declared builds a human-asserted exception: subject and optionally
// one assertion (empty excuses every assertion on the subject), with
// origin naming the committed file and line that asserted it — so
// the report points at the review that approved the excuse.
//
// An empty SUBJECT excuses the assertion wherever it appears — the
// shape a triage decision has, since an advisory decision is about a
// package version and not about the release that happens to carry
// it. ParseDebt refuses both blanks, so a committed line can never
// spell either wildcard: engine vocabulary, not file vocabulary.
func Declared(subject, assertion, origin string) Exception {
	return Exception{kind: kindDeclared, subject: subject, assertion: assertion, origin: origin}
}

// Derived builds an engine-derived exception: same matching shape,
// with origin naming the evidence the derivation read (a run history,
// a tag's tree). Callers are engine code, never file parsers.
func Derived(subject, assertion, origin string) Exception {
	return Exception{kind: kindDerived, subject: subject, assertion: assertion, origin: origin}
}

// matches reports whether this exception excuses the finding. An
// empty field on the exception's side is the wildcard for that side.
func (e *Exception) matches(f *Finding) bool {
	return (e.subject == "" || e.subject == f.Subject) &&
		(e.assertion == "" || e.assertion == f.Assertion)
}

// Canary is a known-positive the run must reproduce, or the run
// cannot see. Most runs declare none; a run that declares one and
// misses it is CANNOT_JUDGE regardless of everything else.
type Canary struct {
	declared bool
	key      string
	seen     bool
}

// NoCanary declares no canary — the judgment rests on population and
// findings alone.
func NoCanary() Canary { return Canary{} }

// CanarySeen records a declared canary the run reproduced.
func CanarySeen(key string) Canary { return Canary{declared: true, key: key, seen: true} }

// CanaryMissed records a declared canary the run did not reproduce.
func CanaryMissed(key string) Canary { return Canary{declared: true, key: key} }

// Fact is one named datum a run reports beside its verdict (a
// computed level, a source revision, a link count) — information,
// never part of the judgment.
type Fact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// JudgedSet is the collapsed, validated input set a run judged,
// rendered ONCE by the engine that judged it. It answers a different
// question from Population: Population records how many subjects a
// run covered and how the set was obtained, this records what the set
// WAS, in full. Information beside the verdict, like Fact — it can
// move no judgment.
//
// It exists because a consumer that iterates a judgment's inputs must
// iterate what PASSED judgment, never its own second reading of the
// same raw bytes (stele#151: a publish guard judged the collapsed
// plan set while the derivation loop beside it re-collapsed the same
// files with jq — two derivations of one set, agreeing by luck). The
// report carries the engine's rendering, and a caller writing the set
// beside the report writes those same bytes back out, so a second
// derivation is unrepresentable. Constructors below, alone.
type JudgedSet struct {
	raw jsonx.Raw
}

// NoJudgedSet declares that a run reports no input set of its own —
// the common case: nothing downstream iterates what it judged.
func NoJudgedSet() JudgedSet { return JudgedSet{} }

// Judged carries one rendered set, as the engine rendered it.
func Judged(raw jsonx.Raw) JudgedSet { return JudgedSet{raw: raw} }

// Report is a sealed judgment. Constructor: Seal, alone — the zero
// value carries no verdict and encodes as nothing.
type Report struct {
	target    string
	subject   string
	verdict   Verdict
	pop       Population
	canary    Canary
	judged    JudgedSet
	facts     []Fact
	unexcused []Finding
	excused   []excusedFinding
	stale     []Exception
	unlooked  []Exception
}

// excusedFinding pairs a finding with the exception that excused it,
// so the report shows every excuse beside what it excused.
type excusedFinding struct {
	finding   Finding
	exception Exception
}

// Seal computes the one verdict the inputs support. target names the
// judging mode; subject what was judged; the journal carries what the
// run checked, what diverged, and what may excuse it. The order of
// judgment: coverage first (population, canary — no coverage, no
// judgment), then findings against exceptions. Findings sealed under
// a CANNOT_JUDGE are still carried: partial sight is reported, never
// laundered into either verdict.
func Seal(
	target, subject string, pop Population, j *Journal, canary Canary, judged JudgedSet, facts ...Fact,
) *Report {
	r := &Report{target: target, subject: subject, pop: pop, canary: canary, judged: judged, facts: facts}

	used := make([]bool, len(j.exceptions))

	for fi := range j.findings {
		excused := false

		for ei := range j.exceptions {
			if j.exceptions[ei].matches(&j.findings[fi]) {
				r.excused = append(r.excused, excusedFinding{finding: j.findings[fi], exception: j.exceptions[ei]})
				used[ei] = true
				excused = true

				break
			}
		}

		if !excused {
			r.unexcused = append(r.unexcused, j.findings[fi])
		}
	}

	// An unmatched exception is sorted by what the run could SEE, not
	// by what it was called: the check ran clean (retire the excuse),
	// or it never ran here (this run has nothing to say about it).
	for i, e := range j.exceptions {
		switch {
		case used[i]:
		case j.exercised(&e):
			r.stale = append(r.stale, e)
		default:
			r.unlooked = append(r.unlooked, e)
		}
	}

	switch {
	case !pop.covered() || (canary.declared && !canary.seen):
		r.verdict = VerdictCannotJudge
	case len(r.unexcused) > 0:
		r.verdict = VerdictFail
	default:
		r.verdict = VerdictPass
	}

	return r
}

// Target reports the judging mode that produced this document, so a
// caller rendering it can name the run rather than assuming which verb
// it belongs to.
func (r *Report) Target() string { return r.target }

// Verdict reports the sealed verdict.
func (r *Report) Verdict() Verdict { return r.verdict }

// Passed reports whether the verdict is PASS — the only green.
func (r *Report) Passed() bool { return r.verdict == VerdictPass }

// Findings returns the unexcused findings, copied.
func (r *Report) Findings() []Finding {
	out := make([]Finding, len(r.unexcused))
	copy(out, r.unexcused)

	return out
}

// Judged returns the rendered input set this report carries, copied,
// and nil where the run declared none — nil, never an empty slice,
// because a caller re-encoding the result must see "no set" as
// absence rather than as bytes that are not a JSON value. A caller
// placing the set beside the report writes exactly these bytes: one
// rendering reaches both destinations, so the file and the document
// cannot disagree about what was judged.
func (r *Report) Judged() jsonx.Raw { return slices.Clone(r.judged.raw) }

// Schema is the document epoch, stamped on every encoded report so a
// consumer can refuse a version it does not implement instead of
// best-efforting it (stele#107: a format with a consumer beyond its
// author needs a version identifier BEFORE the consumer arrives, not
// after it breaks). It is the SAME number the policy documents carry
// — one epoch across every live-read stele document, defined once at
// the version gate (jsonx.Epoch), so the class of drift #107 found
// cannot recur. See docs/versioning.md.
const Schema = jsonx.Epoch

// The encode shapes — exported fields for the jsonx boundary, built
// only from a sealed report. Decoding a document back into a Report
// deliberately does not exist yet: a consumer re-seals from parts, so
// a tampered verdict field could never be believed.
type reportDoc struct {
	Schema     int            `json:"schema"`
	Target     string         `json:"target"`
	Subject    string         `json:"subject,omitempty"`
	Verdict    Verdict        `json:"verdict"`
	Population populationDoc  `json:"population"`
	Canary     *canaryDoc     `json:"canary,omitempty"`
	Facts      []Fact         `json:"facts,omitempty"`
	Findings   []Finding      `json:"findings,omitempty"`
	Excused    []excusedDoc   `json:"excused,omitempty"`
	Stale      []exceptionDoc `json:"staleExceptions,omitempty"`
	Unlooked   []exceptionDoc `json:"unexercisedExceptions,omitempty"`
	Judged     jsonx.Raw      `json:"judged,omitempty"`
}

type populationDoc struct {
	Size     int    `json:"size"`
	Expected *int   `json:"expected,omitempty"`
	Source   string `json:"source"`
	Detail   string `json:"detail,omitempty"`
}

type canaryDoc struct {
	Key  string `json:"key"`
	Seen bool   `json:"seen"`
}

type exceptionDoc struct {
	Kind      string `json:"kind"`
	Subject   string `json:"subject"`
	Assertion string `json:"assertion,omitempty"`
	Origin    string `json:"origin,omitempty"`
}

type excusedDoc struct {
	Finding   Finding      `json:"finding"`
	Exception exceptionDoc `json:"exception"`
}

func exceptionAsDoc(e Exception) exceptionDoc {
	return exceptionDoc{Kind: e.kind, Subject: e.subject, Assertion: e.assertion, Origin: e.origin}
}

// Encode writes the report as one JSON document plus newline. A
// caller that fails to write must not report success — the returned
// error is that contract's carrier.
func (r *Report) Encode(w io.Writer) error {
	if r.verdict == "" {
		return errors.New("report: refusing to encode an unsealed report")
	}

	doc := reportDoc{
		Schema:  Schema,
		Target:  r.target,
		Subject: r.subject,
		Verdict: r.verdict,
		Population: populationDoc{
			Size: r.pop.size, Expected: r.pop.expected, Source: r.pop.source, Detail: r.pop.detail,
		},
		Facts:    r.facts,
		Findings: r.unexcused,
		Judged:   r.judged.raw,
	}

	if r.canary.declared {
		doc.Canary = &canaryDoc{Key: r.canary.key, Seen: r.canary.seen}
	}

	for i := range r.excused {
		doc.Excused = append(doc.Excused,
			excusedDoc{Finding: r.excused[i].finding, Exception: exceptionAsDoc(r.excused[i].exception)})
	}

	for _, e := range r.stale {
		doc.Stale = append(doc.Stale, exceptionAsDoc(e))
	}

	for _, e := range r.unlooked {
		doc.Unlooked = append(doc.Unlooked, exceptionAsDoc(e))
	}

	if err := jsonx.Encode(w, doc); err != nil {
		return fmt.Errorf("report: %w", err)
	}

	return nil
}
