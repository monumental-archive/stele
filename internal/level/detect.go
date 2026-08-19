// Detection: establishing the catalogue's requirements from evidence.
//
// The ladder is DERIVED here, never asserted. A level holds when every
// requirement the specification places at it is established, and the
// scalar is the highest level whose rungs all hold. Nothing an
// organization writes down enters this file — there is no policy
// parameter, no target, no declared floor. Point it at a repository
// and it answers, and a stranger pointing at the same repository gets
// the same answer.
//
// A requirement with no registered detector is UNDETERMINED, and the
// report names it as unevaluated. That is a statement about this
// tool's coverage, not about the world, and it is the only honest
// thing to say: the alternative is a level that holds because nobody
// looked.

package level

import (
	"fmt"
	"sort"
	"time"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/verify"
)

// Outcome is one requirement's result, why, and how strongly.
type Outcome struct {
	Determination Determination
	Reason        string
	// Attested marks a requirement established by what the SCS or the
	// build platform RECORDED, rather than by something this tool
	// recomputed. Both are evidence — for the control requirements a
	// contemporaneous attestation is the only evidence that can exist,
	// because the configuration at that instant is unrecoverable — but
	// they are not the same strength, and a reader is owed the
	// difference. A level resting on attested requirements is only as
	// good as the identity that signed them, which the report names.
	Attested bool
}

// Established is the outcome for a requirement the evidence proves.
func Established(format string, args ...any) Outcome {
	return Outcome{Determination: Held, Reason: fmt.Sprintf(format, args...)}
}

// Contradicted is the outcome for a requirement the evidence refutes —
// the tool looked and the requirement does not hold.
func Contradicted(format string, args ...any) Outcome {
	return Outcome{Determination: Refuted, Reason: fmt.Sprintf(format, args...)}
}

// RecordHeld is the ONLY constructor for an outcome that holds on a
// subject-issued record. It demands the live half by signature: the
// forge's own current answer, and the predicate that says the live
// answer backs this record. A chain link is emitted and signed by the
// repository's own workflow, so a record about itself is a claim, and
// a detector that could hold on it alone would let any repository mint
// its own level — the defect this verb exists to refuse. There is no
// free-form attested constructor to fall back to; a future detector
// cannot reintroduce self-attestation without deleting this door.
//
// Disagreement between the record and the live answer is UNDETERMINED,
// not refutation: rules legitimately change between a revision landing
// and this run looking, so the mismatch impeaches the corroboration,
// not the repository.
func RecordHeld(live *LiveRules, backs func(*LiveRules) bool, record, held string, args ...any) Outcome {
	switch {
	case live == nil:
		return Unevaluated("%s, but the forge's own rules were not readable — a repository's record about"+
			" itself cannot corroborate itself", record)
	case !backs(live):
		return Unevaluated("%s, but the forge's effective rules do not show it enforced now — the record is"+
			" uncorroborated", record)
	}

	return Outcome{Determination: Held, Reason: fmt.Sprintf(held, args...), Attested: true}
}

// Unevaluated is the outcome when the evidence needed was not
// reachable in this run. Never a pass and never a failure.
func Unevaluated(format string, args ...any) Outcome {
	return Outcome{Determination: Undetermined, Reason: fmt.Sprintf(format, args...)}
}

// Detector establishes one requirement of the catalogue from evidence.
// Pure over its Evidence argument, so every branch is reachable from a
// table test with no repository, no forge and no network.
type Detector interface {
	// For is the catalogue ID this detector establishes.
	For() string
	// Detect reads the evidence and reports what it found.
	Detect(ev *Evidence) Outcome
}

// Subject is one artifact under judgment, with what verification
// recovered about it: the platform's own attested claims.
type Subject struct {
	Name string
	// Cert carries the signing certificate's claims. The build track
	// leans on these because they are the PLATFORM's statements about
	// its own execution, issued by its OIDC issuer and bound into a
	// certificate — evidence, not the tenant's word.
	Cert certificate.Extensions
	// BuildType is the provenance's declared buildType.
	BuildType string
	// ExternalParameterKeys are the keys its externalParameters carried.
	ExternalParameterKeys []string
	// UnrecognisedParameters are externalParameter keys outside the
	// buildType's published schema.
	UnrecognisedParameters []string
	// Verified reports whether the provenance signature verified.
	Verified bool
}

// Evidence is everything one run fetched. A nil or empty field means
// "not reached", which detectors turn into UNDETERMINED rather than
// into a pass — the difference between looking and not looking is the
// whole point of the tri-state.
type Evidence struct {
	Owner, Repo, Ref string

	// Measured is the source chain as the measurement walk found it,
	// nil when the walk did not complete. NoChain distinguishes
	// "walked and found none" — which the spec makes Source Level 0 —
	// from "could not walk".
	Measured *verify.Measured
	NoChain  bool

	// Revisions is the branch's history, newest first.
	Revisions []Revision

	// Live is the forge's OWN current statement of the controls
	// enforced on the measured branch, read from the platform's rules
	// API — the platform speaking about its own enforcement, not
	// anything the repository emitted. nil means the rules were not
	// readable, which is not the same as a forge that answered with no
	// rules.
	//
	// It exists because a chain link's recorded controls are written
	// and signed by the repository's own workflow identity: a record a
	// subject issues about itself cannot, alone, establish the controls
	// it names — that is self-attestation wearing a signature. The
	// forge's live answer is the independent half; the link's record is
	// the contemporaneous half; a control rung holds only where the two
	// agree.
	Live *LiveRules

	// Approvals counts the distinct trusted persons who agreed to the
	// change that produced each revision, keyed by revision. nil means
	// the change history was not read — which is UNDETERMINED, never a
	// count of zero: not asking and finding none are different facts.
	Approvals map[string]int

	// Subjects are the released artifacts and what verification
	// recovered about each.
	Subjects []Subject

	// SignerRunsTenantCode reports, for a signing workflow reached by
	// URI and commit, whether it executes any caller-controlled step.
	// nil when the check could not be performed.
	SignerRunsTenantCode func(uri, digest string) (bool, error)

	// Inventoried and Uninventoried split the released artifacts by
	// whether a published inventory covers them.
	Inventoried, Uninventoried []string
	// Findings and Triaged count advisory findings over those
	// inventories and how many carry a published decision; Scanned
	// reports whether a scan ran at all.
	Scanned           bool
	Findings, Triaged int

	// IngestionIntervals maps each dependency to the interval between
	// its version being published upstream and this producer taking
	// it. Empty means no publication time was resolved.
	IngestionIntervals map[string]time.Duration

	// DependencySources maps each resolved dependency source the
	// release records to whether the producer controls that location.
	// nil means the sources were not read.
	DependencySources map[string]bool
	// UnrecognisedSources are locations whose ownership this run could
	// not establish — a host that is neither an ecosystem's default
	// registry nor inside the producer's own forge namespace. Refuting
	// on one would call a genuine private mirror upstream; holding on
	// one would take a stranger's host for the producer's.
	UnrecognisedSources []string

	Now time.Time
}

// LiveRules is what the forge's rules API says is enforced on the
// branch right now. A rules read answers about NOW — that is exactly
// why the spec asks the SCS for contemporaneous records — but the
// branch tip IS now, so for the tip's controls the live answer is the
// one statement no tenant can forge.
type LiveRules struct {
	// Restrictive reports whether any effective rule restricts a
	// sensitive operation on the branch.
	Restrictive bool
	// ForcePushBlocked reports a non-fast-forward prohibition.
	ForcePushBlocked bool
	// RequiredApprovals is the reviews the forge demands before merge.
	RequiredApprovals int
}

// detectors is the registry, keyed by catalogue ID.
//
//nolint:gochecknoglobals // the registry is a constant; Go has no const map
var detectors = map[string]Detector{}

// register adds one detector, refusing a duplicate or an ID outside
// the catalogue: a detector for a requirement that does not exist
// establishes nothing, and would do it silently.
func register(d Detector) {
	if _, taken := detectors[d.For()]; taken {
		panic("level: two detectors registered for " + d.For())
	}

	if !inCatalogue(d.For()) {
		panic("level: detector registered for unknown requirement " + d.For())
	}

	detectors[d.For()] = d
}

func inCatalogue(id string) bool {
	for _, t := range []Track{TrackBuild, TrackSource, TrackDependency} {
		for _, r := range Requirements(t) {
			if r.ID == id {
				return true
			}
		}
	}

	return false
}

// RegisterForTest exposes the registry's refusals to a test in
// another package. Registration itself stays internal: detectors
// belong to this package, and a caller that could add one could add a
// requirement the catalogue does not carry.
func RegisterForTest(d Detector) { register(d) }

// Coverage reports which of one track's requirements this build can
// establish. It exists so the gap between the catalogue and the
// detectors is a number anyone can read, rather than something a
// reader has to infer from UNDETERMINED rungs.
//
//nolint:gocritic // unnamedResult: detected then total, named in the doc
func Coverage(t Track) (int, int) {
	reqs := Requirements(t)
	detected := 0

	for _, r := range reqs {
		if _, ok := detectors[r.ID]; ok {
			detected++
		}
	}

	return detected, len(reqs)
}

// Assess computes one track's level from evidence, and seals it.
//
// The ladder is built rung by rung from the catalogue: for each level,
// every requirement the spec places there must be established. This is
// the correct-by-construction part — a level cannot hold unless its
// requirements did, because the only way to record a rung is to
// evaluate them.
func Assess(t Track, ev *Evidence) *Assessment {
	lad := NewLadder(t)

	var (
		findings []report.Finding
		reasons  []report.Fact
	)

	for lvl := 1; lvl <= t.ceiling; lvl++ {
		reqs := RequirementsAt(t, lvl)
		if len(reqs) == 0 {
			lad.Unclaimed(lvl, "the specification places no requirement at this level")

			continue
		}

		held, outcomes := judgeLevel(reqs, ev)

		for _, o := range outcomes {
			class := string(o.out.Determination)
			if o.out.Attested {
				class = "HELD (attested)"
			}

			reasons = append(reasons, report.Fact{Name: o.id, Value: class + ": " + o.out.Reason})

			if o.out.Determination == Refuted {
				findings = append(findings, report.Finding{
					Subject:   ev.Owner + "/" + ev.Repo,
					Assertion: o.id,
					Expected:  o.text,
					Actual:    o.out.Reason,
					Detail:    fmt.Sprintf("level %d of the %s track is not established", lvl, t.Name()),
				})
			}
		}

		switch held {
		case Held:
			lad.Hold(lvl, summarise(outcomes))
		case Refuted:
			lad.Refute(lvl, summarise(outcomes))
		case Undetermined, Unclaimed:
			lad.Blind(lvl, summarise(outcomes))
		}
	}

	// Sight is lost only at the BOUNDARY. A level left undetermined
	// above one already refuted changes nothing: no level above a
	// refuted one can hold, so failing to evaluate it costs no
	// certainty. Ladder.Scalar reports exactly that — whether the
	// first non-holding rung was undetermined rather than refuted.
	_, blind := lad.Scalar()
	detected, total := Coverage(t)

	in := &Inputs{
		Subject:          ev.Owner + "/" + ev.Repo,
		InScope:          1,
		Determined:       1,
		PopulationDetail: "repository with a determinable ladder",
		Now:              ev.Now,
		Findings:         findings,
		ExtraFacts: append(reasons,
			report.Fact{Name: "requirementCoverage", Value: fmt.Sprintf("%d/%d", detected, total)}),
	}

	if blind {
		in.Determined = 0
	}

	return Seal(t, lad, in)
}

// levelOutcome pairs one requirement with what a detector found.
type levelOutcome struct {
	id   string
	text string
	out  Outcome
}

// judgeLevel runs every detector for one level and folds the results.
// Refuted outranks Undetermined: evidence that contradicts a
// requirement settles the level, while evidence merely missing does
// not.
func judgeLevel(reqs []Requirement, ev *Evidence) (Determination, []levelOutcome) {
	out := make([]levelOutcome, 0, len(reqs))
	fold := Held

	for _, r := range reqs {
		got := Unevaluated("no detector in this build establishes %q — %s", r.ID, r.Evidence)
		if d, ok := detectors[r.ID]; ok {
			got = d.Detect(ev)
		}

		out = append(out, levelOutcome{id: r.ID, text: r.Text, out: got})

		if severity(got.Determination) > severity(fold) {
			fold = got.Determination
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })

	return fold, out
}

// summarise renders one level's outcomes as the rung's reason.
func summarise(outcomes []levelOutcome) string {
	var held, refuted, unevaluated []string

	attested := 0

	for _, o := range outcomes {
		switch o.out.Determination {
		case Held:
			held = append(held, o.id)

			if o.out.Attested {
				attested++
			}
		case Refuted:
			refuted = append(refuted, o.id)
		case Undetermined, Unclaimed:
			unevaluated = append(unevaluated, o.id)
		}
	}

	msg := fmt.Sprintf("%d/%d requirement(s) established", len(held), len(outcomes))
	if attested > 0 {
		msg += fmt.Sprintf(" (%d on the SCS's own record)", attested)
	}

	if len(refuted) > 0 {
		msg += fmt.Sprintf("; contradicted: %v", refuted)
	}

	if len(unevaluated) > 0 {
		msg += fmt.Sprintf("; unevaluated: %v", unevaluated)
	}

	return msg
}

// AssessPopulation measures many repositories and folds them into one
// answer: what the population as a whole supports.
//
// A rung holds only where it holds for EVERY member. That is the only
// honest fold — an organization is not at a level because most of it
// is, and a claim made on behalf of a population is only as true as
// its weakest member. The report names that member, because "the org
// is level 2" without saying which repository held it there is a
// number nobody can act on.
//
// The population itself is evidence, not a declaration: a listing is
// what the forge says exists. Which members are PERMITTED to fall
// short is a different question, asked by a verb that compares
// evidence to a declaration, and deliberately not asked here.
func AssessPopulation(t Track, members []*Evidence, now time.Time) *Assessment {
	if len(members) == 0 {
		lad := NewLadder(t)
		lad.Blind(1, "the population is empty, so there is nothing to measure")

		return Seal(t, lad, &Inputs{
			Subject: "(empty population)", InScope: 1, Determined: 0,
			PopulationDetail: "repositories with a determinable ladder", Now: now,
		})
	}

	lad := NewLadder(t)

	var (
		findings   []report.Finding
		facts      []report.Fact
		determined int
		weakest    string
		lowest     = -1
	)

	// Seeded HELD and folded downward: a rung survives only if no
	// member weakens it. Seeding empty would let an unrecorded rung
	// read as its zero value, which is not a determination at all.
	perLevel := make(map[int]Determination, t.ceiling)
	for lvl := 1; lvl <= t.ceiling; lvl++ {
		perLevel[lvl] = Held
	}

	for _, ev := range members {
		one := Assess(t, ev)
		subject := ev.Owner + "/" + ev.Repo

		facts = append(facts, report.Fact{Name: "member:" + subject, Value: one.Level()})
		findings = append(findings, one.Report().Findings()...)

		if one.Report().Verdict() != report.VerdictCannotJudge {
			determined++
		}

		for _, r := range one.Rungs() {
			if severity(r.Determination) > severity(perLevel[r.Level]) {
				perLevel[r.Level] = r.Determination
			}
		}

		if n, ok := parseLevel(t, one.Level()); ok && (lowest < 0 || n < lowest) {
			lowest, weakest = n, subject
		}
	}

	for lvl := 1; lvl <= t.ceiling; lvl++ {
		record(lad, lvl, perLevel[lvl], len(members))
	}

	return Seal(t, lad, &Inputs{
		Subject:          fmt.Sprintf("%d repositories", len(members)),
		Weakest:          weakest,
		InScope:          len(members),
		Determined:       determined,
		PopulationDetail: "repositories with a determinable ladder",
		Findings:         findings,
		ExtraFacts:       facts,
		Now:              now,
	})
}

// record writes one folded rung, saying how many members it covers.
func record(lad *Ladder, lvl int, d Determination, members int) {
	switch d {
	case Held:
		lad.Hold(lvl, fmt.Sprintf("established for all %d repositories", members))
	case Refuted:
		lad.Refute(lvl, fmt.Sprintf("not established for every one of %d repositories", members))
	case Undetermined, Unclaimed:
		lad.Blind(lvl, fmt.Sprintf("could not be established for every one of %d repositories", members))
	}
}
