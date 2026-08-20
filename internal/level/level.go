// Package level computes the honest current SLSA level per track from
// live evidence — the judge behind `stele level`, specified in
// docs/level.md. It judges; it mints nothing.
//
// Its design rule is the spec's own, read whole: a SLSA level is not
// derived from an artifact, it is LOOKED UP in a map of trusted
// attesters and then bounded by what the evidence proves
// (verifying-artifacts step 1, verifying-source step 1). So every
// track's answer is min(what the claim says, what the policy vouches
// for), never "what this tool worked out".
//
// The scalar level is an output. The model is a ladder: every level of
// the track carries one determination, and the difference between
// REFUTED (I looked and it is not so) and UNDETERMINED (I could not
// look) is preserved to the verdict — which is where the charter's
// "partial sight is CANNOT_JUDGE, never a lower-but-confident answer"
// stops being aspirational.
package level

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/report"
)

// Track is one SLSA track this verb can judge. Constructed only by
// this package's vars: a track is a fact of the spec, never a caller's
// string.
type Track struct {
	name    string
	label   string
	ceiling int
	draft   bool
}

// The judgeable tracks. Build and Source are approved in SLSA v1.2;
// Dependency exists only as a draft page, which is a reason to MARK
// the judgment, not to refuse it — an unexamined claim is likelier to
// be wrong when the spec under it is still moving, not less
// (docs/level.md). The Build Environment track is deliberately absent
// while the only claim made on it is L0, which asserts nothing.
//
//nolint:gochecknoglobals // the track set is a fact of the spec, not state
var (
	TrackBuild      = Track{name: "BUILD", label: "SLSA Build", ceiling: buildCeiling}
	TrackSource     = Track{name: "SOURCE", label: "SLSA Source", ceiling: sourceCeilingLevel}
	TrackDependency = Track{name: "DEPENDENCY", label: "SLSA Dependencies", ceiling: dependencyCeiling, draft: true}
)

// The highest level each track defines: Build L0–L3 and Source L1–L4
// from SLSA v1.2, Dependency L0–L4 from the draft page.
const (
	buildCeiling       = 3
	sourceCeilingLevel = 4
	dependencyCeiling  = 4
)

// Name is the track's SlsaResult name (BUILD, SOURCE, DEPENDENCY).
func (t Track) Name() string { return t.name }

// Label is the shield's human name for the track.
func (t Track) Label() string { return t.label }

// Draft reports whether SLSA v1.2 approves this track.
func (t Track) Draft() bool { return !t.approved() }

// Level renders one level of this track in the spec's SlsaResult
// vocabulary: SLSA_<TRACK>_LEVEL_<N>.
func (t Track) Level(n int) string {
	return "SLSA_" + t.name + "_LEVEL_" + strconv.Itoa(n)
}

// Unevaluated is the spec's value for a track the judge did not
// evaluate — distinct from level zero, which is a judgment.
func (t Track) Unevaluated() string { return "SLSA_" + t.name + "_LEVEL_UNEVALUATED" }

func (t Track) approved() bool { return !t.draft }

// Determination is one level's outcome. Four values, because the two
// ways of not holding a level are not the same claim and the one way
// of not being asked is neither.
type Determination string

// The four determinations.
const (
	// Held: every requirement at this level is proven from evidence.
	Held Determination = "HELD"
	// Refuted: some requirement is contradicted by evidence.
	Refuted Determination = "REFUTED"
	// Undetermined: some requirement could not be looked at.
	Undetermined Determination = "UNDETERMINED"
	// Unclaimed: the policy declares no obligation at this level.
	Unclaimed Determination = "UNCLAIMED"
)

// Rung is one level's determination and the reason for it. A rung
// without a reason is unrepresentable: every constructor takes one,
// because "L3: REFUTED" with no cause is an accusation, not a report.
type Rung struct {
	Level         int
	Determination Determination
	Reason        string
}

// Ladder is one track's per-level determination. Constructor:
// NewLadder plus the recording methods — the zero value carries no
// rungs and Scalar refuses it.
type Ladder struct {
	track Track
	rungs map[int]Rung
}

// NewLadder starts an empty ladder for one track.
func NewLadder(t Track) *Ladder {
	return &Ladder{track: t, rungs: map[int]Rung{}}
}

// Hold records a level as proven.
func (l *Ladder) Hold(n int, reason string) { l.record(n, Held, reason) }

// Refute records a level as contradicted by evidence.
func (l *Ladder) Refute(n int, reason string) { l.record(n, Refuted, reason) }

// Blind records a level whose requirements could not be looked at.
func (l *Ladder) Blind(n int, reason string) { l.record(n, Undetermined, reason) }

// Unclaimed records a level the policy declares no obligation at.
func (l *Ladder) Unclaimed(n int, reason string) { l.record(n, Unclaimed, reason) }

// CapAt marks every level above n as refuted for one reason — the
// underclaim shape: a policy that says "if the controls lapse, this
// branch is level N" is capping the ladder, not silencing it.
func (l *Ladder) CapAt(n int, reason string) {
	for i := n + 1; i <= l.track.ceiling; i++ {
		l.record(i, Refuted, reason)
	}
}

// severity orders determinations by how much they stop a claim.
func severity(d Determination) int {
	switch d {
	case Refuted:
		return rankRefuted
	case Undetermined:
		return rankUndetermined
	case Unclaimed:
		return rankUnclaimed
	case Held:
		return rankHeld
	default:
		return rankHeld
	}
}

// Rungs lists the ladder from level 1 to the track's ceiling. A level
// never recorded reads as Undetermined: a judge that simply forgot to
// ask must not render as a level that holds.
func (l *Ladder) Rungs() []Rung {
	out := make([]Rung, 0, l.track.ceiling)

	for i := 1; i <= l.track.ceiling; i++ {
		if r, ok := l.rungs[i]; ok {
			out = append(out, r)

			continue
		}

		out = append(out, Rung{Level: i, Determination: Undetermined, Reason: "this level was never evaluated"})
	}

	return out
}

// Scalar computes the level the ladder supports and whether sight was
// lost at its boundary. The level is the highest N whose rungs 1..N
// all hold — the spec's own cumulative rule, where each level implies
// those below it. blind reports that the FIRST non-holding rung is
// undetermined rather than refuted or unclaimed: the level above the
// answer was not looked at, so the answer is honest but incomplete,
// and the report must not read as a confident ceiling.
func (l *Ladder) Scalar() (int, bool) {
	scalar := 0

	for _, r := range l.Rungs() {
		if r.Determination != Held {
			return scalar, r.Determination == Undetermined
		}

		scalar = r.Level
	}

	return scalar, false
}

// record writes one rung, never overwriting a worse determination
// with a better one: a level refuted by one requirement is not
// rescued by another requirement holding.
func (l *Ladder) record(n int, d Determination, reason string) {
	if n < 1 || n > l.track.ceiling {
		return
	}

	if prev, ok := l.rungs[n]; ok && severity(prev.Determination) >= severity(d) {
		return
	}

	l.rungs[n] = Rung{Level: n, Determination: d, Reason: reason}
}

// The severity ranks. Refuted outranks Undetermined: evidence that
// contradicts a level settles it, while evidence that is merely
// missing does not.
const (
	rankHeld = iota
	rankUnclaimed
	rankUndetermined
	rankRefuted
)

// Assessment is one track's sealed judgment: the report a consumer
// reads and the shield a README renders, both derived from one seal
// so no copy of the level can drift from another. Constructor: Seal.
type Assessment struct {
	rungs  []Rung
	track  Track
	level  string
	ladder string
	rep    *report.Report
	shield Shield
}

// Report is the sealed verdict document.
func (a *Assessment) Report() *report.Report { return a.rep }

// Level is the computed scalar in the spec's SlsaResult vocabulary.
func (a *Assessment) Level() string { return a.level }

// Track is the track this judgment was made on.
func (a *Assessment) Track() Track { return a.track }

// Ladder renders the per-level determinations as one line, for the
// human-readable half of the verb: a level with no account of how it
// was reached is a number, not a judgment.
func (a *Assessment) Ladder() string { return a.ladder }

// Shield is the shields.io endpoint document for this judgment.
func (a *Assessment) Shield() Shield { return a.shield }

// Rungs lists the per-level determinations this judgment reached.
func (a *Assessment) Rungs() []Rung { return a.rungs }

// Inputs is everything a leg hands to Seal beside its ladder: what was
// judged, what the policy declared, what the trust map permits, and
// which member of the population set the answer.
type Inputs struct {
	// Subject names what was judged, as the mode names it.
	Subject string
	// Declared is the policy's target level for this track, empty when
	// the policy declares no target.
	Declared string
	// Ceiling is the maximum the trust map permits for the attester,
	// empty when no map entry applied.
	Ceiling string
	// Weakest names the population member that set the scalar.
	Weakest string
	// InScope and Determined size the population: a subject whose
	// ladder went blind is NOT a subject this run judged, so the two
	// numbers differ and the report's own coverage law seals
	// CANNOT_JUDGE without this package restating it.
	InScope, Determined int
	// PopulationDetail names what the population is made of.
	PopulationDetail string
	// Findings are the divergences the leg observed.
	Findings []report.Finding
	// ExtraFacts are the leg's own facts, beside the shared ones.
	ExtraFacts []report.Fact
	// Now stamps the judgment.
	Now time.Time
}

// Seal turns a ladder and its inputs into the one sealed judgment
// they support. The comparison with the declared target happens here,
// once, for every track: disagreement in EITHER direction is a
// finding — a level claimed above the evidence is an overclaim, and a
// level the evidence supports above the claim is one that became true
// and went unrecorded, which is the same defect (issue #5).
func Seal(t Track, lad *Ladder, in *Inputs) *Assessment {
	scalar, blind := lad.Scalar()
	computed := t.Level(scalar)

	findings := append([]report.Finding(nil), in.Findings...)

	if in.Declared != "" && !blind {
		if f, ok := disagreement(t, computed, in.Declared, in.Subject); ok {
			findings = append(findings, f)
		}
	}

	facts := []report.Fact{
		{Name: "level", Value: computed},
		{Name: "specStatus", Value: specStatus(t)},
		{Name: "ladder", Value: renderLadder(lad)},
		{Name: "sealedAt", Value: in.Now.UTC().Format(time.RFC3339)},
	}
	facts = optionalFact(facts, "declared", in.Declared)
	facts = optionalFact(facts, "ceiling", in.Ceiling)
	facts = optionalFact(facts, "weakest", in.Weakest)
	facts = append(facts, in.ExtraFacts...)

	// A level is an at-least claim. Blindness ABOVE an established
	// rung is recorded (the boundary fact and the ladder both say so)
	// but does not unseat the answer: level 2 with level 3 unreadable
	// is level 2. Only a ladder that lost sight before any rung held
	// has determined nothing — level zero must mean "measured, and no
	// level holds", never "nobody could look". Applied here rather
	// than in each leg, so a leg CANNOT forget its own blindness and
	// seal a measurement over it.
	established := scalar > 0 || !blind

	if blind && scalar > 0 {
		facts = append(facts, report.Fact{
			Name:  "boundary",
			Value: fmt.Sprintf("sight ends above level %d; the level is a floor, not a ceiling", scalar),
		})
	}

	determined := in.Determined
	if !established {
		determined = 0
	}

	pop := report.PopulationAgainstDeclared(determined, in.InScope, in.PopulationDetail)

	// `level` takes no declaration (#125), and that extends to
	// exceptions: nothing a policy or a debt file says may excuse a
	// measured rung, so the journal this seals through opens empty.
	// Every finding still enters through it, which is what keeps the
	// document's coverage claim answerable.
	j := report.NewJournal()
	for i := range findings {
		j.Check(findings[i].Subject, findings[i].Assertion).
			DivergedFrom(findings[i].Expected, findings[i].Actual, findings[i].Detail)
	}

	rep := report.Seal("level "+strings.ToLower(t.name), in.Subject, pop, j,
		report.NoCanary(), report.NoJudgedSet(), facts...)

	return &Assessment{
		rungs: lad.Rungs(),
		track: t, level: computed, ladder: renderLadder(lad),
		rep: rep, shield: shieldFor(t, established, scalar),
	}
}

// disagreement compares the computed scalar with the declared target
// and names which direction the gap runs.
func disagreement(t Track, computed, declared, subject string) (report.Finding, bool) {
	if computed == declared {
		return report.Finding{}, false
	}

	detail := "the evidence supports a level the declaration does not claim" +
		" — a level that became true and went unrecorded is the same defect as one claimed early"
	if below(t, computed, declared) {
		detail = "the declaration claims a level the evidence does not support"
	}

	return report.Finding{
		Subject:   subject,
		Assertion: "declared-level",
		Expected:  declared,
		Actual:    computed,
		Detail:    detail,
	}, true
}

// below reports whether computed is a lower level than declared on
// this track. A declared value that does not parse as this track's
// level is treated as not-below: the gap is real either way, and the
// wording is the only thing at stake.
func below(t Track, computed, declared string) bool {
	c, cok := parseLevel(t, computed)
	d, dok := parseLevel(t, declared)

	return cok && dok && c < d
}

// parseLevel reads this track's level number out of a SlsaResult
// value, refusing another track's level.
func parseLevel(t Track, s string) (int, bool) {
	prefix := "SLSA_" + t.name + "_LEVEL_"
	if !strings.HasPrefix(s, prefix) {
		return 0, false
	}

	n, err := strconv.Atoi(strings.TrimPrefix(s, prefix))
	if err != nil {
		return 0, false
	}

	return n, true
}

func specStatus(t Track) string {
	if t.approved() {
		return "approved"
	}

	return "draft"
}

func optionalFact(facts []report.Fact, name, value string) []report.Fact {
	if value == "" {
		return facts
	}

	return append(facts, report.Fact{Name: name, Value: value})
}

// renderLadder writes the ladder as one fact value: "1:HELD 2:HELD
// 3:UNDETERMINED 4:UNCLAIMED". Compact on purpose — the reasons live
// in findings and log lines, and a fact is a datum, not a document.
func renderLadder(lad *Ladder) string {
	var b strings.Builder

	for i, r := range lad.Rungs() {
		if i > 0 {
			b.WriteString(" ")
		}

		fmt.Fprintf(&b, "%d:%s", r.Level, r.Determination)
	}

	return b.String()
}

// Shield is the shields.io endpoint document. It is derived from the
// same seal as the report, in the same process: there is no decoder
// from a report document back into a report (report/report.go says
// why), so a render that parsed one could be handed a forged verdict.
type Shield struct {
	SchemaVersion int    `json:"schemaVersion"`
	Label         string `json:"label"`
	Message       string `json:"message"`
	Color         string `json:"color"`
}

// The shields.io colours. The badge is information, not a judgment:
// an established level renders green whatever the number is, because
// the level IS the message — it moves up and down as the evidence
// does. Grey exists for exactly one honest case: the measurement
// could not establish any level at all, and a badge that cannot see
// must not pick a number.
const (
	colorLevel = "brightgreen"
	colorBlind = "lightgrey"
)

// shieldFor renders one judgment as an endpoint document. A draft
// track says so in the message, where a reader sees it, rather than
// in a field only a machine reads.
func shieldFor(t Track, established bool, scalar int) Shield {
	message := "L" + strconv.Itoa(scalar)
	color := colorLevel

	if !established {
		message, color = "unmeasured", colorBlind
	}

	if t.draft {
		message += " (draft)"
	}

	return Shield{SchemaVersion: 1, Label: t.label, Message: message, Color: color}
}

// Encode writes the shield as one JSON document plus newline.
func (s Shield) Encode(w io.Writer) error {
	if err := jsonx.Encode(w, s); err != nil {
		return fmt.Errorf("level: shield: %w", err)
	}

	return nil
}
