package level_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/level"
	"github.com/monumental-archive/stele/internal/report"
)

// epoch is a fixed stamp: a judgment's clock is an input, never a
// reason for a test to differ from itself.
var epoch = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

func TestTrackVocabulary(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		track       level.Track
		name        string
		level3      string
		unevaluated string
		draft       bool
	}{
		{level.TrackBuild, "BUILD", "SLSA_BUILD_LEVEL_3", "SLSA_BUILD_LEVEL_UNEVALUATED", false},
		{level.TrackSource, "SOURCE", "SLSA_SOURCE_LEVEL_3", "SLSA_SOURCE_LEVEL_UNEVALUATED", false},
		// The draft track renders in the spec's own generic syntax —
		// SLSA_<TRACK>_LEVEL_<N> — because that syntax is defined over
		// track names, not over an approved list of them.
		{level.TrackDependency, "DEPENDENCY", "SLSA_DEPENDENCY_LEVEL_3", "SLSA_DEPENDENCY_LEVEL_UNEVALUATED", true},
	} {
		if got := tt.track.Name(); got != tt.name {
			t.Errorf("Name = %q, want %q", got, tt.name)
		}

		if got := tt.track.Level(3); got != tt.level3 {
			t.Errorf("Level(3) = %q, want %q", got, tt.level3)
		}

		if got := tt.track.Unevaluated(); got != tt.unevaluated {
			t.Errorf("Unevaluated = %q, want %q", got, tt.unevaluated)
		}

		if got := tt.track.Draft(); got != tt.draft {
			t.Errorf("Draft = %v, want %v — v1.2 approves the build and source tracks only", got, tt.draft)
		}
	}
}

// TestScalar is the heart of the verb: which level a ladder supports,
// and whether the answer is bounded by a refusal or by blindness. Each
// row breaks exactly one fact.
func TestScalar(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name   string
		build  func(*level.Ladder)
		scalar int
		blind  bool
	}{
		{
			name:   "an empty ladder supports nothing and cannot see",
			build:  func(*level.Ladder) {},
			scalar: 0,
			blind:  true,
		},
		{
			name:   "levels hold cumulatively",
			build:  func(l *level.Ladder) { l.Hold(1, "r"); l.Hold(2, "r"); l.Refute(3, "r") },
			scalar: 2,
		},
		{
			name:   "a refuted level bounds the answer confidently",
			build:  func(l *level.Ladder) { l.Hold(1, "r"); l.Refute(2, "r"); l.Hold(3, "r") },
			scalar: 1,
		},
		{
			name:   "an undetermined level above the answer loses sight",
			build:  func(l *level.Ladder) { l.Hold(1, "r"); l.Hold(2, "r"); l.Blind(3, "r") },
			scalar: 2,
			blind:  true,
		},
		{
			name:   "an unclaimed level above the answer is not blindness",
			build:  func(l *level.Ladder) { l.Hold(1, "r"); l.Hold(2, "r"); l.Unclaimed(3, "r") },
			scalar: 2,
		},
		{
			name:   "a gap in the middle is undetermined, never held by omission",
			build:  func(l *level.Ladder) { l.Hold(1, "r"); l.Hold(3, "r") },
			scalar: 1,
			blind:  true,
		},
		{
			name:   "CapAt refutes every level above the cap",
			build:  func(l *level.Ladder) { l.Hold(1, "r"); l.Hold(2, "r"); l.Hold(3, "r"); l.CapAt(1, "cap") },
			scalar: 1,
		},
		{
			name:   "a refusal is not rescued by a later hold",
			build:  func(l *level.Ladder) { l.Refute(1, "r"); l.Hold(1, "later") },
			scalar: 0,
		},
		{
			name:   "blindness IS replaced by a refusal — evidence settles what absence cannot",
			build:  func(l *level.Ladder) { l.Blind(2, "r"); l.Hold(1, "r"); l.Refute(2, "settled") },
			scalar: 1,
		},
		{
			name:   "a level outside the track's ceiling is not recordable",
			build:  func(l *level.Ladder) { l.Hold(1, "r"); l.Hold(2, "r"); l.Hold(3, "r"); l.Hold(9, "r") },
			scalar: 3,
		},
	} {
		lad := level.NewLadder(level.TrackBuild)
		tt.build(lad)

		scalar, blind := lad.Scalar()
		if scalar != tt.scalar || blind != tt.blind {
			t.Errorf("%s: Scalar = %d, %v — want %d, %v", tt.name, scalar, blind, tt.scalar, tt.blind)
		}
	}
}

func TestRungsFillGapsAsUndetermined(t *testing.T) {
	t.Parallel()

	lad := level.NewLadder(level.TrackSource)
	lad.Hold(1, "proven")

	rungs := lad.Rungs()
	if len(rungs) != 4 {
		t.Fatalf("Rungs = %d, want one per level of the source track", len(rungs))
	}

	for _, r := range rungs[1:] {
		if r.Determination != level.Undetermined || r.Reason == "" {
			t.Errorf("level %d = %q (%q), want an undetermined rung with a reason", r.Level, r.Determination, r.Reason)
		}
	}
}

// TestSealVerdicts proves the three ways a judgment ends, and that the
// declared-level comparison reddens in BOTH directions.
func TestSealVerdicts(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name     string
		build    func(*level.Ladder)
		declared string
		scope    int
		done     int
		want     report.Verdict
		level    string
	}{
		{
			name:     "computed matches the declaration",
			build:    func(l *level.Ladder) { l.Hold(1, "r"); l.Hold(2, "r"); l.Hold(3, "r") },
			declared: "SLSA_BUILD_LEVEL_3",
			scope:    1, done: 1,
			want:  report.VerdictPass,
			level: "SLSA_BUILD_LEVEL_3",
		},
		{
			name:     "the declaration outruns the evidence",
			build:    func(l *level.Ladder) { l.Hold(1, "r"); l.Refute(2, "r") },
			declared: "SLSA_BUILD_LEVEL_3",
			scope:    1, done: 1,
			want:  report.VerdictFail,
			level: "SLSA_BUILD_LEVEL_1",
		},
		{
			name:     "the evidence outruns the declaration — an unrecorded gain reddens too",
			build:    func(l *level.Ladder) { l.Hold(1, "r"); l.Hold(2, "r"); l.Hold(3, "r") },
			declared: "SLSA_BUILD_LEVEL_2",
			scope:    1, done: 1,
			want:  report.VerdictFail,
			level: "SLSA_BUILD_LEVEL_3",
		},
		{
			name:     "a short population cannot be judged",
			build:    func(l *level.Ladder) { l.Hold(1, "r"); l.Hold(2, "r"); l.Hold(3, "r") },
			declared: "SLSA_BUILD_LEVEL_3",
			scope:    2, done: 1,
			want:  report.VerdictCannotJudge,
			level: "SLSA_BUILD_LEVEL_3",
		},
		{
			name:     "an empty population cannot be judged",
			build:    func(l *level.Ladder) { l.Blind(1, "r") },
			declared: "SLSA_BUILD_LEVEL_3",
			scope:    1, done: 0,
			want:  report.VerdictCannotJudge,
			level: "SLSA_BUILD_LEVEL_0",
		},
		{
			name:     "a blind boundary suppresses the comparison rather than accusing",
			build:    func(l *level.Ladder) { l.Hold(1, "r"); l.Blind(2, "r") },
			declared: "SLSA_BUILD_LEVEL_3",
			scope:    1, done: 0,
			want:  report.VerdictCannotJudge,
			level: "SLSA_BUILD_LEVEL_1",
		},
		{
			name:     "no declaration means nothing to disagree with",
			build:    func(l *level.Ladder) { l.Hold(1, "r"); l.Refute(2, "r") },
			declared: "",
			scope:    1, done: 1,
			want:  report.VerdictPass,
			level: "SLSA_BUILD_LEVEL_1",
		},
	} {
		lad := level.NewLadder(level.TrackBuild)
		tt.build(lad)

		a := level.Seal(level.TrackBuild, lad, &level.Inputs{
			Subject: "acme/widget", Declared: tt.declared,
			InScope: tt.scope, Determined: tt.done,
			PopulationDetail: "subjects", Now: epoch,
		})

		if got := a.Report().Verdict(); got != tt.want {
			t.Errorf("%s: verdict = %q, want %q", tt.name, got, tt.want)
		}

		if got := a.Level(); got != tt.level {
			t.Errorf("%s: level = %q, want %q", tt.name, got, tt.level)
		}
	}
}

func TestSealRecordsTheLadderAndTheClock(t *testing.T) {
	t.Parallel()

	lad := level.NewLadder(level.TrackSource)
	lad.Hold(1, "r")
	lad.Hold(2, "r")
	lad.Blind(3, "r")
	lad.Unclaimed(4, "r")

	a := level.Seal(level.TrackSource, lad, &level.Inputs{
		Subject: "acme/widget", InScope: 1, Determined: 1,
		PopulationDetail: "branches", Now: epoch,
	})

	var buf bytes.Buffer
	if err := a.Report().Encode(&buf); err != nil {
		t.Fatalf("Encode = %v", err)
	}

	for _, want := range []string{
		`"target":"level source"`,
		`"1:HELD 2:HELD 3:UNDETERMINED 4:UNCLAIMED"`,
		`"2026-08-18T12:00:00Z"`,
		`"specStatus"`,
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("report does not carry %s:\n%s", want, buf.String())
		}
	}
}

// TestShield proves the render a README points at: the colour follows
// the verdict, and a draft track says so where a reader can see it.
func TestShield(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		track   level.Track
		build   func(*level.Ladder)
		done    int
		label   string
		message string
		color   string
	}{
		{
			name:  "a passing judgment is green",
			track: level.TrackSource,
			build: func(l *level.Ladder) { l.Hold(1, "r"); l.Hold(2, "r"); l.Hold(3, "r"); l.Unclaimed(4, "r") },
			done:  1, label: "SLSA Source", message: "L3", color: "brightgreen",
		},
		{
			name:  "a judgment that could not see is grey and picks no number",
			track: level.TrackSource,
			build: func(l *level.Ladder) { l.Blind(1, "r") },
			done:  0, label: "SLSA Source", message: "unmeasured", color: "lightgrey",
		},
		{
			// The badge is information, not a judgment: a measured zero
			// is an answer, and the level moves down as the evidence
			// does — in green, because green means "this is the level".
			name:  "a measured zero is an answer, in green",
			track: level.TrackSource,
			build: func(l *level.Ladder) { l.Refute(1, "r") },
			done:  1, label: "SLSA Source", message: "L0", color: "brightgreen",
		},
		{
			// Blindness ABOVE an established rung does not grey the
			// badge: a level is an at-least claim, and the floor is the
			// truth.
			name:  "sight lost above an established level stays green at the floor",
			track: level.TrackSource,
			build: func(l *level.Ladder) { l.Hold(1, "r"); l.Hold(2, "r"); l.Blind(3, "r") },
			done:  1, label: "SLSA Source", message: "L2", color: "brightgreen",
		},
		{
			name:  "a draft track carries its status in the message",
			track: level.TrackDependency,
			build: func(l *level.Ladder) { l.Hold(1, "r"); l.Hold(2, "r"); l.Unclaimed(3, "r"); l.Unclaimed(4, "r") },
			done:  1, label: "SLSA Dependencies", message: "L2 (draft)", color: "brightgreen",
		},
	} {
		lad := level.NewLadder(tt.track)
		tt.build(lad)

		a := level.Seal(tt.track, lad, &level.Inputs{
			Subject: "acme/widget", InScope: 1, Determined: tt.done,
			PopulationDetail: "subjects", Now: epoch,
		})

		got := a.Shield()
		if got.SchemaVersion != 1 || got.Label != tt.label || got.Message != tt.message || got.Color != tt.color {
			t.Errorf("%s: Shield = %+v, want {1 %q %q %q}", tt.name, got, tt.label, tt.message, tt.color)
		}

		var buf bytes.Buffer
		if err := got.Encode(&buf); err != nil {
			t.Fatalf("%s: Encode = %v", tt.name, err)
		}

		if !strings.Contains(buf.String(), `"schemaVersion":1`) {
			t.Errorf("%s: shield document = %s", tt.name, buf.String())
		}
	}
}

func TestShieldEncodeReportsWriteFailure(t *testing.T) {
	t.Parallel()

	if err := (level.Shield{SchemaVersion: 1}).Encode(failingWriter{}); err == nil {
		t.Error("Encode = nil, want the write failure — a render that cannot write must not report success")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWrite }

var errWrite = writeError{}

type writeError struct{}

func (writeError) Error() string { return "write refused" }
