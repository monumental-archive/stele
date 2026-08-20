package level_test

import (
	"bytes"
	"errors"
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

	tracks := level.Tracks()
	if len(tracks) != 3 {
		t.Fatalf("Tracks = %v, want the three this release judges", tracks)
	}

	for _, tt := range []struct {
		track       level.Track
		name        string
		key         string
		level3      string
		unevaluated string
		draft       bool
	}{
		{level.TrackBuild, "BUILD", "build", "SLSA_BUILD_LEVEL_3", "SLSA_BUILD_LEVEL_UNEVALUATED", false},
		{level.TrackSource, "SOURCE", "source", "SLSA_SOURCE_LEVEL_3", "SLSA_SOURCE_LEVEL_UNEVALUATED", false},
		// The draft track renders in the spec's own generic syntax —
		// SLSA_<TRACK>_LEVEL_<N> — because that syntax is defined over
		// track names, not over an approved list of them.
		{
			level.TrackDependency, "DEPENDENCY", "dependency",
			"SLSA_DEPENDENCY_LEVEL_3", "SLSA_DEPENDENCY_LEVEL_UNEVALUATED", true,
		},
	} {
		if got := tt.track.Name(); got != tt.name {
			t.Errorf("Name = %q, want %q", got, tt.name)
		}

		// The command line's spelling and the policy document's are
		// one fact DERIVED from the spec name, never written twice.
		if got := tt.track.Key(); got != tt.key {
			t.Errorf("Key = %q, want %q", got, tt.key)
		}

		if got, ok := level.TrackByName(tt.key); !ok || got != tt.track {
			t.Errorf("TrackByName(%q) = %v, %v", tt.key, got, ok)
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

	// A track this release does not judge is ABSENT from the
	// vocabulary; what that means about a caller's own document is the
	// caller's to decide, and this package refuses nothing.
	for _, absent := range []string{"BUILD", "platform", ""} {
		if _, ok := level.TrackByName(absent); ok {
			t.Errorf("TrackByName(%q) resolved — the policy spelling is lower case, and only these three",
				absent)
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

// TestRungPrecedenceIsWorstWins pins the whole ordering, one pair at a
// time. The rule is that a rung is never improved after the fact — a
// level refuted by one requirement is not rescued by the next one
// holding — and that ordering is the only thing standing between a
// ladder and a report that quotes whichever requirement happened to be
// evaluated last.
//
// UNCLAIMED's place in it is the row worth stating: it outranks HELD,
// so a level the specification places no obligation at cannot be
// talked up into holding, but it yields to both UNDETERMINED and
// REFUTED, because "nothing was asked here" must never suppress a
// genuine failure recorded at the same rung.
func TestRungPrecedenceIsWorstWins(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name   string
		first  func(*level.Ladder)
		second func(*level.Ladder)
		want   level.Determination
	}{
		{
			"unclaimed is not talked up into held",
			func(l *level.Ladder) { l.Unclaimed(2, "no obligation") },
			func(l *level.Ladder) { l.Hold(2, "something held") },
			level.Unclaimed,
		},
		{
			"unclaimed yields to a genuine blindness",
			func(l *level.Ladder) { l.Unclaimed(2, "no obligation") },
			func(l *level.Ladder) { l.Blind(2, "could not look") },
			level.Undetermined,
		},
		{
			"unclaimed yields to a refutation",
			func(l *level.Ladder) { l.Unclaimed(2, "no obligation") },
			func(l *level.Ladder) { l.Refute(2, "contradicted") },
			level.Refuted,
		},
		{
			"a refutation is not rescued by a later hold",
			func(l *level.Ladder) { l.Refute(2, "contradicted") },
			func(l *level.Ladder) { l.Hold(2, "something held") },
			level.Refuted,
		},
		{
			"blindness is not rescued by a later hold",
			func(l *level.Ladder) { l.Blind(2, "could not look") },
			func(l *level.Ladder) { l.Hold(2, "something held") },
			level.Undetermined,
		},
		{
			"a refutation outranks blindness: contradiction settles a level, absence does not",
			func(l *level.Ladder) { l.Blind(2, "could not look") },
			func(l *level.Ladder) { l.Refute(2, "contradicted") },
			level.Refuted,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			lad := level.NewLadder(level.TrackBuild)
			tt.first(lad)
			tt.second(lad)

			for _, r := range lad.Rungs() {
				if r.Level == 2 && r.Determination != tt.want {
					t.Errorf("rung 2 = %q, want %q", r.Determination, tt.want)
				}
			}
		})
	}
}

// TestDeclaredLevelThatDoesNotParseStillDiverges. A declaration is
// somebody else's document, and it can say something this track cannot
// read: another track's level, or a spelling with no number in it.
//
// The gap is real either way — the declared string is not what was
// computed — so the finding is raised regardless; only the WORDING
// depends on being able to compare the two, and an unreadable
// declaration cannot be shown to sit above the evidence. Reporting no
// divergence at all would be the dangerous reading: a policy could
// then silence a real disagreement with a typo.
func TestDeclaredLevelThatDoesNotParseStillDiverges(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name     string
		declared string
	}{
		{"another track's level", "SLSA_BUILD_LEVEL_3"},
		{"this track's prefix with no number", "SLSA_SOURCE_LEVEL_three"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			lad := level.NewLadder(level.TrackSource)
			lad.Hold(1, "r")
			lad.Refute(2, "r")

			a := level.Seal(level.TrackSource, lad, &level.Inputs{
				Subject: "acme/widget", Declared: tt.declared,
				InScope: 1, Determined: 1,
				PopulationDetail: "branches", Now: epoch,
			})

			if got := a.Report().Verdict(); got != report.VerdictFail {
				t.Errorf("verdict = %q, want FAIL — an unreadable declaration must not silence the gap", got)
			}

			var buf bytes.Buffer
			if err := a.Report().Encode(&buf); err != nil {
				t.Fatalf("Encode = %v", err)
			}

			// Unreadable means uncomparable, so the report takes the
			// direction it can defend: the evidence supports something
			// the declaration does not claim.
			if !strings.Contains(buf.String(), "the declaration does not claim") {
				t.Errorf("divergence is worded as an overclaim it cannot prove:\n%s", buf.String())
			}
		})
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

// TestShieldRoundTripsThroughItsOwnDecoder is the board's
// never-overwrite rule, held at the one place it is decided.
//
// A published board asks a cell what it ALREADY holds, so that a run
// which cannot judge today does not publish grey over a level somebody
// proved yesterday. Two things have to be true for that to work: a
// shield this package wrote must read back through DecodeShield, and
// Measured must answer from the same field the writer set — if the two
// ever came apart, a grey cell could read as measured and overwrite a
// real level, which is the one direction the rule exists to forbid.
func TestShieldRoundTripsThroughItsOwnDecoder(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		build func(*level.Ladder)
		done  int
		want  bool
	}{
		{"a level that holds was measured", func(l *level.Ladder) { l.Hold(1, "r") }, 1, true},
		{"a measured zero was still measured", func(l *level.Ladder) { l.Refute(1, "r") }, 1, true},
		{"a run that could not see was not", func(l *level.Ladder) { l.Blind(1, "r") }, 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			lad := level.NewLadder(level.TrackSource)
			tt.build(lad)

			a := level.Seal(level.TrackSource, lad, &level.Inputs{
				Subject: "acme/widget", InScope: 1, Determined: tt.done,
				PopulationDetail: "subjects", Now: epoch,
			})

			var buf bytes.Buffer
			if err := a.Shield().Encode(&buf); err != nil {
				t.Fatalf("Encode = %v", err)
			}

			back, err := level.DecodeShield(&buf)
			if err != nil {
				t.Fatalf("DecodeShield(own bytes) = %v", err)
			}

			if *back != a.Shield() {
				t.Errorf("round trip changed the shield: %+v, want %+v", *back, a.Shield())
			}

			if back.Measured() != tt.want {
				t.Errorf("Measured = %v, want %v for %+v", back.Measured(), tt.want, *back)
			}
		})
	}
}

// TestDecodeShieldRefusesWhatItDidNotWrite: the board reads cells off
// a published site, and a document that is not a shield must refuse
// rather than decode to a zero value — a zero Shield has the empty
// colour, which Measured would read as measured, and the board would
// then decline to publish over a cell that never held anything.
func TestDecodeShieldRefusesWhatItDidNotWrite(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		doc  string
	}{
		{"not JSON at all", "<html>404</html>"},
		{"a document with a field no shield carries", `{"schemaVersion":1,"label":"x","extra":true}`},
		{"two documents where one was expected", `{"schemaVersion":1}{"schemaVersion":1}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := level.DecodeShield(strings.NewReader(tt.doc)); err == nil {
				t.Errorf("DecodeShield(%s) succeeded, want a refusal", tt.doc)
			}
		})
	}
}

// TestUnenumeratedIsAnAnswerAboutTheRun, not about the subject. When
// the population itself could not be listed — the degraded forge that
// answers 200 with an empty body — nothing was measured, and the one
// honest output says so: no level, a grey badge, CANNOT_JUDGE, and the
// cause quoted where a reader can act on it. Reporting L0 here would
// be this tool asserting a fact about a repository it never reached.
func TestUnenumeratedIsAnAnswerAboutTheRun(t *testing.T) {
	t.Parallel()

	cause := errors.New("listing acme: 200 with an empty body")

	a := level.Unenumerated(level.TrackSource, "acme", cause, epoch)

	if got := a.Report().Verdict(); got != report.VerdictCannotJudge {
		t.Errorf("verdict = %q, want CANNOT_JUDGE — not reaching the population is not a level", got)
	}

	if got := a.Shield(); got.Measured() {
		t.Errorf("shield = %+v, want an unmeasured cell that cannot overwrite a published level", got)
	}

	var buf bytes.Buffer
	if err := a.Report().Encode(&buf); err != nil {
		t.Fatalf("Encode = %v", err)
	}

	if !strings.Contains(buf.String(), cause.Error()) {
		t.Errorf("the report does not carry the cause:\n%s", buf.String())
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
