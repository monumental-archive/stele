package level_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/monumental-archive/stele/internal/level"
	"github.com/monumental-archive/stele/internal/report"
)

// TestCatalogueIsWellFormed guards the spine. Every requirement must
// carry the spec's words and sit at a level the track defines, because
// a report quotes this text back as the reason a level did not hold.
func TestCatalogueIsWellFormed(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}

	for _, tr := range []level.Track{level.TrackBuild, level.TrackSource, level.TrackDependency} {
		reqs := level.Requirements(tr)
		if len(reqs) == 0 {
			t.Errorf("%s: the catalogue is empty", tr.Name())
		}

		for _, r := range reqs {
			switch {
			case seen[r.ID]:
				t.Errorf("%s: requirement %q appears twice", tr.Name(), r.ID)
			// Source uses the ecosystem's control names, which carry
			// their own namespace; the other tracks have no such
			// vocabulary and use this tool's.
			case !strings.Contains(r.ID, tr.Name()) && !strings.HasPrefix(r.ID, strings.ToLower(tr.Name())+"/"):
				t.Errorf("%s: requirement %q is namespaced to no track", tr.Name(), r.ID)
			case r.Text == "":
				t.Errorf("%s: requirement %q carries no specification text", tr.Name(), r.ID)
			case r.Evidence == "":
				t.Errorf("%s: requirement %q names no evidence", tr.Name(), r.ID)
			case r.Level < 1:
				t.Errorf("%s: requirement %q sits below level 1", tr.Name(), r.ID)
			}

			seen[r.ID] = true
		}
	}
}

// TestRequirementsAtPartitionTheCatalogue: every requirement is
// reachable through the per-level lookup the ladder builds from, so a
// requirement cannot be in the catalogue yet never asked about.
func TestRequirementsAtPartitionTheCatalogue(t *testing.T) {
	t.Parallel()

	for _, tr := range []level.Track{level.TrackBuild, level.TrackSource, level.TrackDependency} {
		reached := 0
		for lvl := 1; lvl <= 4; lvl++ {
			reached += len(level.RequirementsAt(tr, lvl))
		}

		if got := len(level.Requirements(tr)); reached != got {
			t.Errorf("%s: per-level lookup reaches %d of %d requirements", tr.Name(), reached, got)
		}
	}
}

// buildSubject is a released artifact whose platform claims are all in
// order — the shape every row below breaks exactly one fact of.
func buildSubject() level.Subject {
	return level.Subject{
		Name:      "widget_linux_amd64",
		Verified:  true,
		BuildType: "https://actions.github.io/buildtypes/workflow/v1",
		Cert: certificate.Extensions{
			RunnerEnvironment: "github-hosted",
			BuildSignerURI:    "https://github.com/acme/signer/.github/workflows/sign.yml@refs/heads/main",
			BuildSignerDigest: "1111111111111111111111111111111111111111",
		},
	}
}

func buildEvidence() *level.Evidence {
	return &level.Evidence{
		Owner: "acme", Repo: "widget", Now: epoch,
		Subjects:             []level.Subject{buildSubject()},
		SignerRunsTenantCode: func(string, string) (bool, error) { return false, nil },
	}
}

// TestBuildTrackFromPlatformClaims is the answer to "is Build L3
// establishable from evidence". Every rung here is proven from the
// platform's own signed claims, not from anyone's declaration.
func TestBuildTrackFromPlatformClaims(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		breakIt func(*level.Evidence)
		level   string
	}{
		{
			name:    "a hosted build with a clean capability boundary reaches level 3",
			breakIt: func(*level.Evidence) {},
			level:   "SLSA_BUILD_LEVEL_3",
		},
		{
			name: "a self-hosted runner is the tenant's machine, so hosted does not hold",
			breakIt: func(ev *level.Evidence) {
				ev.Subjects[0].Cert.RunnerEnvironment = "self-hosted"
			},
			level: "SLSA_BUILD_LEVEL_1",
		},
		{
			name: "another platform's self-managed value refutes the same way",
			breakIt: func(ev *level.Evidence) {
				ev.Subjects[0].Cert.RunnerEnvironment = "self-managed"
			},
			level: "SLSA_BUILD_LEVEL_1",
		},
		{
			// The vocabulary is a table, not one platform's string: a
			// GitLab-hosted certificate is a hosted claim too.
			name: "another platform's hosted value holds the same way",
			breakIt: func(ev *level.Evidence) {
				ev.Subjects[0].Cert.RunnerEnvironment = "gitlab-hosted"
			},
			level: "SLSA_BUILD_LEVEL_3",
		},
		{
			name: "a signing workflow that runs caller code puts the key within tenant reach",
			breakIt: func(ev *level.Evidence) {
				ev.SignerRunsTenantCode = func(string, string) (bool, error) { return true, nil }
			},
			level: "SLSA_BUILD_LEVEL_2",
		},
		{
			name: "externalParameters outside the buildType's schema bound the track at 2",
			breakIt: func(ev *level.Evidence) {
				ev.Subjects[0].UnrecognisedParameters = []string{"surprise"}
			},
			level: "SLSA_BUILD_LEVEL_2",
		},
		{
			name: "provenance that does not verify establishes nothing",
			breakIt: func(ev *level.Evidence) {
				ev.Subjects[0].Verified = false
			},
			level: "SLSA_BUILD_LEVEL_0",
		},
	} {
		ev := buildEvidence()
		tt.breakIt(ev)

		a := level.Assess(level.TrackBuild, ev)
		if got := a.Level(); got != tt.level {
			t.Errorf("%s: level = %q, want %q\n%s", tt.name, got, tt.level, a.Ladder())
		}
	}
}

// TestBuildTrackBlindnessIsAFloor: absent evidence never becomes a
// pass at the blind rung, and never a refutation either. A level is an
// at-least claim, so sight lost ABOVE an established rung leaves the
// floor as the answer; only sight lost before any rung held is no
// answer at all.
func TestBuildTrackBlindnessIsAFloor(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		breakIt func(*level.Evidence)
		verdict report.Verdict
		level   string
	}{
		{
			name:    "no artifacts reached is no answer at all",
			breakIt: func(ev *level.Evidence) { ev.Subjects = nil },
			verdict: report.VerdictCannotJudge,
			level:   "SLSA_BUILD_LEVEL_0",
		},
		{
			name: "the certificate carries no runner claim, so level one is the floor",
			breakIt: func(ev *level.Evidence) {
				ev.Subjects[0].Cert.RunnerEnvironment = ""
			},
			verdict: report.VerdictPass,
			level:   "SLSA_BUILD_LEVEL_1",
		},
		{
			name: "the signing workflow could not be read, so level two is the floor",
			breakIt: func(ev *level.Evidence) {
				ev.SignerRunsTenantCode = func(string, string) (bool, error) {
					return false, errors.New("the forge refused")
				}
			},
			verdict: report.VerdictPass,
			level:   "SLSA_BUILD_LEVEL_2",
		},
		{
			name:    "no capability-boundary check was possible, so level two is the floor",
			breakIt: func(ev *level.Evidence) { ev.SignerRunsTenantCode = nil },
			verdict: report.VerdictPass,
			level:   "SLSA_BUILD_LEVEL_2",
		},
		{
			// A runner vocabulary this build does not know is a platform
			// it cannot judge — refuting it as "the tenant's machine"
			// would punish every platform the table has not met.
			name: "an unknown runner vocabulary is undetermined, not refuted",
			breakIt: func(ev *level.Evidence) {
				ev.Subjects[0].Cert.RunnerEnvironment = "quantum-hosted-v2"
			},
			verdict: report.VerdictPass,
			level:   "SLSA_BUILD_LEVEL_1",
		},
	} {
		ev := buildEvidence()
		tt.breakIt(ev)

		a := level.Assess(level.TrackBuild, ev)
		if got := a.Report().Verdict(); got != tt.verdict {
			t.Errorf("%s: verdict = %q, want %q\n%s", tt.name, got, tt.verdict, a.Ladder())
		}

		if got := a.Level(); got != tt.level {
			t.Errorf("%s: level = %q, want %q\n%s", tt.name, got, tt.level, a.Ladder())
		}
	}
}

// TestAssessTakesNoDeclaration is the structural guarantee this
// rebuild exists for: there is no policy, target or declared floor in
// the signature, so there is nowhere to write the answer down and have
// the tool repeat it back.
func TestAssessTakesNoDeclaration(t *testing.T) {
	t.Parallel()

	// Two runs over identical evidence must agree, because the only
	// input IS the evidence.
	first := level.Assess(level.TrackBuild, buildEvidence())
	second := level.Assess(level.TrackBuild, buildEvidence())

	if first.Level() != second.Level() || first.Ladder() != second.Ladder() {
		t.Errorf("identical evidence produced different answers:\n%s\n%s", first.Ladder(), second.Ladder())
	}
}

// TestReportNamesEveryRequirement: a level that does not hold must say
// which requirement failed and quote what the specification asked for.
func TestReportNamesEveryRequirement(t *testing.T) {
	t.Parallel()

	ev := buildEvidence()
	ev.Subjects[0].Cert.RunnerEnvironment = "self-hosted"

	a := level.Assess(level.TrackBuild, ev)

	var buf strings.Builder
	if err := a.Report().Encode(&buf); err != nil {
		t.Fatalf("Encode = %v", err)
	}

	doc := buf.String()

	for _, want := range []string{
		"build/hosted",
		"not on an individual's workstation",
		"requirementCoverage",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the report does not carry %q:\n%s", want, doc)
		}
	}
}

// TestDependencyTrackFromReleaseEvidence walks the draft track.
func TestDependencyTrackFromReleaseEvidence(t *testing.T) {
	t.Parallel()

	clean := func() *level.Evidence {
		return &level.Evidence{
			Owner: "acme", Repo: "widget", Now: epoch,
			Inventoried: []string{"widget_linux_amd64"},
			Scanned:     true,
			Findings:    2, Triaged: 2,
			DependencySources: map[string]bool{"https://mirror.acme.example/go": true},
		}
	}

	for _, tt := range []struct {
		name    string
		breakIt func(*level.Evidence)
		level   string
	}{
		{
			name:    "inventory, triage and producer-controlled sources reach level 3",
			breakIt: func(*level.Evidence) {},
			level:   "SLSA_DEPENDENCY_LEVEL_3",
		},
		{
			name: "an artifact with no inventory establishes nothing",
			breakIt: func(ev *level.Evidence) {
				ev.Uninventoried = []string{"widget_darwin_arm64"}
			},
			level: "SLSA_DEPENDENCY_LEVEL_0",
		},
		{
			name:    "an undecided finding bounds the track at the inventory",
			breakIt: func(ev *level.Evidence) { ev.Triaged = 1 },
			level:   "SLSA_DEPENDENCY_LEVEL_1",
		},
		{
			name: "an upstream source bounds the track below producer-controlled",
			breakIt: func(ev *level.Evidence) {
				ev.DependencySources["https://proxy.golang.org"] = false
			},
			level: "SLSA_DEPENDENCY_LEVEL_2",
		},
		{
			name:    "no vulnerability found is the triage requirement met, not dodged",
			breakIt: func(ev *level.Evidence) { ev.Findings, ev.Triaged = 0, 0 },
			level:   "SLSA_DEPENDENCY_LEVEL_3",
		},
	} {
		ev := clean()
		tt.breakIt(ev)

		a := level.Assess(level.TrackDependency, ev)
		if got := a.Level(); got != tt.level {
			t.Errorf("%s: level = %q, want %q\n%s", tt.name, got, tt.level, a.Ladder())
		}
	}
}

// TestDraftTrackAlwaysSaysSo: no output carrying a dependency level
// may omit that SLSA v1.2 approves no such track.
func TestDraftTrackAlwaysSaysSo(t *testing.T) {
	t.Parallel()

	a := level.Assess(level.TrackDependency, &level.Evidence{Owner: "acme", Repo: "widget", Now: epoch})

	var buf strings.Builder
	if err := a.Report().Encode(&buf); err != nil {
		t.Fatalf("Encode = %v", err)
	}

	if !strings.Contains(buf.String(), `"specStatus","value":"draft"`) {
		t.Errorf("the draft track's report does not mark itself draft:\n%s", buf.String())
	}

	if !strings.Contains(a.Shield().Message, "draft") {
		t.Errorf("shield message = %q, want the draft status visible to a reader", a.Shield().Message)
	}
}

// TestSourceTrackWithoutAChain: the difference between walking and
// finding nothing — which the spec makes level zero — and not being
// able to walk, which is no answer at all.
func TestSourceTrackWithoutAChain(t *testing.T) {
	t.Parallel()

	t.Run("no chain found is level zero, stated", func(t *testing.T) {
		t.Parallel()

		a := level.Assess(level.TrackSource, &level.Evidence{
			Owner: "acme", Repo: "widget", NoChain: true, Now: epoch,
		})

		if got := a.Level(); got != "SLSA_SOURCE_LEVEL_0" {
			t.Errorf("level = %q, want level zero — the spec says a revision with no source VSA has it", got)
		}

		// Level zero is an ANSWER — the tool looked, and no level holds.
		// With no declaration in sight nothing has diverged, so the
		// measurement passes and the badge says L0.
		if got := a.Report().Verdict(); got != report.VerdictPass {
			t.Errorf("verdict = %q, want PASS: a measured zero is an answer, not a divergence", got)
		}

		if got := a.Shield(); got.Message != "L0" || got.Color != "brightgreen" {
			t.Errorf("shield = %+v, want a green L0 — the level moves down as the evidence does", got)
		}
	})

	t.Run("a walk that could not run answers nothing", func(t *testing.T) {
		t.Parallel()

		a := level.Assess(level.TrackSource, &level.Evidence{Owner: "acme", Repo: "widget", Now: epoch})
		if got := a.Report().Verdict(); got != report.VerdictCannotJudge {
			t.Errorf("verdict = %q, want CANNOT_JUDGE — not looking is not a level", got)
		}
	})
}

// TestControlNamesAreTheEcosystems: a consumer that invented its own
// dialect could not read another control plane's attestations, and
// being able to is what universal has to mean.
func TestControlNamesAreTheEcosystems(t *testing.T) {
	t.Parallel()

	// Every name the SLSA source proof-of-concept defines, which is the
	// SCS implementation the specification itself points at.
	for _, want := range []string{
		"SLSA_SOURCE_ORG_SCS", "SLSA_SOURCE_ORG_ACCESS_CONTROL", "SLSA_SOURCE_ORG_SAFE_EXPUNGE",
		"SLSA_SOURCE_ORG_CONTINUITY", "SLSA_SOURCE_SCS_REPO_ID", "SLSA_SOURCE_SCS_REVISION_ID",
		"SLSA_SOURCE_SCS_DIFF_DISPLAY", "SLSA_SOURCE_SCS_VSA", "SLSA_SOURCE_SCS_HISTORY",
		"SLSA_SOURCE_SCS_CONTINUITY", "SLSA_SOURCE_SCS_IDENTITY", "SLSA_SOURCE_SCS_PROVENANCE",
		"SLSA_SOURCE_SCS_PROTECTED_REFS", "SLSA_SOURCE_SCS_TWO_PARTY_REVIEW",
	} {
		found := false

		for _, r := range level.Requirements(level.TrackSource) {
			if r.ID == want {
				found = true
			}
		}

		if !found {
			t.Errorf("the catalogue does not carry %s — a private dialect cannot read a foreign chain", want)
		}
	}
}

// TestPopulationFoldsToItsWeakest: a claim made for a population is
// only as true as its weakest member, and the report must say which
// member that is.
func TestPopulationFoldsToItsWeakest(t *testing.T) {
	t.Parallel()

	strong := buildEvidence()
	strong.Repo = "strong"

	weak := buildEvidence()
	weak.Repo = "weak"
	weak.Subjects[0].Cert.RunnerEnvironment = "self-hosted"

	a := level.AssessPopulation(level.TrackBuild, []*level.Evidence{strong, weak}, epoch)

	if got := a.Level(); got != "SLSA_BUILD_LEVEL_1" {
		t.Errorf("level = %q, want the weakest member's — a population is not at a level because most of it is", got)
	}

	var buf strings.Builder
	if err := a.Report().Encode(&buf); err != nil {
		t.Fatalf("Encode = %v", err)
	}

	for _, want := range []string{"acme/weak", "member:acme/strong", "member:acme/weak"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the report does not carry %q:\n%s", want, buf.String())
		}
	}
}

// TestPopulationOfOneAgreesWithTheSingleMeasurement: the fold must not
// change the answer when there is nothing to fold.
func TestPopulationOfOneAgreesWithTheSingleMeasurement(t *testing.T) {
	t.Parallel()

	one := level.Assess(level.TrackBuild, buildEvidence())
	folded := level.AssessPopulation(level.TrackBuild, []*level.Evidence{buildEvidence()}, epoch)

	if one.Level() != folded.Level() {
		t.Errorf("single = %q, folded = %q — folding one measurement must be that measurement",
			one.Level(), folded.Level())
	}
}

// TestEmptyPopulationCannotBeJudged: measuring nothing supports no
// claim, which is the population law the report model already holds.
func TestEmptyPopulationCannotBeJudged(t *testing.T) {
	t.Parallel()

	a := level.AssessPopulation(level.TrackBuild, nil, epoch)
	if got := a.Report().Verdict(); got != report.VerdictCannotJudge {
		t.Errorf("verdict = %q, want CANNOT_JUDGE for an empty population", got)
	}
}

// TestPopulationBlindnessIsNotAPass: a member that could not be
// measured leaves the population short-covered.
func TestPopulationBlindnessIsNotAPass(t *testing.T) {
	t.Parallel()

	seen := buildEvidence()
	seen.Repo = "seen"

	unseen := buildEvidence()
	unseen.Repo = "unseen"
	unseen.Subjects = nil

	a := level.AssessPopulation(level.TrackBuild, []*level.Evidence{seen, unseen}, epoch)
	if got := a.Report().Verdict(); got != report.VerdictCannotJudge {
		t.Errorf("verdict = %q, want CANNOT_JUDGE — a member nobody could measure is not a member that passed", got)
	}
}

// TestAttestedIsMarkedInTheReport: a level resting on what the SCS
// recorded is only as good as the identity that signed it, so the
// report must say which requirements those are rather than folding
// them in with the recomputed ones.
func TestAttestedIsMarkedInTheReport(t *testing.T) {
	t.Parallel()

	a := level.Assess(level.TrackSource, &level.Evidence{
		Owner: "acme", Repo: "widget", NoChain: true, Now: epoch,
	})

	var buf strings.Builder
	if err := a.Report().Encode(&buf); err != nil {
		t.Fatalf("Encode = %v", err)
	}

	// Every requirement reports itself by its ecosystem name, so a
	// reader can match a stele report against another SCS's VSA.
	for _, want := range []string{"SLSA_SOURCE_SCS_VSA", "SLSA_SOURCE_ORG_SCS"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the report does not name %s:\n%s", want, buf.String())
		}
	}
}

// TestControlNamesMatchOnTheirTail: the specification lets each SCS
// choose its own prefix for organization-specified properties, so a
// chain issued by one control plane must be readable by a consumer
// that learned the names from another.
func TestControlNamesMatchOnTheirTail(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		recorded string
		want     bool
	}{
		{recorded: "SLSA_SOURCE_ORG_ACCESS_CONTROL", want: true},
		{recorded: "ORG_SOURCE_ACCESS_CONTROL", want: true},
		{recorded: "ACME_ACCESS_CONTROL", want: true},
		{recorded: "SLSA_SOURCE_ORG_CONTINUITY", want: false},
		{recorded: "ORG_SOURCE_GATED", want: false},
	} {
		if got := level.SameControl(tt.recorded, "SLSA_SOURCE_ORG_ACCESS_CONTROL"); got != tt.want {
			t.Errorf("SameControl(%q) = %v, want %v", tt.recorded, got, tt.want)
		}
	}
}

// TestEveryRequirementHasADetector: a requirement the catalogue
// carries but nothing establishes reports as unevaluated forever, and
// a level that can never hold is worse than no answer. This is the
// ratchet — a requirement added without a detector fails here rather
// than showing up as a silent UNDETERMINED in a report.
func TestEveryRequirementHasADetector(t *testing.T) {
	t.Parallel()

	for _, tr := range []level.Track{level.TrackBuild, level.TrackSource, level.TrackDependency} {
		detected, total := level.Coverage(tr)
		if detected != total {
			t.Errorf("%s coverage = %d/%d — every requirement in the catalogue needs a detector",
				tr.Name(), detected, total)
		}
	}
}

// TestSecureIngestionFromTheQuarantineFloor: the draft's level four,
// judged by the interval between a version being published upstream
// and this producer shipping it. The asymmetry is the requirement's:
// a zero floor refutes — something was consumed the moment it appeared
// — but a positive floor establishes nothing, because a slow release
// cadence leaves the same interval as a real quarantine. The floor is
// stated for the reader; the verdict it cannot carry is not.
func TestSecureIngestionFromTheQuarantineFloor(t *testing.T) {
	t.Parallel()

	base := func() *level.Evidence {
		return &level.Evidence{
			Owner: "acme", Repo: "widget", Now: epoch,
			Inventoried:       []string{"widget_linux_amd64"},
			Scanned:           true,
			DependencySources: map[string]bool{"https://mirror.acme.example/go": true},
		}
	}

	for _, tt := range []struct {
		name      string
		intervals map[string]time.Duration
		want      level.Determination
	}{
		{
			// Consistent with a quarantine — and with a producer who
			// merely releases slowly. Indistinguishable, so no verdict.
			name: "a positive floor across every dependency is not proof of a policy",
			intervals: map[string]time.Duration{
				"pkg:golang/example.com/a@v1.0.0": 8 * 24 * time.Hour,
				"pkg:golang/example.com/b@v2.0.0": 30 * 24 * time.Hour,
			},
			want: level.Undetermined,
		},
		{
			name: "a version taken the moment it appeared",
			intervals: map[string]time.Duration{
				"pkg:golang/example.com/a@v1.0.0": 8 * 24 * time.Hour,
				"pkg:golang/example.com/b@v2.0.0": 0,
			},
			want: level.Refuted,
		},
		{
			name: "a version taken before it was published",
			intervals: map[string]time.Duration{
				"pkg:golang/example.com/a@v1.0.0": -time.Hour,
			},
			want: level.Refuted,
		},
		{
			name:      "no publication time resolved",
			intervals: nil,
			want:      level.Undetermined,
		},
	} {
		ev := base()
		ev.IngestionIntervals = tt.intervals

		var got level.Determination

		for _, r := range level.Assess(level.TrackDependency, ev).Rungs() {
			if r.Level == 4 {
				got = r.Determination
			}
		}

		if got != tt.want {
			t.Errorf("%s: level 4 = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// TestTwoPartyReviewFromTheForgesHistory: level four's second leg —
// where no corroborated control settles it, the forge's own review
// history counts the persons who agreed to each revision.
func TestTwoPartyReviewFromTheForgesHistory(t *testing.T) {
	t.Parallel()

	const (
		revA = "1111111111111111111111111111111111111111"
		revB = "2222222222222222222222222222222222222222"
	)

	base := func() *level.Evidence {
		return &level.Evidence{
			Owner: "acme", Repo: "widget", Now: epoch,
			Revisions: []level.Revision{
				{ID: revA, Subject: "feat: one", Parents: 1},
				{ID: revB, Subject: "feat: two", Parents: 1},
			},
		}
	}

	rungFour := func(ev *level.Evidence) level.Rung {
		for _, r := range level.Assess(level.TrackSource, ev).Rungs() {
			if r.Level == 4 {
				return r
			}
		}

		t.Fatal("no rung four")

		return level.Rung{}
	}

	for _, tt := range []struct {
		name      string
		approvals map[string]int
		want      level.Determination
	}{
		{
			name:      "every revision agreed by two persons",
			approvals: map[string]int{revA: 2, revB: 3},
			want:      level.Held,
		},
		{
			name:      "one revision agreed by its author alone",
			approvals: map[string]int{revA: 2, revB: 1},
			want:      level.Refuted,
		},
		{
			name:      "a revision with no change record is an absence of sight",
			approvals: map[string]int{revA: 2},
			want:      level.Undetermined,
		},
		{
			name: "history never read is no count at all",
			want: level.Undetermined,
		},
	} {
		ev := base()
		ev.Approvals = tt.approvals

		if got := rungFour(ev); got.Determination != tt.want {
			t.Errorf("%s: level 4 = %q (%s), want %q", tt.name, got.Determination, got.Reason, tt.want)
		}
	}
}

// TestOutcomeConstructors: the results and their meanings — and the
// structural rule that an attested outcome has exactly ONE
// constructor, which demands the forge's live half. There is no
// free-form attested constructor: a detector cannot hold a level on a
// repository's record about itself without the platform's own answer
// backing it.
func TestOutcomeConstructors(t *testing.T) {
	t.Parallel()

	backs := func(l *level.LiveRules) bool { return l.Restrictive }

	for _, tt := range []struct {
		got      level.Outcome
		want     level.Determination
		attested bool
	}{
		{got: level.Established("proved %d", 1), want: level.Held},
		{
			got: level.RecordHeld(&level.LiveRules{Restrictive: true}, backs,
				"the record claims it", "recorded %d", 1),
			want: level.Held, attested: true,
		},
		{
			// A record with no live half is self-attestation and holds
			// nothing.
			got:  level.RecordHeld(nil, backs, "the record claims it", "recorded %d", 1),
			want: level.Undetermined,
		},
		{
			// A record the live answer does not back holds nothing.
			got: level.RecordHeld(&level.LiveRules{Restrictive: false}, backs,
				"the record claims it", "recorded %d", 1),
			want: level.Undetermined,
		},
		{got: level.Contradicted("refuted %d", 1), want: level.Refuted},
		{got: level.Unevaluated("unreachable %d", 1), want: level.Undetermined},
	} {
		if tt.got.Determination != tt.want || tt.got.Attested != tt.attested {
			t.Errorf("Outcome = %+v, want %q attested=%v", tt.got, tt.want, tt.attested)
		}

		if tt.got.Reason == "" || strings.Contains(tt.got.Reason, "%") {
			t.Errorf("Reason = %q, want the formatted reason", tt.got.Reason)
		}
	}
}

// TestTrackAccessors covers the vocabulary a shield and a report read.
func TestTrackAccessors(t *testing.T) {
	t.Parallel()

	a := level.Assess(level.TrackSource, &level.Evidence{Owner: "acme", Repo: "widget", Now: epoch})

	if a.Track().Name() != "SOURCE" || a.Track().Label() != "SLSA Source" {
		t.Errorf("Track = %q/%q, want SOURCE/SLSA Source", a.Track().Name(), a.Track().Label())
	}
}

// TestSourceDetectorsWithoutAWalk: every source detector that needs a
// chain must report UNDETERMINED without one — never a pass, and never
// a refusal, because not looking is neither.
func TestSourceDetectorsWithoutAWalk(t *testing.T) {
	t.Parallel()

	a := level.Assess(level.TrackSource, &level.Evidence{
		Owner: "acme", Repo: "widget", Now: epoch,
		Revisions: []level.Revision{
			{ID: "1111111111111111111111111111111111111111", Subject: "feat: one", Parents: 1, Time: epoch},
		},
	})

	var buf strings.Builder
	if err := a.Report().Encode(&buf); err != nil {
		t.Fatalf("Encode = %v", err)
	}

	doc := buf.String()

	// The level-one requirements that need no chain still hold, so the
	// report proves the tri-state is per requirement rather than per
	// run.
	for _, want := range []string{
		"SLSA_SOURCE_SCS_REPO_ID", "SLSA_SOURCE_SCS_REVISION_ID", "SLSA_SOURCE_SCS_DIFF_DISPLAY",
	} {
		if !strings.Contains(doc, `HELD: `) || !strings.Contains(doc, want) {
			t.Errorf("the report does not establish %s without a chain:\n%s", want, doc)
		}
	}

	// And the ones that need a chain say so rather than failing.
	if !strings.Contains(doc, "UNDETERMINED") {
		t.Errorf("no requirement reported as unevaluated without a walk:\n%s", doc)
	}
}

// TestRegisterRefusesAnUnknownRequirement: a detector for a
// requirement outside the catalogue would establish nothing, silently.
func TestRegisterRefusesAnUnknownRequirement(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("registering a detector for a requirement outside the catalogue did not panic")
		}
	}()

	level.RegisterForTest(strayDetector{})
}

type strayDetector struct{}

func (strayDetector) For() string { return "source/not-in-the-catalogue" }

func (strayDetector) Detect(*level.Evidence) level.Outcome { return level.Established("never reached") }
