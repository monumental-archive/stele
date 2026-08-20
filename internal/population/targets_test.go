// The rebuild-target population's guard branches, one row each. The
// four behaviours this door exists for are opposite in pairs, and
// each pair is silent when it fails: a declared target dropped in
// silence is a rebuild nobody judged reading as a rebuild that found
// nothing, and an undeclared target admitted is a finding against a
// release that is fine (release-lab v0.26.0, stele#223).

package population_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/population"
	"github.com/monumental-archive/stele/internal/report"
)

const (
	targetDigestA = "1111111111111111111111111111111111111111111111111111111111111111"
	targetDigestB = "2222222222222222222222222222222222222222222222222222222222222222"
	targetDigestC = "3333333333333333333333333333333333333333333333333333333333333333"
)

// aMultiTargetClass is the release shape the defect was measured on:
// one class, several targets, one of which a canary rebuild covers.
func aMultiTargetClass() []population.Artifact {
	return []population.Artifact{
		{Name: "widget-x86_64-linux.tar.gz", SHA256: targetDigestA, Target: "x86_64-unknown-linux-musl"},
		{Name: "widget-aarch64-linux.tar.gz", SHA256: targetDigestB, Target: "aarch64-unknown-linux-musl"},
		{Name: "widget-x86_64-darwin.tar.gz", SHA256: targetDigestC, Target: "x86_64-apple-darwin"},
	}
}

// anUntypedRelease is the same release published before targets were
// typed: every artifact present, none of them placeable.
func anUntypedRelease() []population.Artifact {
	out := aMultiTargetClass()
	for i := range out {
		out[i].Target = ""
	}

	return out
}

func TestTargetScopeValidate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		targets []string
		want    string
	}{
		{
			// The absence of a declaration is the caller declaring
			// nothing, which is a state this type never holds: the judge
			// keeps its unnarrowed population instead of building a
			// scope of nobody.
			name: "a declaration of nothing cannot be reconciled",
			want: "a declared population of nothing",
		},
		{
			// A matrix that rendered an empty element declares a hole.
			// Admitting it would narrow the judged population by exactly
			// the value nobody noticed was missing.
			name:    "a target with no name",
			targets: []string{"x86_64-unknown-linux-musl", ""},
			want:    "declares nothing",
		},
		{
			name:    "one target declared twice",
			targets: []string{"x86_64-unknown-linux-musl", "x86_64-unknown-linux-musl"},
			want:    "declared twice",
		},
		{
			name:    "a declaration that parses",
			targets: []string{"x86_64-unknown-linux-musl"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := population.TargetScope{Targets: tc.targets}.Validate()

			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate = %v, want a declaration that parses to be accepted", err)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// The four behaviours, each in both directions where the guard has
// two: what a declaration admits, what it excludes, and what it
// cannot place.
func TestTargetScopeResolve(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		targets        []string
		published      []population.Artifact
		wantArtifacts  []string
		wantUnanswered []string
	}{
		{
			// The canary: one target of a multi-target class. The other
			// two artifacts produce NOTHING — not a quieter finding, not
			// a count, nothing — because nobody claimed to have rebuilt
			// them.
			name:          "an undeclared target produces nothing at all",
			targets:       []string{"x86_64-unknown-linux-musl"},
			published:     aMultiTargetClass(),
			wantArtifacts: []string{"widget-x86_64-linux.tar.gz"},
		},
		{
			// The same release, the same manifest, a wider declaration:
			// the artifacts the row above excluded are judged here. The
			// pair is the point — exclusion follows the declaration, not
			// the tool's opinion about the release.
			name:    "declaring the rest admits the rest",
			targets: []string{"x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl", "x86_64-apple-darwin"},

			published: aMultiTargetClass(),
			wantArtifacts: []string{
				"widget-x86_64-linux.tar.gz", "widget-aarch64-linux.tar.gz", "widget-x86_64-darwin.tar.gz",
			},
		},
		{
			// A declared target this release never built. Loud, by name:
			// the caller says it rebuilt something the release cannot
			// show, and the run has nothing to say about that target.
			name:           "a declared target the release does not carry is named",
			targets:        []string{"x86_64-unknown-linux-musl", "riscv64gc-unknown-linux-gnu"},
			published:      aMultiTargetClass(),
			wantArtifacts:  []string{"widget-x86_64-linux.tar.gz"},
			wantUnanswered: []string{"riscv64gc-unknown-linux-gnu"},
		},
		{
			// A release published before targets were typed carries the
			// artifacts and can place none of them. Every declared
			// target is unanswered — never an empty judged set reading
			// as a clean one.
			name:           "an untyped release answers for no declared target",
			targets:        []string{"x86_64-unknown-linux-musl"},
			published:      anUntypedRelease(),
			wantUnanswered: []string{"x86_64-unknown-linux-musl"},
		},
		{
			// The whole class scoped away: a declaration naming targets
			// of some other class places nothing here, and says so.
			name:           "a release that published nothing places nothing",
			targets:        []string{"x86_64-unknown-linux-musl"},
			wantUnanswered: []string{"x86_64-unknown-linux-musl"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set, err := population.TargetScope{Targets: tc.targets}.Resolve(tc.published)
			if err != nil {
				t.Fatalf("Resolve = %v", err)
			}

			var names []string
			for _, a := range set.Artifacts() {
				names = append(names, a.Name)
			}

			if strings.Join(names, ",") != strings.Join(tc.wantArtifacts, ",") {
				t.Errorf("Artifacts = %v, want %v", names, tc.wantArtifacts)
			}

			if strings.Join(set.Unanswered(), ",") != strings.Join(tc.wantUnanswered, ",") {
				t.Errorf("Unanswered = %v, want %v", set.Unanswered(), tc.wantUnanswered)
			}

			if strings.Join(set.Declared(), ",") != strings.Join(tc.targets, ",") {
				t.Errorf("Declared = %v, want the declaration back whatever the release answered",
					set.Declared())
			}
		})
	}
}

// The population a judge seals with, read the way a consumer reads it.
// Both directions of the coverage law: a declaration the release can
// answer for supports a judgment, and one it cannot short-covers into
// CANNOT_JUDGE rather than passing over the targets that did answer.
func TestTargetSetPopulationSeals(t *testing.T) {
	t.Parallel()

	t.Run("every declared target answered supports a judgment", func(t *testing.T) {
		t.Parallel()

		set, err := population.TargetScope{Targets: []string{"x86_64-unknown-linux-musl"}}.
			Resolve(aMultiTargetClass())
		if err != nil {
			t.Fatalf("Resolve = %v", err)
		}

		pop := set.Population("declared rust-binary rebuild targets")

		if got := sealed(t, pop); !strings.Contains(got, `"size":1,"expected":1,"source":"declared"`) {
			t.Errorf("sealed population = %s", got)
		}

		rep := report.Seal("t", "acme", pop, report.NewJournal(), report.NoCanary(), report.NoJudgedSet())
		if rep.Verdict() != report.VerdictPass {
			t.Errorf("verdict = %s, want a healthy canary rebuild to be judgeable", rep.Verdict())
		}
	})

	t.Run("a target nobody could place cannot be judged", func(t *testing.T) {
		t.Parallel()

		set, err := population.TargetScope{
			Targets: []string{"x86_64-unknown-linux-musl", "riscv64gc-unknown-linux-gnu"},
		}.Resolve(aMultiTargetClass())
		if err != nil {
			t.Fatalf("Resolve = %v", err)
		}

		pop := set.Population("declared rust-binary rebuild targets")

		if got := sealed(t, pop); !strings.Contains(got, `"size":1,"expected":2,"source":"declared"`) {
			t.Errorf("sealed population = %s", got)
		}

		rep := report.Seal("t", "acme", pop, report.NewJournal(), report.NoCanary(), report.NoJudgedSet())
		if rep.Verdict() != report.VerdictCannotJudge {
			t.Errorf("verdict = %s, want the shortfall to refuse a judgment", rep.Verdict())
		}
	})
}

// Resolve is total over its own inputs: a declaration that could not
// mean what it says never reaches a population, whoever built it.
func TestTargetScopeResolveValidatesItsOwnInput(t *testing.T) {
	t.Parallel()

	if _, err := (population.TargetScope{}).Resolve(aMultiTargetClass()); err == nil {
		t.Fatal("Resolve = nil, want a declaration of nothing to refuse rather than judge everything")
	}

	_, err := population.TargetScope{Targets: []string{"a", "a"}}.Resolve(aMultiTargetClass())
	if err == nil || !strings.Contains(err.Error(), "declared twice") {
		t.Fatalf("Resolve = %v, want the duplicate refused at the door", err)
	}
}
