// The population's guard branches, one row each. These are the least
// exercised code in the org by construction — a membership rule fires
// on the day an organisation's shape changes, and a rule that admits
// when it should refuse looks exactly like a clean run.

package population_test

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/level"
	"github.com/monumental-archive/stele/internal/population"
	"github.com/monumental-archive/stele/internal/report"
)

// lister is a listing seam that answers with facts, or tears.
type lister struct {
	repos []gh.Repo
	err   error
}

func (l lister) ListRepos(string) ([]gh.Repo, error) {
	if l.err != nil {
		return nil, l.err
	}

	return l.repos, nil
}

// theOrg is the shape this issue was written about: three ordinary
// repositories, one that bears source evidence alone, one archive and
// one fork.
func theOrg() lister {
	return lister{repos: []gh.Repo{
		{Name: "canon"},
		{Name: "lab"},
		{Name: "signer"},
		{Name: "attic", Archived: true},
		{Name: "mirror", Fork: true},
	}}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		decl *population.Declaration
		want string
	}{
		{name: "no declaration is the default predicate, not an error"},
		{
			name: "a declared population of nothing cannot be reconciled",
			decl: &population.Declaration{},
			want: "population.repositories is empty",
		},
		{
			name: "an absent repo name",
			decl: &population.Declaration{Repositories: []population.Entry{{}}},
			want: "repositories[0].repo is absent or empty",
		},
		{
			name: "an empty repo name",
			decl: &population.Declaration{Repositories: []population.Entry{{Repo: new("")}}},
			want: "repositories[0].repo is absent or empty",
		},
		{
			name: "an owner/name spelling names a repository twice",
			decl: &population.Declaration{Repositories: []population.Entry{{Repo: new("acme/canon")}}},
			want: "name the repository alone",
		},
		{
			name: "one repository, one membership",
			decl: &population.Declaration{Repositories: []population.Entry{
				{Repo: new("canon")}, {Repo: new("canon")},
			}},
			want: "names canon twice",
		},
		{
			// The SlsaResult spelling, where the policy takes the
			// command line's. A track name that does not parse would
			// otherwise narrow a population in silence.
			name: "a track name this release does not judge",
			decl: &population.Declaration{Repositories: []population.Entry{
				{Repo: new("canon"), Tracks: &[]string{"BUILD"}, Reason: new("the wrong spelling")},
			}},
			want: `names "BUILD", which is no track this release judges (build, source, dependency)`,
		},
		{
			name: "a narrowing with no reason reads as a mistake",
			decl: &population.Declaration{Repositories: []population.Entry{
				{Repo: new("signer"), Tracks: &[]string{"source"}},
			}},
			want: "repositories[0].reason is absent or empty",
		},
		{
			name: "an empty reason is no reason",
			decl: &population.Declaration{Repositories: []population.Entry{
				{Repo: new("signer"), Tracks: &[]string{"source"}, Reason: new("")},
			}},
			want: "repositories[0].reason is absent or empty",
		},
		{
			name: "an empty track list is a narrowing like any other and needs its reason",
			decl: &population.Declaration{Repositories: []population.Entry{
				{Repo: new("www"), Tracks: &[]string{}},
			}},
			want: "repositories[0].reason is absent or empty",
		},
		{
			name: "full membership needs no words",
			decl: &population.Declaration{Repositories: []population.Entry{{Repo: new("canon")}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.decl.Validate()

			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("Validate = %v, want accepted", err)
			case tc.want == "":
			case err == nil || !strings.Contains(err.Error(), tc.want):
				t.Fatalf("Validate = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestScopeSubject: what a report is about, before anything is
// enumerated — a refusal that could not name its own subject would be
// a document nobody can file.
func TestScopeSubject(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		scope population.Scope
		want  string
	}{
		{population.Scope{Org: "acme"}, "acme"},
		{population.Scope{Repo: "acme/widget"}, "acme/widget"},
		{population.Scope{Org: "acme", Repo: "acme/widget"}, "acme/widget"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()

			if got := tc.scope.Subject(); got != tc.want {
				t.Fatalf("Subject = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDefaultPredicate: with nothing declared, the listing's own facts
// decide — and the verb needs no configuration to run at all, which is
// what keeps a stranger's first run possible.
func TestDefaultPredicate(t *testing.T) {
	t.Parallel()

	set, err := population.Scope{Org: "acme"}.Resolve(theOrg(), nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	for _, track := range level.Tracks() {
		members, merr := set.Members(track)
		if merr != nil {
			t.Fatalf("Members(%s): %v", track.Key(), merr)
		}

		if want := []string{"canon", "lab", "signer"}; !slices.Equal(members, want) {
			t.Fatalf("Members(%s) = %v, want %v — archived repositories and forks are out by default",
				track.Key(), members, want)
		}
	}

	if got := sealed(t, set.Population(level.TrackBuild)); !strings.Contains(got, `"source":"listing"`) {
		t.Fatalf("population = %s, want a listing provenance — nothing was declared", got)
	}

	if set.Owner() != "acme" || set.Subject() != "acme" {
		t.Fatalf("owner/subject = %q/%q, want acme/acme", set.Owner(), set.Subject())
	}
}

// TestPerTrackMembership is the measured refinement (stele#153's
// comment): a repository that measures one track honestly and can
// never have evidence on the others is IN for the first and absent
// from the rest — not a grey cell, not a finding, not a count.
func TestPerTrackMembership(t *testing.T) {
	t.Parallel()

	decl := &population.Declaration{Repositories: []population.Entry{
		{Repo: new("canon")},
		{Repo: new("lab")},
		{
			Repo: new("signer"), Tracks: &[]string{"source"},
			Reason: new("publishes no releases; it is the signing workflow repository"),
		},
	}}

	set, err := population.Scope{Org: "acme"}.Resolve(theOrg(), decl)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	for _, tc := range []struct {
		track level.Track
		want  []string
	}{
		{level.TrackBuild, []string{"canon", "lab"}},
		{level.TrackSource, []string{"canon", "lab", "signer"}},
		{level.TrackDependency, []string{"canon", "lab"}},
	} {
		t.Run(tc.track.Key(), func(t *testing.T) {
			t.Parallel()

			members, merr := set.Members(tc.track)
			if merr != nil {
				t.Fatalf("Members: %v", merr)
			}

			if !slices.Equal(members, tc.want) {
				t.Fatalf("Members = %v, want %v", members, tc.want)
			}

			// Provenance travels with the count: "what a credential
			// happened to show" and "what the organisation declared"
			// are different claims about the same number.
			got := sealed(t, set.Population(tc.track))
			for _, want := range []string{
				`"size":` + strconv.Itoa(len(tc.want)), `"expected":` + strconv.Itoa(len(tc.want)), `"source":"declared"`,
			} {
				if !strings.Contains(got, want) {
					t.Fatalf("population = %s, want %s", got, want)
				}
			}
		})
	}
}

// TestDeclaredOutEntirely: a repository that bears no evidence at all
// produces NOTHING anywhere. Adding it to the organisation changes no
// verdict, no count and no cell — which is the whole issue.
func TestDeclaredOutEntirely(t *testing.T) {
	t.Parallel()

	l := theOrg()
	l.repos = append(l.repos, gh.Repo{Name: "www"})

	decl := &population.Declaration{Repositories: []population.Entry{
		{Repo: new("canon")},
		{Repo: new("lab")},
		{Repo: new("signer")},
		{Repo: new("www"), Tracks: &[]string{}, Reason: new("the product site; it bears no evidence")},
	}}

	set, err := population.Scope{Org: "acme"}.Resolve(l, decl)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	for _, track := range level.Tracks() {
		members, merr := set.Members(track)
		if merr != nil {
			t.Fatalf("Members(%s): %v", track.Key(), merr)
		}

		if !slices.Equal(members, []string{"canon", "lab", "signer"}) {
			t.Fatalf("Members(%s) = %v — a declared-out repository must not appear anywhere",
				track.Key(), members)
		}
	}
}

// TestRoster is the third door (stele#181). A walk that names no
// track reads the roster whole, so the very repository
// TestDeclaredOutEntirely proves invisible to every evidence walk is
// present here: an exclusion says what a repository owes EVIDENCE on,
// and being listed at all is what puts a repository under a walk that
// consumes none.
func TestRoster(t *testing.T) {
	t.Parallel()

	withSite := theOrg()
	withSite.repos = append(withSite.repos, gh.Repo{Name: "www"})

	for _, tc := range []struct {
		name string
		l    lister
		decl *population.Declaration
		want []string
	}{
		{
			name: "the default predicate's roster is its listing, archives and forks out",
			l:    theOrg(),
			want: []string{"canon", "lab", "signer"},
		},
		{
			name: "a declared roster holds every entry, whatever tracks it named",
			l:    withSite,
			decl: &population.Declaration{Repositories: []population.Entry{
				{Repo: new("canon")},
				{Repo: new("lab")},
				{
					Repo: new("signer"), Tracks: &[]string{"source"},
					Reason: new("publishes no releases; it is the signing workflow repository"),
				},
				{Repo: new("www"), Tracks: &[]string{}, Reason: new("the product site; it bears no evidence")},
			}},
			want: []string{"canon", "lab", "signer", "www"},
		},
		{
			name: "an archive the roster names is a member here too, like every other entry",
			l:    lister{repos: []gh.Repo{{Name: "canon"}, {Name: "attic", Archived: true}}},
			decl: &population.Declaration{Repositories: []population.Entry{
				{Repo: new("canon")}, {Repo: new("attic")},
			}},
			want: []string{"canon", "attic"},
		},
		{
			// The Members contradiction has no counterpart at this door:
			// a walk that named no track cannot be pointed at one nobody
			// is in, so nobody is an outage (stele#69) and stays
			// CANNOT_JUDGE over a population of zero.
			name: "a listing that came back empty is an empty roster, never an error",
			l:    lister{},
			want: []string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set, err := population.Scope{Org: "acme"}.Resolve(tc.l, tc.decl)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			if got := set.Roster(); !slices.Equal(got, tc.want) {
				t.Fatalf("Roster = %v, want %v", got, tc.want)
			}
		})
	}

	// The single-repository consumer (stele#79) at the same door: the
	// roster is one repository, and the entry that excludes it from
	// every evidence track does not remove it — a caller who named a
	// target explicitly asked about that target.
	t.Run("the single-repository roster is the repository named", func(t *testing.T) {
		t.Parallel()

		set, err := population.Scope{Repo: "acme/www"}.Resolve(nil,
			&population.Declaration{Repositories: []population.Entry{
				{Repo: new("www"), Tracks: &[]string{}, Reason: new("the product site; it bears no evidence")},
			}})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		if got := set.Roster(); !slices.Equal(got, []string{"www"}) {
			t.Fatalf("Roster = %v, want the one repository named", got)
		}
	})
}

// TestReconciliation: both directions refuse, and both refuse BY NAME.
// A count cannot say which repository went missing, and the repository
// that went missing is the whole finding.
func TestReconciliation(t *testing.T) {
	t.Parallel()

	full := []population.Entry{{Repo: new("canon")}, {Repo: new("lab")}, {Repo: new("signer")}}

	for _, tc := range []struct {
		name  string
		repos []gh.Repo
		decl  []population.Entry
		want  []string
	}{
		{
			name:  "an undeclared repository is the onboarding signal, not a defect to swallow",
			repos: append(theOrg().repos, gh.Repo{Name: "newcomer"}),
			decl:  full,
			want:  []string{"the listing shows newcomer", "declare each"},
		},
		{
			name:  "a declared repository the credential cannot see",
			repos: []gh.Repo{{Name: "canon"}, {Name: "lab"}},
			decl:  full,
			want:  []string{"names signer", "unchecked, not clean"},
		},
		{
			name:  "both at once, both named",
			repos: []gh.Repo{{Name: "canon"}, {Name: "lab"}, {Name: "newcomer"}},
			decl:  full,
			want:  []string{"shows newcomer", "names signer"},
		},
		{
			name:  "an archived repository nobody declared is not a divergence",
			repos: theOrg().repos,
			decl:  full,
		},
		{
			name: "a roster entry OVERRIDES the default, so an archived repository can still be judged",
			repos: []gh.Repo{
				{Name: "canon"}, {Name: "lab"}, {Name: "signer"}, {Name: "attic", Archived: true},
			},
			decl: append(append([]population.Entry{}, full...), population.Entry{Repo: new("attic")}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set, err := population.Scope{Org: "acme"}.Resolve(
				lister{repos: tc.repos}, &population.Declaration{Repositories: tc.decl})

			if len(tc.want) == 0 {
				if err != nil {
					t.Fatalf("Resolve = %v, want a reconciled population", err)
				}

				return
			}

			if err == nil {
				members, merr := set.Members(level.TrackBuild)
				t.Fatalf("Resolve reconciled %v (%v) — a run that does not know its population cannot judge one",
					members, merr)
			}

			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("Resolve = %v, want it to name %q", err, want)
				}
			}
		})
	}
}

// TestArchivedOverrideIsJudged pins the other half of the override:
// the archived repository the roster names is not merely accepted, it
// is a member.
func TestArchivedOverrideIsJudged(t *testing.T) {
	t.Parallel()

	set, err := population.Scope{Org: "acme"}.Resolve(
		lister{repos: []gh.Repo{{Name: "canon"}, {Name: "attic", Archived: true}}},
		&population.Declaration{Repositories: []population.Entry{
			{Repo: new("canon")}, {Repo: new("attic")},
		}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	members, err := set.Members(level.TrackSource)
	if err != nil {
		t.Fatalf("Members: %v", err)
	}

	if !slices.Equal(members, []string{"canon", "attic"}) {
		t.Fatalf("Members = %v, want the declared archive judged", members)
	}
}

// TestOrgResolveRefusals: the enumeration's own degraded states, each
// named rather than answered with a walk over nobody.
func TestOrgResolveRefusals(t *testing.T) {
	t.Parallel()

	torn := errors.New("the forge tore")

	t.Run("a torn listing is carried out, never flattened into an empty organisation", func(t *testing.T) {
		t.Parallel()

		_, err := population.Scope{Org: "acme"}.Resolve(lister{err: torn}, nil)
		if err == nil || !errors.Is(err, torn) {
			t.Fatalf("Resolve = %v, want the tear carried out", err)
		}
	})

	t.Run("a forge with no listing seam says so by name", func(t *testing.T) {
		t.Parallel()

		_, err := population.Scope{Org: "acme"}.Resolve(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "cannot list acme") {
			t.Fatalf("Resolve = %v, want the missing-seam refusal", err)
		}
	})

	t.Run("no scope at all", func(t *testing.T) {
		t.Parallel()

		_, err := population.Scope{}.Resolve(theOrg(), nil)
		if err == nil || !strings.Contains(err.Error(), "neither an organisation nor a repository") {
			t.Fatalf("Resolve = %v, want the empty-scope refusal", err)
		}
	})

	t.Run("a declaration that does not validate never reaches a listing", func(t *testing.T) {
		t.Parallel()

		_, err := population.Scope{Org: "acme"}.Resolve(lister{err: torn}, &population.Declaration{})
		if err == nil || !strings.Contains(err.Error(), "population.repositories is empty") {
			t.Fatalf("Resolve = %v, want the validation refusal before the read", err)
		}
	})
}

// TestSingleRepository is the stele#79 consumer: one repository, no
// listing, no credential that can enumerate — and the declaration
// consulted only where it names the target.
func TestSingleRepository(t *testing.T) {
	t.Parallel()

	decl := &population.Declaration{Repositories: []population.Entry{
		{Repo: new("signer"), Tracks: &[]string{"source"}, Reason: new("publishes no releases")},
	}}

	t.Run("a repository the declaration does not name is walked as the caller asked", func(t *testing.T) {
		t.Parallel()

		set, err := population.Scope{Repo: "other/thing"}.Resolve(nil, decl)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		members, merr := set.Members(level.TrackBuild)
		if merr != nil || !slices.Equal(members, []string{"thing"}) {
			t.Fatalf("Members = %v, %v — a closed roster scopes an ORG listing, never an explicit target",
				members, merr)
		}

		if set.Owner() != "other" || set.Subject() != "other/thing" {
			t.Fatalf("owner/subject = %q/%q", set.Owner(), set.Subject())
		}
	})

	t.Run("the track it is declared on is walked", func(t *testing.T) {
		t.Parallel()

		set, err := population.Scope{Repo: "acme/signer"}.Resolve(nil, decl)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		members, merr := set.Members(level.TrackSource)
		if merr != nil || !slices.Equal(members, []string{"signer"}) {
			t.Fatalf("Members = %v, %v", members, merr)
		}
	})

	t.Run("a track it is declared outside of is a contradiction, reported not answered", func(t *testing.T) {
		t.Parallel()

		set, err := population.Scope{Repo: "acme/signer"}.Resolve(nil, decl)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		for _, track := range []level.Track{level.TrackBuild, level.TrackDependency} {
			_, merr := set.Members(track)
			if merr == nil || !strings.Contains(merr.Error(), "outside the "+track.Key()+" track") {
				t.Fatalf("Members(%s) = %v, want the contradiction reported", track.Key(), merr)
			}
		}
	})

	for _, bad := range []string{"solo", "/name", "owner/", ""} {
		t.Run("a population that is not owner/name: "+bad, func(t *testing.T) {
			t.Parallel()

			scope := population.Scope{Repo: bad}
			if bad == "" {
				// The empty spelling is no scope at all, and the earlier
				// guard answers it — kept in the row so the table covers
				// every value the field can hold.
				scope = population.Scope{Repo: " "}
			}

			if _, err := scope.Resolve(nil, nil); err == nil {
				t.Fatalf("Resolve accepted %q", bad)
			}
		})
	}
}

// TestSingleRepositoryWithNoDeclarationAtAll is the adopter case the
// layout law is written about: a stranger points this walk at their
// own repository holding no policy document whatsoever. Nothing about
// this org's roster may be needed to answer, and the target must come
// back bearing every track — the tool has been told nothing that would
// narrow it.
func TestSingleRepositoryWithNoDeclarationAtAll(t *testing.T) {
	t.Parallel()

	set, err := population.Scope{Repo: "stranger/tool"}.Resolve(nil, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	for _, track := range level.Tracks() {
		members, merr := set.Members(track)
		if merr != nil || !slices.Equal(members, []string{"tool"}) {
			t.Fatalf("Members(%s) = %v, %v — an undeclared target bears every track",
				track.Key(), members, merr)
		}
	}
}

// TestGrid is the fourth door, and the one a board is built from. It
// differs from Members in what an empty answer MEANS: Members is asked
// by a walk that named a track, so a repository outside that track is
// a contradiction; Grid is asked by a consumer that named no track, so
// a repository's missing track is simply a cell that does not exist.
//
// The rows below are the two halves of the exclusion law. signer bears
// source alone and contributes exactly one cell — not three, and not a
// cell marked absent. www is declared out entirely and contributes
// NOTHING: no cell to publish, and so nothing on a board for a reader
// to mistake for an unmeasured one.
func TestGrid(t *testing.T) {
	t.Parallel()

	withSite := theOrg()
	withSite.repos = append(withSite.repos, gh.Repo{Name: "www"})

	decl := &population.Declaration{Repositories: []population.Entry{
		{Repo: new("canon")},
		{
			Repo: new("signer"), Tracks: &[]string{"source"},
			Reason: new("publishes no releases; it is the signing workflow repository"),
		},
		{Repo: new("www"), Tracks: &[]string{}, Reason: new("the product site; it bears no evidence")},
		{Repo: new("lab")},
	}}

	set, err := population.Scope{Org: "acme"}.Resolve(withSite, decl)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	var got []string
	for _, m := range set.Grid() {
		got = append(got, m.Repo+"/"+m.Track.Key())
	}

	// Listing order outer, the spec's track order inner: a board's rows
	// and columns are both stable, so two publications of an unchanged
	// population are the same document.
	want := []string{
		"canon/build", "canon/source", "canon/dependency",
		"lab/build", "lab/source", "lab/dependency",
		"signer/source",
	}

	if !slices.Equal(got, want) {
		t.Fatalf("Grid =\n  %v\nwant\n  %v", got, want)
	}
}

// TestEmptyPopulation pins the two opposite meanings of nobody, which
// is the whole reason exclusions and exceptions may never share a
// vocabulary: a population DECLARED empty is a contradiction the
// operator can fix, and a population that merely CAME BACK empty is
// the degraded forge stele#69 met on its first day.
func TestEmptyPopulation(t *testing.T) {
	t.Parallel()

	t.Run("declared empty is a contradiction, named", func(t *testing.T) {
		t.Parallel()

		set, err := population.Scope{Org: "acme"}.Resolve(
			lister{repos: []gh.Repo{{Name: "www"}}},
			&population.Declaration{Repositories: []population.Entry{
				{Repo: new("www"), Tracks: &[]string{}, Reason: new("bears no evidence")},
			}})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		_, err = set.Members(level.TrackBuild)
		if err == nil || !strings.Contains(err.Error(), "outside the build track") {
			t.Fatalf("Members = %v, want the contradiction rather than a causeless CANNOT_JUDGE", err)
		}
	})

	t.Run("a listing that came back empty stays CANNOT_JUDGE", func(t *testing.T) {
		t.Parallel()

		set, err := population.Scope{Org: "acme"}.Resolve(lister{}, nil)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		members, merr := set.Members(level.TrackBuild)
		if merr != nil || len(members) != 0 {
			t.Fatalf("Members = %v, %v — an outage is not a usage error", members, merr)
		}

		rep := report.Seal("t", "acme", set.Population(level.TrackBuild), report.NewJournal(),
			report.NoCanary(), report.NoJudgedSet())
		if rep.Verdict() != report.VerdictCannotJudge {
			t.Fatalf("verdict = %s, want CANNOT_JUDGE over a population of nobody", rep.Verdict())
		}
	})
}

// sealed renders one population the way a consumer reads it: through
// a sealed report, because report.Population is sealed on purpose and
// a test that reached inside it would assert on a shape no consumer
// can see.
func sealed(t *testing.T, pop report.Population) string {
	t.Helper()

	var buf strings.Builder

	rep := report.Seal("t", "acme", pop, report.NewJournal(), report.NoCanary(), report.NoJudgedSet())
	if err := rep.Encode(&buf); err != nil {
		t.Fatalf("encoding the report: %v", err)
	}

	return buf.String()
}
