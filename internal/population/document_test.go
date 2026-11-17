// The population as printed (stele#388). The rows carry the roster
// shapes the canon's own suite tested (mise/test_adoption_population.py,
// TestTracksAbsentVersusEmpty, TestListing, TestReconcile): shapes the
// live organisation does not contain, which is why they are rows.

package population_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/level"
	"github.com/monumental-archive/stele/internal/population"
)

func TestDocumentMembers(t *testing.T) {
	t.Parallel()

	decl := &population.Declaration{Repositories: []population.Entry{
		{Repo: new("canon")},
		{Repo: new("lab"), Tracks: &[]string{}, Reason: new("a laboratory: it publishes nothing")},
		{Repo: new("signer"), Tracks: &[]string{"source"}, Reason: new("the signing workflow repository")},
	}}

	set, err := population.Scope{Org: "acme"}.Resolve(theOrg(), decl)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	doc := set.Document()

	want := []population.MemberDoc{
		// ABSENT tracks: every track, and the default — the statement
		// that survives a track being added.
		{Repo: "canon", Tracks: []string{"build", "source", "dependency"}},
		// PRESENT and EMPTY: an exclusion, never every track.
		{Repo: "lab", Tracks: []string{}, TracksDeclared: true, Exclusion: true},
		// A narrowing that named its tracks.
		{Repo: "signer", Tracks: []string{"source"}, TracksDeclared: true},
	}

	if doc.Owner != "acme" || !doc.Declared || doc.Schema != jsonx.Epoch {
		t.Fatalf("document = %+v", doc)
	}

	if len(doc.Members) != len(want) {
		t.Fatalf("members = %+v, want %+v", doc.Members, want)
	}

	for i := range want {
		got := doc.Members[i]
		if got.Repo != want[i].Repo || !slices.Equal(got.Tracks, want[i].Tracks) ||
			got.TracksDeclared != want[i].TracksDeclared || got.Exclusion != want[i].Exclusion {
			t.Errorf("member %d = %+v, want %+v", i, got, want[i])
		}
	}

	r := doc.Reconciliation
	if r.Undeclared == nil || r.Unlisted == nil || r.Unexercised == nil ||
		len(r.Undeclared)+len(r.Unlisted)+len(r.Unexercised) != 0 {
		t.Fatalf("reconciliation = %+v — agreement is three present, empty lists", r)
	}
}

// TestDocumentNullTracksIsAbsent: a literal null decodes as absent, not
// as an exclusion — the canon suite's test_null_tracks_is_absent_not_empty,
// through the decoder every policy passes through.
func TestDocumentNullTracksIsAbsent(t *testing.T) {
	t.Parallel()

	decl, err := jsonx.DecodeBytes[population.Declaration](
		[]byte(`{"repositories": [{"repo": "canon", "tracks": null}, {"repo": "lab"}, {"repo": "signer"}]}`),
	)
	if err != nil {
		t.Fatal(err)
	}

	set, err := population.Scope{Org: "acme"}.Resolve(theOrg(), decl)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	m, ok := set.Member("canon")
	if !ok || m.TracksDeclared || m.Exclusion || len(m.Tracks) != len(level.Tracks()) {
		t.Fatalf("member = %+v — a null tracks key is the default, every track", m)
	}
}

// TestDocumentDefaultPredicate: with no declaration, archived
// repositories and forks are out and every other listed repository is
// in on every track (TestListing.test_default_predicate_drops_archived_and_forks).
func TestDocumentDefaultPredicate(t *testing.T) {
	t.Parallel()

	set, err := population.Scope{Org: "acme"}.Resolve(theOrg(), nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	doc := set.Document()

	var names []string
	for _, m := range doc.Members {
		names = append(names, m.Repo)

		if m.TracksDeclared || len(m.Tracks) != len(level.Tracks()) {
			t.Errorf("member %+v — the default predicate admits on every track", m)
		}
	}

	if doc.Declared || !slices.Equal(names, []string{"canon", "lab", "signer"}) {
		t.Fatalf("document = %+v, want the three live repositories, undeclared", doc)
	}
}

// TestDocumentReconciliation: both directions by name, and the case a
// count would not have caught — the same number of repositories on both
// sides, different names (TestReconcile).
func TestDocumentReconciliation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		listed               []string
		declared             []string
		undeclared, unlisted []string
	}{
		{"a declared member not listed", []string{"canon"}, []string{"canon", "gone"}, nil, []string{"gone"}},
		{"a listed repository not declared", []string{"canon", "new"}, []string{"canon"}, []string{"new"}, nil},
		{
			"same count, different names",
			[]string{"canon", "new"},
			[]string{"canon", "gone"},
			[]string{"new"},
			[]string{"gone"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var repos []gh.Repo
			for _, n := range tt.listed {
				repos = append(repos, gh.Repo{Name: n})
			}

			decl := &population.Declaration{}
			for _, n := range tt.declared {
				decl.Repositories = append(decl.Repositories, population.Entry{Repo: new(n)})
			}

			_, err := population.Scope{Org: "acme"}.Resolve(lister{repos: repos}, decl)

			var re *population.ReconcileError
			if !errors.As(err, &re) {
				t.Fatalf("Resolve = %v, want a reconciliation refusal", err)
			}

			doc := re.RefusedDocument()
			if len(doc.Members) != 0 || doc.Owner != "acme" ||
				!slices.Equal(doc.Reconciliation.Undeclared, orEmpty(tt.undeclared)) ||
				!slices.Equal(doc.Reconciliation.Unlisted, orEmpty(tt.unlisted)) {
				t.Fatalf("refused document = %+v", doc)
			}
		})
	}
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}

	return s
}

// TestDocumentUnexercised: a declared member outside the coverage is
// named in the reconciliation, never printed as a member.
func TestDocumentUnexercised(t *testing.T) {
	t.Parallel()

	decl := publicOnly(
		population.Entry{Repo: new("canon")},
		population.Entry{Repo: new("lab")},
		population.Entry{Repo: new("signer")},
		population.Entry{Repo: new("vault"), Visibility: new("private")},
	)

	set, err := population.Scope{Org: "acme"}.Resolve(theOrg(), decl)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	doc := set.Document()
	if _, ok := set.Member("vault"); ok || !slices.Equal(doc.Reconciliation.Unexercised, []string{"vault"}) {
		t.Fatalf("document = %+v — vault is unexercised, not a member", doc)
	}
}

// TestDocumentIsTheWalksPopulation is the one-constructor assertion:
// the printed population is read off the Set a walk receives, so per
// track the printed members are exactly Members(track), member order
// is Roster(), and every (repo, track) pair is Grid(). A second
// derivation for printing would fail one of these on the first shape
// where the two disagreed.
func TestDocumentIsTheWalksPopulation(t *testing.T) {
	t.Parallel()

	decl := &population.Declaration{Repositories: []population.Entry{
		{Repo: new("canon")},
		{Repo: new("lab"), Tracks: &[]string{}, Reason: new("publishes nothing")},
		{Repo: new("signer"), Tracks: &[]string{"source", "build"}, Reason: new("no dependencies")},
	}}

	for _, d := range []*population.Declaration{nil, decl} {
		set, err := population.Scope{Org: "acme"}.Resolve(theOrg(), d)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		doc := set.Document()

		var (
			order []string
			grid  []population.Membership
		)

		for _, m := range doc.Members {
			order = append(order, m.Repo)

			for _, k := range m.Tracks {
				tr, _ := level.TrackByName(k)
				grid = append(grid, population.Membership{Repo: m.Repo, Track: tr})
			}
		}

		if !slices.Equal(order, set.Roster()) {
			t.Fatalf("printed order %v, roster %v", order, set.Roster())
		}

		if !slices.Equal(grid, set.Grid()) {
			t.Fatalf("printed grid %v, the walks' grid %v", grid, set.Grid())
		}

		for _, tr := range level.Tracks() {
			var printed []string

			for _, m := range doc.Members {
				if slices.Contains(m.Tracks, tr.Key()) {
					printed = append(printed, m.Repo)
				}
			}

			members, merr := set.Members(tr)
			if merr != nil {
				continue // a declared-empty track is the walk's contradiction, not this test's
			}

			if !slices.Equal(orEmpty(printed), orEmpty(members)) {
				t.Fatalf("%s: printed %v, the walk's %v", tr.Key(), printed, members)
			}
		}
	}
}
