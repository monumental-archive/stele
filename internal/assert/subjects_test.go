// The door table (stele#181): which population entry point each
// target enumerates through, pinned per target so the next walk added
// cannot reach the wrong door by copying its neighbour — which is
// exactly how the permissions join arrived on the build track.
//
// Pinned by BEHAVIOUR, over a population shaped like the org the
// defect was measured on. A test that read the door out of the value
// would agree with whatever the code says; this one disagrees when a
// repository moves in or out of a walk's sight.

package assert_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/population"
)

// subjectsOrg is the shape .github#580 measured: one repository that
// bears everything, one that bears source evidence alone and still
// carries caller stubs (the signing repository), and one that bears
// no evidence at all and still has workflows.
func subjectsOrg(t *testing.T) *population.Set {
	t.Helper()

	return orgPop(t, &fakeForge{repos: []string{"canon", "signer", "www"}},
		&population.Declaration{Repositories: []population.Entry{
			{Repo: new("canon")},
			{
				Repo: new("signer"), Tracks: &[]string{"source"},
				Reason: new("publishes no releases; it is the signing workflow repository"),
			},
			{Repo: new("www"), Tracks: &[]string{}, Reason: new("the product site; it bears no evidence")},
		}})
}

// TestSubjectsDoors: every target's enumeration over one population,
// in one table. The evidence targets narrow by the track their
// evidence sits on; the permissions join narrows by nothing, because
// a repository that publishes nothing still has workflow grants to
// forecast.
func TestSubjectsDoors(t *testing.T) {
	t.Parallel()

	pop := subjectsOrg(t)

	for _, tc := range []struct {
		name string
		door assert.Subjects
		want []string
	}{
		{"evidence measures what a release published", assert.EvidenceSubjects, []string{"canon"}},
		{"chains measures a source ledger", assert.ChainsSubjects, []string{"canon", "signer"}},
		{"tags measures a statement about the source", assert.TagsSubjects, []string{"canon", "signer"}},
		{"blast-radius measures dependency evidence", assert.BlastRadiusSubjects, []string{"canon"}},
		{
			// The whole issue: signer and www are outside the build
			// track by their own declaration and their grants are
			// audited anyway.
			"permissions measures every repository's grants", assert.PermissionsSubjects,
			[]string{"canon", "signer", "www"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.door.Enumerate(pop)
			if err != nil {
				t.Fatalf("Enumerate: %v", err)
			}

			if !slices.Equal(got, tc.want) {
				t.Fatalf("Enumerate = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSubjectsRosterAsksNoTrackQuestion: a population whose every
// member bears no evidence anywhere is a CONTRADICTION to each
// evidence target — pointed at a track its own policy says nobody is
// in — and an ordinary answer at the roster door, which named no
// track to contradict.
func TestSubjectsRosterAsksNoTrackQuestion(t *testing.T) {
	t.Parallel()

	pop := orgPop(t, &fakeForge{repos: []string{"www"}},
		&population.Declaration{Repositories: []population.Entry{
			{Repo: new("www"), Tracks: &[]string{}, Reason: new("the product site; it bears no evidence")},
		}})

	for _, tc := range []struct {
		name string
		door assert.Subjects
		want string
	}{
		{"evidence", assert.EvidenceSubjects, "outside the build track"},
		{"chains", assert.ChainsSubjects, "outside the source track"},
		{"tags", assert.TagsSubjects, "outside the source track"},
		{"blast-radius", assert.BlastRadiusSubjects, "outside the dependency track"},
	} {
		t.Run(tc.name+" is refused by name", func(t *testing.T) {
			t.Parallel()

			_, err := tc.door.Enumerate(pop)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Enumerate = %v, want the track contradiction naming %q", err, tc.want)
			}
		})
	}

	t.Run("permissions enumerates it", func(t *testing.T) {
		t.Parallel()

		got, err := assert.PermissionsSubjects.Enumerate(pop)
		if err != nil {
			t.Fatalf("Enumerate: %v", err)
		}

		if !slices.Equal(got, []string{"www"}) {
			t.Fatalf("Enumerate = %v, want the repository whose grants still exist", got)
		}
	})
}

// TestSubjectsEmptyListing: a listing that came back with nobody in
// it is the degraded forge stele#69 met on its first day, and EVERY
// door answers it the same way — an empty population, never an error,
// so the walk seals CANNOT_JUDGE over zero rather than turning an
// outage into a usage error.
func TestSubjectsEmptyListing(t *testing.T) {
	t.Parallel()

	pop := orgPop(t, &fakeForge{}, nil)

	for _, tc := range []struct {
		name string
		door assert.Subjects
	}{
		{"evidence", assert.EvidenceSubjects},
		{"chains", assert.ChainsSubjects},
		{"tags", assert.TagsSubjects},
		{"blast-radius", assert.BlastRadiusSubjects},
		{"permissions", assert.PermissionsSubjects},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.door.Enumerate(pop)
			if err != nil || len(got) != 0 {
				t.Fatalf("Enumerate = %v, %v — an outage is not a usage error", got, err)
			}
		})
	}
}
