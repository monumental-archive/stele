package assert_test

import (
	"testing"

	"github.com/monumental-archive/stele/internal/gitrepo"
)

// twinRev is a second founding link, committed in the same second as
// genesisRev: two branches founded together (stele#414).
const twinRev = "0000000000000000000000000000000000000007"

// tiedTags scripts widget's one member on an unlinked target, with two
// genesis candidates tied at the oldest commit time. reaching says
// whether the twin reaches the target; genesisRev never does.
func tiedTags(reaching bool) *fakeTags {
	f := conformantTags()
	f.objects[tagObjSHA].Target = unlinkedRev
	f.notes["widget"] = append(f.notes["widget"], gitrepo.ChainNote{Rev: twinRev, Note: []byte(link)})
	f.meta[twinRev] = &gitrepo.CommitMeta{Parents: []string{preGenesisRev}, CommitEpoch: 100}
	f.ancestry[genesisRev+"..."+unlinkedRev] = false
	f.ancestry[twinRev+"..."+unlinkedRev] = reaching

	return f
}

// TestTagsTiedGenesisJudgesTheSameEveryRun (stele#414): two genesis
// candidates of one commit time, one of which reaches the tag's
// target. The genesis is BOTH, so the tag is witnessed on every run —
// judged, its missing link a defect inside the horizon — and every run
// seals the same bytes. Before the fix the walk kept whichever
// candidate the map yielded first (measured: the other one in 11 of
// 40 runs), and the tag flipped to unjudgeable.
func TestTagsTiedGenesisJudgesTheSameEveryRun(t *testing.T) {
	t.Parallel()

	const runs = 64

	first := ""

	for i := range runs {
		rep := runTags(t, tiedTags(true), &fakeTagVerifier{})
		doc := encoded(t, rep)

		if i == 0 {
			first = doc
		} else if doc != first {
			t.Fatalf("run %d sealed a different report than run 0:\n%s\nvs\n%s", i, doc, first)
		}

		facts := tagFacts(t, rep)
		if facts["tagsJudged:widget"] != "1" || facts["tagsUnjudgeable:widget"] != "0" {
			t.Fatalf("run %d: judged %q, unjudgeable %q — a member of the genesis reaches the target",
				i, facts["tagsJudged:widget"], facts["tagsUnjudgeable:widget"])
		}

		if excused := encodeReport(t, rep).Excused; len(excused) != 0 {
			t.Fatalf("run %d excused %+v — a witnessed tag owes its link", i, excused)
		}
	}
}

// TestTagsGenesisOriginWording pins what the horizon says, member by
// member, in id order wherever it names more than one.
func TestTagsGenesisOriginWording(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		f    func() *fakeTags
		want string
	}{
		{
			name: "a tie that reaches nothing names both, sorted",
			f:    func() *fakeTags { return tiedTags(false) },
			want: "the ledger's founded genesis is tied at one commit time between " + genesisRev + " and " +
				twinRev + ", and none of them reaches target " + unlinkedRev,
		},
		{
			name: "a single candidate keeps its wording",
			f:    preGenesisTags,
			want: "the ledger's founded genesis " + genesisRev + " does not reach target " + preGenesisRev,
		},
		{
			// stele#408: a link no branch or tag reaches is no
			// candidate, so the tie it would have made is not one.
			name: "a tied member no branch or tag reaches is no candidate",
			f: func() *fakeTags {
				f := tiedTags(true)
				f.unheld = map[string]bool{twinRev: true}

				return f
			},
			want: "the ledger's founded genesis " + genesisRev + " does not reach target " + unlinkedRev,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc := encodeReport(t, runTags(t, tc.f(), &fakeTagVerifier{}))
			if len(doc.Excused) != 1 {
				t.Fatalf("excused = %+v, want the one link finding the horizon excuses", doc.Excused)
			}

			if got := doc.Excused[0].Exception.Origin; got != tc.want {
				t.Fatalf("origin =\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}
