package assert_test

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gitrepo"
	"github.com/monumental-archive/stele/internal/report"
)

// unreachableRev is a linked revision no branch and no tag reaches —
// a commit on a branch deleted after its link was noted (stele#408).
const unreachableRev = "0000000000000000000000000000000000000009"

// unreachableLine is what the run says, once per such link.
func unreachableLine(rev string) string {
	return "assert: tags: widget: the ledger links " + rev +
		", a commit no branch or tag reaches — it witnesses no tag and is not a genesis candidate"
}

// TestTagsGenesisIsTheOldestReachableLink (stele#408): a link no
// branch or tag reaches stays linked but is never the genesis, even
// when it is older than every reachable one — read as it was before
// git held the history, it would have become the genesis and left the
// tag unwitnessed. The horizon is named from the reachable genesis,
// the skipped link is named, and the report counts it.
func TestTagsGenesisIsTheOldestReachableLink(t *testing.T) {
	t.Parallel()

	f := preGenesisTags()
	f.notes["widget"] = append(f.notes["widget"], gitrepo.ChainNote{Rev: unreachableRev, Note: []byte(link)})
	// Scripted older than the reachable genesis and parentless: were it
	// a candidate, it would be the genesis.
	f.meta[unreachableRev] = &gitrepo.CommitMeta{CommitEpoch: 50}
	f.unheld = map[string]bool{unreachableRev: true}

	rep, lines := runTagsLogged(t, f, &fakeTagVerifier{})
	doc := encodeReport(t, rep)

	if len(doc.Excused) != 1 {
		t.Fatalf("excused = %+v, want the one link finding the horizon excuses", doc.Excused)
	}

	want := "the ledger's founded genesis " + genesisRev + " does not reach target " + preGenesisRev
	if got := doc.Excused[0].Exception.Origin; got != want {
		t.Fatalf("origin = %q, want %q — the genesis is the oldest REACHABLE link", got, want)
	}

	if !slices.Contains(lines, unreachableLine(unreachableRev)) {
		t.Fatalf("the run does not name the skipped link:\n%q", lines)
	}

	if got := tagFacts(t, rep)["unreachableLinks:widget"]; got != "1" {
		t.Fatalf("unreachableLinks:widget = %q, want 1", got)
	}
}

// TestTagsEveryLinkUnreachableFoundsNoChain: a ledger none of whose
// links a branch or tag reaches witnesses nothing — the existing
// unfounded wording, every link named and counted, and the walk still
// judges, never refuses.
func TestTagsEveryLinkUnreachableFoundsNoChain(t *testing.T) {
	t.Parallel()

	f := preGenesisTags()
	f.unheld = map[string]bool{genesisRev: true, linkedRev: true}

	rep, lines := runTagsLogged(t, f, &fakeTagVerifier{})
	doc := encodeReport(t, rep)

	if len(doc.Excused) != 1 {
		t.Fatalf("excused = %+v, want the one link finding the horizon excuses", doc.Excused)
	}

	want := "the ledger founds no chain, so no link on target " + preGenesisRev + " can be witnessed here"
	if got := doc.Excused[0].Exception.Origin; got != want {
		t.Fatalf("origin = %q, want %q", got, want)
	}

	for _, rev := range []string{genesisRev, linkedRev} {
		if !slices.Contains(lines, unreachableLine(rev)) {
			t.Fatalf("the run does not name %s:\n%q", rev, lines)
		}
	}

	if got := tagFacts(t, rep)["unreachableLinks:widget"]; got != "2" {
		t.Fatalf("unreachableLinks:widget = %q, want 2", got)
	}
}

// TestTagsCountsNoUnreachableLink: the count is stated on every run
// whose ledger the walk read, zero included.
func TestTagsCountsNoUnreachableLink(t *testing.T) {
	t.Parallel()

	rep := runTags(t, conformantTags(), &fakeTagVerifier{})

	if got := tagFacts(t, rep)["unreachableLinks:widget"]; got != "0" {
		t.Fatalf("unreachableLinks:widget = %q, want 0 — the count is stated when the ledger was read", got)
	}
}

// TestTagsGitFailingStillCannotJudge: only a commit the fetch does not
// hold is skipped. git failing — on the presence read, or reading a
// commit it holds — ends the walk, unchanged: the run could not see,
// which says nothing about the tags.
func TestTagsGitFailingStillCannotJudge(t *testing.T) {
	t.Parallel()

	failing := errors.New("git cat-file -e: exit status 128: fatal: unable to read the object store")

	for _, tc := range []struct {
		name   string
		tamper func(*fakeTags)
		want   []string
	}{
		{
			name:   "the commit of a held link will not read",
			tamper: func(f *fakeTags) { delete(f.meta, genesisRev) },
			want: []string{
				"assert: commit " + genesisRev + " of acme/widget: no commit meta scripted for " + genesisRev,
			},
		},
		{
			name:   "the presence read fails",
			tamper: func(f *fakeTags) { f.torn = map[string]error{"Reachable": failing} },
			want: []string{
				"assert: commit " + genesisRev + " of acme/widget: " + failing.Error(),
				"assert: commit " + linkedRev + " of acme/widget: " + failing.Error(),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := conformantTags()
			tc.tamper(f)

			_, err := assert.Tags(loadTagsPolicy(t), repoPop(t, "acme/widget"),
				f, &fakeTagVerifier{}, report.NewJournal(), func(string, ...any) {})
			if err == nil || !slices.Contains(tc.want, err.Error()) {
				t.Fatalf("Tags = %v, want one of %s", err, fmt.Sprintf("%q", tc.want))
			}
		})
	}
}
