// The corroboration and review-history gatherers, branch by branch —
// the guard-branch law applied to the reads that keep a repository
// from minting its own level.

package cli

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/level"
)

// rulesForge scripts the forge's effective-rules answer.
type rulesForge struct {
	levelForge

	rules    []byte
	rulesErr error
}

func (f *rulesForge) BranchRules(_, _, _ string) ([]byte, error) { return f.rules, f.rulesErr }

func (f *rulesForge) Rulesets(_, _ string) ([]byte, error) { return nil, errors.New("unused") }

func (f *rulesForge) Ruleset(_, _ string, _ int64) ([]byte, error) { return nil, errors.New("unused") }

// approvalsForge scripts the review-history answer on top of rules.
type approvalsForge struct {
	rulesForge

	parties  map[string]int
	missing  map[string]bool
	partyErr error
}

//nolint:gocritic // unnamedResult: the ApprovalsReader contract
func (f *approvalsForge) Approvals(_, _, rev string) (int, bool, error) {
	if f.partyErr != nil {
		return 0, false, f.partyErr
	}

	if f.missing[rev] {
		return 0, false, nil
	}

	return f.parties[rev], true, nil
}

// TestLiveRulesDegradedReads: every way the corroboration read can
// fail leaves nil — which the judge turns into unevaluated control
// rungs — never a fabricated answer in either direction.
func TestLiveRulesDegradedReads(t *testing.T) {
	la := &levelArgs{track: trackSource, owner: "acme", name: "widget", ref: "refs/heads/main"}

	t.Run("a forge that cannot serve rules", func(t *testing.T) {
		out := &latch{w: &strings.Builder{}}
		if got := la.liveRules(&levelForge{}, out); got != nil {
			t.Errorf("liveRules = %+v, want nil from a forge with no rules surface", got)
		}
	})

	t.Run("an unreadable rules answer", func(t *testing.T) {
		out := &latch{w: &strings.Builder{}}
		f := &rulesForge{rulesErr: errors.New("HTTP 403")}

		if got := la.liveRules(f, out); got != nil {
			t.Errorf("liveRules = %+v, want nil from an unreadable read", got)
		}
	})

	t.Run("a readable answer becomes the domain's facts", func(t *testing.T) {
		out := &latch{w: &strings.Builder{}}
		f := &rulesForge{rules: []byte(`[{"type": "non_fast_forward"},
			{"type": "pull_request", "parameters": {"required_approving_review_count": 1}}]`)}

		got := la.liveRules(f, out)
		if got == nil || !got.Restrictive || !got.ForcePushBlocked || got.RequiredApprovals != 1 {
			t.Errorf("liveRules = %+v, want the forge's facts", got)
		}
	})
}

// TestGatherApprovalsBranches: the review-history walk's guards — the
// missing surface, the read bound, the per-revision failure — each
// leave an absence the judge reports, never a count.
func TestGatherApprovalsBranches(t *testing.T) {
	la := &levelArgs{track: trackSource, owner: "acme", name: "widget", ref: "refs/heads/main"}

	revs := func(n int) []level.Revision {
		out := make([]level.Revision, 0, n)
		for i := range n {
			out = append(out, level.Revision{ID: fmt.Sprintf("%040d", i)})
		}

		return out
	}

	t.Run("a forge that cannot serve review history", func(t *testing.T) {
		out := &latch{w: &strings.Builder{}}
		ev := &level.Evidence{Revisions: revs(1)}

		la.gatherApprovals(ev, &levelForge{}, out)

		if ev.Approvals != nil {
			t.Errorf("Approvals = %v, want nil", ev.Approvals)
		}
	})

	t.Run("no revisions means nothing to read", func(t *testing.T) {
		out := &latch{w: &strings.Builder{}}
		ev := &level.Evidence{}

		la.gatherApprovals(ev, &approvalsForge{}, out)

		if ev.Approvals != nil {
			t.Errorf("Approvals = %v, want nil", ev.Approvals)
		}
	})

	t.Run("the read bound is logged, never silent", func(t *testing.T) {
		var buf strings.Builder

		out := &latch{w: &buf}
		ev := &level.Evidence{Revisions: revs(maxApprovalReads + 1)}

		la.gatherApprovals(ev, &approvalsForge{}, out)

		if ev.Approvals != nil {
			t.Errorf("Approvals = %v, want nil past the bound", ev.Approvals)
		}

		if !strings.Contains(buf.String(), "exceed") {
			t.Errorf("the bound was not logged:\n%s", buf.String())
		}
	})

	t.Run("a failing read leaves that revision absent", func(t *testing.T) {
		out := &latch{w: &strings.Builder{}}
		ev := &level.Evidence{Revisions: revs(2)}

		la.gatherApprovals(ev, &approvalsForge{partyErr: errors.New("HTTP 500")}, out)

		if len(ev.Approvals) != 0 {
			t.Errorf("Approvals = %v, want empty when every read failed", ev.Approvals)
		}
	})

	t.Run("counts land keyed by revision, absences stay absent", func(t *testing.T) {
		out := &latch{w: &strings.Builder{}}
		ev := &level.Evidence{Revisions: revs(2)}
		f := &approvalsForge{
			parties: map[string]int{fmt.Sprintf("%040d", 0): 2},
			missing: map[string]bool{fmt.Sprintf("%040d", 1): true},
		}

		la.gatherApprovals(ev, f, out)

		if got := ev.Approvals[fmt.Sprintf("%040d", 0)]; got != 2 {
			t.Errorf("parties = %d, want 2", got)
		}

		if _, present := ev.Approvals[fmt.Sprintf("%040d", 1)]; present {
			t.Error("a revision with no change record gained a count")
		}
	})
}

// TestRecordSettlesReview: the walk is skipped exactly when the
// corroborated record already answers the question — a cost rule that
// must never trigger on the record alone.
func TestRecordSettlesReview(t *testing.T) {
	t.Parallel()

	review := "SLSA_SOURCE_SCS_TWO_PARTY_REVIEW"

	for _, tt := range []struct {
		name  string
		props []string
		live  *level.LiveRules
		want  bool
	}{
		{
			name:  "record plus corroborating rules settle it",
			props: []string{review},
			live:  &level.LiveRules{RequiredApprovals: 1},
			want:  true,
		},
		{
			name:  "the record alone settles nothing",
			props: []string{review},
			live:  nil,
		},
		{
			name:  "rules that require no review corroborate no review control",
			props: []string{review},
			live:  &level.LiveRules{Restrictive: true},
		},
		{
			name: "live rules without the recorded control settle nothing",
			live: &level.LiveRules{RequiredApprovals: 2},
		},
	} {
		if got := recordSettlesReview(tt.props, tt.live); got != tt.want {
			t.Errorf("%s: recordSettlesReview = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestInventoriesFoundByContent: an inventory named anything is found
// by its bytes; the name hint orders the probe, never gates it; and
// the probe bound is logged rather than read as absence.
func TestInventoriesFoundByContent(t *testing.T) {
	la := &levelArgs{track: trackDependency, owner: "acme", name: "widget"}

	t.Run("a producer's own filename is not required", func(t *testing.T) {
		out := &latch{w: &strings.Builder{}}
		f := &levelForge{
			assets: []string{"deps.json"},
			files:  map[string][]byte{"deps.json": []byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`)},
		}

		got := la.inventories(f, "v1.0.0", f.assets, out)
		if _, ok := got["deps.json"]; !ok {
			t.Errorf("inventories = %v, want deps.json found by content", got)
		}
	})

	t.Run("the probe bound is logged", func(t *testing.T) {
		var buf strings.Builder

		out := &latch{w: &buf}

		assets := make([]string, 0, maxManifestProbes+2)
		files := map[string][]byte{}

		for i := range maxManifestProbes + 2 {
			name := fmt.Sprintf("binary-%d", i)
			assets = append(assets, name)
			files[name] = []byte("not an inventory")
		}

		f := &levelForge{assets: assets, files: files}

		if got := la.inventories(f, "v1.0.0", assets, out); len(got) != 0 {
			t.Errorf("inventories = %v, want none", got)
		}

		if !strings.Contains(buf.String(), "stopped looking for an inventory") {
			t.Errorf("the bound was not logged:\n%s", buf.String())
		}
	})
}

// TestProducerControlsDecidableGround: ownership is derived only where
// a coordinate can carry it — the default registry, and the subject's
// own forge namespace. Everywhere else is a named unknown.
func TestProducerControlsDecidableGround(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		location string
		want     ownership
	}{
		{"the default golang registry", upstreamDefault},
		{"https://github.com/acme/mirror", ownedByProducer},
		{"https://GitHub.com/ACME/mirror", ownedByProducer},
		{"https://github.com/stranger/mirror", upstreamDefault},
		// A stranger's host carrying the producer's name in a path once
		// read as producer-owned through a substring match.
		{"https://evil.example/acme/mirror", unknownHost},
		{"https://mirror.acme.example/go", unknownHost},
		{"git+https://github.com/acme/dep", ownedByProducer},
	} {
		if got := producerControls(tt.location, "acme"); got != tt.want {
			t.Errorf("producerControls(%q) = %v, want %v", tt.location, got, tt.want)
		}
	}
}

// TestMentionsModule: the module match is bounded on both sides, so a
// dependency that merely extends the module's name is never mistaken
// for the module itself.
func TestMentionsModule(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		s    string
		want bool
	}{
		{"pkg:golang/github.com/acme/widget@v1.0.0", true},
		{"pkg:golang/github.com/acme/widget/v2@v2.0.0", true},
		{"acme/widget", true},
		{"pkg:golang/github.com/acme/widget-utils@v1.0.0", false},
		{"pkg:golang/github.com/other/acme/widget@v1.0.0", true},
		{"pkg:golang/example.com/dep@v1.0.0", false},
	} {
		if got := mentionsModule(tt.s, "acme/widget"); got != tt.want {
			t.Errorf("mentionsModule(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}

// A compile-time seam check: the scripted forges must satisfy the
// surfaces the gatherers assert to.
var (
	_ gh.RulesReader     = (*rulesForge)(nil)
	_ gh.ApprovalsReader = (*approvalsForge)(nil)
)
