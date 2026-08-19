// The level verb's two adapter reads, against a scripted server: the
// forge's own enforced controls (the corroboration half no
// subject-issued record may hold without) and the review history the
// two-party judgment counts.

package gh_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
)

const (
	revMerged = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	revDirect = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	revGone   = "cccccccccccccccccccccccccccccccccccccccc"
)

// levelReadsServer scripts the rules and review surfaces.
func levelReadsServer(t *testing.T, branchRules string) *gh.Client {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/repos/acme/widget/rules/branches/main", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "1" {
			writeBody(w, []byte(`[]`))

			return
		}

		writeBody(w, []byte(branchRules))
	})

	// A pull produced revMerged; its author approved nothing, one
	// reviewer approved twice (counted once), one commented only.
	mux.HandleFunc("/repos/acme/widget/commits/"+revMerged+"/pulls", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`[
		  {"number": 9, "merge_commit_sha": "0000000000000000000000000000000000000000",
		   "user": {"login": "author"}},
		  {"number": 7, "merge_commit_sha": "`+revMerged+`", "user": {"login": "author"}}]`))
	})
	mux.HandleFunc("/repos/acme/widget/pulls/7/reviews", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "1" {
			writeBody(w, []byte(`[]`))

			return
		}

		writeBody(w, []byte(`[
		  {"state": "APPROVED", "user": {"login": "reviewer"}},
		  {"state": "APPROVED", "user": {"login": "reviewer"}},
		  {"state": "APPROVED", "user": {"login": "author"}},
		  {"state": "COMMENTED", "user": {"login": "bystander"}}]`))
	})

	// revDirect is associated with a pull it did not come from — the
	// merge that produced it is nobody's, so it was pushed directly.
	mux.HandleFunc("/repos/acme/widget/commits/"+revDirect+"/pulls", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`[]`))
	})

	mux.HandleFunc("/repos/acme/widget/commits/"+revGone+"/pulls", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &gh.Client{Base: srv.URL, HTTP: srv.Client(), Sleep: func(time.Duration) {}}
}

// TestEnforcedControlsFromTheForge: the rule-type mapping is GitHub
// knowledge and lives behind this adapter; the judge only ever sees
// the domain's facts.
func TestEnforcedControlsFromTheForge(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name        string
		rules       string
		restrictive bool
		forcePush   bool
		approvals   int
	}{
		{
			name: "force-push protection and required reviews",
			rules: `[{"type": "non_fast_forward"},
			         {"type": "pull_request", "parameters": {"required_approving_review_count": 2}}]`,
			restrictive: true, forcePush: true, approvals: 2,
		},
		{
			name:        "a deletion rule restricts without blocking force pushes",
			rules:       `[{"type": "deletion"}]`,
			restrictive: true,
		},
		{
			name:  "no rules at all",
			rules: `[]`,
		},
		{
			name:        "a rule with no type still restricts",
			rules:       `[{"parameters": {}}]`,
			restrictive: true,
		},
	} {
		c := levelReadsServer(t, tt.rules)

		live, err := gh.EnforcedControls(c, "acme", "widget", "main")
		if err != nil {
			t.Fatalf("%s: EnforcedControls = %v", tt.name, err)
		}

		if live.Restrictive != tt.restrictive || live.ForcePushBlocked != tt.forcePush ||
			live.RequiredApprovals != tt.approvals {
			t.Errorf("%s: LiveRules = %+v, want restrictive=%v forcePush=%v approvals=%d",
				tt.name, live, tt.restrictive, tt.forcePush, tt.approvals)
		}
	}
}

// TestEnforcedControlsRefusesAnUnreadableAnswer: a broken read is an
// error, never an empty rule set — corroboration must not degrade into
// "the forge said nothing, carry on".
func TestEnforcedControlsRefusesAnUnreadableAnswer(t *testing.T) {
	t.Parallel()

	c := levelReadsServer(t, `{"not": "a list"}`)

	if _, err := gh.EnforcedControls(c, "acme", "widget", "main"); err == nil {
		t.Error("EnforcedControls read a non-list answer as rules")
	}
}

// TestApprovalsCountsThePartiesTheSpecCounts: the author is one
// person; each distinct approving reviewer who is not the author is
// another; a duplicate approval and the author approving themselves
// count nothing.
func TestApprovalsCountsThePartiesTheSpecCounts(t *testing.T) {
	t.Parallel()

	c := levelReadsServer(t, `[]`)

	parties, found, err := c.Approvals("acme", "widget", revMerged)
	if err != nil || !found {
		t.Fatalf("Approvals = %v, found=%v", err, found)
	}

	if parties != 2 {
		t.Errorf("parties = %d, want 2 (the author plus one distinct approving reviewer)", parties)
	}
}

// TestApprovalsForADirectPush: a revision no pull produced was agreed
// to by its pusher alone — an answer of one person, not an absence.
func TestApprovalsForADirectPush(t *testing.T) {
	t.Parallel()

	c := levelReadsServer(t, `[]`)

	parties, found, err := c.Approvals("acme", "widget", revDirect)
	if err != nil || !found {
		t.Fatalf("Approvals = %v, found=%v", err, found)
	}

	if parties != 1 {
		t.Errorf("parties = %d, want 1 for a direct push", parties)
	}
}

// TestApprovalsAbsenceIsNotACount: a revision the forge holds no
// change record for is an absence of sight, never a count.
func TestApprovalsAbsenceIsNotACount(t *testing.T) {
	t.Parallel()

	c := levelReadsServer(t, `[]`)

	_, found, err := c.Approvals("acme", "widget", revGone)
	if err != nil {
		t.Fatalf("Approvals = %v", err)
	}

	if found {
		t.Error("a 404 change record read as found")
	}
}
