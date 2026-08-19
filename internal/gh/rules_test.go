// The rules read surface against a scripted server, plus the
// snapshot/capture round trip.
//
// The distinction under test throughout: a branch under no rules
// answers 200 with an empty array, while a 404 is the repository or
// the branch not existing. The claims engine's blindness guard needs
// those to arrive differently, so they have to leave here
// differently.

package gh_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
)

// rulesServer scripts the rules endpoints.
func rulesServer(t *testing.T) *gh.Client {
	t.Helper()

	mux := http.NewServeMux()

	// Two pages, so the merge is exercised rather than assumed.
	mux.HandleFunc("/repos/acme/widget/rules/branches/main", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "1":
			writeBody(w, []byte(`[{"type": "deletion", "ruleset_id": 1}]`))
		case "2":
			writeBody(w, []byte(`[{"type": "required_signatures", "ruleset_id": 2}]`))
		default:
			writeBody(w, []byte(`[]`))
		}
	})

	mux.HandleFunc("/repos/acme/widget/rules/branches/quiet", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`[]`))
	})

	mux.HandleFunc("/repos/acme/widget/rules/branches/gone", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	mux.HandleFunc("/repos/acme/widget/rulesets", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			if r.URL.Query().Get("includes_parents") != "true" {
				t.Error("the ruleset listing did not ask for inherited rulesets, where the org controls live")
			}

			writeBody(w, []byte(`[{"id": 101, "target": "tag", "enforcement": "active"}]`))

			return
		}

		writeBody(w, []byte(`[]`))
	})

	mux.HandleFunc("/repos/acme/widget/rulesets/101", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`{"id": 101, "target": "tag", "bypass_actors": []}`))
	})

	mux.HandleFunc("/repos/acme/widget/rulesets/404", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	mux.HandleFunc("/repos/acme/widget/rulesets/403", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &gh.Client{Base: srv.URL, Download: srv.URL, HTTP: srv.Client()}
}

func TestBranchRulesMergesPages(t *testing.T) {
	t.Parallel()

	body, err := rulesServer(t).BranchRules("acme", "widget", "main")
	if err != nil {
		t.Fatalf("BranchRules = %v", err)
	}

	got := string(body)
	for _, want := range []string{`"deletion"`, `"required_signatures"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("merged rules = %s, want it to carry %s", got, want)
		}
	}
}

// A branch under no rules is an empty ANSWER; a branch that does not
// exist is a failure. The claims engine reads the first as a lapse
// and refuses the second, so they must not arrive alike.
func TestBranchRulesEmptyIsNotMissing(t *testing.T) {
	t.Parallel()

	client := rulesServer(t)

	body, err := client.BranchRules("acme", "widget", "quiet")
	if err != nil {
		t.Fatalf("an unruled branch = %v, want an empty answer", err)
	}

	if strings.TrimSpace(string(body)) != "[]" {
		t.Fatalf("an unruled branch = %s, want []", body)
	}

	if _, err := client.BranchRules("acme", "widget", "gone"); err == nil {
		t.Fatal("a missing branch = nil error, want a failure")
	}
}

func TestRulesetReads(t *testing.T) {
	t.Parallel()

	client := rulesServer(t)

	listing, err := client.Rulesets("acme", "widget")
	if err != nil {
		t.Fatalf("Rulesets = %v", err)
	}

	if !strings.Contains(string(listing), `"id":101`) {
		t.Fatalf("listing = %s", listing)
	}

	detail, err := client.Ruleset("acme", "widget", 101)
	if err != nil {
		t.Fatalf("Ruleset = %v", err)
	}

	if !strings.Contains(string(detail), `"bypass_actors": []`) {
		t.Fatalf("detail = %s, want the bytes the forge served", detail)
	}

	// Listed-but-unreadable is a failure both ways: a 404 says the
	// listing lied, a 403 says the credential cannot see org-level
	// content. Either would drop exactly the controls nobody checked.
	for _, id := range []int64{404, 403} {
		if _, err := client.Ruleset("acme", "widget", id); err == nil {
			t.Fatalf("Ruleset(%d) = nil error, want a failure", id)
		}
	}
}

// Capture records what was read; Snapshot replays exactly those
// bytes. A shadow run feeds both legs one recording, so divergence is
// never the API changing between reads.
func TestRulesCaptureAndReplay(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	capture := gh.Capture{Live: rulesServer(t), Dir: dir}

	live, err := capture.BranchRules("acme", "widget", "main")
	if err != nil {
		t.Fatalf("capture BranchRules = %v", err)
	}

	if _, lerr := capture.Rulesets("acme", "widget"); lerr != nil {
		t.Fatalf("capture Rulesets = %v", lerr)
	}

	if _, derr := capture.Ruleset("acme", "widget", 101); derr != nil {
		t.Fatalf("capture Ruleset = %v", derr)
	}

	snapshot := gh.Snapshot{Dir: dir}

	replayed, err := snapshot.BranchRules("acme", "widget", "main")
	if err != nil {
		t.Fatalf("replay BranchRules = %v", err)
	}

	if !bytes.Equal(replayed, live) {
		t.Fatalf("replay = %s, capture = %s — a snapshot must replay the bytes, not a paraphrase", replayed, live)
	}

	if _, err := snapshot.Rulesets("acme", "widget"); err != nil {
		t.Fatalf("replay Rulesets = %v", err)
	}

	if _, err := snapshot.Ruleset("acme", "widget", 101); err != nil {
		t.Fatalf("replay Ruleset = %v", err)
	}

	// A read the capture never made is absent from the snapshot, and
	// absence there is a failure rather than an empty answer: replaying
	// a read nobody recorded would invent enforcement state.
	if _, err := snapshot.Ruleset("acme", "widget", 999); err == nil {
		t.Fatal("replaying an unrecorded read = nil error, want a failure")
	}

	if _, err := os.Stat(filepath.Join(dir, "acme", "widget", "rules", "rulesets", "101.json")); err != nil {
		t.Fatalf("the capture wrote nothing readable: %v", err)
	}
}

// forgeOnly is a Forge that is not a RulesReader.
type forgeOnly struct{ gh.Forge }

// A capture wired over a Forge that cannot read rules refuses by
// name, rather than recording an empty snapshot that later replays as
// enforcement nobody has.
func TestCaptureOverANonRulesForge(t *testing.T) {
	t.Parallel()

	// A Forge and nothing more: the embedded interface satisfies Forge
	// without carrying the rules methods, which is exactly the wiring
	// mistake this guard exists for.
	capture := gh.Capture{Live: forgeOnly{}, Dir: t.TempDir()}

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"branch rules", func() error { _, err := capture.BranchRules("a", "b", "main"); return err }},
		{"ruleset listing", func() error { _, err := capture.Rulesets("a", "b"); return err }},
		{"ruleset detail", func() error { _, err := capture.Ruleset("a", "b", 1); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.call()
			if err == nil {
				t.Fatal("capture = nil error, want the wiring refusal")
			}

			if !strings.Contains(err.Error(), "not a RulesReader") {
				t.Fatalf("capture = %v, want it to name the wiring defect", err)
			}
		})
	}
}
