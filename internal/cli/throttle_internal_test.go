// What a throttled walk REPORTS (stele#209). internal/gh proves the
// classification and the ladder; this proves the sentence a run ends
// on, which is the half the defect was actually about: a walk that
// never got to look reported its subjects unreadable, and an evidence
// tool that says "unreadable" has stated a fact about the subject.
//
// The verdict is the assertion. CANNOT_JUDGE and FAIL are different
// exit codes because they are different claims, and a throttle that
// sealed either FAIL or PASS would be the tool answering a question
// the run never asked the forge.

package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
)

// throttlingForge is a live client whose every read is refused for the
// caller's PACE — the 2026-08-20 outage, scripted.
func throttlingForge(t *testing.T, respond func(http.ResponseWriter)) *gh.Client {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		respond(w)
	}))
	t.Cleanup(srv.Close)

	c := gh.New("test-token")
	c.Base = srv.URL
	c.Download = srv.URL
	c.Sleep = func(time.Duration) {} // no wall time in tests

	return c
}

// TestThrottledWalkCannotJudge pins the terminal, end to end: a
// throttle the ladder cannot outlast ends the run as CANNOT_JUDGE
// naming the THROTTLE, and a credential the forge genuinely refuses
// ends it naming the SUBJECT. Both are CANNOT_JUDGE — an unread
// subject is unchecked either way — and the sentence is what tells an
// operator which of the two to go fix.
func TestThrottledWalkCannotJudge(t *testing.T) {
	for _, tc := range []struct {
		name    string
		respond func(http.ResponseWriter)
		// says is the sentence the run must end on; never is the one it
		// must not, because it belongs to the other refusal.
		says, never string
	}{
		{
			name: "a throttle names the host, never the subject",
			respond: func(w http.ResponseWriter) {
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusForbidden)
			},
			says:  "throttled this walk",
			never: "cannot read this",
		},
		{
			name: "a spent budget names the host too",
			respond: func(w http.ResponseWriter) {
				w.Header().Set("X-Ratelimit-Remaining", "0")
				w.WriteHeader(http.StatusForbidden)
			},
			says:  "throttled this walk",
			never: "cannot read this",
		},
		{
			name: "a credential the forge refuses still names the subject",
			respond: func(w http.ResponseWriter) {
				http.Error(w, "Resource not accessible by personal access token", http.StatusForbidden)
			},
			says:  "cannot read this",
			never: "throttled this walk",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, policy := tagsSnapshot(t)
			swapTagVerifier(t, scriptedTagVerifier{})
			swapForge(t, throttlingForge(t, tc.respond))

			root := filepath.Join(t.TempDir(), "root.json")
			if err := os.WriteFile(root, []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}

			var stdout, stderr bytes.Buffer

			code := Run([]string{
				"assert", "tags", "--repo", "acme/widget", "--policy", policy, "--trusted-root", root,
			}, &stdout, &stderr)
			if code != exitBlind {
				t.Fatalf("Run = %d, want %d (CANNOT_JUDGE)\nstdout: %s\nstderr: %s",
					code, exitBlind, stdout.String(), stderr.String())
			}

			said := stdout.String() + stderr.String()

			if !strings.Contains(said, tc.says) {
				t.Fatalf("the run said %q, want it to name %q", said, tc.says)
			}

			if strings.Contains(said, tc.never) {
				t.Fatalf("the run said %q, which is the OTHER refusal — %q", said, tc.never)
			}

			// The verdict travels in the report, not only in the exit
			// code: a consumer reading the document must see the same
			// answer the shell does.
			if !strings.Contains(stdout.String(), "CANNOT_JUDGE") {
				t.Fatalf("stdout = %q, want the CANNOT_JUDGE verdict", stdout.String())
			}
		})
	}
}
