package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gittest"
)

// TestAssertTagsJudgesPastAnUnreachableLink (stele#408): a ledger that
// links a commit no branch and no tag reaches — here a branch deleted
// after its commit was linked — no longer costs the repository its
// whole tag judgment. The fetch does not hold that commit, so it is an
// ancestor of no tag target and witnesses nothing: it is skipped as a
// genesis candidate, counted and named, and the tag is judged by the
// reachable genesis.
func TestAssertTagsJudgesPastAnUnreachableLink(t *testing.T) {
	r := gittest.New(t)
	r.Commit("feat: c1")
	r.Git("checkout", "-q", "-b", "gone")
	unreachable := r.Commit("feat: g1, on a branch deleted after its link was noted")
	r.Git("checkout", "-q", "main")
	c2 := r.Commit("feat: c2")
	c3 := r.Commit("feat: c3")

	for _, rev := range []string{c2, c3, unreachable} {
		r.Note("refs/notes/commits", rev, []byte(linkNoteJSON))
	}

	r.Annotated("v1.0.0", c3, "release-mint[bot]", true)
	r.Git("branch", "-D", "gone")

	swapGitRemotes(t, map[string]*gittest.Repo{"acme/widget": r})
	swapTagVerifier(t, scriptedTagVerifier{})

	policy := tagsPolicy(t)
	root := filepath.Join(t.TempDir(), "root.json")

	if err := os.WriteFile(root, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "tags", "--repo", "acme/widget", "--policy", policy, "--trusted-root", root, "--json",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s", code, exitOK, stdout.String(), stderr.String())
	}

	for _, want := range []string{`"verdict":"PASS"`, `{"name":"unreachableLinks:widget","value":"1"}`} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("the report does not carry %s:\n%s", want, stdout.String())
		}
	}

	for _, want := range []string{
		"assert: tags: widget: the ledger links " + unreachable +
			", a commit no branch or tag reaches — it witnesses no tag and is not a genesis candidate",
		"widget: 1 tag(s) listed, 0 excluded before epoch v0.1.0, 1 in population: 1 judged, 0 unjudgeable",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("the run does not say %q:\n%s", want, stderr.String())
		}
	}
}
