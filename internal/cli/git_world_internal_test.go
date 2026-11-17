package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/gitfetch"
	"github.com/monumental-archive/stele/internal/gittest"
)

// swapGitRemotes points every git fetch a run makes at repositories
// built in the test, by owner/repo; any other repository is a remote
// that is not there, so a walk over it could not see its history. No
// test reaches the network through it.
func swapGitRemotes(t *testing.T, repos map[string]*gittest.Repo) {
	t.Helper()

	orig := newGitSession
	nowhere := t.TempDir()

	newGitSession = func(want gitfetch.Want, log func(string, ...any)) *gitfetch.Session {
		return &gitfetch.Session{
			Remote: func(owner, repo string) string {
				if r, ok := repos[owner+"/"+repo]; ok {
					return r.URL()
				}

				return "file://" + filepath.Join(nowhere, owner, repo)
			},
			Want: want,
			Log:  log,
		}
	}

	t.Cleanup(func() { newGitSession = orig })
}

// swapForgeSnapshot replays a forge snapshot for the reads that are
// still the forge's — the population listing — while git objects come
// from swapGitRemotes.
func swapForgeSnapshot(t *testing.T, dir string) {
	t.Helper()

	orig := newForge
	newForge = func() gh.Forge { return gh.Snapshot{Dir: dir} }

	t.Cleanup(func() { newForge = orig })
}

// TestTheSnapshotFlagsAreGoneFromTheGitWalks (stele#384): the tag and
// chain audits read git objects through one fetch, and a forge
// snapshot has none of them to replay — so the flags are refused by
// name rather than accepted and ignored.
func TestTheSnapshotFlagsAreGoneFromTheGitWalks(t *testing.T) {
	for _, args := range [][]string{
		{"assert", "tags", "--repo", "acme/widget", "--policy", "p.json", "--snapshot", "s"},
		{"assert", "tags", "--repo", "acme/widget", "--policy", "p.json", "--capture", "s"},
		{"assert", "chains", "--repo", "acme/lab", "--policy", "p.json", "--verify-policy", "v.json", "--snapshot", "s"},
		{"assert", "chains", "--repo", "acme/lab", "--policy", "p.json", "--verify-policy", "v.json", "--capture", "s"},
	} {
		t.Run(strings.Join(args[1:2], "")+" "+args[len(args)-2], func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := Run(args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("Run = %d, want %d", code, exitUsage)
			}

			want := "flag provided but not defined: " + strings.TrimPrefix(args[len(args)-2], "-")
			if !strings.Contains(stderr.String(), want) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), want)
			}
		})
	}
}
