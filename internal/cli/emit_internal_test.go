// Internal tests for the emit verb's dispatch: the effect seams are
// swapped for scripted fakes so every guard and exit path is a table
// row. The engine itself is proven in internal/emit; the render in
// internal/verify.

package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/emit"
)

const emitRev = "1111111111111111111111111111111111111111"

// fakeEmitGit is a one-commit history with no notes — the genesis
// case, the shortest full path through the engine.
type fakeEmitGit struct {
	notes map[string][]byte
}

func (g *fakeEmitGit) Tip(string) (string, error) { return emitRev, nil }

func (g *fakeEmitGit) CommitterIdent() error { return nil }

func (g *fakeEmitGit) DryRunPushNotes(string) error      { return nil }
func (g *fakeEmitGit) Parent(string) (string, error)     { return "", nil }
func (g *fakeEmitGit) Parents(string) ([]string, error)  { return nil, nil }
func (g *fakeEmitGit) CommitTime(string) (string, error) { return "2026-08-01T00:00:00Z", nil }
func (g *fakeEmitGit) IsAncestor(string, string) (bool, error) {
	return true, nil
}

func (g *fakeEmitGit) Note(rev string) ([]byte, error) {
	return g.notes[rev], nil
}

func (g *fakeEmitGit) Noted() ([]string, error) { return nil, nil }

func (g *fakeEmitGit) AddNote(rev string, note []byte) error {
	g.notes[rev] = append(bytes.TrimRight(note, "\n"), '\n')

	return nil
}

func (g *fakeEmitGit) FetchNotes() error { return nil }
func (g *fakeEmitGit) PushNotes() error  { return nil }

// fakeEmitSigner mirrors the emit package's test signer: a bundle the
// scripted verifier accepts unconditionally.
type fakeEmitSigner struct{}

func (fakeEmitSigner) Sign([]byte) ([]byte, error) {
	return []byte(`{"scripted": "bundle"}`), nil
}

func (fakeEmitSigner) Check() error { return nil }

// swapEmit installs the emit seams for one test.
func swapEmit(t *testing.T, g emit.Git, gitErr error) {
	t.Helper()

	// CI itself runs under a workflow ref; the guard under test must
	// see the caller's scripted world, not the harness's own identity.
	// The scripted world's reserved identity, since an absent ref is
	// now a refusal in its own right (stele#69 item 4).
	t.Setenv("GITHUB_WORKFLOW_REF", "acme/widget/.github/workflows/source-attest.yml@refs/heads/main")

	origSigner, origGit, origNow := newSigner, openEmitGit, emitNow

	newSigner = func(string) emit.Signer { return fakeEmitSigner{} }
	openEmitGit = func(string, string, string, string) (emit.Git, error) {
		if gitErr != nil {
			return nil, gitErr
		}

		return g, nil
	}
	emitNow = func() time.Time { return time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC) }

	t.Cleanup(func() {
		newSigner, openEmitGit, emitNow = origSigner, origGit, origNow
	})
}

// emitFiles adds the chain mode's claims payload to the shared
// fixture files.
//
//nolint:gocritic // unnamedResult: the fixture pair reads clearly at every call site
func emitFiles(t *testing.T) (paths, string) {
	t.Helper()

	px := files(t)
	claims := filepath.Join(t.TempDir(), "claims.json")

	const doc = `{
	  "rulesReadAt": "2026-08-15T00:00:00Z",
	  "rulesetsUpdatedAt": [1000000],
	  "controls": [{"property": "ORG_SOURCE_GATED", "evidence": [{"rule": "live"}]}]
	}`

	if err := os.WriteFile(claims, []byte(doc), ownerRW); err != nil {
		t.Fatal(err)
	}

	return px, claims
}

func chainArgs(px paths, claims string) []string {
	return []string{
		"emit", "chain",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--git-dir", "ignored-by-the-seam",
		"--rev", emitRev, "--claims", claims,
		"--actor", "octocat", "--actor-id", "583231",
		"--canon-digest", strings.Repeat("b", 40),
		"--policy-uri", "https://github.com/acme/canon/blob/x/slsa/verify-policy.json",
		"--genesis",
	}
}

func TestEmitChainPasses(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})

	g := &fakeEmitGit{notes: map[string][]byte{}}
	swapEmit(t, g, nil)

	px, claims := emitFiles(t)

	var stdout, stderr bytes.Buffer

	code := Run(chainArgs(px, claims), &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d, stderr: %s", code, stderr.String())
	}

	if g.notes[emitRev] == nil {
		t.Error("no note was written for the pushed revision")
	}

	if !strings.Contains(stdout.String(), "pushed") {
		t.Errorf("stdout = %q, want the push line", stdout.String())
	}
}

func TestEmitChainRefusalExitsOne(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})

	g := &fakeEmitGit{notes: map[string][]byte{}}
	swapEmit(t, g, nil)

	px, claims := emitFiles(t)

	// Not genesis, and no genesis link on the history: the engine
	// refuses and the process reports it as a verification failure.
	args := chainArgs(px, claims)
	args = args[:len(args)-1] // drop --genesis

	var stdout, stderr bytes.Buffer

	code := Run(args, &stdout, &stderr)
	if code != exitRefused || !strings.Contains(stderr.String(), "no genesis link") {
		t.Fatalf("Run = %d, stderr %q — want the engine refusal", code, stderr.String())
	}
}

func TestEmitChainGitOpenFailure(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})
	swapEmit(t, nil, errors.New("not a repository"))

	px, claims := emitFiles(t)

	var stdout, stderr bytes.Buffer

	code := Run(chainArgs(px, claims), &stdout, &stderr)
	if code != exitRefused || !strings.Contains(stderr.String(), "not a repository") {
		t.Fatalf("Run = %d, stderr %q — want the open failure", code, stderr.String())
	}
}

func TestEmitVSARefusalExitsOne(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{err: errors.New("store torn")})

	px := files(t)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"emit", "vsa",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", "v1.2.3",
		"--subjects", px.subjects, "--sboms", px.subjects,
		"--signer-digest", strings.Repeat("a", 40), "--canon-digest", strings.Repeat("b", 40),
		"--policy-uri", "https://github.com/acme/canon/blob/x/slsa/verify-policy.json",
	}, &stdout, &stderr)

	if code != exitRefused || !strings.Contains(stderr.String(), "store torn") {
		t.Fatalf("Run = %d, stderr %q — want the store refusal", code, stderr.String())
	}
}

func TestEmitUsageRefusals(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})

	px := files(t)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no mode", []string{"emit"}, "a mode is required"},
		{"unknown mode", []string{"emit", "conjure"}, "unknown mode"},
		{"bad flag", []string{"emit", "chain", "--conjure"}, ""},
		{
			"repo not owner/repo",
			[]string{"emit", "chain", "--policy", px.policy, "--trusted-root", px.root, "--repo", "solo"},
			"owner/repo",
		},
		{
			"policy missing",
			[]string{"emit", "chain", "--repo", "acme/widget", "--trusted-root", px.root},
			"--policy is required",
		},
		{
			"trusted root missing",
			[]string{"emit", "chain", "--repo", "acme/widget", "--policy", px.policy},
			"--trusted-root is required",
		},
		{
			"git dir missing",
			[]string{"emit", "chain", "--repo", "acme/widget", "--policy", px.policy, "--trusted-root", px.root},
			"--git-dir is required",
		},
		{
			"claims missing",
			[]string{
				"emit", "chain", "--repo", "acme/widget",
				"--policy", px.policy, "--trusted-root", px.root, "--git-dir", "x",
			},
			"--claims is required",
		},
		{
			"claims unreadable",
			[]string{
				"emit", "chain", "--repo", "acme/widget",
				"--policy", px.policy, "--trusted-root", px.root, "--git-dir", "x",
				"--claims", "/nonexistent",
			},
			"nonexistent",
		},
		{
			"claims malformed",
			[]string{
				"emit", "chain", "--repo", "acme/widget",
				"--policy", px.policy, "--trusted-root", px.root, "--git-dir", "x",
				"--claims", px.policy,
			},
			"claims payload",
		},
		{
			"subjects missing",
			[]string{"emit", "vsa", "--repo", "acme/widget", "--policy", px.policy, "--trusted-root", px.root},
			"--subjects is required",
		},
		{
			"sboms missing",
			[]string{
				"emit", "vsa", "--repo", "acme/widget",
				"--policy", px.policy, "--trusted-root", px.root, "--subjects", px.subjects,
			},
			"--sboms is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := Run(tt.args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("Run = %d, want %d (stderr: %s)", code, exitUsage, stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr = %q, want it to name %q", stderr.String(), tt.want)
			}
		})
	}
}

func TestEmitOutputFailures(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})

	g := &fakeEmitGit{notes: map[string][]byte{}}
	swapEmit(t, g, nil)

	px, claims := emitFiles(t)

	t.Run("dead stdout during a passing run", func(t *testing.T) {
		var stderr bytes.Buffer

		if code := Run(chainArgs(px, claims), failWriterI{}, &stderr); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})

	t.Run("dead stderr on a usage error", func(t *testing.T) {
		if code := Run([]string{"emit"}, failWriterI{}, failWriterI{}); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}

		if code := Run([]string{"emit", "conjure"}, failWriterI{}, failWriterI{}); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})
}

// TestCosignSigner proves the exec seam against a stub cosign on
// PATH: the success path (bundle read back) and the failure path
// (non-zero exit surfaces cosign's own words).
func TestCosignSigner(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "cosign")

	const script = `#!/bin/sh
# args: sign-blob --yes --bundle <bundle> <payload>
if [ "$STUB_FAIL" = "1" ]; then echo "no ambient identity" >&2; exit 1; fi
printf '{"stub":"bundle"}' > "$4"
`

	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil { //nolint:gosec // an executable test stub
		t.Fatal(err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	s := newSigner(t.TempDir())

	bundle, err := s.Sign([]byte(`{"the":"payload"}`))
	if err != nil {
		t.Fatalf("Sign = %v", err)
	}

	if string(bundle) != `{"stub":"bundle"}` {
		t.Errorf("Sign returned %q, want the bundle the tool wrote", bundle)
	}

	t.Setenv("STUB_FAIL", "1")

	if _, err := s.Sign([]byte(`{}`)); err == nil || !strings.Contains(err.Error(), "no ambient identity") {
		t.Errorf("Sign = %v, want cosign's own failure words", err)
	}
}

// TestEmitGitWrapper proves the currying seam over a real repository:
// fetch and push reach the named remote.
func TestEmitGitWrapper(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	run := func(args ...string) {
		t.Helper()

		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) //nolint:gosec,noctx // test-owned args
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e",
		)

		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}

	run("init", "-q", "-b", "main")
	run("commit", "-q", "--allow-empty", "-m", "one")
	run("notes", "add", "-m", "n", "HEAD")

	remote := t.TempDir()
	run2 := exec.Command("git", "-C", remote, "init", "-q", "--bare") //nolint:gosec,noctx // test-owned args
	if out, err := run2.CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v: %s", err, out)
	}

	run("remote", "add", "origin", remote)

	g, err := openEmitGit(dir, "refs/notes/commits", "origin", "")
	if err != nil {
		t.Fatalf("openEmitGit = %v", err)
	}

	if err := g.PushNotes(); err != nil {
		t.Errorf("PushNotes = %v", err)
	}

	if err := g.FetchNotes(); err != nil {
		t.Errorf("FetchNotes = %v", err)
	}

	if _, err := openEmitGit(t.TempDir(), "refs/notes/commits", "origin", ""); err == nil {
		t.Error("openEmitGit accepted a directory git does not recognise")
	}
}

func TestEmitVSAManifestRefusals(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})

	px := files(t)
	bad := filepath.Join(t.TempDir(), "bad.sha256")

	if err := os.WriteFile(bad, []byte("not a manifest line\n"), ownerRW); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name            string
		subjects, sboms string
		want            string
	}{
		{"subjects unreadable", "/nonexistent", px.subjects, "nonexistent"},
		{"subjects malformed", bad, px.subjects, "not a sha256sum record"},
		{"sboms unreadable", px.subjects, "/nonexistent", "nonexistent"},
		{"sboms malformed", px.subjects, bad, "not a sha256sum record"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := Run([]string{
				"emit", "vsa",
				"--policy", px.policy, "--trusted-root", px.root,
				"--repo", "acme/widget", "--tag", "v1.2.3",
				"--subjects", tt.subjects, "--sboms", tt.sboms,
				"--signer-digest", strings.Repeat("a", 40), "--canon-digest", strings.Repeat("b", 40),
			}, &stdout, &stderr)

			if code != exitUsage || !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("Run = %d, stderr %q — want %q", code, stderr.String(), tt.want)
			}
		})
	}
}

// TestCosignCheckRefusesWithoutBinary pins the preflight's tooling
// probe: no cosign on PATH is a named refusal, deterministically.
func TestCosignCheckRefusesWithoutBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	if err := (cosignSigner{}).Check(); err == nil {
		t.Fatal("Check passed with no cosign on PATH")
	}
}

// TestEmitGitPreflightAdapters drives the two preflight adapters over
// a real repository: the committer probe answers, and a repo with no
// notes ref refuses the push proof.
func TestEmitGitPreflightAdapters(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	for _, args := range [][]string{
		{"init", "-q"},
		{"-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "seed"},
	} {
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...) //nolint:gosec // test fixture
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}

	g, err := openEmitGit(dir, "refs/notes/commits", "origin", "")
	if err != nil {
		t.Fatalf("openEmitGit = %v", err)
	}

	if err := g.CommitterIdent(); err == nil {
		// A hermetic repo may lack identity; either answer exercises
		// the adapter — the assertion is on the push proof below.
		t.Log("committer identity present")
	}

	if err := g.DryRunPushNotes("0000000000000000000000000000000000000000"); err == nil {
		t.Fatal("a repository with no notes ref proved a push")
	}
}
