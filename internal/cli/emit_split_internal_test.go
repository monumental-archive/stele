// Internal tests for the split chain emission (stele#390): `emit chain
// --no-append` signs and writes links without touching the ledger,
// `emit chain-append` judges and pushes them. Real git end to end —
// the ledger's bytes are git's, so only git can prove the two halves
// publish exactly what the one-piece emitter publishes. Only the
// signer, the bundle verifier and the clock are scripted, and the
// verifier binds every bundle to the digest it was signed over, so a
// tampered link is refused for real.

package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/emit"
	"github.com/monumental-archive/stele/internal/gitrepo"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

const (
	splitWorkflowRef = "acme/widget/.github/workflows/source-attest.yml@refs/heads/main"
	splitIdentity    = "https://github.com/" + splitWorkflowRef
	splitAuthor      = "source-attest <attest@example.test>"
	splitNotesRef    = "refs/notes/commits"
)

// digestBundle is what the scripted signer certifies: the identity and
// the digest of exactly the bytes it signed.
type digestBundle struct {
	SAN    string `json:"san"`
	Digest string `json:"digest"`
}

type digestSigner struct{}

func (digestSigner) Check() error { return nil }

func (digestSigner) Sign(payload []byte) ([]byte, error) {
	return jsonx.Marshal(digestBundle{SAN: splitIdentity, Digest: chain.SHA256Hex(payload)})
}

// digestBV accepts a bundle only for the identity and digest it
// names — what the real trust boundary enforces.
type digestBV struct{}

func (b digestBV) Blob(bundle []byte, id trust.Identity, sha string) (*trust.Verified, error) {
	db, err := jsonx.DecodeForeign[digestBundle](bundle)
	if err != nil {
		return nil, errors.New("unparsable bundle")
	}

	if db.SAN != id.SAN || db.Digest != sha {
		return nil, errors.New("bundle does not cover this statement")
	}

	return &trust.Verified{SAN: db.SAN}, nil
}

func (b digestBV) Attestation(bundle []byte, id trust.Identity, sha string) (*trust.Verified, error) {
	return b.Blob(bundle, id, sha)
}

func (digestBV) Peek([]byte) ([]byte, error) { return nil, errors.New("peek is never judged here") }

// LoggedAt answers one fixed instant: the scripted log observed every
// signing at the clock the scripted emitter runs on.
func (digestBV) LoggedAt(*trust.Verified) (time.Time, error) {
	return time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC), nil
}

// splitEnv is the environment for a git this file spawns: gitrepo's
// hermetic environment with every variable git itself names local to
// a repository removed (`git rev-parse --local-env-vars`) — a hook
// exports GIT_DIR and its companions in a linked worktree, and a
// fixture that inherited one would write to the wrong repository.
func splitEnv(t *testing.T) []string {
	t.Helper()

	//nolint:noctx // local probe, no cancellation surface
	out, err := exec.Command("git", "rev-parse", "--local-env-vars").Output()
	if err != nil {
		t.Fatalf("git rev-parse --local-env-vars: %v", err)
	}

	local := strings.Fields(string(out))

	return slices.DeleteFunc(gitrepo.Env(), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")

		return slices.Contains(local, name)
	})
}

// splitGit runs real git in dir under splitEnv.
func splitGit(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) //nolint:gosec,noctx // test-owned args
	cmd.Env = splitEnv(t)

	var out bytes.Buffer

	cmd.Stdout, cmd.Stderr = &out, &out

	if err := cmd.Run(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out.String())
	}

	return strings.TrimSpace(out.String())
}

// splitWorld is one source repository (seed, a working tree on main)
// and the bare remotes it publishes to.
type splitWorld struct {
	seed   string
	px     paths
	claims string
}

// newSplitWorld scripts the signer, the verifier and the clock, pins
// every git identity and date so identical histories have identical
// object names, and builds a seed with one commit.
func newSplitWorld(t *testing.T) *splitWorld {
	t.Helper()

	swap(t, digestBV{}, scriptedStore{})

	for k, v := range map[string]string{
		"GITHUB_WORKFLOW_REF": splitWorkflowRef,
		"GITHUB_TOKEN":        "",
		"GH_TOKEN":            "",
		"GIT_AUTHOR_NAME":     "t",
		"GIT_AUTHOR_EMAIL":    "t@example.com",
		"GIT_COMMITTER_NAME":  "t",
		"GIT_COMMITTER_EMAIL": "t@example.com",
		"GIT_AUTHOR_DATE":     "@1700000000 +0000",
		"GIT_COMMITTER_DATE":  "@1700000000 +0000",
	} {
		t.Setenv(k, v)
	}

	origSigner, origNow := newSigner, emitNow

	newSigner = func(string) emit.Signer { return digestSigner{} }
	emitNow = func() time.Time { return time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC) }

	t.Cleanup(func() { newSigner, emitNow = origSigner, origNow })

	px, claims := emitFiles(t)
	w := &splitWorld{seed: t.TempDir(), px: px, claims: claims}

	splitGit(t, w.seed, "init", "-q", "-b", "main")
	w.commit(t, "one")

	return w
}

// commit adds an empty commit to the seed and returns it.
func (w *splitWorld) commit(t *testing.T, msg string) string {
	t.Helper()

	splitGit(t, w.seed, "commit", "-q", "--allow-empty", "-m", msg)

	return splitGit(t, w.seed, "rev-parse", "HEAD")
}

// remote creates a bare remote carrying the seed's main.
func (w *splitWorld) remote(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	splitGit(t, dir, "init", "-q", "--bare", "-b", "main")
	w.publish(t, dir)

	return dir
}

// publish pushes the seed's main to a remote.
func (w *splitWorld) publish(t *testing.T, remote string) {
	t.Helper()

	splitGit(t, w.seed, "push", "-q", remote, "main")
}

// clone is a working clone of remote with its ledger fetched — the
// --git-dir a caller's own job would hold.
func clone(t *testing.T, remote string) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "clone")
	splitGit(t, filepath.Dir(dir), "clone", "-q", "-b", "main", remote, dir)
	splitGit(t, dir, "fetch", "-q", "origin", "+"+splitNotesRef+":"+splitNotesRef)

	return dir
}

// ledger is the remote's notes ref, or "" when the chain is unfounded.
func ledger(t *testing.T, repo string) string {
	t.Helper()

	return splitGit(t, repo, "for-each-ref", "--format=%(objectname)", splitNotesRef)
}

// cloneFlags names a remote the engine clones itself.
func cloneFlags(remote string) []string {
	return []string{"--clone", remote, "--committer", splitAuthor}
}

// chainRun is `emit chain` against where, for rev, plus extra.
//
//nolint:gocritic // unnamedResult: the exit code and stderr, the pair every Run test reads
func (w *splitWorld) chainRun(where []string, rev string, extra ...string) (int, string) {
	args := append([]string{
		"emit", "chain",
		"--policy", w.px.policy, "--trusted-root", w.px.root,
		"--repo", "acme/widget",
		"--ref", "refs/heads/main",
		"--rev", rev, "--claims", w.claims,
		"--actor", "octocat", "--actor-id", "583231",
		"--machinery-digest", strings.Repeat("b", 40),
		"--policy-uri", "https://github.com/acme/canon/blob/x/slsa/verify-policy.json",
	}, where...)

	var stdout, stderr bytes.Buffer

	code := Run(append(args, extra...), &stdout, &stderr)

	return code, stderr.String()
}

// mustChain runs `emit chain` and requires it to pass.
func (w *splitWorld) mustChain(t *testing.T, where []string, rev string, extra ...string) {
	t.Helper()

	if code, stderr := w.chainRun(where, rev, extra...); code != exitOK {
		t.Fatalf("emit chain %v = %d: %s", extra, code, stderr)
	}
}

// sign runs the signing half and returns the directory it wrote.
func (w *splitWorld) sign(t *testing.T, where []string, rev string, extra ...string) string {
	t.Helper()

	out := filepath.Join(t.TempDir(), "links")
	w.mustChain(t, where, rev, append([]string{"--no-append", "--out", out}, extra...)...)

	return out
}

// appendRun is `emit chain-append` against where for the links in dir.
//
//nolint:gocritic // unnamedResult: the exit code and stderr, the pair every Run test reads
func (w *splitWorld) appendRun(where []string, dir string) (int, string) {
	args := append([]string{
		"emit", "chain-append",
		"--policy", w.px.policy, "--trusted-root", w.px.root,
		"--repo", "acme/widget", "--ref", "refs/heads/main",
		"--links", dir,
	}, where...)

	var stdout, stderr bytes.Buffer

	code := Run(args, &stdout, &stderr)

	return code, stderr.String()
}

// walk proves the remote's chain the way `stele verify chain` does.
func (w *splitWorld) walk(t *testing.T, remote string) {
	t.Helper()

	p, err := policy.Load(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}

	r, err := gitrepo.Open(clone(t, remote), *p.Source.NotesRef)
	if err != nil {
		t.Fatal(err)
	}

	coords := verify.Coords{Owner: "acme", Repo: "widget"}
	if _, err := verify.Chain(p, coords, "refs/heads/main", r, digestBV{}, func(string, ...any) {}); err != nil {
		t.Fatalf("verify.Chain over the published ledger = %v", err)
	}
}

// linkNames lists the files a signing half wrote.
func linkNames(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}

	return names
}

// TestEmitChainNoAppendLeavesTheLedger: the signing half reads the
// ledger, writes the links it would have appended — a heal and the
// pushed revision, in order — and leaves every notes ref, local and
// remote, exactly as it found it, with no scratch ref behind. The
// links it wrote are ones verify accepts once appended.
func TestEmitChainNoAppendLeavesTheLedger(t *testing.T) {
	w := newSplitWorld(t)
	remote := w.remote(t)

	w.mustChain(t, cloneFlags(remote), splitGit(t, w.seed, "rev-parse", "HEAD"), "--genesis")

	two := w.commit(t, "two")
	three := w.commit(t, "three")
	w.publish(t, remote)

	local := clone(t, remote)
	localRefs := splitGit(t, local, "for-each-ref", "refs/notes/")
	remoteLedger := ledger(t, remote)

	links := w.sign(t, []string{"--git-dir", local}, three)

	if got := splitGit(t, local, "for-each-ref", "refs/notes/"); got != localRefs {
		t.Fatalf("the signing half moved the local notes refs:\nbefore %s\nafter  %s", localRefs, got)
	}

	if got := ledger(t, remote); got != remoteLedger {
		t.Fatal("the signing half moved the remote ledger")
	}

	want := []string{"0001-" + two + ".json", "0002-" + three + ".json"}
	if got := linkNames(t, links); !slices.Equal(got, want) {
		t.Fatalf("links written = %v, want %v", got, want)
	}

	if code, stderr := w.appendRun([]string{"--git-dir", local}, links); code != exitOK {
		t.Fatalf("emit chain-append = %d: %s", code, stderr)
	}

	w.walk(t, remote)
}

// TestEmitChainSplitMatchesOnePiece: on two identical repositories,
// `emit chain` in one piece and the two halves in order publish the
// same notes ref, byte for byte — commit, tree and every note.
func TestEmitChainSplitMatchesOnePiece(t *testing.T) {
	w := newSplitWorld(t)
	one := splitGit(t, w.seed, "rev-parse", "HEAD")
	whole, split := w.remote(t), w.remote(t)

	w.mustChain(t, cloneFlags(whole), one, "--genesis")
	splitGit(t, split, "fetch", "-q", whole, splitNotesRef+":"+splitNotesRef)

	if ledger(t, whole) != ledger(t, split) {
		t.Fatal("the two repositories do not start identical")
	}

	w.commit(t, "two")
	three := w.commit(t, "three")
	w.publish(t, whole)
	w.publish(t, split)

	w.mustChain(t, cloneFlags(whole), three)

	links := w.sign(t, cloneFlags(split), three)
	if code, stderr := w.appendRun(cloneFlags(split), links); code != exitOK {
		t.Fatalf("emit chain-append = %d: %s", code, stderr)
	}

	if got, want := ledger(t, split), ledger(t, whole); got != want {
		t.Fatalf("the halves published notes ref %s, the one-piece emitter %s:\n%s\n---\n%s", got, want,
			splitGit(t, split, "log", "--format=%H %T %cI %cn", splitNotesRef),
			splitGit(t, whole, "log", "--format=%H %T %cI %cn", splitNotesRef))
	}

	w.walk(t, split)
}

// TestEmitChainSplitGenesis: genesis works through both halves, and
// the append half refuses to found a chain that already has a link —
// two founding links signed against the same empty ledger, the second
// appended after the first.
func TestEmitChainSplitGenesis(t *testing.T) {
	w := newSplitWorld(t)
	one := splitGit(t, w.seed, "rev-parse", "HEAD")
	two := w.commit(t, "two")
	remote := w.remote(t)

	first := w.sign(t, cloneFlags(remote), one, "--genesis")
	second := w.sign(t, cloneFlags(remote), two, "--genesis")

	if ledger(t, remote) != "" {
		t.Fatal("the signing half founded the remote ledger")
	}

	if code, stderr := w.appendRun(cloneFlags(remote), first); code != exitOK {
		t.Fatalf("emit chain-append of the founding link = %d: %s", code, stderr)
	}

	w.walk(t, remote)

	founded := ledger(t, remote)

	code, stderr := w.appendRun(cloneFlags(remote), second)
	if code != exitRefused || !strings.Contains(stderr, "genesis refused — a chain link already exists on this history") {
		t.Fatalf("second founding = %d: %s; want the genesis refusal", code, stderr)
	}

	if ledger(t, remote) != founded {
		t.Fatal("a refused founding moved the remote ledger")
	}
}

// tamperLink rewrites a link file's provenance bundle to cover other
// bytes — a link edited after it was signed.
func tamperLink(t *testing.T, dir string) {
	t.Helper()

	names := linkNames(t, dir)
	path := filepath.Join(dir, names[0])

	raw, err := os.ReadFile(path) //nolint:gosec // G304: a test-owned path
	if err != nil {
		t.Fatal(err)
	}

	link, err := jsonx.DecodeBytes[chain.Note](raw)
	if err != nil {
		t.Fatal(err)
	}

	link.Provenance.Bundle, err = jsonx.Marshal(digestBundle{SAN: splitIdentity, Digest: strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}

	out, err := jsonx.Marshal(link)
	if err != nil {
		t.Fatal(err)
	}

	//nolint:gosec // G703: a path under the test's own temp directory
	if err := os.WriteFile(path, append(out, '\n'), ownerRW); err != nil {
		t.Fatal(err)
	}
}

// TestEmitChainAppendRefusals: a tampered link, a ledger that moved
// before the append read it, and a ledger that moved between the
// append's read and its push — each refused by name, and the remote
// ledger is exactly what it was before the append ran.
func TestEmitChainAppendRefusals(t *testing.T) {
	for _, tt := range []struct {
		name string
		// arrange signs, perhaps disturbs the world, and returns the
		// links and where the append half runs.
		arrange func(t *testing.T, w *splitWorld, remote, two string) (string, []string)
		want    string
	}{
		{
			name: "a tampered link file",
			arrange: func(t *testing.T, w *splitWorld, remote, two string) (string, []string) {
				t.Helper()

				links := w.sign(t, cloneFlags(remote), two)
				tamperLink(t, links)

				return links, cloneFlags(remote)
			},
			want: "the link file for %s is refused — the chain it would extend does not verify",
		},
		{
			name: "the ledger moved before the append read it",
			arrange: func(t *testing.T, w *splitWorld, remote, two string) (string, []string) {
				t.Helper()

				links := w.sign(t, cloneFlags(remote), two)
				w.mustChain(t, cloneFlags(remote), two)

				return links, cloneFlags(remote)
			},
			want: "the ledger moved under this run — %s already carries a link; re-run the signing job",
		},
		{
			name: "the ledger moved between the append's read and its push",
			arrange: func(t *testing.T, w *splitWorld, remote, two string) (string, []string) {
				t.Helper()

				local := clone(t, remote)
				links := w.sign(t, []string{"--git-dir", local}, two)

				// A competing run an hour later: with the clock pinned
				// it would publish byte-identical notes, and a push of
				// the same ledger is no race at all.
				emitNow = func() time.Time { return time.Date(2026, 8, 19, 13, 0, 0, 0, time.UTC) }
				w.mustChain(t, cloneFlags(remote), two)

				return links, []string{"--git-dir", local}
			},
			want: "notes push rejected — the ledger moved under this run; re-run it from the signing job",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := newSplitWorld(t)
			remote := w.remote(t)
			w.mustChain(t, cloneFlags(remote), splitGit(t, w.seed, "rev-parse", "HEAD"), "--genesis")

			two := w.commit(t, "two")
			w.publish(t, remote)

			links, where := tt.arrange(t, w, remote, two)
			before := ledger(t, remote)

			code, stderr := w.appendRun(where, links)

			want := strings.Replace(tt.want, "%s", two, 1)

			if code != exitRefused || !strings.Contains(stderr, want) {
				t.Fatalf("emit chain-append = %d: %s; want it to name %q", code, stderr, want)
			}

			if ledger(t, remote) != before {
				t.Fatal("a refused append moved the remote ledger")
			}
		})
	}
}

// TestEmitChainSplitUsageRefusals: the flag contradictions of both
// halves, each refused by name before anything opens the repository.
func TestEmitChainSplitUsageRefusals(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})

	px, claims := emitFiles(t)
	nonEmpty := t.TempDir()

	if err := os.WriteFile(filepath.Join(nonEmpty, "stray"), nil, ownerRW); err != nil {
		t.Fatal(err)
	}

	chainCmd := func(extra ...string) []string {
		return append([]string{
			"emit", "chain", "--repo", "acme/widget",
			"--policy", px.policy, "--trusted-root", px.root, "--git-dir", "x", "--claims", claims,
		}, extra...)
	}

	appendArgs := func(extra ...string) []string {
		return append([]string{
			"emit", "chain-append", "--repo", "acme/widget", "--policy", px.policy, "--trusted-root", px.root,
		}, extra...)
	}

	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"no-append without out", chainCmd("--no-append"), "--no-append needs --out"},
		{"out without no-append", chainCmd("--out", t.TempDir()), "--out is the --no-append hand-off"},
		{"append: no repository", appendArgs("--links", t.TempDir()), "--git-dir is required without --clone"},
		{
			"append: git-dir alongside clone",
			appendArgs("--git-dir", "x", "--clone", "https://example.test/acme/widget.git"),
			"--git-dir cannot accompany --clone",
		},
		{"append: links missing", appendArgs("--git-dir", "x"), "--links is required"},
		{
			"append: links directory absent",
			appendArgs("--git-dir", "x", "--links", filepath.Join(t.TempDir(), "absent")),
			"link directory",
		},
		{
			"append: a stray file among the links",
			appendArgs("--git-dir", "x", "--links", nonEmpty),
			"stray in the link directory is not a link file",
		},
		{
			"append: takes no machinery digest",
			appendArgs("--git-dir", "x", "--links", t.TempDir(), "--machinery-digest", strings.Repeat("b", 40)),
			"flag provided but not defined: -machinery-digest",
		},
	} {
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

// stagingGit is the scripted git with a staging seam whose every step
// can be made to fail.
type stagingGit struct {
	*fakeEmitGit

	stageErr, releaseErr, noteErr error
	staged                        bool
}

func (g *stagingGit) StageNotes() (func() error, error) {
	if g.stageErr != nil {
		return nil, g.stageErr
	}

	g.staged = true

	return func() error {
		g.staged = false

		return g.releaseErr
	}, nil
}

func (g *stagingGit) Note(rev string) ([]byte, error) {
	if g.noteErr != nil && len(g.notes) > 0 {
		return nil, g.noteErr
	}

	return g.fakeEmitGit.Note(rev)
}

// onlyEmitGit hides every method beyond emit.Git — a repository the
// append half cannot list.
type onlyEmitGit struct{ emit.Git }

// TestEmitChainSplitRefusals: every guard branch of the CLI's two
// halves that the real-git tests cannot reach — each asserting its
// message and its exit code.
func TestEmitChainSplitRefusals(t *testing.T) {
	px, claims := emitFiles(t)

	signArgs := func(out string) []string {
		return append(chainArgs(px, claims), "--no-append", "--out", out)
	}

	for _, tt := range []struct {
		name string
		g    emit.Git
		args func(t *testing.T) []string
		want string
	}{
		{
			name: "a repository with no staging seam",
			g:    &fakeEmitGit{notes: map[string][]byte{}},
			args: func(t *testing.T) []string {
				t.Helper()

				return signArgs(t.TempDir())
			},
			want: "this repository cannot stage a ledger",
		},
		{
			name: "staging fails",
			g:    &stagingGit{fakeEmitGit: &fakeEmitGit{notes: map[string][]byte{}}, stageErr: errors.New("refs locked")},
			args: func(t *testing.T) []string {
				t.Helper()

				return signArgs(t.TempDir())
			},
			want: "refs locked",
		},
		{
			name: "the signing half refuses",
			g:    &stagingGit{fakeEmitGit: &fakeEmitGit{notes: map[string][]byte{emitRev: emitLink(t)}}},
			args: func(t *testing.T) []string {
				t.Helper()

				return signArgs(t.TempDir())
			},
			want: "genesis refused",
		},
		{
			name: "a staged note cannot be read back",
			g: &stagingGit{
				fakeEmitGit: &fakeEmitGit{notes: map[string][]byte{}}, noteErr: errors.New("object store torn"),
			},
			args: func(t *testing.T) []string {
				t.Helper()

				return signArgs(t.TempDir())
			},
			want: "object store torn",
		},
		{
			name: "the links cannot be written",
			g:    &stagingGit{fakeEmitGit: &fakeEmitGit{notes: map[string][]byte{}}},
			args: func(t *testing.T) []string {
				t.Helper()

				out := t.TempDir()
				if err := os.WriteFile(filepath.Join(out, "stray"), nil, ownerRW); err != nil {
					t.Fatal(err)
				}

				return signArgs(out)
			},
			want: "is not empty",
		},
		{
			name: "the staging cannot be released",
			g: &stagingGit{
				fakeEmitGit: &fakeEmitGit{notes: map[string][]byte{}}, releaseErr: errors.New("scratch ref stuck"),
			},
			args: func(t *testing.T) []string {
				t.Helper()

				return signArgs(t.TempDir())
			},
			want: "scratch ref stuck",
		},
		{
			name: "the append half's repository cannot be opened",
			args: func(t *testing.T) []string {
				t.Helper()

				return []string{
					"emit", "chain-append", "--repo", "acme/widget", "--policy", px.policy, "--trusted-root", px.root,
					"--clone", "https://example.test/acme/widget.git", "--committer", "nobody", "--links", t.TempDir(),
				}
			},
			want: "is not `Name <email>`",
		},
		{
			name: "the append half's repository cannot list its ledger",
			g:    onlyEmitGit{&fakeEmitGit{notes: map[string][]byte{}}},
			args: func(t *testing.T) []string {
				t.Helper()

				return []string{
					"emit", "chain-append", "--repo", "acme/widget", "--policy", px.policy, "--trusted-root", px.root,
					"--git-dir", "x", "--links", t.TempDir(),
				}
			},
			want: "this repository cannot list its ledger",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			swap(t, scriptedBV{}, scriptedStore{})
			swapEmit(t, tt.g, nil)

			var stdout, stderr bytes.Buffer

			if code := Run(tt.args(t), &stdout, &stderr); code != exitRefused {
				t.Fatalf("Run = %d, want %d (stderr: %s)", code, exitRefused, stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr = %q, want it to name %q", stderr.String(), tt.want)
			}

			if sg, ok := tt.g.(*stagingGit); ok && sg.staged {
				t.Error("the staging was left in place")
			}
		})
	}
}

// TestEmitChainAppendStagingDirectory: the append half, like the
// one-piece emitter, refuses before anything when it cannot make its
// staging directory.
func TestEmitChainAppendStagingDirectory(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})

	px, _ := emitFiles(t)
	links := t.TempDir()

	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"emit", "chain-append", "--repo", "acme/widget", "--policy", px.policy, "--trusted-root", px.root,
		"--git-dir", "x", "--links", links,
	}, &stdout, &stderr)
	if code != exitRefused || !strings.Contains(stderr.String(), "staging directory") {
		t.Fatalf("Run = %d, stderr %q; want the staging-directory refusal", code, stderr.String())
	}
}

// emitLink is a genesis link the scripted engine emits — a note that
// decodes as a link, so a second founding on it is refused.
func emitLink(t *testing.T) []byte {
	t.Helper()

	swap(t, scriptedBV{}, scriptedStore{})

	g := &fakeEmitGit{notes: map[string][]byte{}}
	swapEmit(t, g, nil)

	px, claims := emitFiles(t)

	var stdout, stderr bytes.Buffer

	if code := Run(chainArgs(px, claims), &stdout, &stderr); code != exitOK {
		t.Fatalf("founding the fixture link = %d: %s", code, stderr.String())
	}

	return g.notes[emitRev]
}
