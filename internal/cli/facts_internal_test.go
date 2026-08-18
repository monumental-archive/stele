// `derive facts` at the command surface: the archetype guards, the
// licence precedence and its fallback, and the one property the bash
// got wrong often enough to comment on — that the instant comes from
// the RELEASED checkout rather than wherever the process happens to
// be standing.

package cli

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
)

// factsStub answers the two reads the facts resolver makes.
type factsStub struct {
	tip     string
	tipErr  error
	stamp   string
	timeErr error
	asked   []string
}

func (s *factsStub) Tip(ref string) (string, error) {
	s.asked = append(s.asked, "tip:"+ref)

	return s.tip, s.tipErr
}

func (s *factsStub) CommitTime(rev string) (string, error) {
	s.asked = append(s.asked, "time:"+rev)

	return s.stamp, s.timeErr
}

// withFactsHistory swaps the released-checkout seam and records which
// directory was opened.
func withFactsHistory(t *testing.T, h *factsStub, openErr error) *string {
	t.Helper()

	opened := new(string)
	previous := openFactsGit

	openFactsGit = func(dir string) (factsHistory, error) {
		*opened = dir

		if openErr != nil {
			return nil, openErr
		}

		return h, nil
	}

	t.Cleanup(func() { openFactsGit = previous })

	return opened
}

const forge = "https://github.com"

const factsRev = "aaaabbbbccccddddeeeeffff0000111122223333"

func goodFactsStub() *factsStub {
	return &factsStub{tip: factsRev, stamp: "2026-08-18T09:30:00+01:00"}
}

// withMeta points the metadata seam at a local server. Without it a
// test that supplies no --description reaches the real forge, which
// is both slow and a test whose result depends on a token.
func withMeta(t *testing.T, licence, description string) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/widget/license", func(w http.ResponseWriter, _ *http.Request) {
		if licence == "" {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		if _, err := w.Write([]byte(`{"license": {"spdx_id": "` + licence + `"}}`)); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("/repos/acme/widget", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`{"description": "` + description + `"}`)); err != nil {
			t.Error(err)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	previous := newMetaClient
	newMetaClient = func() *gh.Client {
		return &gh.Client{Base: srv.URL, Download: srv.URL, HTTP: srv.Client()}
	}

	t.Cleanup(func() { newMetaClient = previous })
}

// cargoTree writes a Cargo.toml declaring the given fields.
func cargoTree(t *testing.T, body string) string {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return dir
}

func TestDeriveFactsUsage(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no archetype", []string{
			"facts", "--repo", "acme/widget", "--server-url", forge, "--git-dir", ".",
		}},
		{"an archetype outside the vocabulary", []string{
			"facts", "--archetype", "rolling", "--repo", "acme/widget",
			"--server-url", forge, "--git-dir", ".",
		}},
		{"versioned with no version", []string{
			"facts", "--archetype", "versioned", "--repo", "acme/widget",
			"--server-url", forge, "--git-dir", ".",
		}},
		{"continuous carrying a version", []string{
			"facts", "--archetype", "continuous", "--version", "1.0.0", "--repo", "acme/widget",
			"--server-url", forge, "--git-dir", ".",
		}},
		{"no repo", []string{"facts", "--archetype", "continuous", "--git-dir", "."}},
		{"a repo that is not owner/name", []string{
			"facts", "--archetype", "continuous", "--repo", "widget", "--git-dir", ".",
		}},
		{"no released checkout", []string{"facts", "--archetype", "continuous", "--repo", "acme/widget"}},
		{"unknown flag", []string{"facts", "--nope"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if got := deriveCmd(tc.args, &stdout, &stderr); got != exitUsage {
				t.Errorf("deriveCmd(%v) = %d, want %d (stderr: %s)", tc.args, got, exitUsage, stderr.String())
			}
		})
	}
}

// The whole fact set, from a manifest-declaring tree. No forge read
// happens on this path, which is why no metadata seam is swapped.
func TestDeriveFactsFromTheManifest(t *testing.T) {
	history := goodFactsStub()
	opened := withFactsHistory(t, history, nil)
	withMeta(t, "", "")

	tree := cargoTree(t, `[workspace.package]
license = "Apache-2.0"
repository = "https://github.com/acme/widget"
`)

	var stdout, stderr bytes.Buffer

	args := []string{
		"facts", "--archetype", "versioned", "--version", "1.2.3",
		"--repo", "acme/widget",
		"--server-url", forge, "--git-dir", tree, "--description", "a widget",
	}
	if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	out := stdout.String()

	for _, want := range []string{
		`"org.opencontainers.image.source":"https://github.com/acme/widget"`,
		`"org.opencontainers.image.revision":"` + factsRev + `"`,
		`"org.opencontainers.image.version":"1.2.3"`,
		`"org.opencontainers.image.licenses":"Apache-2.0"`,
		`"org.opencontainers.image.title":"widget"`,
		`"org.opencontainers.image.description":"a widget"`,
		// 09:30+01:00 is 08:30Z. The annotation is normalised, so the
		// committer's own offset never dates the release differently
		// from the rest of the world.
		`"org.opencontainers.image.created":"2026-08-18T08:30:00Z"`,
		"epoch=1787041800",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %s:\n%s", want, out)
		}
	}

	// The instant is read from the checkout the caller NAMED, and from
	// the resolved revision rather than the caller's ref — the two
	// facts describe one commit by construction.
	if *opened != tree {
		t.Errorf("opened %q, want the named checkout %q", *opened, tree)
	}

	if strings.Join(history.asked, ",") != "tip:HEAD,time:"+factsRev {
		t.Errorf("history reads = %v, want the tip then that revision's time", history.asked)
	}
}

// A continuous release renders no version key at all.
func TestDeriveFactsContinuous(t *testing.T) {
	withFactsHistory(t, goodFactsStub(), nil)
	withMeta(t, "", "")

	tree := cargoTree(t, "[package]\nlicense = \"MIT\"\n")

	var stdout, stderr bytes.Buffer

	args := []string{
		"facts", "--archetype", "continuous", "--repo", "acme/widget",
		"--server-url", forge, "--git-dir", tree,
	}
	if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	if strings.Contains(stdout.String(), "image.version") {
		t.Fatalf("a continuous release rendered a version:\n%s", stdout.String())
	}
}

// [workspace.package] wins over [package] — Cargo's own inheritance
// order, so a member resolving `license.workspace = true` gets the
// same answer stele does.
func TestDeriveFactsLicencePrecedence(t *testing.T) {
	withFactsHistory(t, goodFactsStub(), nil)
	withMeta(t, "", "")

	tree := cargoTree(t, `[package]
license = "MIT"

[workspace.package]
license = "Apache-2.0"
`)

	var stdout, stderr bytes.Buffer

	args := []string{
		"facts", "--archetype", "continuous", "--repo", "acme/widget",
		"--server-url", forge, "--git-dir", tree,
	}
	if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	if !strings.Contains(stdout.String(), `"Apache-2.0"`) {
		t.Fatalf("the workspace declaration lost to the package one:\n%s", stdout.String())
	}
}

func TestDeriveFactsRefusals(t *testing.T) {
	tests := []struct {
		name    string
		history *factsStub
		openErr error
		tree    func(*testing.T) string
		want    string
	}{
		{
			name:    "a checkout that cannot be opened",
			history: goodFactsStub(),
			openErr: errors.New("not a repository"),
			want:    "not a repository",
		},
		{
			name:    "a ref that resolves to nothing",
			history: &factsStub{tipErr: errors.New("unknown revision")},
			want:    "unknown revision",
		},
		{
			name:    "a commit with no readable date",
			history: &factsStub{tip: factsRev, stamp: "the other day"},
			want:    "no usable commit date",
		},
		{
			name:    "a manifest declaring a licence that is not SPDX",
			history: goodFactsStub(),
			tree:    func(t *testing.T) string { t.Helper(); return cargoTree(t, "[package]\nlicense = \"MIT/X11\"\n") },
			want:    "not a valid SPDX expression",
		},
		{
			name:    "a manifest whose repository went stale after a transfer",
			history: goodFactsStub(),
			tree: func(t *testing.T) string {
				t.Helper()

				return cargoTree(t, "[package]\nlicense = \"MIT\"\nrepository = \"https://github.com/old/widget\"\n")
			},
			want: "update the repository field",
		},
		{
			name:    "a manifest that is not TOML",
			history: goodFactsStub(),
			tree:    func(t *testing.T) string { t.Helper(); return cargoTree(t, "this is = = not toml") },
			want:    "Cargo.toml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withFactsHistory(t, tt.history, tt.openErr)
			withMeta(t, "", "")

			dir := cargoTree(t, "[package]\nlicense = \"MIT\"\n")
			if tt.tree != nil {
				dir = tt.tree(t)
			}

			var stdout, stderr bytes.Buffer

			args := []string{
				"facts", "--archetype", "continuous", "--repo", "acme/widget",
				"--server-url", forge, "--git-dir", dir,
			}
			if got := deriveCmd(args, &stdout, &stderr); got != exitRefused {
				t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, exitRefused, stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("stderr = %q, want it to mention %q", stderr.String(), tt.want)
			}
		})
	}
}

// --tree separates the checkout that DATES the release from the one
// that DECLARES its licence. They are the same tree in every current
// caller, but the bash conflated them with cwd and stamped a canon
// commit's timestamp onto every extension image once.
func TestDeriveFactsSeparatesDateFromDeclaration(t *testing.T) {
	opened := withFactsHistory(t, goodFactsStub(), nil)
	withMeta(t, "", "")

	dated := t.TempDir()
	declaring := cargoTree(t, "[package]\nlicense = \"MIT\"\n")

	var stdout, stderr bytes.Buffer

	args := []string{
		"facts", "--archetype", "continuous", "--repo", "acme/widget",
		"--server-url", forge,
		"--git-dir", dated, "--tree", declaring,
	}
	if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	if *opened != dated {
		t.Errorf("dated the release from %q, want %q", *opened, dated)
	}

	if !strings.Contains(stdout.String(), `"MIT"`) {
		t.Errorf("did not read the licence from --tree:\n%s", stdout.String())
	}
}

// A tree with no manifest falls back to the forge's own detection.
// The two tiers are deliberately not cross-checked: the manifest is
// the author's declaration, the forge's is a heuristic reading of one
// file that flattens a disjunction to a single id, so a mismatch
// between them would mean nothing.
func TestDeriveFactsFallsBackToTheForge(t *testing.T) {
	withFactsHistory(t, goodFactsStub(), nil)
	withMeta(t, "Apache-2.0", "from the forge")

	var stdout, stderr bytes.Buffer

	// t.TempDir() has no Cargo.toml, which is the manifest-less shape.
	args := []string{
		"facts", "--archetype", "continuous", "--repo", "acme/widget",
		"--server-url", forge, "--git-dir", t.TempDir(),
	}
	if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	for _, want := range []string{`"org.opencontainers.image.licenses":"Apache-2.0"`, `"from the forge"`} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout lacks %s:\n%s", want, stdout.String())
		}
	}
}

// A tree declaring nothing, with a forge that detects nothing, has no
// derivable licence — refused rather than published empty.
func TestDeriveFactsNoDerivableLicence(t *testing.T) {
	withFactsHistory(t, goodFactsStub(), nil)
	withMeta(t, "", "")

	var stdout, stderr bytes.Buffer

	args := []string{
		"facts", "--archetype", "continuous", "--repo", "acme/widget",
		"--server-url", forge, "--git-dir", t.TempDir(),
	}
	if got := deriveCmd(args, &stdout, &stderr); got != exitRefused {
		t.Fatalf("deriveCmd = %d, want %d", got, exitRefused)
	}

	if !strings.Contains(stderr.String(), "no derivable licence") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
