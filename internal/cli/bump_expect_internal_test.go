// `derive bump --check --expect / --manifest-dir` (stele#455): a stated
// version judged against one crate's manifest, with no history read.
// Real trees written per test, and no git repository anywhere: the
// history seam is armed to fail, so a run that reached for history
// would refuse.

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// crateTree writes files under a fresh directory and returns it.
func crateTree(t *testing.T, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	writeTree(t, dir, files)

	return dir
}

// workspace is a root whose members may state or inherit a version:
// the root carries 2.0.0, the inheriting member takes it, and the
// pinned member states its own.
func workspace(t *testing.T) string {
	t.Helper()

	return crateTree(t, map[string]string{
		"Cargo.toml":                 "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.package]\nversion = \"2.0.0\"\n",
		"crates/inherits/Cargo.toml": "[package]\nname = \"inherits\"\nversion.workspace = true\n",
		"crates/pinned/Cargo.toml":   "[package]\nname = \"pinned\"\nversion = \"0.7.1\"\n",
		"crates/nothing/Cargo.toml":  "[package]\nname = \"nothing\"\n",
		"crates/empty/README.md":     "no manifest here\n",
	})
}

// runExpect runs `derive bump` over dir with history armed to refuse:
// nothing on this path may read it.
func runExpect(t *testing.T, dir string, extra ...string) bumpRun {
	t.Helper()

	withHistory(t, nil, errors.New("history was read"))

	var outBuf, errBuf bytes.Buffer

	args := append([]string{"bump", "--git-dir", dir}, extra...)
	code := deriveCmd(args, &outBuf, &errBuf)

	return bumpRun{code: code, stdout: outBuf.String(), stderr: errBuf.String()}
}

// TestBumpCheckAgainstAStatedVersion is the test stele#455 names: a
// member stating its own version that differs from --expect is refused
// by name, and the same member with the matching version passes — with
// no git repository present. Before this change --expect was an
// unknown flag.
func TestBumpCheckAgainstAStatedVersion(t *testing.T) {
	dir := workspace(t)

	refused := runExpect(t, dir, "--check", "--expect", "0.7.2", "--manifest-dir", "crates/pinned")
	named := `manifest: mirrors do not carry "0.7.2": crates/pinned/Cargo.toml package.version = "0.7.1"`
	if refused.code != exitRefused || !strings.Contains(refused.stderr, named) {
		t.Fatalf("a disagreeing member: code %d\nstderr: %s", refused.code, refused.stderr)
	}

	passed := runExpect(t, dir, "--check", "--expect", "0.7.1", "--manifest-dir", "crates/pinned")
	if passed.code != exitOK || !strings.Contains(passed.stdout, "check=ok") {
		t.Fatalf("an agreeing member: code %d\nstdout: %s\nstderr: %s", passed.code, passed.stdout, passed.stderr)
	}
}

// TestBumpCheckExpectRows: every other row, messages asserted.
func TestBumpCheckExpectRows(t *testing.T) {
	for _, tt := range []struct {
		name string
		dir  func(t *testing.T) string
		args []string
		code int
		says string
	}{
		{
			name: "a member inheriting from the workspace, agreeing",
			dir:  workspace,
			args: []string{"--expect", "2.0.0", "--manifest-dir", "crates/inherits"},
			code: exitOK,
			says: "every judged mirror carries 2.0.0",
		},
		{
			name: "a member inheriting from the workspace, disagreeing",
			dir:  workspace,
			args: []string{"--expect", "2.0.1", "--manifest-dir", "crates/inherits"},
			code: exitRefused,
			says: `Cargo.toml workspace.package.version, inherited by crates/inherits/Cargo.toml = "2.0.0"`,
		},
		{
			name: "a manifest directory with no manifest",
			dir:  workspace,
			args: []string{"--expect", "2.0.0", "--manifest-dir", "crates/empty"},
			code: exitRefused,
			says: "no Cargo.toml at crates/empty — the package to judge is not there",
		},
		{
			name: "a member stating no version at all",
			dir:  workspace,
			args: []string{"--expect", "2.0.0", "--manifest-dir", "crates/nothing"},
			code: exitRefused,
			says: "crates/nothing/Cargo.toml states neither package.version nor version.workspace = true",
		},
		{
			name: "a manifest directory outside the tree",
			dir:  workspace,
			args: []string{"--expect", "2.0.0", "--manifest-dir", "../elsewhere"},
			code: exitRefused,
			says: "../elsewhere is outside the tree",
		},
		{
			name: "--expect that is not a version",
			dir:  workspace,
			args: []string{"--expect", "v2.0.0"},
			code: exitUsage,
			says: `--expect "v2.0.0" is not a version (MAJOR.MINOR.PATCH, no prefix)`,
		},
		{
			name: "--expect without --check",
			dir:  workspace,
			args: []string{"--expect", "2.0.0"},
			code: exitUsage,
			says: "--expect and --manifest-dir judge, so they need --check",
		},
		{
			name: "the root's mirrors against --expect, agreeing",
			dir:  func(t *testing.T) string { t.Helper(); return bumpTree(t, "1.4.0") },
			args: []string{"--expect", "1.4.0"},
			code: exitOK,
			says: "every judged mirror carries 1.4.0",
		},
		{
			name: "the root's mirrors against --expect, disagreeing",
			dir:  func(t *testing.T) string { t.Helper(); return bumpTree(t, "1.4.0") },
			args: []string{"--expect", "1.5.0"},
			code: exitRefused,
			says: `mirrors do not carry "1.5.0": Cargo.toml package.version = "1.4.0"`,
		},
		{
			name: "--expect over a tree stating no version",
			dir:  func(t *testing.T) string { t.Helper(); return t.TempDir() },
			args: []string{"--expect", "1.0.0"},
			code: exitRefused,
			says: "--expect 1.0.0, but nothing in this tree states a version to hold it against",
		},
		{
			// The root's mirrors still agree with each other, whatever
			// member is judged.
			name: "a root whose mirrors disagree",
			dir: func(t *testing.T) string {
				t.Helper()

				return crateTree(t, map[string]string{
					"Cargo.toml": "[workspace.package]\nversion = \"2.0.0\"\n\n[workspace.dependencies]\n" +
						"core = { path = \"crates/core\", version = \"1.9.0\" }\n",
					"crates/pinned/Cargo.toml": "[package]\nname = \"pinned\"\nversion = \"0.7.1\"\n",
				})
			},
			args: []string{"--expect", "0.7.1", "--manifest-dir", "crates/pinned"},
			code: exitRefused,
			says: "manifest: mirrors disagree",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			if !strings.Contains(tt.name, "without --check") {
				args = append([]string{"--check"}, args...)
			}

			r := runExpect(t, tt.dir(t), args...)
			if r.code != tt.code {
				t.Fatalf("code = %d, want %d\nstdout: %s\nstderr: %s", r.code, tt.code, r.stdout, r.stderr)
			}

			if !strings.Contains(r.stdout+r.stderr, tt.says) {
				t.Errorf("output does not say %q\nstdout: %s\nstderr: %s", tt.says, r.stdout, r.stderr)
			}
		})
	}
}

// TestBumpCheckManifestDirWithHistory: --manifest-dir alone judges the
// member against the last release, as today's check judges the root.
func TestBumpCheckManifestDirWithHistory(t *testing.T) {
	// The root's own version is not the one judged: it is held only to
	// agree with the root's other mirrors, never with the release.
	dir := crateTree(t, map[string]string{
		"Cargo.toml":               "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.package]\nversion = \"5.0.0\"\n",
		"crates/pinned/Cargo.toml": "[package]\nname = \"pinned\"\nversion = \"0.9.0\"\n",
	})

	r := runBump(t, dir, bumpHistory(), "--check", "--manifest-dir", "crates/pinned")
	if r.code != exitOK || !strings.Contains(r.stdout, "check=ok") {
		t.Fatalf("code %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}

	r = runBump(t, crateTree(t, map[string]string{
		"crates/pinned/Cargo.toml": "[package]\nname = \"pinned\"\nversion = \"0.3.0\"\n",
	}), bumpHistory(), "--check", "--manifest-dir", "crates/pinned")
	if r.code != exitRefused || !strings.Contains(r.stderr, `crates/pinned/Cargo.toml package.version = "0.3.0"`) {
		t.Fatalf("code %d\nstderr: %s", r.code, r.stderr)
	}
}
