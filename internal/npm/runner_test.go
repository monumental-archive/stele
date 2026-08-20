// The runner: the argv this package hands npm, and what it does with
// an answer that is not a tree.
//
// The package doc states two correctness claims about those flags, and
// the closure tests cannot reach either, because they start from
// recorded output. --package-lock-only is what makes the inventory
// describe the resolution the artifact was built from — the recorded
// one — rather than whatever node_modules the derivation machine
// happens to hold, and it is also what keeps the derivation from
// installing a byte to answer. The three --omits are what keep
// development and unselected-optional edges, which never reach a
// consumer, out of the consumer's triage surface. A stand-in npm
// records the argv so both claims are asserted where they are made.

package npm_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/npm"
)

// wantArgv is the whole invocation, spelled out. The list is asserted
// entire rather than by containment: an --omit that stops being passed
// is a silent over-claim in every inventory derived afterwards, and
// containment cannot see a flag go missing from a list it does not
// pin.
var wantArgv = []string{
	"ls", "--all", "--json", "--package-lock-only",
	"--omit=dev", "--omit=peer", "--omit=optional",
}

// stubNPM writes a stand-in npm into a fresh directory under the name
// the toolchain installs, and returns that directory. It records argv
// one entry per line, drops a marker into whatever directory it was
// run in, and replays canned streams from files so no fixture text
// needs shell quoting. /bin/cat is spelled absolutely because one test
// narrows PATH to this directory alone.
func stubNPM(t *testing.T, stdout, stderr string, exit int) string {
	t.Helper()

	dir := t.TempDir()

	for name, content := range map[string]string{"stdout": stdout, "stderr": stderr} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > '" + dir + "/argv'\n" +
		": > 'stele-npm-ran-here'\n" +
		"/bin/cat '" + dir + "/stdout'\n" +
		"/bin/cat '" + dir + "/stderr' >&2\n" +
		"exit " + strconv.Itoa(exit) + "\n"

	//nolint:gosec // a test script must execute
	if err := os.WriteFile(filepath.Join(dir, "npm"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	return dir
}

// TestTreeResolvesFromTheLockfileAlone asserts the invocation the
// package doc promises: the recorded resolution, production edges
// only, of the caller's own package.
func TestTreeResolvesFromTheLockfileAlone(t *testing.T) {
	t.Parallel()

	const canned = `{"name": "@acme/w", "version": "1.0.0"}`

	dir := stubNPM(t, canned, "", 0)
	pkg := t.TempDir()

	out, err := (npm.Runner{Bin: filepath.Join(dir, "npm")}).Tree(pkg)
	if err != nil {
		t.Fatalf("Tree = %v", err)
	}

	if string(out) != canned {
		t.Errorf("Tree returned %q, want npm's stdout verbatim", out)
	}

	//nolint:gosec // G304: a path this test just built in its own temp dir
	raw, rerr := os.ReadFile(filepath.Join(dir, "argv"))
	if rerr != nil {
		t.Fatalf("the stand-in npm was never run: %v", rerr)
	}

	if got := strings.TrimRight(string(raw), "\n"); got != strings.Join(wantArgv, "\n") {
		t.Errorf("npm argv =\n%s\nwant\n%s", got, strings.Join(wantArgv, "\n"))
	}

	// The tree is the caller's package's, not that of whatever
	// directory the derivation happens to be running in.
	if _, serr := os.Stat(filepath.Join(pkg, "stele-npm-ran-here")); serr != nil {
		t.Errorf("npm did not run in %q: %v", pkg, serr)
	}
}

// TestTreeCarriesNpmsOwnDiagnosis: npm's refusals are specific — a
// lockfile that does not cover the tree is the everyday one — and the
// operator needs npm's sentence rather than a bare exit status.
func TestTreeCarriesNpmsOwnDiagnosis(t *testing.T) {
	t.Parallel()

	const complaint = "npm error code ELSPROBLEMS\nnpm error missing: left-pad@1.3.0"

	dir := stubNPM(t, "", complaint+"\n", 1)

	_, err := (npm.Runner{Bin: filepath.Join(dir, "npm")}).Tree(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "missing: left-pad@1.3.0") {
		t.Fatalf("Tree = %v, want npm's own stderr carried through", err)
	}
}

// TestTreeRefusesAnAbsentBinary takes the other error branch: no
// process ran, so there is no stderr to quote, and the refusal must
// still name the directory it was asked about.
func TestTreeRefusesAnAbsentBinary(t *testing.T) {
	t.Parallel()

	pkg := t.TempDir()

	_, err := (npm.Runner{Bin: "/no/such/npm"}).Tree(pkg)
	if err == nil || !strings.Contains(err.Error(), pkg) {
		t.Fatalf("Tree = %v, want a refusal naming %q", err, pkg)
	}
}

// TestRunnerDefaultsToPATH pins the zero-value Runner: an unset Bin is
// the npm that shipped with the toolchain which built the artifact,
// resolved from PATH — not an empty argv[0] the exec layer would
// refuse before any resolution.
func TestRunnerDefaultsToPATH(t *testing.T) {
	dir := stubNPM(t, `{"name": "x", "version": "1.0.0"}`, "", 0)
	t.Setenv("PATH", dir)

	out, err := (npm.Runner{}).Tree(t.TempDir())
	if err != nil || len(out) == 0 {
		t.Fatalf("Tree = %q, %v — an unset Bin must resolve npm from PATH", out, err)
	}
}
