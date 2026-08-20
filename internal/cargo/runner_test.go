// The selection and the runner: the flags this package hands cargo,
// and what it does with an answer that is not metadata.
//
// The flags are correctness claims, not formatting. --locked is what
// makes the inventory describe the resolution the artifact was built
// from rather than one cargo re-derived at inventory time;
// --filter-platform is what keeps one target's cfg(...) edges out of
// another target's closure; and the feature flags are why Selection
// exists at all, because a workspace that builds one crate per feature
// set ships artifacts whose graphs differ. Every one of them is
// invisible to the closure tests, which start from recorded output —
// so they are asserted here, against a stand-in cargo that records the
// argv and working directory it was called with.

package cargo_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/cargo"
)

// metadataJSON is the smallest answer Closure accepts, so a stand-in
// returning it stays valid all the way through the walk.
const metadataJSON = `{"packages": [{"id": "a 1.0.0 (path+file:///a)", "name": "a",` +
	` "version": "1.0.0", "source": ""}],` +
	` "resolve": {"nodes": [{"id": "a 1.0.0 (path+file:///a)", "deps": []}]}}`

// ranHere is the marker the stand-in drops into whatever directory it
// was run in. A marker beats comparing `pwd` against the path handed
// to the runner: on darwin the temporary root reaches the test through
// a symlink, so the two spellings differ while naming one directory,
// and the assertion would be about path normalisation rather than
// about where cargo resolved.
const ranHere = "stele-cargo-ran-here"

// stubCargo writes a stand-in cargo into a fresh directory, under the
// name the toolchain installs, and returns that directory. The script
// records its argv one entry per line into "argv" so a test can read
// back what cargo was actually asked; stdout and stderr travel through
// files rather than through the script's own text, which keeps quoting
// out of the fixture. cat is spelled absolutely because one test
// narrows PATH to the stand-in's own directory.
func stubCargo(t *testing.T, stdout, stderr string, exit int) string {
	t.Helper()

	dir := t.TempDir()

	for name, content := range map[string]string{"stdout": stdout, "stderr": stderr} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > '" + dir + "/argv'\n" +
		": > '" + ranHere + "'\n" +
		"/bin/cat '" + dir + "/stdout'\n" +
		"/bin/cat '" + dir + "/stderr' >&2\n" +
		"exit " + strconv.Itoa(exit) + "\n"

	//nolint:gosec // a test script must execute
	if err := os.WriteFile(filepath.Join(dir, "cargo"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	return dir
}

// recorded reads back the argv the stand-in was called with.
func recorded(t *testing.T, dir string) []string {
	t.Helper()

	//nolint:gosec // G304: a path this test just built in its own temp dir
	raw, err := os.ReadFile(filepath.Join(dir, "argv"))
	if err != nil {
		t.Fatalf("the stand-in cargo was never run: %v", err)
	}

	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

// TestMetadataAsksForALockedResolution is the package doc's central
// claim, and the one a reader cannot check anywhere else: cargo is
// asked for the RECORDED resolution. Without --locked cargo may update
// the lockfile to answer, and the inventory would then describe a
// dependency set no shipped artifact was built from.
func TestMetadataAsksForALockedResolution(t *testing.T) {
	t.Parallel()

	dir := stubCargo(t, metadataJSON, "", 0)
	work := t.TempDir()

	sel, err := cargo.Select("x86_64-unknown-linux-gnu", []string{"pg17"}, true, false)
	if err != nil {
		t.Fatal(err)
	}

	out, err := (cargo.Runner{Bin: filepath.Join(dir, "cargo")}).Metadata(work, sel)
	if err != nil {
		t.Fatalf("Metadata = %v", err)
	}

	if string(out) != metadataJSON {
		t.Errorf("Metadata returned %q, want cargo's stdout verbatim", out)
	}

	argv := recorded(t, dir)

	want := []string{
		"metadata", "--format-version", "1", "--locked",
		"--filter-platform", "x86_64-unknown-linux-gnu",
		"--features", "pg17",
		"--no-default-features",
	}
	if strings.Join(argv, " ") != strings.Join(want, " ") {
		t.Errorf("cargo argv =\n  %v\nwant\n  %v", argv, want)
	}

	// The resolution is of the caller's tree, not of whatever tree the
	// derivation happens to be running in.
	if _, serr := os.Stat(filepath.Join(work, ranHere)); serr != nil {
		t.Errorf("cargo did not run in the manifest dir %q: %v", work, serr)
	}
}

// TestMetadataCarriesCargosOwnDiagnosis: when cargo refuses — an
// out-of-date lockfile under --locked is the everyday case — the
// operator needs cargo's sentence, not just "exit status 101".
func TestMetadataCarriesCargosOwnDiagnosis(t *testing.T) {
	t.Parallel()

	const complaint = "error: the lock file needs to be updated but --locked was passed"

	dir := stubCargo(t, "", complaint+"\n", 101)

	_, err := (cargo.Runner{Bin: filepath.Join(dir, "cargo")}).Metadata(t.TempDir(), cargo.Selection{})
	if err == nil || !strings.Contains(err.Error(), complaint) {
		t.Fatalf("Metadata = %v, want cargo's own stderr carried through", err)
	}
}

// TestMetadataRefusesAnAbsentBinary takes the other error branch: no
// process ever ran, so there is no stderr to quote, and the failure
// must still name the directory it was asked about.
func TestMetadataRefusesAnAbsentBinary(t *testing.T) {
	t.Parallel()

	work := t.TempDir()

	_, err := (cargo.Runner{Bin: "/no/such/cargo"}).Metadata(work, cargo.Selection{})
	if err == nil || !strings.Contains(err.Error(), work) {
		t.Fatalf("Metadata = %v, want a refusal naming %q", err, work)
	}
}

// TestRunnerDefaultsToPATH pins the zero-value Runner's stance: an
// unset Bin is the cargo that shipped with the toolchain which built
// the artifact, resolved from PATH — not an empty argv[0] the exec
// layer would refuse before any resolution.
func TestRunnerDefaultsToPATH(t *testing.T) {
	dir := stubCargo(t, metadataJSON, "", 0)
	t.Setenv("PATH", dir)

	out, err := (cargo.Runner{}).Metadata(t.TempDir(), cargo.Selection{})
	if err != nil || len(out) == 0 {
		t.Fatalf("Metadata = %q, %v — an unset Bin must resolve cargo from PATH", out, err)
	}
}

// TestSelectRefusesTheContradiction: --all-features and an explicit
// list is the one combination cargo itself rejects, and Select is
// where it must be caught. The type's whole point is that a
// contradictory selection cannot exist to be handed to a resolver, so
// the guard has to live in the constructor rather than in the runner,
// where a test double would bypass it.
func TestSelectRefusesTheContradiction(t *testing.T) {
	t.Parallel()

	if _, err := cargo.Select("", []string{"pg17"}, false, true); err == nil {
		t.Fatal("Select accepted --all-features beside an explicit feature list")
	}

	// All features with no list is not the contradiction.
	if _, err := cargo.Select("", nil, false, true); err != nil {
		t.Fatalf("Select(--all-features alone) = %v", err)
	}
}

// TestSelectionReadsBackWhatItResolvesFor: a selection is carried
// alongside the inventory it produced — the target and features are
// how a reader tells two artifacts of one workspace apart — so what
// goes in must come back out.
func TestSelectionReadsBackWhatItResolvesFor(t *testing.T) {
	t.Parallel()

	sel, err := cargo.Select("wasm32-unknown-unknown", []string{"js", "console"}, false, false)
	if err != nil {
		t.Fatal(err)
	}

	if sel.Target() != "wasm32-unknown-unknown" {
		t.Errorf("Target = %q", sel.Target())
	}

	if strings.Join(sel.Features(), ",") != "js,console" {
		t.Errorf("Features = %v", sel.Features())
	}
}

// TestSelectionArgs walks the renderings one row at a time. The zero
// selection rendering NOTHING is the load-bearing row: it is what a
// single-target workspace passes, and a stray --filter-platform or
// --no-default-features there would resolve a graph nobody built.
func TestSelectionArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		target    string
		features  []string
		noDefault bool
		all       bool
		want      string
	}{
		{"the zero selection asks for nothing", "", nil, false, false, ""},
		{
			"a target alone", "aarch64-apple-darwin", nil, false, false,
			"--filter-platform aarch64-apple-darwin",
		},
		{
			"features join on a comma, as cargo spells them", "",
			[]string{"a", "b"},
			false, false,
			"--features a,b",
		},
		{"no-default-features alone", "", nil, true, false, "--no-default-features"},
		{"all-features alone", "", nil, false, true, "--all-features"},
		{
			"the full postgres-extension shape", "x86_64-unknown-linux-gnu",
			[]string{"pg17"},
			true, false,
			"--filter-platform x86_64-unknown-linux-gnu --features pg17 --no-default-features",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sel, err := cargo.Select(tt.target, tt.features, tt.noDefault, tt.all)
			if err != nil {
				t.Fatal(err)
			}

			if got := strings.Join(sel.Args(), " "); got != tt.want {
				t.Errorf("Args = %q, want %q", got, tt.want)
			}
		})
	}
}
