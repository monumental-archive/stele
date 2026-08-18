// The runner's exit-code contract against scripted stand-in binaries:
// 0 and 1 are answers, 128 is the typed zero-packages fault, anything
// else is a scanner failure.

package osv_test

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/osv"
)

// scannerDir writes a stand-in scanner script with the given exit
// code into a fresh directory, under the name the belt installs, and
// returns the directory — so the same world serves both a Runner
// pointed at an explicit path and a PATH lookup.
func scannerDir(t *testing.T, exit int) string {
	t.Helper()

	dir := t.TempDir()
	script := "#!/bin/sh\necho '{\"results\": []}'\nexit " + strconv.Itoa(exit)

	//nolint:gosec // a test script must execute
	if err := os.WriteFile(filepath.Join(dir, "osv-scanner"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	return dir
}

// scriptScanner returns a Runner pointed at that stand-in by path.
func scriptScanner(t *testing.T, exit int) osv.Runner {
	t.Helper()

	return osv.Runner{Bin: filepath.Join(scannerDir(t, exit), "osv-scanner")}
}

func TestRunnerExitContract(t *testing.T) {
	t.Parallel()

	for _, exit := range []int{0, 1} {
		out, err := scriptScanner(t, exit).Scan([]byte("{}"))
		if err != nil || len(out) == 0 {
			t.Fatalf("exit %d: out=%q err=%v — an answer, not an error", exit, out, err)
		}
	}

	if _, err := scriptScanner(t, 128).Scan([]byte("{}")); !errors.Is(err, osv.ErrZeroPackages) {
		t.Fatalf("exit 128: err=%v, want ErrZeroPackages", err)
	}

	if _, err := scriptScanner(t, 2).Scan([]byte("{}")); err == nil || errors.Is(err, osv.ErrZeroPackages) {
		t.Fatalf("exit 2: err=%v, want a scanner failure", err)
	}

	if _, err := (osv.Runner{Bin: "/no/such/scanner"}).Scan([]byte("{}")); err == nil {
		t.Fatal("a missing binary did not refuse")
	}
}

// TestRunnerDefaultsToPATH pins the zero-value Runner's stance: an
// unset Bin is the binary the belt installs, resolved from PATH — not
// an empty argv[0] the exec layer would refuse before any scan.
func TestRunnerDefaultsToPATH(t *testing.T) {
	t.Setenv("PATH", scannerDir(t, 0))

	out, err := (osv.Runner{}).Scan([]byte("{}"))
	if err != nil || len(out) == 0 {
		t.Fatalf("Scan = %q, %v — an unset Bin must resolve osv-scanner from PATH", out, err)
	}
}

// TestRunnerRefusesUnwritableScratch: the scanner reads paths, so an
// SBOM that never reaches a scratch file is a fault BEFORE the scan —
// never a scan of nothing reported clean.
func TestRunnerRefusesUnwritableScratch(t *testing.T) {
	scanner := scriptScanner(t, 0)
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))

	_, err := scanner.Scan([]byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "scratch file") {
		t.Fatalf("Scan = %v, want the scratch-file refusal", err)
	}
}
