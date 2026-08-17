// The runner's exit-code contract against scripted stand-in binaries:
// 0 and 1 are answers, 128 is the typed zero-packages fault, anything
// else is a scanner failure.

package osv_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/monumental-archive/stele/internal/osv"
)

// scriptScanner writes a stand-in scanner script with the given exit
// code and returns a Runner pointed at it.
func scriptScanner(t *testing.T, exit int) osv.Runner {
	t.Helper()

	path := filepath.Join(t.TempDir(), "osv-scanner")
	script := "#!/bin/sh\necho '{\"results\": []}'\nexit " + string(rune('0'+exit%10))

	if exit >= 10 {
		script = "#!/bin/sh\necho '{\"results\": []}'\nexit 128"
	}

	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // a test script must execute
		t.Fatal(err)
	}

	return osv.Runner{Bin: path}
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
