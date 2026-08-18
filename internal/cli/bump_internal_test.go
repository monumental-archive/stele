// `derive bump` end to end through the history seam and a real temp
// tree: the derivation decides the version, the mirrors move to it, and
// every refusal a degraded state produces actually fires.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bumpTree writes a canonical single-crate tree and returns its dir.
func bumpTree(t *testing.T, version string) string {
	t.Helper()

	dir := t.TempDir()

	cargo := "[package]\nname = \"demo\"\nversion = \"" + version + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(cargo), 0o600); err != nil {
		t.Fatal(err)
	}

	return dir
}

// bumpHistory is one released version and one feature since it.
func bumpHistory() *stubHistory {
	return &stubHistory{
		tags:       []string{"v0.9.0"},
		commits:    []string{"c1"},
		messages:   map[string]string{"c1": "feat: add a thing"},
		commitTime: "2026-08-18T10:00:00+02:00",
	}
}

// bumpRun is one invocation's observable outcome — a struct rather
// than three bare returns, two of which share a type.
type bumpRun struct {
	code   int
	stdout string
	stderr string
}

func runBump(t *testing.T, dir string, h deriveHistory, extra ...string) bumpRun {
	t.Helper()

	withHistory(t, h, nil)

	var outBuf, errBuf bytes.Buffer

	args := append([]string{"bump", "--git-dir", dir}, extra...)
	code := deriveCmd(args, &outBuf, &errBuf)

	return bumpRun{code: code, stdout: outBuf.String(), stderr: errBuf.String()}
}

func TestBumpRewritesTheMirrors(t *testing.T) {
	dir := bumpTree(t, "0.9.0")

	r := runBump(t, dir, bumpHistory())
	if r.code != exitOK {
		t.Fatalf("bump = %d, stderr: %s", r.code, r.stderr)
	}

	for _, want := range []string{
		"kind=cargo-package", "release=true", "version=0.10.0", "tag=v0.10.0", "files=Cargo.toml",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("stdout misses %q:\n%s", want, r.stdout)
		}
	}

	cargo, err := os.ReadFile(filepath.Join(dir, "Cargo.toml")) //nolint:gosec // a path this test just wrote
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(cargo), "version = \"0.10.0\"") {
		t.Errorf("the mirror did not move:\n%s", cargo)
	}
}

func TestBumpNothingToRelease(t *testing.T) {
	dir := bumpTree(t, "0.9.0")
	h := bumpHistory()
	h.messages = map[string]string{"c1": "chore: tidy"}

	r := runBump(t, dir, h)
	if r.code != exitOK || !strings.Contains(r.stdout, "release=false") {
		t.Fatalf("bump = %d, want release=false:\n%s", r.code, r.stdout)
	}

	cargo, err := os.ReadFile(filepath.Join(dir, "Cargo.toml")) //nolint:gosec // a path this test just wrote
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(cargo), "version = \"0.9.0\"") {
		t.Errorf("a no-release run touched the mirrors:\n%s", cargo)
	}
}

func TestBumpNoMirrors(t *testing.T) {
	r := runBump(t, t.TempDir(), bumpHistory())
	if r.code != exitOK {
		t.Fatalf("bump = %d, stderr: %s", r.code, r.stderr)
	}

	for _, want := range []string{"kind=none", "release=true", "version=0.10.0", "files=\n"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("stdout misses %q:\n%s", want, r.stdout)
		}
	}
}

// The pre-write state must be the last release or the one being cut;
// anything else is drift and refuses, and a re-run stays safe.
func TestBumpDriftAndRerun(t *testing.T) {
	t.Run("a drifted mirror refuses", func(t *testing.T) {
		dir := bumpTree(t, "0.4.7")

		r := runBump(t, dir, bumpHistory())
		if r.code != exitRefused || !strings.Contains(r.stderr, "mirrors carry \"0.4.7\"") {
			t.Fatalf("bump = %d, stderr: %s", r.code, r.stderr)
		}
	})

	t.Run("a re-run is idempotent", func(t *testing.T) {
		dir := bumpTree(t, "0.10.0") // the first run already moved it

		r := runBump(t, dir, bumpHistory())
		if r.code != exitOK || !strings.Contains(r.stdout, "version=0.10.0") {
			t.Fatalf("bump = %d, stderr: %s", r.code, r.stderr)
		}
	})

	t.Run("disagreeing mirrors refuse before anything moves", func(t *testing.T) {
		dir := bumpTree(t, "0.9.0")
		citation := "version: 0.8.0\ndate-released: 2026-01-01\n"

		if err := os.WriteFile(filepath.Join(dir, "CITATION.cff"), []byte(citation), 0o600); err != nil {
			t.Fatal(err)
		}

		r := runBump(t, dir, bumpHistory())
		if r.code != exitRefused || !strings.Contains(r.stderr, "disagree") {
			t.Fatalf("bump = %d, stderr: %s", r.code, r.stderr)
		}
	})
}

func TestBumpCitationDate(t *testing.T) {
	dir := bumpTree(t, "0.9.0")
	citation := "version: 0.9.0\ndate-released: 2026-01-01\n"

	if err := os.WriteFile(filepath.Join(dir, "CITATION.cff"), []byte(citation), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("defaults to the committer date, normalised to UTC", func(t *testing.T) {
		r := runBump(t, dir, bumpHistory())
		if r.code != exitOK {
			t.Fatalf("bump = %d, stderr: %s", r.code, r.stderr)
		}

		got, err := os.ReadFile(filepath.Join(dir, "CITATION.cff")) //nolint:gosec // a path this test just wrote
		if err != nil {
			t.Fatal(err)
		}

		// 10:00+02:00 is 08:00Z — same calendar day here, and the point
		// is that the date came from the ref, not a clock.
		want := "version: 0.10.0\ndate-released: 2026-08-18\n"
		if string(got) != want {
			t.Errorf("CITATION.cff = %q, want %q", got, want)
		}
	})

	t.Run("--date overrides", func(t *testing.T) {
		r := runBump(t, dir, bumpHistory(), "--date", "2026-12-01")
		if r.code != exitOK {
			t.Fatalf("bump = %d, stderr: %s", r.code, r.stderr)
		}

		got, err := os.ReadFile(filepath.Join(dir, "CITATION.cff")) //nolint:gosec // a path this test just wrote
		if err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(string(got), "date-released: 2026-12-01") {
			t.Errorf("CITATION.cff = %q", got)
		}
	})
}

func TestBumpCheck(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version string
		hist    *stubHistory
		code    int
		out     string
	}{
		{
			name: "mirrors at the released version pass", version: "0.9.0",
			hist: bumpHistory(), code: exitOK, out: "check=ok",
		},
		{
			name: "a drifted mirror fails", version: "0.8.0",
			hist: bumpHistory(), code: exitRefused, out: "",
		},
		{
			name: "no release yet checks agreement only", version: "0.1.0",
			hist: &stubHistory{commitTime: "2026-08-18T10:00:00Z"}, code: exitOK, out: "check=agreement-only",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := bumpTree(t, tc.version)

			r := runBump(t, dir, tc.hist, "--check")
			if r.code != tc.code {
				t.Fatalf("bump --check = %d, want %d (stderr: %s)", r.code, tc.code, r.stderr)
			}

			if tc.out != "" && !strings.Contains(r.stdout, tc.out) {
				t.Errorf("stdout misses %q:\n%s", tc.out, r.stdout)
			}

			// Check mode never writes.
			cargo, err := os.ReadFile(filepath.Join(dir, "Cargo.toml")) //nolint:gosec // a path this test just wrote
			if err != nil {
				t.Fatal(err)
			}

			if !strings.Contains(string(cargo), "version = \""+tc.version+"\"") {
				t.Errorf("check mode moved a mirror:\n%s", cargo)
			}
		})
	}

	t.Run("no mirrors is its own stated outcome", func(t *testing.T) {
		r := runBump(t, t.TempDir(), bumpHistory(), "--check")
		if r.code != exitOK || !strings.Contains(r.stdout, "check=no-mirrors") {
			t.Fatalf("bump --check = %d, stdout:\n%s\nstderr: %s", r.code, r.stdout, r.stderr)
		}
	})
}

func TestBumpRefusesADetectError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte("[package\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := runBump(t, dir, bumpHistory())
	if r.code != exitRefused || !strings.Contains(r.stderr, "parsing") {
		t.Fatalf("bump = %d, stderr: %s", r.code, r.stderr)
	}
}
