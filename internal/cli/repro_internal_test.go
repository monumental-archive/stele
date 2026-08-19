// Wiring tests for `stele verify repro` (stele#96): the tri-state
// exit contract, the usage refusals, and the population rule — an
// empty released manifest is CANNOT_JUDGE, never PASS.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// reproManifests writes a released and a rebuilt manifest and returns
// their paths.
func reproManifests(t *testing.T, released, rebuilt string) (string, string) { //nolint:gocritic // two paths
	t.Helper()

	dir := t.TempDir()
	sub := filepath.Join(dir, "checksums.txt")
	reb := filepath.Join(dir, "rebuilt.txt")

	if err := os.WriteFile(sub, []byte(released), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(reb, []byte(rebuilt), 0o600); err != nil {
		t.Fatal(err)
	}

	return sub, reb
}

const digestA = "1111111111111111111111111111111111111111111111111111111111111111"

const digestB = "2222222222222222222222222222222222222222222222222222222222222222"

func TestVerifyReproPass(t *testing.T) {
	sub, reb := reproManifests(t,
		digestA+"  stele.tar.gz\n", digestA+"  stele.tar.gz\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "repro", "--repo", "acme/widget", "--tag", "v1.0.0",
		"--subjects", sub, "--rebuilt", reb, "--json",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	doc := decodeReport(t, &stdout)
	if doc.Verdict == nil || *doc.Verdict != "PASS" {
		t.Fatalf("verdict = %v, want PASS", doc.Verdict)
	}
}

func TestVerifyReproDivergenceFails(t *testing.T) {
	sub, reb := reproManifests(t,
		digestA+"  stele.tar.gz\n", digestB+"  stele.tar.gz\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "repro", "--repo", "acme/widget", "--tag", "v1.0.0",
		"--subjects", sub, "--rebuilt", reb,
	}, &stdout, &stderr)
	if code != exitRefused {
		t.Fatalf("Run = %d, want %d\nstdout: %s", code, exitRefused, stdout.String())
	}

	if !strings.Contains(stdout.String(), "repro/diverged") {
		t.Errorf("stdout = %q, want the typed divergence", stdout.String())
	}
}

func TestVerifyReproEmptyReleaseCannotJudge(t *testing.T) {
	sub, reb := reproManifests(t, "", digestA+"  stele.tar.gz\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "repro", "--repo", "acme/widget", "--tag", "v1.0.0",
		"--subjects", sub, "--rebuilt", reb,
	}, &stdout, &stderr)
	if code != exitBlind {
		t.Fatalf("Run = %d, want %d — comparing nothing proves nothing\nstdout: %s",
			code, exitBlind, stdout.String())
	}
}

func TestVerifyReproUsageRefusals(t *testing.T) {
	sub, reb := reproManifests(t, digestA+"  a\n", digestA+"  a\n")

	junk := filepath.Join(t.TempDir(), "junk.txt")
	if err := os.WriteFile(junk, []byte("not a manifest line\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rows := [][]string{
		{"verify", "repro", "--tag", "v1", "--subjects", sub, "--rebuilt", reb},
		{"verify", "repro", "--repo", "solo", "--tag", "v1", "--subjects", sub, "--rebuilt", reb},
		{"verify", "repro", "--repo", "a/b", "--subjects", sub, "--rebuilt", reb},
		{"verify", "repro", "--repo", "a/b", "--tag", "v1", "--rebuilt", reb},
		{"verify", "repro", "--repo", "a/b", "--tag", "v1", "--subjects", sub},
		{"verify", "repro", "--repo", "a/b", "--tag", "v1", "--subjects", "/no/such", "--rebuilt", reb},
		{"verify", "repro", "--repo", "a/b", "--tag", "v1", "--subjects", sub, "--rebuilt", "/no/such"},
		{"verify", "repro", "--repo", "a/b", "--tag", "v1", "--subjects", junk, "--rebuilt", reb},
		{"verify", "repro", "--conjure"},
	}

	for _, args := range rows {
		t.Run(strings.Join(args[2:], " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := Run(args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("Run = %d, want %d; stderr: %s", code, exitUsage, stderr.String())
			}
		})
	}
}
