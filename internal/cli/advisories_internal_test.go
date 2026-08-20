// The advisories surface: what it refuses to start on, what it
// judges, and what it must never call clean.
//
// The exit vocabulary is the point of most of these rows. A scan that
// did not happen and a scan that found nothing both hold zero
// findings; only the exit code can tell a reader which one it got, so
// the first is CANNOT_JUDGE and the second is PASS.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// scanDoc is a govulncheck stream in the shape a real v1.7.0 run
// emits — measured, not written from the documentation.
const scanConfig = `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck",` +
	`"scanner_version":"v1.7.0","db":"https://vuln.go.dev","db_last_modified":"2026-08-19T17:06:06Z",` +
	`"go_version":"go1.26.6","scan_level":"symbol","scan_mode":"source"}}`

// calledFinding reaches a vulnerable symbol in a mixed-case module —
// the only shape that gates, on the module path that made the join
// worth moving.
const calledFinding = `{"finding":{"osv":"GO-2026-9999","trace":[{"module":"github.com/Masterminds/semver/v3",` +
	`"version":"v3.5.0","package":"github.com/Masterminds/semver/v3","function":"NewConstraint"}]}}`

// advisoryFixture writes a scan file and a decision directory, and
// returns their paths. An empty status writes no decision at all.
func advisoryFixture(t *testing.T, stream, status string) (string, string) { //nolint:gocritic // scan, vex dir
	t.Helper()

	dir := t.TempDir()

	scanPath := filepath.Join(dir, "scan.json")
	if err := os.WriteFile(scanPath, []byte(stream), 0o600); err != nil {
		t.Fatal(err)
	}

	vexDir := filepath.Join(dir, "vex")
	if err := os.Mkdir(vexDir, 0o750); err != nil {
		t.Fatal(err)
	}

	if status != "" {
		// The product purl is the LITERAL a published stele SBOM
		// carries — lowercased, and never derived here from the module
		// path the finding names.
		doc := `{"@context":"https://openvex.dev/ns/v0.2.0","timestamp":"2026-08-20T00:00:00Z",` +
			`"statements":[{"vulnerability":{"name":"GO-2026-9999"},"status":"` + status + `",` +
			`"justification":"vulnerable_code_not_present",` +
			`"products":[{"@id":"pkg:golang/github.com/masterminds/semver/v3@v3.5.0"}]}]}`
		if err := os.WriteFile(filepath.Join(vexDir, "d.openvex.json"), []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return scanPath, vexDir
}

func TestAssertAdvisoriesUsage(t *testing.T) {
	scanPath, vexDir := advisoryFixture(t, scanConfig, "")

	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"no scan", []string{"assert", "advisories", "--vex", vexDir, "--subject", "."}, "--scan is required"},
		{"no vex", []string{"assert", "advisories", "--scan", scanPath, "--subject", "."}, "--vex is required"},
		{
			"no subject",
			[]string{"assert", "advisories", "--scan", scanPath, "--vex", vexDir},
			"--subject is required",
		},
		{
			"unreadable scan",
			[]string{
				"assert", "advisories", "--scan", filepath.Join(t.TempDir(), "absent.json"),
				"--vex", vexDir, "--subject", ".",
			},
			"absent.json",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := Run(tt.args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("Run = %d, want %d", code, exitUsage)
			}

			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("stderr = %q, want it to name %q", stderr.String(), tt.want)
			}
		})
	}
}

// The verdict rows: what each input state exits as. A decision that
// denies excuses; one that admits, withholds or claims remediation
// does not; and a stream that is not a scan is neither pass nor fail.
func TestAssertAdvisoriesVerdicts(t *testing.T) {
	for _, tt := range []struct {
		name   string
		stream string
		status string
		want   int
	}{
		{"a called finding with no decision fails", scanConfig + calledFinding, "", exitRefused},
		{"a denying decision excuses it", scanConfig + calledFinding, "not_affected", exitOK},
		{"the other dialect's denial excuses it too", scanConfig + calledFinding, "false_positive", exitOK},
		{"an admission does not excuse", scanConfig + calledFinding, "affected", exitRefused},
		{"an unfinished judgment does not excuse", scanConfig + calledFinding, "under_investigation", exitRefused},
		{"a remediation claim the scan disproves does not excuse", scanConfig + calledFinding, "fixed", exitRefused},
		{"a scan finding nothing passes", scanConfig, "", exitOK},
		{"a stream that is not a scan cannot be judged", `{"results":[]}`, "", exitBlind},
		{"an empty stream cannot be judged", "", "", exitBlind},
		{"a truncated stream cannot be judged", scanConfig + `{"finding":{"osv":"GO-1","trace":[{"mod`, "", exitBlind},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scanPath, vexDir := advisoryFixture(t, tt.stream, tt.status)

			var stdout, stderr bytes.Buffer

			code := Run([]string{
				"assert", "advisories", "--scan", scanPath, "--vex", vexDir, "--subject", "example.com/mod",
			}, &stdout, &stderr)

			if code != tt.want {
				t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s", code, tt.want, stdout.String(), stderr.String())
			}
		})
	}
}

// A non-excusing decision must be named on the finding it failed to
// excuse: a red line whose reader cannot tell somebody already looked
// is how one advisory gets triaged twice.
func TestAssertAdvisoriesNamesANonExcusingDecision(t *testing.T) {
	scanPath, vexDir := advisoryFixture(t, scanConfig+calledFinding, "affected")

	var stdout, stderr bytes.Buffer

	if code := Run([]string{
		"assert", "advisories", "--scan", scanPath, "--vex", vexDir, "--subject", "example.com/mod",
	}, &stdout, &stderr); code != exitRefused {
		t.Fatalf("Run = %d, want %d", code, exitRefused)
	}

	for _, want := range []string{"affected", "does not excuse", "d.openvex.json"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout = %q, want it to name %q", stdout.String(), want)
		}
	}
}

// --json puts the document on stdout and moves progress to stderr, so
// a caller can pipe one without the other.
func TestAssertAdvisoriesJSON(t *testing.T) {
	scanPath, vexDir := advisoryFixture(t, scanConfig+calledFinding, "not_affected")

	var stdout, stderr bytes.Buffer

	if code := Run([]string{
		"assert", "advisories", "--scan", scanPath, "--vex", vexDir,
		"--subject", "example.com/mod", "--json",
	}, &stdout, &stderr); code != exitOK {
		t.Fatalf("Run = %d, want %d: %s", code, exitOK, stderr.String())
	}

	doc, err := jsonx.DecodeForeign[jsonReportDoc](stdout.Bytes())
	if err != nil {
		t.Fatalf("stdout is not one report document: %v", err)
	}

	if doc.Target == nil || *doc.Target != "assert advisories" {
		t.Errorf("target = %v, want the verb that sealed it", doc.Target)
	}

	if doc.Verdict == nil || *doc.Verdict != "PASS" {
		t.Errorf("verdict = %v, want PASS", doc.Verdict)
	}

	if strings.Contains(stdout.String(), "govulncheck v1.7.0, db") {
		t.Error("progress reached stdout in a --json run")
	}

	if !strings.Contains(stderr.String(), "govulncheck v1.7.0") {
		t.Errorf("stderr = %q, want the scanner banner", stderr.String())
	}
}

// A malformed decision refuses the run rather than deciding nothing
// silently — the vexjoin law, reached through this surface.
func TestAssertAdvisoriesRefusesAMalformedDecision(t *testing.T) {
	scanPath, vexDir := advisoryFixture(t, scanConfig, "")

	if err := os.WriteFile(filepath.Join(vexDir, "broken.openvex.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	if code := Run([]string{
		"assert", "advisories", "--scan", scanPath, "--vex", vexDir, "--subject", ".",
	}, &stdout, &stderr); code == exitOK {
		t.Fatalf("Run = %d, want a refusal: %s", code, stderr.String())
	}
}

// The stream contract, on every path that writes: a dead sink is
// reported as an I/O failure, never as a verdict.
func TestAssertAdvisoriesOutputFailures(t *testing.T) {
	scanPath, vexDir := advisoryFixture(t, scanConfig+calledFinding, "not_affected")

	args := []string{"assert", "advisories", "--scan", scanPath, "--vex", vexDir, "--subject", "."}

	t.Run("dead stdout during a passing run", func(t *testing.T) {
		var stderr bytes.Buffer

		if code := Run(args, failWriterI{}, &stderr); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})

	t.Run("dead stdout during a --json run", func(t *testing.T) {
		var stderr bytes.Buffer

		if code := Run(append(append([]string{}, args...), "--json"), failWriterI{}, &stderr); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})

	t.Run("dead stderr on a usage error", func(t *testing.T) {
		if code := Run([]string{"assert", "advisories"}, failWriterI{}, failWriterI{}); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})

	t.Run("dead stderr while refusing an unreadable scan", func(t *testing.T) {
		unreadable := []string{
			"assert", "advisories", "--scan", filepath.Join(t.TempDir(), "absent.json"),
			"--vex", vexDir, "--subject", ".",
		}
		if code := Run(unreadable, failWriterI{}, failWriterI{}); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})
}
