// The advisories surface with --scanner cargo-deny (stele#515): a
// Cargo lock judged against the same written decisions, through the
// same join, as a Go module.
//
// The stream is the one cargo-deny 0.20.2 wrote over iiif-server,
// recorded from the real tool (internal/cargodeny/testdata), and the
// decisions are the canon's two for exactly those crate versions,
// copied verbatim from its security/vex/ into testdata here.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/jsonx"
)

const (
	cargoStream    = "../cargodeny/testdata/iiif-server-advisories.jsonl"
	cargoDecisions = "testdata/advisories-cargo-deny"

	chronoKey    = "RUSTSEC-2026-0543:chrono@0.4.45"
	humantimeKey = "RUSTSEC-2026-0542:humantime@2.4.0"
)

// cargoReport is the report document with what these rows assert on:
// the gating findings, and what was excused by what.
type cargoReport struct {
	Verdict *string `json:"verdict"`
	Facts   []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"facts"`
	Findings []struct {
		Assertion string `json:"assertion"`
		Detail    string `json:"detail"`
	} `json:"findings"`
	Excused []struct {
		Finding struct {
			Assertion string `json:"assertion"`
		} `json:"finding"`
		Exception struct {
			Kind   string `json:"kind"`
			Origin string `json:"origin"`
		} `json:"exception"`
	} `json:"excused"`
}

func (r *cargoReport) fact(name string) (string, bool) {
	for i := range r.Facts {
		if r.Facts[i].Name == name {
			return r.Facts[i].Value, true
		}
	}

	return "", false
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()

	b, err := os.ReadFile(path) //nolint:gosec // test fixture paths
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

// canonDecision is one of the canon's decision documents, verbatim.
func canonDecision(t *testing.T, advisory string) string {
	t.Helper()

	return readTestFile(t, filepath.Join(cargoDecisions, advisory+".openvex.json"))
}

// cargoDecision is a minimal decision document for one cargo product.
func cargoDecision(advisory, purl, status string) string {
	return `{"@context":"https://openvex.dev/ns/v0.2.0","timestamp":"2026-11-21T00:00:00Z",` +
		`"statements":[{"vulnerability":{"name":"` + advisory + `"},"status":"` + status + `",` +
		`"justification":"vulnerable_code_not_present","products":[{"@id":"` + purl + `"}]}]}`
}

// cargoRun is one run of the target: its exit, its report, and what
// it wrote to stderr.
type cargoRun struct {
	code   int
	rep    *cargoReport
	stderr string
}

// runCargo writes the stream and the decisions (file name → document)
// and runs the target with --json.
func runCargo(t *testing.T, stream string, decisions map[string]string) cargoRun {
	t.Helper()

	dir := t.TempDir()

	scanPath := filepath.Join(dir, "deny.jsonl")
	if err := os.WriteFile(scanPath, []byte(stream), 0o600); err != nil {
		t.Fatal(err)
	}

	vexDir := filepath.Join(dir, "vex")
	if err := os.Mkdir(vexDir, 0o750); err != nil {
		t.Fatal(err)
	}

	for name, doc := range decisions {
		if err := os.WriteFile(filepath.Join(vexDir, name), []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "advisories", "--scanner", "cargo-deny", "--scan", scanPath, "--vex", vexDir,
		"--subject", "iiif-server", "--json",
	}, &stdout, &stderr)

	doc, err := jsonx.DecodeForeign[cargoReport](stdout.Bytes())
	if err != nil {
		t.Fatalf("stdout is not one report document (exit %d): %v\nstdout: %s\nstderr: %s",
			code, err, stdout.String(), stderr.String())
	}

	return cargoRun{code: code, rep: doc, stderr: stderr.String()}
}

func assertions(r *cargoReport) []string {
	out := make([]string, 0, len(r.Findings))
	for i := range r.Findings {
		out = append(out, r.Findings[i].Assertion)
	}

	return out
}

// The recorded stream with the canon's two decisions: both findings
// excused by the decisions that name their exact crate versions. The
// row the whole batch exists for — it fails against a stele with no
// --scanner flag.
func TestAdvisoriesCargoDenyCanonDecisionsExcuseBoth(t *testing.T) {
	run := runCargo(t, readTestFile(t, cargoStream), map[string]string{
		"RUSTSEC-2026-0542.openvex.json": canonDecision(t, "RUSTSEC-2026-0542"),
		"RUSTSEC-2026-0543.openvex.json": canonDecision(t, "RUSTSEC-2026-0543"),
	})
	code, rep, stderr := run.code, run.rep, run.stderr

	if code != exitOK || rep.Verdict == nil || *rep.Verdict != "PASS" {
		t.Fatalf("exit %d, verdict %v, want PASS: %+v\n%s", code, rep.Verdict, rep.Findings, stderr)
	}

	excused := map[string]string{}
	for i := range rep.Excused {
		excused[rep.Excused[i].Finding.Assertion] = rep.Excused[i].Exception.Kind + " " +
			rep.Excused[i].Exception.Origin
	}

	for key, origin := range map[string]string{
		chronoKey:    "RUSTSEC-2026-0543.openvex.json",
		humantimeKey: "RUSTSEC-2026-0542.openvex.json",
	} {
		if !strings.Contains(excused[key], "declared") || !strings.HasSuffix(excused[key], origin) {
			t.Errorf("%s excused by %q, want the declared decision %s", key, excused[key], origin)
		}
	}

	for name, want := range map[string]string{
		"scanner": "cargo-deny", "advisories": "2", "decisionsRead": "2", "decisionsInScope": "2",
		"diagnostics.error": "2", "diagnostics.warning": "0",
	} {
		if got, ok := rep.fact(name); !ok || got != want {
			t.Errorf("fact %s = %q (present %v), want %q", name, got, ok, want)
		}
	}

	if _, ok := rep.fact("db"); ok {
		t.Error("a db fact was reported, and the stream states none")
	}
}

// The verdict rows: each a state of the stream or the decisions, and
// the report it must seal.
func TestAdvisoriesCargoDenyVerdicts(t *testing.T) {
	recorded := readTestFile(t, cargoStream)
	summary := func(errs string) string {
		return `{"fields":{"advisories":{"errors":` + errs + `,"helps":0,"notes":0,"warnings":0}},` +
			`"type":"summary"}` + "\n"
	}
	lines := strings.SplitAfter(recorded, "\n")
	diagnostics := lines[0] + lines[1]

	yanked := `{"fields":{"code":"yanked","graphs":[{"Krate":{"name":"foo","version":"1.0.0"}}],` +
		`"message":"detected yanked crate","severity":"error"},"type":"diagnostic"}` + "\n"
	warning := strings.Replace(lines[0], `"severity":"error"`, `"severity":"warning"`, 1)

	for _, tt := range []struct {
		name      string
		stream    string
		decisions map[string]string
		exit      int
		verdict   string
		findings  []string
		detail    []string // each must appear in the first finding's detail
	}{
		{
			name: "no decisions: both findings gate", stream: recorded,
			exit: exitRefused, verdict: "FAIL", findings: []string{humantimeKey, chronoKey},
		},
		{
			name: "a decision for another version excuses nothing", stream: recorded,
			decisions: map[string]string{
				"chrono.openvex.json":            cargoDecision("RUSTSEC-2026-0543", "pkg:cargo/chrono@0.4.44", "not_affected"),
				"RUSTSEC-2026-0542.openvex.json": canonDecision(t, "RUSTSEC-2026-0542"),
			},
			exit: exitRefused, verdict: "FAIL", findings: []string{chronoKey},
			detail: []string{"chrono.openvex.json", "0.4.44", "0.4.45", "fresh judgment"},
		},
		{
			name: "an admitting decision is reported on its finding", stream: recorded,
			decisions: map[string]string{
				"chrono.openvex.json":            cargoDecision("RUSTSEC-2026-0543", "pkg:cargo/chrono@0.4.45", "affected"),
				"RUSTSEC-2026-0542.openvex.json": canonDecision(t, "RUSTSEC-2026-0542"),
			},
			exit: exitRefused, verdict: "FAIL", findings: []string{chronoKey},
			detail: []string{`"affected"`, "does not excuse", "chrono.openvex.json"},
		},
		{
			name: "an error with no advisory gates and nothing excuses it", stream: yanked + summary("1"),
			decisions: map[string]string{
				"foo.openvex.json": cargoDecision("yanked", "pkg:cargo/foo@1.0.0", "not_affected"),
			},
			exit: exitRefused, verdict: "FAIL", findings: []string{"yanked:pkg:cargo/foo@1.0.0"},
			detail: []string{"foo@1.0.0", "yanked", "names no advisory"},
		},
		{
			name: "a stream with no summary cannot be judged", stream: diagnostics,
			exit: exitBlind, verdict: "CANNOT_JUDGE",
		},
		{
			name: "a summary counting 3 over two diagnostics cannot be judged", stream: diagnostics + summary("3"),
			exit: exitBlind, verdict: "CANNOT_JUDGE",
		},
		{
			name: "a line that is not JSON cannot be judged", stream: recorded + "error: index failure\n",
			exit: exitBlind, verdict: "CANNOT_JUDGE",
		},
		{
			name: "a warning diagnostic gates nothing", stream: warning + summary("0"),
			exit: exitOK, verdict: "PASS",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			run := runCargo(t, tt.stream, tt.decisions)
			code, rep, stderr := run.code, run.rep, run.stderr

			if code != tt.exit || rep.Verdict == nil || *rep.Verdict != tt.verdict {
				t.Fatalf("exit %d, verdict %v, want %d %s: %+v\n%s",
					code, rep.Verdict, tt.exit, tt.verdict, rep.Findings, stderr)
			}

			if tt.verdict == "CANNOT_JUDGE" {
				return
			}

			if got := assertions(rep); strings.Join(got, ",") != strings.Join(tt.findings, ",") {
				t.Fatalf("findings = %v, want %v", got, tt.findings)
			}

			for _, want := range tt.detail {
				if !strings.Contains(rep.Findings[0].Detail, want) {
					t.Errorf("detail %q does not name %q", rep.Findings[0].Detail, want)
				}
			}
		})
	}
}

// A warning is counted, not judged: the report says how many there
// were, and the error count is zero.
func TestAdvisoriesCargoDenyCountsAWarning(t *testing.T) {
	lines := strings.SplitAfter(readTestFile(t, cargoStream), "\n")
	stream := strings.Replace(lines[0], `"severity":"error"`, `"severity":"warning"`, 1) +
		`{"fields":{"advisories":{"errors":0,"helps":0,"notes":0,"warnings":1}},"type":"summary"}` + "\n"

	rep := runCargo(t, stream, nil).rep

	for name, want := range map[string]string{"diagnostics.warning": "1", "diagnostics.error": "0", "advisories": "0"} {
		if got, _ := rep.fact(name); got != want {
			t.Errorf("fact %s = %q, want %q", name, got, want)
		}
	}
}

// --scanner govulncheck and no flag at all are one reader: the same
// report, byte for byte, over the same govulncheck stream.
func TestAdvisoriesScannerGovulncheckIsTheDefault(t *testing.T) {
	scanPath, vexDir := advisoryFixture(t, scanConfig+calledFinding, "affected")

	run := func(extra ...string) string {
		var stdout, stderr bytes.Buffer

		args := append([]string{
			"assert", "advisories", "--scan", scanPath, "--vex", vexDir, "--subject", "example.com/mod", "--json",
		}, extra...)
		if code := Run(args, &stdout, &stderr); code != exitRefused {
			t.Fatalf("Run(%v) = %d, want %d: %s", extra, code, exitRefused, stderr.String())
		}

		return stdout.String()
	}

	absent, named := run(), run("--scanner", "govulncheck")
	if absent != named {
		t.Fatalf("reports differ:\nno flag:\n%s\n--scanner govulncheck:\n%s", absent, named)
	}
}
