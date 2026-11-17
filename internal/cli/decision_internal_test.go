// Internal tests for `emit decision`: the run writes both files or
// neither, its one stdout line is the policy's predicate type, and
// every usage and write guard refuses by name. The engine's own
// refusals and the golden predicates are proven in internal/emit.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// decisionRun is one `emit decision` invocation's paths.
type decisionRun struct {
	policy, covered, predicate, subjects string
}

func newDecisionRun(t *testing.T) decisionRun {
	t.Helper()

	px := files(t)
	dir := t.TempDir()
	cov := filepath.Join(dir, "covered")

	if err := os.MkdirAll(cov, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(cov, "widget.spdx.json"), []byte("{}"), ownerRW); err != nil {
		t.Fatal(err)
	}

	return decisionRun{
		policy: px.policy, covered: cov,
		predicate: filepath.Join(dir, "predicate.json"), subjects: filepath.Join(dir, "subjects.sha256"),
	}
}

func (r decisionRun) args(extra ...string) []string {
	return append([]string{
		"emit", "decision", "--policy", r.policy,
		"--tag", "v1.2.3", "--classes", "go-binary",
		"--proof", "sbom and advisory triage=success", "--proof", "repro gate=success",
		"--covered", r.covered,
		"--predicate-out", r.predicate, "--subjects-out", r.subjects,
	}, extra...)
}

// pinDecisionClock stops the emit clock for one test.
func pinDecisionClock(t *testing.T) {
	t.Helper()

	orig := emitNow
	emitNow = func() time.Time { return time.Date(2026, 11, 17, 19, 49, 4, 0, time.UTC) }

	t.Cleanup(func() { emitNow = orig })
}

// TestEmitDecisionWritesBoth: a passing run writes the predicate and
// the subject lines, and says the policy's predicate type in the one
// line a workflow step's outputs can take.
func TestEmitDecisionWritesBoth(t *testing.T) {
	pinDecisionClock(t)

	r := newDecisionRun(t)

	var stdout, stderr bytes.Buffer

	if code := Run(r.args(), &stdout, &stderr); code != exitOK {
		t.Fatalf("Run = %d: %s", code, stderr.String())
	}

	want := "predicate-type=https://acme.example/attestations/release-decision/v1\n"
	if got := stdout.String(); got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}

	pred, err := os.ReadFile(r.predicate)
	if err != nil {
		t.Fatal(err)
	}

	want = `{"tag":"v1.2.3","classes":"go-binary","conclusion":"OPEN","decidedAt":"2026-11-17T19:49:04Z",` +
		`"proofs":[{"name":"sbom and advisory triage","result":"success"},{"name":"repro gate","result":"success"}]}` +
		"\n"
	if string(pred) != want {
		t.Fatalf("predicate = %s, want %s", pred, want)
	}

	subjects, err := os.ReadFile(r.subjects)
	if err != nil {
		t.Fatal(err)
	}

	// sha256("{}")
	want = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a  widget.spdx.json\n"
	if string(subjects) != want {
		t.Fatalf("subjects = %q, want %q", subjects, want)
	}
}

// TestEmitDecisionRefusals: every refusal exits 1 or 2 with its
// message, and a refused decision writes neither file — the signer
// step after it has nothing to sign.
func TestEmitDecisionRefusals(t *testing.T) {
	pinDecisionClock(t)

	for _, tt := range []struct {
		name string
		args func(r decisionRun) []string
		code int
		want string
	}{
		{
			name: "a proof that did not succeed",
			args: func(r decisionRun) []string { return r.args("--proof", "fuzz gate=skipped") },
			code: exitRefused,
			want: "fuzz gate is 'skipped' — absence of a proof is never a proof",
		},
		{
			name: "the named inventory absent",
			args: func(r decisionRun) []string { return r.args("--inventory", "other.spdx.json") },
			code: exitRefused,
			want: "the plan names other.spdx.json but the covered set does not carry it",
		},
		{
			name: "the subjects cannot be written",
			args: func(r decisionRun) []string {
				r.subjects = filepath.Join(r.covered, "absent", "subjects.sha256")

				return r.args()
			},
			code: exitRefused,
			want: "writing the subjects",
		},
		{
			name: "the predicate cannot be written",
			args: func(r decisionRun) []string {
				r.predicate = filepath.Join(r.covered, "absent", "predicate.json")

				return r.args()
			},
			code: exitRefused,
			want: "writing the predicate",
		},
		{
			name: "a proof flag that is not name=result",
			args: func(r decisionRun) []string { return r.args("--proof", "repro gate") },
			code: exitUsage,
			want: `--proof "repro gate" is not name=result`,
		},
		{
			name: "no policy",
			args: func(r decisionRun) []string {
				return []string{"emit", "decision", "--covered", r.covered}
			},
			code: exitUsage,
			want: "--policy is required",
		},
		{
			name: "no covered set",
			args: func(r decisionRun) []string { return []string{"emit", "decision", "--policy", r.policy} },
			code: exitUsage,
			want: "--covered is required",
		},
		{
			name: "an output missing",
			args: func(r decisionRun) []string {
				return []string{"emit", "decision", "--policy", r.policy, "--covered", r.covered, "--predicate-out", "x"}
			},
			code: exitUsage,
			want: "--predicate-out and --subjects-out are both required",
		},
		{
			name: "the policy unreadable",
			args: func(r decisionRun) []string {
				r.policy = filepath.Join(r.covered, "absent.json")

				return r.args()
			},
			code: exitUsage,
			want: "absent.json",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newDecisionRun(t)

			var stdout, stderr bytes.Buffer

			if code := Run(tt.args(r), &stdout, &stderr); code != tt.code {
				t.Fatalf("Run = %d, want %d (stderr: %s)", code, tt.code, stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr = %q, want it to name %q", stderr.String(), tt.want)
			}

			for _, path := range []string{r.predicate, r.subjects} {
				if _, err := os.Stat(path); err == nil {
					t.Errorf("a refused decision left %s behind", filepath.Base(path))
				}
			}
		})
	}
}

// TestEmitDecisionOutputFailures: a dead stdout after a passing run,
// and a dead stderr on a usage error, each exit 3.
func TestEmitDecisionOutputFailures(t *testing.T) {
	pinDecisionClock(t)

	r := newDecisionRun(t)

	var stderr bytes.Buffer

	if code := Run(r.args(), failWriterI{}, &stderr); code != exitIO {
		t.Fatalf("dead stdout: Run = %d, want %d", code, exitIO)
	}

	if code := Run([]string{"emit", "decision"}, failWriterI{}, failWriterI{}); code != exitIO {
		t.Fatalf("dead stderr: Run = %d, want %d", code, exitIO)
	}
}
