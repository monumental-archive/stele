// The output-stream guards, swept rather than sampled. Every command
// here writes several times — progress lines, a refusal, a report
// document — and each write has its own guard returning exitIO. A
// sampled test covers the first one and leaves the rest looking like
// success, which is the exact failure the guards exist to prevent: a
// tool whose job is asserting facts must not report success after
// failing to say what it found.

package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// countingWriter tallies writes so a sweep knows how many there are.
type countingWriter struct{ n int }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n++

	return len(p), nil
}

// nthFailWriter fails the (n+1)-th write and succeeds before it, so a
// sweep over n walks every write on a path in turn.
type nthFailWriter struct {
	n    int
	seen int
}

func (w *nthFailWriter) Write(p []byte) (int, error) {
	if w.seen == w.n {
		return 0, errSinkI
	}

	w.seen++

	return len(p), nil
}

var errSinkI = io.ErrClosedPipe

// sweepWriteFailures runs argv once per write the command makes,
// failing exactly one write each time — every stdout write, then every
// stderr write. Every run must exit exitIO.
func sweepWriteFailures(t *testing.T, argv []string) {
	t.Helper()
	sweepWriteFailuresReseeding(t, argv, func() {})
}

// sweepWriteFailuresReseeding is the same sweep for commands whose
// world one run changes — an emitter that appends a note cannot be run
// twice against the same history, so reseed rebuilds it before each
// attempt.
func sweepWriteFailuresReseeding(t *testing.T, argv []string, reseed func()) {
	t.Helper()

	reseed()

	var outCount, errCount countingWriter
	Run(argv, &outCount, &errCount)

	if outCount.n+errCount.n == 0 {
		t.Fatalf("Run(%v) wrote nothing — a sweep over no writes proves nothing", argv)
	}

	streams := []struct {
		name  string
		total int
		run   func(fail, sink io.Writer) int
	}{
		{"stdout", outCount.n, func(fail, sink io.Writer) int { return Run(argv, fail, sink) }},
		{"stderr", errCount.n, func(fail, sink io.Writer) int { return Run(argv, sink, fail) }},
	}

	for _, s := range streams {
		for n := range s.total {
			var sink bytes.Buffer

			reseed()

			if code := s.run(&nthFailWriter{n: n}, &sink); code != exitIO {
				t.Errorf("%v: %s write %d failed but Run = %d, want exitIO", argv, s.name, n, code)
			}
		}
	}
}

// TestVerifyStreamGuards sweeps the verify verb's four modes in the
// three shapes that write differently: a passing run, a refusal, and
// the --json document.
func TestVerifyStreamGuards(t *testing.T) {
	px := files(t)

	base := []string{
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", "v1.2.3", "--subjects", px.subjects,
		"--signer-digest", strings.Repeat("a", 40), "--machinery-digest", strings.Repeat("b", 40),
	}

	t.Run("a passing vsa run", func(t *testing.T) {
		swap(t, scriptedBV{payload: []byte(vsaStatement)}, scriptedStore{})
		sweepWriteFailures(t, append([]string{"verify", "vsa"}, base...))
	})

	t.Run("a passing vsa run as json", func(t *testing.T) {
		swap(t, scriptedBV{payload: []byte(vsaStatement)}, scriptedStore{})
		sweepWriteFailures(t, append([]string{"verify", "vsa", "--json"}, base...))
	})

	t.Run("a refused release run", func(t *testing.T) {
		swap(t, scriptedBV{payload: []byte(vsaStatement)}, scriptedStore{err: errSinkI})
		sweepWriteFailures(t, append([]string{"verify", "release", "--sboms", px.subjects}, base...))
	})

	t.Run("a refused release run as json", func(t *testing.T) {
		swap(t, scriptedBV{payload: []byte(vsaStatement)}, scriptedStore{err: errSinkI})
		sweepWriteFailures(t, append([]string{"verify", "release", "--json", "--sboms", px.subjects}, base...))
	})

	t.Run("a usage refusal", func(t *testing.T) {
		swap(t, scriptedBV{}, scriptedStore{})
		sweepWriteFailures(t, []string{"verify", "vsa", "--policy", px.policy, "--trusted-root", px.root})
	})

	t.Run("a chain walk that cannot open history", func(t *testing.T) {
		swap(t, scriptedBV{}, scriptedStore{})
		sweepWriteFailures(t, []string{
			"verify", "chain", "--policy", px.policy, "--trusted-root", px.root,
			"--repo", "acme/widget", "--git-dir", t.TempDir(),
		})
	})
}

// TestAssertStreamGuards sweeps every assert target in both output
// shapes and in the three verdicts, because the verdict decides how
// many lines are written and therefore how many guards exist.
func TestAssertStreamGuards(t *testing.T) {
	t.Run("image-facts passing", func(t *testing.T) {
		swapOCI(t, cleanOCI())
		setImageFactsEnv(t, `{"rev": "abc"}`)
		sweepWriteFailures(t, []string{"assert", "image-facts"})
	})

	t.Run("image-facts drifted", func(t *testing.T) {
		swapOCI(t, cleanOCI())
		setImageFactsEnv(t, `{"rev": "zzz"}`)
		sweepWriteFailures(t, []string{"assert", "image-facts"})
	})

	t.Run("image-facts blind", func(t *testing.T) {
		swapOCI(t, scriptedOCI{indexErr: errSinkI})
		setImageFactsEnv(t, `{"rev": "abc"}`)
		sweepWriteFailures(t, []string{"assert", "image-facts"})
	})

	t.Run("image-facts blind as json", func(t *testing.T) {
		swapOCI(t, scriptedOCI{indexErr: errSinkI})
		setImageFactsEnv(t, `{"rev": "abc"}`)
		sweepWriteFailures(t, []string{"assert", "image-facts", "--json"})
	})

	t.Run("image-facts missing env", func(t *testing.T) {
		swapOCI(t, cleanOCI())
		t.Setenv("IMAGE", "")
		t.Setenv("DIGEST", "")
		t.Setenv("FACTS", "")
		sweepWriteFailures(t, []string{"assert", "image-facts"})
	})

	t.Run("evidence over a snapshot", func(t *testing.T) {
		snap, policy := evidenceSnapshot(t)
		sweepWriteFailures(t, []string{"assert", "evidence", "--org", "acme", "--policy", policy, "--snapshot", snap})
	})

	t.Run("evidence usage refusal", func(t *testing.T) {
		sweepWriteFailures(t, []string{"assert", "evidence"})
	})

	t.Run("evidence walk torn", func(t *testing.T) {
		_, policy := evidenceSnapshot(t)
		sweepWriteFailures(t, []string{
			"assert", "evidence", "--org", "acme", "--policy", policy, "--snapshot", t.TempDir(),
		})
	})

	t.Run("blast-radius over a snapshot", func(t *testing.T) {
		snap, policy, vex := blastSnapshot(t)
		swapScanner(t, cliScanner{out: `{"results": []}`})
		sweepWriteFailures(t, []string{
			"assert", "blast-radius", "--org", "acme", "--policy", policy, "--vex", vex, "--snapshot", snap,
		})
	})

	t.Run("blast-radius usage refusal", func(t *testing.T) {
		sweepWriteFailures(t, []string{"assert", "blast-radius"})
	})

	t.Run("blast-radius walk torn", func(t *testing.T) {
		_, policy, vex := blastSnapshot(t)
		swapScanner(t, cliScanner{out: `{"results": []}`})
		sweepWriteFailures(t, []string{
			"assert", "blast-radius", "--org", "acme", "--policy", policy, "--vex", vex,
			"--snapshot", t.TempDir(),
		})
	})

	t.Run("tags over a snapshot", func(t *testing.T) {
		snap, policy := tagsSnapshot(t)
		swapTagVerifier(t, scriptedTagVerifier{})
		root := filepath.Join(t.TempDir(), "root.json")

		if err := os.WriteFile(root, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}

		sweepWriteFailures(t, []string{
			"assert", "tags", "--repo", "acme/widget", "--policy", policy,
			"--trusted-root", root, "--snapshot", snap,
		})
	})

	t.Run("tags usage refusal", func(t *testing.T) {
		sweepWriteFailures(t, []string{"assert", "tags"})
	})

	t.Run("tags walk torn", func(t *testing.T) {
		_, policy := tagsSnapshot(t)
		swapTagVerifier(t, scriptedTagVerifier{})
		root := filepath.Join(t.TempDir(), "root.json")

		if err := os.WriteFile(root, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}

		sweepWriteFailures(t, []string{
			"assert", "tags", "--repo", "acme/widget", "--policy", policy,
			"--trusted-root", root, "--snapshot", t.TempDir(),
		})
	})

	t.Run("an unknown target", func(t *testing.T) {
		sweepWriteFailures(t, []string{"assert", "conjure"})
	})

	t.Run("no target", func(t *testing.T) {
		sweepWriteFailures(t, []string{"assert"})
	})
}

// TestDeriveStreamGuards sweeps the derive verb: its dispatch, and the
// two modes' refusals.
func TestDeriveStreamGuards(t *testing.T) {
	t.Run("no mode", func(t *testing.T) {
		sweepWriteFailures(t, []string{"derive"})
	})

	t.Run("an unknown mode", func(t *testing.T) {
		sweepWriteFailures(t, []string{"derive", "conjure"})
	})

	t.Run("version without a clone", func(t *testing.T) {
		sweepWriteFailures(t, []string{"derive", "version"})
	})

	t.Run("notes without a clone", func(t *testing.T) {
		sweepWriteFailures(t, []string{"derive", "notes"})
	})

	t.Run("sbom without a binary", func(t *testing.T) {
		sweepWriteFailures(t, []string{"derive", "sbom"})
	})
}
