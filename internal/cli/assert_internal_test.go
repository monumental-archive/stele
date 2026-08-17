// Internal tests for the assert verb's dispatch: the registry seam
// is swapped for a scripted fake so every guard, exit path and the
// three-way verdict→exit mapping are table rows.

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/oci"
)

const (
	assertDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	assertChild  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// scriptedOCI serves one index and one label map for every read.
type scriptedOCI struct {
	index    string
	indexErr error
	labels   map[string]string
}

func (s scriptedOCI) Index(_, _ string) ([]byte, error) {
	if s.indexErr != nil {
		return nil, s.indexErr
	}

	return []byte(s.index), nil
}

func (s scriptedOCI) ConfigLabels(_, _ string) (map[string]string, error) {
	return s.labels, nil
}

func swapOCI(t *testing.T, r oci.Reader) {
	t.Helper()

	orig := newOCIReader
	newOCIReader = func() oci.Reader { return r }

	t.Cleanup(func() { newOCIReader = orig })
}

func cleanOCI() scriptedOCI {
	return scriptedOCI{
		index: `{"mediaType": "application/vnd.oci.image.index.v1+json",
		  "annotations": {"rev": "abc"},
		  "manifests": [{"digest": "` + assertChild + `", "platform": {"os": "linux", "architecture": "amd64"}}]}`,
		labels: map[string]string{"rev": "abc"},
	}
}

func setImageFactsEnv(t *testing.T, facts string) {
	t.Helper()
	t.Setenv("IMAGE", "ghcr.io/acme/widget")
	t.Setenv("DIGEST", assertDigest)
	t.Setenv("FACTS", facts)
}

func TestAssertImageFactsExitCodes(t *testing.T) {
	tests := []struct {
		name  string
		reg   scriptedOCI
		facts string
		want  int
		out   string
	}{
		{"equal facts pass", cleanOCI(), `{"rev": "abc"}`, exitOK, "assert: PASS"},
		{"drifted facts fail", cleanOCI(), `{"rev": "zzz"}`, exitRefused, "diverges"},
		{
			"a dead registry is blind, not a verdict",
			scriptedOCI{indexErr: errors.New("registry torn")},
			`{"rev": "abc"}`,
			exitBlind, "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swapOCI(t, tt.reg)
			setImageFactsEnv(t, tt.facts)

			var stdout, stderr bytes.Buffer

			code := Run([]string{"assert", "image-facts"}, &stdout, &stderr)
			if code != tt.want {
				t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s", code, tt.want, stdout.String(), stderr.String())
			}

			if tt.out != "" && !strings.Contains(stdout.String(), tt.out) {
				t.Fatalf("stdout = %q, want substring %q", stdout.String(), tt.out)
			}
		})
	}
}

// TestAssertImageFactsJSON pins the --json contract: one document on
// stdout in every outcome, including the blind one.
func TestAssertImageFactsJSON(t *testing.T) {
	t.Run("blind run still emits a CANNOT_JUDGE document", func(t *testing.T) {
		swapOCI(t, scriptedOCI{indexErr: errors.New("registry torn")})
		setImageFactsEnv(t, `{"rev": "abc"}`)

		var stdout, stderr bytes.Buffer

		if code := Run([]string{"assert", "image-facts", "--json"}, &stdout, &stderr); code != exitBlind {
			t.Fatalf("Run = %d, want %d", code, exitBlind)
		}

		doc := decodeReport(t, &stdout)
		if doc.Verdict == nil || *doc.Verdict != "CANNOT_JUDGE" {
			t.Fatalf("verdict = %v, want CANNOT_JUDGE", doc.Verdict)
		}

		if len(doc.Findings) != 1 || !strings.Contains(doc.Findings[0].Detail, "registry torn") {
			t.Fatalf("findings = %+v, want the registry error carried", doc.Findings)
		}
	})

	t.Run("passing run emits a PASS document", func(t *testing.T) {
		swapOCI(t, cleanOCI())
		setImageFactsEnv(t, `{"rev": "abc"}`)

		var stdout, stderr bytes.Buffer

		if code := Run([]string{"assert", "image-facts", "--json"}, &stdout, &stderr); code != exitOK {
			t.Fatalf("Run = %d, stderr: %s", code, stderr.String())
		}

		doc := decodeReport(t, &stdout)
		if doc.Verdict == nil || *doc.Verdict != "PASS" {
			t.Fatalf("verdict = %v, want PASS", doc.Verdict)
		}
	})
}

func TestAssertUsageRefusals(t *testing.T) {
	rows := [][]string{
		{"assert"},
		{"assert", "conjure"},
		{"assert", "image-facts", "--no-such-flag"},
	}

	for _, args := range rows {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := Run(args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("Run = %d, want %d", code, exitUsage)
			}
		})
	}

	t.Run("each missing env input refuses by name", func(t *testing.T) {
		swapOCI(t, cleanOCI())

		for _, unset := range []string{"IMAGE", "DIGEST", "FACTS"} {
			setImageFactsEnv(t, `{"rev": "abc"}`)
			t.Setenv(unset, "")

			var stdout, stderr bytes.Buffer

			if code := Run([]string{"assert", "image-facts"}, &stdout, &stderr); code != exitUsage {
				t.Fatalf("unset %s: Run = %d, want %d", unset, code, exitUsage)
			}

			if !strings.Contains(stderr.String(), unset+" must be set") {
				t.Fatalf("unset %s: stderr = %q, want the name", unset, stderr.String())
			}
		}
	})
}

// TestAssertOutputFailures pins the stream contract for the verb.
func TestAssertOutputFailures(t *testing.T) {
	t.Run("dead stdout during a passing run", func(t *testing.T) {
		swapOCI(t, cleanOCI())
		setImageFactsEnv(t, `{"rev": "abc"}`)

		var stderr bytes.Buffer

		if code := Run([]string{"assert", "image-facts"}, failWriterI{}, &stderr); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})

	t.Run("dead stdout during a --json run", func(t *testing.T) {
		swapOCI(t, cleanOCI())
		setImageFactsEnv(t, `{"rev": "abc"}`)

		var stderr bytes.Buffer

		if code := Run([]string{"assert", "image-facts", "--json"}, failWriterI{}, &stderr); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})

	t.Run("dead stderr on a usage error", func(t *testing.T) {
		if code := Run([]string{"assert"}, failWriterI{}, failWriterI{}); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})
}
