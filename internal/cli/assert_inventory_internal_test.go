// Wiring tests for `assert inventory` (stele#396): the exit codes the
// three verdicts map to, the usage refusals, and the one read failure
// that is NOT a usage refusal — a document that will not read is a
// subject the run could not see.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeInventoryDoc puts one handed document on disk.
func writeInventoryDoc(t *testing.T, name, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), ownerRW); err != nil {
		t.Fatal(err)
	}

	return path
}

const (
	admissibleImage = `{"spdxVersion": "SPDX-2.3", "name": "img@amd64", "packages": [{"name": "libc6",` +
		` "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:deb/debian/libc6@2.36-9"}]}]}`
	versionlessImage = `{"spdxVersion": "SPDX-2.3", "name": "img@arm64", "packages": [{"name": "tzdata",` +
		` "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:deb/debian/tzdata"}]}]}`
)

func TestAssertInventoryExitCodes(t *testing.T) {
	good := writeInventoryDoc(t, "amd64.spdx.json", admissibleImage)
	bare := writeInventoryDoc(t, "arm64.spdx.json", versionlessImage)

	tests := []struct {
		name string
		args []string
		code int
		out  string
	}{
		{"every document admits", []string{good}, exitOK, "assert: PASS"},
		{"a versionless PURL fails", []string{good, bare}, exitRefused, "pkg:deb/debian/tzdata"},
		{
			"a document that will not read cannot be judged",
			[]string{good, filepath.Join(t.TempDir(), "absent.spdx.json")},
			exitBlind,
			"absent.spdx.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := Run(append([]string{"assert", "inventory"}, tt.args...), &stdout, &stderr)
			if code != tt.code {
				t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s", code, tt.code, stdout.String(), stderr.String())
			}

			if !strings.Contains(stdout.String(), tt.out) {
				t.Fatalf("stdout = %q, want substring %q", stdout.String(), tt.out)
			}
		})
	}
}

func TestAssertInventoryJSON(t *testing.T) {
	bare := writeInventoryDoc(t, "arm64.spdx.json", versionlessImage)

	var stdout, stderr bytes.Buffer

	if code := Run([]string{"assert", "inventory", "--json", bare}, &stdout, &stderr); code != exitRefused {
		t.Fatalf("Run = %d, want %d (stderr: %s)", code, exitRefused, stderr.String())
	}

	doc := decodeReport(t, &stdout)
	if doc.Verdict == nil || *doc.Verdict != "FAIL" {
		t.Fatalf("verdict = %v, want FAIL", doc.Verdict)
	}

	if !strings.Contains(stdout.String(), `"actual":"pkg:deb/debian/tzdata"`) {
		t.Errorf("the report does not name the versionless PURL:\n%s", stdout.String())
	}
}

func TestAssertInventoryRefusals(t *testing.T) {
	good := writeInventoryDoc(t, "amd64.spdx.json", admissibleImage)

	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{
			"no document",
			nil,
			exitUsage,
			"stele assert inventory: at least one inventory document is required — a judgment over none judges nothing",
		},
		{"an unknown flag", []string{"--nope", good}, exitUsage, "flag provided but not defined: -nope"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := Run(append([]string{"assert", "inventory"}, tt.args...), &stdout, &stderr); code != tt.code {
				t.Fatalf("Run = %d, want %d (stderr: %s)", code, tt.code, stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr = %q, want %q", stderr.String(), tt.want)
			}
		})
	}

	t.Run("a failing stdout", func(t *testing.T) {
		var stderr bytes.Buffer

		if code := Run([]string{"assert", "inventory", good}, failWriterI{}, &stderr); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})

	t.Run("a failing stderr under --json", func(t *testing.T) {
		var stdout bytes.Buffer

		if code := Run([]string{"assert", "inventory", "--json", good}, &stdout, failWriterI{}); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})

	t.Run("a failing stderr on the empty-list refusal", func(t *testing.T) {
		var stdout bytes.Buffer

		if code := Run([]string{"assert", "inventory"}, &stdout, failWriterI{}); code != exitIO {
			t.Fatalf("Run = %d, want %d", code, exitIO)
		}
	})
}
