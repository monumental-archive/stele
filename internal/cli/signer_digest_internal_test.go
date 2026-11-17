// `derive signer-digest`'s table: one row per guard in the flag
// surface, the policy read, the tree read and the derivation, each
// asserting the exit code AND the message. The derivation's own rows
// live in internal/workflow; these prove the command reaches them
// with the policy's signer and a readable subject.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/jsonx"
)

const (
	signerPath = "monumental-archive/signer/.github/workflows/sign.yml"
	signerPinA = "adfe82d191c3ae605c76c9dc22f6ad081efc4f5d"
	signerPinB = "0123456789abcdef0123456789abcdef01234567"
)

// signerPolicy writes a verify policy naming signer as the provenance
// identity.
func signerPolicy(t *testing.T, dir, signer string) string {
	t.Helper()

	path := filepath.Join(dir, "verify-policy.json")
	content := `{"schema": ` + strconv.Itoa(jsonx.Epoch) + `, "issuer": "https://token.example.com", ` +
		`"trust": {"provenance": {"signerWorkflow": "` + signer + `"}}}`

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// signerCall is a workflow file whose one job calls uses.
func signerCall(uses string) string {
	return "on: workflow_call\njobs:\n  sign:\n    uses: " + uses + "\n"
}

// writeTree writes name→content under dir.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()

	for name, content := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDeriveSignerDigest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	policy := signerPolicy(t, dir, signerPath)
	role := signerPolicy(t, t.TempDir(), "{owner}/{repo}/.github/workflows/sign.yml")
	broken := filepath.Join(dir, "broken-policy.json")

	if err := os.WriteFile(broken, []byte(`{"schema": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	one := filepath.Join(dir, "one")
	writeTree(t, one, map[string]string{
		"publish.yml":    signerCall(signerPath + "@" + signerPinA),
		"continuous.yml": signerCall(signerPath + "@" + signerPinA),
		// Not a workflow file, and a directory beneath the flat set:
		// the platform reads neither, so neither may decide the pin.
		"README.md":          signerCall(signerPath + "@" + signerPinB),
		"nested/publish.yml": signerCall(signerPath + "@" + signerPinB),
		"self-release.yaml":  "on: push\njobs: {}\n",
	})

	two := filepath.Join(dir, "two")
	writeTree(t, two, map[string]string{
		"publish.yml":    signerCall(signerPath + "@" + signerPinA),
		"vex-attest.yml": signerCall(signerPath + "@" + signerPinB),
	})

	none := filepath.Join(dir, "none")
	writeTree(t, none, map[string]string{"ci.yml": "on: push\njobs: {}\n"})

	roleTree := filepath.Join(dir, "role")
	writeTree(t, roleTree, map[string]string{
		"release.yml": signerCall("acme/lab/.github/workflows/sign.yml@" + signerPinA),
	})

	caller := filepath.Join(one, "publish.yml")
	noPin := filepath.Join(none, "ci.yml")

	tests := []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{
			name:   "a tree pinning one digest prints it alone",
			args:   []string{"--policy", policy, "--workflows", one},
			code:   exitOK,
			stdout: signerPinA + "\n",
			stderr: "derive signer-digest: " + one + " pins " + signerPath + " at " + signerPinA,
		},
		{
			name:   "the calling workflow's own file — verify-signed's form",
			args:   []string{"--policy", policy, "--workflow", caller},
			code:   exitOK,
			stdout: signerPinA + "\n",
		},
		{
			name: "a file pinning none — verify-signed's `none` refusal",
			args: []string{"--policy", policy, "--workflow", noPin},
			code: exitRefused,
			stderr: "derive signer-digest: " + noPin +
				" pins no sign.yml uses: — nothing to derive the signer digest from",
		},
		{
			name: "a tree pinning none — verify-release's `none` refusal",
			args: []string{"--policy", policy, "--workflows", none},
			code: exitRefused,
			stderr: "derive signer-digest: " + none +
				" pins no sign.yml uses: — nothing to derive the signer digest from",
		},
		{
			name: "two digests in the tree — the `more than one` refusal",
			args: []string{"--policy", policy, "--workflows", two},
			code: exitRefused,
			stderr: "derive signer-digest: " + two + " pins sign.yml at more than one digest — " +
				"a tree states the trusted signer once: " + signerPinB + " " + signerPinA,
		},
		{
			name:   "a role-shaped signer expands for the named repository",
			args:   []string{"--policy", role, "--workflows", roleTree, "--repo", "acme/lab"},
			code:   exitOK,
			stdout: signerPinA + "\n",
		},
		{
			name:   "a role-shaped signer with no repository to expand it for",
			args:   []string{"--policy", role, "--workflows", roleTree},
			code:   exitRefused,
			stderr: `the policy's signer workflow "{owner}/{repo}/.github/workflows/sign.yml" is a role`,
		},
		{
			name:   "a role-shaped signer with a malformed repository",
			args:   []string{"--policy", role, "--workflows", roleTree, "--repo", "acme/lab/extra"},
			code:   exitRefused,
			stderr: "so --repo owner/repo must say whose",
		},
		{
			name:   "no policy",
			args:   []string{"--workflows", one},
			code:   exitUsage,
			stderr: "stele derive signer-digest: --policy is required",
		},
		{
			name:   "both tree flags",
			args:   []string{"--policy", policy, "--workflows", one, "--workflow", caller},
			code:   exitUsage,
			stderr: "--workflows and --workflow are exclusive",
		},
		{
			name:   "no tree flag",
			args:   []string{"--policy", policy},
			code:   exitUsage,
			stderr: "one of --workflows or --workflow is required",
		},
		{
			name:   "an unknown flag",
			args:   []string{"--policy", policy, "--signer", "x"},
			code:   exitUsage,
			stderr: "flag provided but not defined: -signer",
		},
		{
			name:   "an unreadable policy",
			args:   []string{"--policy", filepath.Join(dir, "absent.json"), "--workflows", one},
			code:   exitRefused,
			stderr: "derive signer-digest: open " + filepath.Join(dir, "absent.json"),
		},
		{
			name:   "a policy the loader refuses",
			args:   []string{"--policy", broken, "--workflows", one},
			code:   exitRefused,
			stderr: "derive signer-digest: policy: ",
		},
		{
			name:   "an unreadable workflow file",
			args:   []string{"--policy", policy, "--workflow", filepath.Join(dir, "absent.yml")},
			code:   exitRefused,
			stderr: "derive signer-digest: open " + filepath.Join(dir, "absent.yml"),
		},
		{
			name:   "an unreadable workflows directory",
			args:   []string{"--policy", policy, "--workflows", filepath.Join(dir, "absent")},
			code:   exitRefused,
			stderr: "derive signer-digest: open " + filepath.Join(dir, "absent"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			code := Run(append([]string{"derive", "signer-digest"}, tt.args...), &stdout, &stderr)
			if code != tt.code {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, tt.code, stdout.String(), stderr.String())
			}

			if tt.stdout != "" && stdout.String() != tt.stdout {
				t.Fatalf("stdout = %q, want %q", stdout.String(), tt.stdout)
			}

			if tt.code != exitOK && stdout.Len() != 0 {
				t.Fatalf("a refusal printed %q on stdout — a caller reading the pin would read that", stdout.String())
			}

			if !strings.Contains(stderr.String(), tt.stderr) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr.String(), tt.stderr)
			}
		})
	}
}

// TestDeriveSignerDigestUnreadableEntry holds the directory read's
// per-file guard: a workflow file the process cannot open is a
// refusal, never a file skipped — skipping it could drop the one call
// that disagrees.
func TestDeriveSignerDigestUnreadableEntry(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 file; the guard is unreachable as root")
	}

	dir := t.TempDir()
	policy := signerPolicy(t, dir, signerPath)
	tree := filepath.Join(dir, "tree")
	writeTree(t, tree, map[string]string{"publish.yml": signerCall(signerPath + "@" + signerPinA)})

	locked := filepath.Join(tree, "publish.yml")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	code := Run([]string{"derive", "signer-digest", "--policy", policy, "--workflows", tree}, &stdout, &stderr)
	if code != exitRefused || !strings.Contains(stderr.String(), "derive signer-digest: open "+locked) {
		t.Fatalf("exit %d, stderr %q: want a refusal naming %s", code, stderr.String(), locked)
	}
}

// TestDeriveSignerDigestBrokenStream holds the output guard: a pin
// that could not be written is not a pin delivered.
func TestDeriveSignerDigestBrokenStream(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	policy := signerPolicy(t, dir, signerPath)
	tree := filepath.Join(dir, "tree")
	writeTree(t, tree, map[string]string{"publish.yml": signerCall(signerPath + "@" + signerPinA)})

	args := []string{"derive", "signer-digest", "--policy", policy, "--workflows", tree}

	if code := Run(args, failWriterI{}, &bytes.Buffer{}); code != exitIO {
		t.Fatalf("a broken stdout exited %d, want %d", code, exitIO)
	}

	if code := Run(args, &bytes.Buffer{}, failWriterI{}); code != exitIO {
		t.Fatalf("a broken log stream exited %d, want %d", code, exitIO)
	}
}
