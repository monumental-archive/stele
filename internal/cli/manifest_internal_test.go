// `emit manifest` at the command surface: the declared contract is
// complete or refused — a manifest missing any field would excuse
// obligations silently on the assert side, which is why nothing here
// is defaulted.

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestEmitManifestWritesTheDeclaredContract(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer

	args := []string{
		"manifest", "--classes", "go-binary,oci-image", "--store-vsa", "true",
		"--machinery-version", "1.40.0",
	}
	if got := emitCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("emitCmd = %d (stderr: %s)", got, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		`"schema":1`,
		`"classes":["go-binary","oci-image"]`,
		`"storeVsa":true`,
		`"machineryVersion":"1.40.0"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manifest lacks %s:\n%s", want, out)
		}
	}
}

func TestEmitManifestUsage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
	}{
		{"no classes", []string{"manifest", "--store-vsa", "true", "--machinery-version", "1.0.0"}},
		{"no layout", []string{"manifest", "--classes", "a", "--machinery-version", "1.0.0"}},
		{"a layout outside true/false", []string{
			"manifest", "--classes", "a", "--store-vsa", "store", "--machinery-version", "1.0.0",
		}},
		{"no machinery version", []string{"manifest", "--classes", "a", "--store-vsa", "false"}},
		{"unknown flag", []string{"manifest", "--nope"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			if got := emitCmd(tt.args, &stdout, &stderr); got != exitUsage {
				t.Errorf("emitCmd(%v) = %d, want %d (stderr: %s)", tt.args, got, exitUsage, stderr.String())
			}
		})
	}
}

// The shape rules live in internal/evidence and refuse through this
// surface too — a duplicate class reaches the shared Validate, not a
// second copy of it here.
func TestEmitManifestRefusesThroughTheSharedDefinition(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer

	args := []string{
		"manifest", "--classes", "a,a", "--store-vsa", "true", "--machinery-version", "1.0.0",
	}
	if got := emitCmd(args, &stdout, &stderr); got != exitRefused {
		t.Fatalf("emitCmd = %d, want %d", got, exitRefused)
	}

	if !strings.Contains(stderr.String(), "declared twice") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
