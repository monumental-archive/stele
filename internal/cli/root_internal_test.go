// The shared trusted-root surface: the plan the flags produce, the
// document the resolution hands back, and the record the report
// carries. TestMain is the structural half — the gate reaches
// nothing, so a test that plans the TUF origin fails loudly here
// instead of quietly depending on the live instance.

package cli

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/trust"
)

// TestMain fences the network out of the package's test binary. The
// file origin resolves for real (it is just a read); the TUF origin
// refuses, so any test that reaches it must swap this seam
// deliberately and say what it is proving.
func TestMain(m *testing.M) {
	resolveTrustedRoot = func(p trust.RootPlan) ([]byte, error) {
		if p.Origin == trust.OriginTUF {
			return nil, errors.New("the gate does not reach the network: plan " + p.Describe())
		}

		return trust.ResolveRoot(p)
	}

	os.Exit(m.Run())
}

// trustedRootBytes stands in for a real trusted-root document. The
// resolution hands bytes through untouched — LoadRoot is the only
// thing that interprets them — so their content proves nothing here.
const trustedRootBytes = `{"any": "bytes — the resolution hands them through"}`

func writeTrustedRoot(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "trusted-root.json")
	if err := os.WriteFile(path, []byte(trustedRootBytes), 0o600); err != nil {
		t.Fatalf("WriteFile = %v", err)
	}

	return path
}

// parseRoot registers the shared flags on a throwaway set and parses
// one argument vector through them — the surface every verifying verb
// gets from register.
func parseRoot(t *testing.T, args ...string) *rootFlags {
	t.Helper()

	rf := &rootFlags{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	rf.register(fs)

	if err := fs.Parse(args); err != nil {
		t.Fatalf("Parse(%v) = %v", args, err)
	}

	return rf
}

func TestRootFlagsResolveFile(t *testing.T) {
	root := writeTrustedRoot(t)

	rf := parseRoot(t, "--trusted-root", root)

	if got := rf.facts(); got != nil {
		t.Fatalf("facts before resolve = %v, want none — nothing was trusted yet", got)
	}

	content, err := rf.resolve()
	if err != nil {
		t.Fatalf("resolve = %v", err)
	}

	if string(content) != trustedRootBytes {
		t.Errorf("resolve = %q, want the document's own bytes", content)
	}

	facts := rf.facts()
	if len(facts) != 2 {
		t.Fatalf("facts = %v, want the origin and the digest", facts)
	}

	if facts[0].Name != factTrustedRoot || !strings.HasPrefix(facts[0].Value, "file ") {
		t.Errorf("facts[0] = %+v, want the file origin named", facts[0])
	}

	if facts[1].Name != factTrustedRootSHA || len(facts[1].Value) != 64 {
		t.Errorf("facts[1] = %+v, want the resolved document's sha256", facts[1])
	}
}

// A verb that names no root at all takes the TUF path — which the
// gate's fence refuses, proving the default is the network path and
// not a silent skip.
func TestRootFlagsDefaultsToTUF(t *testing.T) {
	rf := parseRoot(t)

	_, err := rf.resolve()
	if err == nil {
		t.Fatal("resolve reached a root with nothing named — the default must be the TUF origin")
	}

	if !strings.Contains(err.Error(), "tuf "+trust.DefaultMirror) {
		t.Errorf("resolve error = %v, want it to name the public-good instance", err)
	}

	if got := rf.facts(); got != nil {
		t.Errorf("facts after a failed resolve = %v, want none — nothing was trusted", got)
	}
}

func TestRootFlagsRefusals(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "a file beside a TUF instance names two sources",
			args:    []string{"--trusted-root", "/r.json", "--tuf-root", "/a.json", "--tuf-mirror", "https://m"},
			wantErr: "one root, named once",
		},
		{
			name:    "an anchor without its instance is half a declaration",
			args:    []string{"--tuf-root", "/a.json"},
			wantErr: "declared together or not at all",
		},
		{
			name:    "an instance without its anchor is half a declaration",
			args:    []string{"--tuf-mirror", "https://m"},
			wantErr: "declared together or not at all",
		},
		{
			name:    "an absent document is a refusal, not empty trust material",
			args:    []string{"--trusted-root", "/no/such/root.json"},
			wantErr: "read trusted root",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rf := parseRoot(t, tc.args...)

			got, err := rf.resolve()
			if err == nil {
				t.Fatalf("resolve(%v) = %q, want refusal", tc.args, got)
			}

			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("resolve error = %v, want it to name %q", err, tc.wantErr)
			}
		})
	}
}
