// The root-plan table: every way an invocation can name (or fail to
// name) where its trusted root comes from. The decision is pure, so
// every branch — including both halves of the paired declaration —
// is reachable here without a packet leaving the machine.

package trust_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/trust"
)

const (
	rootFile  = "/etc/stele/trusted-root.json"
	anchorPin = "/etc/stele/tuf-root.json"
	ownMirror = "https://tuf.acme.example"
)

func TestPlanRoot(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		file, anchor, mirror   string
		wantOrigin             trust.RootOrigin
		wantFile               string
		wantAnchor, wantMirror string
		wantBuiltin            bool
		wantErr                string
	}{
		{
			name:       "a file alone is the offline path",
			file:       rootFile,
			wantOrigin: trust.OriginFile,
			wantFile:   rootFile,
		},
		{
			name:        "naming nothing takes TUF at the built-in anchor",
			wantOrigin:  trust.OriginTUF,
			wantMirror:  trust.DefaultMirror,
			wantBuiltin: true,
		},
		{
			name:       "a declared pair takes TUF at that instance",
			anchor:     anchorPin,
			mirror:     ownMirror,
			wantOrigin: trust.OriginTUF,
			wantAnchor: anchorPin,
			wantMirror: ownMirror,
		},
		{
			name:    "a file beside an anchor names two sources",
			file:    rootFile,
			anchor:  anchorPin,
			wantErr: "one root, named once",
		},
		{
			name:    "a file beside a mirror names two sources",
			file:    rootFile,
			mirror:  ownMirror,
			wantErr: "one root, named once",
		},
		{
			name:    "a file beside a whole pair names two sources",
			file:    rootFile,
			anchor:  anchorPin,
			mirror:  ownMirror,
			wantErr: "one root, named once",
		},
		{
			name:    "an anchor without its instance verifies nothing",
			anchor:  anchorPin,
			wantErr: "declared together or not at all",
		},
		{
			name:    "an instance without its anchor is fetched blind",
			mirror:  ownMirror,
			wantErr: "declared together or not at all",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			plan, err := trust.PlanRoot(tc.file, tc.anchor, tc.mirror)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("PlanRoot(%q, %q, %q) = %+v, want refusal", tc.file, tc.anchor, tc.mirror, plan)
				}

				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("PlanRoot error = %v, want it to name %q", err, tc.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("PlanRoot(%q, %q, %q) = %v", tc.file, tc.anchor, tc.mirror, err)
			}

			if plan.Origin != tc.wantOrigin {
				t.Errorf("origin = %q, want %q", plan.Origin, tc.wantOrigin)
			}

			if plan.File != tc.wantFile {
				t.Errorf("file = %q, want %q", plan.File, tc.wantFile)
			}

			if plan.Anchor != tc.wantAnchor {
				t.Errorf("anchor = %q, want %q", plan.Anchor, tc.wantAnchor)
			}

			if plan.Mirror != tc.wantMirror {
				t.Errorf("mirror = %q, want %q", plan.Mirror, tc.wantMirror)
			}

			if plan.BuiltinAnchor() != tc.wantBuiltin {
				t.Errorf("BuiltinAnchor = %v, want %v", plan.BuiltinAnchor(), tc.wantBuiltin)
			}
		})
	}
}

// The file origin is the only one ResolveRoot can prove without a
// network: it must hand back the document's own bytes, and refuse
// audibly when the path is not there.
func TestResolveRootFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "trusted-root.json")
	want := []byte(`{"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`)

	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("WriteFile = %v", err)
	}

	plan, err := trust.PlanRoot(path, "", "")
	if err != nil {
		t.Fatalf("PlanRoot = %v", err)
	}

	got, err := trust.ResolveRoot(plan)
	if err != nil {
		t.Fatalf("ResolveRoot = %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("ResolveRoot = %q, want the file's own bytes %q", got, want)
	}
}

func TestResolveRootRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		plan    trust.RootPlan
		wantErr string
	}{
		{
			name:    "an absent document is a refusal, never empty trust material",
			plan:    trust.RootPlan{Origin: trust.OriginFile, File: filepath.Join(t.TempDir(), "absent.json")},
			wantErr: "read trusted root",
		},
		{
			name:    "a plan that did not come from PlanRoot resolves to nothing",
			plan:    trust.RootPlan{},
			wantErr: "unplanned root origin",
		},
		{
			// The TUF leg is the network boundary and is deliberately
			// not proven here (see fetchTUF's own note) — but the anchor
			// is a LOCAL file, read before any metadata is fetched, and
			// an operator who names one that is not there must be told
			// so. Falling through to the built-in anchor instead would
			// silently resolve against different trust material than the
			// one they asked for, which is the one mistake a trust root
			// must never make quietly.
			name: "a TUF anchor that is not there refuses before any fetch",
			plan: trust.RootPlan{
				Origin: trust.OriginTUF,
				Mirror: "https://tuf-repo-cdn.example.invalid",
				Anchor: filepath.Join(t.TempDir(), "absent-root.json"),
			},
			wantErr: "read TUF anchor",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := trust.ResolveRoot(tc.plan)
			if err == nil {
				t.Fatalf("ResolveRoot(%+v) = %q, want refusal", tc.plan, got)
			}

			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ResolveRoot error = %v, want it to name %q", err, tc.wantErr)
			}
		})
	}
}

// A run that cannot say where its trust material came from has not
// said what it proved, so each origin renders distinguishably — the
// built-in anchor especially, because that is the one nobody named.
func TestRootPlanDescribe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		plan trust.RootPlan
		want string
	}{
		{
			name: "the offline document names its path",
			plan: trust.RootPlan{Origin: trust.OriginFile, File: rootFile},
			want: "file " + rootFile,
		},
		{
			name: "the default path says the anchor was nobody's choice",
			plan: trust.RootPlan{Origin: trust.OriginTUF, Mirror: trust.DefaultMirror},
			want: "tuf " + trust.DefaultMirror + " (anchor pinned in this binary)",
		},
		{
			name: "a declared instance names both halves",
			plan: trust.RootPlan{Origin: trust.OriginTUF, Anchor: anchorPin, Mirror: ownMirror},
			want: "tuf " + ownMirror + " (anchor " + anchorPin + ")",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.plan.Describe(); got != tc.want {
				t.Errorf("Describe = %q, want %q", got, tc.want)
			}
		})
	}
}
