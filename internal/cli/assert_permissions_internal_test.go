// Wiring tests for `assert permissions`: every usage refusal, both
// caller populations, and the verdict→exit mapping. The target runs
// in a gate, where a refusal that exits like a verdict is a red
// nobody can act on and a skip that exits like a pass is a check that
// never ran.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
)

const permissionsCLIPolicy = `{
  "schema": 5,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}
  },
  "permissions": {
    "reusable": {"repo": "acme/shared", "dir": ".github/workflows"},
    "callerDirs": [".github/workflows", "workflow-templates"]
  }
}`

const permissionsCLICallee = `
on:
  workflow_call:
jobs:
  build:
    permissions:
      contents: read
`

const permissionsCLIGrantingCaller = `
permissions:
  contents: read
jobs:
  ci:
    uses: acme/shared/.github/workflows/ci.yml@abc
`

const permissionsCLIShortCaller = `
permissions: {}
jobs:
  ci:
    uses: acme/shared/.github/workflows/ci.yml@abc
`

// permissionsCheckout writes a checkout that is both the shared tree
// and its own caller — the canon's own shape, where `--tree` and
// `--callers` name one root. It returns the policy path, then the
// checkout root.
//
//nolint:gocritic // unnamedResult: the doc line names them
func permissionsCheckout(t *testing.T, caller string) (string, string) {
	t.Helper()

	root := t.TempDir()

	policyPath := filepath.Join(root, "assert-policy.json")
	if err := os.WriteFile(policyPath, []byte(permissionsCLIPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	wf := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o750); err != nil {
		t.Fatal(err)
	}

	for name, body := range map[string]string{"ci.yml": permissionsCLICallee, "gate.yml": caller} {
		if err := os.WriteFile(filepath.Join(wf, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// A non-workflow file beside the workflows: the platform ignores it
	// and so must the walk, or every org's template metadata becomes a
	// refusal.
	if err := os.WriteFile(filepath.Join(wf, "notes.md"), []byte("not a workflow\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	return policyPath, root
}

func TestAssertPermissionsExitCodes(t *testing.T) {
	tests := []struct {
		name   string
		caller string
		want   int
		out    string
	}{
		{"a sufficient grant passes", permissionsCLIGrantingCaller, exitOK, "assert: PASS"},
		{"a caller short of the callee's ask fails", permissionsCLIShortCaller, exitRefused, "contents: read"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyPath, root := permissionsCheckout(t, tt.caller)

			var stdout, stderr bytes.Buffer

			code := Run([]string{
				"assert", "permissions", "--policy", policyPath, "--tree", root, "--callers", root,
			}, &stdout, &stderr)
			if code != tt.want {
				t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s", code, tt.want, stdout.String(), stderr.String())
			}

			if !strings.Contains(stdout.String(), tt.out) {
				t.Fatalf("stdout = %q, want it to name %q", stdout.String(), tt.out)
			}
		})
	}
}

// TestAssertPermissionsEmptyCheckoutCannotJudge: a root holding no
// workflow file at all seals CANNOT_JUDGE and exits 4. A wrong
// --callers path and a genuinely workflow-free tree look identical
// from here, and the first must never exit like a pass.
func TestAssertPermissionsEmptyCheckoutCannotJudge(t *testing.T) {
	policyPath, root := permissionsCheckout(t, permissionsCLIGrantingCaller)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "permissions", "--policy", policyPath, "--tree", root, "--callers", t.TempDir(),
	}, &stdout, &stderr)
	if code != exitBlind {
		t.Fatalf("Run = %d, want %d (CANNOT_JUDGE)\nstdout: %s", code, exitBlind, stdout.String())
	}
}

// TestAssertPermissionsJSON: the document a gate consumes, with the
// facts that separate "nothing to find" from "nothing was looked at".
func TestAssertPermissionsJSON(t *testing.T) {
	policyPath, root := permissionsCheckout(t, permissionsCLIGrantingCaller)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "permissions", "--policy", policyPath, "--tree", root, "--callers", root, "--json",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
	}

	for _, want := range []string{
		`"target":"assert permissions"`, `"verdict":"PASS"`,
		`"name":"callsChecked"`, `"name":"reusableWorkflows"`, `"name":"callsOutsideDeclaredTrees"`,
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("document is missing %s:\n%s", want, stdout.String())
		}
	}
}

func TestAssertPermissionsUsageRefusals(t *testing.T) {
	policyPath, root := permissionsCheckout(t, permissionsCLIGrantingCaller)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no policy", []string{"--tree", root}, "--policy is required"},
		{
			"both populations",
			[]string{"--policy", policyPath, "--org", "acme", "--repo", "acme/widget"},
			"one population, named once",
		},
		{"a repo that is not owner/name", []string{"--policy", policyPath, "--repo", "widget"}, "must be owner/name"},
		{
			"a checkout and a walk",
			[]string{"--policy", policyPath, "--callers", root, "--org", "acme"},
			"name one caller population",
		},
		{
			"replay and capture",
			[]string{"--policy", policyPath, "--org", "acme", "--snapshot", root, "--capture", root},
			"replay reads, capture writes",
		},
		{
			"a recording with no walk",
			[]string{"--policy", policyPath, "--snapshot", root},
			"record a forge walk",
		},
		{
			"named files, which this target does not take",
			[]string{"--policy", policyPath, "--tree", root, "--callers", root, "extra.yml"},
			"extra arguments name nothing",
		},
		{
			"a declared tree the checkout does not carry",
			[]string{"--policy", policyPath, "--tree", filepath.Join(root, "nowhere"), "--callers", root},
			"holds no such directory",
		},
		{"a policy that is not there", []string{"--policy", filepath.Join(root, "ghost.json")}, "no such file"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := Run(append([]string{"assert", "permissions"}, tt.args...), &stdout, &stderr)
			if code != exitUsage {
				t.Fatalf("Run = %d, want %d (usage)\nstderr: %s", code, exitUsage, stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("stderr = %q, want it to name %q", stderr.String(), tt.want)
			}
		})
	}
}

// TestAssertPermissionsWithoutSection: a policy that declares no
// permissions section is refused rather than judged — a run asked for
// nothing must not report finding nothing.
func TestAssertPermissionsWithoutSection(t *testing.T) {
	root := t.TempDir()

	policyPath := filepath.Join(root, "assert-policy.json")

	stripped := strings.Replace(permissionsCLIPolicy, `,
  "permissions": {
    "reusable": {"repo": "acme/shared", "dir": ".github/workflows"},
    "callerDirs": [".github/workflows", "workflow-templates"]
  }`, "", 1)
	if err := os.WriteFile(policyPath, []byte(stripped), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	code := Run([]string{"assert", "permissions", "--policy", policyPath, "--tree", root}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("Run = %d, want %d (usage)\nstderr: %s", code, exitUsage, stderr.String())
	}

	if !strings.Contains(stderr.String(), "declares no permissions section") {
		t.Fatalf("stderr = %q, want the absent-section refusal", stderr.String())
	}
}

// permissionsSnapshot writes the population walk's inputs as a
// replayable snapshot: the org listing, and one repository whose own
// workflows carry the caller.
func permissionsSnapshot(t *testing.T, caller string) string {
	t.Helper()

	dir := t.TempDir()

	if err := os.MkdirAll(filepath.Join(dir, "acme", "widget", "workflows"), 0o750); err != nil {
		t.Fatal(err)
	}

	write := func(path, content string) {
		t.Helper()

		if err := os.WriteFile(filepath.Join(dir, path), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// The snapshot's repos.json is the recorded listing; workflow files
	// ride as their own bytes under the repository.
	write(filepath.Join("acme", "repos.json"), `[{"name": "widget"}]`)
	write(filepath.Join("acme", "widget", "workflows", "gate.yml"), caller)

	return dir
}

// TestAssertPermissionsPopulationWalk: the scheduled half, replayed.
// The callers are a population member's own workflows and the tree is
// the shared repository's current state — the forecast of the next
// pin bump.
func TestAssertPermissionsPopulationWalk(t *testing.T) {
	tests := []struct {
		name   string
		caller string
		want   int
	}{
		{"a population member granting enough", permissionsCLIGrantingCaller, exitOK},
		{"a population member that will startup-fail on its next bump", permissionsCLIShortCaller, exitRefused},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyPath, root := permissionsCheckout(t, permissionsCLIGrantingCaller)
			snap := permissionsSnapshot(t, tt.caller)

			var stdout, stderr bytes.Buffer

			code := Run([]string{
				"assert", "permissions", "--policy", policyPath, "--tree", root,
				"--org", "acme", "--snapshot", snap,
			}, &stdout, &stderr)
			if code != tt.want {
				t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s", code, tt.want, stdout.String(), stderr.String())
			}

			if !strings.Contains(stdout.String(), "acme/widget") {
				t.Fatalf("stdout = %q, want the population member named", stdout.String())
			}
		})
	}
}

// TestAssertPermissionsUnreadablePopulation: a listing the walk
// cannot read is blindness, and blindness exits 4 — never 0, and
// never 1.
func TestAssertPermissionsUnreadablePopulation(t *testing.T) {
	policyPath, root := permissionsCheckout(t, permissionsCLIGrantingCaller)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "permissions", "--policy", policyPath, "--tree", root,
		"--org", "acme", "--snapshot", t.TempDir(),
	}, &stdout, &stderr)
	if code != exitBlind {
		t.Fatalf("Run = %d, want %d (CANNOT_JUDGE)\nstdout: %s\nstderr: %s",
			code, exitBlind, stdout.String(), stderr.String())
	}
}

// emptyTreeCheckout is the declared reusable tree, present and
// holding nothing. It is a distinct degraded state from an absent
// directory: the path is right and the tree is not there, which is
// blindness the engine refuses rather than a wave of missing callees.
func emptyTreeCheckout(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o750); err != nil {
		t.Fatal(err)
	}

	return root
}

// TestAssertPermissionsEmptyDeclaredTree: the guard above, as a
// verdict. Blindness exits 4 and says which tree was empty.
func TestAssertPermissionsEmptyDeclaredTree(t *testing.T) {
	policyPath, root := permissionsCheckout(t, permissionsCLIGrantingCaller)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "permissions", "--policy", policyPath, "--tree", emptyTreeCheckout(t), "--callers", root,
	}, &stdout, &stderr)
	if code != exitBlind {
		t.Fatalf("Run = %d, want %d (CANNOT_JUDGE)\nstderr: %s", code, exitBlind, stderr.String())
	}

	if !strings.Contains(stderr.String(), "would read as absent") {
		t.Fatalf("stderr = %q, want the empty-tree refusal", stderr.String())
	}
}

// TestAssertPermissionsLocalOnlyAdopter: no declared reusable tree,
// so no tree is read and the join covers the checkout's own calls.
// The universality claim, exercised through the command surface.
func TestAssertPermissionsLocalOnlyAdopter(t *testing.T) {
	root := t.TempDir()

	policyPath := filepath.Join(root, "assert-policy.json")

	localOnly := strings.Replace(permissionsCLIPolicy,
		`"reusable": {"repo": "acme/shared", "dir": ".github/workflows"},
    "callerDirs"`, `"callerDirs"`, 1)
	if err := os.WriteFile(policyPath, []byte(localOnly), 0o600); err != nil {
		t.Fatal(err)
	}

	wf := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o750); err != nil {
		t.Fatal(err)
	}

	for name, body := range map[string]string{
		"inner.yml": permissionsCLICallee,
		"outer.yml": "permissions: {}\njobs:\n  ci:\n    uses: ./.github/workflows/inner.yml\n",
	} {
		if err := os.WriteFile(filepath.Join(wf, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// No --callers either: the default is the working directory, which
	// is what the gate invocation relies on.
	t.Chdir(root)

	var stdout, stderr bytes.Buffer

	code := Run([]string{"assert", "permissions", "--policy", policyPath}, &stdout, &stderr)
	if code != exitRefused {
		t.Fatalf("Run = %d, want %d — the local caller grants nothing\nstdout: %s", code, exitRefused, stdout.String())
	}

	if !strings.Contains(stdout.String(), "contents: read") {
		t.Fatalf("stdout = %q, want the local under-grant", stdout.String())
	}
}

// TestAssertPermissionsUnreadableInputs: paths that are there and
// will not read. Each is a refusal, never a shorter walk — a walk
// that quietly covered less is the failure this target exists to
// remove.
func TestAssertPermissionsUnreadableInputs(t *testing.T) {
	tests := []struct {
		name  string
		build func(t *testing.T) []string
		want  int
	}{
		{
			name: "an unparsable flag",
			build: func(t *testing.T) []string {
				t.Helper()
				policyPath, root := permissionsCheckout(t, permissionsCLIGrantingCaller)

				return []string{"--policy", policyPath, "--tree", root, "--conjure"}
			},
			want: exitUsage,
		},
		{
			name: "a policy that is not a policy",
			build: func(t *testing.T) []string {
				t.Helper()
				root := t.TempDir()
				path := filepath.Join(root, "policy.json")

				if err := os.WriteFile(path, []byte(`{"schema": 5}`), 0o600); err != nil {
					t.Fatal(err)
				}

				return []string{"--policy", path, "--tree", root}
			},
			want: exitUsage,
		},
		{
			name: "a declared tree that is a file",
			build: func(t *testing.T) []string {
				t.Helper()
				policyPath, root := permissionsCheckout(t, permissionsCLIGrantingCaller)
				fake := t.TempDir()

				if err := os.MkdirAll(filepath.Join(fake, ".github"), 0o750); err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(filepath.Join(fake, ".github", "workflows"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}

				return []string{"--policy", policyPath, "--tree", fake, "--callers", root}
			},
			want: exitUsage,
		},
		{
			name: "a caller directory that is a file",
			build: func(t *testing.T) []string {
				t.Helper()
				policyPath, root := permissionsCheckout(t, permissionsCLIGrantingCaller)
				callers := t.TempDir()

				if err := os.MkdirAll(filepath.Join(callers, ".github"), 0o750); err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(filepath.Join(callers, ".github", "workflows"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}

				return []string{"--policy", policyPath, "--tree", root, "--callers", callers}
			},
			want: exitBlind,
		},
		{
			name: "a workflow entry that is a directory",
			build: func(t *testing.T) []string {
				t.Helper()
				policyPath, root := permissionsCheckout(t, permissionsCLIGrantingCaller)

				if err := os.MkdirAll(filepath.Join(root, "workflow-templates", "stub.yml"), 0o750); err != nil {
					t.Fatal(err)
				}

				return []string{"--policy", policyPath, "--tree", root, "--callers", root}
			},
			want: exitOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := Run(append([]string{"assert", "permissions"}, tt.build(t)...), &stdout, &stderr)
			if code != tt.want {
				t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s", code, tt.want, stdout.String(), stderr.String())
			}
		})
	}
}

// TestAssertPermissionsCaptureThrough: the capture wrapper records
// the walk it replays later. Bound through the forge seam, so the
// branch is exercised without a network.
func TestAssertPermissionsCaptureThrough(t *testing.T) {
	policyPath, root := permissionsCheckout(t, permissionsCLIGrantingCaller)
	snap := permissionsSnapshot(t, permissionsCLIGrantingCaller)

	swapForge(t, gh.Snapshot{Dir: snap})

	capture := filepath.Join(t.TempDir(), "capture")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "permissions", "--policy", policyPath, "--tree", root,
		"--repo", "acme/widget", "--capture", capture,
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
	}

	// The capture must carry the workflow under the name its repository
	// knows it by: a snapshot that numbers its files replays a tree in
	// which no local call can be resolved.
	if _, err := os.Stat(filepath.Join(capture, "acme", "widget", "workflows", "gate.yml")); err != nil {
		t.Fatalf("capture is missing the named workflow: %v", err)
	}
}

// TestAssertPermissionsLiveForge: with neither --snapshot nor
// --capture the walk reads the forge the binary builds for itself.
// Bound through the seam, so the branch is exercised without a
// network.
func TestAssertPermissionsLiveForge(t *testing.T) {
	policyPath, root := permissionsCheckout(t, permissionsCLIGrantingCaller)

	swapForge(t, gh.Snapshot{Dir: permissionsSnapshot(t, permissionsCLIGrantingCaller)})

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "permissions", "--policy", policyPath, "--tree", root, "--org", "acme",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitOK, stderr.String())
	}
}

// TestAssertPermissionsUnreadableMember: the population listed a
// repository whose workflows will not read. That is blindness over
// the whole walk, not a shorter one — a member skipped in silence is
// a member reported clean.
func TestAssertPermissionsUnreadableMember(t *testing.T) {
	policyPath, root := permissionsCheckout(t, permissionsCLIGrantingCaller)

	snap := t.TempDir()
	if err := os.MkdirAll(filepath.Join(snap, "acme", "widget"), 0o750); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(snap, "acme", "repos.json"), []byte(`[{"name": "widget"}]`), 0o600); err != nil {
		t.Fatal(err)
	}

	// The recorded workflow directory is a file: present, unreadable.
	if err := os.WriteFile(filepath.Join(snap, "acme", "widget", "workflows"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "permissions", "--policy", policyPath, "--tree", root,
		"--org", "acme", "--snapshot", snap,
	}, &stdout, &stderr)
	if code != exitBlind {
		t.Fatalf("Run = %d, want %d (CANNOT_JUDGE)\nstdout: %s", code, exitBlind, stdout.String())
	}
}

// TestAssertPermissionsUnreadableWorkflowFile: a directory entry the
// walk must read and cannot. The run refuses rather than judging the
// files it managed to open.
func TestAssertPermissionsUnreadableWorkflowFile(t *testing.T) {
	policyPath, root := permissionsCheckout(t, permissionsCLIGrantingCaller)

	// A dangling symlink reads as a file to the directory listing and
	// fails to open — the same shape as any file the walk cannot read,
	// without depending on the runner's user.
	if err := os.Symlink(filepath.Join(root, "nowhere.yml"),
		filepath.Join(root, ".github", "workflows", "broken.yml")); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "permissions", "--policy", policyPath, "--tree", root, "--callers", root,
	}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("Run = %d, want %d (usage)\nstderr: %s", code, exitUsage, stderr.String())
	}
}
