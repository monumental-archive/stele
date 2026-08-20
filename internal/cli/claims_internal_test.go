// `derive claims` at the command surface: the flag guards, the
// undeclared-obligation refusal, the reviewed-tree confinement, and
// one end-to-end run through the snapshot leg producing a payload the
// emitter's own decoder accepts.
//
// The engine's guard branches are tabled in internal/claims; what is
// exercised here is the wiring — which is where a verb acquires the
// ability to be quietly wrong about WHICH tree, WHICH branch, or
// whether it read anything at all.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/claims"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// claimsPolicy is a minimal valid policy carrying a two-property
// table: one matched against branch rules, one carried by the gate.
const claimsPolicy = `{
  "schema": 6,
  "issuer": "https://token.example.com",
  "trust": {"provenance": {"signerWorkflow": "acme/signer/.github/workflows/sign.yml"}},
  "source": {
    "identity": "https://github.com/{owner}/{repo}/.github/workflows/source-attest.yml@refs/heads/main",
    "notesRef": "refs/notes/commits",
    "provenancePredicateType": "https://acme.example/attestations/source-provenance/v1",
    "propertyPrefix": "ACME_SOURCE_",
    "resourceUri": "git+https://github.com/{owner}/{repo}",
    "claims": {"properties": [
      {"name": "ACME_SOURCE_GATED", "scope": "branchRules",
       "match": {"$contains": [{"type": "required_status_checks"}]}},
      {"name": "ACME_SOURCE_DCO", "scope": "gatedTask", "requiresProperty": "ACME_SOURCE_GATED",
       "file": "mise/config.toml", "tablePath": ["tasks", "lint:dco"]}
    ]},
    "protectedBranches": [
      {"name": "main", "targetLevel": "SLSA_SOURCE_LEVEL_3",
       "levels": [{"level": "SLSA_SOURCE_LEVEL_3", "requiredProperties": [
         {"name": "ACME_SOURCE_GATED", "since": "2026-08-09T16:29:06+01:00"}
       ]}]}
    ],
    "healedContinuity": true,
    "underclaimLevel": "SLSA_SOURCE_LEVEL_2"
  }
}`

// claimsFixture lays out a policy, a rules snapshot and a reviewed
// tree, and returns their paths.
type claimsFixture struct {
	policy   string
	snapshot string
	canon    string
}

func newClaimsFixture(t *testing.T) claimsFixture {
	t.Helper()

	dir := t.TempDir()

	policyPath := filepath.Join(dir, "policy.json")
	write(t, policyPath, claimsPolicy)

	snap := filepath.Join(dir, "snapshot")
	write(t, filepath.Join(snap, "acme", "widget", "rules", "branches", "main.json"),
		`[{"type": "required_status_checks", "ruleset_id": 1}]`)
	write(t, filepath.Join(snap, "acme", "widget", "rules", "rulesets", "1.json"),
		`{"id": 1, "target": "branch", "enforcement": "active", "updated_at": "2020-01-01T00:00:00Z"}`)

	canon := filepath.Join(dir, "canon")
	write(t, filepath.Join(canon, "mise", "config.toml"), "[tasks.\"lint:dco\"]\nrun = \"belt dco\"\n")

	return claimsFixture{policy: policyPath, snapshot: snap, canon: canon}
}

func write(t *testing.T, path, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// args builds a full argument list with the fixture's paths.
func (f claimsFixture) args(extra ...string) []string {
	return append([]string{
		"claims",
		"--policy", f.policy,
		"--repo", "acme/widget",
		"--branch", "main",
		"--snapshot", f.snapshot,
		"--canon-root", f.canon,
		"--canon-digest", "canonref",
	}, extra...)
}

func TestDeriveClaimsUsage(t *testing.T) {
	f := newClaimsFixture(t)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no policy", []string{"claims", "--repo", "acme/widget", "--branch", "main"}},
		{"no repo", []string{"claims", "--policy", f.policy, "--branch", "main"}},
		{"a repo that is not owner/name", []string{
			"claims", "--policy", f.policy, "--repo", "widget", "--branch", "main",
		}},
		{"no branch", []string{"claims", "--policy", f.policy, "--repo", "acme/widget"}},
		{"replay and capture at once", []string{
			"claims", "--policy", f.policy, "--repo", "acme/widget", "--branch", "main",
			"--snapshot", f.snapshot, "--capture", t.TempDir(),
		}},
		{"unknown flag", []string{"claims", "--nope"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if got := deriveCmd(tc.args, &stdout, &stderr); got != exitUsage {
				t.Errorf("deriveCmd(%v) = %d, want %d (stderr: %s)", tc.args, got, exitUsage, stderr.String())
			}
		})
	}
}

// A gated property needs the reviewed tree it rests on, named. Both
// halves are refused by flag name up front rather than half-way
// through a derivation.
func TestDeriveClaimsNeedsTheReviewedTree(t *testing.T) {
	f := newClaimsFixture(t)

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			"no tree",
			[]string{
				"claims", "--policy", f.policy, "--repo", "acme/widget", "--branch", "main",
				"--snapshot", f.snapshot,
			},
			"--canon-root is required",
		},
		{
			"a tree nothing names",
			[]string{
				"claims", "--policy", f.policy, "--repo", "acme/widget", "--branch", "main",
				"--snapshot", f.snapshot, "--canon-root", f.canon,
			},
			"--canon-digest is required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if got := deriveCmd(tc.args, &stdout, &stderr); got != exitRefused {
				t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, exitRefused, stderr.String())
			}

			if !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("stderr = %q, want it to mention %q", stderr.String(), tc.want)
			}
		})
	}
}

// A policy with no table is an undeclared obligation, refused by name
// at USE — never a load failure and never a silent empty claim set.
func TestDeriveClaimsUndeclaredTable(t *testing.T) {
	f := newClaimsFixture(t)
	bare := filepath.Join(t.TempDir(), "policy.json")

	stripped := strings.Replace(claimsPolicy, `"claims": {"properties": [
      {"name": "ACME_SOURCE_GATED", "scope": "branchRules",
       "match": {"$contains": [{"type": "required_status_checks"}]}},
      {"name": "ACME_SOURCE_DCO", "scope": "gatedTask", "requiresProperty": "ACME_SOURCE_GATED",
       "file": "mise/config.toml", "tablePath": ["tasks", "lint:dco"]}
    ]},`, "", 1)
	write(t, bare, stripped)

	var stdout, stderr bytes.Buffer

	args := []string{
		"claims", "--policy", bare, "--repo", "acme/widget", "--branch", "main", "--snapshot", f.snapshot,
	}
	if got := deriveCmd(args, &stdout, &stderr); got != exitRefused {
		t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, exitRefused, stderr.String())
	}

	if !strings.Contains(stderr.String(), "declares no source.claims table") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

// End to end: the payload lands on stdout in the shape the emitter
// decodes, and its own decoder accepts it.
func TestDeriveClaimsEndToEnd(t *testing.T) {
	f := newClaimsFixture(t)

	var stdout, stderr bytes.Buffer

	if got := deriveCmd(f.args(), &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	payload, err := jsonx.DecodeBytes[claims.Payload](stdout.Bytes())
	if err != nil {
		t.Fatalf("the emitter's decoder refused what derive wrote: %v", err)
	}

	if err := payload.Validate(); err != nil {
		t.Fatalf("Validate = %v", err)
	}

	got := payload.Properties()
	if !got["ACME_SOURCE_GATED"] || !got["ACME_SOURCE_DCO"] {
		t.Fatalf("claimed %v, want both properties", got)
	}
}

// --out writes the same document to a file, which is how the calling
// workflow hands it across the job boundary.
func TestDeriveClaimsWritesOut(t *testing.T) {
	f := newClaimsFixture(t)
	out := filepath.Join(t.TempDir(), "claims.json")

	var stdout, stderr bytes.Buffer

	if got := deriveCmd(f.args("--out", out), &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	body, err := os.ReadFile(out) //nolint:gosec // the path is this test's own temp dir
	if err != nil {
		t.Fatal(err)
	}

	if _, err := jsonx.DecodeBytes[claims.Payload](body); err != nil {
		t.Fatalf("the written payload is not one the emitter accepts: %v", err)
	}
}

// A blind read reaches the command surface as a refusal, not as an
// empty claim set that looks like a total lapse.
func TestDeriveClaimsBlindReadRefuses(t *testing.T) {
	f := newClaimsFixture(t)
	write(t, filepath.Join(f.snapshot, "acme", "widget", "rules", "branches", "main.json"), `[]`)

	var stdout, stderr bytes.Buffer

	if got := deriveCmd(f.args(), &stdout, &stderr); got != exitRefused {
		t.Fatalf("deriveCmd = %d, want %d", got, exitRefused)
	}

	if !strings.Contains(stderr.String(), "blind read") {
		t.Fatalf("stderr = %q, want the blind-read refusal", stderr.String())
	}

	if stdout.Len() != 0 {
		t.Fatalf("a refused derivation still wrote a payload: %q", stdout.String())
	}
}

// The reviewed tree is a root, not a starting point: a policy-declared
// path that climbs out of it is refused rather than followed. A policy
// is data, and data does not get to name a file outside the tree the
// caller vouched for.
func TestTreeDirConfinesReads(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "inside.toml"), "[tasks]\n")
	write(t, filepath.Join(filepath.Dir(root), "outside.toml"), "[tasks]\n")

	tree := treeDir{root: root, ref: "r"}

	if _, ok, err := tree.File("inside.toml"); err != nil || !ok {
		t.Fatalf("File(inside) = %v, %v", ok, err)
	}

	if _, _, err := tree.File("../outside.toml"); err == nil {
		t.Fatal("File(../outside.toml) = nil error, want a refusal")
	}

	if _, ok, err := tree.File("absent.toml"); err != nil || ok {
		t.Fatalf("File(absent) = %v, %v — absence is an answer, not an error", ok, err)
	}
}
