// The permissions join's table: one row per way a call can fail to
// be judged, because a guard that skips when it should fire looks
// exactly like a green check. The shape under test throughout is the
// one the Python this replaces could not express — a local call
// resolved against the CALLER's own tree rather than against the
// shared one.

package assert_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/workflow"
)

const permissionsPolicyJSON = `{
  "schema": 7,
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

// localOnlyPolicyJSON declares no reusable tree: the adopter whose
// reusable workflows all live beside their callers.
const localOnlyPolicyJSON = `{
  "schema": 7,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}
  },
  "permissions": {"callerDirs": [".github/workflows"]}
}`

// The shared tree's one reusable workflow: two jobs, so the
// requirement is genuinely a union.
const sharedCallee = `
on:
  workflow_call:
permissions: {}
jobs:
  build:
    permissions:
      contents: read
  attest:
    permissions:
      id-token: write
      contents: read
`

func loadPermissionsPolicy(t *testing.T, doc string) *assert.Policy {
	t.Helper()

	p, err := assert.LoadPolicy(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	return p
}

func file(name, content string) workflow.File {
	return workflow.File{Name: name, Content: []byte(content)}
}

// callers wraps one caller file as the checkout's workflow directory.
func callers(files ...workflow.File) []assert.CallerSet {
	return []assert.CallerSet{{Origin: ".github/workflows", Dir: ".github/workflows", Files: files}}
}

func sharedTree() []workflow.File { return []workflow.File{file("ci.yml", sharedCallee)} }

func runPermissions(t *testing.T, pol *assert.Policy, tree []workflow.File, sets []assert.CallerSet) *report.Report {
	t.Helper()

	rep, err := assert.Permissions(pol, "acme/widget", tree, sets, report.NewJournal(), func(string, ...any) {})
	if err != nil {
		t.Fatalf("Permissions = %v", err)
	}

	return rep
}

// only returns the single finding a row expects, refusing anything
// else: a row that meant to see one defect and saw two saw a
// different run.
func only(t *testing.T, rep *report.Report) report.Finding {
	t.Helper()

	findings := rep.Findings()
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", findings)
	}

	return findings[0]
}

// assertFact reads one fact off the sealed document. The report
// package exports no decoder by design — a consumer re-seals from
// parts rather than believing a verdict field — so the test reads the
// wire bytes the way any other consumer would.
func assertFact(t *testing.T, rep *report.Report, name, want string) {
	t.Helper()

	var buf bytes.Buffer
	if err := rep.Encode(&buf); err != nil {
		t.Fatalf("Encode = %v", err)
	}

	doc, err := jsonx.DecodeForeign[struct {
		Facts []report.Fact `json:"facts"`
	}](buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, f := range doc.Facts {
		if f.Name == name {
			if f.Value != want {
				t.Fatalf("fact %s = %q, want %q", name, f.Value, want)
			}

			return
		}
	}

	t.Fatalf("fact %s is absent from %+v", name, doc.Facts)
}

const grantingCaller = `
on: push
permissions: {}
jobs:
  ci:
    permissions:
      contents: read
      id-token: write
    uses: acme/shared/.github/workflows/ci.yml@abc123
`

func TestPermissionsSufficientGrantPasses(t *testing.T) {
	t.Parallel()

	rep := runPermissions(t, loadPermissionsPolicy(t, permissionsPolicyJSON), sharedTree(),
		callers(file("gate.yml", grantingCaller)))

	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS: %+v", rep.Verdict(), rep.Findings())
	}
}

func TestPermissionsFindings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		caller    string
		tree      []workflow.File
		assertion string
		detail    string
	}{
		{
			name: "a caller short one scope is the whole point of the join",
			caller: "jobs:\n  ci:\n    permissions:\n      contents: read\n" +
				"    uses: acme/shared/.github/workflows/ci.yml@abc\n",
			tree: sharedTree(), assertion: "caller-grant", detail: "startup failure",
		},
		{
			name:   "a callee the shared tree does not hold",
			caller: "jobs:\n  ci:\n    uses: acme/shared/.github/workflows/ghost.yml@abc\n",
			tree:   sharedTree(), assertion: "callee-absent", detail: "unrecognised callee is an unchecked grant",
		},
		{
			name:      "a callee that declares no workflow_call trigger",
			caller:    "jobs:\n  ci:\n    uses: acme/shared/.github/workflows/ci.yml@abc\n",
			tree:      []workflow.File{file("ci.yml", "on: push\njobs: {}\n")},
			assertion: "callee-not-callable", detail: "cannot start at all",
		},
		{
			name:      "a callee whose file will not parse",
			caller:    "jobs:\n  ci:\n    uses: acme/shared/.github/workflows/ci.yml@abc\n",
			tree:      []workflow.File{file("ci.yml", "permissions:\n  contents: sideways\n")},
			assertion: "callee-unreadable", detail: "what it asks of this caller is unknown",
		},
		{
			name:   "a call shape the join cannot read",
			caller: "jobs:\n  ci:\n    uses: acme/shared/.github/workflows/ci.yml\n",
			tree:   sharedTree(), assertion: "call-shape", detail: "unchecked grant",
		},
		{
			name:   "a call naming the declared repository outside its declared tree",
			caller: "jobs:\n  ci:\n    uses: acme/shared/elsewhere/ci.yml@abc\n",
			tree:   sharedTree(), assertion: "call-shape", detail: "outside the tree this run holds",
		},
		{
			name:   "a local call naming a directory this run does not hold for the set",
			caller: "jobs:\n  ci:\n    uses: ./elsewhere/ci.yml\n",
			tree:   sharedTree(), assertion: "call-shape", detail: "outside the tree this run holds",
		},
		{
			name:   "a caller file that will not parse",
			caller: "permissions:\n\tcontents: read\n",
			tree:   sharedTree(), assertion: "workflow-shape", detail: "the workflow does not read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rep := runPermissions(t, loadPermissionsPolicy(t, permissionsPolicyJSON), tt.tree,
				callers(file("gate.yml", tt.caller)))

			if rep.Verdict() != report.VerdictFail {
				t.Fatalf("verdict = %s, want FAIL", rep.Verdict())
			}

			f := only(t, rep)
			if f.Assertion != tt.assertion {
				t.Fatalf("assertion = %q, want %q (%+v)", f.Assertion, tt.assertion, f)
			}

			if !strings.Contains(f.Detail, tt.detail) {
				t.Fatalf("detail = %q, want it to name %q", f.Detail, tt.detail)
			}
		})
	}
}

// TestPermissionsNamesEveryMissingScope: a caller job with no block
// of its own takes the workflow-level default, and every scope it
// falls short on is named. One finding per missing scope, because a
// caller fixing the first would otherwise return to the same red.
func TestPermissionsNamesEveryMissingScope(t *testing.T) {
	t.Parallel()

	caller := file("gate.yml", "permissions: {}\njobs:\n  ci:\n    uses: acme/shared/.github/workflows/ci.yml@abc\n")

	rep := runPermissions(t, loadPermissionsPolicy(t, permissionsPolicyJSON), sharedTree(), callers(caller))

	var named []string
	for _, f := range rep.Findings() {
		if f.Assertion != "caller-grant" {
			t.Fatalf("finding = %+v, want caller-grant", f)
		}

		named = append(named, f.Expected)
	}

	if strings.Join(named, "; ") != "contents: read; id-token: write" {
		t.Fatalf("findings named %v, want every scope the callee's jobs ask for, in scope order", named)
	}
}

// TestPermissionsLocalCallResolvesInTheCallersOwnTree is the defect
// the Python carried: a `./` call in a consumer was looked up in the
// SHARED tree, so a repository calling its own reusable workflow was
// reported as calling a workflow that does not exist. The call is
// judged here, against the caller's own file.
func TestPermissionsLocalCallResolvesInTheCallersOwnTree(t *testing.T) {
	t.Parallel()

	own := file("secret-scan.yml",
		"on:\n  workflow_call:\npermissions:\n  contents: read\njobs:\n  scan:\n    runs-on: x\n")

	short := file("ci.yml", "permissions: {}\njobs:\n  scan:\n    uses: ./.github/workflows/secret-scan.yml\n")
	ok := file("ci.yml", "permissions:\n  contents: read\njobs:\n  scan:\n    uses: ./.github/workflows/secret-scan.yml\n")

	pol := loadPermissionsPolicy(t, permissionsPolicyJSON)

	if rep := runPermissions(t, pol, sharedTree(), callers(ok, own)); rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS — the callee is the caller's own file: %+v", rep.Verdict(), rep.Findings())
	}

	rep := runPermissions(t, pol, sharedTree(), callers(short, own))
	if f := only(t, rep); f.Assertion != "caller-grant" || f.Expected != "contents: read" {
		t.Fatalf("finding = %+v, want the under-grant against the caller's own callee", f)
	}
}

// TestPermissionsOtherRepositoriesAreOutsideTheDeclaredScope: a
// sibling's reusable workflow is not this run's to judge — no tree
// for it was declared — but it is counted rather than silently
// invisible.
func TestPermissionsOtherRepositoriesAreOutsideTheDeclaredScope(t *testing.T) {
	t.Parallel()

	caller := file("gate.yml", "jobs:\n  sign:\n    uses: acme/signer/.github/workflows/sign.yml@abc\n")

	rep := runPermissions(t, loadPermissionsPolicy(t, permissionsPolicyJSON), sharedTree(), callers(caller))
	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS: %+v", rep.Verdict(), rep.Findings())
	}

	assertFact(t, rep, "callsOutsideDeclaredTrees", "1")
	assertFact(t, rep, "callsChecked", "0")
}

// TestPermissionsBlanketAsk: a callee asking for a blanket grant is
// answered by a blanket grant alone. Proving an enumerated caller
// sufficient would need the platform's full scope list, which this
// tool refuses to hardcode — so it says so rather than guessing.
func TestPermissionsBlanketAsk(t *testing.T) {
	t.Parallel()

	tree := []workflow.File{file("ci.yml", "on:\n  workflow_call:\njobs:\n  a:\n    permissions: read-all\n")}
	pol := loadPermissionsPolicy(t, permissionsPolicyJSON)

	enumerated := file("gate.yml",
		"jobs:\n  ci:\n    permissions:\n      contents: read\n    uses: acme/shared/.github/workflows/ci.yml@abc\n")

	rep := runPermissions(t, pol, tree, callers(enumerated))

	f := only(t, rep)
	if f.Assertion != "caller-grant" || !strings.Contains(f.Detail, "full scope list") {
		t.Fatalf("finding = %+v, want the blanket-ask refusal", f)
	}

	blanket := file("gate.yml",
		"jobs:\n  ci:\n    permissions: write-all\n    uses: acme/shared/.github/workflows/ci.yml@abc\n")
	if rep := runPermissions(t, pol, tree, callers(blanket)); rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS — a blanket grant covers a blanket ask: %+v", rep.Verdict(), rep.Findings())
	}
}

// TestPermissionsEmptyPopulationCannotJudge: the population rule. A
// run that examined no workflow file did not find a clean tree, it
// found nothing — which is what a wrong path, an empty checkout or a
// narrowed credential all look like.
func TestPermissionsEmptyPopulationCannotJudge(t *testing.T) {
	t.Parallel()

	for _, sets := range [][]assert.CallerSet{nil, {{Origin: "acme/ghost", Dir: ".github/workflows"}}} {
		rep := runPermissions(t, loadPermissionsPolicy(t, permissionsPolicyJSON), sharedTree(), sets)
		if rep.Verdict() != report.VerdictCannotJudge {
			t.Fatalf("verdict = %s, want CANNOT_JUDGE — a walk over no file judged nothing", rep.Verdict())
		}
	}
}

// TestPermissionsLocalOnlyAdopter: an adopter declaring no shared
// tree still gets the join over its own calls, with no tree handed
// in — the universality test, run as a test.
func TestPermissionsLocalOnlyAdopter(t *testing.T) {
	t.Parallel()

	own := file("inner.yml", "on:\n  workflow_call:\njobs:\n  a:\n    permissions:\n      packages: write\n")
	caller := file("outer.yml", "permissions: {}\njobs:\n  a:\n    uses: ./.github/workflows/inner.yml\n")

	rep := runPermissions(t, loadPermissionsPolicy(t, localOnlyPolicyJSON), nil, callers(caller, own))

	f := only(t, rep)
	if f.Assertion != "caller-grant" || f.Expected != "packages: write" {
		t.Fatalf("finding = %+v, want the local under-grant", f)
	}
}

// TestPermissionsRemoteCallWithNoDeclaredTree: with no reusable tree
// declared, a remote call is outside the run's scope rather than a
// defect — the adopter never told this tool that repository was
// theirs.
func TestPermissionsRemoteCallWithNoDeclaredTree(t *testing.T) {
	t.Parallel()

	caller := file("outer.yml", "jobs:\n  a:\n    uses: acme/shared/.github/workflows/ci.yml@abc\n")

	rep := runPermissions(t, loadPermissionsPolicy(t, localOnlyPolicyJSON), nil, callers(caller))
	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS: %+v", rep.Verdict(), rep.Findings())
	}

	assertFact(t, rep, "callsOutsideDeclaredTrees", "1")
}

func TestPermissionsRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		policy string
		tree   []workflow.File
		want   string
	}{
		{"a policy declaring no permissions section", chainsPolicyJSON, sharedTree(), "declares no permissions section"},
		{
			"a declared shared tree this run holds no file from",
			permissionsPolicyJSON, nil, "every call into it would read as absent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := assert.Permissions(loadPermissionsPolicy(t, tt.policy), "acme", tt.tree,
				callers(file("gate.yml", grantingCaller)), report.NewJournal(), func(string, ...any) {})
			if err == nil {
				t.Fatal("Permissions judged an input it could not judge from")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Permissions = %v, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestPermissionsFactsCountTheWalk: the facts are how a reader tells
// "nothing to find" from "nothing was looked at" — a tree read from
// the wrong place holds zero reusable workflows and says so.
func TestPermissionsFactsCountTheWalk(t *testing.T) {
	t.Parallel()

	rep := runPermissions(t, loadPermissionsPolicy(t, permissionsPolicyJSON), sharedTree(),
		callers(file("gate.yml", grantingCaller)))

	assertFact(t, rep, "reusableWorkflows", "1")
	assertFact(t, rep, "callsChecked", "1")
}

// TestPermissionsPolicyRefusals: every declared convention refuses by
// name when it is malformed. A caller directory that could climb out
// of the checkout is refused with the rest — a reviewed policy is
// data, and the run joins these onto an operator-supplied root.
func TestPermissionsPolicyRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		section string
		want    string
	}{
		{"no caller directories", `{"callerDirs": []}`, "a join with no callers judges nothing"},
		{"an absent caller list", `{"reusable": {"repo": "a/b", "dir": "d"}}`, "callerDirs is absent"},
		{"an empty caller directory", `{"callerDirs": [""]}`, "the directory is empty"},
		{"an absolute caller directory", `{"callerDirs": ["/etc"]}`, "is absolute"},
		{"a caller directory climbing out", `{"callerDirs": ["../elsewhere"]}`, "climbs out of the checkout"},
		{"a repeated caller directory", `{"callerDirs": ["a", "a"]}`, "twice — the caller directories are a set"},
		{"a reusable tree with no repo", `{"callerDirs": ["a"], "reusable": {"dir": "d"}}`, "reusable.repo is absent"},
		{
			"a reusable repo that is not owner/name",
			`{"callerDirs": ["a"], "reusable": {"repo": "shared", "dir": "d"}}`, "is not owner/name",
		},
		{
			"a reusable repo carrying a path",
			`{"callerDirs": ["a"], "reusable": {"repo": "a/b/c", "dir": "d"}}`, "is not owner/name",
		},
		{"a reusable tree with no dir", `{"callerDirs": ["a"], "reusable": {"repo": "a/b"}}`, "reusable.dir is absent"},
		{
			"a reusable dir climbing out",
			`{"callerDirs": ["a"], "reusable": {"repo": "a/b", "dir": "../x"}}`, "climbs out of the checkout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := strings.Replace(permissionsPolicyJSON,
				`"permissions": {
    "reusable": {"repo": "acme/shared", "dir": ".github/workflows"},
    "callerDirs": [".github/workflows", "workflow-templates"]
  }`, `"permissions": `+tt.section, 1)

			_, err := assert.LoadPolicy(strings.NewReader(doc))
			if err == nil {
				t.Fatal("LoadPolicy accepted a malformed permissions section")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("LoadPolicy = %v, want it to name %q", err, tt.want)
			}
		})
	}
}
