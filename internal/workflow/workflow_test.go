// The format reader's table: the shapes the platform accepts, the
// shapes it does not, and the two distinctions the whole join turns
// on — absent versus empty, and a blanket grant versus an enumerated
// one.
//
// Several rows are shapes the line scanner this replaces could not
// see: a scalar or sequence `on:`, a blanket `permissions: read-all`,
// a flow mapping, a file written at other indents. They are here
// because "the scanner never met one" is not the same as "no tree
// writes one", and the second is what a universal reader must answer.

package workflow_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/workflow"
)

func TestParseReusableTrigger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  string
		want bool
	}{
		{"a mapping trigger", "on:\n  workflow_call:\njobs: {}\n", true},
		{"a scalar trigger", "on: workflow_call\njobs: {}\n", true},
		{"a sequence trigger", "on: [push, workflow_call]\njobs: {}\n", true},
		{"the quoted key the YAML 1.1 boolean trap forces on some writers", "\"on\":\n  workflow_call:\n", true},
		{"a trigger list without it", "on:\n  push:\n    branches: [main]\n", false},
		{"no triggers at all", "jobs: {}\n", false},
		{"the word in a comment", "on:\n  push: # workflow_call: not here\n", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc, err := workflow.Parse([]byte(tt.doc))
			if err != nil {
				t.Fatalf("Parse = %v", err)
			}

			if doc.Reusable != tt.want {
				t.Fatalf("Reusable = %v, want %v", doc.Reusable, tt.want)
			}
		})
	}
}

func TestParseGrantShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		doc   string
		scope string
		want  workflow.Level
		all   workflow.Level
	}{
		{"an enumerated grant", "permissions:\n  contents: write\n", "contents", workflow.LevelWrite, workflow.LevelNone},
		{"a flow mapping", "permissions: {contents: read}\n", "contents", workflow.LevelRead, workflow.LevelNone},
		{"the empty grant", "permissions: {}\n", "contents", workflow.LevelNone, workflow.LevelNone},
		{"a blanket read", "permissions: read-all\n", "contents", workflow.LevelRead, workflow.LevelRead},
		{"a blanket write", "permissions: write-all\n", "id-token", workflow.LevelWrite, workflow.LevelWrite},
		{"an explicit none", "permissions:\n  contents: none\n", "contents", workflow.LevelNone, workflow.LevelNone},
		{
			"a scope this reader has never heard of, because the platform keeps adding them",
			"permissions:\n  time-travel: write\n", "time-travel", workflow.LevelWrite, workflow.LevelNone,
		},
		{
			"an enumerated scope above the blanket level",
			"permissions: read-all\n", "contents", workflow.LevelRead, workflow.LevelRead,
		},
		{
			"six-space indent, which no scanner assumption survives", "permissions:\n      contents: write\n",
			"contents", workflow.LevelWrite, workflow.LevelNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc, err := workflow.Parse([]byte(tt.doc))
			if err != nil {
				t.Fatalf("Parse = %v", err)
			}

			if doc.Grant == nil {
				t.Fatal("Grant is nil — the block is present, so the grant is not absent")
			}

			if got := doc.Grant.Level(tt.scope); got != tt.want {
				t.Fatalf("Level(%s) = %s, want %s", tt.scope, got, tt.want)
			}

			if got := doc.Grant.All(); got != tt.all {
				t.Fatalf("All() = %s, want %s", got, tt.all)
			}
		})
	}
}

// TestParseAbsentIsNotEmpty holds the distinction every fallback in
// the join reads: a job with no block takes the workflow-level
// default, and one with an empty block does not.
func TestParseAbsentIsNotEmpty(t *testing.T) {
	t.Parallel()

	doc, err := workflow.Parse([]byte(
		"permissions:\n  contents: write\njobs:\n  inherits:\n    runs-on: x\n  restates:\n    permissions: {}\n"))
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}

	if doc.Jobs[0].Grant != nil {
		t.Fatal("a job with no permissions block carries a grant — absent must stay absent")
	}

	if doc.Jobs[1].Grant == nil {
		t.Fatal("a job with `permissions: {}` carries no grant — an empty block is a grant of nothing, not an absent one")
	}

	if got := doc.Effective(&doc.Jobs[0]).Level("contents"); got != workflow.LevelWrite {
		t.Fatalf("the inheriting job holds %s, want the workflow-level write", got)
	}

	if got := doc.Effective(&doc.Jobs[1]).Level("contents"); got != workflow.LevelNone {
		t.Fatalf("the restating job holds %s, want nothing — an empty block overrides the default", got)
	}
}

func TestParseRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"bytes that are not YAML", "permissions:\n\tcontents: read\n", "workflow:"},
		{"a level outside the three", "permissions:\n  contents: readonly\n", "not none, read or write"},
		{"a blanket spelling that is not one", "permissions: all\n", "is not a blanket grant"},
		{"a permissions key with nothing after it", "permissions:\njobs: {}\n", "write `{}` to grant nothing"},
		{"a permissions sequence", "permissions:\n  - contents\n", "neither a blanket level nor a scope mapping"},
		{
			"a trigger list behind a YAML anchor, which the platform does not run",
			"x: &t\n  workflow_call:\non: *t\n", "the platform does not accept anchors",
		},
		{"a scope whose level is a structure", "permissions:\n  contents:\n    - read\n", "not a name/level pair"},
		{"jobs that are not a mapping", "jobs:\n  - build\n", "jobs: is not a mapping"},
		{"a job that is not a mapping", "jobs:\n  build: yes\n", "jobs.build is not a mapping"},
		{"a uses that is not a string", "jobs:\n  build:\n    uses:\n      - a\n", "jobs.build.uses is not a string"},
		{"a job grant the reader cannot read", "jobs:\n  build:\n    permissions: some-all\n", "jobs.build.permissions"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := workflow.Parse([]byte(tt.doc))
			if err == nil {
				t.Fatal("Parse accepted a shape it cannot read — a file read wrongly grants silently")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse = %v, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestRequirementIsTheUnion holds the rule the join rests on: what a
// caller must grant is every job's ask, the `uses:` jobs' restated
// grants included, because a nested callee's ask chains up.
func TestRequirementIsTheUnion(t *testing.T) {
	t.Parallel()

	doc, err := workflow.Parse([]byte(`
on:
  workflow_call:
permissions: {}
jobs:
  build:
    permissions:
      contents: read
      id-token: write
  nested:
    permissions:
      contents: write
      packages: read
    uses: ./.github/workflows/inner.yml
  inherits:
    runs-on: ubuntu-24.04
`))
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}

	req := doc.Requirement()

	for scope, want := range map[string]workflow.Level{
		"contents": workflow.LevelWrite, "id-token": workflow.LevelWrite, "packages": workflow.LevelRead,
	} {
		if got := req.Level(scope); got != want {
			t.Fatalf("Requirement.Level(%s) = %s, want %s", scope, got, want)
		}
	}

	if got := strings.Join(req.Scopes(), ","); got != "contents,id-token,packages" {
		t.Fatalf("Scopes() = %q, want the sorted union", got)
	}
}

// TestRequirementCarriesTheBlanketAsk: a callee job asking for a
// blanket grant makes the whole workflow's requirement a blanket one,
// which the join answers with a blanket grant alone.
func TestRequirementCarriesTheBlanketAsk(t *testing.T) {
	t.Parallel()

	doc, err := workflow.Parse([]byte(
		"jobs:\n  a:\n    permissions:\n      contents: read\n  b:\n    permissions: write-all\n"))
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}

	req := doc.Requirement()
	if got := req.All(); got != workflow.LevelWrite {
		t.Fatalf("All() = %s, want write — one job's blanket ask is the workflow's", got)
	}

	if got := req.Level("contents"); got != workflow.LevelWrite {
		t.Fatalf("Level(contents) = %s, want write — the blanket level covers an enumerated scope below it", got)
	}
}

// TestRequirementNoneAsksNothing: a scope granted `none` is not a
// scope asked for, so it never appears in what a caller must hold.
func TestRequirementNoneAsksNothing(t *testing.T) {
	t.Parallel()

	doc, err := workflow.Parse([]byte("jobs:\n  a:\n    permissions:\n      contents: none\n"))
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}

	if scopes := doc.Requirement().Scopes(); len(scopes) != 0 {
		t.Fatalf("Scopes() = %v, want none — a grant of nothing asks for nothing", scopes)
	}
}

// TestEffectiveWithNoBlockAnywhere: a file that states no grant at
// all is read as granting nothing. The platform would fall back to
// the repository's default, which no file states — so a static read
// that assumed it would be asserting a repository setting it cannot
// see.
func TestEffectiveWithNoBlockAnywhere(t *testing.T) {
	t.Parallel()

	doc, err := workflow.Parse([]byte("jobs:\n  a:\n    runs-on: ubuntu-24.04\n"))
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}

	if got := doc.Effective(&doc.Jobs[0]).Level("contents"); got != workflow.LevelNone {
		t.Fatalf("Level(contents) = %s, want none", got)
	}
}

func TestParseRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		uses  string
		want  workflow.Ref
		fname string
	}{
		{
			"a remote call at a commit",
			"acme/.github/.github/workflows/ci.yml@" + strings.Repeat("a", 40),
			workflow.Ref{
				Owner: "acme", Repo: ".github", Path: ".github/workflows/ci.yml",
				Version: strings.Repeat("a", 40),
			},
			"ci.yml",
		},
		{
			"a remote call at a tag — a ref this join never resolves, so its shape is not its business",
			"acme/shared/.github/workflows/ci.yml@v1.2.3",
			workflow.Ref{Owner: "acme", Repo: "shared", Path: ".github/workflows/ci.yml", Version: "v1.2.3"},
			"ci.yml",
		},
		{
			"a local call",
			"./.github/workflows/publish.yml",
			workflow.Ref{Local: true, Path: ".github/workflows/publish.yml"},
			"publish.yml",
		},
		{
			"a local call naming a bare file, whose whole path is its name",
			"./ci.yml",
			workflow.Ref{Local: true, Path: "ci.yml"},
			"ci.yml",
		},
		{
			"a remote call into a nested path",
			"acme/shared/deep/.github/workflows/ci.yml@main",
			workflow.Ref{
				Owner: "acme", Repo: "shared", Path: "deep/.github/workflows/ci.yml", Version: "main",
			},
			"ci.yml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := workflow.ParseRef(tt.uses)
			if err != nil {
				t.Fatalf("ParseRef = %v", err)
			}

			if got != tt.want {
				t.Fatalf("ParseRef = %+v, want %+v", got, tt.want)
			}

			if got.Name() != tt.fname {
				t.Fatalf("Name() = %q, want %q", got.Name(), tt.fname)
			}
		})
	}
}

func TestParseRefRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		uses string
		want string
	}{
		{"nothing at all", "  ", "the reference is empty"},
		{"a container action", "docker://alpine:3", "names an action"},
		{"an action, which a job may not call", "actions/checkout@v5", "names no workflow path"},
		{"a remote call with no ref", "acme/shared/.github/workflows/ci.yml", "names a ref after `@`"},
		{"a remote call with an empty ref", "acme/shared/.github/workflows/ci.yml@", "the ref after `@` is empty"},
		{"a local call carrying a ref", "./.github/workflows/ci.yml@main", "takes no `@ref`"},
		{"a local call naming nothing", "./", "names no path"},
		{"an empty path segment", "acme//ci.yml@main", "empty path segment"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := workflow.ParseRef(tt.uses)
			if err == nil {
				t.Fatal("ParseRef accepted a reference it cannot resolve — an unreadable call is an unchecked grant")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ParseRef = %v, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestLevelString covers the rendering every finding message reads
// through, including the value no parse can produce — a switch that
// falls through silently would print an empty expectation.
func TestLevelString(t *testing.T) {
	t.Parallel()

	for level, want := range map[workflow.Level]string{
		workflow.LevelNone: "none", workflow.LevelRead: "read", workflow.LevelWrite: "write",
		workflow.Level(9): "level(9)",
	} {
		if got := level.String(); got != want {
			t.Fatalf("Level(%d).String() = %q, want %q", int(level), got, want)
		}
	}
}

// TestMergeNil: folding an absent grant changes nothing, which is
// what lets the union loop stay free of a nil check per job.
func TestMergeNil(t *testing.T) {
	t.Parallel()

	doc, err := workflow.Parse([]byte("permissions:\n  contents: read\n"))
	if err != nil {
		t.Fatalf("Parse = %v", err)
	}

	doc.Grant.Merge(nil)

	if got := doc.Grant.Level("contents"); got != workflow.LevelRead {
		t.Fatalf("Level(contents) = %s, want read", got)
	}
}
