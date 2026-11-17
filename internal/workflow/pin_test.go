// The signer-pin derivation's table (stele#392, .github#314): a tree
// states its trusted signer once, by the `uses:` line the platform
// runs, and the digest a verifier pins is derived from that line. One
// row per guard, each asserting the message — the two refusals keep
// the wording the canon's shell printed, so a reader of an old log and
// a new one read the same sentence.

package workflow_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/workflow"
)

const (
	signer = "monumental-archive/signer/.github/workflows/sign.yml"
	pinA   = "adfe82d191c3ae605c76c9dc22f6ad081efc4f5d"
	pinB   = "0123456789abcdef0123456789abcdef01234567"
)

// call renders a workflow file with one job per uses: value.
func call(uses ...string) []byte {
	var b strings.Builder

	b.WriteString("on: workflow_call\njobs:\n")

	for i, u := range uses {
		b.WriteString("  call" + strconv.Itoa(i) + ":\n    uses: " + u + "\n")
	}

	return []byte(b.String())
}

func TestPinnedCommitDerives(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		files []workflow.File
	}{
		{
			"one file pinning one digest",
			[]workflow.File{{Name: "publish.yml", Content: call(signer + "@" + pinA)}},
		},
		{
			"the same digest in two files and twice in one — one statement, restated",
			[]workflow.File{
				{Name: "publish.yml", Content: call(signer+"@"+pinA, signer+"@"+pinA)},
				{Name: "continuous.yml", Content: call(signer + "@" + pinA)},
				{Name: "ci.yml", Content: []byte("on: push\njobs:\n  test:\n    runs-on: x\n    steps: []\n")},
			},
		},
		{
			"owner and repository compare without case, as the platform resolves them",
			[]workflow.File{{Name: "publish.yml", Content: call(
				"Monumental-Archive/Signer/.github/workflows/sign.yml@" + pinA,
			)}},
		},
		{
			"a comment and a run: string naming another digest are not calls",
			[]workflow.File{{Name: "publish.yml", Content: []byte(
				"on: push\n# uses: " + signer + "@" + pinB + "\njobs:\n" +
					"  echo:\n    runs-on: x\n    steps:\n      - run: echo " + signer + "@" + pinB + "\n" +
					"  sign:\n    uses: " + signer + "@" + pinA + "\n",
			)}},
		},
		{
			"a local call to a file of the same name is the caller's own workflow, not the signer",
			[]workflow.File{{Name: "publish.yml", Content: call(
				"./.github/workflows/sign.yml", signer+"@"+pinA,
			)}},
		},
		{
			"a call to another repository's workflow of the same name is not the signer",
			[]workflow.File{{Name: "publish.yml", Content: call(
				"someone-else/signer/.github/workflows/sign.yml@"+pinB, signer+"@"+pinA,
			)}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := workflow.PinnedCommit(tt.files, signer, "the tree")
			if err != nil {
				t.Fatalf("PinnedCommit = %v", err)
			}

			if got != pinA {
				t.Fatalf("PinnedCommit = %q, want %q", got, pinA)
			}
		})
	}
}

func TestPinnedCommitRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		files  []workflow.File
		target string
		want   string
	}{
		{
			"no call at all — the verify-signed and verify-release `none` refusal",
			[]workflow.File{{Name: "ci.yml", Content: []byte("on: push\njobs: {}\n")}},
			signer,
			"the tree pins no sign.yml uses: — nothing to derive the signer digest from",
		},
		{
			"an empty tree",
			nil,
			signer,
			"the tree pins no sign.yml uses: — nothing to derive the signer digest from",
		},
		{
			"two digests — the `more than one` refusal, both named, sorted",
			[]workflow.File{
				{Name: "publish.yml", Content: call(signer + "@" + pinA)},
				{Name: "continuous.yml", Content: call(signer + "@" + pinB)},
			},
			signer,
			"the tree pins sign.yml at more than one digest — a tree states the trusted signer once: " +
				pinB + " " + pinA,
		},
		{
			"a branch is not a pin",
			[]workflow.File{{Name: "publish.yml", Content: call(signer+"@"+pinA, signer+"@main")}},
			signer,
			`the tree calls sign.yml at "main" (publish.yml, jobs.call1), which is not a commit — ` +
				"a tree pins the trusted signer by its full commit",
		},
		{
			"a short commit is not a pin",
			[]workflow.File{{Name: "publish.yml", Content: call(signer + "@" + pinA[:12])}},
			signer,
			`the tree calls sign.yml at "` + pinA[:12] + `" (publish.yml, jobs.call0), which is not a commit`,
		},
		{
			"a file the reader cannot understand",
			[]workflow.File{{Name: "broken.yml", Content: []byte("jobs: [\n")}},
			signer,
			"broken.yml: workflow: ",
		},
		{
			"a job-level uses: the reader cannot parse",
			[]workflow.File{{Name: "publish.yml", Content: call("monumental-archive/signer/sign.yml")}},
			signer,
			"publish.yml: jobs.call0.uses: a remote workflow call names a ref after `@`",
		},
		{
			"a target that is not owner/repo/path",
			nil,
			"./.github/workflows/sign.yml",
			`workflow: "./.github/workflows/sign.yml" is not owner/repo/path`,
		},
		{
			"a target with too few segments",
			nil,
			"monumental-archive/signer",
			`workflow: "monumental-archive/signer" is not owner/repo/path`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := workflow.PinnedCommit(tt.files, tt.target, "the tree")
			if err == nil {
				t.Fatalf("PinnedCommit = %q, want a refusal", got)
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("PinnedCommit refused with\n  %v\nwant it to say\n  %s", err, tt.want)
			}
		})
	}
}
