package emit_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/emit"
	"github.com/monumental-archive/stele/internal/policy"
)

// covered writes a covered-documents directory: name → content, with
// subdirectories where a name carries a slash.
func covered(t *testing.T, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()

	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

// at is a clock stopped at an RFC 3339 instant.
func at(t *testing.T, instant string) func() time.Time {
	t.Helper()

	when, err := time.Parse(time.RFC3339, instant)
	if err != nil {
		t.Fatal(err)
	}

	return func() time.Time { return when }
}

func golden(t *testing.T, name string) []byte {
	t.Helper()

	b, err := os.ReadFile(filepath.Join("testdata", "decision", name)) //nolint:gosec // G304: a fixed fixture path
	if err != nil {
		t.Fatal(err)
	}

	return b
}

// TestDecideGolden: the predicate is byte for byte the record the
// canon's shell signed, for each form, given the same inputs and the
// same clock. The fixtures are the predicates of two real decisions,
// read out of the attestation store on 2026-11-17:
//
//   - release: monumental-archive/stele v0.24.2, subject
//     stele-0.24.2.spdx.json, signed by publish.yml in run
//     monumental-archive/stele/actions/runs/44161784819;
//   - stream: monumental-archive/release-lab's continuous publish,
//     signed by continuous.yml in run
//     monumental-archive/release-lab/actions/runs/44151804193.
func TestDecideGolden(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		in      emit.DecisionInputs
		decided string
		fixture string
	}{
		{
			name: "release",
			in: emit.DecisionInputs{
				Tag: "v0.24.2", Classes: "go-binary",
				Proofs: []emit.Proof{
					{Name: "sbom and advisory triage", Result: "success"},
					{Name: "repro gate", Result: "success"},
				},
			},
			decided: "2026-11-17T19:49:04Z",
			fixture: "release.predicate.golden",
		},
		{
			name: "stream",
			in: emit.DecisionInputs{
				Stream: true, Classes: "oci-image",
				Proofs: []emit.Proof{{Name: "inventory and advisory triage", Result: "success"}},
			},
			decided: "2026-11-17T18:53:10Z",
			fixture: "stream.predicate.golden",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			in := tt.in
			in.Covered = covered(t, map[string]string{"widget.spdx.json": "{}"})

			d, err := emit.Decide(loadPolicy(t), &in, at(t, tt.decided))
			if err != nil {
				t.Fatalf("Decide = %v", err)
			}

			if want := golden(t, tt.fixture); !bytes.Equal(d.Predicate, want) {
				t.Fatalf("predicate:\n got %s\nwant %s", d.Predicate, want)
			}

			if d.PredicateType != "https://acme.example/attestations/release-decision/v1" {
				t.Fatalf("predicate type %q is not the policy's", d.PredicateType)
			}
		})
	}
}

// TestDecideSubjects: the subject lines the record is signed over —
// every covered document in path order, or the planned inventory
// alone, with the extra lines after.
func TestDecideSubjects(t *testing.T) {
	t.Parallel()

	docs := map[string]string{"b.spdx.json": "b", "a.spdx.json": "a", "nested/c.spdx.json": "c"}
	sha := func(s string) string { return chain.SHA256Hex([]byte(s)) }
	image := strings.Repeat("e", 64) + "  registry.example/acme/widget@sha256:" + strings.Repeat("e", 64) + " (amd64)"

	for _, tt := range []struct {
		name string
		in   emit.DecisionInputs
		want []string
	}{
		{
			name: "every covered document, in path order",
			want: []string{sha("a") + "  a.spdx.json", sha("b") + "  b.spdx.json", sha("c") + "  c.spdx.json"},
		},
		{
			// stele#158: a planned inventory decides for itself and
			// names nothing else — a decision naming the others is one
			// decision standing in for the per-artifact ones the plan
			// owes, which the verdict refuses.
			name: "a planned inventory names nothing else (stele#158)",
			in:   emit.DecisionInputs{Inventory: "b.spdx.json"},
			want: []string{sha("b") + "  b.spdx.json"},
		},
		{
			// #859: the stream's per-architecture images ride in the
			// subject list beside the documents, so the store reaches
			// the decision from the registry.
			name: "extra lines follow the documents (#859)",
			in:   emit.DecisionInputs{Inventory: "a.spdx.json", Also: []string{image}},
			want: []string{sha("a") + "  a.spdx.json", image},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			in := tt.in
			in.Tag, in.Classes = "v1.2.3", "go-binary"
			in.Proofs = []emit.Proof{{Name: "repro gate", Result: "success"}}
			in.Covered = covered(t, docs)

			d, err := emit.Decide(loadPolicy(t), &in, fixedNow)
			if err != nil {
				t.Fatalf("Decide = %v", err)
			}

			if want := strings.Join(tt.want, "\n") + "\n"; string(d.Subjects) != want {
				t.Fatalf("subjects:\n%s\nwant:\n%s", d.Subjects, want)
			}
		})
	}
}

// refusalInputs fills a refusal row's unset inputs with a passing
// decision's, so each row states only what it breaks. A tag of "-"
// means none.
func refusalInputs(
	t *testing.T, row *emit.DecisionInputs, docs map[string]string, ok []emit.Proof,
) emit.DecisionInputs {
	t.Helper()

	in := *row

	if docs == nil {
		docs = map[string]string{"widget.spdx.json": "{}"}
	}

	if in.Proofs == nil {
		in.Proofs = ok
	}

	switch in.Tag {
	case "":
		in.Tag = "v1.2.3"
	case "-":
		in.Tag = ""
	}

	if in.Classes == "" {
		in.Classes = "go-binary"
	}

	if in.Covered == "" {
		in.Covered = covered(t, docs)
	}

	return in
}

// TestDecideRefusals: every guard branch, each asserting its message.
// The shell's own refusals keep their meaning: a proof that is not
// success, and a covered set that is empty or lacks the planned
// inventory.
func TestDecideRefusals(t *testing.T) {
	t.Parallel()

	ok := []emit.Proof{{Name: "sbom and advisory triage", Result: "success"}}

	for _, tt := range []struct {
		name    string
		in      emit.DecisionInputs
		docs    map[string]string
		arrange func(t *testing.T, dir string)
		policy  func(t *testing.T) *policy.Policy
		want    string
	}{
		{
			name: "a failed proof",
			in: emit.DecisionInputs{Proofs: []emit.Proof{
				{Name: "sbom and advisory triage", Result: "success"}, {Name: "repro gate", Result: "failure"},
			}},
			want: "repro gate is 'failure' — absence of a proof is never a proof",
		},
		{
			name: "a skipped proof",
			in:   emit.DecisionInputs{Proofs: []emit.Proof{{Name: "repro gate", Result: "skipped"}}},
			want: "repro gate is 'skipped' — absence of a proof is never a proof",
		},
		{
			name: "every failing proof is named",
			in: emit.DecisionInputs{Proofs: []emit.Proof{
				{Name: "sbom and advisory triage", Result: "cancelled"}, {Name: "repro gate", Result: ""},
			}},
			want: "sbom and advisory triage is 'cancelled' — absence of a proof is never a proof; " +
				"repro gate is '' — absence of a proof is never a proof",
		},
		{
			name: "no proof at all",
			in:   emit.DecisionInputs{Proofs: []emit.Proof{}},
			want: "no required proof is named — absence of a proof is never a proof",
		},
		{
			name: "an unnamed proof",
			in:   emit.DecisionInputs{Proofs: []emit.Proof{{Name: " ", Result: "success"}}},
			want: "a required proof has no name",
		},
		{
			name: "a proof named twice",
			in:   emit.DecisionInputs{Proofs: []emit.Proof{ok[0], ok[0]}},
			want: `proof "sbom and advisory triage" is named twice`,
		},
		{
			name: "an empty covered set",
			docs: map[string]string{},
			want: "is empty — a decision over nothing decides nothing",
		},
		{
			name: "the named inventory absent",
			in:   emit.DecisionInputs{Inventory: "missing.spdx.json"},
			want: "the plan names missing.spdx.json but the covered set does not carry it",
		},
		{
			name: "the named inventory twice",
			in:   emit.DecisionInputs{Inventory: "w.spdx.json"},
			docs: map[string]string{"w.spdx.json": "1", "sub/w.spdx.json": "2"},
			want: "the covered set carries w.spdx.json 2 times",
		},
		{
			// A listing that errored must never read as an empty
			// covered set — the canon's shell moved its `find` into its
			// own statement for exactly this.
			name: "the covered set cannot be listed",
			arrange: func(t *testing.T, dir string) {
				t.Helper()

				locked := filepath.Join(dir, "locked")
				if err := os.Mkdir(locked, 0o700); err != nil {
					t.Fatal(err)
				}

				if err := os.Chmod(locked, 0o000); err != nil {
					t.Fatal(err)
				}

				t.Cleanup(func() { _ = os.Chmod(locked, 0o700) }) //nolint:gosec,errcheck // G302: test cleanup
			},
			want: "listing the covered set",
		},
		{
			name: "the covered set is absent",
			in:   emit.DecisionInputs{Covered: "/nonexistent/covered"},
			want: "listing the covered set",
		},
		{
			name: "a covered document cannot be read",
			arrange: func(t *testing.T, dir string) {
				t.Helper()

				if err := os.Chmod(filepath.Join(dir, "widget.spdx.json"), 0o000); err != nil {
					t.Fatal(err)
				}
			},
			want: "covered document",
		},
		{
			name: "a malformed extra line",
			in:   emit.DecisionInputs{Also: []string{"abc  name"}},
			want: "subject line \"abc  name\" is not `<sha256>  <name>`",
		},
		{
			name: "both a tag and a stream",
			in:   emit.DecisionInputs{Stream: true},
			want: "a release tag or for a stream, never both",
		},
		{
			name: "neither a tag nor a stream",
			in:   emit.DecisionInputs{Tag: "-"},
			want: "a decision names its subject: a release tag, or a stream",
		},
		{
			name: "no classes",
			in:   emit.DecisionInputs{Classes: " "},
			want: "a decision names the classes it publishes",
		},
		{
			name: "no trust.decision in the policy",
			policy: func(t *testing.T) *policy.Policy {
				t.Helper()

				p := loadPolicy(t)
				p.Trust.Decision = nil

				return p
			},
			want: "the policy declares no trust.decision",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			in := refusalInputs(t, &tt.in, tt.docs, ok)

			if tt.arrange != nil {
				tt.arrange(t, in.Covered)
			}

			p := loadPolicy(t)
			if tt.policy != nil {
				p = tt.policy(t)
			}

			d, err := emit.Decide(p, &in, fixedNow)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Decide = %v, %v; want it to mention %q", d, err, tt.want)
			}
		})
	}
}
