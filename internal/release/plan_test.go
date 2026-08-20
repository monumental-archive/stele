// The plan's own table. Every row is a repository state the release
// path actually reaches, and the two refusals are the states that burn
// something irreversible — an immutable version number, or a set of
// published mirrors. A refusal that does not fire looks exactly like a
// clean release until the tag exists.

package release_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/release"
)

func version(t *testing.T, s string) *semver.Version {
	t.Helper()

	v, err := semver.StrictNewVersion(s)
	if err != nil {
		t.Fatalf("StrictNewVersion(%q): %v", s, err)
	}

	return v
}

// tree writes the named files into a fresh root and returns it.
func tree(t *testing.T, paths ...string) string {
	t.Helper()

	root := t.TempDir()

	for _, path := range paths {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(full, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return root
}

// inputs is a releasing plan's inputs, for a row to vary one thing.
func inputs(t *testing.T, root string) *release.Inputs {
	t.Helper()

	return &release.Inputs{
		Root: root, Next: version(t, "0.16.0"), Base: version(t, "0.15.0"),
		TagPrefix: "v", AppliedBump: "minor", RequestedBump: "minor",
		Notes: "## 0.16.0\n", Subject: "chore: release v" + release.VersionToken,
		Branch: "release/next", Staging: "release-staging/next",
	}
}

func TestAssemble(t *testing.T) {
	for _, tc := range []struct {
		name   string
		files  []string
		mutate func(*release.Inputs)
		want   func(*testing.T, *release.Plan)
	}{
		{
			name:  "the release commit carries the mirrors, the changelog and the caller's extras",
			files: []string{"Cargo.toml", "CITATION.cff", "CHANGELOG.md", "Cargo.lock"},
			mutate: func(in *release.Inputs) {
				in.MirrorFiles = []string{"Cargo.toml", "CITATION.cff"}
				in.MirrorsFound = true
				in.MirrorVersion = "0.15.0"
				in.Changelog = "CHANGELOG.md"
				in.Also = []string{"Cargo.lock"}
			},
			want: func(t *testing.T, p *release.Plan) {
				t.Helper()

				want := []string{"CHANGELOG.md", "CITATION.cff", "Cargo.lock", "Cargo.toml"}
				if strings.Join(p.Commit.Additions, ",") != strings.Join(want, ",") {
					t.Errorf("additions = %v, want %v", p.Commit.Additions, want)
				}

				if len(p.Commit.Deletions) != 0 {
					t.Errorf("deletions = %v, want none", p.Commit.Deletions)
				}

				if p.Commit.Subject != "chore: release v0.16.0" {
					t.Errorf("subject = %q", p.Commit.Subject)
				}
			},
		},
		{
			// The old half of a rename: named by the release and gone
			// from the tree, so the commit must carry it as a deletion
			// or the rename never lands.
			name:  "a named path the tree no longer has rides as a deletion",
			files: []string{"CHANGELOG.md"},
			mutate: func(in *release.Inputs) {
				in.Changelog = "CHANGELOG.md"
				in.Also = []string{"sql/ext--0.15.0--next.sql"}
			},
			want: func(t *testing.T, p *release.Plan) {
				t.Helper()

				if len(p.Commit.Deletions) != 1 || p.Commit.Deletions[0] != "sql/ext--0.15.0--next.sql" {
					t.Errorf("deletions = %v, want the vanished path", p.Commit.Deletions)
				}
			},
		},
		{
			name: "a range that releases nothing is a plan, not a refusal",
			mutate: func(in *release.Inputs) {
				in.Next = nil
			},
			want: func(t *testing.T, p *release.Plan) {
				t.Helper()

				switch {
				case p.Release:
					t.Error("a quiet range planned a release")
				case len(p.Refusals) != 0:
					t.Errorf("refusals = %v, want none — a quiet range is no defect", p.Refusals)
				case p.Commit != nil || p.Branch != nil:
					t.Error("a plan that releases nothing carries instructions")
				}
			},
		},
		{
			// The maintenance-branch case: the base is the highest
			// version REACHABLE, so the namespace can carry a higher
			// one this derivation cannot see.
			name: "a name the namespace already carries is refused",
			mutate: func(in *release.Inputs) {
				in.Taken = []*semver.Version{version(t, "0.15.0"), version(t, "0.16.0")}
			},
			want: refusedWith(release.CauseTagTaken, "would name one release twice"),
		},
		{
			name: "mirrors that moved on their own are refused",
			mutate: func(in *release.Inputs) {
				in.MirrorsFound = true
				in.MirrorVersion = "0.14.7"
			},
			want: refusedWith(release.CauseMirrorDrift, "the last release is 0.15.0"),
		},
		{
			name: "mirrors ahead of any release are refused",
			mutate: func(in *release.Inputs) {
				in.Base = nil
				in.MirrorsFound = true
				in.MirrorVersion = "9.9.9"
			},
			want: refusedWith(release.CauseMirrorDrift, "nothing released them"),
		},
		{
			// A release step must be safe to repeat: mirrors already
			// carrying the version being cut are the release being cut,
			// not drift.
			name:  "mirrors already carrying this release are a re-run",
			files: []string{"Cargo.toml"},
			mutate: func(in *release.Inputs) {
				in.MirrorsFound = true
				in.MirrorVersion = "0.16.0"
				in.MirrorFiles = []string{"Cargo.toml"}
			},
			want: func(t *testing.T, p *release.Plan) {
				t.Helper()

				if !p.Release {
					t.Errorf("a re-run was refused: %v", p.Refusals)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := inputs(t, tree(t, tc.files...))
			tc.mutate(in)

			plan, err := release.Assemble(in)
			if err != nil {
				t.Fatalf("Assemble: %v", err)
			}

			if plan.Schema != release.Schema {
				t.Errorf("schema = %d, want %d", plan.Schema, release.Schema)
			}

			tc.want(t, plan)
		})
	}
}

// The other question: inputs that make a plan impossible to STATE.
// These are errors with no document, where a forbidding tree state is
// a document — "I cannot say" and "the answer is no" are not the same
// answer, and an executor handed the wrong one acts on it.
func TestAssembleInputErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		files  []string
		mutate func(*release.Inputs)
		want   string
	}{
		{
			name: "a subject naming no version",
			mutate: func(in *release.Inputs) {
				in.Subject = "chore: release"
			},
			want: "names no {version}",
		},
		{
			name:  "a directory is not a release commit's content",
			files: []string{"sql/keep"},
			mutate: func(in *release.Inputs) {
				in.Also = []string{"sql"}
			},
			want: "is a directory",
		},
		{
			name: "an absolute path names something no commit can carry",
			mutate: func(in *release.Inputs) {
				in.Also = []string{"/etc/passwd"}
			},
			want: "not a path inside the tree",
		},
		{
			name: "a path climbing out of the tree is the same defect",
			mutate: func(in *release.Inputs) {
				in.Also = []string{"../elsewhere/Cargo.toml"}
			},
			want: "not a path inside the tree",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := inputs(t, tree(t, tc.files...))
			tc.mutate(in)

			_, err := release.Assemble(in)
			if err == nil {
				t.Fatalf("Assemble was accepted, want an error mentioning %q", tc.want)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Assemble error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// refusedWith asserts a refused plan: the named cause, the detail, and
// no instructions an executor could half-run.
func refusedWith(cause, detail string) func(*testing.T, *release.Plan) {
	return func(t *testing.T, p *release.Plan) {
		t.Helper()

		if p.Release {
			t.Fatal("the plan releases despite the refusal")
		}

		if p.Commit != nil || p.Branch != nil || p.Version != "" {
			t.Error("a refused plan carries instructions — a partial plan is one an executor can half-run")
		}

		for _, r := range p.Refusals {
			if r.Cause == cause && strings.Contains(r.Detail, detail) {
				return
			}
		}

		t.Fatalf("refusals = %+v, want %s naming %q", p.Refusals, cause, detail)
	}
}

// Assemble reads; it never writes. A plan that acted while being
// computed could not be computed twice, which is the property the tag
// leg and the pull-request leg both depend on.
func TestAssembleWritesNothing(t *testing.T) {
	root := tree(t, "Cargo.toml", "CHANGELOG.md")

	before, err := os.ReadFile(filepath.Join(root, "Cargo.toml")) //nolint:gosec // a path this test just wrote
	if err != nil {
		t.Fatal(err)
	}

	in := inputs(t, root)
	in.MirrorFiles = []string{"Cargo.toml"}
	in.MirrorsFound = true
	in.MirrorVersion = "0.15.0"
	in.Changelog = "CHANGELOG.md"

	first, err := release.Assemble(in)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	second, err := release.Assemble(in)
	if err != nil {
		t.Fatalf("Assemble twice: %v", err)
	}

	after, err := os.ReadFile(filepath.Join(root, "Cargo.toml")) //nolint:gosec // a path this test just wrote
	if err != nil {
		t.Fatal(err)
	}

	switch {
	case !bytes.Equal(before, after):
		t.Error("Assemble wrote to the tree")
	case first.Commit.Subject != second.Commit.Subject:
		t.Error("two assemblies of one state disagree")
	}
}

// A nil input set is a caller holding it wrong, not a plan.
func TestAssembleRefusesNoInputs(t *testing.T) {
	if _, err := release.Assemble(nil); err == nil {
		t.Error("assembling from nothing was accepted")
	}
}
