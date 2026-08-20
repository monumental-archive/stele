// `derive release-plan` at the surface: the document, the preparation
// it names, and the refusals that stop both. The mode stands where the
// canon's three release scripts made their decisions, so a refusal
// that does not fire here is a release that proceeds on a tree state
// nobody judged.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/release"
)

// planTree writes a single-crate tree with a changelog, the shape the
// release path runs against.
func planTree(t *testing.T, version string) string {
	t.Helper()

	dir := t.TempDir()

	files := map[string]string{
		"Cargo.toml":   "[package]\nname = \"demo\"\nversion = \"" + version + "\"\n",
		"CHANGELOG.md": "# Changelog\n",
	}

	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

// runPlan invokes the mode and decodes whatever document it wrote.
//
//nolint:gocritic // unnamedResult: the exit code, the plan, then the streams
func runPlan(t *testing.T, dir string, h deriveHistory, extra ...string) (int, *release.Plan, string) {
	t.Helper()

	withHistory(t, h, nil)

	var stdout, stderr bytes.Buffer

	args := append([]string{"release-plan", "--git-dir", dir}, extra...)
	code := deriveCmd(args, &stdout, &stderr)

	var plan *release.Plan

	if body := stdout.String(); strings.HasPrefix(strings.TrimSpace(body), "{") {
		decoded, err := jsonx.DecodeBytes[release.Plan]([]byte(body))
		if err != nil {
			t.Fatalf("the emitted plan does not decode: %v\n%s", err, body)
		}

		plan = decoded
	}

	return code, plan, stderr.String()
}

func TestReleasePlanEmitsTheDecisions(t *testing.T) {
	dir := planTree(t, "0.9.0")

	code, plan, stderr := runPlan(t, dir, bumpHistory(), "--changelog", "CHANGELOG.md")
	if code != exitOK {
		t.Fatalf("release-plan = %d, stderr: %s", code, stderr)
	}

	switch {
	case plan == nil:
		t.Fatal("no plan document reached stdout")
	case !plan.Release:
		t.Fatalf("plan does not release: %+v", plan.Refusals)
	case plan.Version != "0.10.0" || plan.Tag != "v0.10.0" || plan.Base != "0.9.0":
		t.Errorf("version/tag/base = %s/%s/%s", plan.Version, plan.Tag, plan.Base)
	case plan.Commit.Subject != "chore: release v0.10.0":
		t.Errorf("subject = %q", plan.Commit.Subject)
	case plan.Branch.Name != "release/next" || plan.Branch.Staging != "release-staging/next":
		t.Errorf("branch = %+v", plan.Branch)
	case !strings.Contains(plan.Notes, "add a thing"):
		t.Errorf("notes = %q, want the range's own section", plan.Notes)
	case strings.Join(plan.Commit.Additions, ",") != "CHANGELOG.md,Cargo.toml":
		t.Errorf("additions = %v", plan.Commit.Additions)
	}
}

// The plan is safe to compute twice, which is what lets the
// pull-request leg and the tag leg read one document rather than each
// deriving its own.
func TestReleasePlanWritesNothingWithoutPrepare(t *testing.T) {
	dir := planTree(t, "0.9.0")

	if code, _, stderr := runPlan(t, dir, bumpHistory(), "--changelog", "CHANGELOG.md"); code != exitOK {
		t.Fatalf("release-plan = %d, stderr: %s", code, stderr)
	}

	for name, want := range map[string]string{
		"Cargo.toml": "version = \"0.9.0\"", "CHANGELOG.md": "# Changelog\n",
	} {
		got, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // a path this test just wrote
		if err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(string(got), want) {
			t.Errorf("%s was written by a plan that only reads:\n%s", name, got)
		}
	}
}

// --prepare writes exactly what the plan names, and the notes it wrote
// are the notes it emitted: one rendering reaches the changelog a
// reviewer reads and the document a release is published from.
func TestReleasePlanPreparesTheTreeItNames(t *testing.T) {
	dir := planTree(t, "0.9.0")

	code, plan, stderr := runPlan(t, dir, bumpHistory(), "--changelog", "CHANGELOG.md", "--prepare")
	if code != exitOK {
		t.Fatalf("release-plan = %d, stderr: %s", code, stderr)
	}

	cargo, err := os.ReadFile(filepath.Join(dir, "Cargo.toml")) //nolint:gosec // a path this test just wrote
	if err != nil {
		t.Fatal(err)
	}

	changelog, err := os.ReadFile(filepath.Join(dir, "CHANGELOG.md")) //nolint:gosec // a path this test just wrote
	if err != nil {
		t.Fatal(err)
	}

	switch {
	case !strings.Contains(string(cargo), "version = \"0.10.0\""):
		t.Errorf("the mirror did not move:\n%s", cargo)
	case !strings.Contains(string(changelog), strings.TrimRight(plan.Notes, "\n")):
		t.Errorf("the changelog does not carry the plan's own notes:\n%s", changelog)
	}
}

// A declared version reaches the plan by the same decision every other
// mode reads (stele#146), so the number is never spelled twice.
func TestReleasePlanCarriesADeclaredVersion(t *testing.T) {
	dir := planTree(t, "0.9.0")

	code, plan, stderr := runPlan(t, dir, bumpHistory(), "--release-as", "1.0.0")
	if code != exitOK {
		t.Fatalf("release-plan = %d, stderr: %s", code, stderr)
	}

	switch {
	case plan.Version != "1.0.0" || plan.Tag != "v1.0.0":
		t.Errorf("version/tag = %s/%s", plan.Version, plan.Tag)
	case !plan.Bump.Declared:
		t.Error("the plan does not report the version as declared")
	case plan.Bump.Applied != "major" || plan.Bump.Requested != "minor":
		t.Errorf("bump = %+v, want the move described and the range's vote kept", plan.Bump)
	}
}

// Every refusal, and what a refused plan must NOT do: prepare a tree,
// or carry instructions.
func TestReleasePlanRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mirror  string
		history func() *stubHistory
		cause   string
	}{
		{
			name: "mirrors that moved on their own", mirror: "0.8.1",
			history: bumpHistory, cause: release.CauseMirrorDrift,
		},
		{
			name: "a name published on another line of history", mirror: "0.9.0",
			history: func() *stubHistory {
				h := bumpHistory()
				h.allTags = []string{"v0.9.0", "v0.10.0"}

				return h
			},
			cause: release.CauseTagTaken,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := planTree(t, tc.mirror)

			code, plan, stderr := runPlan(t, dir, tc.history(), "--changelog", "CHANGELOG.md", "--prepare")
			if code != exitRefused {
				t.Fatalf("release-plan = %d, want %d\nstderr: %s", code, exitRefused, stderr)
			}

			if plan == nil {
				t.Fatal("a refused run emitted no document — a refused plan is a document saying why")
			}

			if len(plan.Refusals) != 1 || plan.Refusals[0].Cause != tc.cause {
				t.Fatalf("refusals = %+v, want %s", plan.Refusals, tc.cause)
			}

			if plan.Commit != nil {
				t.Error("a refused plan carries instructions")
			}

			cargo, err := os.ReadFile(filepath.Join(dir, "Cargo.toml")) //nolint:gosec // a path this test just wrote
			if err != nil {
				t.Fatal(err)
			}

			if !strings.Contains(string(cargo), "version = \""+tc.mirror+"\"") {
				t.Errorf("a refused plan prepared the tree anyway:\n%s", cargo)
			}
		})
	}
}

// A quiet range plans nothing and prepares nothing — and says so
// rather than exiting like a refusal.
func TestReleasePlanQuietRange(t *testing.T) {
	dir := planTree(t, "0.9.0")
	h := bumpHistory()
	h.messages = map[string]string{"c1": "chore: tidy"}

	code, plan, stderr := runPlan(t, dir, h, "--changelog", "CHANGELOG.md", "--prepare")
	if code != exitOK {
		t.Fatalf("release-plan = %d, stderr: %s", code, stderr)
	}

	switch {
	case plan.Release:
		t.Error("a quiet range planned a release")
	case len(plan.Refusals) != 0:
		t.Errorf("refusals = %+v, want none", plan.Refusals)
	}

	changelog, err := os.ReadFile(filepath.Join(dir, "CHANGELOG.md")) //nolint:gosec // a path this test just wrote
	if err != nil {
		t.Fatal(err)
	}

	if string(changelog) != "# Changelog\n" {
		t.Errorf("a quiet range spliced a section:\n%s", changelog)
	}
}

// The document goes where the caller says, and a plan that cannot be
// placed is an output failure rather than a silent success.
func TestReleasePlanOut(t *testing.T) {
	dir := planTree(t, "0.9.0")
	out := filepath.Join(dir, "plan.json")

	if code, _, stderr := runPlan(t, dir, bumpHistory(), "--out", out); code != exitOK {
		t.Fatalf("release-plan = %d, stderr: %s", code, stderr)
	}

	body, err := os.ReadFile(out) //nolint:gosec // a path this test named
	if err != nil {
		t.Fatalf("the plan was not written: %v", err)
	}

	if _, derr := jsonx.DecodeBytes[release.Plan](body); derr != nil {
		t.Fatalf("the written plan does not decode: %v", derr)
	}

	code, _, _ := runPlan(t, dir, bumpHistory(), "--out", filepath.Join(dir, "no-such-dir", "plan.json"))
	if code != exitRefused {
		t.Errorf("an unwritable plan = %d, want %d", code, exitRefused)
	}
}

// A subject template naming no version would leave the tag leg
// comparing candidate commits against a constant.
func TestReleasePlanSubjectMustNameTheVersion(t *testing.T) {
	dir := planTree(t, "0.9.0")

	code, _, stderr := runPlan(t, dir, bumpHistory(), "--subject", "chore: release")
	if code != exitRefused {
		t.Fatalf("release-plan = %d, want %d", code, exitRefused)
	}

	if !strings.Contains(stderr, "{version}") {
		t.Errorf("stderr = %q, want it to name the missing token", stderr)
	}
}
