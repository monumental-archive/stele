// What the derive surface does when a step below it fails.
//
// These are the branches that decide whether a broken inventory
// REFUSES or ships. An inventory is the document a consumer triages
// against, and every failure here has the same worst case: a document
// that renders anyway, describing fewer packages than the artifact
// actually links, and reads to a scanner as a clean artifact rather
// than an unexamined one.

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/cargo"
	"github.com/monumental-archive/stele/internal/npm"
)

// TestDeriveSBOMCarriesTheResolversRefusal: the toolchain's own
// diagnosis reaches the operator. A resolver that could not resolve is
// the everyday failure — an out-of-date lockfile under --locked — and
// the run must stop rather than describe an artifact from nothing.
func TestDeriveSBOMCarriesTheResolversRefusal(t *testing.T) {
	t.Run("cargo", func(t *testing.T) {
		withResolver(t, &stubResolver{err: errors.New("cargo: the lock file needs to be updated")})

		var stdout, stderr bytes.Buffer

		args := []string{"sbom", "--cargo-package", "lab-cli", "--tree", "/w", "--created", created}
		if got := deriveCmd(args, &stdout, &stderr); got != exitRefused {
			t.Fatalf("deriveCmd = %d, want %d", got, exitRefused)
		}

		if !strings.Contains(stderr.String(), "the lock file needs to be updated") {
			t.Errorf("stderr = %q, want cargo's own words", stderr.String())
		}

		if stdout.Len() != 0 {
			t.Errorf("a document was written despite the refusal:\n%s", stdout.String())
		}
	})

	t.Run("npm", func(t *testing.T) {
		withNpmResolver(t, &stubNpmResolver{err: errors.New("npm: missing: left-pad@1.3.0")})

		var stdout, stderr bytes.Buffer

		args := []string{"sbom", "--npm-dir", "/w", "--created", created}
		if got := deriveCmd(args, &stdout, &stderr); got != exitRefused {
			t.Fatalf("deriveCmd = %d, want %d", got, exitRefused)
		}

		if !strings.Contains(stderr.String(), "missing: left-pad@1.3.0") {
			t.Errorf("stderr = %q, want npm's own words", stderr.String())
		}
	})
}

// created is the artifact instant every row below shares; the format
// is asserted at parse time and is not what these rows are about.
const created = "2026-08-18T12:00:00Z"

// TestDeriveSBOMRefusesAnUnusableClosure: the resolver answered, but
// not with something an inventory can be built from.
func TestDeriveSBOMRefusesAnUnusableClosure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata string
		args     []string
		want     string
	}{
		{
			"metadata carrying no resolved graph",
			`{"packages": [{"id": "a", "name": "lab-cli", "version": "0.1.0", "source": ""}]}`,
			[]string{"sbom", "--cargo-package", "lab-cli", "--tree", "/w", "--created", created},
			"no resolved dependency graph",
		},
		{
			"a root the workspace does not contain",
			cargoMetadata,
			[]string{"sbom", "--cargo-package", "absent", "--tree", "/w", "--created", created},
			"is not a package in this workspace",
		},
		{
			// A root with no version renders a versionless purl, which
			// matches no advisory and is therefore invisible to every
			// scanner. Refusing is the only honest answer.
			"a root the resolver gave no version",
			`{"packages": [{"id": "a 0 (path+file:///w)", "name": "lab-cli", "version": "", "source": ""}],
			  "resolve": {"nodes": [{"id": "a 0 (path+file:///w)", "deps": []}]}}`,
			[]string{"sbom", "--cargo-package", "lab-cli", "--tree", "/w", "--created", created},
			"must carry a name and a version",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withResolver(t, &stubResolver{metadata: tc.metadata})

			var stdout, stderr bytes.Buffer

			if got := deriveCmd(tc.args, &stdout, &stderr); got != exitRefused {
				t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, exitRefused, stderr.String())
			}

			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr = %q, want it to mention %q", stderr.String(), tc.want)
			}
		})
	}
}

// TestDeriveSBOMNpmRefusesAnUnusableTree is the same guard on the npm
// side: a tree naming no versioned root describes an artifact nobody
// can hold.
func TestDeriveSBOMNpmRefusesAnUnusableTree(t *testing.T) {
	withNpmResolver(t, &stubNpmResolver{tree: []byte(`{"name": "@acme/w"}`)})

	var stdout, stderr bytes.Buffer

	args := []string{"sbom", "--npm-dir", "/w", "--created", created}
	if got := deriveCmd(args, &stdout, &stderr); got != exitRefused {
		t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, exitRefused, stderr.String())
	}

	if !strings.Contains(stderr.String(), "no versioned root package") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// TestDeriveSBOMPerArtifactWriteFailures: a derived inventory that
// cannot be written must fail the run. --out naming an unwritable path
// leaves the previous document in place, and reporting success would
// tell a release its inventory had been refreshed when it had not.
func TestDeriveSBOMPerArtifactWriteFailures(t *testing.T) {
	unwritable := filepath.Join(t.TempDir(), "absent-dir", "doc.json")

	t.Run("cargo", func(t *testing.T) {
		withResolver(t, &stubResolver{metadata: cargoMetadata})

		var stdout, stderr bytes.Buffer

		args := []string{
			"sbom", "--cargo-package", "lab-cli", "--tree", "/w",
			"--created", created, "--out", unwritable,
		}
		if got := deriveCmd(args, &stdout, &stderr); got == exitOK {
			t.Fatalf("deriveCmd reported success writing to %s", unwritable)
		}
	})

	t.Run("npm", func(t *testing.T) {
		withNpmResolver(t, &stubNpmResolver{tree: []byte(`{"name": "w", "version": "1.0.0"}`)})

		var stdout, stderr bytes.Buffer

		args := []string{"sbom", "--npm-dir", "/w", "--created", created, "--out", unwritable}
		if got := deriveCmd(args, &stdout, &stderr); got == exitOK {
			t.Fatalf("deriveCmd reported success writing to %s", unwritable)
		}
	})
}

// TestDeriveUnionRefusals: the view is folded from documents the
// caller names, so every way a named document fails to be one is a
// refusal. A view that quietly skipped an unreadable input would
// describe a release as shipping fewer artifacts than it does.
func TestDeriveUnionRefusals(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "good.spdx.json")
	writeUnionInput(t, good, "widget-cli")

	notJSON := filepath.Join(dir, "bad.spdx.json")
	if err := os.WriteFile(notJSON, []byte("<html>404</html>"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		union string
		want  string
	}{
		{"a document that is not there", filepath.Join(dir, "absent.json"), "absent.json"},
		{"a document that is not a document", notJSON, "bad.spdx.json"},
		{
			// Two inventories claiming one artifact are two answers
			// about it, and the view has no way to choose.
			"one artifact described twice",
			good + "," + good,
			"widget-cli",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			args := []string{"sbom", "--union", tc.union, "--union-name", "widget", "--created", created}
			if got := deriveCmd(args, &stdout, &stderr); got != exitRefused {
				t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, exitRefused, stderr.String())
			}

			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr = %q, want it to mention %q", stderr.String(), tc.want)
			}
		})
	}
}

// TestDeriveUnionSkipsEmptyListEntries: the list is comma-separated
// and assembled by a shell, so a trailing comma or an unset variable
// leaves an empty entry. That is nothing to aggregate rather than a
// document at the empty path — the second reading would refuse every
// release whose list was built by a loop.
func TestDeriveUnionSkipsEmptyListEntries(t *testing.T) {
	dir := t.TempDir()

	one := filepath.Join(dir, "one.spdx.json")
	writeUnionInput(t, one, "widget-cli")

	var stdout, stderr bytes.Buffer

	args := []string{
		"sbom", "--union", "," + one + ", ,",
		"--union-name", "widget", "--created", created,
	}
	if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	if !strings.Contains(stdout.String(), "widget-cli") {
		t.Errorf("the view does not carry the one real document:\n%s", stdout.String())
	}
}

// TestDeriveUnionWriteFailure: the view is the document a release
// publishes, and a write that fails must not report success.
func TestDeriveUnionWriteFailure(t *testing.T) {
	dir := t.TempDir()

	one := filepath.Join(dir, "one.spdx.json")
	writeUnionInput(t, one, "widget-cli")

	var stdout, stderr bytes.Buffer

	args := []string{
		"sbom", "--union", one, "--union-name", "widget", "--created", created,
		"--out", filepath.Join(dir, "absent-dir", "view.json"),
	}
	if got := deriveCmd(args, &stdout, &stderr); got == exitOK {
		t.Fatal("deriveCmd reported success writing into a directory that is not there")
	}
}

// writeUnionInput puts one per-artifact inventory on disk, derived
// through the same command surface the view aggregates — so the
// fixture is a document this tool actually writes, not a hand-rolled
// approximation of one.
func writeUnionInput(t *testing.T, path, artifact string) {
	t.Helper()

	withResolver(t, &stubResolver{metadata: cargoMetadata})

	var stdout, stderr bytes.Buffer

	args := []string{
		"sbom", "--cargo-package", "lab-cli", "--tree", "/w",
		"--created", created, "--artifact", artifact, "--out", path,
	}
	if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("seeding %s: deriveCmd = %d (stderr: %s)", path, got, stderr.String())
	}
}

// TestResolverSeamsDefaultToTheRealToolchain. Both resolvers are
// package-level seams every test swaps, so nothing else asserts what
// they are when nobody has. A stub left behind as the default would
// derive empty inventories for every artifact in the org, and every
// one of them would look like a clean scan.
func TestResolverSeamsDefaultToTheRealToolchain(t *testing.T) {
	if _, ok := newCargoResolver().(cargo.Runner); !ok {
		t.Errorf("newCargoResolver = %T, want the cargo binary", newCargoResolver())
	}

	if _, ok := newNpmResolver().(npm.Runner); !ok {
		t.Errorf("newNpmResolver = %T, want the npm binary", newNpmResolver())
	}
}
