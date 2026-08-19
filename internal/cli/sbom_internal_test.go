package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/cargo"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/npm"
)

// releaseInfo is one release-shaped leg, as the toolchain would stamp
// it. The refusal branches live in internal/sbom and are tabled there;
// these tests exercise the command surface around them.
func releaseInfo(goos, goarch string) *debug.BuildInfo {
	return &debug.BuildInfo{
		GoVersion: "go1.26.6",
		Main:      debug.Module{Path: "github.com/monumental-archive/stele", Version: "v0.3.0"},
		Deps:      []*debug.Module{{Path: "golang.org/x/mod", Version: "v0.38.0"}},
		Settings: []debug.BuildSetting{
			{Key: "GOOS", Value: goos},
			{Key: "GOARCH", Value: goarch},
			{Key: "vcs.revision", Value: "aaaabbbbccccddddeeeeffff0000111122223333"},
			{Key: "vcs.time", Value: "2026-08-17T10:00:00Z"},
			{Key: "vcs.modified", Value: "false"},
		},
	}
}

// withBinaries swaps the binary-reading seam: each named path resolves
// to a canned build info, everything else to err.
func withBinaries(t *testing.T, infos map[string]*debug.BuildInfo, err error) {
	t.Helper()

	previous := readBinary
	readBinary = func(path string) (*debug.BuildInfo, error) {
		if info, ok := infos[path]; ok {
			return info, nil
		}

		return nil, err
	}

	t.Cleanup(func() { readBinary = previous })
}

func TestDeriveSBOMUsage(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "no binaries", args: []string{"sbom"}},
		{name: "unknown flag", args: []string{"sbom", "--nope", "bin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if got := deriveCmd(tc.args, &stdout, &stderr); got != exitUsage {
				t.Errorf("deriveCmd(%v) = %d, want %d (stderr: %s)", tc.args, got, exitUsage, stderr.String())
			}
		})
	}
}

func TestDeriveSBOMPrintsTheUnion(t *testing.T) {
	withBinaries(t, map[string]*debug.BuildInfo{
		"dist/a": releaseInfo("linux", "amd64"),
		"dist/b": releaseInfo("darwin", "arm64"),
	}, nil)

	var stdout, stderr bytes.Buffer

	if got := deriveCmd([]string{"sbom", "dist/a", "dist/b"}, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	// The document owns stdout when it is going there, so a caller can
	// pipe it. Progress is on stderr for exactly that reason: a
	// progress line spliced into a JSON document is a corruption that
	// only surfaces in production.
	text := stdout.String()
	for _, want := range []string{
		`"spdxVersion":"SPDX-2.3"`,
		"pkg:golang/github.com/monumental-archive/stele@v0.3.0",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("stdout lacks %q:\n%s", want, text)
		}
	}

	if strings.Contains(text, "2 packages, 2 platform(s)") {
		t.Errorf("progress polluted the document stream:\n%s", text)
	}

	if !strings.Contains(stderr.String(), "github.com/monumental-archive/stele@v0.3.0: 2 packages, 2 platform(s)") {
		t.Errorf("stderr lacks the progress line:\n%s", stderr.String())
	}

	if _, err := jsonx.DecodeBytes[jsonx.Raw](stdout.Bytes()); err != nil {
		t.Errorf("stdout is not exactly one JSON document: %v", err)
	}
}

func TestDeriveSBOMWritesTheOutFile(t *testing.T) {
	withBinaries(t, map[string]*debug.BuildInfo{"bin": releaseInfo("linux", "amd64")}, nil)

	out := filepath.Join(t.TempDir(), "stele.spdx.json")

	var stdout, stderr bytes.Buffer

	if got := deriveCmd([]string{"sbom", "--out", out, "bin"}, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	// The document went to the file; stdout carries only the summary.
	if strings.Contains(stdout.String(), "spdxVersion") {
		t.Errorf("document leaked to stdout: %s", stdout.String())
	}

	doc := readFile(t, out)
	if !strings.Contains(doc, `"SPDXID":"SPDXRef-DOCUMENT"`) {
		t.Errorf("out file is not the document:\n%s", doc)
	}
}

func TestDeriveSBOMRefusals(t *testing.T) {
	sentinel := errors.New("not a go binary")

	devel := releaseInfo("linux", "amd64")
	devel.Main.Version = "(devel)"

	for _, tc := range []struct {
		name  string
		args  []string
		infos map[string]*debug.BuildInfo
		match string
	}{
		{
			name:  "unreadable binary",
			args:  []string{"sbom", "missing"},
			match: "not a go binary",
		},
		{
			name:  "engine refusal surfaces",
			args:  []string{"sbom", "bin"},
			infos: map[string]*debug.BuildInfo{"bin": devel},
			match: "no release version",
		},
		{
			name:  "expect-version mismatch",
			args:  []string{"sbom", "--expect-version", "0.9.9", "bin"},
			infos: map[string]*debug.BuildInfo{"bin": releaseInfo("linux", "amd64")},
			match: "did not check out the tag",
		},
		{
			name:  "unwritable out file",
			args:  []string{"sbom", "--out", filepath.Join(t.TempDir(), "no", "such", "dir", "x.json"), "bin"},
			infos: map[string]*debug.BuildInfo{"bin": releaseInfo("linux", "amd64")},
			match: "no such file or directory",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withBinaries(t, tc.infos, sentinel)

			var stdout, stderr bytes.Buffer

			if got := deriveCmd(tc.args, &stdout, &stderr); got != exitRefused {
				t.Fatalf("deriveCmd(%v) = %d, want %d", tc.args, got, exitRefused)
			}

			if !strings.Contains(stderr.String(), tc.match) {
				t.Errorf("stderr %q does not name %q", stderr.String(), tc.match)
			}
		})
	}
}

// The pipeline's belief may arrive bare or v-prefixed; both are the
// same tag, and neither is what the document reports — that stays the
// artifact's own stamp.
func TestDeriveSBOMExpectVersionForms(t *testing.T) {
	for _, expect := range []string{"0.3.0", "v0.3.0"} {
		t.Run(expect, func(t *testing.T) {
			withBinaries(t, map[string]*debug.BuildInfo{"bin": releaseInfo("linux", "amd64")}, nil)

			var stdout, stderr bytes.Buffer

			if got := deriveCmd([]string{"sbom", "--expect-version", expect, "bin"}, &stdout, &stderr); got != exitOK {
				t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
			}
		})
	}
}

// A tool whose job is asserting facts must not report success after
// failing to write them — for both things this mode writes: the
// document stream and the summary line.
func TestDeriveSBOMFailingWriter(t *testing.T) {
	withBinaries(t, map[string]*debug.BuildInfo{"bin": releaseInfo("linux", "amd64")}, nil)

	t.Run("document to stdout", func(t *testing.T) {
		var stderr bytes.Buffer

		if got := deriveCmd([]string{"sbom", "bin"}, failWriterI{}, &stderr); got != exitIO {
			t.Fatalf("deriveCmd = %d, want %d", got, exitIO)
		}
	})

	t.Run("summary after --out", func(t *testing.T) {
		var stderr bytes.Buffer

		out := filepath.Join(t.TempDir(), "x.json")

		if got := deriveCmd([]string{"sbom", "--out", out, "bin"}, failWriterI{}, &stderr); got != exitIO {
			t.Fatalf("deriveCmd = %d, want %d", got, exitIO)
		}
	})
}

// stubResolver returns recorded cargo output.
type stubResolver struct {
	metadata string
	err      error
	tree     string
	sel      cargo.Selection
}

func (s *stubResolver) Metadata(tree string, sel cargo.Selection) ([]byte, error) {
	s.tree, s.sel = tree, sel

	return []byte(s.metadata), s.err
}

func withResolver(t *testing.T, r cargo.Resolver) {
	t.Helper()

	previous := newCargoResolver
	newCargoResolver = func() cargo.Resolver { return r }

	t.Cleanup(func() { newCargoResolver = previous })
}

const cargoMetadata = `{"packages": [
  {"id": "lab-cli 0.1.0 (path+file:///w/cli)", "name": "lab-cli", "version": "0.1.0", "source": ""},
  {"id": "mimalloc 0.1.39 (registry+x)", "name": "mimalloc", "version": "0.1.39", "source": "registry+x"}],
 "resolve": {"nodes": [
  {"id": "lab-cli 0.1.0 (path+file:///w/cli)",
   "deps": [{"pkg": "mimalloc 0.1.39 (registry+x)", "dep_kinds": [{"kind": ""}]}]},
  {"id": "mimalloc 0.1.39 (registry+x)", "deps": []}]}}`

// The per-artifact path: one package's own closure, every PURL
// versioned, dated by the artifact rather than by the run.
func TestDeriveSBOMFromACargoClosure(t *testing.T) {
	resolver := &stubResolver{metadata: cargoMetadata}
	withResolver(t, resolver)

	var stdout, stderr bytes.Buffer

	args := []string{
		"sbom", "--cargo-package", "lab-cli", "--tree", "/w",
		"--target", "x86_64-unknown-linux-gnu", "--created", "2026-08-18T12:00:00Z",
	}
	if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		`"name":"lab-cli@0.1.0"`,
		`"referenceLocator":"pkg:cargo/lab-cli@0.1.0"`,
		`"referenceLocator":"pkg:cargo/mimalloc@0.1.39"`,
		`"created":"2026-08-18T12:00:00Z"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("document lacks %s:\n%s", want, out)
		}
	}

	// A versionless PURL matches no advisory, so it is invisible to
	// every scanner — the defect the canon's bash asserts against
	// afterwards and this renders unwritable.
	if strings.Contains(out, `"pkg:cargo/lab-cli"`) || strings.Contains(out, `"pkg:cargo/mimalloc"`) {
		t.Errorf("a versionless PURL was rendered:\n%s", out)
	}

	if resolver.tree != "/w" || resolver.sel.Target() != "x86_64-unknown-linux-gnu" {
		t.Errorf("resolved in %q for %q", resolver.tree, resolver.sel.Target())
	}
}

// The view is folded from documents. Its input is documents and
// nothing else, so it cannot be derived a second time from a tree.
func TestDeriveSBOMUnionAggregates(t *testing.T) {
	dir := t.TempDir()

	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}

		return path
	}

	a := write("a.spdx.json", `{"SPDXID": "SPDXRef-DOCUMENT", "packages": [
	  {"SPDXID": "SPDXRef-Package-0", "name": "widget-cli"},
	  {"SPDXID": "SPDXRef-Package-1", "name": "shared", "versionInfo": "1.0.0"}],
	 "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
	  "relatedSpdxElement": "SPDXRef-Package-0", "relationshipType": "DESCRIBES"}]}`)
	b := write("b.spdx.json", `{"SPDXID": "SPDXRef-DOCUMENT", "packages": [
	  {"SPDXID": "SPDXRef-Package-0", "name": "widget-npm"},
	  {"SPDXID": "SPDXRef-Package-1", "name": "only-npm", "versionInfo": "3.0.0"}],
	 "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
	  "relatedSpdxElement": "SPDXRef-Package-0", "relationshipType": "DESCRIBES"}]}`)

	var stdout, stderr bytes.Buffer

	args := []string{
		"sbom", "--union", a + "," + b, "--union-name", "widget@1.0.0",
		"--created", "2026-08-18T12:00:00Z",
	}
	if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		`"name":"widget@1.0.0"`,
		"aggregated from widget-cli, widget-npm",
		// Each package names who ships it, so the view never
		// over-claims the way the per-release document did.
		"shipped in: widget-cli",
		"shipped in: widget-npm",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("view lacks %q:\n%s", want, out)
		}
	}
}

func TestDeriveSBOMSourceRefusals(t *testing.T) {
	withResolver(t, &stubResolver{metadata: cargoMetadata})

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			"deriving and aggregating at once",
			[]string{"sbom", "--cargo-package", "a", "--union", "x"},
			"exclusive",
		},
		{
			"a cargo closure with no workspace",
			[]string{"sbom", "--cargo-package", "a", "--created", "2026-08-18T12:00:00Z"},
			"--tree is required",
		},
		{
			"a cargo closure dated by nothing",
			[]string{"sbom", "--cargo-package", "a", "--tree", "/w"},
			"dated by the artifact",
		},
		{
			"a view naming no release",
			[]string{"sbom", "--union", "x", "--created", "2026-08-18T12:00:00Z"},
			"--union-name is required",
		},
		{
			"a view dated by nothing",
			[]string{"sbom", "--union", "x", "--union-name", "w"},
			"--created is required",
		},
		{
			"a closure dated by a spelling the format does not admit",
			[]string{"sbom", "--cargo-package", "a", "--tree", "/w", "--created", "yesterday"},
			"not RFC 3339",
		},
		{
			"a view dated by a spelling the format does not admit",
			[]string{"sbom", "--union", "x", "--union-name", "w", "--created", "18 Aug 2026"},
			"not RFC 3339",
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

// One crate built once per feature set ships SEPARATE artifacts with
// separate digests, and their dependency graphs differ because the
// features differ. Resolving them alike would give every artifact the
// same inventory and quietly assert they are identical — which is
// exactly what a Postgres extension built for pg16 and pg17 would get.
func TestDeriveSBOMCarriesTheFeatureSelection(t *testing.T) {
	resolver := &stubResolver{metadata: cargoMetadata}
	withResolver(t, resolver)

	var stdout, stderr bytes.Buffer

	args := []string{
		"sbom", "--cargo-package", "lab-cli", "--tree", "/w", "--created", "2026-08-18T12:00:00Z",
		"--features", "pg17,serde", "--no-default-features",
	}
	if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	if strings.Join(resolver.sel.Features(), ",") != "pg17,serde" {
		t.Errorf("features = %v, want the artifact's own", resolver.sel.Features())
	}

	if !strings.Contains(strings.Join(resolver.sel.Args(), " "), "--no-default-features") {
		t.Error("--no-default-features did not reach the resolver")
	}
}

// cargo refuses --all-features beside an explicit list, so a resolver
// that silently preferred one would answer a question nobody asked.
func TestDeriveSBOMRefusesContradictoryFeatures(t *testing.T) {
	withResolver(t, &stubResolver{metadata: cargoMetadata})

	var stdout, stderr bytes.Buffer

	args := []string{
		"sbom", "--cargo-package", "lab-cli", "--tree", "/w", "--created", "2026-08-18T12:00:00Z",
		"--all-features", "--features", "pg17",
	}
	if got := deriveCmd(args, &stdout, &stderr); got != exitRefused {
		t.Fatalf("deriveCmd = %d, want %d", got, exitRefused)
	}

	if !strings.Contains(stderr.String(), "exclusive") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

// stubNpmResolver returns recorded npm ls output.
type stubNpmResolver struct {
	tree []byte
	dir  string
}

func (s *stubNpmResolver) Tree(dir string) ([]byte, error) {
	s.dir = dir

	return s.tree, nil
}

func withNpmResolver(t *testing.T, r npm.Resolver) {
	t.Helper()

	previous := newNpmResolver
	newNpmResolver = func() npm.Resolver { return r }

	t.Cleanup(func() { newNpmResolver = previous })
}

// The npm leg renders the artifact's own production closure, with
// scoped purls percent-encoded the way the purl spec demands — a
// `pkg:npm/@scope/...` spelling matches no advisory in a conforming
// scanner.
func TestDeriveSBOMNpmClosure(t *testing.T) {
	resolver := &stubNpmResolver{tree: []byte(`{
	  "name": "@acme/widget-wasm", "version": "1.2.0",
	  "dependencies": {"zlib-shim": {"version": "3.0.0"}}}`)}
	withNpmResolver(t, resolver)

	var stdout, stderr bytes.Buffer

	args := []string{"sbom", "--npm-dir", "/w/pkg", "--created", "2026-08-18T12:00:00Z"}
	if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		`"name":"@acme/widget-wasm@1.2.0"`,
		`"pkg:npm/%40acme/widget-wasm@1.2.0"`,
		`"pkg:npm/zlib-shim@3.0.0"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("document lacks %s:\n%s", want, out)
		}
	}

	if resolver.dir != "/w/pkg" {
		t.Errorf("resolved in %q, want the named package dir", resolver.dir)
	}
}

// The npm leg is dated by the artifact like every other source.
func TestDeriveSBOMNpmRefusals(t *testing.T) {
	withNpmResolver(t, &stubNpmResolver{tree: []byte(`{"name": "w", "version": "1.0.0"}`)})

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			"dated by nothing",
			[]string{"sbom", "--npm-dir", "/w"},
			"--created is required",
		},
		{
			"two artifact sources at once",
			[]string{"sbom", "--npm-dir", "/w", "--cargo-package", "a", "--created", "2026-08-18T12:00:00Z"},
			"exclusive",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if got := deriveCmd(tc.args, &stdout, &stderr); got != exitRefused {
				t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, exitRefused, stderr.String())
			}

			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr = %q, want %q", stderr.String(), tc.want)
			}
		})
	}
}

// --artifact renames what the document CALLS the artifact — feature
// variants of one package must union as distinct artifacts — while
// the purl keeps the package's real identity, because advisory
// matching runs on what the artifact IS (stele#126).
func TestDeriveSBOMArtifactDisplayName(t *testing.T) {
	resolver := &stubResolver{metadata: cargoMetadata}
	withResolver(t, resolver)

	var stdout, stderr bytes.Buffer

	args := []string{
		"sbom", "--cargo-package", "lab-cli", "--tree", "/w",
		"--artifact", "lab-cli-pg16", "--created", "2026-08-18T12:00:00Z",
	}
	if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		`"name":"lab-cli-pg16@0.1.0"`,
		`"name":"lab-cli-pg16"`,
		`"pkg:cargo/lab-cli@0.1.0"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("document lacks %s:\n%s", want, out)
		}
	}
}
