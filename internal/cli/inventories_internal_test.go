// The `derive inventories` table (stele#396): each class-combination
// refusal, a missing Postgres major, a manifest with no plan, an empty
// binaries directory, the dependency-graph path on the recorded
// response, and each path's success — every refusal asserted by its
// message. Each refusal the canon's shell printed keeps its meaning;
// the shell's message is quoted beside the row where it differs.

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/jsonx"
)

const inventoriesPolicy = `{
  "schema": 9,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "classes": {
      "rust-crate": {
        "bundles": ["attestations-crates.intoto.jsonl"],
        "assetPrefixes": [{"prefix": "sbom-cargo-", "owedFrom": "1.0.0", "planned": true}]
      },
      "pgrx-extension": {
        "bundles": ["attestations-extensions.intoto.jsonl"],
        "assetPrefixes": [{"prefix": "sbom-pgrx-", "owedFrom": "1.0.0", "planned": true}]
      },
      "go-binary": {"bundles": ["attestations-binaries.intoto.jsonl"]},
      "oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}
    }
  }
}`

// edtfMetadata is one workspace holding the crate and the extension,
// both resolving to one registry dependency.
const edtfMetadata = `{"packages": [
  {"id": "edtf 0.4.2 (path+file:///w/edtf)", "name": "edtf", "version": "0.4.2", "source": ""},
  {"id": "pg_edtf 0.4.2 (path+file:///w/pg)", "name": "pg_edtf", "version": "0.4.2", "source": ""},
  {"id": "chrono 0.4.38 (registry+x)", "name": "chrono", "version": "0.4.38", "source": "registry+x"}],
 "resolve": {"nodes": [
  {"id": "edtf 0.4.2 (path+file:///w/edtf)",
   "deps": [{"pkg": "chrono 0.4.38 (registry+x)", "dep_kinds": [{"kind": ""}]}]},
  {"id": "pg_edtf 0.4.2 (path+file:///w/pg)",
   "deps": [{"pkg": "chrono 0.4.38 (registry+x)", "dep_kinds": [{"kind": ""}]}]},
  {"id": "chrono 0.4.38 (registry+x)", "deps": []}]}}`

const (
	cratePlan = `[{"class": "rust-crate", "doc": "sbom-cargo-edtf-crate", "artifact": "edtf-crate",` +
		` "params": {"cargoPackage": "edtf"}}]`
	extPlan16 = `[{"class": "pgrx-extension", "doc": "sbom-pgrx-pg_edtf-pg16", "artifact": "pg_edtf-pg16",` +
		` "params": {"cargoPackage": "pg_edtf", "features": ["pg16"], "noDefaultFeatures": true}}]`
	extPlan17 = `[{"class": "pgrx-extension", "doc": "sbom-pgrx-pg_edtf-pg17", "artifact": "pg_edtf-pg17",` +
		` "params": {"cargoPackage": "pg_edtf", "features": ["pg17"], "noDefaultFeatures": true}}]`
)

// stubGraph serves the forge's dependency-graph export.
type stubGraph struct {
	body []byte
	err  error
}

func (s stubGraph) DependencyGraphSBOM(string, string) ([]byte, error) { return s.body, s.err }

// inventoriesWorld swaps every seam the mode reads: the cargo
// resolver, the tracked-manifest read and the forge.
func inventoriesWorld(t *testing.T, tracked []string, graph stubGraph) {
	t.Helper()

	withResolver(t, &stubResolver{metadata: edtfMetadata})

	prevTracked, prevGraph := trackedManifests, newDependencyGraph
	trackedManifests = func(string) ([]string, error) { return tracked, nil }
	newDependencyGraph = func() dependencyGraph { return graph }

	t.Cleanup(func() { trackedManifests, newDependencyGraph = prevTracked, prevGraph })
}

// planFiles writes each plan into its own leg directory, as the
// download step lays them out.
func planFiles(t *testing.T, plans ...string) []string {
	t.Helper()

	dir := t.TempDir()
	paths := make([]string, 0, len(plans))

	for i, p := range plans {
		leg := filepath.Join(dir, "sbom-plan-"+string(rune('a'+i)))
		if err := os.MkdirAll(leg, 0o750); err != nil {
			t.Fatal(err)
		}

		path := filepath.Join(leg, "plan.json")
		if err := os.WriteFile(path, []byte(p), ownerRW); err != nil {
			t.Fatal(err)
		}

		paths = append(paths, path)
	}

	return paths
}

// inventoriesArgsFor is a release of acme/edtf 0.4.2.
func inventoriesArgsFor(t *testing.T, classes, outDir string, extra ...string) []string {
	t.Helper()

	return append([]string{
		"inventories", "--policy", writeInventoryPlanPolicy(t, inventoriesPolicy),
		"--classes", classes, "--repo", "acme/edtf", "--version", "0.4.2",
		"--created", "2026-11-17T12:00:00Z", "--tree", "/w", "--out-dir", outDir,
	}, extra...)
}

// withPlans adds the judgment's inputs and the plan files.
func withPlans(evidence string, plans []string) []string {
	return append([]string{"--evidence-classes", evidence, "--machinery-version", "1.2.0"}, plans...)
}

//nolint:gocritic // unnamedResult: the exit code, then stdout and stderr, in Run's order
func runInventories(t *testing.T, args []string) (int, string, string) {
	t.Helper()

	var stdout, stderr bytes.Buffer

	code := deriveCmd(args, &stdout, &stderr)

	return code, stdout.String(), stderr.String()
}

// TestDeriveInventoriesFromPlans: the judged set derives one document
// per entry and the view folded from them; the list names the
// per-artifact documents and never the view. The pg16 plan arrives
// twice, as both arches of one major state it: the derivation iterates
// the set the judgment collapsed (stele#151), so it derives once — a
// second reading of the raw plans would derive it twice and the view
// would refuse two documents describing one artifact.
func TestDeriveInventoriesFromPlans(t *testing.T) {
	inventoriesWorld(t, nil, stubGraph{})

	out := t.TempDir()
	args := inventoriesArgsFor(t, "rust-crate,pgrx-extension", out, append([]string{"--pg-majors", "16,17"},
		withPlans("rust-crate,pgrx-extension", planFiles(t, cratePlan, extPlan16, extPlan17, extPlan16))...)...)

	code, stdout, stderr := runInventories(t, args)
	if code != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", code, stderr)
	}

	want := `["sbom-cargo-edtf-crate-0.4.2.spdx.json","sbom-pgrx-pg_edtf-pg16-0.4.2.spdx.json",` +
		`"sbom-pgrx-pg_edtf-pg17-0.4.2.spdx.json"]` + "\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}

	for _, name := range []string{
		"sbom-cargo-edtf-crate-0.4.2.spdx.json", "sbom-pgrx-pg_edtf-pg16-0.4.2.spdx.json",
		"sbom-pgrx-pg_edtf-pg17-0.4.2.spdx.json", "edtf-0.4.2.spdx.json",
	} {
		body, err := os.ReadFile(filepath.Join(out, name)) //nolint:gosec // the test's own temp file
		if err != nil {
			t.Fatalf("%s was not written: %v", name, err)
		}

		if !bytes.Contains(body, []byte(`"pkg:cargo/chrono@0.4.38"`)) {
			t.Errorf("%s lacks the resolved dependency:\n%s", name, body)
		}
	}

	// stele#126: the document calls the artifact by its name, and the
	// PURL keeps the package's real identity — advisory matching runs
	// on what the artifact IS.
	pg16, err := os.ReadFile(filepath.Join(out, "sbom-pgrx-pg_edtf-pg16-0.4.2.spdx.json")) //nolint:gosec // temp file
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(pg16, []byte(`"name":"pg_edtf-pg16"`)) ||
		!bytes.Contains(pg16, []byte(`"referenceLocator":"pkg:cargo/pg_edtf@0.4.2"`)) {
		t.Errorf("the pg16 document does not name its artifact over the package's real PURL:\n%s", pg16)
	}

	view, err := os.ReadFile(filepath.Join(out, "edtf-0.4.2.spdx.json")) //nolint:gosec // the test's own temp file
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(view, []byte(`"name":"edtf@v0.4.2"`)) {
		t.Errorf("the view is not named for the release:\n%s", view)
	}

	if !strings.Contains(stderr, "decision population:") {
		t.Errorf("stderr = %q, want the decision population named", stderr)
	}
}

// TestDeriveInventoriesFromBinaries: shipped binaries speak for the
// release, one document, and the release decides as one.
func TestDeriveInventoriesFromBinaries(t *testing.T) {
	inventoriesWorld(t, nil, stubGraph{})

	bins := t.TempDir()
	if err := os.WriteFile(filepath.Join(bins, "stele"), nil, ownerRW); err != nil {
		t.Fatal(err)
	}

	info := releaseInfo("linux", "amd64")
	withBinaries(t, map[string]*debug.BuildInfo{filepath.Join(bins, "stele"): info}, nil)

	out := t.TempDir()

	args := inventoriesArgsFor(t, "go-binary,oci-image", out,
		"--binaries-dir", bins, "--expect-revision", "aaaabbbbccccddddeeeeffff0000111122223333")
	args[slices.Index(args, "--version")+1] = "0.3.0"

	code, stdout, stderr := runInventories(t, args)
	if code != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", code, stderr)
	}

	if stdout != `[""]`+"\n" {
		t.Errorf("stdout = %q, want the one-release population", stdout)
	}

	if _, err := os.Stat(filepath.Join(out, "edtf-0.3.0.spdx.json")); err != nil {
		t.Errorf("the binaries' inventory was not written: %v", err)
	}
}

// TestDeriveInventoriesFromTheDependencyGraph: a tree tracking no
// manifest, no plan and no binaries exports the forge's dependency
// graph — the recorded export, admitted and written as the view.
func TestDeriveInventoriesFromTheDependencyGraph(t *testing.T) {
	recorded, err := os.ReadFile("../gh/testdata/dependency-graph-sbom.golden")
	if err != nil {
		t.Fatal(err)
	}

	envelope, err := jsonx.DecodeForeign[struct {
		SBOM jsonx.Raw `json:"sbom"`
	}](recorded)
	if err != nil {
		t.Fatal(err)
	}

	inventoriesWorld(t, nil, stubGraph{body: envelope.SBOM})

	out := t.TempDir()

	code, stdout, stderr := runInventories(t, inventoriesArgsFor(t, "source-archive", out, "--name", ".github"))
	if code != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", code, stderr)
	}

	if stdout != `[""]`+"\n" {
		t.Errorf("stdout = %q, want the one-release population", stdout)
	}

	// The leading dot goes: a dotfile is skipped by every release-asset
	// glob (measured in the canon: releases shipped without their SBOM).
	written, err := os.ReadFile(filepath.Join(out, "github-0.4.2.spdx.json")) //nolint:gosec // the test's own temp file
	if err != nil {
		t.Fatalf("the dependency graph was not written: %v", err)
	}

	if !bytes.Contains(written, []byte("com.github.monumental-archive/.github")) {
		t.Errorf("the written view is not the recorded export:\n%.200s", written)
	}
}

// TestDeriveInventoriesRefusals: every refusal the sequence makes,
// asserted by message.
func TestDeriveInventoriesRefusals(t *testing.T) {
	emptyBins := t.TempDir()

	versionless := []byte(`{"spdxVersion": "SPDX-2.3", "name": "acme/edtf", "packages": [{"name": "x",` +
		` "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:githubactions/actions/checkout"}]}]}`)

	tests := []struct {
		name    string
		tracked []string
		graph   stubGraph
		args    func(t *testing.T, out string) []string
		want    string
	}{
		{
			// shell: "go-binary cannot yet ship beside rust-crate: the
			// inventory would omit the Go binaries' packages (.github#784)"
			name: "a binaries-carry class beside a planning class",
			args: func(t *testing.T, out string) []string {
				t.Helper()

				return inventoriesArgsFor(t, "go-binary,rust-crate", out)
			},
			want: "derive inventories: go-binary cannot yet ship beside rust-crate: the inventory would omit the" +
				" binaries' packages (.github#784)",
		},
		{
			// shell: "... declare the classes that own the plan, or
			// drop binary-crate from the image" — the image input is the
			// workflow's; the refusal names the planning leg instead.
			name: "a plan while the binaries speak for the release",
			args: func(t *testing.T, out string) []string {
				t.Helper()

				return inventoriesArgsFor(t, "go-binary,oci-image", out, append([]string{"--binaries-dir", emptyBins},
					withPlans("go-binary", planFiles(t, cratePlan))...)...)
			},
			want: "derive inventories: a build leg emitted an inventory plan while the shipped binaries would speak" +
				" for the whole release — the two describe different artifact sets",
		},
		{
			// shell: "BINARIES_DIR holds no binaries — an inventory of
			// nothing asserts nothing"
			name: "an empty binaries directory",
			args: func(t *testing.T, out string) []string {
				t.Helper()

				return inventoriesArgsFor(t, "go-binary", out, "--binaries-dir", emptyBins)
			},
			want: "derive inventories: the binaries directory holds no binaries — an inventory of nothing asserts" +
				" nothing",
		},
		{
			name: "a binaries directory that is not there",
			args: func(t *testing.T, out string) []string {
				t.Helper()

				return inventoriesArgsFor(t, "go-binary", out, "--binaries-dir", filepath.Join(emptyBins, "absent"))
			},
			want: "derive inventories: listing the binaries: lstat ",
		},
		{
			// shell: "pg-majors names 17 but no pgrx inventory covers it"
			name: "a requested major no plan covers",
			args: func(t *testing.T, out string) []string {
				t.Helper()

				return inventoriesArgsFor(t, "pgrx-extension", out, append([]string{"--pg-majors", "16,17"},
					withPlans("pgrx-extension", planFiles(t, extPlan16))...)...)
			},
			want: "derive inventories: pg-majors names 17 but no extension inventory covers it",
		},
		{
			name: "plans that do not pass judgment",
			args: func(t *testing.T, out string) []string {
				t.Helper()

				return inventoriesArgsFor(t, "rust-crate", out,
					withPlans("rust-crate,pgrx-extension", planFiles(t, cratePlan))...)
			},
			want: "derive inventories: the plans did not pass judgment (FAIL): pgrx-extension: planned-obligation:",
		},
		{
			name: "a plan file that will not read",
			args: func(t *testing.T, out string) []string {
				t.Helper()

				return inventoriesArgsFor(t, "rust-crate", out,
					withPlans("rust-crate", []string{filepath.Join(out, "absent.json")})...)
			},
			want: "derive inventories: open ",
		},
		{
			name: "a planned entry naming no closure",
			args: func(t *testing.T, out string) []string {
				t.Helper()

				return inventoriesArgsFor(t, "rust-crate", out, withPlans("rust-crate", planFiles(t,
					`[{"class": "rust-crate", "doc": "sbom-cargo-edtf-crate"}]`))...)
			},
			want: "derive inventories: sbom-cargo-edtf-crate: the plan names no closure (params are absent)",
		},
		{
			name: "a planned entry naming no package",
			args: func(t *testing.T, out string) []string {
				t.Helper()

				return inventoriesArgsFor(t, "rust-crate", out, withPlans("rust-crate", planFiles(t,
					`[{"class": "rust-crate", "doc": "sbom-cargo-edtf-crate", "params": {"features": ["x"]}}]`))...)
			},
			want: "derive inventories: sbom-cargo-edtf-crate: params.cargoPackage is absent — the closure has no root",
		},
		{
			name: "planned params of another shape",
			args: func(t *testing.T, out string) []string {
				t.Helper()

				return inventoriesArgsFor(t, "rust-crate", out, withPlans("rust-crate", planFiles(t,
					`[{"class": "rust-crate", "doc": "sbom-cargo-edtf-crate", "params": {"npmDir": "x"}}]`))...)
			},
			want: "derive inventories: sbom-cargo-edtf-crate: params:",
		},
		{
			name: "a planned package the workspace does not hold",
			args: func(t *testing.T, out string) []string {
				t.Helper()

				return inventoriesArgsFor(t, "rust-crate", out, withPlans("rust-crate", planFiles(t,
					`[{"class": "rust-crate", "doc": "sbom-cargo-ghost-crate", "params": {"cargoPackage": "ghost"}}]`))...)
			},
			want: `derive inventories: sbom-cargo-ghost-crate: cargo: "ghost" is not a package in this workspace`,
		},
		{
			// shell: "this release tracks a manifest but no build leg
			// emitted an inventory plan — ..." — the tracked paths named.
			name:    "a manifest with no plan",
			tracked: []string{"Cargo.lock"},
			args: func(t *testing.T, out string) []string {
				t.Helper()

				return inventoriesArgsFor(t, "rust-crate", out)
			},
			want: "derive inventories: this release tracks a manifest (Cargo.lock) but no build leg emitted an" +
				" inventory plan — the per-release inventory is aggregated from per-artifact documents (#492)",
		},
		{
			// shell: reported "N of M PURLs versionless" and published.
			name:  "a dependency graph carrying a versionless PURL",
			graph: stubGraph{body: versionless},
			args: func(t *testing.T, out string) []string {
				t.Helper()

				return inventoriesArgsFor(t, "source-archive", out)
			},
			want: "derive inventories: the dependency graph: sbom: acme/edtf has 1 PURLs, 1 versionless" +
				" (pkg:githubactions/actions/checkout)",
		},
		{
			name:  "a dependency graph that will not read",
			graph: stubGraph{err: errors.New("gh: acme/edtf has no dependency graph to export")},
			args: func(t *testing.T, out string) []string {
				t.Helper()

				return inventoriesArgsFor(t, "source-archive", out)
			},
			want: "derive inventories: gh: acme/edtf has no dependency graph to export",
		},
		{
			name: "an output directory that is not there",
			args: func(t *testing.T, out string) []string {
				t.Helper()

				return inventoriesArgsFor(t, "rust-crate", filepath.Join(out, "absent"),
					withPlans("rust-crate", planFiles(t, cratePlan))...)
			},
			want: "derive: open ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inventoriesWorld(t, tt.tracked, tt.graph)

			code, _, stderr := runInventories(t, tt.args(t, t.TempDir()))
			if code != exitRefused {
				t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", code, exitRefused, stderr)
			}

			if !strings.Contains(stderr, tt.want) {
				t.Errorf("stderr = %q\nwant it to carry %q", stderr, tt.want)
			}
		})
	}
}

// TestDeriveInventoriesTrackedReadFailure: git refusing to say what
// the tree tracks is a refusal, never "tracks nothing".
func TestDeriveInventoriesTrackedReadFailure(t *testing.T) {
	inventoriesWorld(t, nil, stubGraph{})

	prev := trackedManifests
	trackedManifests = func(string) ([]string, error) { return nil, errors.New("gitrepo: /w is not a git repository") }

	t.Cleanup(func() { trackedManifests = prev })

	code, _, stderr := runInventories(t, inventoriesArgsFor(t, "rust-crate", t.TempDir()))
	if code != exitRefused || !strings.Contains(stderr, "derive inventories: gitrepo: /w is not a git repository") {
		t.Fatalf("deriveCmd = %d, stderr %q; want the read refusal", code, stderr)
	}
}

// TestDeriveInventoriesUsage: every usage refusal, by message.
func TestDeriveInventoriesUsage(t *testing.T) {
	policy := writeInventoryPlanPolicy(t, inventoriesPolicy)
	notAPolicy := writeInventoryPlanPolicy(t, `{"schema": 9}`)

	base := func(drop string, extra ...string) []string {
		args := []string{"inventories"}

		for _, kv := range [][2]string{
			{"--policy", policy},
			{"--classes", "rust-crate"},
			{"--repo", "acme/edtf"},
			{"--version", "0.4.2"},
			{"--created", "2026-11-17T12:00:00Z"},
			{"--out-dir", t.TempDir()},
		} {
			if kv[0] != drop {
				args = append(args, kv[0], kv[1])
			}
		}

		return append(args, extra...)
	}

	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"no policy", base("--policy"), exitUsage, "stele derive inventories: --policy is required"},
		{"no classes", base("--classes"), exitUsage, "--classes is required — a release that ran no build leg"},
		{"no repo", base("--repo"), exitUsage, "--repo is required as owner/repo"},
		{"no version", base("--version"), exitUsage, "--version is required, with no v prefix"},
		{"a v-prefixed version", base("", "--version", "v0.4.2"), exitUsage, "--version is required, with no v prefix"},
		{"no created", base("--created"), exitUsage, "--created is required"},
		{"no out-dir", base("--out-dir"), exitUsage, "--out-dir is required"},
		{
			"plans without their judgment's inputs",
			base("", "plan.json"),
			exitUsage,
			"--evidence-classes and --machinery-version are required to judge the plans",
		},
		{"an unknown flag", base("", "--nope"), exitUsage, "flag provided but not defined: -nope"},
		{
			"a policy that does not load",
			append(base("--policy"), "--policy", notAPolicy),
			exitRefused,
			"derive inventories: " + notAPolicy + ":",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := runInventories(t, tt.args)
			if code != tt.code {
				t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", code, tt.code, stderr)
			}

			if !strings.Contains(stderr, tt.want) {
				t.Errorf("stderr = %q\nwant it to carry %q", stderr, tt.want)
			}
		})
	}

	t.Run("a failing stdout", func(t *testing.T) {
		inventoriesWorld(t, nil, stubGraph{})

		var stderr bytes.Buffer

		args := inventoriesArgsFor(t, "rust-crate", t.TempDir(), withPlans("rust-crate", planFiles(t, cratePlan))...)
		if code := deriveCmd(args, failWriterI{}, &stderr); code != exitIO {
			t.Fatalf("deriveCmd = %d, want %d", code, exitIO)
		}
	})
}
