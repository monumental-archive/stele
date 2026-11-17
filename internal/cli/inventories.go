// `derive inventories`: a release's every inventory in one call
// (stele#396). It was a loop in the canon's publish workflow that
// called `assert plans` and then `derive sbom` once per judged entry,
// and decided in shell which classes could ship together, whether
// every Postgres major was covered, whether a tree tracking a manifest
// could release without a plan, and where the dependency graph stood
// in. Those decisions are evidence rules, so they live here; the
// workflow passes its facts and writes one line.
//
// Which inventory a class owes is the release contract's (the
// InventoryRole rows in internal/release); how a document is named is
// the assert policy's (its sbomSuffix, its planned prefixes). This
// file is the sequence, the refusals the sequence makes, and the
// placement — nothing else.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/gitrepo"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/release"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/sbom"
)

// deriveInventories is the mode name.
const deriveInventories = "inventories"

// manifestPathspecs are the dependency manifests whose presence means
// a tree has an inventory to derive and must plan it (#492, #537).
func manifestPathspecs() []string {
	return []string{"Cargo.lock", "*/Cargo.lock", "go.mod", "*/go.mod"}
}

// The effect seams, swapped only by tests.
//
//nolint:gochecknoglobals // test seams, written only by test setup
var (
	// trackedManifests answers which dependency manifests the tree's
	// index tracks.
	trackedManifests = func(tree string) ([]string, error) {
		r, err := gitrepo.OpenObjects(tree)
		if err != nil {
			return nil, err
		}

		return r.TrackedPaths(manifestPathspecs()...)
	}

	// newDependencyGraph reads the forge's dependency-graph export.
	newDependencyGraph = func() dependencyGraph { return gh.New(forgeToken()) }
)

// dependencyGraph is the one forge read this mode makes.
type dependencyGraph interface {
	DependencyGraphSBOM(owner, repo string) ([]byte, error)
}

// inventoriesArgs is the mode's whole argument surface.
type inventoriesArgs struct {
	policy          string
	classes         string
	evidenceClasses string
	machinery       string
	repo            string
	name            string
	version         string
	created         string
	tree            string
	binariesDir     string
	expectRevision  string
	pgMajors        string
	outDir          string
	plans           []string
}

// parseInventoriesArgs parses and validates the flags.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseInventoriesArgs(args []string, stderr io.Writer) (*inventoriesArgs, int) {
	ia := &inventoriesArgs{}

	flags := flag.NewFlagSet("stele derive inventories", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&ia.policy, "policy", "", "the assert policy: the plans' judgment and the documents' names (required)")
	flags.StringVar(&ia.classes, "classes", "", "comma-separated classes whose build legs ran (required)")
	flags.StringVar(&ia.evidenceClasses, "evidence-classes", "",
		"comma-separated classes the release's evidence declares, which the plans are judged for"+
			" (required when plans are given)")
	flags.StringVar(&ia.machinery, "machinery-version", "",
		"the machinery version the release rides (required when plans are given)")
	flags.StringVar(&ia.repo, "repo", "", "owner/repo being released (required)")
	flags.StringVar(&ia.name, "name", "", "the release view's base name; empty is the repository's name")
	flags.StringVar(&ia.version, "version", "", "the version being released, with no v prefix (required)")
	flags.StringVar(&ia.created, "created", "", "the released commit's instant, RFC 3339 (required)")
	flags.StringVar(&ia.tree, "tree", ".", "the released tree: cargo resolves in it, git says what it tracks")
	flags.StringVar(&ia.binariesDir, "binaries-dir", "",
		"the shipped binaries, when the release ships only binaries that carry their own inventory")
	flags.StringVar(&ia.expectRevision, "expect-revision", "",
		"the released commit every shipped binary must be stamped with (with --binaries-dir)")
	flags.StringVar(&ia.pgMajors, "pg-majors", "", "comma-separated Postgres majors the release builds")
	flags.StringVar(&ia.outDir, "out-dir", "", "where every document is written (required)")

	if err := flags.Parse(args); err != nil {
		return ia, exitUsage
	}

	ia.plans = flags.Args()

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele derive inventories: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch {
	case ia.policy == "":
		return ia, usageFail("--policy is required")
	case strings.Trim(ia.classes, ",") == "":
		return ia, usageFail("--classes is required — a release that ran no build leg ships nothing to describe")
	case !strings.Contains(ia.repo, "/"):
		return ia, usageFail("--repo is required as owner/repo")
	case ia.version == "" || strings.HasPrefix(ia.version, "v"):
		return ia, usageFail("--version is required, with no v prefix: documents are named <doc>-<version>")
	case ia.created == "":
		return ia, usageFail("--created is required — every document is dated by the release, never the run")
	case ia.outDir == "":
		return ia, usageFail("--out-dir is required")
	case len(ia.plans) > 0 && (ia.evidenceClasses == "" || ia.machinery == ""):
		return ia, usageFail("--evidence-classes and --machinery-version are required to judge the plans")
	}

	return ia, exitOK
}

// inventoriesRun is one run's resolved facts.
type inventoriesRun struct {
	ia     *inventoriesArgs
	pol    *assert.Policy
	suffix string
	base   string
	out    *latch
}

// runDeriveInventories derives the release's inventories and prints
// the list of documents the release decision covers.
func runDeriveInventories(ia *inventoriesArgs, doc io.Writer, out *latch) error {
	pol, err := loadAssertPolicy(ia.policy)
	if err != nil {
		return fmt.Errorf("derive inventories: %w", err)
	}

	run := &inventoriesRun{ia: ia, pol: pol, suffix: *pol.Evidence.SBOMSuffix, base: baseName(ia), out: out}

	carries, planned, err := judgeClassCombination(splitList(ia.classes))
	if err != nil {
		return err
	}

	var covered []string

	switch {
	case ia.binariesDir != "" && len(planned) == 0:
		covered, err = run.fromBinaries(carries)
	case len(ia.plans) > 0:
		covered, err = run.fromPlans()
	default:
		covered, err = run.withoutPlans()
	}

	if err != nil {
		return err
	}

	if out.err == nil {
		out.err = jsonx.Encode(doc, covered)
	}

	out.logf("decision population: %s", strings.Join(quoteAll(covered), ","))

	return nil
}

// judgeClassCombination refuses the class sets the release contract
// cannot describe, and returns the classes whose binaries carry their
// own inventory and the classes that plan theirs.
//
//nolint:gocritic // unnamedResult: the two class sets, documented above
func judgeClassCombination(classes []string) ([]string, []string, error) {
	var carries, planned []string

	for _, class := range classes {
		switch release.InventoryRoleOf(class) {
		case release.InventoryCarriedByBinaries:
			carries = append(carries, class)
		case release.InventoryNone:
		case release.InventoryPlanned:
			planned = append(planned, class)
		}
	}

	// A binaries-carry class beside a planning class would take the
	// plan path, where the binaries have no plan to offer, and the
	// release would publish an inventory omitting them (.github#784).
	if len(carries) > 0 && len(planned) > 0 {
		return nil, nil, fmt.Errorf(
			"derive inventories: %s cannot yet ship beside %s: the inventory would omit the binaries'"+
				" packages (.github#784)", strings.Join(carries, ","), strings.Join(planned, ","),
		)
	}

	return carries, planned, nil
}

// fromBinaries is the release whose shipped binaries speak for it:
// one inventory, read out of the shipped bytes.
func (r *inventoriesRun) fromBinaries(carries []string) ([]string, error) {
	// An image beside the binaries adds no inventory of its own, but a
	// leg that planned one would be dropped here: the two shapes
	// disagree about what the release ships, and only the caller can
	// say which it meant (#775).
	if len(r.ia.plans) > 0 {
		return nil, errors.New("derive inventories: a build leg emitted an inventory plan while the shipped binaries" +
			" would speak for the whole release — the two describe different artifact sets; declare the classes" +
			" that own the plan, or drop the planning leg")
	}

	bins, err := listFiles(r.ia.binariesDir)
	if err != nil {
		return nil, fmt.Errorf("derive inventories: %w", err)
	}

	if len(bins) == 0 {
		return nil, errors.New("derive inventories: the binaries directory holds no binaries — an inventory of" +
			" nothing asserts nothing")
	}

	document, legs, err := binaryDocument(&sbomArgs{
		binaries: bins, expectVersion: r.ia.version, expectRevision: r.ia.expectRevision,
	})
	if err != nil {
		return nil, err
	}

	if err := r.write(r.viewName(), document); err != nil {
		return nil, err
	}

	r.out.logf("%s: %d packages from %d binary leg(s) of %s", r.viewName(), len(document.Packages), legs,
		strings.Join(carries, ","))

	// The release decides as one release: one population member, the
	// release itself.
	return []string{""}, nil
}

// fromPlans judges the build legs' plans, derives one document per
// judged entry, checks every requested major is covered, and folds the
// release view from the documents.
func (r *inventoriesRun) fromPlans() ([]string, error) {
	entries, err := r.judgePlans()
	if err != nil {
		return nil, err
	}

	docs := make([]*sbom.Document, 0, len(entries))
	covered := map[string]bool{}

	for _, e := range entries {
		document, derr := r.derivePlanned(e)
		if derr != nil {
			return nil, derr
		}

		name := *e.Doc + "-" + r.ia.version + r.suffix
		if werr := r.write(name, document); werr != nil {
			return nil, werr
		}

		r.out.logf("%s: %d packages", name, len(document.Packages))

		docs = append(docs, document)
		covered[name] = true
	}

	if cerr := r.coverMajors(entries); cerr != nil {
		return nil, cerr
	}

	view, err := sbom.Union(r.base+"@v"+r.ia.version, r.ia.created, "stele-"+selfVersion(), docs)
	if err != nil {
		return nil, err
	}

	if err := r.write(r.viewName(), view); err != nil {
		return nil, err
	}

	r.out.logf("%s: %d packages aggregated from %d artifact(s)", r.viewName(), len(view.Packages)-1, len(docs))

	// The view bears no decision of its own (#492): it is not listed.
	list := make([]string, 0, len(covered))
	for name := range covered {
		list = append(list, name)
	}

	sort.Strings(list)

	return list, nil
}

// judgePlans runs `assert plans` over the handed plan files and
// returns the set it judged. A judgment that does not pass is a
// refusal carrying the findings: nothing is derived from plans that
// did not pass.
func (r *inventoriesRun) judgePlans() ([]assert.PlanEntry, error) {
	files := make([]assert.PlanFile, 0, len(r.ia.plans))

	for _, path := range r.ia.plans {
		content, err := os.ReadFile(path) //nolint:gosec // the plan paths are operator-supplied by design
		if err != nil {
			return nil, fmt.Errorf("derive inventories: %w", err)
		}

		files = append(files, assert.PlanFile{Name: path, Content: content})
	}

	rep := assert.Plans(r.pol, splitList(r.ia.evidenceClasses), r.ia.machinery, files, report.NewJournal(), r.out.logf)
	if !rep.Passed() {
		findings := make([]string, 0, len(rep.Findings()))
		for _, f := range rep.Findings() {
			findings = append(findings, f.Subject+": "+f.Assertion+": "+f.Detail)
		}

		return nil, fmt.Errorf("derive inventories: the plans did not pass judgment (%s): %s",
			rep.Verdict(), strings.Join(findings, "; "))
	}

	entries, err := jsonx.DecodeBytes[[]assert.PlanEntry](rep.Judged())
	if err != nil {
		return nil, fmt.Errorf("derive inventories: the judged plan set: %w", err)
	}

	return *entries, nil
}

// plannedParams is the cargo closure description a plan entry carries.
type plannedParams struct {
	CargoPackage      *string  `json:"cargoPackage"`
	Features          []string `json:"features,omitempty"`
	NoDefaultFeatures *bool    `json:"noDefaultFeatures,omitempty"`
}

// derivePlanned derives one judged entry's document from the tree.
func (r *inventoriesRun) derivePlanned(e assert.PlanEntry) (*sbom.Document, error) {
	params, err := entryParams(e)
	if err != nil {
		return nil, err
	}

	sa := &sbomArgs{
		cargoRoot: *params.CargoPackage, tree: r.ia.tree, created: r.ia.created,
		features: strings.Join(params.Features, ","),
	}

	if params.NoDefaultFeatures != nil {
		sa.noDefaultFeatures = *params.NoDefaultFeatures
	}

	if e.Artifact != nil {
		sa.artifact = *e.Artifact
	}

	document, err := cargoDocument(sa)
	if err != nil {
		return nil, fmt.Errorf("derive inventories: %s: %w", *e.Doc, err)
	}

	return document, nil
}

// entryParams reads the closure description of one judged entry. The
// judgment guards params' charset and leaves their content to the leg
// that derives the document — this one — so a missing package is
// refused here, by the entry's name.
func entryParams(e assert.PlanEntry) (*plannedParams, error) {
	if len(e.Params) == 0 {
		return nil, fmt.Errorf("derive inventories: %s: the plan names no closure (params are absent)", *e.Doc)
	}

	params, err := jsonx.DecodeBytes[plannedParams](e.Params)
	if err != nil {
		return nil, fmt.Errorf("derive inventories: %s: params: %w", *e.Doc, err)
	}

	if params.CargoPackage == nil || *params.CargoPackage == "" {
		return nil, fmt.Errorf("derive inventories: %s: params.cargoPackage is absent — the closure has no root",
			*e.Doc)
	}

	return params, nil
}

// coverMajors refuses a requested Postgres major no planned extension
// document covers: one crate built once per major is several
// artifacts, and each owes its own inventory (#492).
func (r *inventoriesRun) coverMajors(entries []assert.PlanEntry) error {
	majors := splitList(r.ia.pgMajors)
	if len(majors) == 0 {
		return nil
	}

	extensions := release.ExtensionClasses()

	for _, major := range majors {
		found := false

		for _, e := range entries {
			if !extensions[*e.Class] || e.Artifact == nil {
				continue
			}

			params, err := entryParams(e)
			if err != nil {
				return err
			}

			if *e.Artifact == release.ExtensionArtifact(*params.CargoPackage, major) {
				found = true
			}
		}

		if !found {
			return fmt.Errorf("derive inventories: pg-majors names %s but no extension inventory covers it", major)
		}
	}

	return nil
}

// withoutPlans is a release no leg planned for: refused when the tree
// tracks a dependency manifest, else the forge's dependency graph.
func (r *inventoriesRun) withoutPlans() ([]string, error) {
	tracked, err := trackedManifests(r.ia.tree)
	if err != nil {
		return nil, fmt.Errorf("derive inventories: %w", err)
	}

	if len(tracked) > 0 {
		return nil, fmt.Errorf("derive inventories: this release tracks a manifest (%s) but no build leg emitted an"+
			" inventory plan — the per-release inventory is aggregated from per-artifact documents (#492), and the"+
			" artifact-to-package mapping lives in the build leg that holds it (#537); release through a class"+
			" whose build emits plans", strings.Join(tracked, ", "))
	}

	owner, repo, _ := strings.Cut(r.ia.repo, "/")

	raw, err := newDependencyGraph().DependencyGraphSBOM(owner, repo)
	if err != nil {
		return nil, fmt.Errorf("derive inventories: %w", err)
	}

	document, err := sbom.AdmitBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("derive inventories: the dependency graph: %w", err)
	}

	if err := r.write(r.viewName(), document); err != nil {
		return nil, err
	}

	r.out.logf("%s: %d packages from the forge's dependency graph", r.viewName(), len(document.Packages))

	return []string{""}, nil
}

// viewName is the release view's asset name.
func (r *inventoriesRun) viewName() string { return r.base + "-" + r.ia.version + r.suffix }

// write admits one document and writes it into the output directory.
func (r *inventoriesRun) write(name string, document *sbom.Document) error {
	path := filepath.Join(r.ia.outDir, name)

	discard := &latch{w: io.Discard}

	if err := writeInventory(path, document, io.Discard, discard); err != nil {
		return err
	}

	return nil
}

// baseName is the release view's base: the caller's, else the
// repository's own name, with a leading dot stripped — a dotfile is
// skipped by every glob that collects release assets.
func baseName(ia *inventoriesArgs) string {
	base := ia.name
	if base == "" {
		_, base, _ = strings.Cut(ia.repo, "/")
	}

	return strings.TrimPrefix(base, ".")
}

// listFiles lists every regular file under dir, sorted.
func listFiles(dir string) ([]string, error) {
	var files []string

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.Type().IsRegular() {
			files = append(files, path)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing the binaries: %w", err)
	}

	sort.Strings(files)

	return files, nil
}

// splitList splits a comma list, dropping empty entries.
func splitList(s string) []string {
	var out []string

	for item := range strings.SplitSeq(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}

	return out
}

// quoteAll renders names for a log line.
func quoteAll(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, fmt.Sprintf("%q", n))
	}

	return out
}
