// Package sbom derives a release SBOM from shipped Go binaries — the
// module list the toolchain embedded at link time, read back out of the
// artifact bytes with debug/buildinfo. That source is the design (#46):
// a source-tree scan describes what COULD have been linked, the
// embedded list is what WAS, and the version is stamped into the
// binary by the toolchain from the tag rather than asserted by a
// pipeline that happens to know it.
//
// A release ships several binaries (GOOS × GOARCH), and their linked
// module sets may legitimately differ — platform-conditional imports
// pull platform-conditional modules. The release SBOM is therefore the
// UNION of the legs' inventories, with every fact the legs must share
// (main module, version, revision, commit time) asserted equal across
// them: divergence there means the legs were not built from one
// source, which is a refusal, not a merge.
package sbom

import (
	"errors"
	"fmt"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// Binary is one shipped artifact: the name errors report, and the
// build info read out of its bytes.
type Binary struct {
	Name string
	Info *debug.BuildInfo
}

// The build settings a release binary must carry. All are stamped by
// the toolchain when building a clean git checkout; their absence
// means the build was not the release shape (-buildvcs=false, a
// non-checkout tree) and the SBOM would describe nothing verifiable.
const (
	settingGOOS     = "GOOS"
	settingGOARCH   = "GOARCH"
	settingRevision = "vcs.revision"
	settingTime     = "vcs.time"
	settingModified = "vcs.modified"
)

// The SPDX literals both renderers share. Spec, not policy: these are
// what the format calls the document element, the not-asserted value,
// the version this writes and its data licence.
const (
	documentID     = "SPDXRef-DOCUMENT"
	rootPackageID  = "SPDXRef-Package-0"
	purposeApp     = "APPLICATION"
	purposeLibrary = "LIBRARY"
	relDescribes   = "DESCRIBES"
	relDependsOn   = "DEPENDS_ON"
	noAssertion    = "NOASSERTION"
	spdxVersion    = "SPDX-2.3"
	spdxDataLicHse = "CC0-1.0"
)

// ErrNoBinaries reports a derivation asked to describe nothing.
var ErrNoBinaries = errors.New("sbom: no binaries given")

// Document is the SPDX 2.3 document this package renders. Written
// with plain fields, not pointers: the union leg does decode foreign
// per-artifact documents into it, but leniently and never to
// distinguish absent from empty — validation there is structural (the
// DESCRIBES walk), not field-presence.
type Document struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      CreationInfo   `json:"creationInfo"`
	Packages          []Package      `json:"packages"`
	Relationships     []Relationship `json:"relationships"`
}

// CreationInfo dates the document. Created is the commit time read
// out of the binaries, never a wall clock: the same bytes must render
// the same document on every run, and the inventory IS a fact about
// that commit.
type CreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// Package is one module in the inventory.
type Package struct {
	SPDXID           string        `json:"SPDXID"`
	Name             string        `json:"name"`
	VersionInfo      string        `json:"versionInfo"`
	DownloadLocation string        `json:"downloadLocation"`
	PrimaryPurpose   string        `json:"primaryPackagePurpose"`
	SourceInfo       string        `json:"sourceInfo,omitempty"`
	ExternalRefs     []ExternalRef `json:"externalRefs"`
}

// ExternalRef carries the PURL — the identifier advisory matching
// runs on, which is why every one of them must be versioned.
type ExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// Relationship is one edge: the document describes the root, the root
// depends on each module.
type Relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

// module is one (path, version) the union collects, with the legs
// that linked it.
type module struct {
	path      string
	version   string
	platforms []string
}

// Derive reads the binaries' embedded module lists into one SPDX
// document. tool names the creator (e.g. "stele-v0.3.0").
func Derive(bins []Binary, tool string) (*Document, error) {
	if len(bins) == 0 {
		return nil, ErrNoBinaries
	}

	facts, err := sharedFacts(bins)
	if err != nil {
		return nil, err
	}

	inv, err := unionDeps(bins)
	if err != nil {
		return nil, err
	}

	return render(facts, tool, inv), nil
}

// facts are what every leg must agree on: one release, one commit.
type facts struct {
	mainPath    string
	mainVersion string
	revision    string
	created     string
}

// stamp is one binary's commit identity.
type stamp struct {
	revision string
	created  string
}

// inventory is the union the legs contribute to.
type inventory struct {
	mods      map[string]*module
	platforms []string
}

// sharedFacts reads the facts every leg must agree on, refusing the
// first divergence by name. Divergent legs were not built from one
// source, and an SBOM that averaged over that would describe no
// release at all.
func sharedFacts(bins []Binary) (*facts, error) {
	firstBin := bins[0]

	mainPath := firstBin.Info.Main.Path
	if mainPath == "" {
		return nil, fmt.Errorf("sbom: %s carries no main module path", firstBin.Name)
	}

	mainVersion := firstBin.Info.Main.Version
	if err := validReleaseVersion(firstBin.Name, mainVersion); err != nil {
		return nil, err
	}

	first, err := vcsFacts(firstBin)
	if err != nil {
		return nil, err
	}

	for _, b := range bins[1:] {
		if b.Info.Main.Path != mainPath || b.Info.Main.Version != mainVersion {
			return nil, fmt.Errorf("sbom: %s is %s@%s but %s is %s@%s — not one release",
				firstBin.Name, mainPath, mainVersion, b.Name, b.Info.Main.Path, b.Info.Main.Version)
		}

		st, vcsErr := vcsFacts(b)
		if vcsErr != nil {
			return nil, vcsErr
		}

		if *st != *first {
			return nil, fmt.Errorf("sbom: %s built at %s (%s) but %s at %s (%s) — not one commit",
				firstBin.Name, first.revision, first.created, b.Name, st.revision, st.created)
		}
	}

	return &facts{mainPath: mainPath, mainVersion: mainVersion, revision: first.revision, created: first.created}, nil
}

// validReleaseVersion refuses a main-module version the toolchain did
// not stamp from a release tag. "(devel)" is a build from an untagged
// or unclean checkout; a non-semver string is not a tag at all. Either
// way the artifact cannot name its own version, which is the one claim
// this SBOM exists to carry.
func validReleaseVersion(name, version string) error {
	if version == "" || version == "(devel)" {
		return fmt.Errorf("sbom: %s carries no release version (got %q): "+
			"a release binary is built from a clean checkout of the tagged commit, "+
			"which the toolchain stamps as the module version", name, version)
	}

	if !semver.IsValid(version) {
		return fmt.Errorf("sbom: %s carries main version %q, which is not a semantic version", name, version)
	}

	return nil
}

// vcsFacts reads the commit identity stamped into one binary,
// refusing a dirty or unstamped build.
func vcsFacts(b Binary) (*stamp, error) {
	revision := setting(b.Info, settingRevision)
	committed := setting(b.Info, settingTime)
	modified := setting(b.Info, settingModified)

	if revision == "" || committed == "" || modified == "" {
		return nil, fmt.Errorf("sbom: %s carries no VCS stamp: "+
			"built with -buildvcs=false or outside a checkout, so its inventory dates nothing", b.Name)
	}

	if modified != "false" {
		return nil, fmt.Errorf("sbom: %s was built from a modified tree (vcs.modified=%s): "+
			"its bytes match no commit, so nothing about them is attestable", b.Name, modified)
	}

	at, parseErr := time.Parse(time.RFC3339, committed)
	if parseErr != nil {
		return nil, fmt.Errorf("sbom: %s carries unreadable vcs.time %q: %w", b.Name, committed, parseErr)
	}

	return &stamp{revision: revision, created: at.UTC().Format("2006-01-02T15:04:05Z")}, nil
}

// unionDeps collects every linked module across the legs. One module
// at two versions is refused, not merged: with one go.mod the module
// graph resolves each path to exactly one version for every platform,
// so a conflict means the legs saw different lockfiles.
//
// A release may legitimately carry several binaries per platform — one
// module can hold several main packages, and every one of them ships
// for every leg. What may NOT recur is the same command on the same
// platform: that is the same file handed in twice, or two builds of
// one thing, and either way one of them is not in the release.
func unionDeps(bins []Binary) (*inventory, error) {
	inv := &inventory{mods: make(map[string]*module)}
	seen := make(map[string]string)
	platforms := make(map[string]bool)

	for _, b := range bins {
		platform, err := platformOf(b)
		if err != nil {
			return nil, err
		}

		key := platform + " " + b.Info.Path
		if prior, dup := seen[key]; dup {
			return nil, fmt.Errorf("sbom: %s and %s are both %s builds of %s — one binary per command per platform",
				prior, b.Name, platform, b.Info.Path)
		}

		seen[key] = b.Name

		platforms[platform] = true

		for _, dep := range b.Info.Deps {
			if err := collect(inv.mods, b, dep, platform); err != nil {
				return nil, err
			}
		}
	}

	for p := range platforms {
		inv.platforms = append(inv.platforms, p)
	}

	sort.Strings(inv.platforms)

	return inv, nil
}

// platformOf names the leg by its GOOS/GOARCH stamp.
func platformOf(b Binary) (string, error) {
	goos := setting(b.Info, settingGOOS)
	goarch := setting(b.Info, settingGOARCH)

	if goos == "" || goarch == "" {
		return "", fmt.Errorf("sbom: %s carries no GOOS/GOARCH stamp", b.Name)
	}

	return goos + "/" + goarch, nil
}

// collect adds one linked module to the union. A replaced module is
// recorded as its replacement — the code that was actually linked —
// and a replacement without a version (a directory replace) is
// refused: those bytes exist on one machine and match no publishable
// module, so no inventory can name them.
func collect(mods map[string]*module, b Binary, dep *debug.Module, platform string) error {
	path, version := dep.Path, dep.Version
	if dep.Replace != nil {
		path, version = dep.Replace.Path, dep.Replace.Version
	}

	if !semver.IsValid(version) {
		return fmt.Errorf("sbom: %s links %s at %q, which is not a published module version "+
			"(a directory replace, or a truncated build)", b.Name, path, version)
	}

	existing, ok := mods[path]
	if !ok {
		mods[path] = &module{path: path, version: version, platforms: []string{platform}}

		return nil
	}

	if existing.version != version {
		return fmt.Errorf("sbom: %s links %s@%s but another leg linked %s — the legs saw different lockfiles",
			b.Name, path, version, existing.version)
	}

	// Two commands on one platform both linking the module is still one
	// platform in the attribution.
	if !slices.Contains(existing.platforms, platform) {
		existing.platforms = append(existing.platforms, platform)
	}

	return nil
}

// render lays the union out as SPDX: root first, dependencies sorted
// by path, identifiers assigned in that order — the same bytes for
// the same facts on every run.
func render(f *facts, tool string, inv *inventory) *Document {
	deps := make([]*module, 0, len(inv.mods))
	for _, m := range inv.mods {
		deps = append(deps, m)
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].path < deps[j].path })

	name := f.mainPath + "@" + f.mainVersion

	doc := &Document{
		SPDXVersion:       spdxVersion,
		DataLicense:       spdxDataLicHse,
		SPDXID:            documentID,
		Name:              name,
		DocumentNamespace: "https://spdx.org/spdxdocs/" + strings.ReplaceAll(name, "/", "-") + "-" + f.revision,
		CreationInfo:      CreationInfo{Created: f.created, Creators: []string{"Tool: " + tool}},
	}

	root := Package{
		SPDXID:           rootPackageID,
		Name:             f.mainPath,
		VersionInfo:      f.mainVersion,
		DownloadLocation: noAssertion,
		PrimaryPurpose:   purposeApp,
		ExternalRefs:     []ExternalRef{purlRef(f.mainPath, f.mainVersion)},
	}

	doc.Packages = append(doc.Packages, root)
	doc.Relationships = append(doc.Relationships, Relationship{
		SPDXElementID:      documentID,
		RelatedSPDXElement: root.SPDXID,
		RelationshipType:   relDescribes,
	})

	for i, m := range deps {
		pkg := Package{
			SPDXID:           fmt.Sprintf("SPDXRef-Package-%d", i+1),
			Name:             m.path,
			VersionInfo:      m.version,
			DownloadLocation: noAssertion,
			PrimaryPurpose:   purposeLibrary,
			SourceInfo:       linkedInto(m.platforms, inv.platforms),
			ExternalRefs:     []ExternalRef{purlRef(m.path, m.version)},
		}

		doc.Packages = append(doc.Packages, pkg)
		doc.Relationships = append(doc.Relationships, Relationship{
			SPDXElementID:      root.SPDXID,
			RelatedSPDXElement: pkg.SPDXID,
			RelationshipType:   relDependsOn,
		})
	}

	return doc
}

// linkedInto states which legs linked a module — only when that is a
// strict subset, because that is the honesty the union costs: a
// reader of one inventory covering four binaries may need to know a
// module shipped in two of them.
func linkedInto(linked, all []string) string {
	if len(linked) == len(all) {
		return ""
	}

	sort.Strings(linked)

	return "linked into: " + strings.Join(linked, ", ")
}

// purlRef renders the module's package URL. The purl golang type
// lowercases namespace and name (the spec's rule, not a convenience);
// a Go module path's charset is a purl-safe ASCII subset, so no
// further escaping applies.
func purlRef(path, version string) ExternalRef {
	return ExternalRef{
		ReferenceCategory: "PACKAGE-MANAGER",
		ReferenceType:     "purl",
		ReferenceLocator:  "pkg:golang/" + strings.ToLower(path) + "@" + version,
	}
}

// setting reads one build setting by key; absent is "".
func setting(info *debug.BuildInfo, key string) string {
	for _, s := range info.Settings {
		if s.Key == key {
			return s.Value
		}
	}

	return ""
}
