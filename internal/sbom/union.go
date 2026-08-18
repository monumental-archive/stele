// The union view: one release's inventory, AGGREGATED from the
// per-artifact documents rather than derived a second time.
//
// The unit of description is the artifact, because the artifact is
// the unit of consumption — a consumer holds one artifact verified by
// one digest, and the inventory that travels with it should describe
// what is in that artifact and nothing else. The per-release document
// remains, because some consumers want exactly that, but it is a
// VIEW: produced by folding the per-artifact documents together, never
// derived independently.
//
// That distinction is the whole file. Union's input is []*Document
// and nothing else — it cannot be handed a source tree or a lockfile,
// so "derive the union separately" is not a thing a caller can
// express. Two independent derivations of one inventory is the same
// defect class as two implementations of a digest: they agree until
// the day they do not, and then nobody can say which was right.
//
// What Union does NOT do is assert that its inputs agree about
// versions. That assertion belongs to the go-binary derivation, where
// it is justified — the platform legs of ONE binary share one module
// graph, so two versions of a package there means the legs were not
// built from one source. Across ARTIFACTS the same divergence is
// ordinary: a Rust binary and an npm package legitimately resolve
// different versions of a shared dependency. The union records both,
// each naming the artifacts that ship it. Enforcement that a release's
// artifacts belong together lives where it can see the release —
// `assert evidence`, against the declared class obligations — and
// never here, where a refusal would be a guess.

package sbom

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrNoDocuments reports a union asked to aggregate nothing.
var ErrNoDocuments = errors.New("sbom: no documents to aggregate")

// artifact is one input document reduced to what the union needs: the
// name it describes, and its packages.
type artifact struct {
	name     string
	packages []Package
}

// shipped is one package in the union, with the artifacts carrying it.
type shipped struct {
	pkg       Package
	artifacts []string
}

// Union folds per-artifact documents into one release view. name is
// the release the view describes and tool names the creator; created
// is the release's own instant, never a clock reading, so the view
// renders the same bytes as often as it is built.
func Union(name, created, tool string, docs []*Document) (*Document, error) {
	if len(docs) == 0 {
		return nil, ErrNoDocuments
	}

	if created == "" {
		return nil, errors.New("sbom: the union needs the release instant its inputs share")
	}

	arts := make([]artifact, 0, len(docs))

	for i, doc := range docs {
		if doc == nil || len(doc.Packages) == 0 {
			return nil, fmt.Errorf("sbom: document %d describes nothing", i)
		}

		arts = append(arts, artifact{name: doc.Packages[0].Name, packages: doc.Packages[1:]})
	}

	return renderUnion(name, created, tool, arts), nil
}

// renderUnion builds the view. Packages are keyed by (name, version),
// so one package at two versions across artifacts is two entries —
// each naming who ships it — rather than one entry silently choosing
// a winner.
func renderUnion(name, created, tool string, arts []artifact) *Document {
	byKey := map[string]*shipped{}

	for _, art := range arts {
		for _, pkg := range art.packages {
			key := pkg.Name + "\x00" + pkg.VersionInfo

			entry, seen := byKey[key]
			if !seen {
				// SourceInfo is rebuilt from this view's own membership:
				// the input's "linked into" describes ITS platform legs,
				// which says nothing about which artifacts ship it.
				pkg.SourceInfo = ""
				entry = &shipped{pkg: pkg}
				byKey[key] = entry
			}

			entry.artifacts = append(entry.artifacts, art.name)
		}
	}

	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	doc := &Document{
		SPDXVersion:       spdxVersion,
		DataLicense:       spdxDataLicHse,
		SPDXID:            documentID,
		Name:              name,
		DocumentNamespace: "https://spdx.org/spdxdocs/" + strings.ReplaceAll(name, "/", "-") + "-union",
		CreationInfo:      CreationInfo{Created: created, Creators: []string{"Tool: " + tool}},
	}

	root := Package{
		SPDXID:           rootPackageID,
		Name:             name,
		DownloadLocation: noAssertion,
		PrimaryPurpose:   purposeApp,
		SourceInfo:       "aggregated from " + strings.Join(artifactNames(arts), ", "),
	}

	doc.Packages = append(doc.Packages, root)
	doc.Relationships = append(doc.Relationships, Relationship{
		SPDXElementID:      documentID,
		RelatedSPDXElement: root.SPDXID,
		RelationshipType:   relDescribes,
	})

	for i, key := range keys {
		entry := byKey[key]
		pkg := entry.pkg
		pkg.SPDXID = fmt.Sprintf("SPDXRef-Package-%d", i+1)
		pkg.SourceInfo = shippedIn(entry.artifacts, arts)

		doc.Packages = append(doc.Packages, pkg)
		doc.Relationships = append(doc.Relationships, Relationship{
			SPDXElementID:      root.SPDXID,
			RelatedSPDXElement: pkg.SPDXID,
			RelationshipType:   relDependsOn,
		})
	}

	return doc
}

// shippedIn names the artifacts carrying a package, and only when
// that is a strict subset — the honesty the view costs. A reader of a
// union covering five artifacts needs to know which two ship a
// package, or the view over-claims exactly the way the per-release
// document did before it became a view.
func shippedIn(carriers []string, arts []artifact) string {
	unique := dedupe(carriers)
	if len(unique) == len(arts) {
		return ""
	}

	return "shipped in: " + strings.Join(unique, ", ")
}

func artifactNames(arts []artifact) []string {
	out := make([]string, 0, len(arts))
	for _, a := range arts {
		out = append(out, a.name)
	}

	sort.Strings(out)

	return out
}

func dedupe(values []string) []string {
	seen := map[string]bool{}

	out := make([]string, 0, len(values))

	for _, v := range values {
		if seen[v] {
			continue
		}

		seen[v] = true

		out = append(out, v)
	}

	sort.Strings(out)

	return out
}

// FromPackages renders one artifact's inventory from a resolved
// closure: the artifact itself as the root, its dependencies beneath.
//
// The closure is computed by whoever owns the ecosystem's resolver
// (internal/cargo for Cargo), so this function does no resolution of
// its own — it is the SPDX rendering and nothing else. Keeping the two
// apart is what lets a second ecosystem arrive without touching either.
func FromPackages(artifact, created, tool string, deps []Package) (*Document, error) {
	switch {
	case artifact == "":
		return nil, errors.New("sbom: the artifact must be named")
	case created == "":
		return nil, errors.New("sbom: the artifact's own instant is required, never a clock reading")
	case len(deps) == 0:
		return nil, errors.New("sbom: an inventory of nothing asserts nothing")
	}

	doc := &Document{
		SPDXVersion:       spdxVersion,
		DataLicense:       spdxDataLicHse,
		SPDXID:            documentID,
		Name:              artifact,
		DocumentNamespace: "https://spdx.org/spdxdocs/" + strings.ReplaceAll(artifact, "/", "-"),
		CreationInfo:      CreationInfo{Created: created, Creators: []string{"Tool: " + tool}},
	}

	root := deps[0]
	root.SPDXID = rootPackageID
	root.PrimaryPurpose = purposeApp
	root.DownloadLocation = noAssertion

	doc.Packages = append(doc.Packages, root)
	doc.Relationships = append(doc.Relationships, Relationship{
		SPDXElementID:      documentID,
		RelatedSPDXElement: root.SPDXID,
		RelationshipType:   relDescribes,
	})

	for i, dep := range deps[1:] {
		dep.SPDXID = fmt.Sprintf("SPDXRef-Package-%d", i+1)
		dep.PrimaryPurpose = purposeLibrary
		dep.DownloadLocation = noAssertion

		doc.Packages = append(doc.Packages, dep)
		doc.Relationships = append(doc.Relationships, Relationship{
			SPDXElementID:      root.SPDXID,
			RelatedSPDXElement: dep.SPDXID,
			RelationshipType:   relDependsOn,
		})
	}

	return doc, nil
}

// CargoPackage renders one resolved Cargo package as an SPDX package.
// Every PURL is versioned by construction: a versionless one matches
// no advisory, so it is silently invisible to every scanner — which is
// the defect the canon's bash asserts against after the fact.
func CargoPackage(name, version string) Package {
	return Package{
		Name:         name,
		VersionInfo:  version,
		ExternalRefs: []ExternalRef{purlRef2("cargo", name, version)},
	}
}

// purlRef2 renders a versioned PURL for one ecosystem.
func purlRef2(ecosystem, name, version string) ExternalRef {
	return ExternalRef{
		ReferenceCategory: "PACKAGE-MANAGER",
		ReferenceType:     "purl",
		ReferenceLocator:  "pkg:" + ecosystem + "/" + name + "@" + version,
	}
}
