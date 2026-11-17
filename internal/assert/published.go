// This file: the published-bytes proof (stele#392). Every file subject
// a release declares is pulled back from the store that serves it and
// its bytes compared to the digest the build recorded; every image
// subject's advertised tag is asked of its registry and compared to the
// attested index. The manifest this judgment passes is what the signer
// attests next, so the attested subject is what SHIPPED, not what was
// hoped to ship.
//
// Where a file is served is declared, never guessed: the policy's
// `published.registries` claim subjects by extension and say, by URL
// template, where each is served; a subject no registry claims is a
// release asset when the caller declared a release, and refused when it
// did not. No registry host or path is written here — the hosts are the
// policy's, the forge's release-asset address is internal/gh's.
//
// Two answers are kept apart all the way out (docs/report-schema.md):
// a store that served other bytes, or a tag that names another index,
// is divergence — FAIL; a store that would not answer within the
// waiting rule is a run that could not look — CANNOT_JUDGE, named.

package assert

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/published"
	"github.com/monumental-archive/stele/internal/report"
)

// The assertion vocabulary for published findings.
const (
	assertPublishedBytes = "published-bytes"
	assertTagBinding     = "tag-binding"
	assertPublishedRead  = "published-read"
)

// PublishedPolicy declares where a release's file subjects are served
// (stele#392). Its PRESENCE is the declaration `assert published`
// needs: absent, the target refuses at use, because which registry
// serves which file is the policy's to say. The list may be empty — an
// organisation whose files are all release assets, and whose images
// prove themselves by tag binding, declares no registry at all.
type PublishedPolicy struct {
	Registries []Registry `json:"registries,omitempty"`
}

// Registry is one store that serves published files: the subjects it
// claims, by extension, and the URL template it serves each one at.
//
// The template's vocabulary is closed and refused at load:
//
//	{file}      the subject's file name
//	{name}      the package name    ┐ from the coordinate:
//	{version}   the package version │ the file name, or the
//	{basename}  {name} after its    │ caller's declared package
//	            last "/"            ┘
//
// Placeholders live in the path alone: a subject may never choose the
// host it is fetched from.
type Registry struct {
	Extension *string `json:"extension"`
	URL       *string `json:"url"`
	// Coordinate says where {name} and {version} come from, when the
	// template uses them: "file" reads them out of the subject's file
	// name, <name>-<version><extension>, the version a semantic
	// version; "declared" takes the package the caller declares for
	// this extension, because some packers mangle the name into the
	// file (a scoped npm package packs as scope-name-<version>.tgz).
	Coordinate *string `json:"coordinate,omitempty"`
}

// The coordinate kinds. Kinds are code; which registry uses which is
// the policy's.
const (
	CoordinateFile     = "file"
	CoordinateDeclared = "declared"
)

// The template placeholders.
const (
	phFile     = "{file}"
	phName     = "{name}"
	phVersion  = "{version}"
	phBasename = "{basename}"
)

var (
	templatePlaceholderRE = regexp.MustCompile(`\{[^{}]*\}`)
	extensionRE           = regexp.MustCompile(`^\.[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// validate holds the section to its grammar at load; an absent section
// declares nothing to hold.
func (pp *PublishedPolicy) validate() error {
	if pp == nil {
		return nil
	}

	for i := range pp.Registries {
		if err := pp.Registries[i].validate(i); err != nil {
			return err
		}
	}

	// One subject, one registry: an extension that ends another (".gz"
	// beside ".tar.gz") would claim the same file twice.
	for i := range pp.Registries {
		for k := i + 1; k < len(pp.Registries); k++ {
			a, b := *pp.Registries[i].Extension, *pp.Registries[k].Extension
			if strings.HasSuffix(a, b) || strings.HasSuffix(b, a) {
				return fmt.Errorf("published.registries[%d] and [%d] both claim a file ending in %q — "+
					"one subject, one registry", i, k, longer(a, b))
			}
		}
	}

	return nil
}

func longer(a, b string) string {
	if len(a) >= len(b) {
		return a
	}

	return b
}

func (r *Registry) validate(i int) error {
	field := fmt.Sprintf("published.registries[%d]", i)

	if r.Extension == nil || !extensionRE.MatchString(*r.Extension) {
		return fmt.Errorf(`%s.extension must be present and a file extension (".crate", ".tar.gz")`, field)
	}

	if r.Coordinate != nil && *r.Coordinate != CoordinateFile && *r.Coordinate != CoordinateDeclared {
		return fmt.Errorf("%s.coordinate %q is not a coordinate (%s, %s)",
			field, *r.Coordinate, CoordinateFile, CoordinateDeclared)
	}

	if r.URL == nil || !strings.HasPrefix(*r.URL, "https://") {
		return fmt.Errorf("%s.url must be present and an https URL template", field)
	}

	return r.validateTemplate(field)
}

// validateTemplate holds the template's vocabulary and its shape: the
// host fixed, the placeholders in the path, no query to escape into.
func (r *Registry) validateTemplate(field string) error {
	tmpl := *r.URL

	host, _, _ := strings.Cut(strings.TrimPrefix(tmpl, "https://"), "/")
	if strings.ContainsAny(host, "{}") {
		return fmt.Errorf("%s.url places a placeholder in the host — a subject must not choose where it is fetched from",
			field)
	}

	if strings.ContainsAny(tmpl, "?#") {
		return fmt.Errorf("%s.url carries a query or a fragment — a registry serves a file by its path", field)
	}

	found := templatePlaceholderRE.FindAllString(tmpl, -1)
	if len(found) == 0 {
		return fmt.Errorf("%s.url carries no placeholder — every subject would be fetched from one address", field)
	}

	for _, ph := range found {
		switch ph {
		case phFile:
		case phName, phVersion, phBasename:
			if r.Coordinate == nil {
				return fmt.Errorf("%s.url uses %s, which needs a coordinate — declare where the name and version"+
					" come from (%s, %s)", field, ph, CoordinateFile, CoordinateDeclared)
			}
		default:
			return fmt.Errorf("%s.url carries placeholder %s — the vocabulary is {file}, {name}, {version} and"+
				" {basename}", field, ph)
		}
	}

	// The fixed text around the placeholders must itself be a URL.
	dummy := templatePlaceholderRE.ReplaceAllString(tmpl, "x")
	if u, err := url.Parse(dummy); err != nil || u.Host == "" {
		return fmt.Errorf("%s.url is not a URL template", field)
	}

	return nil
}

// Package is one declared package coordinate: the name and version a
// caller states for the files of one extension.
type Package struct {
	Name    string
	Version string
}

// Locator says where each file subject of one release is served. The
// release is optional: without one, a subject no registry claims is
// refused, never guessed to be an asset.
type Locator struct {
	Registries []Registry
	// Packages are the caller's declared coordinates, by extension.
	Packages map[string]Package
	// Asset builds a release asset's public address; nil when the
	// caller declared no release.
	Asset func(name string) string
}

// Locate is the URL one file subject is served at. Every refusal here
// is a refusal of the input — it happens before any store is asked.
func (l *Locator) Locate(file string) (string, error) {
	for i := range l.Registries {
		r := &l.Registries[i]
		if strings.HasSuffix(file, *r.Extension) && len(file) > len(*r.Extension) {
			return r.expand(file, l.Packages)
		}
	}

	if l.Asset == nil {
		return "", fmt.Errorf("%s: no registry claims this subject type and no release-tag was declared", file)
	}

	return l.Asset(file), nil
}

// expand fills the template for one subject. Only the placeholders the
// template carries are computed, so a coordinate the URL never reads
// cannot refuse a subject.
func (r *Registry) expand(file string, packages map[string]Package) (string, error) {
	values := map[string]string{phFile: file}

	if strings.Contains(*r.URL, phName) || strings.Contains(*r.URL, phVersion) ||
		strings.Contains(*r.URL, phBasename) {
		pkg, err := r.coordinate(file, packages)
		if err != nil {
			return "", err
		}

		values[phName] = pkg.Name
		values[phVersion] = pkg.Version
		values[phBasename] = pkg.Name[strings.LastIndex(pkg.Name, "/")+1:]
	}

	var bad error

	out := templatePlaceholderRE.ReplaceAllStringFunc(*r.URL, func(ph string) string {
		escaped, err := escapePath(values[ph], ph == phName)
		if err != nil && bad == nil {
			bad = fmt.Errorf("%s: %s %w", file, ph, err)
		}

		return escaped
	})

	return out, bad
}

// coordinate reads the subject's package name and version.
func (r *Registry) coordinate(file string, packages map[string]Package) (Package, error) {
	ext := *r.Extension

	if *r.Coordinate == CoordinateDeclared {
		pkg, ok := packages[ext]
		if !ok {
			return Package{}, fmt.Errorf("%s is a %s subject but no package was declared for %s", file, ext, ext)
		}

		return pkg, nil
	}

	// <name>-<version><extension>: the version is the first split whose
	// remainder is a semantic version, so a hyphenated name and a
	// pre-release version both survive (foo-bar-1.0.0-rc.1).
	stem := strings.TrimSuffix(file, ext)

	for i := range len(stem) {
		if stem[i] != '-' || i == 0 {
			continue
		}

		if _, err := semver.StrictNewVersion(stem[i+1:]); err == nil {
			return Package{Name: stem[:i], Version: stem[i+1:]}, nil
		}
	}

	return Package{}, fmt.Errorf("%s: the file name is not <name>-<version>%s", file, ext)
}

// escapePath escapes one value for a URL path. A value that may span
// segments (a scoped package name) is escaped segment by segment; any
// other is one segment. Either way, a segment that is empty or that
// would walk the path instead of naming a file in it refuses.
func escapePath(v string, multi bool) (string, error) {
	parts := []string{v}
	if multi {
		parts = strings.Split(v, "/")
	}

	for i, p := range parts {
		if p == "" || p == "." || p == ".." {
			return "", fmt.Errorf("%q cannot stand in a URL path", v)
		}

		parts[i] = url.PathEscape(p)
	}

	return strings.Join(parts, "/"), nil
}

// PublishedFile is one file subject with the address it is served at,
// located before the judgment begins.
type PublishedFile struct {
	Name   string
	SHA256 string
	URL    string
}

// BytesFetcher pulls one published file and returns the sha256 of what
// was served — internal/published's Fetcher, which owns the waiting
// rule; every refusal it returns is a store that would not answer.
type BytesFetcher interface {
	Fetch(name, url string) (string, error)
}

// ImageResolver asks a registry which digest a tag names now: "" when
// it names none. oci.Reader's Resolve is the production one.
type ImageResolver interface {
	Resolve(image, tag string) (string, error)
}

// Published judges one release's declared subjects against the stores
// that serve them and seals the verdict. subject names the release.
//
// The first store that will not answer ends the walk: it is recorded,
// named, as a read this run could not make, and the population comes
// up short — CANNOT_JUDGE, with whatever was judged before it carried.
// A registry that is down is not asked about the rest, because every
// one of those asks would wait out the same rule.
//
// On PASS the report carries the proven manifest as its judged set —
// sha256sum lines, re-derived from what was served — which is what the
// caller writes out for the signer: the set that passed judgment, never
// a second reading of the inputs.
func Published(
	subject string, files []PublishedFile, images []published.Image,
	fetch BytesFetcher, registry ImageResolver, j *report.Journal, log Logf,
) *report.Report {
	total := len(files) + len(images)
	looked := 0
	lines := make([]string, 0, total)

	seal := func() *report.Report {
		pop := report.PopulationAgainstDeclared(looked, total, "declared file and image subjects")

		judged, err := jsonx.Marshal(lines)
		if err != nil {
			// A slice of strings always renders; kept fail-closed so a
			// run that cannot state what it proved states nothing.
			judged = nil
		}

		return report.Seal("assert published", subject, pop, j, report.NoCanary(), report.Judged(judged))
	}

	for _, f := range files {
		served, err := fetch.Fetch(f.Name, f.URL)
		if err != nil {
			j.Check(f.Name, assertPublishedRead).Diverged(err.Error())

			return seal()
		}

		looked++

		if c := j.Check(f.Name, assertPublishedBytes); served != f.SHA256 {
			c.DivergedFrom(f.SHA256, served, "the store served other bytes than were built")

			continue
		}

		lines = append(lines, published.Line{SHA256: served, Name: f.Name}.String())
		log("assert: published: verified %s", f.Name)
	}

	for _, img := range images {
		ref := img.Image + ":" + img.Tag

		resolved, err := registry.Resolve(img.Image, img.Tag)
		if err != nil {
			j.Check(ref, assertPublishedRead).Diverged(err.Error())

			return seal()
		}

		looked++

		if c := j.Check(ref, assertTagBinding); resolved != img.Digest {
			if resolved == "" {
				resolved = "nothing"
			}

			c.DivergedFrom(img.Digest, resolved, "the tag does not resolve to the attested index")

			continue
		}

		// The UNTAGGED reference: the subject name the signer attested.
		lines = append(lines, published.Line{SHA256: strings.TrimPrefix(img.Digest, "sha256:"), Name: img.Image}.String())
		log("assert: published: verified tag binding for %s", ref)
	}

	log("assert: published: %d file subject(s) and %d image subject(s) judged", len(files), len(images))

	return seal()
}
