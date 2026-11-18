package sbom_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/sbom"
)

// spdxWith renders a minimal SPDX document, named img, carrying the given PURLs,
// one package each — the shape an image scanner hands over.
func spdxWith(purls ...string) string {
	pkgs := make([]string, 0, len(purls))
	for i, p := range purls {
		pkgs = append(pkgs, `{"SPDXID": "SPDXRef-`+strings.Repeat("p", i+1)+`", "name": "p",`+
			` "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",`+
			` "referenceLocator": "`+p+`"}]}`)
	}

	return `{"spdxVersion": "SPDX-2.3", "name": "img", "packages": [` + strings.Join(pkgs, ", ") + `]}`
}

// TestAdmit holds the one admissibility rule: zero PURLs, or any
// versionless PURL, is refused by name, with the counts the canon's
// three shell copies printed.
func TestAdmit(t *testing.T) {
	t.Parallel()

	const tail = " — a versionless PURL is invisible to every scanner, so an inventory carrying one gates on a set" +
		" it cannot see"

	tests := []struct {
		name string
		doc  string
		want string // "" admits
	}{
		{name: "every PURL versioned", doc: spdxWith("pkg:deb/debian/libc6@2.36-9", "pkg:golang/stdlib@v1.26.6")},
		{name: "a scoped npm PURL, scope encoded", doc: spdxWith("pkg:npm/%40acme/widget@1.0.0")},
		{name: "a version before qualifiers", doc: spdxWith("pkg:deb/debian/libc6@2.36-9?arch=amd64")},
		{
			name: "a package with no PURL beside one with a versioned PURL",
			doc: `{"name": "img", "packages": [{"name": "os", "externalRefs": [{"referenceType": "cpe23Type",` +
				` "referenceLocator": "cpe:2.3:o:debian"}]}, {"name": "p", "externalRefs": [{"referenceType": "purl",` +
				` "referenceLocator": "pkg:deb/debian/libc6@2.36-9"}]}]}`,
		},
		{
			name: "no PURL at all",
			doc:  spdxWith(),
			want: "sbom: img has 0 PURLs, 0 versionless" + tail,
		},
		{
			name: "only non-PURL references",
			doc: `{"name": "img", "packages": [{"name": "os", "externalRefs": [{"referenceType": "cpe23Type",` +
				` "referenceLocator": "cpe:2.3:o:debian"}]}]}`,
			want: "sbom: img has 0 PURLs, 0 versionless" + tail,
		},
		{
			name: "one versionless PURL",
			doc:  spdxWith("pkg:deb/debian/libc6@2.36-9", "pkg:github/acme/widget"),
			want: "sbom: img has 2 PURLs, 1 versionless (pkg:github/acme/widget)" + tail,
		},
		{
			name: "an empty version",
			doc:  spdxWith("pkg:npm/widget@"),
			want: "sbom: img has 1 PURLs, 1 versionless (pkg:npm/widget@)" + tail,
		},
		{
			name: "an unencoded scope's @ is not a version",
			doc:  spdxWith("pkg:npm/@acme/widget"),
			want: "sbom: img has 1 PURLs, 1 versionless (pkg:npm/@acme/widget)" + tail,
		},
		{
			name: "an @ in the qualifiers is not a version",
			doc:  spdxWith("pkg:generic/widget?download_url=https://x@y/z"),
			want: "1 versionless (pkg:generic/widget?download_url=https://x@y/z)",
		},
		{
			name: "many versionless PURLs are counted, three named",
			doc:  spdxWith("pkg:a/one", "pkg:a/two", "pkg:a/three", "pkg:a/four", "pkg:a/five"),
			want: "sbom: img has 5 PURLs, 5 versionless (pkg:a/one, pkg:a/two, pkg:a/three, and 2 more)" + tail,
		},
		{
			name: "not JSON",
			doc:  "not json",
			want: "sbom: not an SPDX JSON document",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc, err := sbom.AdmitBytes([]byte(tt.doc))

			if tt.want == "" {
				if err != nil || doc == nil {
					t.Fatalf("AdmitBytes = %v, %v; want the document admitted", doc, err)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("AdmitBytes error = %v\nwant it to carry %q", err, tt.want)
			}
		})
	}
}
