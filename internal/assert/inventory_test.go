package assert_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/report"
)

// spdx renders an image-scanner-shaped SPDX document carrying the
// given PURLs, one package each.
func spdx(name string, purls ...string) []byte {
	pkgs := make([]string, 0, len(purls))
	for _, p := range purls {
		pkgs = append(pkgs, `{"name": "p", "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",`+
			` "referenceType": "purl", "referenceLocator": "`+p+`"}]}`)
	}

	return []byte(`{"spdxVersion": "SPDX-2.3", "name": "` + name + `", "packages": [` + strings.Join(pkgs, ", ") + `]}`)
}

// TestInventories: each handed document by the one rule — admitted,
// FAIL naming the document and each versionless PURL, FAIL for no PURL
// at all, CANNOT_JUDGE for a document that will not read or parse.
func TestInventories(t *testing.T) {
	t.Parallel()

	good := assert.InventoryFile{Name: "amd64.spdx.json", Content: spdx("img@amd64", "pkg:deb/debian/libc6@2.36-9")}

	type want struct{ subject, assertion, actual, detail string }

	tests := []struct {
		name    string
		files   []assert.InventoryFile
		verdict report.Verdict
		want    []want
	}{
		{
			name: "every document admits",
			files: []assert.InventoryFile{
				good, {Name: "arm64.spdx.json", Content: spdx("img@arm64", "pkg:golang/stdlib@v1.26.6")},
			},
			verdict: report.VerdictPass,
		},
		{
			name: "a versionless PURL",
			files: []assert.InventoryFile{good, {
				Name:    "arm64.spdx.json",
				Content: spdx("img@arm64", "pkg:deb/debian/libc6@2.36-9", "pkg:deb/debian/tzdata", "pkg:npm/x"),
			}},
			verdict: report.VerdictFail,
			want: []want{
				{"arm64.spdx.json", "versioned-purl", "pkg:deb/debian/tzdata", "a versionless PURL is invisible to every scanner"},
				{"arm64.spdx.json", "versioned-purl", "pkg:npm/x", "a versionless PURL is invisible to every scanner"},
			},
		},
		{
			name:    "no PURL at all",
			files:   []assert.InventoryFile{{Name: "empty.spdx.json", Content: spdx("img")}},
			verdict: report.VerdictFail,
			want: []want{
				{
					"empty.spdx.json", "inventory-purls", "",
					"the inventory carries no PURL — an inventory carrying none gates on nothing",
				},
			},
		},
		{
			name:    "a document that is not SPDX JSON",
			files:   []assert.InventoryFile{good, {Name: "page.html", Content: []byte("<html>404</html>")}},
			verdict: report.VerdictCannotJudge,
			want: []want{
				{"page.html", "inventory-readable", "", "no inventory was judged: sbom: not an SPDX JSON document"},
			},
		},
		{
			name:    "a document that could not be read",
			files:   []assert.InventoryFile{{Name: "gone.spdx.json", ReadErr: errors.New("no such file")}},
			verdict: report.VerdictCannotJudge,
			want: []want{
				{
					"gone.spdx.json", "inventory-readable", "",
					"the document could not be read, so no inventory was judged: no such file",
				},
			},
		},
		{
			name: "blindness outranks a finding",
			files: []assert.InventoryFile{
				{Name: "gone.spdx.json", ReadErr: errors.New("no such file")},
				{Name: "empty.spdx.json", Content: spdx("img")},
			},
			verdict: report.VerdictCannotJudge,
			want: []want{
				{"gone.spdx.json", "inventory-readable", "", "could not be read"},
				{"empty.spdx.json", "inventory-purls", "", "carries no PURL"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rep := assert.Inventories(tt.files, report.NewJournal(), discard)

			if rep.Verdict() != tt.verdict {
				t.Fatalf("verdict = %s, want %s\nfindings: %+v", rep.Verdict(), tt.verdict, rep.Findings())
			}

			got := rep.Findings()
			if len(got) != len(tt.want) {
				t.Fatalf("findings = %+v, want %d", got, len(tt.want))
			}

			for i, w := range tt.want {
				f := got[i]
				if f.Subject != w.subject || f.Assertion != w.assertion || f.Actual != w.actual ||
					!strings.Contains(f.Detail, w.detail) {
					t.Errorf("finding %d = %+v\nwant %+v", i, f, w)
				}
			}
		})
	}
}
