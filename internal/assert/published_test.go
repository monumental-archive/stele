// The published-bytes proof: the policy section's grammar, the locator
// that turns a subject into the address its store serves it at, and
// the judgment's three answers — PASS, FAIL on divergence, CANNOT_JUDGE
// on a store that would not answer — each asserting its message.

package assert_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/published"
	"github.com/monumental-archive/stele/internal/report"
)

const (
	pubHexA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pubHexB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	pubRef  = "ghcr.io/acme/app"

	crates = `{"extension": ".crate", "coordinate": "file",
	  "url": "https://static.crates.example/crates/{name}/{name}-{version}.crate"}`
	npm = `{"extension": ".tgz", "coordinate": "declared",
	  "url": "https://registry.npm.example/{name}/-/{basename}-{version}.tgz"}`
)

// publishedPolicyJSON renders a minimal assert policy declaring the
// given published section; "" declares none.
func publishedPolicyJSON(section string) string {
	doc := fmt.Sprintf(`{"schema": %d, "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",
	  "umbrellaBundle": "u.jsonl", "manifestAsset": "m.json", "classes": {"a": {"bundles": ["b"]}}}`,
		assert.PolicySchema)
	if section != "" {
		doc += `, "published": ` + section
	}

	return doc + "}"
}

func loadPublished(t *testing.T, section string) *assert.Policy {
	t.Helper()

	pol, err := assert.LoadPolicy(strings.NewReader(publishedPolicyJSON(section)))
	if err != nil {
		t.Fatalf("LoadPolicy = %v", err)
	}

	return pol
}

func TestPublishedPolicyLoads(t *testing.T) {
	t.Parallel()

	for _, section := range []string{
		`{"registries": [` + crates + `, ` + npm + `]}`,
		`{"registries": []}`,
		`{}`,
		`{"registries": [{"extension": ".bin", "url": "https://files.example/{file}"}]}`,
		`{"registries": [{"extension": ".tar.gz", "coordinate": "file",
		  "url": "https://x.example/{name}/{version}/{file}"}]}`,
	} {
		pol := loadPublished(t, section)
		if pol.Published == nil {
			t.Fatalf("a declared published section %s loaded as absent", section)
		}
	}

	if pol := loadPublished(t, ""); pol.Published != nil {
		t.Fatal("an undeclared published section loaded as declared")
	}
}

func TestPublishedPolicyRefusals(t *testing.T) {
	t.Parallel()

	reg := func(body string) string { return `{"registries": [` + body + `]}` }

	tests := []struct {
		name, section, want string
	}{
		{
			"no extension",
			reg(`{"url": "https://x.example/{file}"}`),
			`published.registries[0].extension must be present and a file extension`,
		},
		{
			"an extension with no dot",
			reg(`{"extension": "crate", "url": "https://x.example/{file}"}`),
			`published.registries[0].extension must be present and a file extension`,
		},
		{
			"an extension with a slash",
			reg(`{"extension": ".a/b", "url": "https://x.example/{file}"}`),
			`published.registries[0].extension must be present and a file extension`,
		},
		{
			"an unknown coordinate",
			reg(`{"extension": ".crate", "coordinate": "guess", "url": "https://x.example/{file}"}`),
			`published.registries[0].coordinate "guess" is not a coordinate (file, declared)`,
		},
		{
			"no url",
			reg(`{"extension": ".crate"}`),
			"published.registries[0].url must be present and an https URL template",
		},
		{
			"a plain-http url",
			reg(`{"extension": ".crate", "url": "http://x.example/{file}"}`),
			"published.registries[0].url must be present and an https URL template",
		},
		{
			"a placeholder in the host",
			reg(`{"extension": ".crate", "url": "https://{name}.example/{file}"}`),
			"published.registries[0].url places a placeholder in the host",
		},
		{
			"a query",
			reg(`{"extension": ".crate", "url": "https://x.example/get?f={file}"}`),
			"published.registries[0].url carries a query or a fragment",
		},
		{
			"no placeholder",
			reg(`{"extension": ".crate", "url": "https://x.example/one.crate"}`),
			"published.registries[0].url carries no placeholder — every subject would be fetched from one address",
		},
		{
			"an unknown placeholder",
			reg(`{"extension": ".crate", "url": "https://x.example/{owner}/{file}"}`),
			"published.registries[0].url carries placeholder {owner} — the vocabulary is",
		},
		{
			"a coordinate placeholder with no coordinate",
			reg(`{"extension": ".crate", "url": "https://x.example/{name}/{file}"}`),
			"published.registries[0].url uses {name}, which needs a coordinate",
		},
		{
			"a template that is no URL around its placeholders",
			reg(`{"extension": ".crate", "url": "https:///{file}"}`),
			"published.registries[0].url is not a URL template",
		},
		{
			"two registries claiming one extension",
			reg(crates + `, {"extension": ".crate", "url": "https://y.example/{file}"}`),
			`published.registries[0] and [1] both claim a file ending in ".crate" — one subject, one registry`,
		},
		{
			"one extension ending another",
			reg(`{"extension": ".gz", "url": "https://y.example/{file}"}, ` +
				`{"extension": ".tar.gz", "url": "https://z.example/{file}"}`),
			`published.registries[0] and [1] both claim a file ending in ".tar.gz"`,
		},
		{
			"the second entry's refusal names its own index",
			reg(crates + `, {"extension": ".tgz"}`),
			"published.registries[1].url must be present",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := assert.LoadPolicy(strings.NewReader(publishedPolicyJSON(tt.section)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("LoadPolicy = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestPublishedLocate(t *testing.T) {
	t.Parallel()

	pol := loadPublished(t, `{"registries": [`+crates+`, `+npm+`,
	  {"extension": ".bin", "url": "https://files.example/dl/{file}"}]}`)

	loc := &assert.Locator{
		Registries: pol.Published.Registries,
		Packages:   map[string]assert.Package{".tgz": {Name: "@acme/widget", Version: "1.2.0-rc.1"}},
		Asset:      func(name string) string { return "https://forge.example/assets/" + name },
	}

	tests := []struct {
		file, want string
	}{
		{"widget-1.2.0.crate", "https://static.crates.example/crates/widget/widget-1.2.0.crate"},
		// A hyphenated name and a pre-release survive the split, as the
		// shell's last-hyphen cut did not.
		{"foo-bar-1.0.0-rc.1.crate", "https://static.crates.example/crates/foo-bar/foo-bar-1.0.0-rc.1.crate"},
		{"foo-1-1.0.0.crate", "https://static.crates.example/crates/foo-1/foo-1-1.0.0.crate"},
		{"widget-1.0.0+build.5.crate", "https://static.crates.example/crates/widget/widget-1.0.0+build.5.crate"},
		{"acme-widget-1.2.0-rc.1.tgz", "https://registry.npm.example/@acme/widget/-/widget-1.2.0-rc.1.tgz"},
		{"tool linux.bin", "https://files.example/dl/tool%20linux.bin"},
		{"app-1.0.0-x86_64.tar.gz", "https://forge.example/assets/app-1.0.0-x86_64.tar.gz"},
		{".crate", "https://forge.example/assets/.crate"},
	}

	for _, tt := range tests {
		got, err := loc.Locate(tt.file)
		if err != nil {
			t.Fatalf("Locate(%q) = %v", tt.file, err)
		}

		if got != tt.want {
			t.Errorf("Locate(%q) = %s, want %s", tt.file, got, tt.want)
		}
	}
}

func TestPublishedLocateRefusals(t *testing.T) {
	t.Parallel()

	pol := loadPublished(t, `{"registries": [`+crates+`, `+npm+`,
	  {"extension": ".bin", "coordinate": "declared", "url": "https://files.example/{name}/{file}"}]}`)

	tests := []struct {
		name, file string
		packages   map[string]assert.Package
		asset      bool
		want       string
	}{
		{
			name: "a subject no registry claims, and no release declared",
			file: "app.tar.gz",
			want: "app.tar.gz: no registry claims this subject type and no release-tag was declared",
		},
		{
			name: "a declared-coordinate subject with no package declared",
			file: "acme-widget-1.0.0.tgz",
			want: "acme-widget-1.0.0.tgz is a .tgz subject but no package was declared for .tgz",
		},
		{
			name: "a file name that is not <name>-<version><extension>",
			file: "widget.crate",
			want: "widget.crate: the file name is not <name>-<version>.crate",
		},
		{
			name:  "a version that is not a semantic version, even with a release declared",
			file:  "widget-v1.0.crate",
			asset: true,
			want:  "widget-v1.0.crate: the file name is not <name>-<version>.crate",
		},
		{
			name:     "a declared name that walks the path",
			file:     "x.bin",
			packages: map[string]assert.Package{".bin": {Name: "../etc", Version: "1.0.0"}},
			want:     `x.bin: {name} "../etc" cannot stand in a URL path`,
		},
		{
			name:     "a declared name with an empty segment",
			file:     "x.bin",
			packages: map[string]assert.Package{".bin": {Name: "@acme//w", Version: "1.0.0"}},
			want:     `x.bin: {name} "@acme//w" cannot stand in a URL path`,
		},
		{
			name:     "a declared version that walks the path",
			file:     "acme-w.tgz",
			packages: map[string]assert.Package{".tgz": {Name: "w", Version: ".."}},
			want:     `acme-w.tgz: {version} ".." cannot stand in a URL path`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			loc := &assert.Locator{Registries: pol.Published.Registries, Packages: tt.packages}
			if tt.asset {
				loc.Asset = func(name string) string { return "https://forge.example/" + name }
			}

			got, err := loc.Locate(tt.file)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("Locate = %q, %v; want the refusal %q", got, err, tt.want)
			}
		})
	}
}

// pubWorld is the stores, scripted: what each URL serves and what each
// tag names, and every ask recorded.
type pubWorld struct {
	served   map[string]string // URL → digest; absent refuses as not served
	resolved map[string]string // image:tag → digest; absent refuses
	asked    []string
}

func (w *pubWorld) Fetch(name, url string) (string, error) {
	w.asked = append(w.asked, url)

	if d, ok := w.served[url]; ok {
		return d, nil
	}

	return "", fmt.Errorf("%s: not served after 10 minutes", name)
}

func (w *pubWorld) Resolve(image, tag string) (string, error) {
	w.asked = append(w.asked, image+":"+tag)

	if d, ok := w.resolved[image+":"+tag]; ok {
		return d, nil
	}

	return "", errors.New("oci: resolving: connection refused")
}

// judgedLines reads the report's judged set back as manifest lines.
func judgedLines(t *testing.T, rep *report.Report) []string {
	t.Helper()

	if rep.Judged() == nil {
		return nil
	}

	lines, err := jsonx.DecodeBytes[[]string](rep.Judged())
	if err != nil {
		t.Fatalf("the judged set is not a list of lines: %v", err)
	}

	return *lines
}

func TestPublishedJudgment(t *testing.T) {
	t.Parallel()

	crate := assert.PublishedFile{Name: "app-1.0.0.crate", SHA256: pubHexA, URL: "u/crate"}
	asset := assert.PublishedFile{Name: "app.tar.gz", SHA256: pubHexB, URL: "u/asset"}
	image := published.Image{Image: pubRef, Tag: "1.0.0", Digest: "sha256:" + pubHexB}

	tests := []struct {
		name     string
		world    pubWorld
		files    []assert.PublishedFile
		images   []published.Image
		verdict  report.Verdict
		findings []string // subject|assertion|detail|expected|actual, in order
		judged   []string
		asked    int
	}{
		{
			name: "every subject proved",
			world: pubWorld{
				served:   map[string]string{"u/crate": pubHexA, "u/asset": pubHexB},
				resolved: map[string]string{pubRef + ":1.0.0": "sha256:" + pubHexB},
			},
			files:   []assert.PublishedFile{crate, asset},
			images:  []published.Image{image},
			verdict: report.VerdictPass,
			// The image line carries the UNTAGGED reference and the bare
			// hex: the subject name the signer attested.
			judged: []string{pubHexA + "  app-1.0.0.crate", pubHexB + "  app.tar.gz", pubHexB + "  " + pubRef},
			asked:  3,
		},
		{
			name: "a store serving other bytes is divergence, and the walk goes on",
			world: pubWorld{
				served:   map[string]string{"u/crate": pubHexB, "u/asset": pubHexB},
				resolved: map[string]string{pubRef + ":1.0.0": "sha256:" + pubHexB},
			},
			files:   []assert.PublishedFile{crate, asset},
			images:  []published.Image{image},
			verdict: report.VerdictFail,
			findings: []string{
				"app-1.0.0.crate|published-bytes|the store served other bytes than were built|" + pubHexA + "|" + pubHexB,
			},
			asked: 3,
		},
		{
			name:    "a tag naming nothing is divergence",
			world:   pubWorld{resolved: map[string]string{pubRef + ":1.0.0": ""}},
			images:  []published.Image{image},
			verdict: report.VerdictFail,
			findings: []string{
				pubRef + ":1.0.0|tag-binding|the tag does not resolve to the attested index|sha256:" + pubHexB + "|nothing",
			},
			asked: 1,
		},
		{
			name:    "a tag naming another index is divergence",
			world:   pubWorld{resolved: map[string]string{pubRef + ":1.0.0": "sha256:" + pubHexA}},
			images:  []published.Image{image},
			verdict: report.VerdictFail,
			findings: []string{
				pubRef + ":1.0.0|tag-binding|the tag does not resolve to the attested index|sha256:" + pubHexB +
					"|sha256:" + pubHexA,
			},
			asked: 1,
		},
		{
			name: "a store that will not answer is CANNOT_JUDGE, named, and nothing after it is asked",
			world: pubWorld{
				served:   map[string]string{"u/asset": pubHexB},
				resolved: map[string]string{pubRef + ":1.0.0": "sha256:" + pubHexB},
			},
			files:    []assert.PublishedFile{crate, asset},
			images:   []published.Image{image},
			verdict:  report.VerdictCannotJudge,
			findings: []string{"app-1.0.0.crate|published-read|app-1.0.0.crate: not served after 10 minutes||"},
			asked:    1,
		},
		{
			name:     "a registry that cannot be asked about a tag is CANNOT_JUDGE",
			world:    pubWorld{served: map[string]string{"u/crate": pubHexA}},
			files:    []assert.PublishedFile{crate},
			images:   []published.Image{image},
			verdict:  report.VerdictCannotJudge,
			findings: []string{pubRef + ":1.0.0|published-read|oci: resolving: connection refused||"},
			asked:    2,
		},
		{
			name:    "divergence found before the blind read is carried under CANNOT_JUDGE",
			world:   pubWorld{served: map[string]string{"u/crate": pubHexB}},
			files:   []assert.PublishedFile{crate, asset},
			verdict: report.VerdictCannotJudge,
			findings: []string{
				"app-1.0.0.crate|published-bytes|the store served other bytes than were built|" + pubHexA + "|" + pubHexB,
				"app.tar.gz|published-read|app.tar.gz: not served after 10 minutes||",
			},
			asked: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := tt.world

			var logs []string

			rep := assert.Published("acme/app@v1.0.0", tt.files, tt.images, &w, &w, report.NewJournal(),
				func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) })

			if rep.Verdict() != tt.verdict {
				t.Fatalf("verdict = %s, want %s; findings %+v", rep.Verdict(), tt.verdict, rep.Findings())
			}

			if rep.Target() != "assert published" {
				t.Fatalf("target = %q", rep.Target())
			}

			var got []string
			for _, f := range rep.Findings() {
				got = append(got, strings.Join([]string{f.Subject, f.Assertion, f.Detail, f.Expected, f.Actual}, "|"))
			}

			if !slices.Equal(got, tt.findings) {
				t.Fatalf("findings =\n  %q\nwant\n  %q", got, tt.findings)
			}

			if tt.verdict == report.VerdictPass && !slices.Equal(judgedLines(t, rep), tt.judged) {
				t.Fatalf("judged = %q, want %q", judgedLines(t, rep), tt.judged)
			}

			if len(w.asked) != tt.asked {
				t.Fatalf("the stores were asked %d time(s) (%q), want %d", len(w.asked), w.asked, tt.asked)
			}
		})
	}
}
