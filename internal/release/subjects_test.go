// The subject manifest's table (stele#393). The golden files under
// testdata/subjects were written by the canon's own shell blocks —
// "Compute the subject manifest" and "Assemble and refuse a partial
// set", run verbatim under bash on ubuntu:24.04 with LANG=C.UTF-8
// against the fixture files beside them — so a passing golden row is
// byte-identity with what the canon signs today, not with a hand
// transcription of it. Every refusal row asserts the message: a
// refusal that names the wrong asset sends the reader to the wrong
// leg.
//
// The classes are not the engine's (stele#442): every row reads its
// class's shape from testdata/subjects/policy.json, the organisation's
// four shapes and a stranger's, through the assert policy's own
// loader — so a golden row is also proof that the declaration
// reproduces #429's bytes.

package release_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/release"
)

const fixtures = "testdata/subjects"

var (
	goPlan   = []string{"linux-arm64", "darwin-arm64", "linux-amd64", "darwin-amd64"}
	pgrxPlan = []string{"17-amd64", "17-arm64", "16-amd64", "16-arm64"}
	imgPlan  = []string{"18", "16", "17"}
)

// copyFixture copies a fixture directory so a row can mutate it.
func copyFixture(t *testing.T, src string) string {
	t.Helper()

	dst := t.TempDir()

	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}

	for _, e := range entries {
		b, rerr := os.ReadFile(filepath.Join(src, e.Name())) //nolint:gosec // a fixture path
		if rerr != nil {
			t.Fatal(rerr)
		}

		//nolint:gosec // G703: a fixture name, copied into this test's own directory
		if werr := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o600); werr != nil {
			t.Fatal(werr)
		}
	}

	return dst
}

// write is a row mutation adding (or replacing) one file.
func write(name, body string) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()

		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// remove is a row mutation deleting files.
func remove(names ...string) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()

		for _, n := range names {
			if err := os.Remove(filepath.Join(dir, n)); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// emptyDir is a row mutation deleting everything.
func emptyDir(t *testing.T, dir string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, e := range entries {
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
}

// refused asserts err carries every wanted fragment.
func refused(t *testing.T, err error, want []string) {
	t.Helper()

	if err == nil {
		t.Fatal("the set was accepted")
	}

	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q\nlacks %q", err, w)
		}
	}
}

func golden(t *testing.T, path string) string {
	t.Helper()

	b, err := os.ReadFile(path) //nolint:gosec // a fixture path
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

// fixturePolicy is the one policy every row's class is read from.
var fixturePolicy = sync.OnceValues(func() (*assert.Policy, error) {
	f, err := os.Open(filepath.Join(fixtures, "policy.json"))
	if err != nil {
		return nil, fmt.Errorf("the fixture policy: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only close

	return assert.LoadPolicy(f)
})

// shape compiles the fixture policy's declaration for a class.
func shape(t *testing.T, name string) *release.Compiled {
	t.Helper()

	pol, err := fixturePolicy()
	if err != nil {
		t.Fatalf("the fixture policy: %v", err)
	}

	c, ok := pol.Evidence.Classes[name]
	if !ok || c.Subjects == nil {
		t.Fatalf("the fixture policy declares no subjects for %q", name)
	}

	compiled, err := c.Subjects.Compile(name)
	if err != nil {
		t.Fatal(err)
	}

	return compiled
}

func class(t *testing.T, name string) *release.AssetClass {
	t.Helper()

	c := shape(t, name).Files
	if c == nil {
		t.Fatalf("%q is not a files class", name)
	}

	return c
}

// TestSubjectsFromADeclaredShape is the stranger test: a class named
// and shaped unlike any of this organisation's — boards and revisions,
// two `.bin` images per leg, a dotted label — derives its manifest
// from the fixture policy alone, with no code naming it.
func TestSubjectsFromADeclaredShape(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(fixtures, "firmware")

	m, err := class(t, "board-firmware").Subjects(filepath.Join(dir, "assets"), []string{"beta@r10", "alpha@r2"})
	if err != nil {
		t.Fatalf("Subjects: %v", err)
	}

	if got, want := string(m.SubjectLines()), golden(t, filepath.Join(dir, "subjects.golden")); got != want {
		t.Errorf("subjects:\n%s\nwant:\n%s", got, want)
	}

	if got, want := string(m.LegLines()), golden(t, filepath.Join(dir, "leg-subjects.golden")); got != want {
		t.Errorf("leg subjects:\n%s\nwant:\n%s", got, want)
	}

	_, err = class(t, "board-firmware").Subjects(filepath.Join(dir, "assets"), []string{"alpha@r2", "gamma-r1"})
	refused(t, err, []string{
		`release: board-firmware subjects: planned board "gamma-r1" is not <board>@r<rev>`,
	})

	_, err = class(t, "board-firmware").Subjects(filepath.Join(dir, "assets"), []string{"alpha@r2", "delta@r1"})
	refused(t, err, []string{
		"expected exactly one image for delta r1 (*_delta_r1.bin), found 0",
		"expected exactly one recovery image for delta r1 (*_delta_r1.rescue.bin), found 0",
		"unplanned image fw_beta_r10.bin: 4 images for 2 planned boards (2 each)",
	})
}

func TestSubjectsGolden(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name, class, fixture string
		plan                 []string
	}{
		{"go-binary", "go-binary", "go", goPlan},
		{"rust-binary shares the shape", "rust-binary", "go", goPlan},
		{"pgrx-extension", "pgrx-extension", "pgrx", pgrxPlan},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			m, err := class(t, row.class).Subjects(filepath.Join(fixtures, row.fixture, "assets"), row.plan)
			if err != nil {
				t.Fatalf("Subjects: %v", err)
			}

			dir := filepath.Join(fixtures, row.fixture)

			if got, want := string(m.SubjectLines()), golden(t, filepath.Join(dir, "subjects.golden")); got != want {
				t.Errorf("subjects:\n%s\nwant (the shell's):\n%s", got, want)
			}

			if got, want := string(m.LegLines()), golden(t, filepath.Join(dir, "leg-subjects.golden")); got != want {
				t.Errorf("leg subjects:\n%s\nwant (the shell's):\n%s", got, want)
			}
		})
	}
}

// TestSubjectsIgnoresWhatTheGlobIgnores: a hidden archive and a file
// without the class's extension are not assets, exactly as `./*.tar.gz`
// does not list them — so the manifest is still the shell's.
func TestSubjectsIgnoresWhatTheGlobIgnores(t *testing.T) {
	t.Parallel()

	dir := copyFixture(t, filepath.Join(fixtures, "go", "assets"))
	for name, body := range map[string]string{
		".tool-1.2.3-linux-amd64.tar.gz": "hidden\n",
		"README.txt":                     "not an asset\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	m, err := class(t, "go-binary").Subjects(dir, goPlan)
	if err != nil {
		t.Fatalf("Subjects: %v", err)
	}

	if got, want := string(m.SubjectLines()), golden(t, filepath.Join(fixtures, "go", "subjects.golden")); got != want {
		t.Errorf("subjects:\n%s\nwant:\n%s", got, want)
	}
}

func TestSubjectsRefusals(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name, class, fixture string
		plan                 []string
		mutate               func(*testing.T, string)
		want                 []string
	}{
		{
			name: "a missing leg", class: "go-binary", fixture: "go", plan: goPlan,
			mutate: remove("tool-1.2.3-darwin-amd64.tar.gz"),
			want:   []string{"expected exactly one archive for darwin-amd64 (*-darwin-amd64.tar.gz), found 0"},
		},
		{
			name: "two archives for one leg", class: "go-binary", fixture: "go", plan: goPlan,
			mutate: write("other-linux-amd64.tar.gz", "other\n"),
			want: []string{
				"expected exactly one archive for linux-amd64 (*-linux-amd64.tar.gz), found 2: " +
					"other-linux-amd64.tar.gz, tool-1.2.3-linux-amd64.tar.gz",
			},
		},
		{
			name: "an unplanned archive", class: "go-binary", fixture: "go", plan: goPlan,
			mutate: write("tool-1.2.3-freebsd-amd64.tar.gz", "x\n"),
			want:   []string{"unplanned archive tool-1.2.3-freebsd-amd64.tar.gz: 5 archives for 4 planned targets"},
		},
		{
			name: "an unplanned extension tarball counts two per cell", class: "pgrx-extension", fixture: "pgrx",
			plan:   pgrxPlan,
			mutate: write("ext-0.3.0-pg18-linux-amd64.tar.gz", "x\n"),
			want:   []string{"unplanned tarball ext-0.3.0-pg18-linux-amd64.tar.gz: 9 tarballs for 4 planned cells (2 each)"},
		},
		{
			name: "a pgrx cell missing its debug tarball", class: "pgrx-extension", fixture: "pgrx", plan: pgrxPlan,
			mutate: remove("ext-0.3.0-pg16-linux-arm64-debug.tar.gz"),
			want: []string{
				"expected exactly one debug tarball for pg16/arm64 (*-pg16-linux-arm64-debug.tar.gz), found 0",
			},
		},
		{
			name: "a pgrx cell missing its installable tarball", class: "pgrx-extension", fixture: "pgrx",
			plan:   pgrxPlan,
			mutate: remove("ext-0.3.0-pg17-linux-amd64.tar.gz"),
			want:   []string{"expected exactly one tarball for pg17/amd64 (*-pg17-linux-amd64.tar.gz), found 0"},
		},
		{
			name: "an empty directory names every leg", class: "go-binary", fixture: "go", plan: goPlan,
			mutate: emptyDir,
			want: []string{
				"expected exactly one archive for linux-arm64 (*-linux-arm64.tar.gz), found 0",
				"expected exactly one archive for darwin-arm64 (*-darwin-arm64.tar.gz), found 0",
				"expected exactly one archive for linux-amd64 (*-linux-amd64.tar.gz), found 0",
				"expected exactly one archive for darwin-amd64 (*-darwin-amd64.tar.gz), found 0",
			},
		},
		{
			name: "an empty pgrx directory", class: "pgrx-extension", fixture: "pgrx", plan: pgrxPlan,
			mutate: emptyDir,
			want: []string{
				"expected exactly one tarball for pg17/amd64 (*-pg17-linux-amd64.tar.gz), found 0",
				"expected exactly one debug tarball for pg16/arm64 (*-pg16-linux-arm64-debug.tar.gz), found 0",
			},
		},
		{
			// The shell hashed stdin here (sha256sum with no operands)
			// and signed a subject named "-".
			name: "an empty plan", class: "go-binary", fixture: "go", plan: []string{},
			mutate: emptyDir,
			want:   []string{"the plan names no targets — a release that builds nothing is not a release"},
		},
		{
			name: "a target planned twice", class: "go-binary", fixture: "go",
			plan: []string{"linux-amd64", "linux-amd64"},
			want: []string{`target "linux-amd64" is planned twice`},
		},
		{
			name: "a target that is not a plain name", class: "rust-binary", fixture: "go",
			plan: []string{"linux-*"},
			want: []string{`planned target "linux-*" is not a plain name`},
		},
		{
			name: "an empty target", class: "go-binary", fixture: "go", plan: []string{""},
			want: []string{`planned target "" is not a plain name`},
		},
		{
			name: "a pgrx cell that is not major-arch", class: "pgrx-extension", fixture: "pgrx",
			plan: []string{"16-x-amd64"},
			want: []string{`planned cell "16-x-amd64" is not <major>-<arch>`},
		},
		{
			name: "one archive claimed by two legs", class: "go-binary", fixture: "go",
			plan:   []string{"linux-amd64", "amd64"},
			mutate: remove("tool-1.2.3-linux-arm64.tar.gz", "tool-1.2.3-darwin-arm64.tar.gz", "tool-1.2.3-darwin-amd64.tar.gz"),
			want:   []string{"tool-1.2.3-linux-amd64.tar.gz is claimed by both linux-amd64 and amd64"},
		},
		{
			name: "a name a subject line cannot carry", class: "go-binary", fixture: "go", plan: goPlan,
			mutate: write(`odd\name-linux-amd64.tar.gz`, "x\n"),
			want:   []string{`asset "odd\\name-linux-amd64.tar.gz" carries a character a subject line cannot`},
		},
		{
			name: "an asset that is not a regular file", class: "go-binary", fixture: "go", plan: goPlan,
			mutate: func(t *testing.T, dir string) {
				t.Helper()

				if err := os.Mkdir(filepath.Join(dir, "dir-linux-amd64.tar.gz"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			want: []string{"asset dir-linux-amd64.tar.gz is not a regular file"},
		},
		{
			name: "an asset that cannot be read", class: "go-binary", fixture: "go", plan: goPlan,
			mutate: func(t *testing.T, dir string) {
				t.Helper()

				if err := os.Symlink("nowhere", filepath.Join(dir, "dangling-linux-amd64.tar.gz")); err != nil {
					t.Fatal(err)
				}
			},
			want: []string{"reading asset dangling-linux-amd64.tar.gz"},
		},
		{
			name: "an asset whose bytes cannot be hashed", class: "go-binary", fixture: "go", plan: goPlan,
			mutate: func(t *testing.T, dir string) {
				t.Helper()

				if err := os.Chmod(filepath.Join(dir, "tool-1.2.3-linux-amd64.tar.gz"), 0o000); err != nil {
					t.Fatal(err)
				}
			},
			want: []string{"hashing tool-1.2.3-linux-amd64.tar.gz"},
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			dir := copyFixture(t, filepath.Join(fixtures, row.fixture, "assets"))
			if row.mutate != nil {
				row.mutate(t, dir)
			}

			_, err := class(t, row.class).Subjects(dir, row.plan)
			refused(t, err, row.want)

			if strings.Contains(err.Error(), "unplanned") && !strings.Contains(row.name, "unplanned") {
				t.Errorf("error %q reports an unplanned asset the row did not add", err)
			}
		})
	}
}

func TestSubjectsUnreadableDirectory(t *testing.T) {
	t.Parallel()

	_, err := class(t, "go-binary").Subjects(filepath.Join(t.TempDir(), "absent"), goPlan)
	if err == nil || !strings.Contains(err.Error(), "reading the asset directory") {
		t.Fatalf("err = %v, want the directory read refused", err)
	}
}

func registry(t *testing.T) *release.RegistryClass {
	t.Helper()

	c := shape(t, "pgrx-extension-image").Registry
	if c == nil {
		t.Fatal("pgrx-extension-image is not a registry class")
	}

	return c
}

func TestRegistrySubjectsGolden(t *testing.T) {
	t.Parallel()

	r, err := registry(t).RegistrySubjects(filepath.Join(fixtures, "images", "digests"), imgPlan)
	if err != nil {
		t.Fatalf("RegistrySubjects: %v", err)
	}

	want := golden(t, filepath.Join(fixtures, "images", "registry-subjects.golden"))
	if got := string(r.Bytes()); got != want {
		t.Errorf("registry subjects:\n%s\nwant (the shell's):\n%s", got, want)
	}
}

func TestRegistrySubjectsRefusals(t *testing.T) {
	t.Parallel()

	const digest = "sha256:a000000000000000000000000000000000000000000000000000000000000009"

	doc := func(fields string) string { return "{" + fields + "}\n" }
	all := func(pg, image, tag, dig string) string {
		return doc(`"pg":"` + pg + `","image":"` + image + `","tag":"` + tag + `","digest":"` + dig + `"`)
	}

	rows := []struct {
		name   string
		plan   []string
		mutate func(*testing.T, string)
		want   []string
	}{
		{
			name: "one major missing", plan: imgPlan,
			mutate: remove("pg17.json"),
			want:   []string{"2 image digests for 3 planned majors; refusing a partial set: no digest for major 17"},
		},
		{
			name: "an extra digest file", plan: imgPlan,
			mutate: write("pg15.json", all("15", "ghcr.io/example/ext-pg15-artifact", "t", digest)),
			want: []string{
				"4 image digests for 3 planned majors; refusing a partial set: " +
					"pg15.json names major 15, which is not planned",
			},
		},
		{
			// The shell counted and accepted this set.
			name: "a major swapped for an unplanned one", plan: imgPlan,
			mutate: write("pg16.json", all("15", "ghcr.io/example/ext-pg15-artifact", "t", digest)),
			want: []string{
				"pg16.json names major 15, which is not planned",
				"no digest for major 16",
			},
		},
		{
			name: "two documents for one major", plan: imgPlan,
			mutate: write("pg16b.json", all("16", "ghcr.io/example/ext-pg16-artifact", "t", digest)),
			want:   []string{"pg16.json and pg16b.json both name major 16"},
		},
		{
			name: "a digest that is not sha256", plan: imgPlan,
			mutate: write("pg16.json", all("16", "i", "t", "sha512:00")),
			want:   []string{`pg16.json: digest "sha512:00" is not sha256:<64 hex>`},
		},
		{
			name: "an absent digest", plan: imgPlan,
			mutate: write("pg16.json", doc(`"pg":"16","image":"i","tag":"t"`)),
			want:   []string{"pg16.json: no digest"},
		},
		{
			name: "an absent image", plan: imgPlan,
			mutate: write("pg16.json", doc(`"pg":"16","tag":"t","digest":"`+digest+`"`)),
			want:   []string{"pg16.json: no image"},
		},
		{
			name: "an image a line cannot carry", plan: imgPlan,
			mutate: write("pg16.json", all("16", "ghcr.io/x y", "t", digest)),
			want:   []string{`pg16.json: image "ghcr.io/x y" carries a character a subject line cannot`},
		},
		{
			name: "an absent tag", plan: imgPlan,
			mutate: write("pg16.json", doc(`"pg":"16","image":"i","digest":"`+digest+`"`)),
			want:   []string{"pg16.json: no tag"},
		},
		{
			name: "an absent major", plan: imgPlan,
			mutate: write("pg16.json", doc(`"image":"i","tag":"t","digest":"`+digest+`"`)),
			want:   []string{"pg16.json: no pg"},
		},
		{
			name: "a field the document never had", plan: imgPlan,
			mutate: write("pg16.json", doc(`"pg":"16","image":"i","tag":"t","digest":"`+digest+`","arch":"x"`)),
			want:   []string{`pg16.json: unknown field "arch"`},
		},
		{
			name: "an unreadable document", plan: imgPlan,
			mutate: func(t *testing.T, dir string) {
				t.Helper()

				if err := os.Chmod(filepath.Join(dir, "pg16.json"), 0o000); err != nil {
					t.Fatal(err)
				}
			},
			want: []string{"pg16.json: reading:"},
		},
		{
			name: "an empty plan", plan: nil,
			want: []string{"the plan names no majors — a release that publishes nothing is not a release"},
		},
		{
			name: "a major that is not a number", plan: []string{"16", "pg17"},
			want: []string{`planned major "pg17" is not a major`},
		},
		{
			name: "a major planned twice", plan: []string{"16", "16"},
			want: []string{`major "16" is planned twice`},
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			dir := copyFixture(t, filepath.Join(fixtures, "images", "digests"))
			if row.mutate != nil {
				row.mutate(t, dir)
			}

			_, err := registry(t).RegistrySubjects(dir, row.plan)
			refused(t, err, row.want)
		})
	}
}

func TestRegistrySubjectsUnreadableDirectory(t *testing.T) {
	t.Parallel()

	_, err := registry(t).RegistrySubjects(filepath.Join(t.TempDir(), "absent"), imgPlan)
	if err == nil || !strings.Contains(err.Error(), "reading the asset directory") {
		t.Fatalf("err = %v, want the directory read refused", err)
	}
}
