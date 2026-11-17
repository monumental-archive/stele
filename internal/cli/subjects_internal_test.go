// `derive subjects`' surface: every usage guard, every refusal, and the
// placement — stdout and the named files carry the engine's bytes, and
// a refused set leaves no file behind. The fixtures and goldens are
// internal/release's, written by the canon's own shell blocks.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const subjectsFixtures = "../release/testdata/subjects"

// plannedFile writes a planned-legs document and returns its path.
func plannedFile(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "expected.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func readGolden(t *testing.T, rel string) string {
	t.Helper()

	b, err := os.ReadFile(filepath.Join(subjectsFixtures, rel)) //nolint:gosec // a fixture path
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

func TestDeriveSubjectsFileClass(t *testing.T) {
	t.Parallel()

	out := t.TempDir()
	subjects := filepath.Join(out, "subjects")
	legs := filepath.Join(out, "legs")

	var stdout, stderr bytes.Buffer

	code := deriveCmd([]string{
		"subjects", "--class", "go-binary",
		"--expected", filepath.Join(subjectsFixtures, "go", "expected.json"),
		"--dir", filepath.Join(subjectsFixtures, "go", "assets"),
		"--subjects-out", subjects, "--leg-subjects-out", legs,
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}

	want := readGolden(t, "go/subjects.golden")
	if stdout.String() != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", stdout.String(), want)
	}

	for path, golden := range map[string]string{subjects: "go/subjects.golden", legs: "go/leg-subjects.golden"} {
		got, err := os.ReadFile(path) //nolint:gosec // a path this test chose
		if err != nil {
			t.Fatal(err)
		}

		if w := readGolden(t, golden); string(got) != w {
			t.Errorf("%s:\n%s\nwant:\n%s", filepath.Base(path), got, w)
		}
	}
}

func TestDeriveSubjectsPgrxClass(t *testing.T) {
	t.Parallel()

	legs := filepath.Join(t.TempDir(), "legs")

	var stdout, stderr bytes.Buffer

	code := deriveCmd([]string{
		"subjects", "--class", "pgrx-extension",
		"--expected", filepath.Join(subjectsFixtures, "pgrx", "expected.json"),
		"--dir", filepath.Join(subjectsFixtures, "pgrx", "assets"),
		"--leg-subjects-out", legs,
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}

	if want := readGolden(t, "pgrx/subjects.golden"); stdout.String() != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", stdout.String(), want)
	}

	got, err := os.ReadFile(legs) //nolint:gosec // a path this test chose
	if err != nil {
		t.Fatal(err)
	}

	if want := readGolden(t, "pgrx/leg-subjects.golden"); string(got) != want {
		t.Errorf("legs:\n%s\nwant:\n%s", got, want)
	}
}

func TestDeriveSubjectsRegistryClass(t *testing.T) {
	t.Parallel()

	registry := filepath.Join(t.TempDir(), "registry")

	var stdout, stderr bytes.Buffer

	code := deriveCmd([]string{
		"subjects", "--class", "pgrx-extension-image",
		"--expected", filepath.Join(subjectsFixtures, "images", "expected.json"),
		"--dir", filepath.Join(subjectsFixtures, "images", "digests"),
		"--registry-subjects-out", registry,
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}

	want := readGolden(t, "images/registry-subjects.golden")
	if stdout.String() != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", stdout.String(), want)
	}

	got, err := os.ReadFile(registry) //nolint:gosec // a path this test chose
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != want {
		t.Errorf("registry file:\n%s\nwant:\n%s", got, want)
	}
}

func TestDeriveSubjectsUsage(t *testing.T) {
	t.Parallel()

	goDir := filepath.Join(subjectsFixtures, "go", "assets")
	goPlan := filepath.Join(subjectsFixtures, "go", "expected.json")

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no class", []string{"--expected", goPlan, "--dir", goDir}, "--class is required"},
		{"no planned legs", []string{"--class", "go-binary", "--dir", goDir}, "--expected is required"},
		{"no directory", []string{"--class", "go-binary", "--expected", goPlan}, "--dir is required"},
		{
			"a stray argument",
			[]string{"--class", "go-binary", "--expected", goPlan, "--dir", goDir, "extra"},
			`unexpected argument "extra"`,
		},
		{"an unknown flag", []string{"--pattern", "*.tar.gz"}, "flag provided but not defined: -pattern"},
		{
			"an unknown class",
			[]string{"--class", "wasm-npm", "--expected", goPlan, "--dir", goDir},
			`unknown class "wasm-npm": subjects are defined for go-binary, pgrx-extension,` +
				` pgrx-extension-image, rust-binary`,
		},
		{
			"a class whose row defines no subjects: rust-crate",
			[]string{"--class", "rust-crate", "--expected", goPlan, "--dir", goDir},
			`class "rust-crate" has no file or registry subjects defined: subjects are defined for go-binary,` +
				` pgrx-extension, pgrx-extension-image, rust-binary`,
		},
		{
			"a class whose row defines no subjects: oci-image",
			[]string{"--class", "oci-image", "--expected", goPlan, "--dir", goDir},
			`class "oci-image" has no file or registry subjects defined: subjects are defined for go-binary,` +
				` pgrx-extension, pgrx-extension-image, rust-binary`,
		},
		{
			"registry lines asked of a file class",
			[]string{"--class", "go-binary", "--expected", goPlan, "--dir", goDir, "--registry-subjects-out", "x"},
			"--registry-subjects-out: go-binary ships files, not registry subjects",
		},
		{
			"file lines asked of a registry class",
			[]string{"--class", "pgrx-extension-image", "--expected", goPlan, "--dir", goDir, "--leg-subjects-out", "x"},
			"pgrx-extension-image publishes to a registry; its lines are --registry-subjects-out",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			if code := deriveCmd(append([]string{"subjects"}, tc.args...), &stdout, &stderr); code != exitUsage {
				t.Errorf("exit %d, want %d (stderr: %s)", code, exitUsage, stderr.String())
			}

			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr %q lacks %q", stderr.String(), tc.want)
			}

			if stdout.Len() != 0 {
				t.Errorf("stdout carried %q on a usage error", stdout.String())
			}
		})
	}
}

func TestDeriveSubjectsRefusals(t *testing.T) {
	t.Parallel()

	goDir := filepath.Join(subjectsFixtures, "go", "assets")
	pgrxDir := filepath.Join(subjectsFixtures, "pgrx", "assets")
	imgDir := filepath.Join(subjectsFixtures, "images", "digests")

	for _, tc := range []struct {
		name, class, planned, dir, want string
	}{
		{
			"planned legs that cannot be read", "go-binary", "", goDir,
			"derive subjects: reading the planned legs:",
		},
		{
			"planned legs that are not a list", "go-binary", `{"include":[]}`, goDir,
			"are not a JSON list of strings",
		},
		{
			"a null planned leg", "go-binary", `["linux-amd64",null]`, goDir,
			"planned leg 1 in",
		},
		{
			"an empty leg list", "go-binary", `[]`, goDir,
			"the plan names no targets — a release that builds nothing is not a release",
		},
		{
			"an empty major list", "pgrx-extension-image", `[]`, imgDir,
			"the plan names no majors — a release that publishes nothing is not a release",
		},
		{
			"a pgrx cell not shaped for its class", "pgrx-extension", `["16"]`, pgrxDir,
			`planned cell "16" is not <major>-<arch>`,
		},
		{
			"a leg the directory does not hold", "go-binary", `["linux-amd64","windows-amd64"]`, goDir,
			"expected exactly one archive for windows-amd64 (*-windows-amd64.tar.gz), found 0",
		},
		{
			"a major the digests do not cover", "pgrx-extension-image", `["16","17","18","19"]`, imgDir,
			"3 image digests for 4 planned majors; refusing a partial set: no digest for major 19",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			planned := filepath.Join(t.TempDir(), "absent.json")
			if tc.planned != "" {
				planned = plannedFile(t, tc.planned)
			}

			outDir := t.TempDir()
			subjectsOut := filepath.Join(outDir, "subjects")

			args := []string{"subjects", "--class", tc.class, "--expected", planned, "--dir", tc.dir}
			if tc.class == "pgrx-extension-image" {
				args = append(args, "--registry-subjects-out", subjectsOut)
			} else {
				args = append(args, "--subjects-out", subjectsOut)
			}

			var stdout, stderr bytes.Buffer

			if code := deriveCmd(args, &stdout, &stderr); code != exitRefused {
				t.Errorf("exit %d, want %d (stderr: %s)", code, exitRefused, stderr.String())
			}

			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr %q lacks %q", stderr.String(), tc.want)
			}

			if stdout.Len() != 0 {
				t.Errorf("stdout carried %q on a refusal", stdout.String())
			}

			if _, err := os.Stat(subjectsOut); !os.IsNotExist(err) {
				t.Errorf("a refused set left %s behind (stat: %v)", subjectsOut, err)
			}
		})
	}
}

func TestDeriveSubjectsPlacementFailures(t *testing.T) {
	t.Parallel()

	goArgs := []string{
		"subjects", "--class", "go-binary",
		"--expected", filepath.Join(subjectsFixtures, "go", "expected.json"),
		"--dir", filepath.Join(subjectsFixtures, "go", "assets"),
	}

	t.Run("a file that cannot be written", func(t *testing.T) {
		t.Parallel()

		var stdout, stderr bytes.Buffer

		bad := filepath.Join(t.TempDir(), "missing", "subjects")

		code := deriveCmd(append(append([]string{}, goArgs...), "--subjects-out", bad), &stdout, &stderr)
		if code != exitRefused {
			t.Errorf("exit %d, want %d", code, exitRefused)
		}

		if want := "derive subjects: writing " + bad; !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr %q lacks %q", stderr.String(), want)
		}
	})

	t.Run("a broken stdout", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer

		if code := deriveCmd(goArgs, failWriterI{}, &stderr); code != exitIO {
			t.Errorf("exit %d, want %d (stderr: %s)", code, exitIO, stderr.String())
		}
	})
}
