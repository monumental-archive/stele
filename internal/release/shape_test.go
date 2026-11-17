// The declared subject shape (stele#442): every load guard, both
// registry forms through the one digest reader, and the structural
// rule that no class and no asset-name shape is written in code.

package release_test

import (
	"go/scanner"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/release"
)

// decl decodes one shape declaration the way the policy does.
func decl(t *testing.T, body string) *release.SubjectShape {
	t.Helper()

	s, err := jsonx.DecodeBytes[release.SubjectShape]([]byte(body))
	if err != nil {
		t.Fatalf("decoding the shape: %v", err)
	}

	return s
}

const (
	filesHead = `"kind":"files","entry":"^(?P<a>[a-z]+)-(?P<b>[0-9]+)$","unit":"leg","extension":".zip"`
	oneAsset  = `"assets":[{"noun":"bundle","of":"${a}/${b}","suffix":"-${a}-${b}.zip"}]`
	docHead   = `"kind":"registry","form":"document","entry":"^v[0-9]+$","unit":"variant","extension":".json"`
	bareHead  = `"kind":"registry","form":"bare-digest","entry":"^[a-z0-9]+$","unit":"arch"`
	digestA   = "sha256:b000000000000000000000000000000000000000000000000000000000000001"
	digestB   = "sha256:b000000000000000000000000000000000000000000000000000000000000002"
)

// writeFiles writes name → body into a fresh directory.
func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()

	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

func TestShapeCompileRefusals(t *testing.T) {
	t.Parallel()

	const where = "evidence.classes.k.subjects"

	for _, row := range []struct {
		name, body, want string
	}{
		{"no kind", `{"entry":"^x$"}`, where + ".kind is absent or empty"},
		{
			"an unknown kind", `{"kind":"tarballs","entry":"^x$"}`,
			where + `.kind "tarballs" is not a subject shape this stele implements`,
		},
		{
			"a parameter the kind requires is absent",
			`{` + filesHead + `,` + oneAsset + `}`,
			where + ".label is absent or empty — the files kind requires it",
		},
		{
			"no unit",
			`{"kind":"files","entry":"^(?P<a>x)$","extension":".zip","label":"${a}",` + oneAsset + `}`,
			where + ".unit is absent or empty — the files kind requires it",
		},
		{
			"no assets", `{` + filesHead + `,"label":"${a}"}`,
			where + ".assets is absent or empty — the files kind requires it",
		},
		{
			"a registry parameter on a files shape",
			`{` + filesHead + `,"label":"${a}",` + oneAsset + `,"legField":"v"}`,
			where + ".legField is declared but the files kind does not read it",
		},
		{
			"a form on a files shape",
			`{` + filesHead + `,"label":"${a}",` + oneAsset + `,"form":"document"}`,
			where + ".form is declared but the files kind does not read it",
		},
		{
			"a registry shape with no form",
			`{"kind":"registry","entry":"^v$","unit":"u","extension":".json","legField":"v"}`,
			where + ".form is absent or empty — the registry kind requires it",
		},
		{
			"an unknown form",
			`{"kind":"registry","form":"manifest-list","entry":"^v$","unit":"u"}`,
			where + `.form "manifest-list" is not a registry form this stele implements`,
		},
		{
			"a files parameter on a registry shape",
			`{` + docHead + `,"legField":"variant","label":"x"}`,
			where + ".label is declared but the registry kind's document form does not read it",
		},
		{
			"a document with no leg field",
			`{` + docHead + `}`,
			where + ".legField is absent or empty — the registry kind's document form requires it",
		},
		{
			"a document with no extension",
			`{"kind":"registry","form":"document","entry":"^v$","unit":"u","legField":"v"}`,
			where + ".extension is absent or empty — the registry kind's document form requires it",
		},
		{
			"a leg field on a bare digest",
			`{` + bareHead + `,"legField":"arch"}`,
			where + ".legField is declared but the registry kind's bare-digest form does not read it",
		},
		{
			"an entry with no leading anchor",
			`{"kind":"registry","form":"bare-digest","entry":"v[0-9]+$","unit":"u"}`,
			where + `.entry "v[0-9]+$" is not anchored — it must begin with ^ and end with $`,
		},
		{
			"an entry with no trailing anchor",
			`{"kind":"registry","form":"bare-digest","entry":"^v[0-9]+","unit":"u"}`,
			where + `.entry "^v[0-9]+" is not anchored`,
		},
		{
			"an entry ending in an escaped dollar",
			`{"kind":"registry","form":"bare-digest","entry":"^v\\$","unit":"u"}`,
			where + `.entry "^v\\$" is not anchored`,
		},
		{
			"an entry that does not compile",
			`{"kind":"registry","form":"bare-digest","entry":"^(v$","unit":"u"}`,
			where + ".entry: error parsing regexp: missing closing )",
		},
		{
			"a label naming an undefined group",
			`{` + filesHead + `,"label":"${c}",` + oneAsset + `}`,
			where + `.label "${c}" names the group "c", which entry does not define`,
		},
		{
			"a suffix naming an undefined group",
			`{` + filesHead + `,"label":"${a}","assets":[{"noun":"n","suffix":"-$arch.zip"}]}`,
			where + `.assets[0].suffix "-$arch.zip" names the group "arch", which entry does not define`,
		},
		{
			"an of naming an undefined group",
			`{` + filesHead + `,"label":"${a}","assets":[{"noun":"n","of":"${major}","suffix":"-${a}.zip"}]}`,
			where + `.assets[0].of "${major}" names the group "major", which entry does not define`,
		},
		{
			"a group named by position",
			`{` + filesHead + `,"label":"$1",` + oneAsset + `}`,
			where + `.label "$1" names group 1 by position — name it`,
		},
		{
			"a dollar naming nothing",
			`{` + filesHead + `,"label":"${a}","assets":[{"noun":"n","suffix":"-$.zip"}]}`,
			where + `.assets[0].suffix "-$.zip" carries a $ that names no group — write $$ for a literal dollar`,
		},
		{
			"an empty braced placeholder",
			`{` + filesHead + `,"label":"${}",` + oneAsset + `}`,
			where + `.label "${}" carries a $ that names no group`,
		},
		{
			"an asset with no noun",
			`{` + filesHead + `,"label":"${a}","assets":[{"suffix":"-${a}.zip"}]}`,
			where + ".assets[0].noun is absent or empty",
		},
		{
			"an asset with no suffix",
			`{` + filesHead + `,"label":"${a}","assets":[{"noun":"n","suffix":""}]}`,
			where + ".assets[0].suffix is absent or empty",
		},
		{
			"a suffix outside the extension",
			`{` + filesHead + `,"label":"${a}","assets":[{"noun":"n","suffix":"-${a}.tar"}]}`,
			where + `.assets[0].suffix "-${a}.tar" does not end in the extension ".zip" — no listed file could match it`,
		},
		{
			"a leg field the document carries for itself",
			`{` + docHead + `,"legField":"digest"}`,
			where + `.legField "digest" is a field every digest document already carries for itself`,
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			_, err := decl(t, row.body).Compile("k")
			refused(t, err, []string{row.want})
		})
	}
}

// TestShapeOfDefaultsToTheEntry: an asset declaring no `of` names its
// leg in a refusal as the plan wrote it.
func TestShapeOfDefaultsToTheEntry(t *testing.T) {
	t.Parallel()

	c, err := decl(t, `{`+filesHead+`,"label":"${a}","assets":[{"noun":"n","suffix":"-${a}-${b}.zip"}]}`).Compile("k")
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.Files.Subjects(t.TempDir(), []string{"q-1"})
	refused(t, err, []string{"expected exactly one n for q-1 (*-q-1.zip), found 0"})
}

// TestShapeLiteralDollar: $$ is the one placeholder that names no
// group, and it renders a dollar.
func TestShapeLiteralDollar(t *testing.T) {
	t.Parallel()

	dir := writeFiles(t, map[string]string{"x-$q-1.zip": "x\n"})

	c, err := decl(t, `{`+filesHead+`,"label":"${a}","assets":[{"noun":"n","of":"${a}","suffix":"-$$${a}-${b}.zip"}]}`).
		Compile("k")
	if err != nil {
		t.Fatal(err)
	}

	m, err := c.Files.Subjects(dir, []string{"q-1"})
	if err != nil {
		t.Fatalf("Subjects: %v", err)
	}

	if got := string(m.LegLines()); !strings.HasSuffix(got, "  x-$q-1.zip\n") || !strings.HasPrefix(got, "q ") {
		t.Errorf("leg lines %q", got)
	}
}

// TestRegistryFromADeclaredShape: a document-form registry class whose
// digest documents name their leg in a field of the policy's choosing.
func TestRegistryFromADeclaredShape(t *testing.T) {
	t.Parallel()

	c, err := decl(t, `{`+docHead+`,"legField":"variant"}`).Compile("edge-image")
	if err != nil {
		t.Fatal(err)
	}

	dir := writeFiles(t, map[string]string{
		"v2.json": `{"variant":"v2","image":"registry.example/edge","tag":"v2-1","digest":"` + digestA + `"}`,
	})

	r, err := c.Registry.RegistrySubjects(dir, []string{"v2"})
	if err != nil {
		t.Fatalf("RegistrySubjects: %v", err)
	}

	want := "v2 " + strings.TrimPrefix(digestA, "sha256:") + "  registry.example/edge\n"
	if got := string(r.Bytes()); got != want {
		t.Errorf("lines %q, want %q", got, want)
	}

	_, err = c.Registry.RegistrySubjects(dir, []string{"v2", "3"})
	refused(t, err, []string{`release: edge-image subjects: planned variant "3" does not match ^v[0-9]+$`})

	bad := writeFiles(t, map[string]string{"v2.json": `{"pg":"v2"}`})
	_, err = c.Registry.RegistrySubjects(bad, []string{"v2"})
	refused(t, err, []string{`v2.json: unknown field "pg"`})
}

// TestRegistryDigests is the one reader, through both forms.
func TestRegistryDigests(t *testing.T) {
	t.Parallel()

	hexA, hexB := strings.TrimPrefix(digestA, "sha256:"), strings.TrimPrefix(digestB, "sha256:")

	rows := []struct {
		name, shape string
		files       map[string]string
		want        []release.RegistryDigest
		refusal     []string
	}{
		{
			name: "documents", shape: `{` + docHead + `,"legField":"variant"}`,
			files: map[string]string{
				"b.json":    `{"variant":"v2","image":"r/e","tag":"t","digest":"` + digestB + `"}`,
				"a.json":    `{"variant":"v1","image":"r/e","tag":"t","digest":"` + digestA + `"}`,
				"notes.txt": "not a digest file\n",
			},
			want: []release.RegistryDigest{
				{File: "a.json", Label: "v1", SHA256: hexA, Image: "r/e"},
				{File: "b.json", Label: "v2", SHA256: hexB, Image: "r/e"},
			},
		},
		{
			name: "bare digests, every file", shape: `{` + bareHead + `}`,
			files: map[string]string{"arm64": digestB + "\n", "amd64": digestA},
			want: []release.RegistryDigest{
				{File: "amd64", Label: "amd64", SHA256: hexA},
				{File: "arm64", Label: "arm64", SHA256: hexB},
			},
		},
		{
			name: "bare digests under an extension", shape: `{` + bareHead + `,"extension":".digest"}`,
			files: map[string]string{"amd64.digest": digestA + "\n", "README": "ignored\n"},
			want:  []release.RegistryDigest{{File: "amd64.digest", Label: "amd64", SHA256: hexA}},
		},
		{
			name: "a bare digest that is not one digest", shape: `{` + bareHead + `}`,
			files:   map[string]string{"amd64": digestA + "\n" + digestB + "\n"},
			refusal: []string{"release: k digests: amd64: is not one sha256:<64 hex> digest"},
		},
		{
			name: "two documents naming one leg", shape: `{` + docHead + `,"legField":"variant"}`,
			files: map[string]string{
				"a.json": `{"variant":"v1","image":"r/e","tag":"t","digest":"` + digestA + `"}`,
				"b.json": `{"variant":"v1","image":"r/e","tag":"t","digest":"` + digestB + `"}`,
			},
			refusal: []string{"release: k digests: a.json and b.json both name variant v1"},
		},
		{
			name: "an unreadable bare digest", shape: `{` + bareHead + `}`,
			files:   map[string]string{"amd64": digestA},
			refusal: []string{"amd64: reading:"},
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			c, err := decl(t, row.shape).Compile("k")
			if err != nil {
				t.Fatal(err)
			}

			dir := writeFiles(t, row.files)
			if row.name == "an unreadable bare digest" {
				if cerr := os.Chmod(filepath.Join(dir, "amd64"), 0o000); cerr != nil {
					t.Fatal(cerr)
				}
			}

			got, err := c.Registry.Digests(dir)
			if row.refusal != nil {
				refused(t, err, row.refusal)

				return
			}

			if err != nil {
				t.Fatalf("Digests: %v", err)
			}

			if len(got) != len(row.want) {
				t.Fatalf("got %+v, want %+v", got, row.want)
			}

			for i := range got {
				if got[i] != row.want[i] {
					t.Errorf("digest %d = %+v, want %+v", i, got[i], row.want[i])
				}
			}
		})
	}

	t.Run("an unreadable directory", func(t *testing.T) {
		t.Parallel()

		c, err := decl(t, `{`+bareHead+`}`).Compile("k")
		if err != nil {
			t.Fatal(err)
		}

		_, err = c.Registry.Digests(filepath.Join(t.TempDir(), "absent"))
		refused(t, err, []string{"reading the asset directory"})
	})
}

// TestBareDigestHasNoSubjectLines: a subject line names the image
// pushed, which a bare digest does not state, so none is invented.
func TestBareDigestHasNoSubjectLines(t *testing.T) {
	t.Parallel()

	c, err := decl(t, `{`+bareHead+`}`).Compile("arch-image")
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.Registry.RegistrySubjects(writeFiles(t, map[string]string{"amd64": digestA}), []string{"amd64"})
	refused(t, err, []string{
		"release: arch-image subjects: a bare-digest class records no image name, so it has no subject lines",
	})
}

// forbidden are this organisation's class names and asset-name
// shapes: none may be written in non-test code (stele#442). They are
// policy, declared on each class's assert-policy entry.
var forbidden = []string{
	"go-binary", "rust-binary", "pgrx-extension", "pgrx-extension-image",
	"-pg", "-linux-", "-debug",
}

// TestNoClassIsNamedInCode reads every string literal in the non-test
// Go source under internal/ and cmd/. Prose may mention a class; code
// may not spell one, because what code spells it decides.
func TestNoClassIsNamedInCode(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")

	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() && d.Name() == "testdata" {
				return filepath.SkipDir
			}

			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			for _, lit := range stringLiterals(t, path) {
				for _, f := range forbidden {
					if strings.Contains(lit.text, f) {
						t.Errorf("%s: %s spells %q — a class or asset shape is policy, never code", lit.pos, lit.text, f)
					}
				}
			}

			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

type literal struct {
	pos  token.Position
	text string
}

// stringLiterals scans one file's string and rune literals; comments
// are skipped by the scanner.
func stringLiterals(t *testing.T, path string) []literal {
	t.Helper()

	src, err := os.ReadFile(path) //nolint:gosec // a path under this repository
	if err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	file := fset.AddFile(path, -1, len(src))

	var (
		s   scanner.Scanner
		out []literal
	)

	s.Init(file, src, func(pos token.Position, msg string) { t.Errorf("%s: %s", pos, msg) }, 0)

	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			return out
		}

		if tok == token.STRING || tok == token.CHAR {
			out = append(out, literal{fset.Position(pos), lit})
		}
	}
}
