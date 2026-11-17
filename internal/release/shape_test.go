// The declared subject shape (stele#442): every load guard, the
// stranger's registry class, and the structural rule that no class
// and no asset-name shape is written in code.

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
	filesHead = `"kind":"files","entry":"^(?P<a>[a-z]+)-(?P<b>[0-9]+)$","unit":"leg","shape":"<a>-<b>",` +
		`"extension":".zip"`
	oneAsset = `"assets":[{"noun":"bundle","of":"${a}/${b}","suffix":"-${a}-${b}.zip"}]`
	regHead  = `"kind":"registry","entry":"^v[0-9]+$","unit":"variant","shape":"a variant","extension":".json"`
)

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
			"no assets", `{` + filesHead + `,"label":"${a}"}`,
			where + ".assets is absent or empty — the files kind requires it",
		},
		{
			"a registry parameter on a files shape",
			`{` + filesHead + `,"label":"${a}",` + oneAsset + `,"legField":"v"}`,
			where + ".legField is declared but the files kind does not read it",
		},
		{
			"a files parameter on a registry shape",
			`{` + regHead + `,"legField":"variant","label":"x"}`,
			where + ".label is declared but the registry kind does not read it",
		},
		{
			"an entry with no leading anchor",
			`{"kind":"registry","entry":"v[0-9]+$","unit":"u","shape":"s","extension":".json","legField":"v"}`,
			where + `.entry "v[0-9]+$" is not anchored — it must begin with ^ and end with $`,
		},
		{
			"an entry with no trailing anchor",
			`{"kind":"registry","entry":"^v[0-9]+","unit":"u","shape":"s","extension":".json","legField":"v"}`,
			where + `.entry "^v[0-9]+" is not anchored`,
		},
		{
			"an entry ending in an escaped dollar",
			`{"kind":"registry","entry":"^v\\$","unit":"u","shape":"s","extension":".json","legField":"v"}`,
			where + `.entry "^v\\$" is not anchored`,
		},
		{
			"an entry that does not compile",
			`{"kind":"registry","entry":"^(v$","unit":"u","shape":"s","extension":".json","legField":"v"}`,
			where + ".entry: error parsing regexp: missing closing )",
		},
		{
			"a label naming an undefined group",
			`{` + filesHead + `,"label":"${c}",` + oneAsset + `}`,
			where + `.label "${c}" names the group "c", which entry does not define`,
		},
		{
			"a suffix naming an undefined group",
			`{` + filesHead + `,"label":"${a}","assets":[{"noun":"n","of":"${a}","suffix":"-$arch.zip"}]}`,
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
			`{` + filesHead + `,"label":"${a}","assets":[{"noun":"n","of":"${a}","suffix":"-$.zip"}]}`,
			where + `.assets[0].suffix "-$.zip" carries a $ that names no group — write $$ for a literal dollar`,
		},
		{
			"an empty braced placeholder",
			`{` + filesHead + `,"label":"${}",` + oneAsset + `}`,
			where + `.label "${}" carries a $ that names no group`,
		},
		{
			"an asset with no noun",
			`{` + filesHead + `,"label":"${a}","assets":[{"of":"${a}","suffix":"-${a}.zip"}]}`,
			where + ".assets[0].noun is absent or empty",
		},
		{
			"an asset with no suffix",
			`{` + filesHead + `,"label":"${a}","assets":[{"noun":"n","of":"${a}","suffix":""}]}`,
			where + ".assets[0].suffix is absent or empty",
		},
		{
			"a suffix outside the extension",
			`{` + filesHead + `,"label":"${a}","assets":[{"noun":"n","of":"${a}","suffix":"-${a}.tar"}]}`,
			where + `.assets[0].suffix "-${a}.tar" does not end in the extension ".zip" — no listed file could match it`,
		},
		{
			"a leg field the document carries for itself",
			`{` + regHead + `,"legField":"digest"}`,
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

// TestShapeLiteralDollar: $$ is the one placeholder that names no
// group, and it renders a dollar.
func TestShapeLiteralDollar(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x-$q-1.zip"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

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

// TestRegistryFromADeclaredShape: a registry class whose digest
// documents name their leg in a field of the policy's choosing.
func TestRegistryFromADeclaredShape(t *testing.T) {
	t.Parallel()

	const digest = "sha256:b000000000000000000000000000000000000000000000000000000000000001"

	c, err := decl(t, `{`+regHead+`,"legField":"variant"}`).Compile("edge-image")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	body := `{"variant":"v2","image":"registry.example/edge","tag":"v2-1","digest":"` + digest + `"}`

	if werr := os.WriteFile(filepath.Join(dir, "v2.json"), []byte(body), 0o600); werr != nil {
		t.Fatal(werr)
	}

	r, err := c.Registry.RegistrySubjects(dir, []string{"v2"})
	if err != nil {
		t.Fatalf("RegistrySubjects: %v", err)
	}

	want := "v2 " + strings.TrimPrefix(digest, "sha256:") + "  registry.example/edge\n"
	if got := string(r.Bytes()); got != want {
		t.Errorf("lines %q, want %q", got, want)
	}

	_, err = c.Registry.RegistrySubjects(dir, []string{"v2", "3"})
	refused(t, err, []string{`release: edge-image subjects: planned variant "3" is not a variant`})

	if werr := os.WriteFile(filepath.Join(dir, "v2.json"), []byte(`{"pg":"v2"}`), 0o600); werr != nil {
		t.Fatal(werr)
	}

	_, err = c.Registry.RegistrySubjects(dir, []string{"v2"})
	refused(t, err, []string{`v2.json: unknown field "pg"`})
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
