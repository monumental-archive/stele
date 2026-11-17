package assert_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
)

// classPolicy wraps a classes block in the rest of a valid policy.
func classPolicy(t *testing.T, classes string) (*assert.Policy, error) {
	t.Helper()

	return assert.LoadPolicy(strings.NewReader(`{
  "schema": 9,
  "evidence": {
    "sbomSuffix": ".spdx.json", "checksums": "SHA256SUMS",
    "umbrellaBundle": "attestations.intoto.jsonl", "manifestAsset": "evidence-manifest.json",
    "storeVsaFromVersion": "1.0.0",
    "classes": ` + classes + `
  }
}`))
}

func mustClassPolicy(t *testing.T, classes string) *assert.Policy {
	t.Helper()

	p, err := classPolicy(t, classes)
	if err != nil {
		t.Fatalf("LoadPolicy = %v", err)
	}

	return p
}

// canonShapes is the canon's class vocabulary and expansions as its
// publish workflow applied them (.github 30ba101) — test data, and the
// only place these names appear: nine declared classes, seven
// requestable, oci-image declared as oci-image-crate IN ITS PLACE when
// a binary crate is given, and pgrx-extension followed by its image
// class.
const canonShapes = `{
  "rust-crate": {"bundles": ["a.intoto.jsonl"]},
  "oci-image": {"bundles": ["b.intoto.jsonl"], "declares": [
    {"kind": "instead", "when": "binary-crate", "class": "oci-image-crate", "output": "image-class"}
  ]},
  "oci-image-crate": {"bundles": ["b.intoto.jsonl"], "requestable": false},
  "rust-binary": {"bundles": ["c.intoto.jsonl"]},
  "go-binary": {"bundles": ["d.intoto.jsonl"]},
  "wasm-npm": {"bundles": ["e.intoto.jsonl"]},
  "pgrx-extension": {"bundles": ["f.intoto.jsonl"], "declares": [
    {"kind": "after", "class": "pgrx-extension-image", "output": "extension-image-class"}
  ]},
  "pgrx-extension-image": {"bundles": ["f.intoto.jsonl"], "requestable": false},
  "source-archive": {"bundles": ["g.intoto.jsonl"]}
}`

// strangerShapes shares no class, input or output name with the
// canon's, and derives through the same engine with no code change: a
// firmware vendor whose firmware is declared as its signed variant
// when a signing key is given, and whose charts always bring their
// recovery bundle.
const strangerShapes = `{
  "firmware": {"bundles": ["fw.intoto.jsonl"], "declares": [
    {"kind": "instead", "when": "signing-key", "class": "firmware-signed", "output": "signed-class"},
    {"kind": "after", "when": "rescue-partition", "class": "rescue-image"}
  ]},
  "firmware-signed": {"bundles": ["fw.intoto.jsonl"], "requestable": false},
  "rescue-image": {"bundles": ["rescue.intoto.jsonl"]},
  "helm-chart": {"bundles": ["charts.intoto.jsonl"], "declares": [
    {"kind": "after", "class": "recovery-bundle", "output": "recovery-class"}
  ]},
  "recovery-bundle": {"bundles": ["recovery.intoto.jsonl"], "requestable": false}
}`

func declare(t *testing.T, p *assert.Policy, csv string, given map[string]string) (*assert.ClassDeclaration, error) {
	t.Helper()

	requested, err := assert.ParseClassRequest(csv)
	if err != nil {
		return nil, err
	}

	return p.DeclareClasses(requested, given)
}

func outputs(d *assert.ClassDeclaration) []string {
	out := make([]string, 0, len(d.Outputs))
	for _, o := range d.Outputs {
		out = append(out, o.Key+"="+o.Value)
	}

	return out
}

// TestDeclareClassesCanonShapes: every requestable class alone, each
// expansion, and the order of the declared list as the canon's step
// gave it. The outputs are always all printed, in policy order.
func TestDeclareClassesCanonShapes(t *testing.T) {
	t.Parallel()

	p := mustClassPolicy(t, canonShapes)
	crate := map[string]string{"binary-crate": "widget-cli"}

	for _, tt := range []struct {
		name    string
		csv     string
		given   map[string]string
		classes []string
		image   string
		ext     string
	}{
		{"rust-crate alone", "rust-crate", nil, []string{"rust-crate"}, "", ""},
		{"oci-image alone", "oci-image", nil, []string{"oci-image"}, "", ""},
		{"rust-binary alone", "rust-binary", nil, []string{"rust-binary"}, "", ""},
		{"go-binary alone", "go-binary", nil, []string{"go-binary"}, "", ""},
		{"wasm-npm alone", "wasm-npm", nil, []string{"wasm-npm"}, "", ""},
		{"source-archive alone", "source-archive", nil, []string{"source-archive"}, "", ""},
		{
			name: "pgrx-extension brings its image class right after it",
			csv:  "pgrx-extension", classes: []string{"pgrx-extension", "pgrx-extension-image"},
			ext: "pgrx-extension-image",
		},
		{
			// #843: a crate-built image is a different class, declared
			// IN PLACE of oci-image — never beside it.
			name: "oci-image with a binary crate is oci-image-crate in its place",
			csv:  "oci-image", given: crate, classes: []string{"oci-image-crate"}, image: "oci-image-crate",
		},
		{
			name: "an empty binary crate is no crate",
			csv:  "oci-image", given: map[string]string{"binary-crate": ""}, classes: []string{"oci-image"},
		},
		{
			name: "order as requested, with the substitution and the insertion in place",
			csv:  "rust-binary, oci-image, pgrx-extension, source-archive", given: crate,
			classes: []string{"rust-binary", "oci-image-crate", "pgrx-extension", "pgrx-extension-image", "source-archive"},
			image:   "oci-image-crate", ext: "pgrx-extension-image",
		},
		{
			name: "a class named twice is declared twice",
			csv:  "go-binary,go-binary", classes: []string{"go-binary", "go-binary"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d, err := declare(t, p, tt.csv, tt.given)
			if err != nil {
				t.Fatalf("DeclareClasses = %v", err)
			}

			if !slices.Equal(d.Classes, tt.classes) {
				t.Errorf("classes = %v, want %v", d.Classes, tt.classes)
			}

			// Policy order: classes sorted, then each list in order.
			want := []string{"image-class=" + tt.image, "extension-image-class=" + tt.ext}
			if got := outputs(d); !slices.Equal(got, want) {
				t.Errorf("outputs = %v, want %v", got, want)
			}
		})
	}
}

// TestDeclareClassesStranger: a policy that shares no name with the
// canon's derives through the same engine — the expansion is the
// policy's, never this code's.
func TestDeclareClassesStranger(t *testing.T) {
	t.Parallel()

	p := mustClassPolicy(t, strangerShapes)

	for _, tt := range []struct {
		name    string
		csv     string
		given   map[string]string
		classes []string
		outputs []string
	}{
		{
			name: "a chart brings its recovery bundle", csv: "helm-chart",
			classes: []string{"helm-chart", "recovery-bundle"},
			outputs: []string{"signed-class=", "recovery-class=recovery-bundle"},
		},
		{
			name: "signed firmware in place, and a conditional after with no output", csv: "firmware",
			given:   map[string]string{"signing-key": "k1", "rescue-partition": "p2"},
			classes: []string{"firmware-signed", "rescue-image"},
			outputs: []string{"signed-class=firmware-signed", "recovery-class="},
		},
		{
			name: "firmware with nothing given is firmware", csv: "firmware",
			classes: []string{"firmware"},
			outputs: []string{"signed-class=", "recovery-class="},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d, err := declare(t, p, tt.csv, tt.given)
			if err != nil {
				t.Fatalf("DeclareClasses = %v", err)
			}

			if !slices.Equal(d.Classes, tt.classes) || !slices.Equal(outputs(d), tt.outputs) {
				t.Fatalf("declared %v %v, want %v %v", d.Classes, outputs(d), tt.classes, tt.outputs)
			}
		})
	}
}

// TestDeclareClassesRefusals: every refusal of a request, by name.
func TestDeclareClassesRefusals(t *testing.T) {
	t.Parallel()

	canon := mustClassPolicy(t, canonShapes)
	bothInstead := mustClassPolicy(t, `{
	  "board": {"bundles": ["b.intoto.jsonl"], "declares": [
	    {"kind": "instead", "when": "rev-a", "class": "board-a"},
	    {"kind": "instead", "when": "rev-b", "class": "board-b"}
	  ]},
	  "board-a": {"bundles": ["a.intoto.jsonl"]},
	  "board-b": {"bundles": ["c.intoto.jsonl"]}
	}`)

	for _, tt := range []struct {
		name  string
		p     *assert.Policy
		csv   string
		given map[string]string
		want  string
		is    error
	}{
		{
			name: "an empty request", p: canon, csv: "",
			want: "no classes requested — a release that builds nothing is not a release", is: assert.ErrNoClasses,
		},
		{name: "a request of spaces", p: canon, csv: "  ", want: "no classes requested", is: assert.ErrNoClasses},
		{name: "an empty element", p: canon, csv: "go-binary,,rust-crate", want: "requested class 2 of 3 is empty"},
		{name: "a trailing comma", p: canon, csv: "go-binary,", want: "requested class 2 of 2 is empty"},
		{
			name: "an unknown class", p: canon, csv: "go-binary,firmware",
			want: `unknown class requested: "firmware" is not declared in evidence.classes`,
		},
		{
			name: "a name with a space inside", p: canon, csv: "go binary",
			want: `unknown class requested: "go binary"`,
		},
		{
			name: "a class only ever derived", p: canon, csv: "oci-image-crate",
			want: `class "oci-image-crate" is not requestable`,
		},
		{
			// #775: a crate declared for an image nobody requested
			// would build nothing.
			name: "a binary crate without oci-image", p: canon, csv: "go-binary",
			given: map[string]string{"binary-crate": "widget-cli"},
			want:  "binary-crate is declared but oci-image is not among the classes — it would build nothing",
		},
		{
			name: "an input no expansion turns on", p: canon, csv: "go-binary",
			given: map[string]string{"signing-key": "k1"},
			want:  `input "signing-key" is turned on by no expansion in evidence.classes`,
		},
		{
			name: "two instead expansions that both apply", p: bothInstead, csv: "board",
			given: map[string]string{"rev-a": "1", "rev-b": "1"},
			want:  `class "board" would be declared as both "board-a" and "board-b"`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := declare(t, tt.p, tt.csv, tt.given)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want it to name %q", err, tt.want)
			}

			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("got %v, want it to wrap %v", err, tt.is)
			}
		})
	}

	t.Run("a declaration with nothing requested", func(t *testing.T) {
		t.Parallel()

		if _, err := canon.DeclareClasses(nil, nil); !errors.Is(err, assert.ErrNoClasses) {
			t.Fatalf("DeclareClasses(nil) = %v, want the empty-request refusal", err)
		}
	})
}

// TestExpansionLoadRefusals: an expansion one pass could not apply is
// refused with the rest of the policy, never at release time.
func TestExpansionLoadRefusals(t *testing.T) {
	t.Parallel()

	base := `"t": {"bundles": ["t.intoto.jsonl"]}, "u": {"bundles": ["u.intoto.jsonl"]}`

	for _, tt := range []struct {
		name     string
		declares string
		extra    string
		want     string
	}{
		{"no kind", `{"class": "t"}`, "", "names no kind (instead or after)"},
		{"an unknown kind", `{"kind": "beside", "class": "t"}`, "", `.kind "beside" is not an expansion`},
		{"instead without when", `{"kind": "instead", "class": "t"}`, "", "names the input it turns on (when)"},
		{"an empty when", `{"kind": "after", "when": "", "class": "t"}`, "", ".when is empty"},
		{"no class", `{"kind": "after"}`, "", "names no class to declare"},
		{"an empty class", `{"kind": "after", "class": ""}`, "", "names no class to declare"},
		{"an empty output", `{"kind": "after", "class": "t", "output": ""}`, "", ".output is empty"},
		{"an undeclared target", `{"kind": "after", "class": "nowhere"}`, "", `.class "nowhere" is not declared`},
		{
			"a target that declares", `{"kind": "after", "class": "v"}`,
			`, "v": {"bundles": ["v.intoto.jsonl"], "declares": [{"kind": "after", "class": "t"}]}`,
			`.class "v" declares expansions of its own — expansion is one pass`,
		},
		{
			"one output key twice",
			`{"kind": "after", "class": "t", "output": "k"}, {"kind": "after", "class": "u", "output": "k"}`,
			"", `.output "k" is already`,
		},
		{"a parameter no kind reads", `{"kind": "after", "class": "t", "unless": "x"}`, "", "unknown field"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := classPolicy(t, `{`+base+`, "s": {"bundles": ["s.intoto.jsonl"], "declares": [`+
				tt.declares+`]}`+tt.extra+`}`)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("LoadPolicy = %v, want it to name %q", err, tt.want)
			}
		})
	}
}
