// The enrichment write side: names held to the policy's closed set,
// sources read from the two trees, rows claimed only for declared
// keys. The first row is the canon shell's own output shape; every
// refusal row asserts its message.

package emit_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/emit"
	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/policy"
)

const (
	enrSrc    = "1111111111111111111111111111111111111111"
	enrCommit = "2222222222222222222222222222222222222222"
	enrPolSHA = "3333333333333333333333333333333333333333333333333333333333333333"

	baseTOML = `[build]
"14" = "postgres:14-bookworm@sha256:aa"
"16" = "postgres:16-bookworm@sha256:bb"

[smoke]
"14" = "postgres:14-trixie@sha256:cc"
"16" = "postgres:16-trixie@sha256:dd"
`
)

// fakeTrees serves two in-memory trees; a path listed in fail refuses.
type fakeTrees struct {
	files map[string]string // "<tree>:<path>" → content
	fail  map[string]bool
}

//nolint:gocritic // unnamedResult: the Trees interface documents the results
func (f fakeTrees) Read(tree, path string) ([]byte, bool, error) {
	if f.fail[tree+":"+path] {
		return nil, false, errors.New("HTTP 503")
	}

	content, ok := f.files[tree+":"+path]
	if !ok {
		return nil, false, nil
	}

	return []byte(content), true, nil
}

func (fakeTrees) URI(tree, path string) string { return "https://" + tree + ".example/" + path }

func sum(s string) string {
	h := sha256.Sum256([]byte(s))

	return hex.EncodeToString(h[:])
}

func orgEnrichment() *policy.Enrichment {
	return &policy.Enrichment{
		Required:  []string{"toolbelt-lock"},
		Permitted: []string{"pgrx-base-images", "pgrx-base", "Cargo.lock", "package-lock.json", "mise.toml"},
	}
}

func orgTrees() fakeTrees {
	return fakeTrees{files: map[string]string{
		"policy:mise/mise.lock":                  "lock",
		"policy:docker/pgrx-base-images.toml":    baseTOML,
		"source:Cargo.lock":                      "cargo",
		"source:mise.toml":                       "mise",
		"policy:docker/not-toml.toml":            "= = =",
		"policy:docker/pgrx-base-images-14.toml": "[build]\n\"14\" = \"x\"\n",
	}}
}

func orgSources(keys ...string) []emit.Source {
	return []emit.Source{
		{Name: "toolbelt-lock", Tree: emit.TreePolicy, Path: "mise/mise.lock"},
		{Name: "pgrx-base", Tree: emit.TreePolicy, Path: "docker/pgrx-base-images.toml", Rows: &emit.Rows{
			Tables: []string{"build", "smoke"}, Prefix: "oci://docker.io/library/", Keys: keys,
			File: "pgrx-base-images",
		}},
		{Name: "Cargo.lock", Tree: emit.TreeSource, Path: "Cargo.lock"},
		{Name: "package-lock.json", Tree: emit.TreeSource, Path: "package-lock.json"},
		{Name: "mise.toml", Tree: emit.TreeSource, Path: "mise.toml"},
	}
}

func enrInputs(sources []emit.Source) *emit.EnrichmentInputs {
	return &emit.EnrichmentInputs{
		ResourceURI:      "pkg:github/acme/widget@v1.0.0",
		SourceRepository: "https://github.com/acme/widget",
		SourceRevision:   enrSrc,
		PolicyURI:        "https://policy.example/verify-policy.json",
		PolicySHA256:     enrPolSHA,
		PolicyCommit:     enrCommit,
		Sources:          sources,
	}
}

// render flattens the claimed dependencies for comparison.
func render(deps []intoto.ResourceDescriptor) []string {
	out := make([]string, 0, len(deps))

	for _, d := range deps {
		out = append(out, *d.Name+" "+*d.URI+" "+d.Digest[intoto.AlgSHA256])
	}

	return out
}

func TestEnrichmentClaims(t *testing.T) {
	t.Parallel()

	var logs []string

	pred, err := emit.Enrichment(orgEnrichment(), enrInputs(orgSources("14", "16")), orgTrees(),
		func(format string, _ ...any) { logs = append(logs, format) })
	if err != nil {
		t.Fatalf("Enrichment = %v", err)
	}

	// The canon shell's order and shape: the toolbelt lock, the base
	// mapping file and then its rows (build and smoke per declared key,
	// digestless), then the source lockfiles the revision carries — an
	// absent one simply not claimed.
	want := []string{
		"toolbelt-lock https://policy.example/mise/mise.lock " + sum("lock"),
		"pgrx-base-images https://policy.example/docker/pgrx-base-images.toml " + sum(baseTOML),
		"pgrx-base oci://docker.io/library/postgres:14-bookworm@sha256:aa ",
		"pgrx-base oci://docker.io/library/postgres:14-trixie@sha256:cc ",
		"pgrx-base oci://docker.io/library/postgres:16-bookworm@sha256:bb ",
		"pgrx-base oci://docker.io/library/postgres:16-trixie@sha256:dd ",
		"Cargo.lock https://source.example/Cargo.lock " + sum("cargo"),
		"mise.toml https://source.example/mise.toml " + sum("mise"),
	}

	if got := render(pred.ResolvedDependencies); !slices.Equal(got, want) {
		t.Fatalf("dependencies =\n  %q\nwant\n  %q", got, want)
	}

	if pred.ResolvedDependencies[2].Digest != nil {
		t.Fatalf("a row carries a digest of its own: %v", pred.ResolvedDependencies[2].Digest)
	}

	if *pred.ResourceURI != "pkg:github/acme/widget@v1.0.0" || pred.Revision() != enrSrc ||
		*pred.SourceRevision.URI != "https://github.com/acme/widget" {
		t.Fatalf("the claim is bound to %q / %q / %q", *pred.ResourceURI, *pred.SourceRevision.URI, pred.Revision())
	}

	if p := pred.Policy; *p.URI != "https://policy.example/verify-policy.json" ||
		p.Digest[intoto.AlgSHA256] != enrPolSHA || p.Digest[intoto.AlgGitCommit] != enrCommit {
		t.Fatalf("policy descriptor = %v %v", *p.URI, p.Digest)
	}

	if err := pred.Validate(); err != nil {
		t.Fatalf("the emitted claim does not validate: %v", err)
	}

	if !slices.Contains(logs, "emit: enrichment: %s: the %s tree carries no %s — not claimed") {
		t.Fatalf("the absent lockfile went unsaid: %q", logs)
	}
}

// TestEnrichmentNoKeysClaimsNoRows is #316 finding 3 held: a build that
// declares no base consumed claims neither the rows nor their file.
func TestEnrichmentNoKeysClaimsNoRows(t *testing.T) {
	t.Parallel()

	pred, err := emit.Enrichment(orgEnrichment(), enrInputs(orgSources()), orgTrees(), func(string, ...any) {})
	if err != nil {
		t.Fatalf("Enrichment = %v", err)
	}

	for _, n := range pred.Names() {
		if strings.HasPrefix(n, "pgrx-base") {
			t.Fatalf("a build that consumed no base claims %s", n)
		}
	}
}

func TestEnrichmentRefusals(t *testing.T) {
	t.Parallel()

	with := func(edit func([]emit.Source) []emit.Source) []emit.Source { return edit(orgSources("14")) }

	tests := []struct {
		name    string
		policy  *policy.Enrichment
		sources []emit.Source
		trees   fakeTrees
		edit    func(*emit.EnrichmentInputs)
		want    string
	}{
		{
			name:   "no enrichment obligation",
			policy: nil,
			want:   "emit: the policy declares no build.enrichment — no enrichment is owed, and none is emitted",
		},
		{
			name: "a name the policy does not permit",
			sources: with(func(s []emit.Source) []emit.Source {
				return append(s, emit.Source{Name: "go.sum", Tree: emit.TreeSource, Path: "go.sum"})
			}),
			want: `emit: a source names "go.sum", which the policy neither requires nor permits — the declared set is closed`,
		},
		{
			name: "a rows file name the policy does not permit",
			sources: with(func(s []emit.Source) []emit.Source {
				s[1].Rows.File = "base-map"

				return s
			}),
			want: `emit: a source names "base-map", which the policy neither requires nor permits`,
		},
		{
			name: "one name, two sources",
			sources: with(func(s []emit.Source) []emit.Source {
				return append(s, emit.Source{Name: "mise.toml", Tree: emit.TreePolicy, Path: "mise.toml"})
			}),
			want: `emit: two sources name "mise.toml" — one name, one source`,
		},
		{
			name:    "a required name with no source",
			sources: with(func(s []emit.Source) []emit.Source { return s[1:] }),
			want:    `emit: the policy requires enrichment name "toolbelt-lock" and no source declares where it comes from`,
		},
		{
			name: "a required file the tree does not carry",
			sources: with(func(s []emit.Source) []emit.Source {
				s[0].Path = "mise/absent.lock"

				return s
			}),
			want: `emit: enrichment: the policy requires "toolbelt-lock", and the policy tree carries no mise/absent.lock`,
		},
		{
			name: "rows declared from a file the tree does not carry",
			sources: with(func(s []emit.Source) []emit.Source {
				s[1].Path = "docker/absent.toml"

				return s
			}),
			want: "emit: enrichment: pgrx-base: rows are declared for keys 14, but the policy tree carries no " +
				"docker/absent.toml — the declaration cannot be honoured",
		},
		{
			name: "a declared key a table lacks",
			sources: with(func(s []emit.Source) []emit.Source {
				s[1].Rows.Keys = []string{"14", "99"}

				return s
			}),
			want: "emit: enrichment: pgrx-base: declared key 99 has no build row in docker/pgrx-base-images.toml — " +
				"the declaration cannot be honoured",
		},
		{
			name: "a declared table the file lacks",
			sources: with(func(s []emit.Source) []emit.Source {
				s[1].Path = "docker/pgrx-base-images-14.toml"

				return s
			}),
			want: "declared key 14 has no smoke row in docker/pgrx-base-images-14.toml",
		},
		{
			name: "a rows file that is not TOML",
			sources: with(func(s []emit.Source) []emit.Source {
				s[1].Path = "docker/not-toml.toml"

				return s
			}),
			want: "emit: enrichment: pgrx-base: docker/not-toml.toml is not TOML",
		},
		{
			name:  "a tree that cannot be read",
			trees: fakeTrees{fail: map[string]bool{"source:Cargo.lock": true}},
			want:  "emit: enrichment: Cargo.lock: reading Cargo.lock from the source tree: HTTP 503",
		},
		{
			name:   "a required rows name with no keys declared claims nothing, and refuses",
			policy: &policy.Enrichment{Required: []string{"pgrx-base"}},
			sources: []emit.Source{{Name: "pgrx-base", Tree: emit.TreePolicy, Path: "x.toml", Rows: &emit.Rows{
				Tables: []string{"build"}, Prefix: "oci://",
			}}},
			want: "emit: enrichment: resolvedDependencies is empty",
		},
		{
			name: "a source revision that is no commit",
			edit: func(in *emit.EnrichmentInputs) { in.SourceRevision = "main" },
			want: "emit: enrichment: sourceRevision",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pol := tt.policy
			if pol == nil && tt.name != "no enrichment obligation" {
				pol = orgEnrichment()
			}

			sources := tt.sources
			if sources == nil {
				sources = orgSources("14")
			}

			trees := tt.trees
			if trees.files == nil {
				trees.files = orgTrees().files
			}

			in := enrInputs(sources)
			if tt.edit != nil {
				tt.edit(in)
			}

			pred, err := emit.Enrichment(pol, in, trees, func(string, ...any) {})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Enrichment = %v, %v; want the refusal %q", pred, err, tt.want)
			}
		})
	}
}

// TestEnrichmentRequiredClaimedNone holds the last guard: a required
// name whose source yielded nothing — rows with no keys — refuses by
// name even when another source keeps the claim non-empty.
func TestEnrichmentRequiredClaimedNone(t *testing.T) {
	t.Parallel()

	pol := &policy.Enrichment{Required: []string{"toolbelt-lock", "pgrx-base"}}
	sources := []emit.Source{
		{Name: "toolbelt-lock", Tree: emit.TreePolicy, Path: "mise/mise.lock"},
		{Name: "pgrx-base", Tree: emit.TreePolicy, Path: "docker/pgrx-base-images.toml", Rows: &emit.Rows{
			Tables: []string{"build"}, Prefix: "oci://",
		}},
	}

	_, err := emit.Enrichment(pol, enrInputs(sources), orgTrees(), func(string, ...any) {})
	if err == nil || err.Error() != `emit: the policy requires enrichment name "pgrx-base" and the claim carries none` {
		t.Fatalf("Enrichment = %v", err)
	}
}
