// The release workflow as a declaration (stele#448): pins derive from
// the stub the assert policy names, read through internal/workflow,
// and no workflow file name is written in this engine's code.

package assert_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/verify"
)

const otherPin40 = "dddddddddddddddddddddddddddddddddddddddd"

// publishOf is a release-workflow declaration.
func publishOf(stubPath, stubUses, selfStubPath string) *assert.PublishPolicy {
	p := &assert.PublishPolicy{StubPath: &stubPath, StubUses: &stubUses}
	if selfStubPath != "" {
		p.SelfStubPath = &selfStubPath
	}

	return p
}

// strangerRoots resolves for a repository published through
// `.github/workflows/ship.yaml` into `other/machinery`, whose
// workflow `flows/release-it.yml` calls the signer.
func strangerRoots(t *testing.T, f *fakeForge) assert.PinRoots {
	t.Helper()

	roots, err := assert.NewPinRoots(f, "other/machinery/flows/verify.yml", "acme/signer/.github/workflows/sign.yml")
	if err != nil {
		t.Fatal(err)
	}

	roots.Publish = publishOf(".github/workflows/ship.yaml", "other/machinery/flows/", "")

	return roots
}

// strangerForge carries that repository's release: a stub not named
// publish.yml, and a machinery workflow at its pin.
func strangerForge(stub string) *fakeForge {
	return &fakeForge{files: map[string]string{
		"widget:v1.0.0:.github/workflows/ship.yaml": stub,
		"machinery:" + machineryPin40 + ":flows/release-it.yml": "jobs:\n  sign:\n" +
			"    uses: acme/signer/.github/workflows/sign.yml@" + signerPin40 + "\n",
	}}
}

const strangerStub = "on: push\njobs:\n  ship:\n    uses: other/machinery/flows/release-it.yml@" +
	machineryPin40 + "\n"

// TestResolvePinsFromADeclaredStub: a repository whose stub is not
// named publish.yml derives its pins from a policy that says so, with
// no code change — and the same tree under a declaration naming
// another stub refuses, naming the stub it looked for.
func TestResolvePinsFromADeclaredStub(t *testing.T) {
	t.Parallel()

	f := strangerForge(strangerStub)
	declared := strangerRoots(t, f)

	pins, err := declared.Resolve(f, testOrg, "widget", "v1.0.0")
	if err != nil || pins != (verify.Pins{Machinery: machineryPin40, Signer: signerPin40}) {
		t.Fatalf("Resolve = %+v, %v; want the pins the declared stub names", pins, err)
	}

	roots := strangerRoots(t, f)
	roots.Publish = publishOf(".github/workflows/publish.yml", "other/machinery/flows/", "")

	if _, err := roots.Resolve(f, testOrg, "widget", "v1.0.0"); err == nil ||
		!strings.Contains(err.Error(), ".github/workflows/publish.yml is absent at v1.0.0") {
		t.Fatalf("Resolve = %v, want the undeclared stub's absence named", err)
	}
}

// TestResolvePinsIgnoresACommentedPin: the first full-commit `uses:` in
// the stub sits in a comment; the pin is the job's.
func TestResolvePinsIgnoresACommentedPin(t *testing.T) {
	t.Parallel()

	stub := "# was: uses: other/machinery/flows/release-it.yml@" + otherPin40 + "\n" + strangerStub
	f := strangerForge(stub)
	roots := strangerRoots(t, f)

	pins, err := roots.Resolve(f, testOrg, "widget", "v1.0.0")
	if err != nil || pins.Machinery != machineryPin40 {
		t.Fatalf("Resolve = %+v, %v; want the job's pin %s, not the comment's", pins, err, machineryPin40)
	}
}

func TestResolvePinsRefusals(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		stub  string
		shape func(f *fakeForge, r *assert.PinRoots)
		want  string
	}{
		{
			name:  "no evidence.publish and a non-templated signer",
			stub:  strangerStub,
			shape: func(_ *fakeForge, r *assert.PinRoots) { r.Publish = nil },
			want:  "no evidence.publish is declared and the signer identity is not templated",
		},
		{
			name:  "the stub absent at the tag",
			stub:  strangerStub,
			shape: func(f *fakeForge, _ *assert.PinRoots) { delete(f.files, "widget:v1.0.0:.github/workflows/ship.yaml") },
			want:  "the publish workflow .github/workflows/ship.yaml is absent at v1.0.0",
		},
		{
			name: "two commits",
			stub: strangerStub + "  again:\n    uses: other/machinery/flows/release-it.yml@" + otherPin40 + "\n",
			want: "calls other/machinery/flows/ at more than one commit — a release states its machinery once: " +
				machineryPin40 + " " + otherPin40,
		},
		{
			name: "a moving ref",
			stub: "jobs:\n  ship:\n    uses: other/machinery/flows/release-it.yml@v2\n",
			want: `calls flows/release-it.yml at "v2" (jobs.ship), which is not a commit — a moving ref pins no machinery`,
		},
		{
			name: "the machinery tree naming no signer pin",
			stub: strangerStub,
			shape: func(f *fakeForge, _ *assert.PinRoots) {
				f.files["machinery:"+machineryPin40+":flows/release-it.yml"] = "jobs:\n  build:\n    runs-on: x\n"
			},
			want: "the provenance identity cannot be derived: the machinery publish workflow " +
				"other/machinery/flows/release-it.yml at " + machineryPin40[:12] + " pins no sign.yml uses:",
		},
		{
			name: "the stub calls nothing under the declared machinery",
			stub: "jobs:\n  ship:\n    uses: acme/elsewhere/.github/workflows/x.yml@" + machineryPin40 + "\n",
			want: ".github/workflows/ship.yaml at v1.0.0 calls nothing under other/machinery/flows/",
		},
		{
			name: "two workflows at one commit",
			stub: strangerStub + "  also:\n    uses: other/machinery/flows/second.yml@" + machineryPin40 + "\n",
			want: "calls more than one workflow under other/machinery/flows/ — which one publishes is not stated",
		},
		{
			name: "a stub the reader cannot parse",
			stub: "jobs: [unclosed\n",
			want: ".github/workflows/ship.yaml at v1.0.0: workflow:",
		},
		{
			name: "a job reference the reader cannot parse",
			stub: "jobs:\n  ship:\n    uses: docker://alpine\n",
			want: ".github/workflows/ship.yaml at v1.0.0: jobs.ship.uses:",
		},
		{
			name: "the machinery workflow absent at its pin",
			stub: strangerStub,
			shape: func(f *fakeForge, _ *assert.PinRoots) {
				delete(f.files, "machinery:"+machineryPin40+":flows/release-it.yml")
			},
			want: "the machinery repository carries no publish workflow flows/release-it.yml at " + machineryPin40[:12],
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := strangerForge(tc.stub)
			roots := strangerRoots(t, f)

			if tc.shape != nil {
				tc.shape(f, &roots)
			}

			pins, err := roots.Resolve(f, testOrg, "widget", "v1.0.0")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Resolve = %+v, %v; want a refusal naming %q", pins, err, tc.want)
			}
		})
	}
}

// TestResolvePinsOwnMachinery: the machinery repository's own release
// runs at its tag, through the self stub that calls the machinery
// locally — and every way that declaration cannot be read refuses.
func TestResolvePinsOwnMachinery(t *testing.T) {
	t.Parallel()

	canonForge := func(self string) *fakeForge {
		f := &fakeForge{
			tagCommits: map[string]string{"v1.0.0": tagSHA40},
			files: map[string]string{
				"canon:" + tagSHA40 + ":.github/workflows/publish.yml": "on: workflow_call\njobs:\n  sign:\n" +
					"    uses: acme/signer/.github/workflows/sign.yml@" + signerPin40 + "\n",
			},
		}
		if self != "" {
			f.files["canon:v1.0.0:.github/workflows/self-publish.yml"] = self
		}

		return f
	}

	resolve := func(t *testing.T, f *fakeForge, selfStub string) (verify.Pins, error) {
		t.Helper()

		roots, err := assert.NewPinRoots(f, "acme/canon/.github/workflows/verify-release.yml",
			"acme/signer/.github/workflows/sign.yml")
		if err != nil {
			t.Fatal(err)
		}

		roots.Publish = publishOf(".github/workflows/publish.yml", "acme/canon/", selfStub)

		return roots.Resolve(f, testOrg, "canon", "v1.0.0")
	}

	const selfStub = ".github/workflows/self-publish.yml"

	t.Run("the self stub's local call names the machinery at the tag", func(t *testing.T) {
		t.Parallel()

		f := canonForge("jobs:\n  publish:\n    uses: ./.github/workflows/publish.yml\n")

		pins, err := resolve(t, f, selfStub)
		if err != nil || pins != (verify.Pins{Machinery: tagSHA40, Signer: signerPin40}) {
			t.Fatalf("Resolve = %+v, %v", pins, err)
		}
	})

	for _, tc := range []struct {
		name, self, selfStub, want string
		tagErr                     bool
	}{
		{
			name: "no selfStubPath declared", self: "jobs: {}\n",
			want: "acme/canon carries its own machinery, and evidence.publish declares no selfStubPath",
		},
		{
			name: "the tag's commit cannot be read", self: "jobs: {}\n", selfStub: selfStub, tagErr: true,
			want: "the tag's commit is unreadable",
		},
		{
			name: "the self stub absent at the tag", selfStub: selfStub,
			want: "the publish workflow .github/workflows/self-publish.yml is absent at v1.0.0",
		},
		{
			name: "the self stub calls nothing local", self: "jobs:\n  x:\n    runs-on: y\n", selfStub: selfStub,
			want: "calls no workflow of its own repository",
		},
		{
			name: "the self stub calls two local workflows", selfStub: selfStub,
			self: "jobs:\n  a:\n    uses: ./.github/workflows/publish.yml\n  b:\n    uses: ./.github/workflows/other.yml\n",
			want: "calls more than one workflow of its own repository",
		},
		{
			name: "the self stub cannot be parsed", self: "jobs: [\n", selfStub: selfStub,
			want: ".github/workflows/self-publish.yml at v1.0.0: workflow:",
		},
		{
			name: "a self stub reference cannot be parsed", self: "jobs:\n  a:\n    uses: docker://x\n", selfStub: selfStub,
			want: ".github/workflows/self-publish.yml at v1.0.0: jobs.a.uses:",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := canonForge(tc.self)
			if tc.tagErr {
				f.tagCommits = nil
			}

			pins, err := resolve(t, f, tc.selfStub)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Resolve = %+v, %v; want a refusal naming %q", pins, err, tc.want)
			}
		})
	}
}

// TestWorkflowContractReadsTheDeclaredStub: the legacy adapter reads
// the stub the policy names, and its machinery version is the comment
// beside the call the reader found — never a comment elsewhere.
func TestWorkflowContractReadsTheDeclaredStub(t *testing.T) {
	t.Parallel()

	const stubKey = "widget:v1.0.0:.github/workflows/ship.yaml"

	contract := func(t *testing.T, stub string, pub *assert.PublishPolicy) (*assert.Contract, bool) {
		t.Helper()

		pol := loadTestPolicy(t)
		pol.Evidence.Publish = pub

		f := &fakeForge{files: map[string]string{stubKey: stub}}

		c, ok, err := assert.WorkflowSource{Forge: f, Policy: pol.Evidence}.Contract(testOrg, "widget", "v1.0.0")
		if err != nil {
			t.Fatalf("Contract = %v", err)
		}

		return c, ok
	}

	declared := publishOf(".github/workflows/ship.yaml", "other/machinery/", "")

	t.Run("the version is the comment beside the found call", func(t *testing.T) {
		t.Parallel()

		stub := "# uses: other/machinery/flows/old.yml@x # v0.1.0\njobs:\n  ship:\n" +
			"    uses: other/machinery/flows/release-it.yml@" + machineryPin40 + " # v1.20.0\n" +
			"    with:\n      classes: oci-image\n"

		c, ok := contract(t, stub, declared)
		if !ok || c.MachineryVersion != "1.20.0" {
			t.Fatalf("contract = %+v, %v; want machinery 1.20.0 from the call's own comment", c, ok)
		}
	})

	t.Run("a call with no version comment falls back to the tag", func(t *testing.T) {
		t.Parallel()

		stub := "jobs:\n  ship:\n    uses: other/machinery/flows/release-it.yml@" + machineryPin40 + "\n" +
			"    with:\n      classes: oci-image\n"

		c, ok := contract(t, stub, declared)
		if !ok || c.MachineryVersion != "1.0.0" {
			t.Fatalf("contract = %+v, %v; want the tag's version", c, ok)
		}
	})

	t.Run("a stub the reader cannot parse falls back to the tag", func(t *testing.T) {
		t.Parallel()

		c, ok := contract(t, "classes: oci-image\njobs: [\n", declared)
		if !ok || c.MachineryVersion != "1.0.0" {
			t.Fatalf("contract = %+v, %v; want the tag's version", c, ok)
		}
	})

	t.Run("no evidence.publish: the adapter speaks for nothing", func(t *testing.T) {
		t.Parallel()

		if c, ok := contract(t, "jobs: {}\n", nil); ok {
			t.Fatalf("contract = %+v — an undeclared release workflow was read", c)
		}
	})

	t.Run("a reusable stub with no selfStubPath speaks for nothing", func(t *testing.T) {
		t.Parallel()

		if c, ok := contract(t, "on: workflow_call\njobs: {}\n", declared); ok {
			t.Fatalf("contract = %+v — a reusable was read as its own caller", c)
		}
	})
}

func TestPublishPolicyValidation(t *testing.T) {
	t.Parallel()

	base := `{"schema": 9, "evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",` +
		` "umbrellaBundle": "u.jsonl", "manifestAsset": "m.json", "classes": {"c": {"bundles": ["b.jsonl"]}},` +
		` "publish": %s}}`

	for _, tc := range []struct {
		name, publish, want string
	}{
		{"no stubPath", `{"stubUses": "acme/canon/"}`, "evidence.publish.stubPath is absent or empty"},
		{"empty stubUses", `{"stubPath": "s.yml", "stubUses": ""}`, "evidence.publish.stubUses is absent or empty"},
		{"stubUses naming no repository", `{"stubPath": "s.yml", "stubUses": "acme"}`, "names no owner and repository"},
		{
			"an empty selfStubPath", `{"stubPath": "s.yml", "stubUses": "acme/canon/", "selfStubPath": ""}`,
			"evidence.publish.selfStubPath is empty",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := assert.LoadPolicy(strings.NewReader(strings.Replace(base, "%s", tc.publish, 1)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadPolicy = %v, want %q", err, tc.want)
			}
		})
	}
}

// workflowFileRE is a workflow file name as a string literal would
// spell one, escaped or not: a name, then .yml or .yaml, ending there.
var workflowFileRE = regexp.MustCompile(`[A-Za-z0-9_-]\\?\.ya?ml($|[^A-Za-z0-9.])`)

// TestNoWorkflowPathIsWrittenInCode holds the engine to its own rule
// (stele#448): which workflow publishes a release is the adopter's
// declaration, so no workflow file name appears in a string literal in
// non-test Go source. Import paths are not literals in this sense.
func TestNoWorkflowPathIsWrittenInCode(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")

	var found []string

	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}

			file, perr := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return fmt.Errorf("%s: %w", path, perr)
			}

			ast.Inspect(file, func(n ast.Node) bool {
				if _, isImport := n.(*ast.ImportSpec); isImport {
					return false
				}

				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}

				value, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					value = lit.Value
				}

				if workflowFileRE.MatchString(value) {
					found = append(found, path+": "+lit.Value)
				}

				return true
			})

			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	if len(found) > 0 {
		t.Fatalf("workflow file names written in code — declare them in policy:\n%s", strings.Join(found, "\n"))
	}
}
