// `emit enrichment` through Run: the canon shell's invocation shape end
// to end, every refusal of the input before a byte is read (usage, the
// message asserted), the engine's refusals (exit 1), and the streams.
// The released source is a forge snapshot; the policy tree is a
// directory, as the caller's checkout is.

package cli

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/enrichment"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
)

const (
	enrSource    = "1111111111111111111111111111111111111111"
	enrMachinery = "2222222222222222222222222222222222222222"
)

// enrPolicy is a verify policy owing the canon's enrichment names.
func enrPolicy(build bool) string {
	doc := fmt.Sprintf(`{"schema": %d, "issuer": "https://token.example.com",
	  "trust": {"provenance": {"signerWorkflow": "acme/signer/.github/workflows/sign.yml"},
	    "verdict": {"verifierWorkflow": "acme/canon/.github/workflows/verify-release.yml"}}`, policy.Schema)

	if build {
		doc += `, "build": {
	    "buildTypes": {"https://actions.github.io/buildtypes/workflow/v1": {"externalParameterKeys": ["workflow"]}},
	    "resourceUri": "pkg:github/{owner}/{repo}@v{version}",
	    "sourceRepository": "https://github.com/{owner}/{repo}",
	    "targetLevel": "SLSA_BUILD_LEVEL_3", "denySelfHostedRunners": true,
	    "enrichment": {"predicateType": "https://acme.example/build-enrichment/v2",
	      "required": ["toolbelt-lock"],
	      "permitted": ["pgrx-base-images", "pgrx-base", "Cargo.lock", "package-lock.json", "mise.toml"]}}`
	}

	return doc + "}"
}

// enrWorld lays out a policy tree and a forge snapshot of the source.
type enrWorld struct {
	tree, policy, snap string
}

func newEnrWorld(t *testing.T) *enrWorld {
	t.Helper()

	dir := t.TempDir()
	files := filepath.Join("snap", "acme", "widget", "files", enrSource)

	writeTree(t, dir, map[string]string{
		"canon/slsa/verify-policy.json": enrPolicy(true),
		"canon/slsa/no-build.json":      enrPolicy(false),
		"canon/mise/mise.lock":          "lock",
		"canon/docker/pgrx-base-images.toml": "[build]\n\"14\" = \"postgres:14@sha256:aa\"\n" +
			"[smoke]\n\"14\" = \"postgres:14-t@sha256:bb\"\n",
		"outside.json":                         enrPolicy(true),
		"canon/slsa/broken.json":               `{"schema": 1}`,
		filepath.Join(files, "Cargo.lock"):     "cargo",
		filepath.Join(files, "mise.toml", "x"): "a directory where the file is: the forge read fails",
	})

	swapForge(t, gh.Snapshot{Dir: filepath.Join(dir, "snap")})

	return &enrWorld{
		tree:   filepath.Join(dir, "canon"),
		policy: filepath.Join(dir, "canon", "slsa", "verify-policy.json"),
		snap:   filepath.Join(dir, "snap"),
	}
}

// args is the canon's invocation, the org's name-to-file mapping
// spelled out where it belongs: in the caller.
func (w *enrWorld) args(extra ...string) []string {
	return append([]string{
		"emit", "enrichment",
		"--policy", w.policy, "--policy-tree", w.tree, "--policy-repo", "acme/canon",
		"--machinery-digest", enrMachinery,
		"--repo", "acme/widget", "--tag", "v1.0.0", "--source-revision", enrSource,
		"--file", "toolbelt-lock=policy:mise/mise.lock",
		"--rows", "pgrx-base=policy:docker/pgrx-base-images.toml",
		"--rows-tables", "pgrx-base=build,smoke",
		"--rows-prefix", "pgrx-base=oci://docker.io/library/",
		"--rows-file", "pgrx-base=pgrx-base-images",
		"--rows-keys", "pgrx-base=14",
		"--file", "Cargo.lock=source:Cargo.lock",
		"--file", "package-lock.json=source:package-lock.json",
	}, extra...)
}

// with is the canon invocation with one flag's value replaced.
func (w *enrWorld) with(flag, value string) []string {
	args := w.args()
	for i := range args {
		if args[i] == flag {
			args[i+1] = value

			break
		}
	}

	return args
}

func sha256Of(b []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func TestEmitEnrichment(t *testing.T) {
	w := newEnrWorld(t)

	var stdout, stderr bytes.Buffer
	if code := Run(w.args(), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d\nstderr: %s", code, stderr.String())
	}

	pred, err := jsonx.DecodeBytes[enrichment.Predicate](stdout.Bytes())
	if err != nil {
		t.Fatalf("stdout is not one predicate: %v\n%s", err, stdout.String())
	}

	if verr := pred.Validate(); verr != nil {
		t.Fatalf("the emitted predicate does not validate: %v", verr)
	}

	policyBytes, err := os.ReadFile(w.policy)
	if err != nil {
		t.Fatal(err)
	}

	checks := map[string][2]string{
		"resourceUri": {*pred.ResourceURI, "pkg:github/acme/widget@v1.0.0"},
		"sourceRevision": {
			*pred.SourceRevision.URI + "@" + pred.Revision(),
			"https://github.com/acme/widget@" + enrSource,
		},
		"policy.uri": {
			*pred.Policy.URI,
			"https://github.com/acme/canon/blob/" + enrMachinery + "/slsa/verify-policy.json",
		},
		"policy.sha256":    {pred.Policy.Digest["sha256"], sha256Of(policyBytes)},
		"policy.gitCommit": {pred.Policy.Digest["gitCommit"], enrMachinery},
		"names": {
			strings.Join(pred.Names(), ","),
			"toolbelt-lock,pgrx-base-images,pgrx-base,pgrx-base,Cargo.lock",
		},
		"toolbelt-lock.uri": {
			*pred.ResolvedDependencies[0].URI,
			"https://github.com/acme/canon/blob/" + enrMachinery + "/mise/mise.lock",
		},
		"row.uri": {*pred.ResolvedDependencies[2].URI, "oci://docker.io/library/postgres:14@sha256:aa"},
		"Cargo.lock.uri": {
			*pred.ResolvedDependencies[4].URI,
			"https://raw.githubusercontent.com/acme/widget/" + enrSource + "/Cargo.lock",
		},
	}

	for what, pair := range checks {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", what, pair[0], pair[1])
		}
	}

	if !strings.Contains(stderr.String(), "emit: enrichment: 5 resolved dependencies") {
		t.Errorf("the account did not reach stderr: %q", stderr.String())
	}

	// --out writes the document and moves the account to stdout.
	out := filepath.Join(t.TempDir(), "enrichment.json")

	stdout.Reset()
	stderr.Reset()

	if code := Run(w.args("--out", out), &stdout, &stderr); code != exitOK {
		t.Fatalf("--out exit %d: %s", code, stderr.String())
	}

	written, rerr := os.ReadFile(out) //nolint:gosec // the test's own file
	if rerr != nil || !strings.Contains(string(written), `"toolbelt-lock"`) {
		t.Fatalf("--out wrote %q, %v", written, rerr)
	}
}

func TestEmitEnrichmentInputRefusals(t *testing.T) {
	w := newEnrWorld(t)

	replace := w.with

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no policy", replace("--policy", ""), "--policy is required"},
		{"a repository that is no owner/repo", replace("--repo", "widget"), "--repo must be owner/repo"},
		{"an implausible tag", replace("--tag", "1.0.0 rc"), `--tag "1.0.0 rc" is not a plausible release tag`},
		{
			"a source revision that is no commit — the verdict step's 'stated no source revision'",
			replace("--source-revision", "main"),
			`--source-revision "main" is not a commit — enrichment unbound to a revision would claim nothing`,
		},
		{
			"a machinery digest that is no commit — 'stated no resolved policy pin'",
			replace("--machinery-digest", ""),
			`--machinery-digest "" is not a commit — enrichment cannot name its policy`,
		},
		{
			"a policy repository that is no owner/repo", replace("--policy-repo", "canon"),
			"--policy-repo must be owner/repo",
		},
		{"no policy tree", replace("--policy-tree", ""), "--policy-tree is required"},
		{
			"a policy outside its tree",
			replace("--policy", filepath.Join(filepath.Dir(w.tree), "outside.json")),
			"is not inside --policy-tree",
		},
		{"an unreadable policy", replace("--policy", filepath.Join(w.tree, "slsa", "absent.json")), "absent.json"},
		{"a policy the loader refuses", replace("--policy", filepath.Join(w.tree, "slsa", "broken.json")), "policy:"},
		{
			"a policy with no build section",
			replace("--policy", filepath.Join(w.tree, "slsa", "no-build.json")),
			"the policy declares no build section",
		},
		{"a source that is no name=tree:path", w.args("--file", "go.sum"), `--file "go.sum" is not <name>=<tree>:<path>`},
		{"an unknown tree", w.args("--file", "x=cache:x"), `--file "x=cache:x": the tree is policy or source`},
		{
			"a path that leaves its tree",
			w.args("--rows", "x=policy:../x.toml"),
			`--rows "x=policy:../x.toml": the path must be clean and stay inside its tree`,
		},
		{"an absolute path", w.args("--file", "x=source:/etc/x"), "the path must be clean"},
		{
			"a row parameter no --rows declares", w.args("--rows-prefix", "other=x"),
			"--rows-prefix names other, which no --rows declares",
		},
		{
			"rows with no tables", w.args("--rows", "r=policy:r.toml", "--rows-prefix", "r=x"),
			"--rows r declares no --rows-tables",
		},
		{
			"rows with no prefix", w.args("--rows", "r=policy:r.toml", "--rows-tables", "r=t"),
			"--rows r declares no --rows-prefix",
		},
		{
			"keys that are no keys — base-majors' 'comma-separated majors'",
			replace("--rows-keys", "pgrx-base=14;16"),
			`--rows-keys pgrx-base must be comma-separated keys, got: "14;16"`,
		},
		{"a keyed flag with no name", w.args("--rows-file", "=x"), `--rows-file "=x" is not <name>=<value>`},
		{"a keyed flag twice", w.args("--rows-keys", "pgrx-base=16"), "--rows-keys names pgrx-base twice"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := Run(tt.args, &stdout, &stderr)
			if code != exitUsage {
				t.Fatalf("exit %d, want %d\nstderr: %s", code, exitUsage, stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr.String(), tt.want)
			}

			if stdout.Len() != 0 {
				t.Fatalf("a refused input printed %q", stdout.String())
			}
		})
	}
}

func TestEmitEnrichmentRefusals(t *testing.T) {
	w := newEnrWorld(t)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			// stele#392 Done when: an enrichment name the policy does
			// not permit, refused.
			"a name the policy does not permit",
			w.args("--file", "go.sum=source:go.sum"),
			`emit: a source names "go.sum", which the policy neither requires nor permits — the declared set is closed`,
		},
		{
			"a source tree the forge cannot read",
			w.args("--file", "mise.toml=source:mise.toml"),
			"emit: enrichment: mise.toml: reading mise.toml from the source tree: the forge: gh: snapshot file",
		},
		{
			"a declared base key the pinned mapping lacks — 'the declaration cannot be honoured'",
			w.with("--rows-keys", "pgrx-base=14,99"),
			"declared key 99 has no build row in docker/pgrx-base-images.toml — the declaration cannot be honoured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := Run(tt.args, &stdout, &stderr)
			if code != exitRefused {
				t.Fatalf("exit %d, want %d\nstderr: %s", code, exitRefused, stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr.String(), tt.want)
			}
		})
	}

	var stderr bytes.Buffer
	if code := Run(append(w.args(), "--bogus"), &bytes.Buffer{}, &stderr); code != exitUsage {
		t.Fatalf("an unknown flag exited %d", code)
	}

	if code := Run(w.args(), failWriterI{}, &bytes.Buffer{}); code != exitIO {
		t.Fatalf("a broken document stream exited %d, want %d", code, exitIO)
	}

	if code := Run(w.args("--policy", ""), &bytes.Buffer{}, failWriterI{}); code != exitIO {
		t.Fatalf("a usage refusal on a broken stderr exited %d, want %d", code, exitIO)
	}
}
