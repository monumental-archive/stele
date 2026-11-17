// emit vsa's resolved inputs (stele#392): the canon verdict step's
// shell — the ref resolved to a commit, the signer pin derived from the
// tree, the SBOM manifest read off the release, the plan filtered by
// name — driven end to end over the release world, and every refusal
// asserting its message.

package cli

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
)

const (
	policyCommit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	signerCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// vsaInputsWorld is the release world plus everything the resolved
// inputs read: the policy in its tree, a workflows directory pinning
// the signer, and the release's assets in a forge snapshot.
type vsaInputsWorld struct {
	root, subjects             string
	tree, policy, workflows    string
	twoPins, roleTree, outside string
}

func newVSAInputsWorld(t *testing.T) *vsaInputsWorld {
	t.Helper()

	w := newReleaseWorld(t)
	swap(t, w.bv, w.store)

	px := files(t)
	subjects, _ := w.manifests(t)

	dir := t.TempDir()
	role := strings.Replace(testPolicy, `"acme/signer/.github/workflows/sign.yml"`,
		`"{owner}/{repo}/.github/workflows/sign.yml"`, 1)

	writeTree(t, dir, map[string]string{
		"canon/slsa/verify-policy.json":                         testPolicy,
		"canon/slsa/role-policy.json":                           role,
		"outside.json":                                          testPolicy,
		"workflows/publish.yml":                                 signerCall(relSignerWF + "@" + signerCommit),
		"two/publish.yml":                                       signerCall(relSignerWF + "@" + signerCommit),
		"two/vex-attest.yml":                                    signerCall(relSignerWF + "@" + strings.Repeat("c", 40)),
		"snap/acme/widget/releases/v1.2.3/assets.json":          `["notes.md", "app.spdx.json", "app.tar.gz"]`,
		"snap/acme/widget/releases/v1.2.3/assets/app.spdx.json": "sbom bytes",
		"snap/acme/widget/releases/v1.2.3/assets/notes.md":      "notes",
		"snap/acme/bare/releases/v1.2.3/assets.json":            `["app.tar.gz"]`,
		"snap/acme/torn/releases/v1.2.3/assets.json":            `["app.spdx.json"]`,
	})

	swapForge(t, gh.Snapshot{Dir: filepath.Join(dir, "snap")})

	return &vsaInputsWorld{
		root: px.root, subjects: subjects,
		tree:      filepath.Join(dir, "canon"),
		policy:    filepath.Join(dir, "canon", "slsa", "verify-policy.json"),
		workflows: filepath.Join(dir, "workflows"),
		twoPins:   filepath.Join(dir, "two"),
		roleTree:  filepath.Join(dir, "canon", "slsa", "role-policy.json"),
		outside:   filepath.Join(dir, "outside.json"),
	}
}

// args is the verdict step as one call: every resolved form in use.
func (v *vsaInputsWorld) args(extra ...string) []string {
	return append([]string{
		"emit", "vsa", "--policy", v.policy, "--trusted-root", v.root,
		"--repo", "acme/widget", "--tag", relTag, "--subjects", v.subjects,
		"--policy-ref", policyCommit, "--policy-repo", "acme/canon", "--policy-tree", v.tree,
		"--signer-workflows", v.workflows,
		"--sbom-assets", ".spdx.json",
		"--inventory-plan", `["app.spdx.json"]`,
	}, extra...)
}

// without drops one flag and its value from the canonical call.
func (v *vsaInputsWorld) without(flag string, extra ...string) []string {
	args := v.args()
	for i := range args {
		if args[i] == flag {
			args = append(args[:i:i], args[i+2:]...)

			break
		}
	}

	return append(args, extra...)
}

func swapResolveCommit(t *testing.T, sha string, ok bool, err error) {
	t.Helper()

	orig := resolveCommit
	resolveCommit = func(_, _, _ string) (string, bool, error) { return sha, ok, err }

	t.Cleanup(func() { resolveCommit = orig })
}

func TestEmitVSAResolvedInputs(t *testing.T) {
	v := newVSAInputsWorld(t)

	var stdout, stderr bytes.Buffer
	if code := Run(v.args(), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	for _, want := range []string{
		`"verificationResult":"PASSED"`,
		"https://github.com/acme/canon/blob/" + policyCommit + "/slsa/verify-policy.json",
		"emit: policy ref " + policyCommit + " is commit " + policyCommit,
		"emit: 1 SBOM asset(s) read from the release",
		"emit: planned inventories: 1",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout lacks %q", want)
		}
	}
}

func TestEmitVSAResolvesAPolicyTag(t *testing.T) {
	v := newVSAInputsWorld(t)

	for _, tt := range []struct {
		name string
		sha  string
		ok   bool
		err  error
		code int
		want string
	}{
		{"a tag the forge resolves", policyCommit, true, nil, exitOK, "emit: policy ref v1.68.8 is commit " + policyCommit},
		{
			"a forge that cannot be read", "", false, errors.New("HTTP 503"), exitRefused,
			"emit: could not resolve the policy ref v1.68.8 to a commit: HTTP 503",
		},
		{
			"a ref the repository does not have", "", false, nil, exitRefused,
			"emit: could not resolve the policy ref v1.68.8 to a commit: acme/canon has no such ref",
		},
		{
			"an answer that is no commit", "main", true, nil, exitRefused,
			`emit: could not resolve the policy ref v1.68.8 to a commit: the forge answered "main"`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			swapResolveCommit(t, tt.sha, tt.ok, tt.err)

			args := v.without("--policy-ref", "--policy-ref", "v1.68.8")

			var stdout, stderr bytes.Buffer
			if code := Run(args, &stdout, &stderr); code != tt.code {
				t.Fatalf("exit %d, want %d\nstderr: %s", code, tt.code, stderr.String())
			}

			if !strings.Contains(stdout.String()+stderr.String(), tt.want) {
				t.Fatalf("output lacks %q\nstdout: %s\nstderr: %s", tt.want, stdout.String(), stderr.String())
			}
		})
	}
}

func TestEmitVSAInputRefusals(t *testing.T) {
	v := newVSAInputsWorld(t)

	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{
			"both SBOM manifests", v.args("--sboms", v.subjects), exitUsage,
			"--sboms and --sbom-assets are exclusive — the SBOM manifest is stated once",
		},
		{
			"no SBOM manifest at all", v.without("--sbom-assets"), exitUsage,
			"--sboms is required unless --sbom-assets names the release's own SBOM assets",
		},
		{
			"both plans", v.args("--inventories", v.subjects), exitUsage,
			"--inventories and --inventory-plan are exclusive — the plan is stated once",
		},
		{
			"a plan that is no list of names", v.without("--inventory-plan", "--inventory-plan", `{"a": 1}`),
			exitUsage, "--inventory-plan is not a JSON array of inventory names",
		},
		{
			"an implausible tag — the version check the step made", v.without("--tag", "--tag", "1.2.3; true"),
			exitUsage, `--tag "1.2.3; true" is not a plausible release tag`,
		},
		{
			"no policy pin at all — 'refusing a verdict with no policy'", v.without("--policy-ref"), exitUsage,
			`--machinery-digest "" is not a commit, and no --policy-ref names one — refusing a verdict with no policy`,
		},
		{
			"a ref beside an explicit digest", v.args("--machinery-digest", policyCommit), exitUsage,
			"--policy-ref resolves the machinery digest and the policy URI — --machinery-digest and --policy-uri" +
				" cannot accompany it",
		},
		{
			"a ref with no repository to resolve it in", v.without("--policy-repo"), exitUsage,
			"--policy-ref needs --policy-repo owner/repo",
		},
		{"a ref with no tree", v.without("--policy-tree"), exitUsage, "--policy-tree is required"},
		{
			"a policy outside its tree", v.without("--policy", "--policy", v.outside), exitUsage,
			"is not inside --policy-tree",
		},
		{
			"a pin both derived and stated", v.args("--signer-digest", signerCommit), exitUsage,
			"--signer-digest and --signer-workflows are exclusive — the pin is stated once",
		},
		{
			"a workflows directory that cannot be read", v.without("--signer-workflows", "--signer-workflows",
				filepath.Join(v.tree, "absent")), exitUsage, "reading the workflows: open",
		},
		{
			"a tree pinning the signer twice — the #314 refusal", v.without("--signer-workflows",
				"--signer-workflows", v.twoPins), exitUsage,
			"deriving the signer digest: " + v.twoPins + " pins sign.yml at more than one digest — a tree states" +
				" the trusted signer once",
		},
		{
			"a role-shaped signer and a repository that names no one",
			append(v.without("--policy", "--policy", v.roleTree), "--repo", "acme/widget/extra"), exitUsage,
			"is a role, so --repo owner/repo must say whose",
		},
		{
			"a release whose assets cannot be listed", v.without("--repo", "--repo", "acme/absent"), exitRefused,
			"emit: listing the release's assets:",
		},
		{
			"a listed SBOM that cannot be downloaded", v.without("--repo", "--repo", "acme/torn"), exitRefused,
			"emit: downloading app.spdx.json:",
		},
		{
			"a release with no SBOM asset", v.without("--repo", "--repo", "acme/bare"), exitRefused,
			"emit: the release has no SBOM asset — the decision has no subject to verify against",
		},
		{
			"a plan naming an inventory the release does not publish",
			v.without("--inventory-plan", "--inventory-plan", `["app.spdx.json", "lib.spdx.json"]`), exitRefused,
			"emit: the plan names lib.spdx.json but the release publishes no such inventory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := Run(tt.args, &stdout, &stderr)
			if code != tt.code {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, tt.code, stdout.String(), stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr.String(), tt.want)
			}
		})
	}
}

// TestEmitVSAEmptyPlanIsNoPlan holds the shell's reading of the plan:
// [] and [""] declare no plan, and the whole-release invariant judges.
func TestEmitVSAEmptyPlanIsNoPlan(t *testing.T) {
	v := newVSAInputsWorld(t)

	for _, plan := range []string{`[]`, `[""]`} {
		var stdout, stderr bytes.Buffer

		code := Run(v.without("--inventory-plan", "--inventory-plan", plan), &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("plan %s: exit %d\nstderr: %s", plan, code, stderr.String())
		}

		if strings.Contains(stdout.String(), "planned inventories") {
			t.Fatalf("plan %s was read as a plan:\n%s", plan, stdout.String())
		}
	}
}
