// emit's input resolution (stele#392, stele#472): what the canon's
// verdict steps resolved in shell before they called this binary,
// resolved here so each step is one call. Every input keeps its
// explicit form; each alternative here is exclusive with it, so one
// fact is stated once:
//
//   - --policy-ref (with --policy-repo and --policy-tree) instead of
//     --machinery-digest and --policy-uri: the ref the caller pinned,
//     resolved to its commit through the forge. Both verdict modes —
//     `emit vsa` and `emit source-vsa` — take it, through the one
//     policyPin below;
//   - --signer-workflows instead of --signer-digest: the pin derived
//     from the tree's own uses: lines (derive signer-digest's rule);
//   - --sbom-assets instead of --sboms: the release's own SBOM assets,
//     downloaded and hashed into the manifest;
//   - --inventory-plan instead of --inventories: the planned inventory
//     NAMES, filtered from those assets by exact name.
//
// Nothing here renders or judges a verdict: it fills emitArgs, and the
// verification that follows is unchanged.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/verify"
	"github.com/monumental-archive/stele/internal/workflow"
)

// resolveCommit is the forge's ref resolution, swapped only by tests.
//
//nolint:gochecknoglobals // test seam, written only by test setup
var resolveCommit = func(owner, repo, ref string) (string, bool, error) {
	return gh.New(forgeToken()).CommitSHA(owner, repo, ref)
}

// policyPin is the policy pin's alternative form: the ref the caller
// pinned, resolved to the commit a verdict names as its policy digest,
// and the URI of the policy document at that commit. One type, so the
// two verdict modes that take it run one implementation (stele#472).
type policyPin struct {
	ref, repo, tree string

	// resolved by load, consumed by resolve
	rel string
}

// register adds the policy-ref alternative to a verdict mode's flags.
func (p *policyPin) register(fs *flag.FlagSet) {
	fs.StringVar(&p.ref, "policy-ref", "",
		"the ref the policy tree is pinned at, resolved to its commit — the machinery digest, and the commit the"+
			" policy URI names (instead of --machinery-digest and --policy-uri; needs --policy-repo, --policy-tree)")
	fs.StringVar(&p.repo, "policy-repo", "", "owner/repo the policy tree is (with --policy-ref)")
	fs.StringVar(&p.tree, "policy-tree", "", "the checkout the policy is read from (with --policy-ref)")
}

// vsaInputs is emit vsa's own alternative inputs — the release's SBOMs,
// the inventory plan and the signer pin, which only that mode reads —
// and what they resolve to.
type vsaInputs struct {
	signerWorkflows string
	sbomSuffix      string
	inventoryPlan   string

	// resolved by load, consumed by resolve
	planned []string
}

// register adds the alternatives to emit vsa's flag set.
func (v *vsaInputs) register(fs *flag.FlagSet) {
	fs.StringVar(&v.signerWorkflows, "signer-workflows", "",
		"a workflows directory the signer digest is derived from, as derive signer-digest does"+
			" (instead of --signer-digest)")
	fs.StringVar(&v.sbomSuffix, "sbom-assets", "",
		"read the release's own assets ending in this suffix as the SBOM manifest (instead of --sboms)")
	fs.StringVar(&v.inventoryPlan, "inventory-plan", "",
		`the planned inventory names as a JSON array, filtered from the SBOM manifest; [] or [""] declares no`+
			" plan (instead of --inventories)")
}

// load holds the alternatives to their explicit forms and does every
// offline resolution: the signer pin from the tree, the policy's path
// in its tree, the plan's names. Called from loadVSA, so a refusal here
// is a usage refusal, before anything networks.
func (v *vsaInputs) load(ea *emitArgs) error {
	if !verify.PlausibleTag(ea.tag) {
		return fmt.Errorf("--tag %q is not a plausible release tag", ea.tag)
	}

	if err := ea.pin.load(ea); err != nil {
		return err
	}

	if err := v.loadSigner(ea); err != nil {
		return err
	}

	if ea.inventories != "" && v.inventoryPlan != "" {
		return errors.New("--inventories and --inventory-plan are exclusive — the plan is stated once")
	}

	if v.inventoryPlan == "" {
		return nil
	}

	names, err := jsonx.DecodeBytes[[]string]([]byte(v.inventoryPlan))
	if err != nil {
		return errors.New("--inventory-plan is not a JSON array of inventory names")
	}

	for _, n := range *names {
		if n != "" {
			v.planned = append(v.planned, n)
		}
	}

	return nil
}

// load holds the policy pin: either the explicit commit, or the ref to
// resolve with what names the policy at it. Offline, so a refusal here
// is a usage refusal, before anything networks.
func (p *policyPin) load(ea *emitArgs) error {
	if p.ref == "" {
		if !commitRE.MatchString(ea.machineryPin) {
			return fmt.Errorf("--machinery-digest %q is not a commit, and no --policy-ref names one — "+
				"refusing a verdict with no policy", ea.machineryPin)
		}

		return nil
	}

	if ea.machineryPin != "" || ea.policyURI != "" {
		return errors.New("--policy-ref resolves the machinery digest and the policy URI — " +
			"--machinery-digest and --policy-uri cannot accompany it")
	}

	if owner, repo, ok := strings.Cut(p.repo, "/"); !ok || owner == "" || repo == "" {
		return errors.New("--policy-ref needs --policy-repo owner/repo: the repository the ref is resolved in")
	}

	rel, err := policyPathInTree(p.tree, ea.policyPath)
	if err != nil {
		return err
	}

	p.rel = rel

	return nil
}

// loadSigner derives the signer pin from the tree when asked to.
func (v *vsaInputs) loadSigner(ea *emitArgs) error {
	if v.signerWorkflows == "" {
		return nil
	}

	if ea.signerPin != "" {
		return errors.New("--signer-digest and --signer-workflows are exclusive — the pin is stated once")
	}

	target, err := expandSigner(ea.p, ea.repo)
	if err != nil {
		return err
	}

	files, err := readWorkflowDir(v.signerWorkflows)
	if err != nil {
		return err
	}

	pin, err := workflow.PinnedCommit(files, target, v.signerWorkflows)
	if err != nil {
		return fmt.Errorf("deriving the signer digest: %w", err)
	}

	ea.signerPin = pin

	return nil
}

// sbomsRequired is the refusal for a run naming no SBOM manifest.
const sbomsRequired = "--sboms is required unless --sbom-assets names the release's own SBOM assets"

// resolve does what needs the forge: the ref's commit, the release's
// SBOM assets, and the plan filtered from them. A refusal here is the
// run's (exit 1): the inputs were well-formed and the forge's answer
// would not do.
func (v *vsaInputs) resolve(ea *emitArgs, log func(format string, args ...any)) error {
	if err := ea.pin.resolve(ea, log); err != nil {
		return err
	}

	if v.sbomSuffix != "" {
		if err := v.resolveSBOMs(ea, log); err != nil {
			return err
		}
	}

	if v.planned == nil {
		return nil
	}

	for _, want := range v.planned {
		i := slices.IndexFunc(ea.sbomList, func(s verify.Subject) bool { return s.Name == want })
		if i < 0 {
			return fmt.Errorf("emit: the plan names %s but the release publishes no such inventory", want)
		}

		ea.inventoryList = append(ea.inventoryList, ea.sbomList[i])
	}

	log("emit: planned inventories: %d", len(ea.inventoryList))

	return nil
}

// resolve turns the ref, when one was given, into the commit the
// verdict names, and names the policy document at that commit. No ref,
// nothing to resolve: the explicit pin stands.
func (p *policyPin) resolve(ea *emitArgs, log func(format string, args ...any)) error {
	if p.ref == "" {
		return nil
	}

	owner, repo, _ := strings.Cut(p.repo, "/")

	commit := p.ref
	if !commitRE.MatchString(commit) {
		sha, ok, err := resolveCommit(owner, repo, p.ref)

		switch {
		case err != nil:
			return fmt.Errorf("emit: could not resolve the policy ref %s to a commit: %w", p.ref, err)
		case !ok:
			return fmt.Errorf("emit: could not resolve the policy ref %s to a commit: %s has no such ref",
				p.ref, p.repo)
		case !commitRE.MatchString(sha):
			return fmt.Errorf("emit: could not resolve the policy ref %s to a commit: the forge answered %q",
				p.ref, sha)
		}

		commit = sha
	}

	ea.machineryPin = commit
	ea.policyURI = gh.New("").BlobURL(owner, repo, commit, p.rel)

	log("emit: policy ref %s is commit %s", p.ref, commit)

	return nil
}

// resolveSBOMs reads the release's SBOM assets into the manifest the
// decision is selected from, in name order — which one carries the
// decision is the verification's by-attestation selection, never a
// guess made here.
func (v *vsaInputs) resolveSBOMs(ea *emitArgs, log func(format string, args ...any)) error {
	forge := newForge()

	names, err := forge.ReleaseAssets(ea.coords.Owner, ea.coords.Repo, ea.tag)
	if err != nil {
		return fmt.Errorf("emit: listing the release's assets: %w", err)
	}

	slices.Sort(names)

	for _, name := range names {
		if !strings.HasSuffix(name, v.sbomSuffix) {
			continue
		}

		content, err := forge.Asset(ea.coords.Owner, ea.coords.Repo, ea.tag, name)
		if err != nil {
			return fmt.Errorf("emit: downloading %s: %w", name, err)
		}

		ea.sbomList = append(ea.sbomList, verify.Subject{Name: name, SHA256: chain.SHA256Hex(content)})
	}

	if len(ea.sbomList) == 0 {
		return errors.New("emit: the release has no SBOM asset — the decision has no subject to verify against")
	}

	log("emit: %d SBOM asset(s) read from the release", len(ea.sbomList))

	return nil
}
