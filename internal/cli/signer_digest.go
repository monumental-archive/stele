// `derive signer-digest`: the commit a workflow tree pins its trusted
// signer at, derived from the `uses:` lines the platform runs
// (.github#314, stele#392). The tree states the signer once, and the
// digest every verifier pins is read off that statement — no second
// copy exists to drift. The workflow path comes from the verify
// policy's trust.provenance.signerWorkflow, so nothing org-shaped is
// written here; the reading is internal/workflow's, the one reader.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/workflow"
)

// deriveSignerDigest is the mode's name in the dispatch vocabulary.
const deriveSignerDigest = "signer-digest"

// signerDigestArgs is everything the mode reads.
type signerDigestArgs struct {
	policyPath string
	workflows  string
	workflow   string
	repo       string
}

// parseSignerDigestArgs reads the flag surface. Exactly one of --workflows
// and --workflow names the tree: a directory is a repository's whole
// workflow set, a file is the one workflow a caller is running.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseSignerDigestArgs(args []string, stderr io.Writer) (*signerDigestArgs, int) {
	sa := &signerDigestArgs{}

	fs := flag.NewFlagSet("stele derive "+deriveSignerDigest, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&sa.policyPath, "policy", "",
		"the verify policy; its trust.provenance.signerWorkflow names the workflow whose pin is derived (required)")
	fs.StringVar(&sa.workflows, "workflows", "",
		"a workflows directory: every .yml and .yaml file in it is read (one of --workflows, --workflow)")
	fs.StringVar(&sa.workflow, "workflow", "",
		"one workflow file — the calling workflow's own text (one of --workflows, --workflow)")
	fs.StringVar(&sa.repo, "repo", "",
		"owner/repo the policy's {owner} and {repo} expand to; required when the signer workflow is templated")

	if err := fs.Parse(args); err != nil {
		return nil, exitUsage
	}

	var refusal error

	switch {
	case sa.policyPath == "":
		refusal = errors.New("--policy is required")
	case sa.workflows != "" && sa.workflow != "":
		refusal = errors.New("--workflows and --workflow are exclusive — one names the tree")
	case sa.workflows == "" && sa.workflow == "":
		refusal = errors.New("one of --workflows or --workflow is required")
	}

	if refusal != nil {
		if _, err := fmt.Fprintf(stderr, "stele derive %s: %v\n", deriveSignerDigest, refusal); err != nil {
			return nil, exitIO
		}

		return nil, exitUsage
	}

	return sa, exitOK
}

// runDeriveSignerDigest derives the pin and prints it alone, so a
// caller reads the value with nothing to strip; what it was derived
// from goes to the log.
func runDeriveSignerDigest(sa *signerDigestArgs, doc io.Writer, out *latch) error {
	target, err := signerWorkflow(sa.policyPath, sa.repo)
	if err != nil {
		return err
	}

	files, subject, err := sa.tree()
	if err != nil {
		return err
	}

	pin, err := workflow.PinnedCommit(files, target, subject)
	if err != nil {
		return fmt.Errorf("derive %s: %w", deriveSignerDigest, err)
	}

	out.logf("derive %s: %s pins %s at %s", deriveSignerDigest, subject, target, pin)

	if _, err := fmt.Fprintln(doc, pin); err != nil {
		out.err = err
	}

	return nil
}

// signerWorkflow reads the policy's signer workflow, expanded for the
// repository when the policy states it as a role.
func signerWorkflow(path, repo string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is the --policy flag; reading it is the feature
	if err != nil {
		return "", fmt.Errorf("derive %s: %w", deriveSignerDigest, err)
	}
	defer f.Close() //nolint:errcheck // read-only close

	p, err := policy.Load(f)
	if err != nil {
		return "", fmt.Errorf("derive %s: %w", deriveSignerDigest, err)
	}

	target, err := expandSigner(p, repo)
	if err != nil {
		return "", fmt.Errorf("derive %s: %w", deriveSignerDigest, err)
	}

	return target, nil
}

// expandSigner is the policy's signer workflow for one repository: a
// role ({owner}/{repo}/...) names that repository's own workflow. One
// expansion, shared by every leg that derives the signer's pin.
func expandSigner(p *policy.Policy, repo string) (string, error) {
	target := *p.Trust.Provenance.SignerWorkflow
	if !strings.Contains(target, "{") {
		return target, nil
	}

	owner, name, ok := strings.Cut(repo, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", fmt.Errorf("the policy's signer workflow %q is a role, so --repo owner/repo must say whose", target)
	}

	return strings.NewReplacer("{owner}", owner, "{repo}", name).Replace(target), nil
}

// tree reads the named workflows and says what they are, for the
// refusals to open with.
func (sa *signerDigestArgs) tree() ([]workflow.File, string, error) {
	if sa.workflow != "" {
		content, err := os.ReadFile(sa.workflow)
		if err != nil {
			return nil, "", fmt.Errorf("derive %s: %w", deriveSignerDigest, err)
		}

		return []workflow.File{{Name: filepath.Base(sa.workflow), Content: content}}, sa.workflow, nil
	}

	files, err := readWorkflowDir(sa.workflows)
	if err != nil {
		return nil, "", fmt.Errorf("derive %s: %w", deriveSignerDigest, err)
	}

	return files, sa.workflows, nil
}

// readWorkflowDir reads a workflows directory. The platform keeps a
// repository's workflows in one flat directory, so the set is that
// directory's YAML files and nothing beneath it — in name order, which
// ReadDir already gives.
func readWorkflowDir(dir string) ([]workflow.File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading the workflows: %w", err)
	}

	var files []workflow.File

	for _, e := range entries {
		ext := filepath.Ext(e.Name())
		if !e.Type().IsRegular() || (ext != ".yml" && ext != ".yaml") {
			continue
		}

		//nolint:gosec // G304: the directory is the caller's flag; reading its workflows is the feature
		content, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", e.Name(), err)
		}

		files = append(files, workflow.File{Name: e.Name(), Content: content})
	}

	return files, nil
}
