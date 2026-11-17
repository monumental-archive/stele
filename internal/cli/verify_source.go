// `stele verify source-vsa` (stele#391): the single-release read of a
// published source verdict. The verdict is a release asset — its
// subject is a commit, which the attestation store's sha256-keyed
// lookup cannot address — so it is fetched from the release named by
// --repo/--tag through the forge's asset read, and held against the
// tag's commit and that commit's chain link in the clone, as they
// stand now. Epoch-free: whether a release OWES one is the corpus
// walk's question (`assert evidence`).

package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/verify"
)

// registerSourceVSAFlags adds the source-vsa mode's inputs.
func registerSourceVSAFlags(fs *flag.FlagSet, va *verifyArgs) {
	fs.StringVar(&va.tag, "tag", "", "release tag (required)")
	fs.StringVar(&va.gitDir, "git-dir", "",
		"local clone with the protected branches, the notes ref and the tag fetched (required)")
	fs.StringVar(&va.assertPolicy, "assert-policy", "",
		"path to the committed assert policy: evidence.sourceVerdictBundle names the asset (required)")
	fs.StringVar(&va.machineryPin, "machinery-digest", "",
		"commit digest the verdict identity is pinned at (required)")
}

// loadSourceVSA reads the mode's file inputs.
func (va *verifyArgs) loadSourceVSA() error {
	switch {
	case va.tag == "":
		return errors.New("--tag is required")
	case va.gitDir == "":
		return errors.New("--git-dir is required")
	case va.assertPolicy == "":
		return errors.New("--assert-policy is required: it names the asset the verdict is published as")
	}

	ap, err := loadAssertPolicyFile(va.assertPolicy)
	if err != nil {
		return err
	}

	if ap.Evidence.SourceVerdictBundle == nil {
		return errors.New("the assert policy declares no evidence.sourceVerdictBundle — " +
			"there is no asset a source verdict is published as")
	}

	va.sourceAsset = *ap.Evidence.SourceVerdictBundle

	return nil
}

// loadAssertPolicyFile reads one committed assert policy — the load the
// verify modes that read the publisher's assert policy share.
func loadAssertPolicyFile(path string) (*assert.Policy, error) {
	f, err := os.Open(path) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return nil, err //nolint:wrapcheck // the refusal names the path already
	}
	defer f.Close() //nolint:errcheck // read-only close

	ap, err := assert.LoadPolicy(f)
	if err != nil {
		return nil, fmt.Errorf("assert policy: %w", err)
	}

	return ap, nil
}

// runSourceVSA fetches the verdict asset and runs the one read.
func runSourceVSA(va *verifyArgs, out *latch) (*verifyOutcome, error) {
	if va.p.Source == nil {
		return nil, errors.New("verify: the verify policy declares no source section — " +
			"a source verdict names its resource")
	}

	envelope, err := newForge().Asset(va.coords.Owner, va.coords.Repo, va.tag, va.sourceAsset)
	if err != nil {
		return nil, fmt.Errorf("verify: source verdict asset %s of %s@%s: %w",
			va.sourceAsset, va.coords.Slug(), va.tag, err)
	}

	g, err := openSourceGit(va.gitDir, *va.p.Source.NotesRef)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}

	pins := verify.Pins{Machinery: va.machineryPin}

	verdict, err := readSourceVerdict(va.p, va.coords, pins, g, envelope, va.bv, out.logf)
	if err != nil {
		return nil, err
	}

	out.logf("verify: source verdict %s@%s: commit %s, levels %v",
		va.coords.Slug(), va.tag, verdict.Commit(), verdict.Levels())

	return &verifyOutcome{
		pop: report.PopulationFromEvidence(1, "release tag"),
		facts: []report.Fact{
			{Name: factSourceRevision, Value: verdict.Commit()},
			{Name: "verifiedLevels", Value: strings.Join(verdict.Levels(), " ")},
		},
	}, nil
}

// factSourceRevision names the commit a verify mode proved — one
// spelling for every mode that reports it.
const factSourceRevision = "sourceRevision"
