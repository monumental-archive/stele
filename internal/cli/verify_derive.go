// The derived inputs of `verify release` and `verify vsa` (stele#447):
// a published release verified from what a consumer knows — the
// repository, the tag and the policies. The signing pins and the
// release's own statement of what it shipped are read by the ONE
// derivation the deep corpus walk uses (assert.PinRoots.Resolve,
// assert.EvidencePolicy.DeriveRelease), never a copy of it. A flag
// that is given is used exactly as it always was; only an absent one
// is derived, and every derived value is printed, so a run states what
// it verified against.

package cli

import (
	"fmt"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/gitfetch"
)

// newPinTags builds the tag resolver pins resolve through: the same
// git session the deep walk reads tags with (stele#384), checked and
// fetched only if a pin needs a tag's commit — the two-hop topology
// never does. The returned func removes what it fetched. Swappable in
// tests.
//
//nolint:gochecknoglobals // test seam, written only by test setup
var newPinTags = func(log func(string, ...any)) (assert.TagResolver, func() error) {
	s := newGitSession(gitfetch.Want{Tags: true, Shallow: true}, log)

	return &checkedTags{s: s}, s.Close
}

// checkedTags checks the machine's git on first use, the refusal
// openFullDepth makes up front, made here only when it is needed.
type checkedTags struct {
	s       *gitfetch.Session
	checked bool
}

func (c *checkedTags) TagCommit(owner, repo, tag string) (string, error) {
	if !c.checked {
		if err := c.s.Check(); err != nil {
			return "", err
		}

		c.checked = true
	}

	return c.s.TagCommit(owner, repo, tag)
}

// contractSources is the one composition of where a release's
// evidence contract is read from — the walk's and the verb's.
func contractSources(ev *assert.EvidencePolicy, forge gh.Forge) assert.Sources {
	return assert.Sources{
		assert.ManifestSource{Forge: forge, Policy: ev, Asset: *ev.ManifestAsset},
		assert.WorkflowSource{Forge: forge, Policy: ev},
	}
}

// subjectsDerived and sbomsDerived report which inputs the run reads
// from the release rather than from a flag.
func (va *verifyArgs) subjectsDerived() bool { return va.subjects == "" }

func (va *verifyArgs) sbomsDerived() bool { return va.mode == modeRelease && va.sboms == "" }

// loadEvidencePolicy reads the publisher's assert policy, whose
// evidence section says where a release states what it shipped. The
// section is one the loader itself requires, so a policy without it
// never reaches here.
func (va *verifyArgs) loadEvidencePolicy() error {
	ap, err := loadAssertPolicyFile(va.assertPolicy)
	if err != nil {
		return err
	}

	va.evidence = ap.Evidence

	return nil
}

// derive fills every absent input of a release or vsa run from the
// release itself, printing each value it derived.
func (va *verifyArgs) derive(out *latch) error {
	forge := newForge()
	slug := va.coords.Slug() + "@" + va.tag

	if va.signerPin == "" || va.machineryPin == "" {
		if err := va.derivePins(forge, out); err != nil {
			return fmt.Errorf("verify: the signing pins of %s: %w", slug, err)
		}
	}

	if !va.subjectsDerived() && !va.sbomsDerived() {
		return nil
	}

	logf := func(format string, args ...any) { out.logf("verify: "+format, args...) }

	in, err := va.evidence.DeriveRelease(
		forge, contractSources(va.evidence, forge), va.coords.Owner, va.coords.Repo, va.tag, logf,
	)
	if err != nil {
		return fmt.Errorf("verify: what %s shipped: %w", slug, err)
	}

	if va.subjectsDerived() {
		va.subjectList = in.Subjects
		for _, s := range va.subjectList {
			out.logf("verify: derived subject %s  %s", s.SHA256, s.Name)
		}
	}

	if va.sbomsDerived() {
		va.sbomList = in.SBOMs.Assets
		for _, s := range va.sbomList {
			out.logf("verify: derived SBOM asset %s  %s", s.SHA256, s.Name)
		}

		// An explicit plan is used as given; only an absent one is the
		// release's own.
		if va.inventories == "" {
			va.inventoryList = in.SBOMs.Planned
			for _, s := range va.inventoryList {
				out.logf("verify: derived planned inventory %s  %s", s.SHA256, s.Name)
			}
		}
	}

	return nil
}

// derivePins resolves the absent pins through the walk's resolution.
func (va *verifyArgs) derivePins(forge gh.Forge, out *latch) error {
	verifierWorkflow := ""
	if va.p.Trust.Verdict != nil {
		verifierWorkflow = *va.p.Trust.Verdict.VerifierWorkflow
	}

	tags, closeTags := newPinTags(out.logf)

	defer func() {
		if cerr := closeTags(); cerr != nil {
			out.logf("verify: %v", cerr)
		}
	}()

	roots, err := assert.NewPinRoots(tags, verifierWorkflow, *va.p.Trust.Provenance.SignerWorkflow)
	if err != nil {
		return err
	}

	// The release workflow is the publisher's declaration
	// (stele#448): read from --assert-policy where one is given, and
	// refused by name at resolution where it is needed and absent.
	if va.evidence != nil {
		roots.Publish = va.evidence.Publish
	}

	pins, err := roots.Resolve(forge, va.coords.Owner, va.coords.Repo, va.tag)
	if err != nil {
		return err
	}

	if va.signerPin == "" {
		va.signerPin = pins.Signer
		out.logf("verify: derived --signer-digest %s", va.signerPin)
	}

	if va.machineryPin == "" {
		va.machineryPin = pins.Machinery
		out.logf("verify: derived --machinery-digest %s", va.machineryPin)
	}

	return nil
}
