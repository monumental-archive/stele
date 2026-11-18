// The source verdict for a release tag (stele#391, stele#468): a
// signed statement binding the tag to its commit and to the level that
// commit's chain link already holds.
//
// `emit source-vsa` is its one producer. It proves the tag, finds the
// link at the tag's own target, signs and proves the envelope as a
// stranger would, and reads no release, no store and no registry — so
// it runs before a release exists, which is the only time a publisher
// that seals its releases at publish can still attach it.
//
// `emit vsa` no longer writes one. Where the assert policy owes a
// source verdict it reads the PUBLISHED envelope back (`--source-verdict`)
// through the one read `verify source-vsa` runs, and refuses unless the
// commit it binds is the one the release's own provenance names — the
// comparison only the release-verdict leg can make, because only it
// knows that commit. Where none is owed it is byte-for-byte what it was.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gitrepo"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

// sourceGit is what the source verdict reads from the local clone:
// the chain walk's history and the tag objects.
type sourceGit interface {
	verify.History
	TagRefs() ([]gitrepo.TagRef, error)
	ResolveTag(ref gitrepo.TagRef) (string, *gitrepo.TagObject, error)
}

// The source verdict's effect seams, swapped only by tests.
//
//nolint:gochecknoglobals // test seams, written only by test setup
var (
	openSourceGit = func(dir, notesRef string) (sourceGit, error) {
		return gitrepo.Open(dir, notesRef)
	}

	// verifyTagSignature proves one tag signature under the trusted
	// root — the real gitsign verification; tests script it.
	verifyTagSignature = func(
		rootJSON, payload, sig []byte, id trust.TagIdentity, floor trust.TagFloor,
	) (*trust.TagVerdict, error) {
		tr, err := trust.LoadRoot(rootJSON)
		if err != nil {
			return nil, fmt.Errorf("trusted root: %w", err)
		}

		v, err := trust.NewVerifier(tr)
		if err != nil {
			return nil, fmt.Errorf("verifier: %w", err)
		}

		return v.VerifyTag(payload, sig, id, floor)
	}
)

// tagIdentity is the one reading of the tags policy's signer: the
// declared SAN pattern under the declared issuer. The tag audit's
// verifier and the source verdict's tag check both build it here.
func tagIdentity(sanPattern, issuer string) (trust.TagIdentity, error) {
	re, err := regexp.Compile(sanPattern)
	if err != nil {
		return trust.TagIdentity{}, fmt.Errorf("identity pattern: %w", err)
	}

	return trust.TagIdentity{SANPattern: re, Issuer: issuer}, nil
}

// registerSourceVerdictFlags adds the published source verdict's
// inputs to `emit vsa`.
func registerSourceVerdictFlags(fs *flag.FlagSet, ea *emitArgs) {
	fs.StringVar(&ea.assertPolicy, "assert-policy", "",
		"path to the committed assert policy; when it owes a source verdict for the tag, --source-verdict is "+
			"read and held against the release's own commit")
	fs.StringVar(&ea.gitDir, "git-dir", "",
		"local clone with the protected branches, the notes ref and the tag fetched (required when a source "+
			"verdict is owed)")
	fs.StringVar(&ea.sourceVerdictIn, "source-verdict", "",
		"the source verdict envelope the release published, from `emit source-vsa` (required when one is owed)")
	registerMachineryVersion(fs, ea)
}

// registerMachineryVersion is the one spelling of the input "owed" is
// read against, on both modes.
func registerMachineryVersion(fs *flag.FlagSet, ea *emitArgs) {
	fs.StringVar(&ea.machineryVersion, "machinery-version", "",
		"the version of the release machinery this release runs — what evidence.sourceVerdictFromVersion is "+
			"read against (required when the assert policy declares it)")
}

// registerEmitSourceVSAFlags is `emit source-vsa`'s surface: the tag, the
// two policies, the clone, and where the envelope goes.
func registerEmitSourceVSAFlags(fs *flag.FlagSet, ea *emitArgs) {
	fs.StringVar(&ea.tag, "tag", "", "release tag (required)")
	fs.StringVar(&ea.assertPolicy, "assert-policy", "",
		"path to the committed assert policy: its tags section and evidence.sourceVerdictFromVersion (required)")
	fs.StringVar(&ea.gitDir, "git-dir", "",
		"local clone with the protected branches, the notes ref and the tag fetched (required)")
	fs.StringVar(&ea.out, "out", "", "write the signed source verdict envelope here (required)")
	registerMachineryVersion(fs, ea)
}

// loadSourceVerdict reads the assert policy for `emit vsa` and decides
// whether this run owes a source verdict; when it does, the published
// envelope and the clone it is read against are required. Not owed,
// nothing is read and the flag is refused: an envelope nobody owes is
// a caller that misread its policy.
func (ea *emitArgs) loadSourceVerdict(fail func(error) int) int {
	if ea.assertPolicy == "" {
		if ea.sourceVerdictIn != "" {
			return fail(errors.New("--source-verdict needs --assert-policy: whether one is owed is that policy's"))
		}

		return exitOK
	}

	ap, err := loadAssertPolicy(ea.assertPolicy)
	if err != nil {
		return fail(fmt.Errorf("assert policy: %w", err))
	}

	owed, why, err := ea.sourceVerdictOwed(ap)
	if err != nil {
		return fail(err)
	}

	if !owed {
		if ea.sourceVerdictIn != "" {
			return fail(fmt.Errorf("--source-verdict was given, but this release owes no source verdict: %s", why))
		}

		return exitOK
	}

	switch {
	case ea.p.Source == nil:
		return fail(errors.New("a source verdict is owed but the verify policy declares no source section"))
	case ea.gitDir == "":
		return fail(errors.New("--git-dir is required: the assert policy owes a source verdict for the tag"))
	case ea.sourceVerdictIn == "":
		return fail(errors.New("--source-verdict is required: the assert policy owes a source verdict for the tag, " +
			"and this verdict holds the published one against the release's commit"))
	}

	env, err := os.ReadFile(ea.sourceVerdictIn)
	if err != nil {
		return fail(fmt.Errorf("--source-verdict: %w", err))
	}

	ea.sourceEnvelope = env
	ea.tags = ap.Tags

	return exitOK
}

// loadSourceVSA reads `emit source-vsa`'s inputs and refuses, by name,
// a caller asking for a verdict nobody owes.
func (ea *emitArgs) loadSourceVSA(fail func(error) int) int {
	switch {
	case ea.tag == "":
		return fail(errors.New("--tag is required"))
	case ea.assertPolicy == "":
		return fail(errors.New("--assert-policy is required: its tags section says how the tag is proven"))
	case ea.gitDir == "":
		return fail(errors.New("--git-dir is required"))
	case ea.out == "":
		return fail(errors.New("--out is required"))
	case ea.p.Source == nil:
		return fail(errors.New("the verify policy declares no source section — a source verdict names its resource"))
	}

	if err := ea.pin.load(ea); err != nil {
		return fail(err)
	}

	ap, err := loadAssertPolicy(ea.assertPolicy)
	if err != nil {
		return fail(fmt.Errorf("assert policy: %w", err))
	}

	switch {
	case ap.Tags == nil:
		return fail(errors.New("the assert policy declares no tags section — a source verdict binds a signed " +
			"tag, and this policy owes none"))
	case ap.Evidence.SourceVerdictFromVersion == nil:
		return fail(errors.New("the assert policy declares no evidence.sourceVerdictFromVersion — " +
			"nobody owes a source verdict"))
	}

	owed, why, err := ea.sourceVerdictOwed(ap)
	if err != nil {
		return fail(err)
	}

	if !owed {
		return fail(fmt.Errorf("%s@%s owes no source verdict: %s", ea.coords.Slug(), ea.tag, why))
	}

	ea.tags = ap.Tags
	ea.issuer = *ap.Issuer

	return exitOK
}

// sourceVerdictOwed asks the one predicate the evidence walk asks
// (assert.SourceVerdictOwed) for this release's tag. A policy that
// declares the epoch cannot be answered without the machinery version
// it is read against, so its absence is refused by name; one that
// declares none owes nothing and needs no version.
//
//nolint:gocritic // unnamedResult: owed, why, and the refusal
func (ea *emitArgs) sourceVerdictOwed(ap *assert.Policy) (bool, string, error) {
	if ap.Evidence.SourceVerdictFromVersion != nil && ea.machineryVersion == "" {
		return false, "", errors.New("--machinery-version is required: the assert policy declares " +
			"evidence.sourceVerdictFromVersion, which is read against the release machinery's version")
	}

	owed, why := assert.SourceVerdictOwed(ap.Evidence, ap.Tags, ea.coords.Repo, ea.coords.Tag, ea.machineryVersion)

	return owed, why, nil
}

// runEmitSourceVSA produces the source verdict for one tag and writes
// its envelope — the mode reads no release, so it runs before one
// exists.
func runEmitSourceVSA(ea *emitArgs, out *latch) error {
	workDir, err := os.MkdirTemp("", "stele-source-verdict-*")
	if err != nil {
		return fmt.Errorf("emit: staging directory: %w", err)
	}
	defer os.RemoveAll(workDir) //nolint:errcheck // best-effort cleanup of a temp dir

	when := emitNow().UTC().Truncate(time.Second).Format(time.RFC3339)

	env, err := ea.sourceVerdict(when, workDir, out)
	if err != nil {
		return err
	}

	if err := os.WriteFile(ea.out, append(env, '\n'), ownerRW); err != nil {
		return fmt.Errorf("emit: writing the source verdict: %w", err)
	}

	out.logf("emit: source verdict for %s@%s written to %s", ea.coords.Slug(), ea.coords.Tag, ea.out)

	return nil
}

// sourceVerdict proves the tag, finds the chain link at the tag's own
// target, renders the verdict, signs it and proves the bundle with a
// stranger's inputs — returning the envelope to write.
func (ea *emitArgs) sourceVerdict(when, workDir string, out *latch) ([]byte, error) {
	g, err := openSourceGit(ea.gitDir, *ea.p.Source.NotesRef)
	if err != nil {
		return nil, fmt.Errorf("emit: source verdict: %w", err)
	}

	target, tagProof, err := ea.releaseTag(g)
	if err != nil {
		return nil, err
	}

	// No release exists yet, so the only commit is the tag's own: the
	// comparison with the release's commit is `emit vsa`'s, made on the
	// published envelope (checkPublishedSourceVerdict).
	link, err := protectedLink(ea.p, ea.coords, g, target, ea.bv, out.logf)
	if err != nil {
		return nil, fmt.Errorf("emit: %w", err)
	}

	verdict, err := verify.NewSourceVerdict(ea.coords, target, target, tagProof, link)
	if err != nil {
		return nil, err
	}

	stmt, err := verdict.Statement(ea.p, ea.coords, ea.policyURI, ea.machineryPin, when)
	if err != nil {
		return nil, err
	}

	signer := newSigner(workDir)
	if cerr := signer.Check(); cerr != nil {
		return nil, fmt.Errorf("emit: source verdict: %w", cerr)
	}

	bundle, err := signer.Sign(verify.SourceVerdictPAE(stmt))
	if err != nil {
		return nil, fmt.Errorf("emit: source verdict: signing: %w", err)
	}

	env, err := verify.SourceVerdictEnvelope(stmt, bundle)
	if err != nil {
		return nil, fmt.Errorf("emit: source verdict: %w", err)
	}

	// The proof is the consumer's own read over the bytes about to be
	// written: an envelope `verify source-vsa` would refuse is never
	// emitted.
	pins := verify.Pins{Signer: ea.signerPin, Machinery: ea.machineryPin}
	if _, perr := verify.SourceVSA(ea.p, ea.coords, pins, target, link, env, ea.bv); perr != nil {
		return nil, fmt.Errorf("emit: the source verdict just signed does not verify as published: %w", perr)
	}

	out.logf("emit: source verdict for %s@%s: commit %s, levels %v",
		ea.coords.Slug(), ea.coords.Tag, target, verdict.Levels())

	return env, nil
}

// releaseTag reads the release tag out of the clone and proves it
// under the tags policy: annotated, minted by the declared tagger,
// signed, and verified at the floor the policy owes for this tag.
// Returns the commit the tag points at and the signature's verdict.
func (ea *emitArgs) releaseTag(g sourceGit) (string, *trust.TagVerdict, error) {
	tag := ea.coords.Tag

	target, obj, err := findTag(g, tag)
	if err != nil {
		return "", nil, fmt.Errorf("emit: %w", err)
	}

	switch {
	case obj == nil:
		return "", nil, fmt.Errorf("emit: source verdict: tag %s is lightweight — no tagger and no signature to verify", tag)
	case obj.Tagger != *ea.tags.TaggerName:
		return "", nil, fmt.Errorf("emit: source verdict: tag %s was made by tagger %q, not the minting identity %q",
			tag, obj.Tagger, *ea.tags.TaggerName)
	case len(obj.Signature) == 0:
		return "", nil, fmt.Errorf("emit: source verdict: tag %s is unsigned", tag)
	}

	id, err := tagIdentity(*ea.tags.IdentityPattern, ea.issuer)
	if err != nil {
		return "", nil, fmt.Errorf("emit: source verdict: %w", err)
	}

	floor := trust.TagFloor(ea.tags.ProofFloor.FloorFor(ea.coords.Repo, tag))

	proof, err := verifyTagSignature(ea.rootJSON, obj.Payload, obj.Signature, id, floor)
	if err != nil {
		return "", nil, fmt.Errorf("emit: source verdict: tag %s signature refused (floor %s): %w", tag, floor, err)
	}

	return target, proof, nil
}

// findTag reads one tag out of the clone: the commit it points at and
// its tag object (nil for a lightweight tag) — through gitrepo's one
// resolution, the same the tag audit reads.
func findTag(g sourceGit, tag string) (string, *gitrepo.TagObject, error) {
	refs, err := g.TagRefs()
	if err != nil {
		return "", nil, fmt.Errorf("source verdict: %w", err)
	}

	for _, ref := range refs {
		if ref.Name != tag {
			continue
		}

		target, obj, rerr := g.ResolveTag(ref)
		if rerr != nil {
			return "", nil, fmt.Errorf("source verdict: %w", rerr)
		}

		return target, obj, nil
	}

	return "", nil, fmt.Errorf("source verdict: tag %s is not in the clone — fetch it", tag)
}

// protectedLink finds the verified chain link on the commit in the
// walk of a branch the verify policy protects. A link is one note per
// commit, so any declared branch whose walk holds it gives the same
// facts; a branch whose walk fails is named only when no branch holds
// the link. The emitter and every read share it, so they cannot
// disagree about which link a verdict copies.
func protectedLink(
	vp *policy.Policy, c verify.Coords, g sourceGit, commit string, bv verify.BundleVerifier, log verify.Logf,
) (*verify.TipFacts, error) {
	var walkErrs []error

	for _, b := range vp.Source.ProtectedBranches {
		ref := "refs/heads/" + *b.Name

		chain, err := verify.Chain(vp, c, ref, g, bv, log)
		if err != nil {
			walkErrs = append(walkErrs, fmt.Errorf("%s: %w", ref, err))

			continue
		}

		if link, ok := chain.Link(commit); ok {
			return link, nil
		}
	}

	refusal := fmt.Errorf(
		"source verdict for %s: commit %s carries no verified chain link on a declared protected branch",
		c.Tag, commit,
	)
	if len(walkErrs) > 0 {
		return nil, fmt.Errorf("%w (walks refused: %w)", refusal, errors.Join(walkErrs...))
	}

	return nil, refusal
}

// readSourceVerdict is the one read of a published source verdict —
// `verify source-vsa` and the corpus walk's full depth both run it:
// the tag resolved to its commit in the clone, that commit's link
// found on a protected branch as it stands now, and the envelope held
// against both.
func readSourceVerdict(
	vp *policy.Policy, c verify.Coords, pins verify.Pins, g sourceGit, envelope []byte,
	bv verify.BundleVerifier, log verify.Logf,
) (*verify.SourceVSAVerdict, error) {
	if vp.Source == nil {
		return nil, errors.New("verify: the verify policy declares no source section — " +
			"a source verdict names its resource")
	}

	commit, _, err := findTag(g, c.Tag)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}

	link, err := protectedLink(vp, c, g, commit, bv, log)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}

	return verify.SourceVSA(vp, c, pins, commit, link, envelope, bv)
}

// checkPublishedSourceVerdict reads the source verdict the release
// published through the one read `verify source-vsa` runs, and refuses
// unless the commit it binds is the one the release was built from.
func (ea *emitArgs) checkPublishedSourceVerdict(release string, out *latch) error {
	if ea.tags == nil {
		return nil
	}

	g, err := openSourceGit(ea.gitDir, *ea.p.Source.NotesRef)
	if err != nil {
		return fmt.Errorf("emit: published source verdict: %w", err)
	}

	pins := verify.Pins{Signer: ea.signerPin, Machinery: ea.machineryPin}

	sv, err := readSourceVerdict(ea.p, ea.coords, pins, g, ea.sourceEnvelope, ea.bv, out.logf)
	if err != nil {
		return fmt.Errorf("emit: the published source verdict does not verify: %w", err)
	}

	if sv.Commit() != release {
		return fmt.Errorf("emit: the published source verdict binds %s to commit %s, but the release was built "+
			"from %s", ea.coords.Tag, sv.Commit(), release)
	}

	out.logf("emit: published source verdict for %s@%s holds: commit %s", ea.coords.Slug(), ea.coords.Tag, release)

	return nil
}
