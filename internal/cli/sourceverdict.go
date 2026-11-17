// The source verdict leg of `emit vsa` (stele#391): beside the
// release verdict, a signed statement binding the release tag to its
// commit and to the level that commit's chain link already holds.
// Attempted only when the assert policy declares both the tag
// obligation and the source-verdict epoch; otherwise `emit vsa` is
// byte-for-byte what it was. All-or-nothing with the release verdict:
// every check passes before either verdict is written.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"

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

// registerSourceVerdictFlags adds the source verdict's inputs to
// `emit vsa`.
func registerSourceVerdictFlags(fs *flag.FlagSet, ea *emitArgs) {
	fs.StringVar(&ea.assertPolicy, "assert-policy", "",
		"path to the committed assert policy; when it declares tags and evidence.sourceVerdictFromVersion, "+
			"a source verdict for the tag is emitted beside the release verdict")
	fs.StringVar(&ea.gitDir, "git-dir", "",
		"local clone with the protected branches, the notes ref and the tag fetched (required for a source verdict)")
	fs.StringVar(&ea.sourceOut, "source-out", "",
		"write the signed source verdict envelope here (required for a source verdict)")
}

// loadSourceVerdict reads the assert policy and decides whether this
// run owes a source verdict; when it does, its two other inputs are
// required.
func (ea *emitArgs) loadSourceVerdict(fail func(error) int) int {
	if ea.assertPolicy == "" {
		return exitOK
	}

	f, err := os.Open(ea.assertPolicy)
	if err != nil {
		return fail(err)
	}
	defer f.Close() //nolint:errcheck // read-only close

	ap, err := assert.LoadPolicy(f)
	if err != nil {
		return fail(fmt.Errorf("assert policy: %w", err))
	}

	if ap.Tags == nil || ap.Evidence.SourceVerdictFromVersion == nil {
		return exitOK
	}

	switch {
	case ea.p.Source == nil:
		return fail(errors.New("a source verdict is owed but the verify policy declares no source section"))
	case ea.gitDir == "":
		return fail(errors.New("--git-dir is required: the assert policy owes a source verdict for the tag"))
	case ea.sourceOut == "":
		return fail(errors.New("--source-out is required: the assert policy owes a source verdict for the tag"))
	}

	ea.tags = ap.Tags
	ea.issuer = *ap.Issuer

	return exitOK
}

// sourceVerdict runs both source checks for the tag, renders the
// verdict, signs it and proves the bundle with a stranger's inputs —
// returning the envelope to write. Nothing
// is written here: the caller writes both verdicts or neither.
func (ea *emitArgs) sourceVerdict(release, when, workDir string, out *latch) ([]byte, error) {
	g, err := openSourceGit(ea.gitDir, *ea.p.Source.NotesRef)
	if err != nil {
		return nil, fmt.Errorf("emit: source verdict: %w", err)
	}

	target, tagProof, err := ea.releaseTag(g)
	if err != nil {
		return nil, err
	}

	// The link is looked up at the commit the RELEASE was built from;
	// the verdict's constructor then refuses a tag pointing anywhere
	// else, by name.
	link, err := protectedLink(ea.p, ea.coords, g, release, ea.bv, out.logf)
	if err != nil {
		return nil, fmt.Errorf("emit: %w", err)
	}

	verdict, err := verify.NewSourceVerdict(ea.coords, release, target, tagProof, link)
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

	switch epoch, declared := ea.tags.Epochs[ea.coords.Repo]; {
	case obj == nil:
		return "", nil, fmt.Errorf("emit: source verdict: tag %s is lightweight — no tagger and no signature to verify", tag)
	case obj.Tagger != *ea.tags.TaggerName:
		return "", nil, fmt.Errorf("emit: source verdict: tag %s was made by tagger %q, not the minting identity %q",
			tag, obj.Tagger, *ea.tags.TaggerName)
	case !declared:
		return "", nil, fmt.Errorf("emit: source verdict: the tags policy declares no signing epoch for %s",
			ea.coords.Repo)
	case epoch == assert.EpochPending:
		return "", nil, fmt.Errorf("emit: source verdict: the tags policy declares %s unsigned (pending) — "+
			"a tag that owes no signature cannot vouch for a verdict", ea.coords.Repo)
	case !ea.tags.SignsTag(ea.coords.Repo, tag):
		return "", nil, fmt.Errorf("emit: source verdict: tag %s predates %s's signing epoch %s — "+
			"a tag that owes no signature cannot vouch for a verdict", tag, ea.coords.Repo, epoch)
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

// writeSourceVerdict writes the source envelope when one is owed. The
// caller writes it before the release predicate and removes it again
// if that write fails, so neither verdict is left without the other.
func writeSourceVerdict(path string, env []byte) error {
	if env == nil {
		return nil
	}

	if err := os.WriteFile(path, append(env, '\n'), ownerRW); err != nil {
		return fmt.Errorf("emit: writing the source verdict: %w", err)
	}

	return nil
}

// emitSourceVerdict stages the signing directory the source verdict
// needs, only when one is owed.
func (ea *emitArgs) emitSourceVerdict(release, when string, out *latch) ([]byte, error) {
	if ea.tags == nil {
		return nil, nil
	}

	workDir, err := os.MkdirTemp("", "stele-source-verdict-*")
	if err != nil {
		return nil, fmt.Errorf("emit: staging directory: %w", err)
	}
	defer os.RemoveAll(workDir) //nolint:errcheck // best-effort cleanup of a temp dir

	return ea.sourceVerdict(release, when, workDir, out)
}
