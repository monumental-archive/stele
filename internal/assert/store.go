// The two store-resident halves of the evidence walk: continuous
// digests and base-image approvals. Neither has a release to hang
// evidence off — a rolling digest's bundle expires with the run that
// made it, and a base image is somebody else's artifact — so for both
// the attestation store is the durable record, and presence there is
// not enough: the bundle must VERIFY under a pinned identity, which
// is why this file takes an Attestor seam rather than peeking bytes.
//
// The expected signer pin is derived from the chain that actually
// signs, never taken from policy as a literal (#316 finding 9): the
// consumer's stub names a reusable workflow at a commit, and THAT
// released tree names the signer pin. Both hops are the same release,
// so the declared identity and the signing surface can never disagree
// across a bump window (#230). Finding NO pins fails closed — an org
// image the org signer cannot vouch for is the finding, not a skip.

package assert

import (
	"fmt"
	"regexp"
	"strings"
)

// Candidate is one identity the artifact may have been signed under.
// Identity and SignerPin travel together because they are two views
// of the same fact: a workflow reached through a commit-pinned uses:
// carries that commit as its certificate SAN ref AND as the signer
// digest, so checking one without the other checks half the binding.
// An empty SignerPin means the pin is not asserted (the signer runs
// from its own branch, and the identity alone names it).
type Candidate struct {
	Identity  string
	SignerPin string
}

// Attestor proves one artifact digest carries a verifying attestation
// in the store. Interface-shaped so every guard here is table-tested;
// the implementation composes the trust boundary the verify verb
// already owns.
type Attestor interface {
	// Verify proves that some attestation stored for subjectDigest in
	// the named repository verifies under ONE of the candidates and —
	// when predicateType is non-empty — carries that predicate. Any
	// candidate suffices: mid-bump a repo can declare several, and the
	// artifact must verify under one of them.
	Verify(owner, repo, subjectDigest string, candidates []Candidate, predicateType string) error
}

// serverURL is the host every GitHub Actions identity lives under —
// part of the certificate's semantics, so code, not policy.
const serverURL = "https://github.com"

// The assertion vocabulary for the store halves.
const (
	assertContinuous = "continuous-digest"
	assertBaseImage  = "base-image-approval"
)

// continuous walks the repos that publish rolling digests and proves
// each one's latest digest verifies.
func (w *evidenceWalk) continuous(repo string) error {
	c := w.pol.Continuous
	if c == nil {
		return nil
	}

	stub, ok, err := w.forge.FileAt(w.org, repo, *c.StubPath, defaultRef)
	if err != nil {
		return fmt.Errorf("assert: continuous stub of %s: %w", repo, err)
	}

	if !ok || !strings.Contains(string(stub), *c.StubUses) {
		return nil // not a publishing repo — an answer, not a gap
	}

	digest, err := w.forge.PackageVersionDigest(w.org, repo, *c.Tag)
	if err != nil {
		return fmt.Errorf("assert: package versions of %s: %w", repo, err)
	}

	if cc := w.check(repo+"@"+*c.Tag, assertContinuous); digest == "" {
		// The stub says this repo publishes, and the registry says it
		// has nothing under the rolling tag. That is a gap, not a skip.
		cc.Diverged("the repository publishes continuous digests but no image carries the rolling tag")

		return nil
	}

	w.checked++

	derived, err := w.signerPins(stub, *c.StubUses, *c.SignerPinPattern)
	if err != nil {
		return err
	}

	pins := derived.Pins

	subject := repo + "@" + *c.Tag
	continuous := w.check(subject, assertContinuous)

	if len(pins) == 0 {
		continuous.Diverged(
			derived.Cause + " — the expected identity cannot be derived, so the image cannot be vouched for")

		return nil
	}

	// One candidate per declared pin: the signer is reached through a
	// commit-pinned uses:, so the pin IS the certificate's ref.
	candidates := make([]Candidate, 0, len(pins))
	for _, pin := range pins {
		candidates = append(candidates, Candidate{
			Identity:  serverURL + "/" + *c.SignerWorkflow + "@" + pin,
			SignerPin: pin,
		})
	}

	if verr := w.attestor.Verify(w.org, repo, digest, candidates, ""); verr != nil {
		continuous.Diverged(
			fmt.Sprintf("%s@%s carries no attestation verifying under %s at any of the %d declared pin(s): %v",
				*c.Registry, shortDigest(digest), *c.SignerWorkflow, len(pins), verr))
	}

	w.log("assert: evidence: %s continuous digest %s checked", repo, shortDigest(digest))

	return nil
}

// stubCallRE builds the matcher for the stub's own pinned call: the
// reusable workflow it reaches, spelled owner/repo/path@sha. The
// prefix comes from the policy's stubUses, so nothing org-shaped
// enters this engine — the stub's uses: line already carries the
// whole path.
func stubCallRE(stubUses string) (*regexp.Regexp, error) {
	re, err := regexp.Compile(regexp.QuoteMeta(stubUses) + `([A-Za-z0-9._/-]+\.ya?ml)@([0-9a-f]{40})`)
	if err != nil {
		return nil, fmt.Errorf("assert: continuous stub uses pattern: %w", err)
	}

	return re, nil
}

// signerPins derives the commit pins the CONSUMING chain declares for
// the signer, two hops: the stub's own pinned uses: names a reusable
// workflow at a sha, and THAT released tree carries the signer pin.
//
// The one-hop read this replaced regexed the consuming repository's
// own workflows at default-branch HEAD, which is not the tree that
// signs (.github#645): an unrelated workflow naming the signer became
// the declared pin, and a bump on the shared repository's main
// demanded an identity no consumer's release could yet have signed
// under. Derived through the stub's pin, the declared set and the
// signing surface move together, because they ARE the same release.
func (w *evidenceWalk) signerPins(stub []byte, stubUses, pattern string) (derivedPins, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return derivedPins{}, fmt.Errorf("assert: signer pin pattern: %w", err)
	}

	callRE, err := stubCallRE(stubUses)
	if err != nil {
		return derivedPins{}, err
	}

	shared, ok := splitStubUses(stubUses)
	if !ok {
		return derivedPins{}, fmt.Errorf("assert: continuous stubUses %q names no owner and repository", stubUses)
	}

	calls := callRE.FindAllSubmatch(stub, -1)
	if len(calls) == 0 {
		return derivedPins{Cause: "the continuous stub declares no commit-pinned call to " + stubUses}, nil
	}

	// The pattern's first capture group is the pin; a pattern with no
	// group cannot name one, so its matches are skipped rather than
	// mistaken for pins.
	const pinGroup = 1

	seen := map[string]bool{}

	var (
		pins   []string
		missed []string
	)

	for _, call := range calls {
		const (
			pathGroup = 1
			shaGroup  = 2
		)

		path, sha := string(call[pathGroup]), string(call[shaGroup])

		content, found, ferr := w.forge.FileAt(shared.Owner, shared.Name, path, sha)
		if ferr != nil {
			return derivedPins{}, fmt.Errorf("assert: %s/%s %s at %s: %w",
				shared.Owner, shared.Name, path, sha, ferr)
		}

		if !found {
			missed = append(missed, path+"@"+sha)

			continue
		}

		for _, m := range re.FindAllSubmatch(content, -1) {
			if len(m) <= pinGroup {
				continue
			}

			pin := string(m[pinGroup])
			if !seen[pin] {
				seen[pin] = true
				pins = append(pins, pin)
			}
		}
	}

	if len(pins) > 0 {
		return derivedPins{Pins: pins}, nil
	}

	if len(missed) > 0 {
		return derivedPins{Cause: fmt.Sprintf(
			"the pinned reusable workflow the stub calls is not readable at its pin (%s)",
			strings.Join(missed, ", "))}, nil
	}

	return derivedPins{Cause: "no signer pin found in the released tree the stub's pin names"}, nil
}

// splitStubUses takes the owner and repository off the front of the
// stubUses prefix: everything after them is the path INSIDE that
// repository, which the stub's own uses: line spells out.
func splitStubUses(stubUses string) (sharedRepo, bool) {
	// owner, repository, and whatever path prefix follows them.
	const segments = 3

	parts := strings.SplitN(strings.TrimPrefix(stubUses, "/"), "/", segments)
	if len(parts) < segments || parts[0] == "" || parts[1] == "" {
		return sharedRepo{}, false
	}

	return sharedRepo{Owner: parts[0], Name: parts[1]}, true
}

// sharedRepo is the repository the consumer's stub calls into: the
// one whose RELEASED tree carries the signer pin.
type sharedRepo struct {
	Owner string
	Name  string
}

// derivedPins is the pin derivation's answer: the pins, or — when
// there are none — the cause to report. Each fail-closed step names
// which hop was missing, because a finding that cannot say that is a
// finding nobody can act on.
type derivedPins struct {
	Pins  []string
	Cause string
}

// baseRefRE finds pinned base references in the pin file: any
// registry reference carrying an explicit digest.
var baseRefRE = regexp.MustCompile(`["']([a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64})["']`)

// baseImages proves every pinned base digest carries its approval
// attestation. The pin file lives in the policy-owning checkout: a
// Renovate roll that outran the approval run surfaces here, not at
// the next release.
func (w *evidenceWalk) baseImages(pinFileContent []byte) {
	b := w.pol.BaseImages
	if b == nil {
		return
	}

	// The pin file itself is one check: declared and unreadable, or
	// declared and pinning nothing, are both defects in the file.
	file := w.check(*b.PinFile, assertBaseImage)

	if pinFileContent == nil {
		// The policy declares base images and the walk was handed no
		// pin file: whatever the caller's reason, the half would be
		// checking nothing, and that may never look like PASS.
		file.Diverged("the declared pin file was not provided to the walk")

		return
	}

	matches := baseRefRE.FindAllSubmatch(pinFileContent, -1)
	if len(matches) == 0 {
		// A pin file that pins nothing is a defect in the file, not a
		// clean answer: the walk was told to check something.
		file.Diverged("the pin file carries no digest-pinned base references")

		return
	}

	for _, m := range matches {
		ref := string(m[1])

		at := strings.LastIndex(ref, "@")
		digest := ref[at+1:]

		w.checked++

		pin := w.check(ref, assertBaseImage)

		if err := w.attestor.Verify(
			w.org, *b.AttestorRepo, digest,
			[]Candidate{{Identity: *b.AttestorIdentity}}, *b.PredicateType,
		); err != nil {
			pin.Diverged(
				fmt.Sprintf("no %s attestation verifies for this pinned base: %v", *b.PredicateType, err))
		}

		w.log("assert: evidence: base pin %s checked", ref)
	}
}

// defaultRef reads a repository's default branch state — the honest
// source for "what does this repo pin RIGHT NOW", as opposed to the
// tag-time reads the release contract uses.
const defaultRef = "HEAD"

// shortDigest renders a digest for a human-facing line.
func shortDigest(d string) string {
	const shown = 12

	trimmed := strings.TrimPrefix(d, "sha256:")
	if len(trimmed) <= shown {
		return trimmed
	}

	return trimmed[:shown]
}
