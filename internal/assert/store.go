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

// baseRefRE finds pinned base references in a pin file: any registry
// reference carrying an explicit digest, quoted as a value in the
// committed file's own syntax.
var baseRefRE = regexp.MustCompile(`["']([a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64})["']`)

// fromRefRE finds the digest-pinned bases a build file instantiates.
// `FROM` is the container build standard, so it is code; which FILE
// carries it and which of its references this org vouches for are the
// scope's declarations. Build flags between the keyword and the
// reference (`--platform=`) are skipped, and a trailing `AS <stage>`
// is simply not captured.
var fromRefRE = regexp.MustCompile(
	`(?im)^[ \t]*FROM[ \t]+(?:--[^ \t]+[ \t]+)*([a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64})`)

// baseScopes is the declared approval scopes, or none.
func (w *evidenceWalk) baseScopes() []BaseImageScope {
	if w.pol.BaseImages == nil {
		return nil
	}

	return w.pol.BaseImages.Scopes
}

// scopeAssertion qualifies the shared vocabulary with the scope that
// demanded it. Two scopes may judge the same reference by different
// mechanisms, and a finding that cannot say which one asked is a
// finding nobody can act on.
func scopeAssertion(s *BaseImageScope) string {
	return assertBaseImage + ":" + *s.Name
}

// baseImagesInCheckout runs the pin-file scopes. Each one's committed
// file lives in the policy-owning checkout and arrives read, keyed by
// scope name: a Renovate roll that outran the approval run surfaces
// here, not at the next release.
func (w *evidenceWalk) baseImagesInCheckout(pinFiles map[string][]byte) {
	scopes := w.baseScopes()
	for i := range scopes {
		if s := &scopes[i]; *s.Mechanism == MechanismPinFile {
			w.pinFileScope(s, pinFiles[*s.Name])
		}
	}
}

// baseImagesInRepo runs the provenance-verified scopes against one
// population repository. This mechanism's subjects live in the
// population rather than in the policy-owning checkout — the caller's
// build file is where its bases are named — so it rides the repo loop
// the population already drives.
func (w *evidenceWalk) baseImagesInRepo(repo string) error {
	scopes := w.baseScopes()
	for i := range scopes {
		if s := &scopes[i]; *s.Mechanism == MechanismProvenanceVerified {
			if err := w.provenanceScope(s, repo); err != nil {
				return err
			}
		}
	}

	return nil
}

// pinFileScope proves every digest-pinned base the scope's file
// carries holds an approval attestation from the declared attestor.
func (w *evidenceWalk) pinFileScope(s *BaseImageScope, content []byte) {
	assertion := scopeAssertion(s)

	// The pin file itself is one check: declared and unreadable, or
	// declared and pinning nothing, are both defects in the file.
	file := w.check(*s.PinFile, assertion)

	if content == nil {
		// The policy declares this scope and the walk was handed no
		// pin file: whatever the caller's reason, the scope would be
		// checking nothing, and that may never look like PASS.
		file.Diverged("the declared pin file was not provided to the walk")

		return
	}

	matches := baseRefRE.FindAllSubmatch(content, -1)
	if len(matches) == 0 {
		// A pin file that pins nothing is a defect in the file, not a
		// clean answer: the walk was told to check something.
		file.Diverged("the pin file carries no digest-pinned base references")

		return
	}

	for _, m := range matches {
		ref := string(m[1])

		w.checked++

		// Recorded BEFORE the verdict, pass or fail: Journal.Check is
		// what says this run was in a position to see this
		// (subject, assertion), which is the question a declared
		// exception's staleness rests on.
		pin := w.check(ref, assertion)

		if err := w.attestor.Verify(
			w.org, *s.AttestorRepo, refDigest(ref),
			[]Candidate{{Identity: *s.AttestorIdentity}}, *s.PredicateType,
		); err != nil {
			pin.Diverged(
				fmt.Sprintf("no %s attestation verifies for this pinned base: %v", *s.PredicateType, err))
		}

		w.log("assert: evidence: base pin %s checked", ref)
	}
}

// provenanceScope proves every base under the scope's registry prefix
// that this repository's build file instantiates carries provenance
// from the identity its own pin implies. Nothing here is a literal:
// the expected identity is expanded out of the reference, so the
// identity demanded travels with the pin that names it.
func (w *evidenceWalk) provenanceScope(s *BaseImageScope, repo string) error {
	content, ok, err := w.forge.FileAt(w.org, repo, *s.FromFile, defaultRef)
	if err != nil {
		return fmt.Errorf("assert: build file of %s: %w", repo, err)
	}

	if !ok {
		return nil // this repo builds no image — an answer, not a gap
	}

	// Compiled here rather than assumed: policy load already refused
	// an unparsable pattern, and a walk that PANICS on one instead of
	// refusing would be the wrong failure at the wrong altitude.
	re, err := regexp.Compile(*s.PinPattern)
	if err != nil {
		return fmt.Errorf("assert: base scope %s pinPattern: %w", *s.Name, err)
	}

	owner, assertion := publisherOwner(*s.RegistryPrefix), scopeAssertion(s)

	for _, m := range fromRefRE.FindAllSubmatch(content, -1) {
		ref := string(m[1])
		if !strings.HasPrefix(ref, *s.RegistryPrefix) {
			// Somebody else's base. Whose bases those are is another
			// mechanism's question, so this scope reports nothing —
			// an exclusion produces no finding, no count, no cell.
			continue
		}

		w.checked++

		pin := w.check(ref, assertion)

		idx := re.FindStringSubmatchIndex(ref)
		if idx == nil {
			// The identity is derived from the pin, so a pin the
			// pattern cannot read leaves nothing to demand. Fail
			// closed: an unreadable pin is not an approved one.
			pin.Diverged("the pinned reference does not match this scope's pinPattern," +
				" so the identity that should have published it cannot be derived")

			continue
		}

		identity := string(re.ExpandString(nil, *s.Identity, ref, idx))
		if identity == "" {
			pin.Diverged("this scope's identity template expands to nothing for the pinned reference")

			continue
		}

		if verr := w.attestor.Verify(
			owner, publisherRepo(ref, *s.RegistryPrefix), refDigest(ref),
			[]Candidate{{Identity: identity}}, *s.PredicateType,
		); verr != nil {
			pin.Diverged(fmt.Sprintf(
				"no %s attestation verifies for this base under %s: %v", *s.PredicateType, identity, verr))
		}

		w.log("assert: evidence: %s base %s checked", repo, ref)
	}

	return nil
}

// publisherOwner and publisherRepo split the publishing repository
// out of a reference: the prefix is validated to stop at the owner
// boundary (`<host>/<owner>/`), so the owner is its last segment and
// the repository is the first segment of whatever follows. That
// precondition is checked at policy load, never assumed here.
func publisherOwner(prefix string) string {
	trimmed := strings.TrimSuffix(prefix, "/")

	_, owner, _ := strings.Cut(trimmed, "/")

	return owner
}

func publisherRepo(ref, prefix string) string {
	rest := strings.TrimPrefix(ref, prefix)
	if end := strings.IndexAny(rest, "/:@"); end >= 0 {
		return rest[:end]
	}

	return rest
}

// refDigest is the digest half of a digest-pinned reference — the
// bytes the attestation must cover.
func refDigest(ref string) string {
	return ref[strings.LastIndex(ref, "@")+1:]
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
