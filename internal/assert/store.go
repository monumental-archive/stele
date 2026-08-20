// The two store-resident halves of the evidence walk: continuous
// digests and base-image approvals. Neither has a release to hang
// evidence off — a rolling digest's bundle expires with the run that
// made it, and a base image is somebody else's artifact — so for both
// the attestation store is the durable record, and presence there is
// not enough: the bundle must VERIFY under a pinned identity, which
// is why this file takes an Attestor seam rather than peeking bytes.
//
// The expected signer pin is derived from the producing repository's
// own workflows, never taken from policy as a literal (#316 finding
// 9): mid-bump a repo can carry one candidate per branch state and
// the artifact must verify under one of them. Finding NO pins fails
// closed — an org image the org signer cannot vouch for is the
// finding, not a skip.

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

	if digest == "" {
		// The stub says this repo publishes, and the registry says it
		// has nothing under the rolling tag. That is a gap, not a skip.
		w.finding(repo+"@"+*c.Tag, assertContinuous,
			"the repository publishes continuous digests but no image carries the rolling tag")

		return nil
	}

	w.checked++

	pins, err := w.signerPins(repo, *c.SignerPinPattern)
	if err != nil {
		return err
	}

	subject := repo + "@" + *c.Tag

	if len(pins) == 0 {
		w.finding(subject, assertContinuous,
			"no signer pin found in the repository's workflows — the expected identity cannot be derived, so the "+
				"image cannot be vouched for")

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
		w.finding(subject, assertContinuous,
			fmt.Sprintf("%s@%s carries no attestation verifying under %s at any of the %d declared pin(s): %v",
				*c.Registry, shortDigest(digest), *c.SignerWorkflow, len(pins), verr))
	}

	w.log("assert: evidence: %s continuous digest %s checked", repo, shortDigest(digest))

	return nil
}

// signerPins derives the commit pins the repository's own workflows
// declare for the signer — the verify-signed derivation.
func (w *evidenceWalk) signerPins(repo, pattern string) ([]string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("assert: signer pin pattern: %w", err)
	}

	files, err := w.forge.Workflows(w.org, repo)
	if err != nil {
		return nil, fmt.Errorf("assert: workflows of %s: %w", repo, err)
	}

	// The pattern's first capture group is the pin; a pattern with no
	// group cannot name one, so its matches are skipped rather than
	// mistaken for pins.
	const pinGroup = 1

	seen := map[string]bool{}

	var pins []string

	for _, f := range files {
		for _, m := range re.FindAllSubmatch(f.Content, -1) {
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

	return pins, nil
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

	if pinFileContent == nil {
		// The policy declares base images and the walk was handed no
		// pin file: whatever the caller's reason, the half would be
		// checking nothing, and that may never look like PASS.
		w.finding(*b.PinFile, assertBaseImage, "the declared pin file was not provided to the walk")

		return
	}

	matches := baseRefRE.FindAllSubmatch(pinFileContent, -1)
	if len(matches) == 0 {
		// A pin file that pins nothing is a defect in the file, not a
		// clean answer: the walk was told to check something.
		w.finding(*b.PinFile, assertBaseImage, "the pin file carries no digest-pinned base references")

		return
	}

	for _, m := range matches {
		ref := string(m[1])

		at := strings.LastIndex(ref, "@")
		digest := ref[at+1:]

		w.checked++

		if err := w.attestor.Verify(
			w.org, *b.AttestorRepo, digest,
			[]Candidate{{Identity: *b.AttestorIdentity}}, *b.PredicateType,
		); err != nil {
			w.finding(ref, assertBaseImage,
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
