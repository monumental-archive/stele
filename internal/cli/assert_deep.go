// The full-depth wiring: the walk's DeepVerifier seam filled with the
// real verify engine, reading the store through the same forge the
// walk uses — so a snapshot replay re-verifies the exact bytes the
// capture run saw, and the single-engine law holds (assert judges
// through the code path a stranger runs, never a private copy).

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/verify"
)

// newDeepVerifier builds the full-depth options from the verify
// policy's trust identities. Swappable in tests.
//
//nolint:gochecknoglobals // test seam, written only by test setup
var newDeepVerifier = func(vp *policy.Policy, forge gh.Forge, bv verify.BundleVerifier) (*assert.FullDepth, error) {
	ev := &engineVerifier{
		vp:    vp,
		store: forgeStore{forge: forge},
		bv:    bv,
	}

	// The verdict obligation is declared, not assumed (#82): an empty
	// verifier workflow tells the walk to skip the deep verdict half,
	// logged per release.
	verifierWorkflow := ""
	if vp.Trust.Verdict != nil {
		verifierWorkflow = *vp.Trust.Verdict.VerifierWorkflow
	}

	return assert.NewFullDepth(ev, verifierWorkflow, *vp.Trust.Provenance.SignerWorkflow)
}

// loadFullDepth reads the trust authority and builds the full-depth
// options — every failure here is a usage refusal at the call site.
// The trusted-root document arrives already resolved: the caller
// resolves once for the whole run, so the deep half and the store
// halves cannot end up holding different trust material.
func loadFullDepth(verifyPolicyPath string, rootJSON []byte, forge gh.Forge) (*assert.FullDepth, error) {
	vf, err := os.Open(verifyPolicyPath) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return nil, err //nolint:wrapcheck // the refusal names the path already
	}

	vp, perr := policy.Load(vf)
	vf.Close() //nolint:errcheck,gosec // read-only close

	if perr != nil {
		return nil, perr
	}

	bv, berr := newBundleVerifier(rootJSON)
	if berr != nil {
		return nil, berr
	}

	return newDeepVerifier(vp, forge, bv)
}

// storeHalvesDeclared reports whether this policy gives the walk a
// cryptographic half at all. One predicate, read by the caller that
// resolves the trusted root and by the builder that consumes it, so
// the two cannot disagree about whether this run owes a root.
func storeHalvesDeclared(pol *assert.Policy) bool {
	return pol.Evidence.Continuous != nil || pol.Evidence.BaseImages != nil
}

// loadStoreInputs builds what the store halves need: the attestor
// over the trust boundary, and the committed pin file. A declared pin
// file absent from the checkout is a usage refusal: the far likelier
// cause is the wrong working directory, and proceeding would judge
// nothing while looking green.
//
//nolint:ireturn // the walk's own parameter type — the seam is the point
func loadStoreInputs(
	pol *assert.Policy, forge gh.Forge, rootJSON []byte, pinPath string,
) (assert.Attestor, []byte, error) {
	var attestor assert.Attestor

	if storeHalvesDeclared(pol) {
		bv, berr := newBundleVerifier(rootJSON)
		if berr != nil {
			return nil, nil, berr
		}

		attestor = newAttestor(forge, bv, *pol.Issuer)
	}

	var pinFile []byte

	if pol.Evidence.BaseImages != nil {
		if pinPath == "" {
			pinPath = *pol.Evidence.BaseImages.PinFile
		}

		content, perr := os.ReadFile(pinPath) //nolint:gosec // the pin path is operator-supplied by design
		switch {
		case errors.Is(perr, fs.ErrNotExist):
			return nil, nil, fmt.Errorf(
				"the policy declares baseImages but %s is absent from this checkout", pinPath)
		case perr != nil:
			return nil, nil, perr //nolint:wrapcheck // the refusal names the path already
		default:
			pinFile = content
		}
	}

	return attestor, pinFile, nil
}

// engineVerifier implements assert.DeepVerifier over the verify
// engine.
type engineVerifier struct {
	vp    *policy.Policy
	store verify.Store
	bv    verify.BundleVerifier
}

func (e *engineVerifier) Release(
	c verify.Coords, subjects, sboms []verify.Subject, pins verify.Pins, decision bool,
) error {
	if !decision {
		_, err := verify.ReleaseProvenance(e.vp, c, subjects, pins, e.store, e.bv, func(string, ...any) {})

		return err
	}

	_, err := verify.Release(e.vp, c, subjects, sboms, pins, e.store, e.bv, func(string, ...any) {})

	return err
}

func (e *engineVerifier) VSA(
	c verify.Coords, subjects []verify.Subject, pins verify.Pins, enrichment bool,
) error {
	if !enrichment {
		_, err := verify.VSAVerdictOnly(e.vp, c, subjects, pins, e.store, e.bv, func(string, ...any) {})

		return err
	}

	_, err := verify.VSA(e.vp, c, subjects, pins, e.store, e.bv, func(string, ...any) {})

	return err
}

// forgeStore adapts the walk's forge to the verify engine's Store:
// the same attestation read serves both, which is what lets a
// captured snapshot replay the deep walk byte-identically.
type forgeStore struct {
	forge gh.Forge
}

func (s forgeStore) Bundles(slug, sha256Hex string) ([]verify.StoredBundle, error) {
	owner, repo, ok := strings.Cut(slug, "/")
	if !ok {
		return nil, fmt.Errorf("store slug %q is not owner/repo", slug)
	}

	raws, err := s.forge.Attestations(owner, repo, sha256Hex)
	if err != nil {
		return nil, err
	}

	out := make([]verify.StoredBundle, 0, len(raws))
	for i, raw := range raws {
		out = append(out, verify.StoredBundle{
			URI:    fmt.Sprintf("store://%s/sha256:%s#%d", slug, sha256Hex, i),
			Bundle: raw,
		})
	}

	return out, nil
}
