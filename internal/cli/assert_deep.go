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
	"maps"
	"os"
	"slices"
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

// basePins are the --base-pins overrides: one committed file per
// named pin-file scope. Repeatable and scope-named because the policy
// may declare several pin-file scopes (stele#247), and a single
// global path could not say which of them it replaced.
type basePins map[string]string

// String implements flag.Value — the scopes overridden so far, which
// is what a usage dump should show; the paths are noise there.
func (b *basePins) String() string {
	return strings.Join(slices.Sorted(maps.Keys(*b)), ",")
}

// Set implements flag.Value. The path is cut off at the leftmost `=`,
// so a path may carry one; a scope name may not, which is the price
// of a delimiter and is paid where the adopter chooses the name.
func (b *basePins) Set(v string) error {
	scope, path, ok := strings.Cut(v, "=")

	scope, path = strings.TrimSpace(scope), strings.TrimSpace(path)
	if !ok || scope == "" || path == "" {
		return fmt.Errorf("--base-pins %q is not <scope>=<path>", v)
	}

	if *b == nil {
		*b = basePins{}
	}

	if _, dup := (*b)[scope]; dup {
		return fmt.Errorf("--base-pins names scope %q twice — one scope has one pin file", scope)
	}

	(*b)[scope] = path

	return nil
}

// loadStoreInputs builds what the store halves need: the attestor
// over the trust boundary, and each pin-file scope's committed file,
// keyed by scope. A declared pin file absent from the checkout is a
// usage refusal: the far likelier cause is the wrong working
// directory, and proceeding would judge nothing while looking green.
//
//nolint:ireturn // the walk's own parameter type — the seam is the point
func loadStoreInputs(
	pol *assert.Policy, forge gh.Forge, rootJSON []byte, overrides basePins,
) (assert.Attestor, map[string][]byte, error) {
	var attestor assert.Attestor

	if storeHalvesDeclared(pol) {
		bv, berr := newBundleVerifier(rootJSON)
		if berr != nil {
			return nil, nil, berr
		}

		attestor = newAttestor(forge, bv, *pol.Issuer)
	}

	scopes := pinFileScopes(pol)

	// An override naming a scope that takes no pin file is a typo the
	// caller must see: silently ignoring it would read as an override
	// that took effect.
	for _, name := range slices.Sorted(maps.Keys(overrides)) {
		if !slices.ContainsFunc(scopes, func(s *assert.BaseImageScope) bool { return *s.Name == name }) {
			return nil, nil, fmt.Errorf(
				"--base-pins names scope %q, which this policy declares no pin-file scope for", name)
		}
	}

	pinFiles, err := readPinFiles(scopes, overrides)
	if err != nil {
		return nil, nil, err
	}

	return attestor, pinFiles, nil
}

// pinFileScopes is the declared scopes whose mechanism reads a
// committed file — the only ones the caller must supply anything for.
func pinFileScopes(pol *assert.Policy) []*assert.BaseImageScope {
	var out []*assert.BaseImageScope

	if pol.Evidence.BaseImages == nil {
		return out
	}

	for i := range pol.Evidence.BaseImages.Scopes {
		if s := &pol.Evidence.BaseImages.Scopes[i]; *s.Mechanism == assert.MechanismPinFile {
			out = append(out, s)
		}
	}

	return out
}

// readPinFiles reads one file per pin-file scope, honouring any
// override, keyed by the scope that declared it.
func readPinFiles(scopes []*assert.BaseImageScope, overrides basePins) (map[string][]byte, error) {
	pinFiles := map[string][]byte{}

	for _, s := range scopes {
		pinPath := *s.PinFile
		if override, ok := overrides[*s.Name]; ok {
			pinPath = override
		}

		content, perr := os.ReadFile(pinPath) //nolint:gosec // the pin path is operator-supplied by design
		switch {
		case errors.Is(perr, fs.ErrNotExist):
			return nil, fmt.Errorf(
				"the policy declares baseImages scope %q but %s is absent from this checkout"+
					" — pass --base-pins %s=<path> to supply it from elsewhere", *s.Name, pinPath, *s.Name)
		case perr != nil:
			return nil, perr //nolint:wrapcheck // the refusal names the path already
		default:
			pinFiles[*s.Name] = content
		}
	}

	return pinFiles, nil
}

// engineVerifier implements assert.DeepVerifier over the verify
// engine.
type engineVerifier struct {
	vp    *policy.Policy
	store verify.Store
	bv    verify.BundleVerifier
}

func (e *engineVerifier) Release(
	c verify.Coords, subjects []verify.Subject, sboms verify.SBOMs, pins verify.Pins, decision bool,
) error {
	if !decision {
		_, err := verify.ReleaseProvenance(e.vp, c, subjects, pins, e.store, e.bv, func(string, ...any) {})

		return err
	}

	_, err := verify.Release(e.vp, c, subjects, sboms, pins, e.store, e.bv, func(string, ...any) {})

	return err
}

func (e *engineVerifier) VSA(
	c verify.Coords, subjects []verify.Subject, pins verify.Pins, demand *verify.EnrichmentDemand,
) error {
	_, err := verify.VSA(e.vp, c, subjects, pins, e.store, e.bv, func(string, ...any) {}, demand)

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
