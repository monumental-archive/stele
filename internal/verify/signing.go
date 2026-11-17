// This file: the one source-signing identity rule (stele#389). A
// chain may change which workflow signs its links ONCE, in order:
// a link verifies under the policy's source.identity, or under
// source.legacyIdentity.identity while no earlier link has verified
// under source.identity and, when an until is declared, the link was
// logged no later than it. Every reader of the source identity —
// the chain walk here and emit chain's check of the link it extends —
// classifies links through SourceSigning and judges their order
// through it; no caller implements its own.
//
// No per-repository boundary is declared: the chain shows where the
// change happened, and the walk names that revision once.

package verify

import (
	"fmt"
	"time"

	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
)

// Signatures is what the rule reads: a signature proven against one
// identity, and the moment a transparency log observed that signing.
// The second method sits on the seam rather than on trust.Verified
// alone so a test can script the instant — an observed instant is
// constructible only from a countersignature (stele#173).
type Signatures interface {
	Blob(bundleJSON []byte, id trust.Identity, sha256Hex string) (*trust.Verified, error)
	LoggedAt(v *trust.Verified) (time.Time, error)
}

// SourceSigning is the policy's source-signing identities for one
// repository. Constructor: NewSourceSigning.
type SourceSigning struct {
	current trust.Identity
	legacy  *trust.Identity
	until   time.Time
	dated   bool
	sigs    Signatures
}

// NewSourceSigning expands the policy's identities for one
// repository. The policy must carry a source section; Load proved
// every field the rule reads.
func NewSourceSigning(p *policy.Policy, c Coords, sigs Signatures) *SourceSigning {
	s := &SourceSigning{
		current: trust.Identity{SAN: expand(*p.Source.Identity, c), Issuer: *p.Issuer},
		sigs:    sigs,
	}

	if l := p.Source.LegacyIdentity; l != nil {
		s.legacy = &trust.Identity{SAN: expand(*l.Identity, c), Issuer: *p.Issuer}
		s.until, s.dated = l.UntilTime()
	}

	return s
}

// Current is the identity every new link is signed under.
func (s *SourceSigning) Current() trust.Identity { return s.current }

// Signing is one link's classification: which identity signed it.
type Signing struct {
	rev    string
	id     trust.Identity
	legacy bool
}

// Identity is the identity the link was signed under — the one its
// other half and its summary's verifier.id must also carry.
func (g Signing) Identity() trust.Identity { return g.id }

// Legacy reports whether the link was signed under the legacy
// identity.
func (g Signing) Legacy() bool { return g.legacy }

// Classify proves which identity signed one link half's bundle over
// the given digest: the current identity first; the legacy identity
// only when the policy declares one, and then only if the signing was
// logged no later than its until. A bundle neither identity verifies
// returns the CURRENT identity's refusal unchanged — exactly the
// failure the walk gave before a legacy identity existed.
func (s *SourceSigning) Classify(rev string, bundle []byte, sha256Hex string) (Signing, error) {
	_, err := s.sigs.Blob(bundle, s.current, sha256Hex)
	if err == nil {
		return Signing{rev: rev, id: s.current}, nil
	}

	if s.legacy == nil {
		return Signing{}, err
	}

	verified, lerr := s.sigs.Blob(bundle, *s.legacy, sha256Hex)
	if lerr != nil {
		return Signing{}, err
	}

	if s.dated {
		at, terr := s.sigs.LoggedAt(verified)
		if terr != nil {
			return Signing{}, fmt.Errorf(
				"signed under the legacy identity %s, which carries an until, and the signing has no logged instant to"+
					" judge it by: %w", s.legacy.SAN, terr,
			)
		}

		if at.After(s.until) {
			return Signing{}, fmt.Errorf(
				"signed under the legacy identity %s at %s, after its until %s — the legacy identity signs nothing"+
					" past its until",
				s.legacy.SAN, at.UTC().Format(time.RFC3339), s.until.UTC().Format(time.RFC3339),
			)
		}
	}

	return Signing{rev: rev, id: *s.legacy, legacy: true}, nil
}

// Order judges a chain's classified links, GENESIS FIRST: once a link
// is signed under the current identity, no later link may be signed
// under the legacy one — the change happens once and never goes back.
// It returns the revision of the first link signed under the current
// identity when the chain changed identity (a legacy link precedes
// it), and "" when it did not.
func (s *SourceSigning) Order(genesisFirst []Signing) (string, error) {
	firstCurrent := ""
	sawLegacy := false

	for _, g := range genesisFirst {
		switch {
		case !g.legacy && firstCurrent == "":
			firstCurrent = g.rev
		case g.legacy && firstCurrent != "":
			return "", fmt.Errorf(
				"link at %s is signed under the legacy identity %s after link at %s was signed under the current"+
					" identity %s — a chain changes its signing identity once and never goes back",
				g.rev, g.id.SAN, firstCurrent, s.current.SAN,
			)
		case g.legacy:
			sawLegacy = true
		}
	}

	if !sawLegacy {
		return "", nil
	}

	return firstCurrent, nil
}
