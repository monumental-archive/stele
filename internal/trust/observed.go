// The observed instant: the one moment a verdict is allowed to hold
// evidence against, and the type that makes a weaker verdict
// unwritable (stele#173). An ObservedInstant is constructible ONLY
// from a countersignature — a third party's attestation of a moment,
// verified against the trusted root before the value exists. There
// is no constructor taking a plain time: an instant any party to the
// signing chose is not an observation, and code that wants one
// cannot be written against this package.
//
// Chain verification lives INSIDE the construction (observeCT builds
// and requires the chain while proving the SCT; the bundle paths
// chain inside sigstore-go's Verify against the tlog/TSA instants it
// verified). There is no chain entry point that takes a time, so
// verifying a chain without a third party's attestation is not
// expressible — which is the invariant #167's fix could only state
// in prose.

package trust

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/ctutil"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// The countersignature classes an ObservedInstant may come from.
// Each names WHO attested the moment: a certificate transparency log
// countersigns the certificate's issuance; a transparency log or a
// timestamp authority countersigns an observation of the signature
// itself.
const (
	SourceCertificateTransparency = "certificate-transparency"
	SourceTransparencyLog         = "transparency-log"
	SourceTimestampAuthority      = "timestamp-authority"
)

// ObservedInstant is a moment somebody other than the signer attests
// to. Constructors are deliberately unexported and each one verifies
// the countersignature first — see the package comment above.
type ObservedInstant struct {
	at     time.Time
	source string
	log    string
}

// Time is the countersigned moment.
func (o ObservedInstant) Time() time.Time { return o.at }

// Source is the countersignature class (the Source* constants).
func (o ObservedInstant) Source() string { return o.source }

// Log identifies the log or authority that carries the
// countersignature — a key ID for a CT log, a base URL for a
// transparency log or timestamp authority.
func (o ObservedInstant) Log() string { return o.log }

// String renders the instant the way a verdict names it.
func (o ObservedInstant) String() string {
	return fmt.Sprintf("%s (%s %s)", o.at.UTC().Format(time.RFC3339), o.source, o.log)
}

// observeCT proves the leaf's embedded signed certificate timestamp
// against the trusted root's CT logs and returns the countersigned
// issuance instant. This is the ONE certificate-transparency check —
// every verification path runs it (stele#173: CT is part of the
// stance, not a per-path option; the Sigstore client spec makes it a
// MUST for offline verification).
//
// The chain to a trusted Fulcio CA is built AT the countersigned
// instant, inside this construction: proving the SCT needs the
// issuer, and the issuer's vouching is only meaningful at a moment
// somebody attested. sigstore-go's own SCT verifier proves the same
// facts and discards the instant; this one must carry it, because
// the instant IS the value being constructed — the loop shape is
// shared with sigstore-go's sct.go and the cryptographic definition
// is ctutil.VerifySCT, unrepeated.
func (t *Verifier) observeCT(leaf *x509.Certificate) (ObservedInstant, error) {
	ctlogs := t.trusted.CTLogs()
	if len(ctlogs) == 0 {
		return ObservedInstant{}, errors.New("trust: the trusted root names no certificate transparency log")
	}

	scts, err := x509util.ParseSCTsFromCertificate(leaf.Raw)
	if err != nil {
		return ObservedInstant{}, fmt.Errorf("trust: signing certificate SCTs: %w", err)
	}

	if len(scts) == 0 {
		return ObservedInstant{}, errors.New(
			"trust: the signing certificate carries no signed certificate timestamp — nothing countersigns its issuance")
	}

	leafCT, err := ctx509.ParseCertificates(leaf.Raw)
	if err != nil {
		return ObservedInstant{}, fmt.Errorf("trust: signing certificate re-parse: %w", err)
	}

	var last error

	for _, sct := range scts {
		keyID := hex.EncodeToString(sct.LogID.KeyID[:])

		key, ok := ctlogs[keyID]
		if !ok {
			last = fmt.Errorf("trust: no trusted CT log carries key %s", keyID)

			continue
		}

		at := ct.TimestampToTime(sct.Timestamp)
		if (!key.ValidityPeriodStart.IsZero() && at.Before(key.ValidityPeriodStart)) ||
			(!key.ValidityPeriodEnd.IsZero() && at.After(key.ValidityPeriodEnd)) {
			last = fmt.Errorf("trust: SCT instant %s is outside CT log %s's validity", at.UTC().Format(time.RFC3339), keyID)

			continue
		}

		chains, cerr := t.chainsAt(leaf, at)
		if cerr != nil {
			last = cerr

			continue
		}

		if verr := verifySCTOverChains(key.PublicKey, leafCT, chains, sct); verr != nil {
			last = verr

			continue
		}

		return ObservedInstant{at: at, source: SourceCertificateTransparency, log: keyID}, nil
	}

	return ObservedInstant{}, fmt.Errorf(
		"trust: no trusted certificate transparency log countersigns the signing certificate: %w", last)
}

// verifySCTOverChains proves one SCT against one trusted CT log key,
// trying each vouched chain's issuer (an embedded SCT signs the
// precertificate, which names its issuer by key hash).
func verifySCTOverChains(
	key any, leafCT []*ctx509.Certificate, chains [][]*x509.Certificate, sct *ct.SignedCertificateTimestamp,
) error {
	last := errors.New("trust: no vouched chain carries an issuer")

	// A chain is leaf-then-issuer at minimum; the SCT names its
	// issuer by key hash, so a chain without one proves nothing.
	const leafAndIssuer = 2

	for _, chain := range chains {
		if len(chain) < leafAndIssuer {
			continue
		}

		issuer, perr := ctx509.ParseCertificates(chain[1].Raw)
		if perr != nil {
			last = perr

			continue
		}

		fulcioChain := append(append([]*ctx509.Certificate{}, leafCT...), issuer...)

		if verr := ctutil.VerifySCT(key, fulcioChain, sct, true); verr != nil {
			last = verr

			continue
		}

		return nil
	}

	return last
}

// chainsAt accepts the leaf if any trusted Fulcio CA builds a chain
// for it at the given instant. Unexported on purpose: the only
// callers are the ObservedInstant constructions, so no chain is ever
// built against a moment nobody countersigned.
func (t *Verifier) chainsAt(leaf *x509.Certificate, at time.Time) ([][]*x509.Certificate, error) {
	cas := t.trusted.FulcioCertificateAuthorities()
	if len(cas) == 0 {
		return nil, errors.New("trust: the trusted root names no certificate authority")
	}

	// Go does not implement the OtherName GeneralName SAN, so a leaf
	// Fulcio issued with one carries it as an unhandled critical
	// extension and path validation refuses. sigstore-go's own Verify
	// drops exactly that extension before chaining (the SAN is still
	// read through SummarizeCertificate); this chain must treat the
	// same leaf the same way.
	if len(leaf.UnhandledCriticalExtensions) > 0 {
		var unhandled []asn1.ObjectIdentifier

		for _, oid := range leaf.UnhandledCriticalExtensions {
			if !oid.Equal(cryptoutils.SANOID) {
				unhandled = append(unhandled, oid)
			}
		}

		leaf.UnhandledCriticalExtensions = unhandled
	}

	var last error

	for _, ca := range cas {
		chains, cerr := ca.Verify(leaf, at)
		if cerr == nil {
			return chains, nil
		}

		last = cerr
	}

	return nil, fmt.Errorf("trust: signing certificate chains to no trusted authority: %w", last)
}

// observedFromResult lifts sigstore-go's verified timestamps into
// ObservedInstants. Every timestamp in a VerificationResult is
// countersigned by construction: the verifier is configured to admit
// only transparency-log and timestamp-authority instants, each
// verified against the trusted root before it lands in the result.
func observedFromResult(result *verify.VerificationResult) []ObservedInstant {
	observed := make([]ObservedInstant, 0, len(result.VerifiedTimestamps))

	for _, ts := range result.VerifiedTimestamps {
		source := SourceTransparencyLog
		if ts.Type == "TimestampAuthority" {
			source = SourceTimestampAuthority
		}

		observed = append(observed, ObservedInstant{at: ts.Timestamp, source: source, log: ts.URI})
	}

	return observed
}
