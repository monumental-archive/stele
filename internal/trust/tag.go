// Gitsign tag verification: the x509-in-the-PGP-slot signature a
// gitsign mint leaves on an annotated tag, verified natively — no
// gitsign binary on the runner (stele#83). The signature block is a
// PEM-wrapped CMS SignedData, detached over the tag payload (the tag
// object with the signature block removed). Verification is:
//
//  1. CMS signature integrity over the payload, and the signer's own
//     signing instant held inside the certificate that signed it —
//     both from digitorus/pkcs7, the module sigstore's timestamp
//     path already pins. See requireSigningTime for the half pkcs7
//     will not do.
//  2. Certificate chain to the trusted root's Fulcio CAs through
//     sigstore-go's own CA verification, observed at the
//     certificate's issuance instant. See chainToFulcio: the
//     observation instant is not a parameter, and that is the point.
//  3. The payload's tagger clock against the certificate that signed
//     it, bounded by the certificate itself. See
//     taggerWithinCertificate.
//  4. Certificate identity: the Fulcio issuer extension equal to the
//     policy issuer, and the SAN matched against the policy's
//     identity pattern.
//
// Integrity bound, stated plainly (stele#167 owed this in writing).
// NOTHING read here is a countersigned timestamp. The tagger line
// and the signingTime attribute are both authored by the signer,
// inside material the signer produced; a certificate holds them only
// against a window Fulcio chose. So steps 1 and 3 prove CONSISTENCY
// — that the tag's own account of when it was made agrees with the
// certificate that signed it — and they never prove WHEN. Reading
// either of them as an independent anchor was the defect #167
// recorded: it bought no property against any adversary, and it
// reddened honest tags whenever the mint crossed a second boundary
// between git's stamp and Fulcio's issuance — measured over every
// gitsign tag inside the org's two declared epochs, 10 of 43, each
// by exactly one second.
//
// The observer timestamp the bundle path requires (see NewVerifier)
// has no counterpart here, and no bound in this file can supply one.
// A gitsign signature CAN carry its own Rekor entry as a CMS
// unsigned attribute (OID 1.3.6.1.4.1.57264.3.1), which would make
// the tag path offline-verifiable against a real countersigned
// instant on the same stance as every other artifact. No tag this
// org has minted carries one (measured: 0 of 43). That is a gap in
// the mint, not a choice of this verifier.

package trust

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
)

// TagIdentity is the trust expectation for one tag signature: the
// exact OIDC issuer and a compiled pattern over the certificate SAN.
type TagIdentity struct {
	SANPattern *regexp.Regexp
	Issuer     string
}

// VerifyTag proves one gitsign tag signature: CMS over the payload,
// a declared signing instant, a chain to a trusted Fulcio CA, a
// tagger clock consistent with the certificate, and the certificate
// identity. Returns the verified certificate's SAN.
func (t *Verifier) VerifyTag(payload, sigPEM []byte, id TagIdentity) (string, error) {
	block, _ := pem.Decode(sigPEM)
	if block == nil {
		return "", errors.New("trust: tag signature is not PEM")
	}

	p7, err := pkcs7.Parse(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("trust: tag signature is not CMS: %w", err)
	}

	p7.Content = payload

	if verr := p7.Verify(); verr != nil {
		return "", fmt.Errorf("trust: tag signature does not verify over the tag payload: %w", verr)
	}

	leaf := p7.GetOnlySigner()
	if leaf == nil {
		return "", errors.New("trust: tag signature carries no single signer certificate")
	}

	if serr := requireSigningTime(p7); serr != nil {
		return "", serr
	}

	if cerr := t.chainToFulcio(leaf); cerr != nil {
		return "", cerr
	}

	if terr := taggerWithinCertificate(payload, leaf); terr != nil {
		return "", terr
	}

	return tagIdentity(leaf, id)
}

// requireSigningTime proves the CMS carries its RFC 5652 signingTime
// signed attribute.
//
// The WINDOW check — that instant inside the certificate's validity
// — is pkcs7's, already run by Verify above, and is deliberately not
// repeated here: two places deciding one fact is how they come to
// disagree. What pkcs7 will not do is refuse a signature that simply
// OMITS the attribute; it skips its check and returns success, so a
// forger deletes the check by deleting the field. Presence is
// therefore stele's to require, and it costs nothing honest: every
// tag inside the org's declared epochs carries one (43 of 43).
func requireSigningTime(p7 *pkcs7.PKCS7) error {
	var signed time.Time

	if err := p7.UnmarshalSignedAttribute(pkcs7.OIDAttributeSigningTime, &signed); err != nil {
		return fmt.Errorf("trust: tag signature declares no signing time: %w", err)
	}

	return nil
}

// chainToFulcio accepts the leaf if any trusted Fulcio CA builds a
// chain for it at the certificate's own issuance instant.
//
// The observation instant is NOT a parameter, and that is the whole
// design (stele#167). What the instant selects is which CA
// generation is asked to vouch — sigstore's hybrid model, where a
// signature holds only if every certificate up the chain was valid
// at one instant — and the only instant at which a ten-minute leaf
// and a years-long CA are jointly meaningful is the leaf's issuance.
// NotBefore is the CA's own statement of that instant, is present on
// every certificate, and lies inside the leaf's window by
// construction, so this call cannot redden a healthy tag over a
// clock. A time that can be passed in is a time that can be passed
// in wrong.
//
// What this deliberately does NOT prove is that the signature was
// made while the certificate was live. Only a countersigned
// timestamp proves that (see the integrity bound at the head of this
// file). A signer-authored instant fed in here would wear that
// proof's shape and carry none.
func (t *Verifier) chainToFulcio(leaf *x509.Certificate) error {
	cas := t.trusted.FulcioCertificateAuthorities()
	if len(cas) == 0 {
		return errors.New("trust: the trusted root names no certificate authority")
	}

	var last error

	for _, ca := range cas {
		_, cerr := ca.Verify(leaf, leaf.NotBefore)
		if cerr == nil {
			return nil
		}

		last = cerr
	}

	return fmt.Errorf("trust: tag signing certificate chains to no trusted authority: %w", last)
}

// taggerWithinCertificate holds the payload's tagger clock against
// the certificate that signed it.
//
// The bound is DERIVED, never declared: a tag may not claim a time
// after its certificate expires, nor more than one certificate
// lifetime before that certificate was issued. Nobody chooses that
// number — the certificate states its own tolerance by stating its
// own window — so it cannot be widened under pressure, which is what
// a declared tolerance eventually becomes.
//
// The asymmetry is the mint's real shape: git stamps the tagger line
// from the tagging process's clock and only then invokes the signer,
// so an honest tagger time PRECEDES issuance by the mint's latency
// (measured across both declared epochs: zero or one second, never
// more, never negative) and can never legitimately follow the
// certificate's expiry.
func taggerWithinCertificate(payload []byte, leaf *x509.Certificate) error {
	tagged, err := taggerTime(payload)
	if err != nil {
		return err
	}

	earliest := leaf.NotBefore.Add(-leaf.NotAfter.Sub(leaf.NotBefore))

	if tagged.Before(earliest) || tagged.After(leaf.NotAfter) {
		return fmt.Errorf(
			"trust: the tag is stamped %s, outside the window its signing certificate allows (%s to %s)",
			tagged.UTC().Format(time.RFC3339),
			earliest.UTC().Format(time.RFC3339),
			leaf.NotAfter.UTC().Format(time.RFC3339))
	}

	return nil
}

// tagIdentity holds the leaf's Fulcio identity against the
// expectation and returns the SAN that matched.
func tagIdentity(leaf *x509.Certificate, id TagIdentity) (string, error) {
	ext, err := certificate.ParseExtensions(leaf.Extensions)
	if err != nil {
		return "", fmt.Errorf("trust: tag signing certificate extensions: %w", err)
	}

	if ext.Issuer != id.Issuer {
		return "", fmt.Errorf("trust: tag signing certificate issuer %q is not %q", ext.Issuer, id.Issuer)
	}

	san := ""

	for _, uri := range leaf.URIs {
		if id.SANPattern.MatchString(uri.String()) {
			san = uri.String()

			break
		}
	}

	if san == "" {
		return "", fmt.Errorf(
			"trust: no certificate SAN matches the declared identity pattern %q", id.SANPattern.String())
	}

	return san, nil
}

// taggerTime reads the tagger timestamp out of the signed payload —
// the tag's own account of when it was made, which
// taggerWithinCertificate holds against the signing certificate. The
// line is `tagger NAME <EMAIL> UNIX TZ`, git's own format; a payload
// without one is not an annotated tag and refuses.
func taggerTime(payload []byte) (time.Time, error) {
	for line := range strings.SplitSeq(string(payload), "\n") {
		if line == "" {
			// Headers end at the first blank line; a tagger below it
			// would be message text, not metadata.
			break
		}

		if !strings.HasPrefix(line, "tagger ") {
			continue
		}

		fields := strings.Fields(line)
		const tzAndEpoch = 2

		if len(fields) < tzAndEpoch+1 {
			break
		}

		epoch, err := strconv.ParseInt(fields[len(fields)-tzAndEpoch], 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("trust: tag payload tagger timestamp: %w", err)
		}

		return time.Unix(epoch, 0), nil
	}

	return time.Time{}, errors.New("trust: tag payload carries no tagger line")
}
