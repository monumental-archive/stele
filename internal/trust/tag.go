// Gitsign tag verification: the x509-in-the-PGP-slot signature a
// gitsign mint leaves on an annotated tag, verified natively — no
// gitsign binary on the runner (stele#83). The signature block is a
// PEM-wrapped CMS SignedData, detached over the tag payload (the tag
// object with the signature block removed). Verification is:
//
//  1. CMS signature integrity over the payload (digitorus/pkcs7 —
//     the same module sigstore's timestamp path already pins).
//  2. Certificate chain to the trusted root's Fulcio CAs through
//     sigstore-go's own CA verification, observed at the tagger
//     timestamp the signed payload itself carries.
//  3. Certificate identity: the Fulcio issuer extension equal to the
//     policy issuer, and the SAN matched against the policy's
//     identity pattern.
//
// Integrity bound, stated plainly: without a transparency-log or TSA
// countersignature this is gitsign's offline stance — the signing
// window is anchored by the certificate's own validity against the
// signed payload's tagger time. The shadow run against the live org
// is the gate before any cutover relies on it.

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
// chain to a trusted Fulcio CA at the payload's tagger time, and the
// certificate identity. Returns the verified certificate's SAN.
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

	observed, err := taggerTime(payload)
	if err != nil {
		return "", err
	}

	if err := t.chainToFulcio(leaf, observed); err != nil {
		return "", err
	}

	return tagIdentity(leaf, id)
}

// chainToFulcio accepts the leaf if any trusted Fulcio CA builds a
// chain for it at the observed time.
func (t *Verifier) chainToFulcio(leaf *x509.Certificate, observed time.Time) error {
	cas := t.trusted.FulcioCertificateAuthorities()
	if len(cas) == 0 {
		return errors.New("trust: the trusted root names no certificate authority")
	}

	var last error

	for _, ca := range cas {
		_, cerr := ca.Verify(leaf, observed)
		if cerr == nil {
			return nil
		}

		last = cerr
	}

	return fmt.Errorf("trust: tag signing certificate chains to no trusted authority: %w", last)
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
// the observation time the certificate window is held against. The
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
