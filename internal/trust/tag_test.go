// VerifyTag's table: a synthesized Fulcio-shaped CA issues a leaf
// with the identity extensions, a CMS is signed over a real tag
// payload, and every guard is exercised with exactly one fact broken.

package trust_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/monumental-archive/stele/internal/trust"
)

// tagWorld is one synthesized signing world: a CA trusted by the
// verifier, and a leaf that signed the payload.
type tagWorld struct {
	verifier *trust.Verifier
	payload  []byte
	sigPEM   []byte
	leaf     *x509.Certificate
	leafKey  *ecdsa.PrivateKey
}

// tagTaggerEpoch is anchored to the test run: the CMS signer stamps
// a wall-clock signingTime attribute that pkcs7 holds against the
// certificate window, so the synthesized certs must be valid NOW and
// the payload's tagger time must sit inside the same window.
var tagTaggerEpoch = time.Now().Unix()

func tagPayload(epoch int64) []byte {
	return fmt.Appendf(nil,
		"object 1111111111111111111111111111111111111111\ntype commit\ntag v1.0.0\n"+
			"tagger release-mint[bot] <mint@example.com> %d +0000\n\nrelease v1.0.0\n", epoch)
}

// material satisfies root.TrustedMaterial with exactly one Fulcio CA.
type material struct {
	root.BaseTrustedMaterial

	cas []root.CertificateAuthority
}

func (m *material) FulcioCertificateAuthorities() []root.CertificateAuthority { return m.cas }

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-fulcio"},
		NotBefore:             time.Unix(tagTaggerEpoch-3600, 0),
		NotAfter:              time.Unix(tagTaggerEpoch+3600, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return cert, key
}

// newLeaf issues a Fulcio-shaped leaf: SAN URI plus the issuer
// extension (OID 1.3.6.1.4.1.57264.1.8, DER UTF8String).
func newLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, san, issuer string,
	notBefore, notAfter time.Time,
) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	issuerDER, err := asn1.MarshalWithParams(issuer, "utf8")
	if err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(san)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:         []*url.URL{u},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, Value: issuerDER},
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return cert, key
}

func signCMS(t *testing.T, payload []byte, leaf *x509.Certificate, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	return buildCMS(t, payload, func(sd *pkcs7.SignedData) error {
		return sd.AddSigner(leaf, key, pkcs7.SignerInfoConfig{})
	})
}

// signCMSWithoutAttributes signs with no authenticated attributes at
// all — the shape a signature takes when it declares no signing
// time. pkcs7 accepts it and silently skips its own window check,
// which is why requireSigningTime exists.
func signCMSWithoutAttributes(t *testing.T, payload []byte, leaf *x509.Certificate, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	return buildCMS(t, payload, func(sd *pkcs7.SignedData) error {
		return sd.SignWithoutAttr(leaf, key, pkcs7.SignerInfoConfig{})
	})
}

func buildCMS(t *testing.T, payload []byte, sign func(*pkcs7.SignedData) error) []byte {
	t.Helper()

	sd, err := pkcs7.NewSignedData(payload)
	if err != nil {
		t.Fatal(err)
	}

	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)

	if serr := sign(sd); serr != nil {
		t.Fatal(serr)
	}

	sd.Detach()

	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: der})
}

const tagSAN = "https://github.com/acme/widget/.github/workflows/release.yml@refs/tags/v1.0.0"

// newTagWorld builds the happy path; tests break one fact each.
func newTagWorld(t *testing.T) tagWorld {
	t.Helper()

	ca, caKey := newCA(t)
	leaf, leafKey := newLeaf(t, ca, caKey, tagSAN, "https://token.example.com",
		time.Unix(tagTaggerEpoch-300, 0), time.Unix(tagTaggerEpoch+300, 0))

	payload := tagPayload(tagTaggerEpoch)

	m := &material{cas: []root.CertificateAuthority{
		&root.FulcioCertificateAuthority{
			Root:                ca,
			ValidityPeriodStart: ca.NotBefore,
			ValidityPeriodEnd:   ca.NotAfter,
		},
	}}

	v, err := trust.NewVerifier(m)
	if err != nil {
		t.Fatal(err)
	}

	return tagWorld{
		verifier: v, payload: payload, sigPEM: signCMS(t, payload, leaf, leafKey),
		leaf: leaf, leafKey: leafKey,
	}
}

func tagID() trust.TagIdentity {
	return trust.TagIdentity{
		SANPattern: regexp.MustCompile(`^https://github\.com/acme/`),
		Issuer:     "https://token.example.com",
	}
}

func TestVerifyTag(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)

	san, err := w.verifier.VerifyTag(w.payload, w.sigPEM, tagID())
	if err != nil {
		t.Fatalf("VerifyTag = %v", err)
	}

	if san != tagSAN {
		t.Fatalf("san = %q, want %q", san, tagSAN)
	}
}

func TestVerifyTagRefusals(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)

	taggerless := []byte("object 1111111111111111111111111111111111111111\ntype commit\ntag v1\n\nmsg\n")

	tests := []struct {
		name    string
		payload []byte
		sig     []byte
		id      trust.TagIdentity
		want    string
	}{
		{"tampered payload", tagPayload(tagTaggerEpoch + 1), w.sigPEM, tagID(), "does not verify"},
		{"not PEM", w.payload, []byte("junk"), tagID(), "not PEM"},
		{
			"not CMS", w.payload,
			pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: []byte("junk")}),
			tagID(), "not CMS",
		},
		{
			"wrong issuer", w.payload, w.sigPEM,
			trust.TagIdentity{
				SANPattern: regexp.MustCompile(`^https://github\.com/acme/`),
				Issuer:     "https://other.example.com",
			},
			"issuer",
		},
		{
			"SAN outside the pattern", w.payload, w.sigPEM,
			trust.TagIdentity{
				SANPattern: regexp.MustCompile(`^https://github\.com/rival/`),
				Issuer:     "https://token.example.com",
			},
			"identity pattern",
		},
		{
			"no tagger line",
			taggerless,
			signCMS(t, taggerless, w.leaf, w.leafKey), tagID(), "no tagger line",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := w.verifier.VerifyTag(tt.payload, tt.sig, tt.id); err == nil ||
				!strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

// TestVerifyTagUntrustedCA: a signature chaining to a CA the trusted
// root does not carry refuses.
func TestVerifyTagUntrustedCA(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)
	rogue := newTagWorld(t)

	// rogue's signature against w's trust: same shape, wrong root.
	if _, err := w.verifier.VerifyTag(rogue.payload, rogue.sigPEM, tagID()); err == nil ||
		!strings.Contains(err.Error(), "chains to no trusted authority") {
		t.Fatalf("error = %v, want the chain refusal", err)
	}
}

// TestVerifyTagCertificateAuthorityGeneration: the observation
// instant selects WHICH CA generation is asked to vouch, so a leaf
// issued before the trusted root says that authority began refuses.
// This is the question chainToFulcio exists to ask, and the only one
// its instant decides.
func TestVerifyTagCertificateAuthorityGeneration(t *testing.T) {
	t.Parallel()

	ca, caKey := newCA(t)
	leaf, leafKey := newLeaf(t, ca, caKey, tagSAN, "https://token.example.com",
		time.Unix(tagTaggerEpoch-300, 0), time.Unix(tagTaggerEpoch+300, 0))

	// The authority's declared period opens AFTER the leaf was
	// issued: this generation did not exist to issue it.
	m := &material{cas: []root.CertificateAuthority{
		&root.FulcioCertificateAuthority{
			Root:                ca,
			ValidityPeriodStart: time.Unix(tagTaggerEpoch-100, 0),
			ValidityPeriodEnd:   ca.NotAfter,
		},
	}}

	v, err := trust.NewVerifier(m)
	if err != nil {
		t.Fatal(err)
	}

	payload := tagPayload(tagTaggerEpoch)

	if _, verr := v.VerifyTag(payload, signCMS(t, payload, leaf, leafKey), tagID()); verr == nil ||
		!strings.Contains(verr.Error(), "chains to no trusted authority") {
		t.Fatalf("error = %v, want the authority-generation refusal", verr)
	}
}

// TestVerifyTagIssuanceAfterTheTaggerClock is stele#167's regression,
// stated as the live defect stated it: git stamps the tag object and
// only then does the mint request a certificate, so an honest tag is
// routinely stamped one second BEFORE its certificate was issued.
// Every failure measured against the org's live tags was exactly this
// one second. It must verify.
func TestVerifyTagIssuanceAfterTheTaggerClock(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)

	// The leaf opens at tagTaggerEpoch-300; stamp the tag one second
	// before that instant, the shape the mint actually produces.
	payload := tagPayload(tagTaggerEpoch - 301)

	san, err := w.verifier.VerifyTag(payload, signCMS(t, payload, w.leaf, w.leafKey), tagID())
	if err != nil {
		t.Fatalf("VerifyTag = %v, want a tag stamped one second before issuance to verify", err)
	}

	if san != tagSAN {
		t.Fatalf("san = %q, want %q", san, tagSAN)
	}
}

// TestVerifyTagTaggerWindow walks the whole bound
// taggerWithinCertificate derives from the certificate: a tag may sit
// anywhere from one certificate lifetime before issuance to the
// certificate's expiry, and nowhere else. The world's leaf runs
// [epoch-300, epoch+300], so its lifetime is 600s and the earliest
// admissible stamp is epoch-900.
func TestVerifyTagTaggerWindow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		tagger int64
		want   string
	}{
		{"one second before issuance — the #167 shape", tagTaggerEpoch - 301, ""},
		{"the same second as issuance", tagTaggerEpoch - 300, ""},
		{"exactly one certificate lifetime before issuance", tagTaggerEpoch - 900, ""},
		{"a second beyond one certificate lifetime", tagTaggerEpoch - 901, "outside the window"},
		{"exactly at expiry", tagTaggerEpoch + 300, ""},
		{"a second past expiry", tagTaggerEpoch + 301, "outside the window"},
		{"far past expiry", tagTaggerEpoch + 7200, "outside the window"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newTagWorld(t)
			payload := tagPayload(tt.tagger)

			_, err := w.verifier.VerifyTag(payload, signCMS(t, payload, w.leaf, w.leafKey), tagID())

			if tt.want == "" {
				if err != nil {
					t.Fatalf("VerifyTag = %v, want the tag to verify", err)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

// TestVerifyTagWithoutSigningTime: pkcs7 holds the CMS signing time
// against the certificate window only when the attribute is PRESENT,
// and returns success when it is absent. A guard a forger deletes by
// deleting a field is not a guard, so presence is required here.
func TestVerifyTagWithoutSigningTime(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)
	sig := signCMSWithoutAttributes(t, w.payload, w.leaf, w.leafKey)

	if _, err := w.verifier.VerifyTag(w.payload, sig, tagID()); err == nil ||
		!strings.Contains(err.Error(), "declares no signing time") {
		t.Fatalf("error = %v, want the absent-signing-time refusal", err)
	}
}

// TestVerifyTagTaggerLineShapes: the tagger line is git's own format
// and carries the tag's own account of when it was made, which
// taggerWithinCertificate holds against the signing certificate, so
// every shape that cannot yield one refuses. Defaulting the time here
// would hold a certificate against an instant no evidence states.
func TestVerifyTagTaggerLineShapes(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)

	tests := []struct {
		name    string
		payload []byte
		want    string
	}{
		{
			name: "a tagger line with no timestamp at all",
			payload: []byte("object 1111111111111111111111111111111111111111\ntype commit\ntag v1\n" +
				"tagger release-mint[bot]\n\nmsg\n"),
			want: "no tagger line",
		},
		{
			name: "a tagger timestamp that is not a number",
			payload: []byte("object 1111111111111111111111111111111111111111\ntype commit\ntag v1\n" +
				"tagger release-mint[bot] <mint@example.com> whenever +0000\n\nmsg\n"),
			want: "tagger timestamp",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sig := signCMS(t, tc.payload, w.leaf, w.leafKey)

			if _, err := w.verifier.VerifyTag(tc.payload, sig, tagID()); err == nil ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// TestVerifyTagWithoutACertificateAuthority: a trusted root naming no
// Fulcio CA vouches for nothing, and the refusal must say so rather
// than fall through the empty loop as "chains to no authority" — the
// two are different faults, one in the root and one in the signature.
func TestVerifyTagWithoutACertificateAuthority(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)

	empty, err := trust.NewVerifier(&material{})
	if err != nil {
		t.Fatalf("NewVerifier = %v", err)
	}

	if _, err := empty.VerifyTag(w.payload, w.sigPEM, tagID()); err == nil ||
		!strings.Contains(err.Error(), "names no certificate authority") {
		t.Fatalf("error = %v, want the empty-root refusal", err)
	}
}
