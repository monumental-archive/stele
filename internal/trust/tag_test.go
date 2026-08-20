// VerifyTag's table: the synthesized world (world_test.go) issues an
// SCT-carrying leaf with the identity extensions, a CMS is signed
// over a real tag payload, and every guard is exercised with exactly
// one fact broken — including the countersignature guards stele#173
// added: a floor the evidence cannot meet, a leaf nothing
// countersigns, a root naming no CT log, and a Rekor receipt that
// does not match its signature.

package trust_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/sigstore/rekor/pkg/types/hashedrekord"
	"github.com/sigstore/sigstore-go/pkg/root"
	"google.golang.org/protobuf/proto"

	"github.com/monumental-archive/stele/internal/trust"
)

// tagWorld is one synthesized signing world: the shared world's
// anchors, and a leaf that signed the payload.
type tagWorld struct {
	world    *world
	verifier *trust.Verifier
	payload  []byte
	sigPEM   []byte
	leaf     *x509.Certificate
	leafKey  *ecdsa.PrivateKey
}

func tagPayload(epoch int64) []byte {
	return fmt.Appendf(nil,
		"object 1111111111111111111111111111111111111111\ntype commit\ntag v1.0.0\n"+
			"tagger release-mint[bot] <mint@example.com> %d +0000\n\nrelease v1.0.0\n", epoch)
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

	w := newWorld(t)

	leaf, leafKey := w.issueLeaf(t, &leafSpec{
		san: tagSAN, issuer: "https://token.example.com",
		notBefore: time.Unix(worldEpoch-300, 0), notAfter: time.Unix(worldEpoch+300, 0),
	})

	payload := tagPayload(worldEpoch)

	v, err := trust.NewVerifier(w.material(t))
	if err != nil {
		t.Fatal(err)
	}

	return tagWorld{
		world: w, verifier: v, payload: payload,
		sigPEM: signCMS(t, payload, leaf, leafKey),
		leaf:   leaf, leafKey: leafKey,
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

	verdict, err := w.verifier.VerifyTag(w.payload, w.sigPEM, tagID(), trust.TagFloorCertificateTransparency)
	if err != nil {
		t.Fatalf("VerifyTag = %v", err)
	}

	if verdict.SAN != tagSAN {
		t.Fatalf("san = %q, want %q", verdict.SAN, tagSAN)
	}

	if verdict.Depth != trust.TagFloorCertificateTransparency {
		t.Fatalf("depth = %q, want %q", verdict.Depth, trust.TagFloorCertificateTransparency)
	}

	if len(verdict.Observed) != 1 {
		t.Fatalf("observed = %v, want exactly the countersigned issuance", verdict.Observed)
	}

	got := verdict.Observed[0]
	if got.Source() != trust.SourceCertificateTransparency || got.Log() == "" {
		t.Errorf("observed instant %v does not name the CT log that carries it", got)
	}

	if !got.Time().Equal(w.leaf.NotBefore) {
		t.Errorf("observed instant %v is not the countersigned issuance %v", got.Time(), w.leaf.NotBefore)
	}
}

// TestVerifyTagObserverFloorWithoutReceipts: a floor the evidence
// cannot meet refuses honestly, naming what is missing — the tool
// never rounds a declared floor down (stele#173).
func TestVerifyTagObserverFloorWithoutReceipts(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)

	if _, err := w.verifier.VerifyTag(w.payload, w.sigPEM, tagID(), trust.TagFloorObserverTimestamp); err == nil ||
		!strings.Contains(err.Error(), "the declared floor requires one") {
		t.Fatalf("error = %v, want the unmet-floor refusal", err)
	}
}

// TestVerifyTagUnknownFloor: a floor this verifier does not judge is
// refused as such, so a policy typo cannot select a depth by
// accident.
func TestVerifyTagUnknownFloor(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)

	if _, err := w.verifier.VerifyTag(w.payload, w.sigPEM, tagID(), trust.TagFloor("everything")); err == nil ||
		!strings.Contains(err.Error(), "unknown tag proof floor") {
		t.Fatalf("error = %v, want the unknown-floor refusal", err)
	}
}

// TestVerifyTagWithoutSCT: a leaf whose issuance nothing countersigns
// cannot yield an observed instant, and without one there is no
// moment to hold the chain against — the stance refuses (stele#173
// invariant 1, as a runtime guard for material that predates it).
func TestVerifyTagWithoutSCT(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)

	leaf, key := w.world.issueLeaf(t, &leafSpec{
		san: tagSAN, issuer: "https://token.example.com",
		notBefore: time.Unix(worldEpoch-300, 0), notAfter: time.Unix(worldEpoch+300, 0),
		noSCT: true,
	})

	sig := signCMS(t, w.payload, leaf, key)

	if _, err := w.verifier.VerifyTag(w.payload, sig, tagID(), trust.TagFloorCertificateTransparency); err == nil ||
		!strings.Contains(err.Error(), "no signed certificate timestamp") {
		t.Fatalf("error = %v, want the missing-SCT refusal", err)
	}
}

// TestVerifyTagWithoutACTLog: a trusted root naming no certificate
// transparency log can countersign nothing, and the refusal names
// the root's gap rather than blaming the signature.
func TestVerifyTagWithoutACTLog(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)

	m := w.world.material(t)
	m.ctlogs = nil

	v, err := trust.NewVerifier(m)
	if err != nil {
		t.Fatal(err)
	}

	if _, verr := v.VerifyTag(w.payload, w.sigPEM, tagID(), trust.TagFloorCertificateTransparency); verr == nil ||
		!strings.Contains(verr.Error(), "names no certificate transparency log") {
		t.Fatalf("error = %v, want the empty-CT-root refusal", verr)
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
		{"tampered payload", tagPayload(worldEpoch + 1), w.sigPEM, tagID(), "does not verify"},
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
			"identity",
		},
		{
			"SAN outside the pattern", w.payload, w.sigPEM,
			trust.TagIdentity{
				SANPattern: regexp.MustCompile(`^https://github\.com/rival/`),
				Issuer:     "https://token.example.com",
			},
			"identity",
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

			if _, err := w.verifier.VerifyTag(tt.payload, tt.sig, tt.id,
				trust.TagFloorCertificateTransparency); err == nil ||
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
	if _, err := w.verifier.VerifyTag(rogue.payload, rogue.sigPEM, tagID(),
		trust.TagFloorCertificateTransparency); err == nil ||
		!strings.Contains(err.Error(), "countersigns") {
		t.Fatalf("error = %v, want the foreign-world refusal", err)
	}
}

// TestVerifyTagCertificateAuthorityGeneration: the countersigned
// instant selects WHICH CA generation is asked to vouch, so a leaf
// countersigned before the trusted root says that authority began
// refuses — this generation did not exist to issue it.
func TestVerifyTagCertificateAuthorityGeneration(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)

	m := w.world.material(t)
	// The authority's declared period opens AFTER the leaf's
	// countersigned issuance: this generation did not exist to
	// issue it.
	m.cas = []root.CertificateAuthority{
		&root.FulcioCertificateAuthority{
			Root:                w.world.caCert,
			ValidityPeriodStart: time.Unix(worldEpoch-100, 0),
			ValidityPeriodEnd:   w.world.caCert.NotAfter,
		},
	}

	v, err := trust.NewVerifier(m)
	if err != nil {
		t.Fatal(err)
	}

	if _, verr := v.VerifyTag(w.payload, w.sigPEM, tagID(), trust.TagFloorCertificateTransparency); verr == nil ||
		!strings.Contains(verr.Error(), "chains to no trusted authority") {
		t.Fatalf("error = %v, want the authority-generation refusal", verr)
	}
}

// TestVerifyTagTaggerWindow walks the whole bound taggerConsistent
// derives from the certificate, anchored at the countersigned
// issuance: a tag may sit anywhere from one certificate lifetime
// before that instant to the certificate's expiry, and nowhere else.
// The world's leaf runs [epoch-300, epoch+300] with its SCT at
// issuance, so its lifetime is 600s and the earliest admissible
// stamp is epoch-900.
func TestVerifyTagTaggerWindow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		tagger int64
		want   string
	}{
		{"one second before issuance — the #167 shape", worldEpoch - 301, ""},
		{"the same second as issuance", worldEpoch - 300, ""},
		{"exactly one certificate lifetime before issuance", worldEpoch - 900, ""},
		{"a second beyond one certificate lifetime", worldEpoch - 901, "outside the window"},
		{"exactly at expiry", worldEpoch + 300, ""},
		{"a second past expiry", worldEpoch + 301, "outside the window"},
		{"far past expiry", worldEpoch + 7200, "outside the window"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newTagWorld(t)
			payload := tagPayload(tt.tagger)

			_, err := w.verifier.VerifyTag(payload, signCMS(t, payload, w.leaf, w.leafKey), tagID(),
				trust.TagFloorCertificateTransparency)

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

	if _, err := w.verifier.VerifyTag(w.payload, sig, tagID(), trust.TagFloorCertificateTransparency); err == nil ||
		!strings.Contains(err.Error(), "declares no signing time") {
		t.Fatalf("error = %v, want the absent-signing-time refusal", err)
	}
}

// TestVerifyTagTaggerLineShapes: the tagger line is git's own format
// and carries the tag's own account of when it was made, which
// taggerConsistent holds against the countersigned issuance, so
// every shape that cannot yield one refuses. Defaulting the time
// here would hold a certificate against an instant no evidence
// states.
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

			if _, err := w.verifier.VerifyTag(tc.payload, sig, tagID(),
				trust.TagFloorCertificateTransparency); err == nil ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// TestVerifyTagWithoutACertificateAuthority: a trusted root naming no
// Fulcio CA vouches for nothing, and the refusal must say so rather
// than blame the signature — the fault is in the root.
func TestVerifyTagWithoutACertificateAuthority(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)

	m := w.world.material(t)
	m.cas = nil

	empty, err := trust.NewVerifier(m)
	if err != nil {
		t.Fatalf("NewVerifier = %v", err)
	}

	if _, err := empty.VerifyTag(w.payload, w.sigPEM, tagID(), trust.TagFloorCertificateTransparency); err == nil ||
		!strings.Contains(err.Error(), "names no certificate authority") {
		t.Fatalf("error = %v, want the empty-root refusal", err)
	}
}

// TestVerifyTagWithReceipt: a tag whose mint embedded its Rekor entry
// reaches the observer-timestamp depth through the SAME verifier the
// bundle path uses — offline, against a real countersigned
// observation of the signature. Both floors accept it; the verdict
// states the depth actually reached.
func TestVerifyTagWithReceipt(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)
	sig := attachReceipt(t, &w, w.sigPEM, false)

	for _, floor := range []trust.TagFloor{trust.TagFloorCertificateTransparency, trust.TagFloorObserverTimestamp} {
		verdict, err := w.verifier.VerifyTag(w.payload, sig, tagID(), floor)
		if err != nil {
			t.Fatalf("VerifyTag(floor %s) = %v", floor, err)
		}

		if verdict.Depth != trust.TagFloorObserverTimestamp {
			t.Fatalf("depth = %q, want %q", verdict.Depth, trust.TagFloorObserverTimestamp)
		}

		if verdict.SAN != tagSAN {
			t.Fatalf("san = %q, want %q", verdict.SAN, tagSAN)
		}

		sources := map[string]bool{}
		for _, o := range verdict.Observed {
			sources[o.Source()] = true
		}

		if !sources[trust.SourceTransparencyLog] || !sources[trust.SourceCertificateTransparency] {
			t.Fatalf("observed = %v, want both the log observation and the countersigned issuance", verdict.Observed)
		}
	}
}

// TestVerifyTagWithMismatchedReceipt: a receipt whose log entry does
// not match the signature it rides on is tampering-shaped and
// refuses loudly — even at a floor that never asked for a receipt.
func TestVerifyTagWithMismatchedReceipt(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)
	sig := attachReceipt(t, &w, w.sigPEM, true)

	if _, err := w.verifier.VerifyTag(w.payload, sig, tagID(), trust.TagFloorCertificateTransparency); err == nil ||
		!strings.Contains(err.Error(), "countersignatures do not verify") {
		t.Fatalf("error = %v, want the mismatched-receipt refusal", err)
	}
}

// TestVerifyTagWithMalformedReceipt: a receipt that does not even
// decode refuses — a malformed countersignature is never fallen back
// from.
func TestVerifyTagWithMalformedReceipt(t *testing.T) {
	t.Parallel()

	w := newTagWorld(t)
	sig := attachRawReceipt(t, w.sigPEM, []byte("not a protobuf entry at all, definitely not"))

	if _, err := w.verifier.VerifyTag(w.payload, sig, tagID(), trust.TagFloorCertificateTransparency); err == nil ||
		!strings.Contains(err.Error(), "does not decode") {
		t.Fatalf("error = %v, want the malformed-receipt refusal", err)
	}
}

// attachReceipt mints a Rekor entry over the CMS's signed-attribute
// blob (or, when mismatch is set, a genuine entry for DIFFERENT
// bytes — a receipt for something else, sealed by the same log) and
// rides it into the signature's unsigned attributes the way a
// gitsign offline mint does.
func attachReceipt(t *testing.T, w *tagWorld, sigPEM []byte, mismatch bool) []byte {
	t.Helper()

	blob, sig := cmsSignedPieces(t, sigPEM)

	if mismatch {
		blob = append([]byte("tampered"), blob...)

		digest := sha256.Sum256(blob)

		var err error

		sig, err = ecdsa.SignASN1(rand.Reader, w.leafKey, digest[:])
		if err != nil {
			t.Fatal(err)
		}
	}

	body := w.world.rekorBody(t, hashedrekord.KIND, blob, sig, w.leaf, time.Unix(worldEpoch, 0))

	pb, err := proto.Marshal(w.world.rekorProto(t, body, time.Unix(worldEpoch, 0)))
	if err != nil {
		t.Fatal(err)
	}

	return attachRawReceipt(t, sigPEM, pb)
}

// The raw-CMS mirror structures the surgery below marshals through;
// RawValue fields carry original bytes verbatim, so nothing the
// signature covers is re-encoded.
type rawContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type rawSignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue `asn1:"set"`
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	SignerInfos      []rawSignerInfo `asn1:"set"`
}

type rawSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type rawAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// cmsSignedPieces reads the signed-attribute blob (SET-retagged, the
// bytes the signature covers and a gitsign mint logs) and the
// signature out of a PEM CMS.
//
//nolint:gocritic // unnamedResult: the blob, then the signature
func cmsSignedPieces(t *testing.T, sigPEM []byte) ([]byte, []byte) {
	t.Helper()

	sd, _ := parseRawCMS(t, sigPEM)
	si := sd.SignerInfos[0]

	blob := make([]byte, len(si.SignedAttrs.FullBytes))
	copy(blob, si.SignedAttrs.FullBytes)
	blob[0] = 0x31

	return blob, si.Signature
}

func parseRawCMS(t *testing.T, sigPEM []byte) (rawSignedData, asn1.ObjectIdentifier) {
	t.Helper()

	block, _ := pem.Decode(sigPEM)
	if block == nil {
		t.Fatal("test CMS is not PEM")
	}

	var ci rawContentInfo
	if _, err := asn1.Unmarshal(block.Bytes, &ci); err != nil {
		t.Fatal(err)
	}

	var sd rawSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatal(err)
	}

	if len(sd.SignerInfos) != 1 {
		t.Fatalf("test CMS carries %d signers", len(sd.SignerInfos))
	}

	return sd, ci.ContentType
}

// attachRawReceipt splices the given bytes into the CMS as the
// gitsign transparency-log-entry unsigned attribute (an OCTET STRING
// under OID 1.3.6.1.4.1.57264.3.1) and re-serializes everything else
// byte-identically.
func attachRawReceipt(t *testing.T, sigPEM, receipt []byte) []byte {
	t.Helper()

	sd, contentType := parseRawCMS(t, sigPEM)

	attrs, err := asn1.MarshalWithParams([]rawAttribute{{
		Type:   asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 3, 1},
		Values: mustMarshalSet(t, receipt),
	}}, "set")
	if err != nil {
		t.Fatal(err)
	}

	// SET OF → [1] IMPLICIT, the tag UnsignedAttrs carries in a
	// SignerInfo.
	attrs[0] = 0xA1
	sd.SignerInfos[0].UnsignedAttrs = asn1.RawValue{FullBytes: attrs}

	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}

	ciDER, err := asn1.Marshal(rawContentInfo{
		ContentType: contentType,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER},
	})
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: ciDER})
}

// mustMarshalSet renders one attribute value set holding the receipt
// as an OCTET STRING.
func mustMarshalSet(t *testing.T, receipt []byte) asn1.RawValue {
	t.Helper()

	value, err := asn1.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}

	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: value}
}
