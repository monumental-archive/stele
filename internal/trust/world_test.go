// The synthesized trust world every test in this package signs in: a
// Fulcio-shaped CA, a certificate transparency log that countersigns
// issuance (the stance requires one on every path, so every minted
// leaf carries an embedded SCT), and a Rekor-shaped transparency log
// for entities that carry receipts. sigstore-go's own VirtualSigstore
// mints leaves without SCTs, which the stance refuses — hence this
// world; its recipes are adapted from sigstore-go's testing/ca and
// sct_test (Apache-2.0).

package trust_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/types"
	dsseEntry "github.com/sigstore/rekor/pkg/types/dsse"
	"github.com/sigstore/rekor/pkg/types/hashedrekord"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// worldEpoch anchors every synthesized artifact to the test run: the
// CMS signer stamps a wall-clock signingTime attribute that pkcs7
// holds against the certificate window, so certificates must be
// valid NOW.
var worldEpoch = time.Now().Unix()

// world is one synthesized signing world.
type world struct {
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
	ctKey    *ecdsa.PrivateKey
	rekorKey *ecdsa.PrivateKey
}

func newWorld(t *testing.T) *world {
	t.Helper()

	caCert, caKey := newCA(t)

	ctKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rekorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return &world{caCert: caCert, caKey: caKey, ctKey: ctKey, rekorKey: rekorKey}
}

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-fulcio"},
		NotBefore:             time.Unix(worldEpoch-3600, 0),
		NotAfter:              time.Unix(worldEpoch+3600, 0),
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

func logID(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(der)

	return hex.EncodeToString(digest[:])
}

// material satisfies root.TrustedMaterial over the world's anchors.
// Zero-valued maps stand for a root that names no such log — the
// degraded shapes the guards refuse.
type material struct {
	root.BaseTrustedMaterial

	cas    []root.CertificateAuthority
	ctlogs map[string]*root.TransparencyLog
	rekors map[string]*root.TransparencyLog
}

func (m *material) FulcioCertificateAuthorities() []root.CertificateAuthority { return m.cas }

func (m *material) CTLogs() map[string]*root.TransparencyLog { return m.ctlogs }

func (m *material) RekorLogs() map[string]*root.TransparencyLog { return m.rekors }

// material builds the trusted material naming every anchor the world
// holds.
func (w *world) material(t *testing.T) *material {
	t.Helper()

	return &material{
		cas: []root.CertificateAuthority{
			&root.FulcioCertificateAuthority{
				Root:                w.caCert,
				ValidityPeriodStart: w.caCert.NotBefore,
				ValidityPeriodEnd:   w.caCert.NotAfter,
			},
		},
		ctlogs: map[string]*root.TransparencyLog{
			logID(t, w.ctKey.Public()): {
				ID:                  []byte(logID(t, w.ctKey.Public())),
				ValidityPeriodStart: time.Unix(worldEpoch-3600, 0),
				ValidityPeriodEnd:   time.Unix(worldEpoch+3600, 0),
				HashFunc:            crypto.SHA256,
				PublicKey:           w.ctKey.Public(),
			},
		},
		rekors: map[string]*root.TransparencyLog{
			logID(t, w.rekorKey.Public()): {
				BaseURL:             "https://rekor.localhost",
				ID:                  []byte(logID(t, w.rekorKey.Public())),
				ValidityPeriodStart: time.Unix(worldEpoch-3600, 0),
				ValidityPeriodEnd:   time.Unix(worldEpoch+3600, 0),
				HashFunc:            crypto.SHA256,
				PublicKey:           w.rekorKey.Public(),
				SignatureHashFunc:   crypto.SHA256,
			},
		},
	}
}

// leafSpec parameterises one leaf mint.
type leafSpec struct {
	san       string
	issuer    string
	notBefore time.Time
	notAfter  time.Time
	// noSCT mints a leaf whose issuance nothing countersigns — the
	// shape the stance refuses.
	noSCT bool
	// sctAt overrides the countersigned issuance instant (defaults
	// to notBefore).
	sctAt time.Time
}

// issueLeaf mints one Fulcio-shaped leaf: SAN URI, the issuer
// extension, and (unless noSCT) an embedded SCT countersigned by the
// world's CT log — the sct_test recipe: sign the precertificate's
// TBS, then reissue the same template with the SCT list appended.
func (w *world) issueLeaf(t *testing.T, spec *leafSpec) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	issuerDER, err := asn1.MarshalWithParams(spec.issuer, "utf8")
	if err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(spec.san)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    spec.notBefore,
		NotAfter:     spec.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:         []*url.URL{u},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, Value: issuerDER},
		},
	}

	pre := w.signTemplate(t, tmpl, &key.PublicKey)
	if spec.noSCT {
		return pre, key
	}

	at := spec.sctAt
	if at.IsZero() {
		at = spec.notBefore
	}

	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
		Id:    asn1.ObjectIdentifier(ctx509.OIDExtensionCTSCT),
		Value: w.sctExtension(t, pre, at),
	})

	return w.signTemplate(t, tmpl, &key.PublicKey), key
}

func (w *world) signTemplate(t *testing.T, tmpl *x509.Certificate, pub *ecdsa.PublicKey) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(rand.Reader, tmpl, w.caCert, pub, w.caKey)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

// sctExtension countersigns the precertificate's issuance with the
// world's CT log and renders the embedded-SCT extension value.
func (w *world) sctExtension(t *testing.T, pre *x509.Certificate, at time.Time) []byte {
	t.Helper()

	var keyID [32]byte

	pubDER, err := x509.MarshalPKIXPublicKey(w.ctKey.Public())
	if err != nil {
		t.Fatal(err)
	}

	keyID = sha256.Sum256(pubDER)

	sct := ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		Timestamp:  uint64(at.UnixMilli()),
		LogID:      ct.LogID{KeyID: keyID},
	}

	entry := ct.LogEntry{
		Leaf: ct.MerkleTreeLeaf{
			Version:  ct.V1,
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: &ct.TimestampedEntry{
				Timestamp: sct.Timestamp,
				EntryType: ct.PrecertLogEntryType,
				PrecertEntry: &ct.PreCert{
					IssuerKeyHash:  sha256.Sum256(w.caCert.RawSubjectPublicKeyInfo),
					TBSCertificate: pre.RawTBSCertificate,
				},
			},
		},
	}

	input, err := ct.SerializeSCTSignatureInput(sct, entry)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(input)

	sig, err := ecdsa.SignASN1(rand.Reader, w.ctKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	sct.Signature = ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{Hash: cttls.SHA256, Signature: cttls.ECDSA},
		Signature: sig,
	}

	list, err := ctx509util.MarshalSCTsIntoSCTList([]*ct.SignedCertificateTimestamp{&sct})
	if err != nil {
		t.Fatal(err)
	}

	listBytes, err := cttls.Marshal(*list)
	if err != nil {
		t.Fatal(err)
	}

	value, err := asn1.Marshal(listBytes)
	if err != nil {
		t.Fatal(err)
	}

	return value
}

// rekorEntry writes one canonical Rekor v1 entry over the artifact
// (kind hashedrekord) or envelope (kind dsse) and countersigns it
// with the world's Rekor key — the testing/ca recipe.
func (w *world) rekorEntry(t *testing.T, kind string, blob, sig []byte, leaf *x509.Certificate,
	integrated time.Time,
) *tlog.Entry {
	t.Helper()

	leafPEM, err := cryptoutils.MarshalCertificateToPEM(leaf)
	if err != nil {
		t.Fatal(err)
	}

	props := types.ArtifactProperties{
		PublicKeyBytes: [][]byte{leafPEM},
		PKIFormat:      string(pki.X509),
	}

	var version string

	switch kind {
	case hashedrekord.KIND:
		digest := sha256.Sum256(blob)
		props.ArtifactHash = hex.EncodeToString(digest[:])
		props.SignatureBytes = sig
		version = hashedrekord.New().DefaultVersion()
	case dsseEntry.KIND:
		props.ArtifactBytes = blob
		props.SignatureBytes = sig
		version = dsseEntry.New().DefaultVersion()
	default:
		t.Fatalf("unexpected rekor kind %q", kind)
	}

	proposed, err := types.NewProposedEntry(context.Background(), kind, version, props)
	if err != nil {
		t.Fatal(err)
	}

	impl, err := types.CreateVersionedEntry(proposed)
	if err != nil {
		t.Fatal(err)
	}

	// types.CanonicalizeEntry is Canonicalize FOLLOWED BY the JCS
	// transform, and those canonical bytes are what a Rekor log
	// stores and countersigns. Re-marshalling the entry afterwards
	// would undo the transform and mint bodies in an ordering no log
	// produces — which stays invisible while the body travels with
	// its entry, and is exactly what an offline mint's rebuilt body
	// has to match (stele#182).
	body, err := types.CanonicalizeEntry(context.Background(), impl)
	if err != nil {
		t.Fatal(err)
	}

	return w.sealRekorEntry(t, body, integrated)
}

// rekorBody renders just the canonical entry body, for tests that
// assemble the protobuf carrier themselves.
func (w *world) rekorBody(t *testing.T, kind string, blob, sig []byte, leaf *x509.Certificate,
	integrated time.Time,
) []byte {
	t.Helper()

	entry := w.rekorEntry(t, kind, blob, sig, leaf, integrated)

	return entry.TransparencyLogEntry().GetCanonicalizedBody()
}

// rekorProto seals a canonical body into the protobuf
// TransparencyLogEntry shape a gitsign offline mint embeds — kind,
// log ID, integrated time, and the world's signed entry timestamp.
func (w *world) rekorProto(t *testing.T, body []byte, integrated time.Time) *protorekor.TransparencyLogEntry {
	t.Helper()

	id := logID(t, w.rekorKey.Public())

	idRaw, err := hex.DecodeString(id)
	if err != nil {
		t.Fatal(err)
	}

	const logIndex = int64(42)

	set := w.signRekorPayload(t, tlog.RekorPayload{
		LogID:          id,
		IntegratedTime: integrated.Unix(),
		LogIndex:       logIndex,
		Body:           base64.StdEncoding.EncodeToString(body),
	})

	return &protorekor.TransparencyLogEntry{
		LogIndex:          logIndex,
		LogId:             &protocommon.LogId{KeyId: idRaw},
		KindVersion:       &protorekor.KindVersion{Kind: hashedrekord.KIND, Version: hashedrekord.New().DefaultVersion()},
		IntegratedTime:    integrated.Unix(),
		InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: set},
		CanonicalizedBody: body,
	}
}

// rekorOfflineProto seals a body into the entry shape a gitsign
// offline mint actually embeds (stele#182): every countersignature
// over the body, and the body itself LEFT OUT — derivable from the
// signature the entry rides on, so gitsign carries no second copy.
//
// The body argument is what the LOG signed, not what the entry
// carries. Passing bytes other than the signature's own is how a
// receipt for something else is synthesized.
func (w *world) rekorOfflineProto(t *testing.T, body []byte, integrated time.Time) *protorekor.TransparencyLogEntry {
	t.Helper()

	pb := w.rekorProto(t, body, integrated)
	pb.CanonicalizedBody = nil

	return pb
}

// withInclusionProof adds a single-leaf inclusion proof over body,
// under a checkpoint the world's Rekor key signs. A one-leaf tree's
// root IS its leaf hash, which is the smallest proof that can be
// honestly built — and enough for a verifier to refuse a proof drawn
// over different bytes.
func (w *world) withInclusionProof(
	t *testing.T, pb *protorekor.TransparencyLogEntry, body []byte,
) *protorekor.TransparencyLogEntry {
	t.Helper()

	leafHash := rfc6962.DefaultHasher.HashLeaf(body)

	signer, err := signature.LoadECDSASignerVerifier(w.rekorKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	const treeID = int64(1)

	checkpoint, err := util.CreateAndSignCheckpoint(context.Background(), "rekor.example", treeID, 1, leafHash, signer)
	if err != nil {
		t.Fatal(err)
	}

	pb.InclusionProof = &protorekor.InclusionProof{
		LogIndex:   0,
		RootHash:   leafHash,
		TreeSize:   1,
		Checkpoint: &protorekor.Checkpoint{Envelope: string(checkpoint)},
	}

	return pb
}

// sealRekorEntry wraps a canonical body into a tlog entry with the
// world's signed entry timestamp over it.
func (w *world) sealRekorEntry(t *testing.T, body []byte, integrated time.Time) *tlog.Entry {
	t.Helper()

	id := logID(t, w.rekorKey.Public())

	const logIndex = int64(42)

	payload := tlog.RekorPayload{
		LogID:          id,
		IntegratedTime: integrated.Unix(),
		LogIndex:       logIndex,
		Body:           base64.StdEncoding.EncodeToString(body),
	}

	set := w.signRekorPayload(t, payload)

	idRaw, err := hex.DecodeString(id)
	if err != nil {
		t.Fatal(err)
	}

	entry, err := tlog.NewEntry(body, integrated.Unix(), logIndex, idRaw, set, nil) //nolint:staticcheck // v1 SET shape
	if err != nil {
		t.Fatal(err)
	}

	return entry
}

func (w *world) signRekorPayload(t *testing.T, payload tlog.RekorPayload) []byte {
	t.Helper()

	raw, err := jsonx.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := signature.LoadECDSASignerVerifier(w.rekorKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	set, err := signer.SignMessage(bytes.NewReader(canonical))
	if err != nil {
		t.Fatal(err)
	}

	return set
}

// entity is a minted signed entity — the testing/ca TestEntity shape.
type entity struct {
	leaf             *x509.Certificate
	envelope         *dsse.Envelope
	messageSignature *bundle.MessageSignature
	tlogEntries      []*tlog.Entry
}

//nolint:ireturn // sigstore-go's SignedEntity contract returns its interface
func (e *entity) VerificationContent() (verify.VerificationContent, error) {
	return bundle.NewCertificate(e.leaf), nil
}

func (e *entity) HasInclusionPromise() bool { return true }

func (e *entity) HasInclusionProof() bool { return false }

func (e *entity) Version() (string, error) { return "v0.3", nil }

//nolint:ireturn // sigstore-go's SignedEntity contract returns its interface
func (e *entity) SignatureContent() (verify.SignatureContent, error) {
	if e.envelope != nil {
		return &bundle.Envelope{Envelope: e.envelope}, nil
	}

	return e.messageSignature, nil
}

func (e *entity) Timestamps() ([][]byte, error) { return nil, nil }

func (e *entity) TlogEntries() ([]*tlog.Entry, error) { return e.tlogEntries, nil }

// attest mints a DSSE attestation entity over the statement body.
func (w *world) attest(t *testing.T, san, issuer string, body []byte) *entity {
	t.Helper()

	leaf, key := w.issueLeaf(t, &leafSpec{
		san: san, issuer: issuer,
		notBefore: time.Unix(worldEpoch-300, 0), notAfter: time.Unix(worldEpoch+300, 0),
	})

	return w.attestWithLeaf(t, leaf, key, body)
}

// attestWithLeaf mints a DSSE attestation entity under a caller-made
// leaf — the seam degraded-shape tests break one certificate fact
// through.
func (w *world) attestWithLeaf(t *testing.T, leaf *x509.Certificate, key *ecdsa.PrivateKey, body []byte) *entity {
	t.Helper()

	signer, err := signature.LoadECDSASignerVerifier(key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	envelopeSigner, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{
		SignatureSigner: signer,
		Pub:             &key.PublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	envelope, err := envelopeSigner.SignPayload(context.Background(), "application/vnd.in-toto+json", body)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		t.Fatal(err)
	}

	envelopeBytes, err := jsonx.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}

	entry := w.rekorEntry(t, dsseEntry.KIND, envelopeBytes, sig, leaf, time.Unix(worldEpoch, 0))

	return &entity{leaf: leaf, envelope: envelope, tlogEntries: []*tlog.Entry{entry}}
}

// sign mints a blob-signature entity over the artifact — the cosign
// sign-blob shape.
func (w *world) sign(t *testing.T, san, issuer string, artifact []byte) *entity {
	t.Helper()

	leaf, key := w.issueLeaf(t, &leafSpec{
		san: san, issuer: issuer,
		notBefore: time.Unix(worldEpoch-300, 0), notAfter: time.Unix(worldEpoch+300, 0),
	})

	digest := sha256.Sum256(artifact)

	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	entry := w.rekorEntry(t, hashedrekord.KIND, artifact, sig, leaf, time.Unix(worldEpoch, 0))

	return &entity{
		leaf:             leaf,
		messageSignature: bundle.NewMessageSignature(digest[:], "SHA2_256", sig),
		tlogEntries:      []*tlog.Entry{entry},
	}
}
