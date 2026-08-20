// Gitsign tag verification: the x509-in-the-PGP-slot signature a
// gitsign mint leaves on an annotated tag, verified natively — no
// gitsign binary on the runner (stele#83). The signature block is a
// PEM-wrapped CMS SignedData, detached over the tag payload (the tag
// object with the signature block removed).
//
// One stance, one path (stele#173): the tag is an ADAPTER over the
// signed-entity abstraction, not a second verifier. What differs by
// shape is only the binding — a CMS binds its payload to the
// signature through the message-digest attribute (pkcs7 proves
// that), and binds the signature to any transparency log through the
// signed-attribute blob the log records (cms.go extracts it
// byte-exact). Everything past the binding is the package stance:
// certificate transparency, a chain observed at a countersigned
// instant, identity — and, when the tag carries its mint's receipts
// or the caller's floor demands them, the full observer stance
// through the SAME sigstore-go verifier the bundle path uses.
//
// How much proof is enough is NOT decided here. The caller declares
// a floor (TagFloor, policy data); the verdict states the depth it
// reached and the instants it observed. A mint that logs its tags
// but drops the receipt — this org's, today — verifies honestly at
// the certificate-transparency floor: its certificate's issuance is
// countersigned by a CT log, and nothing countersigns an observation
// of the signature itself. The moment the mint embeds its Rekor
// entry (the decision recorded on stele#167), the same tag verifies
// at the observer-timestamp floor with no code change here.

package trust

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/digitorus/pkcs7"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/proto"
)

// TagFloor is the floor of proof a caller requires of a tag
// signature — declared policy data, never a code decision
// (stele#173). The ladder is ordered: observer-timestamp implies
// everything certificate-transparency proves.
type TagFloor string

const (
	// TagFloorCertificateTransparency requires the signing
	// certificate's issuance to be countersigned by a trusted CT log
	// — the depth every Fulcio-minted signature can reach offline,
	// receipts or not.
	TagFloorCertificateTransparency TagFloor = "certificate-transparency"
	// TagFloorObserverTimestamp additionally requires a countersigned
	// observation of the signature itself: a transparency-log entry
	// and an observer timestamp, the same stance the bundle path
	// holds. Only a mint that embeds its receipts can meet it.
	TagFloorObserverTimestamp TagFloor = "observer-timestamp"
)

// TagIdentity is the trust expectation for one tag signature: the
// exact OIDC issuer and a compiled pattern over the certificate SAN.
type TagIdentity struct {
	SANPattern *regexp.Regexp
	Issuer     string
}

// TagVerdict is a successful tag verification: who signed, the depth
// the proof reached, and every countersigned instant it was held
// against — stated, never implied.
type TagVerdict struct {
	SAN      string
	Depth    TagFloor
	Observed []ObservedInstant
}

// VerifyTag proves one gitsign tag signature to at least the given
// floor: CMS integrity over the payload, the package stance
// (transparency, chain at a countersigned instant, identity), the
// floor's observer obligations, and the tagger clock's consistency
// with the countersigned issuance. Returns the verdict with the
// depth actually reached.
func (t *Verifier) VerifyTag(payload, sigPEM []byte, id TagIdentity, floor TagFloor) (*TagVerdict, error) {
	if floor != TagFloorCertificateTransparency && floor != TagFloorObserverTimestamp {
		return nil, fmt.Errorf("trust: unknown tag proof floor %q", floor)
	}

	block, _ := pem.Decode(sigPEM)
	if block == nil {
		return nil, errors.New("trust: tag signature is not PEM")
	}

	p7, err := pkcs7.Parse(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("trust: tag signature is not CMS: %w", err)
	}

	p7.Content = payload

	// The payload↔signature binding: the message-digest attribute
	// covers the payload, the signature covers the attributes.
	if verr := p7.Verify(); verr != nil {
		return nil, fmt.Errorf("trust: tag signature does not verify over the tag payload: %w", verr)
	}

	leaf := p7.GetOnlySigner()
	if leaf == nil {
		return nil, errors.New("trust: tag signature carries no single signer certificate")
	}

	if serr := requireSigningTime(p7); serr != nil {
		return nil, serr
	}

	pieces, err := parseCMS(block.Bytes)
	if err != nil {
		return nil, err
	}

	verdict, issuance, err := t.judgeTag(leaf, pieces, id, floor)
	if err != nil {
		return nil, err
	}

	// The tag's own account of when it was made, held against the
	// countersigned issuance instant — never against a window the
	// signer chose.
	if terr := taggerConsistent(payload, leaf, issuance); terr != nil {
		return nil, terr
	}

	return verdict, nil
}

// judgeTag runs the stance over the parsed signature and returns the
// verdict scaffold (SAN, depth, instants) along with the
// countersigned issuance instant the tagger clock is held against.
//
// Route selection is by EVIDENCE, not only by floor: a tag carrying
// its mint's receipts is judged through the full observer path even
// when the floor asks less, because a receipt that does not prove is
// tampering-shaped and must refuse loudly, never be ignored down to
// a shallower success.
func (t *Verifier) judgeTag(
	leaf *x509.Certificate, pieces *cmsPieces, id TagIdentity, floor TagFloor,
) (*TagVerdict, ObservedInstant, error) {
	entries, err := parseTagTlogEntries(pieces.tlogEntries)
	if err != nil {
		return nil, ObservedInstant{}, err
	}

	if floor == TagFloorObserverTimestamp && len(entries) == 0 && len(pieces.timestamps) == 0 {
		return nil, ObservedInstant{}, errors.New(
			"trust: the tag signature carries no transparency-log entry and no signed timestamp — " +
				"nothing countersigns an observation of the signature, and the declared floor requires one")
	}

	if len(entries) > 0 || len(pieces.timestamps) > 0 {
		return t.judgeTagObserved(leaf, pieces, entries, id)
	}

	return t.judgeTagIssuance(leaf, id)
}

// judgeTagObserved reaches the verdict through the SAME verifier the
// bundle path uses: the CMS becomes a message-signature entity over
// its signed-attribute blob, and sigstore-go proves the log entry,
// the observer timestamps, the chain at those instants, the
// signature and the identity — the whole stance, unrepeated.
func (t *Verifier) judgeTagObserved(
	leaf *x509.Certificate, pieces *cmsPieces, entries []*tlog.Entry, id TagIdentity,
) (*TagVerdict, ObservedInstant, error) {
	ci, err := tagCertIdentity(id)
	if err != nil {
		return nil, ObservedInstant{}, err
	}

	entity := &tagEntity{leaf: leaf, pieces: pieces, entries: entries}

	result, err := t.v.Verify(entity, verify.NewPolicy(
		verify.WithArtifact(bytes.NewReader(pieces.signedBlob)),
		verify.WithCertificateIdentity(ci),
	))
	if err != nil {
		return nil, ObservedInstant{}, fmt.Errorf("trust: tag signature countersignatures do not verify: %w", err)
	}

	ctInstant, err := t.observeCT(leaf)
	if err != nil {
		return nil, ObservedInstant{}, err
	}

	if result.Signature == nil || result.Signature.Certificate == nil {
		return nil, ObservedInstant{}, errors.New(
			"trust: verification returned no certificate — nothing to hold the policy against")
	}

	return &TagVerdict{
		SAN:      result.Signature.Certificate.SubjectAlternativeName,
		Depth:    TagFloorObserverTimestamp,
		Observed: append(observedFromResult(result), ctInstant),
	}, ctInstant, nil
}

// judgeTagIssuance is the certificate-transparency depth: nothing
// countersigns an observation of the signature, so the verdict rests
// on what IS countersigned — the certificate's issuance, proven by
// observeCT together with the chain at that instant — plus the
// identity, held through sigstore-go's own identity matcher so the
// definition is the bundle path's.
func (t *Verifier) judgeTagIssuance(leaf *x509.Certificate, id TagIdentity) (*TagVerdict, ObservedInstant, error) {
	ctInstant, err := t.observeCT(leaf)
	if err != nil {
		return nil, ObservedInstant{}, err
	}

	ci, err := tagCertIdentity(id)
	if err != nil {
		return nil, ObservedInstant{}, err
	}

	summary, err := certificate.SummarizeCertificate(leaf)
	if err != nil {
		return nil, ObservedInstant{}, fmt.Errorf("trust: tag signing certificate: %w", err)
	}

	if _, ierr := (verify.CertificateIdentities{ci}).Verify(summary); ierr != nil {
		return nil, ObservedInstant{}, fmt.Errorf("trust: tag signing certificate identity: %w", ierr)
	}

	return &TagVerdict{
		SAN:      summary.SubjectAlternativeName,
		Depth:    TagFloorCertificateTransparency,
		Observed: []ObservedInstant{ctInstant},
	}, ctInstant, nil
}

// tagCertIdentity builds the identity expectation once, in
// sigstore-go's own vocabulary: issuer exact, SAN by the declared
// pattern.
func tagCertIdentity(id TagIdentity) (verify.CertificateIdentity, error) {
	ci, err := verify.NewShortCertificateIdentity(id.Issuer, "", "", id.SANPattern.String())
	if err != nil {
		return verify.CertificateIdentity{}, fmt.Errorf("trust: tag identity: %w", err)
	}

	return ci, nil
}

// parseTagTlogEntries decodes the embedded Rekor entries. A receipt
// that does not parse refuses — a malformed countersignature is
// evidence of tampering, never something to fall back from. The
// attribute payload is the protobuf TransparencyLogEntry gitsign
// embeds in its offline mode; no tag this org has minted carries one
// yet (measured on stele#167: 0 of 43), so the canon's mint change
// shadow-proves this decode against real material before any policy
// floor relies on it.
func parseTagTlogEntries(raw [][]byte) ([]*tlog.Entry, error) {
	entries := make([]*tlog.Entry, 0, len(raw))

	for _, data := range raw {
		var pb protorekor.TransparencyLogEntry
		if err := proto.Unmarshal(data, &pb); err != nil {
			return nil, fmt.Errorf("trust: tag signature transparency-log entry does not decode: %w", err)
		}

		entry, err := tlog.ParseTransparencyLogEntry(&pb)
		if err != nil {
			return nil, fmt.Errorf("trust: tag signature transparency-log entry: %w", err)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// tagEntity adapts one parsed CMS to sigstore-go's signed-entity
// abstraction: a message signature over the signed-attribute blob
// (the seam invariant, cms.go), the signer's certificate, and
// whatever countersignatures the mint embedded.
type tagEntity struct {
	leaf    *x509.Certificate
	pieces  *cmsPieces
	entries []*tlog.Entry
}

//nolint:ireturn // sigstore-go's SignedEntity contract returns its interface
func (e *tagEntity) VerificationContent() (verify.VerificationContent, error) {
	return bundle.NewCertificate(e.leaf), nil
}

//nolint:ireturn // sigstore-go's SignedEntity contract returns its interface
func (e *tagEntity) SignatureContent() (verify.SignatureContent, error) {
	digest := sha256.Sum256(e.pieces.signedBlob)

	return bundle.NewMessageSignature(digest[:], "SHA2_256", e.pieces.signature), nil
}

func (e *tagEntity) Timestamps() ([][]byte, error) { return e.pieces.timestamps, nil }

func (e *tagEntity) TlogEntries() ([]*tlog.Entry, error) { return e.entries, nil }

func (e *tagEntity) HasInclusionPromise() bool {
	for _, entry := range e.entries {
		if entry.HasInclusionPromise() {
			return true
		}
	}

	return false
}

func (e *tagEntity) HasInclusionProof() bool {
	for _, entry := range e.entries {
		if entry.HasInclusionProof() {
			return true
		}
	}

	return false
}

// Version names the entity shape; nothing here needs the bundle
// media-type compatibility switches keyed off it.
func (e *tagEntity) Version() (string, error) { return "gitsign-tag", nil }

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

// taggerConsistent holds the payload's tagger clock against the
// countersigned instant the verdict observed — one side of the
// comparison is finally trustworthy (stele#173), so the bound needs
// no declared tolerance.
//
// The bound is still DERIVED, never chosen: a tag may not claim a
// time after its signing certificate expires, nor more than one
// certificate lifetime before the countersigned instant. The
// certificate states its own tolerance by stating its own window, so
// nothing here can widen under pressure.
//
// The asymmetry is the mint's real shape: git stamps the tagger line
// from the tagging process's clock and only then invokes the signer,
// so an honest tagger time PRECEDES the countersigned issuance by
// the mint's latency (measured across both declared epochs: zero or
// one second, never more) and can never legitimately follow the
// certificate's expiry.
func taggerConsistent(payload []byte, leaf *x509.Certificate, observed ObservedInstant) error {
	tagged, err := taggerTime(payload)
	if err != nil {
		return err
	}

	earliest := observed.Time().Add(-leaf.NotAfter.Sub(leaf.NotBefore))

	if tagged.Before(earliest) || tagged.After(leaf.NotAfter) {
		return fmt.Errorf(
			"trust: the tag is stamped %s, outside the window its countersigned issuance allows (%s to %s)",
			tagged.UTC().Format(time.RFC3339),
			earliest.UTC().Format(time.RFC3339),
			leaf.NotAfter.UTC().Format(time.RFC3339))
	}

	return nil
}

// taggerTime reads the tagger timestamp out of the signed payload —
// the tag's own account of when it was made, which taggerConsistent
// holds against the countersigned issuance. The line is
// `tagger NAME <EMAIL> UNIX TZ`, git's own format; a payload without
// one is not an annotated tag and refuses.
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
