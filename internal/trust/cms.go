// Raw CMS SignedData access: the byte-exact pieces of a gitsign
// signature that the one verification path needs and digitorus/pkcs7
// does not expose — the signed-attribute blob the signature actually
// covers, the signature bytes, and the unsigned attributes that may
// carry the mint's own countersignatures (a Rekor transparency-log
// entry, an RFC 3161 timestamp token).
//
// Seam invariant (stele#173): CMS is an indirection. The tag payload
// is bound to the signature by the CMS message-digest attribute
// (pkcs7's Verify proves that), and the signature is bound to the
// log by the signed-attribute blob the log records — the blob THIS
// file extracts, byte-exact from the original DER, never
// re-serialized. Both bindings are proven; neither is assumed.

package trust

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// The unsigned-attribute OIDs a gitsign mint may countersign with:
// the Rekor transparency-log entry (sigstore's 1.3.6.1.4.1.57264.3.1)
// and the RFC 3161 id-aa-timeStampToken.
//
//nolint:gochecknoglobals // OID constants; asn1.ObjectIdentifier has no const form
var (
	oidRekorTransparencyLogEntry = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 3, 1}
	oidTimeStampToken            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
)

// cmsContentInfo is RFC 5652 ContentInfo.
type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// cmsSignedData is RFC 5652 SignedData, with everything this file
// does not read held raw.
type cmsSignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue `asn1:"set"`
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue   `asn1:"optional,tag:1"`
	SignerInfos      []cmsSignerInfo `asn1:"set"`
}

// cmsSignerInfo is RFC 5652 SignerInfo. SignedAttrs stays a RawValue
// because the signature covers those exact bytes ([0] IMPLICIT in
// the message, SET OF under the signature) — re-serializing them is
// how byte-identity quietly breaks.
type cmsSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

// cmsAttribute is RFC 5652 Attribute.
type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// cmsPieces is what one signer's CMS contributes to the signed-entity
// adapter.
type cmsPieces struct {
	// signedBlob is the DER the signature covers: the signed
	// attributes with their implicit [0] tag replaced by the
	// universal SET tag, as RFC 5652 §5.4 prescribes — and the blob
	// a gitsign mint hashes into its Rekor entry.
	signedBlob []byte
	// signature is the raw signature bytes.
	signature []byte
	// tlogEntries are the raw values of every Rekor
	// transparency-log-entry unsigned attribute.
	tlogEntries [][]byte
	// timestamps are the DER RFC 3161 timestamp tokens.
	timestamps [][]byte
}

// parseCMS extracts the byte-exact signer pieces from one CMS DER.
func parseCMS(der []byte) (*cmsPieces, error) {
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("trust: tag signature ContentInfo: %w", err)
	}

	var sd cmsSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("trust: tag signature SignedData: %w", err)
	}

	if len(sd.SignerInfos) != 1 {
		return nil, fmt.Errorf("trust: tag signature carries %d signers, want exactly one", len(sd.SignerInfos))
	}

	si := sd.SignerInfos[0]

	if len(si.SignedAttrs.FullBytes) == 0 {
		return nil, errors.New("trust: tag signature carries no signed attributes")
	}

	blob := make([]byte, len(si.SignedAttrs.FullBytes))
	copy(blob, si.SignedAttrs.FullBytes)
	// [0] IMPLICIT (0xA0) → SET OF (0x31): the tag swap RFC 5652
	// defines for the bytes the signature is computed over.
	blob[0] = 0x31

	pieces := &cmsPieces{signedBlob: blob, signature: si.Signature}

	if err := pieces.readUnsignedAttrs(si.UnsignedAttrs); err != nil {
		return nil, err
	}

	return pieces, nil
}

// readUnsignedAttrs collects the countersignature-bearing unsigned
// attributes. Unknown attributes are ignored — they are outside the
// signature and assert nothing here; the two known OIDs are carried
// to the verifier, which refuses anything that does not prove.
func (p *cmsPieces) readUnsignedAttrs(raw asn1.RawValue) error {
	if len(raw.FullBytes) == 0 {
		return nil
	}

	retagged := make([]byte, len(raw.FullBytes))
	copy(retagged, raw.FullBytes)
	retagged[0] = 0x31

	var attrs []cmsAttribute
	if _, err := asn1.UnmarshalWithParams(retagged, &attrs, "set"); err != nil {
		return fmt.Errorf("trust: tag signature unsigned attributes: %w", err)
	}

	for _, attr := range attrs {
		var value asn1.RawValue
		if _, err := asn1.Unmarshal(attr.Values.Bytes, &value); err != nil {
			return fmt.Errorf("trust: tag signature unsigned attribute %s: %w", attr.Type.String(), err)
		}

		switch {
		case attr.Type.Equal(oidRekorTransparencyLogEntry):
			// The entry rides as an OCTET STRING when wrapped, or as
			// raw bytes; either way the payload is the protobuf
			// TransparencyLogEntry.
			data := value.FullBytes
			if value.Tag == asn1.TagOctetString && value.Class == asn1.ClassUniversal {
				data = value.Bytes
			}

			p.tlogEntries = append(p.tlogEntries, data)
		case attr.Type.Equal(oidTimeStampToken):
			p.timestamps = append(p.timestamps, value.FullBytes)
		}
	}

	return nil
}
