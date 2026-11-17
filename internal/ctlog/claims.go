// What a log entry's certificate says about who it was issued to, read
// from the Merkle tree leaf the log committed to — the precertificate's
// own TBSCertificate for a precert entry, the certificate for an X.509
// entry. Never from the unsigned extra data beside the leaf.

package ctlog

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
)

// oidSubjectAltName is the X.509 subject alternative name extension
// (RFC 5280 §4.2.1.6).
//
//nolint:gochecknoglobals // a format constant; Go has no const OID
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// sanURITag is the GeneralName choice for a uniformResourceIdentifier:
// [6] IMPLICIT IA5String (RFC 5280 §4.2.1.6).
const sanURITag = 6

// Certificate is an entry's certificate, held as what a reconciliation
// reads: the URI subject alternative names exactly as encoded, and the
// extensions for Fulcio's claims.
type Certificate struct {
	// URIs are the URI subject alternative names, byte for byte as the
	// certificate encodes them — never re-rendered through a URL
	// parser, whose idea of a canonical spelling is not the issuer's.
	URIs []string

	extensions []pkix.Extension
}

// Fulcio reads the certificate's Fulcio extensions through
// sigstore-go's own reader — the definition every verification in
// this tool already uses, so the claims a reconciliation reads are the
// claims a verification would.
func (c *Certificate) Fulcio() (certificate.Extensions, error) {
	ext, err := certificate.ParseExtensions(c.extensions)
	if err != nil {
		return certificate.Extensions{}, fmt.Errorf("ctlog: the certificate's Fulcio extensions do not parse: %w", err)
	}

	return ext, nil
}

// ParseLeaf reads the certificate an entry's Merkle tree leaf carries.
func ParseLeaf(leafInput []byte) (*Certificate, error) {
	var leaf ct.MerkleTreeLeaf

	rest, err := cttls.Unmarshal(leafInput, &leaf)
	if err != nil {
		return nil, fmt.Errorf("ctlog: the leaf is not an RFC 6962 MerkleTreeLeaf: %w", err)
	}

	if len(rest) > 0 {
		return nil, fmt.Errorf("ctlog: the leaf carries %d trailing bytes", len(rest))
	}

	// The TLS decoder has already refused every leaf type but a
	// timestamped entry, and every entry type but the three RFC 6962
	// and its JSON extension define, each with its body present.
	var (
		cert *ctx509.Certificate
		perr error
	)

	switch te := leaf.TimestampedEntry; te.EntryType {
	case ct.X509LogEntryType:
		cert, perr = ctx509.ParseCertificate(te.X509Entry.Data)
	case ct.PrecertLogEntryType:
		cert, perr = ctx509.ParseTBSCertificate(te.PrecertEntry.TBSCertificate)
	default:
		return nil, fmt.Errorf("ctlog: the entry is of type %v, neither a certificate nor a precertificate", te.EntryType)
	}

	// The x509 fork reports problems a strict parser would refuse but a
	// log accepted as non-fatal, and hands the certificate back: what a
	// reconciliation reads is the extensions, which a non-fatal problem
	// elsewhere does not touch.
	if cert == nil || ctx509.IsFatal(perr) {
		return nil, fmt.Errorf("ctlog: the certificate does not parse: %w", perr)
	}

	return fromParsed(cert)
}

// fromParsed keeps what a reconciliation reads from a parsed
// certificate: its extensions, and its URI names read out of the raw
// subject alternative name extension.
func fromParsed(cert *ctx509.Certificate) (*Certificate, error) {
	out := &Certificate{extensions: make([]pkix.Extension, 0, len(cert.Extensions))}

	for _, e := range cert.Extensions {
		id := asn1.ObjectIdentifier(e.Id)
		out.extensions = append(out.extensions, pkix.Extension{Id: id, Critical: e.Critical, Value: e.Value})

		if !id.Equal(oidSubjectAltName) {
			continue
		}

		uris, err := sanURIs(e.Value)
		if err != nil {
			return nil, err
		}

		out.URIs = append(out.URIs, uris...)
	}

	return out, nil
}

// sanURIs reads the uniformResourceIdentifier names out of a subject
// alternative name extension's value: a SEQUENCE OF GeneralName.
func sanURIs(value []byte) ([]string, error) {
	var names asn1.RawValue

	rest, err := asn1.Unmarshal(value, &names)
	if err != nil || len(rest) > 0 || names.Tag != asn1.TagSequence || !names.IsCompound {
		return nil, errors.New("ctlog: the subject alternative name extension is not a SEQUENCE OF GeneralName")
	}

	var uris []string

	for inner := names.Bytes; len(inner) > 0; {
		var name asn1.RawValue

		inner, err = asn1.Unmarshal(inner, &name)
		if err != nil {
			return nil, fmt.Errorf("ctlog: a subject alternative name does not parse: %w", err)
		}

		if name.Class == asn1.ClassContextSpecific && name.Tag == sanURITag && !name.IsCompound {
			uris = append(uris, string(name.Bytes))
		}
	}

	return uris, nil
}
