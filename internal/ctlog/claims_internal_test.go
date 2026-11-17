package ctlog

import (
	"encoding/asn1"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	ctasn1 "github.com/google/certificate-transparency-go/asn1"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctpkix "github.com/google/certificate-transparency-go/x509/pkix"
)

// leafOf wraps an entry in a Merkle tree leaf.
func leafOf(t *testing.T, te *ct.TimestampedEntry) []byte {
	t.Helper()

	b, err := cttls.Marshal(ct.MerkleTreeLeaf{Version: ct.V1, LeafType: ct.TimestampedEntryLeafType, TimestampedEntry: te})
	if err != nil {
		t.Fatal(err)
	}

	return b
}

// Every entry ParseLeaf refuses after the leaf itself decoded.
func TestParseLeafEntryRefusals(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		te   *ct.TimestampedEntry
		want string
	}{
		{
			"a JSON entry",
			&ct.TimestampedEntry{EntryType: ct.LogEntryType(32768), JSONEntry: &ct.JSONDataEntry{Data: []byte("{}")}},
			"neither a certificate nor a precertificate",
		},
		{"a certificate that is not DER", &ct.TimestampedEntry{
			EntryType: ct.X509LogEntryType,
			X509Entry: &ct.ASN1Cert{Data: []byte("nope")},
		}, "the certificate does not parse"},
		{"a precertificate that is not DER", &ct.TimestampedEntry{
			EntryType:    ct.PrecertLogEntryType,
			PrecertEntry: &ct.PreCert{TBSCertificate: []byte("nope")},
		}, "the certificate does not parse"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := ParseLeaf(leafOf(t, tc.te)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}
}

// sanURIs reads URI names and nothing else, and refuses an extension
// that is not a SEQUENCE OF GeneralName.
func TestSANURIs(t *testing.T) {
	t.Parallel()

	uri := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte("https://a.example/x")}
	dns := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("a.example")}

	good, err := asn1.Marshal([]asn1.RawValue{dns, uri})
	if err != nil {
		t.Fatal(err)
	}

	got, err := sanURIs(good)
	if err != nil || len(got) != 1 || got[0] != "https://a.example/x" {
		t.Fatalf("sanURIs = %q, %v", got, err)
	}

	notSeq, err := asn1.Marshal("a string")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		value []byte
		want  string
	}{
		{"not DER", []byte{0xff}, "is not a SEQUENCE OF GeneralName"},
		{"not a sequence", notSeq, "is not a SEQUENCE OF GeneralName"},
		{"bytes after it", append(append([]byte{}, good...), 0), "is not a SEQUENCE OF GeneralName"},
		{"a name that does not parse", []byte{0x30, 0x02, 0x86, 0x05}, "a subject alternative name does not parse"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := sanURIs(tc.value); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}
}

// A certificate the x509 fork took whose subject alternative name does
// not read is refused, not read as naming nobody.
func TestFromParsedRefusesAnUnreadableSAN(t *testing.T) {
	t.Parallel()

	cert := &ctx509.Certificate{Extensions: []ctpkix.Extension{
		{Id: ctasn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{0xff}},
	}}

	if _, err := fromParsed(cert); err == nil || !strings.Contains(err.Error(), "is not a SEQUENCE OF GeneralName") {
		t.Fatalf("err = %v", err)
	}
}

// Fulcio extensions that do not read are an error naming them.
func TestFulcioRefusesUnreadableExtensions(t *testing.T) {
	t.Parallel()

	cert := &ctx509.Certificate{Extensions: []ctpkix.Extension{
		{Id: ctasn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, Value: []byte{0xff}},
	}}

	c, err := fromParsed(cert)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.Fulcio(); err == nil ||
		!strings.Contains(err.Error(), "the certificate's Fulcio extensions do not parse") {
		t.Fatalf("err = %v", err)
	}
}

// fill closes the file whatever happened, and reports the failure.
func TestFillReportsAFailedWrite(t *testing.T) {
	t.Parallel()

	f, err := os.Create(filepath.Join(t.TempDir(), "x"))
	if err != nil {
		t.Fatal(err)
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if err := fill(f, []byte("x")); err == nil || !strings.Contains(err.Error(), "file already closed") {
		t.Fatalf("err = %v", err)
	}
}
