package assert_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"

	"github.com/monumental-archive/stele/internal/report"
)

// The Fulcio extensions a synthetic certificate may carry
// (sigstore/fulcio docs/oid-info.md).
var (
	oidIssuerV2         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
	oidBuildSignerURI   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9}
	oidBuildSignerDigst = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 10}
	oidRunInvocationURI = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 21}
)

// utf8Ext is one Fulcio v2 extension: a DER UTF8String.
func utf8Ext(t *testing.T, id asn1.ObjectIdentifier, value string) pkix.Extension {
	t.Helper()

	der, err := asn1.MarshalWithParams(value, "utf8")
	if err != nil {
		t.Fatal(err)
	}

	return pkix.Extension{Id: id, Value: der}
}

// x509Leaf is an RFC 6962 X.509 entry over der — the entry type the
// two real certificates (precertificates both) do not exercise.
func x509Leaf(t *testing.T, der []byte) []byte {
	t.Helper()

	leaf, err := cttls.Marshal(ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: uint64(fakeLogTime.UnixMilli()),
			EntryType: ct.X509LogEntryType,
			X509Entry: &ct.ASN1Cert{Data: der},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	return leaf
}

// syntheticLeaf is a self-signed certificate naming san, carrying the
// given extensions, as an X.509 log entry.
func syntheticLeaf(t *testing.T, san string, exts ...pkix.Extension) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(san)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		NotBefore:       fakeLogTime,
		NotAfter:        fakeLogTime.Add(10 * time.Minute),
		URIs:            []*url.URL{u},
		ExtraExtensions: exts,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	return x509Leaf(t, der)
}

// The guard rows the two real certificates cannot reach: each claim
// shape the reconciliation refuses, and each way an entry carrying the
// signer's subject bytes is or is not a match.
func TestSignerClaimShapes(t *testing.T) {
	t.Parallel()

	const releaseRunURI = "https://github.com/" + captureCanon + "/actions/runs/" + releaseRun + "/attempts/1"

	sanAt := "https://github.com/" + captureSignYML + "@"

	cases := []struct {
		name      string
		leaf      func(t *testing.T) []byte
		verdict   report.Verdict
		condition string
		message   string
	}{
		{
			name: "an X.509 entry for the release run reconciles like the precertificate",
			leaf: func(t *testing.T) []byte {
				t.Helper()

				return syntheticLeaf(t, sanAt+releaseSigner,
					utf8Ext(t, oidIssuerV2, githubIssuer),
					utf8Ext(t, oidBuildSignerDigst, releaseSigner),
					utf8Ext(t, oidRunInvocationURI, releaseRunURI))
			},
			verdict: report.VerdictPass,
		},
		{
			name: "a Build Signer Digest that is not a commit",
			leaf: func(t *testing.T) []byte {
				t.Helper()

				return syntheticLeaf(t, sanAt+"refs/heads/main",
					utf8Ext(t, oidIssuerV2, githubIssuer),
					utf8Ext(t, oidBuildSignerDigst, "main"),
					utf8Ext(t, oidRunInvocationURI, releaseRunURI))
			},
			verdict:   report.VerdictFail,
			condition: "signer-in-run",
			message:   `signer claim unreadable: Build Signer Digest "main" is not a commit`,
		},
		{
			name: "a Run Invocation URI on another host",
			leaf: func(t *testing.T) []byte {
				t.Helper()

				return syntheticLeaf(t, sanAt+releaseSigner,
					utf8Ext(t, oidIssuerV2, githubIssuer),
					utf8Ext(t, oidBuildSignerDigst, releaseSigner),
					utf8Ext(t, oidRunInvocationURI, "https://elsewhere.example/acme/x/actions/runs/1"))
			},
			verdict:   report.VerdictFail,
			condition: "run",
			message:   `no Run Invocation URI a run can be read from: "https://elsewhere.example/acme/x/actions/runs/1"`,
		},
		{
			name: "a run id no run can have",
			leaf: func(t *testing.T) []byte {
				t.Helper()

				return syntheticLeaf(t, sanAt+releaseSigner,
					utf8Ext(t, oidIssuerV2, githubIssuer),
					utf8Ext(t, oidBuildSignerDigst, releaseSigner),
					utf8Ext(t, oidRunInvocationURI,
						"https://github.com/"+captureCanon+"/actions/runs/99999999999999999999999"))
			},
			verdict:   report.VerdictFail,
			condition: "run",
			message:   "no Run Invocation URI a run can be read from",
		},
		{
			name: "Fulcio extensions that do not parse",
			leaf: func(t *testing.T) []byte {
				t.Helper()

				return syntheticLeaf(t, sanAt+releaseSigner, pkix.Extension{Id: oidIssuerV2, Value: []byte{0xff}})
			},
			verdict:   report.VerdictFail,
			condition: "signer-in-run",
			message:   "signer claim unreadable: ctlog: the certificate's Fulcio extensions do not parse",
		},
		{
			name: "a certificate that does not parse, carrying the signer's subject",
			leaf: func(t *testing.T) []byte {
				t.Helper()

				return x509Leaf(t, []byte("not DER, but naming "+sanAt+releaseSigner))
			},
			verdict:   report.VerdictFail,
			condition: "signer-in-run",
			message:   "signer claim unreadable: ctlog: the certificate does not parse",
		},
		{
			name: "the signer's subject in an extension, not in the subject: not a match",
			leaf: func(t *testing.T) []byte {
				t.Helper()

				return syntheticLeaf(t, "https://github.com/someone/else/.github/workflows/x.yml@refs/heads/main",
					utf8Ext(t, oidIssuerV2, githubIssuer),
					utf8Ext(t, oidBuildSignerURI, sanAt+releaseSigner))
			},
			verdict: report.VerdictPass,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, withLeaf(fillerLeaves(smallLog), releaseAt, tc.leaf(t)))

			rep, err := h.run(0)
			if err != nil {
				t.Fatal(err)
			}

			if rep.Verdict() != tc.verdict {
				t.Fatalf("verdict = %s, want %s; findings %+v", rep.Verdict(), tc.verdict, rep.Findings())
			}

			if tc.condition == "" {
				return
			}

			findings := rep.Findings()
			if len(findings) != 1 || findings[0].Assertion != tc.condition ||
				!strings.Contains(findings[0].Detail, tc.message) {
				t.Fatalf("findings %+v, want one %s finding saying %q", findings, tc.condition, tc.message)
			}
		})
	}
}
