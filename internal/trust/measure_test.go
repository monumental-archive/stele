// The measurement path: prove the signature, assert no identity,
// report who signed.
//
// This is the half of the trust boundary a gate never uses, and the
// reason `stele level` can answer about a repository nobody wrote a
// policy for. Verify and VerifyBlob are HANDED an identity and check
// the bundle against it; MeasureBlob and MeasureAttestation are handed
// nothing and read the identity out of the certificate the signature
// was made under.
//
// Asserting nothing is not the same as accepting anything, and that
// distinction is what these rows exist to hold. The cryptography is
// unchanged — the certificate must chain to the trusted root, the
// signature must cover the named digest, and the transparency stance
// still applies. Only the identity check is dropped. A measurement
// that skipped any of the rest would mint a level from an unsigned
// claim, which is precisely the defect the level verb exists to refuse.
//
// The material is upstream's own signed bundles rather than this
// package's synthesized world, because the Measure legs take a parsed
// *bundle.Bundle where the world produces its own SignedEntity — and
// a real bundle is the stronger fixture anyway.

package trust_test

import (
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/testing/data"

	"github.com/monumental-archive/stele/internal/trust"
)

// The othername bundle is a real cosign blob signature over a sha256
// digest, issued by the scaffolding CA — the one shipped bundle whose
// subject digest is the algorithm this verifier speaks.
const (
	othernameSAN    = "foo!oidc.local"
	othernameDigest = "bc103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b"
)

// upstreamVerifier stands up a verifier over one of upstream's
// trusted roots, through this package's own loader — so the material
// arrives the way production material does.
func upstreamVerifier(t *testing.T, rootName string) *trust.Verifier {
	t.Helper()

	rootJSON, err := data.TrustedRoot(t, rootName).MarshalJSON()
	if err != nil {
		t.Fatalf("marshalling %s: %v", rootName, err)
	}

	tr, err := trust.LoadRoot(rootJSON)
	if err != nil {
		t.Fatalf("LoadRoot = %v", err)
	}

	v, err := trust.NewVerifier(tr)
	if err != nil {
		t.Fatalf("NewVerifier = %v", err)
	}

	return v
}

// loadBundle parses one of upstream's bundles through LoadBundle.
func loadBundle(t *testing.T, name string) *bundle.Bundle {
	t.Helper()

	bundleJSON, err := data.Bundle(t, name).MarshalJSON()
	if err != nil {
		t.Fatalf("marshalling %s: %v", name, err)
	}

	b, err := trust.LoadBundle(bundleJSON)
	if err != nil {
		t.Fatalf("LoadBundle = %v", err)
	}

	return b
}

// TestMeasureBlobReportsTheSignerNobodyNamed is the contract in one
// assertion: no Identity is passed, and the SAN comes back.
func TestMeasureBlobReportsTheSignerNobodyNamed(t *testing.T) {
	t.Parallel()

	v := upstreamVerifier(t, "scaffolding.json")
	b := loadBundle(t, "othername.sigstore.json")

	got, err := v.MeasureBlob(b, algSHA256, othernameDigest)
	if err != nil {
		t.Fatalf("MeasureBlob = %v", err)
	}

	if got.SAN != othernameSAN {
		t.Errorf("SAN = %q, want the identity the certificate carries", got.SAN)
	}

	// A blob signature covers the artifact the caller already holds,
	// so there is no payload to hand back — the same shape VerifyBlob
	// returns, because it is the same question asked without a name.
	if got.Payload != nil {
		t.Errorf("Payload = %q, want nil for a blob measurement", got.Payload)
	}

	// The measurement still states the depth it reached. A level rests
	// on this: an identity read from a certificate nobody countersigned
	// is an identity anybody could have minted.
	if len(got.Observed) == 0 {
		t.Error("the measurement reports no observation, so nothing dates the signature")
	}
}

// TestObservedInstantRenders: a verdict has to say not just THAT the
// signature was observed but when, by what class of countersignature,
// and by which log. An operator reading a level back months later has
// only this line to tell a Rekor inclusion from a CT countersignature
// from a timestamp authority — and the three carry different weight,
// which is why the proof floor is expressed over them.
func TestObservedInstantRenders(t *testing.T) {
	t.Parallel()

	v := upstreamVerifier(t, "scaffolding.json")

	got, err := v.MeasureBlob(loadBundle(t, "othername.sigstore.json"), algSHA256, othernameDigest)
	if err != nil {
		t.Fatalf("MeasureBlob = %v", err)
	}

	if len(got.Observed) == 0 {
		t.Fatal("nothing was observed, so there is no instant to render")
	}

	for _, o := range got.Observed {
		rendered := o.String()

		for _, want := range []string{
			o.Time().UTC().Format(time.RFC3339),
			o.Source(),
			o.Log(),
		} {
			if want == "" {
				t.Errorf("an observation carries an empty field: %+v", o)

				continue
			}

			if !strings.Contains(rendered, want) {
				t.Errorf("String() = %q, want it to carry %q", rendered, want)
			}
		}
	}
}

// TestMeasureRefusesWhatItCannotProve. Dropping the identity check
// drops ONLY the identity check. Each row is something the gating path
// refuses, and the measuring path must refuse it identically — a
// measurement that shrugged here would report a signer for bytes the
// signature does not cover, and `stele level` would publish it.
func TestMeasureRefusesWhatItCannotProve(t *testing.T) {
	t.Parallel()

	v := upstreamVerifier(t, "scaffolding.json")
	blob := loadBundle(t, "othername.sigstore.json")
	dsse := loadBundle(t, "dsse.sigstore.json")

	for _, tt := range []struct {
		name string
		call func() error
		want string
	}{
		{
			name: "a digest that is not hex",
			call: func() error { _, err := v.MeasureBlob(blob, algSHA256, "zz"); return err },
			want: "not hex",
		},
		{
			name: "an empty digest",
			call: func() error { _, err := v.MeasureBlob(blob, algSHA256, ""); return err },
			want: "not hex",
		},
		{
			// One digit changed: the same bundle, a different artifact.
			name: "a digest the signature does not cover",
			call: func() error {
				_, err := v.MeasureBlob(blob, algSHA256, "ac"+othernameDigest[2:])

				return err
			},
			want: "measure",
		},
		{
			name: "an attestation about another artifact",
			call: func() error { _, err := v.MeasureAttestation(dsse, algSHA256, othernameDigest); return err },
			want: "measure",
		},
		{
			name: "an attestation digest that is not hex",
			call: func() error { _, err := v.MeasureAttestation(dsse, algSHA256, "nothex"); return err },
			want: "not hex",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.call()
			if err == nil {
				t.Fatal("the measurement accepted what it cannot prove")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

// TestMeasureRefusesAForeignWorld: the trusted root still decides. A
// bundle signed under a CA this verifier does not carry is refused,
// identity or no identity — otherwise "assert no identity" would mean
// "trust anybody", and every repository could measure itself to any
// level it liked.
func TestMeasureRefusesAForeignWorld(t *testing.T) {
	t.Parallel()

	// The public-good root knows nothing of the scaffolding CA that
	// issued this bundle.
	v := upstreamVerifier(t, "public-good.json")
	blob := loadBundle(t, "othername.sigstore.json")

	if _, err := v.MeasureBlob(blob, algSHA256, othernameDigest); err == nil {
		t.Fatal("MeasureBlob accepted a bundle from a CA this verifier does not trust")
	}
}
