// Fuzz targets for the trust boundary's two foreign-byte parsers
// (#38): the Sigstore trusted root and attestation bundles are the
// bytes a hostile or broken producer hands the verifier, and a panic
// inside the crypto layer's decoders is a denial of judgment. Seeds
// are real org artifacts — the trusted root gh serves and a bundle
// from the live attestation store — never invented shapes.

package trust_test

import (
	"os"
	"testing"

	"github.com/monumental-archive/stele/internal/trust"
)

func seed(f *testing.F, path string) {
	f.Helper()

	b, err := os.ReadFile(path) //nolint:gosec // fixed testdata paths, fuzz seeds
	if err != nil {
		f.Fatal(err)
	}

	f.Add(b)
}

func FuzzLoadRoot(f *testing.F) {
	seed(f, "testdata/trusted-root-seed.json")
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		if _, err := trust.LoadRoot(data); err != nil {
			return // a refusal is an answer; only a panic is a finding
		}
	})
}

func FuzzLoadBundle(f *testing.F) {
	seed(f, "testdata/bundle-seed.jsonl")
	f.Add([]byte(`{"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3"}`))
	f.Add([]byte(`[]`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		if _, err := trust.LoadBundle(data); err != nil {
			return // a refusal is an answer; only a panic is a finding
		}
	})
}
