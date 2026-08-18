// Fuzz targets for the assert verb's foreign-byte readers (#38):
// bundle assets are JSONL somebody else wrote, the assert policy is a
// stranger's committed data, and the debt file is hand-edited text.
// All three seeds are real org artifacts — a live bundle line, the
// canon's committed policy and debt file — never invented shapes.

package assert

import (
	"os"
	"strings"
	"testing"
)

func fuzzSeed(f *testing.F, path string) {
	f.Helper()

	b, err := os.ReadFile(path) //nolint:gosec // fixed testdata paths, fuzz seeds
	if err != nil {
		f.Fatal(err)
	}

	f.Add(b)
}

func FuzzLoadPolicy(f *testing.F) {
	fuzzSeed(f, "testdata/policy-seed.json")
	f.Add([]byte(`{"schema": 1, "evidence": {}}`))
	f.Add([]byte(`null`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		if _, err := LoadPolicy(strings.NewReader(string(data))); err != nil {
			return // a refusal is an answer; only a panic is a finding
		}
	})
}

func FuzzSubjectDigests(f *testing.F) {
	fuzzSeed(f, "testdata/bundle-line-seed.jsonl")
	f.Add([]byte(`{"dsseEnvelope": {"payload": "e30="}}`))
	f.Add([]byte("\n\n"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		if _, err := subjectDigests(data); err != nil {
			return // a refusal is an answer; only a panic is a finding
		}
	})
}

func FuzzParseDebt(f *testing.F) {
	fuzzSeed(f, "testdata/debt-seed.txt")
	f.Add([]byte("# comment only\n"))
	f.Add([]byte("widget@v1.0.0(sbom)\n"))
	f.Add([]byte("malformed line\n"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		if _, err := ParseDebt(data, "fuzz"); err != nil {
			return // a refusal is an answer; only a panic is a finding
		}
	})
}
