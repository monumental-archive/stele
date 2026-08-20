// Fuzz targets for the assert verb's foreign-byte readers (#38):
// bundle assets are JSONL somebody else wrote and the assert policy
// is a stranger's committed data. Both seeds are real org artifacts —
// a live bundle line and the canon's committed policy — never
// invented shapes. The debt file's target moved to internal/report
// with the parser (#147).

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
	f.Add([]byte(`{"schema": 6, "evidence": {}}`))
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
