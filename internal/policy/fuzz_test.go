// Fuzz target for the verify-policy loader (#38): the committed
// policy is reviewed data, but the loader is a foreign-byte parser
// all the same — a stranger runs this binary against a policy stele's
// authors never saw, and validation must refuse malformed input with
// an error, never a panic. Seeded with the first conforming org's
// real policy.

package policy_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/monumental-archive/stele/internal/policy"
)

func FuzzLoad(f *testing.F) {
	b, err := os.ReadFile("testdata/policy-seed.json")
	if err != nil {
		f.Fatal(err)
	}

	f.Add(b)
	f.Add([]byte(`{"schema": 6}`))
	f.Add([]byte(`{`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		if _, err := policy.Load(bytes.NewReader(data)); err != nil {
			return // a refusal is an answer; only a panic is a finding
		}
	})
}
