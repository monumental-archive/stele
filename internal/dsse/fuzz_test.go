// Fuzz target for the DSSE base64 decoder (#38): envelope payloads
// arrive from whatever produced the bundle, in whichever base64
// dialect it spoke — the decoder's leniency rules are exactly the
// kind of code a malformed producer exercises.

package dsse_test

import (
	"testing"

	"github.com/monumental-archive/stele/internal/dsse"
)

func FuzzDecodeBase64(f *testing.F) {
	f.Add("eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbXX0=")
	f.Add("eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbXX0")
	f.Add("not base64 !!!")
	f.Add("")

	f.Fuzz(func(_ *testing.T, s string) {
		if _, err := dsse.DecodeBase64(s); err != nil {
			return // a refusal is an answer; only a panic is a finding
		}
	})
}
