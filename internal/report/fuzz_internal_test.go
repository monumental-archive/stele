// The debt file is hand-edited text a human commits, so its parser
// meets bytes nobody validated (#38). The seed is the canon's own
// committed file — a real artifact, never an invented shape.

package report

import (
	"os"
	"testing"
)

func FuzzParseDebt(f *testing.F) {
	b, err := os.ReadFile("testdata/debt-seed.txt")
	if err != nil {
		f.Fatal(err)
	}

	f.Add(b)
	f.Add([]byte("# comment only\n"))
	f.Add([]byte("widget@v1.0.0(sbom)\n"))
	f.Add([]byte("malformed line\n"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		if _, err := ParseDebt(data, "fuzz"); err != nil {
			return // a refusal is an answer; only a panic is a finding
		}
	})
}
