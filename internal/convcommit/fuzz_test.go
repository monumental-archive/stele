// Fuzz target for the conventional-commit parser (#38, named as a
// fuzz surface when #6 closed into #38): commit messages are
// human-typed bytes with no schema at all, and the version derivation
// walks every one of them. Seeds are real messages from this
// repository's own history.

package convcommit_test

import (
	"testing"

	"github.com/monumental-archive/stele/internal/convcommit"
)

func FuzzParse(f *testing.F) {
	f.Add("feat(assert): re-verify the corpus with --depth full (#78)\n\nBody text.\n\nCloses #4.")
	f.Add("fix(assert): retry transport, split classes, narrow the burn (#70)")
	f.Add("chore: release v0.5.0 (#72)")
	f.Add("feat!: breaking\n\nBREAKING CHANGE: the flag is gone")
	f.Add("revert: \"feat(x): y\"")
	f.Add("not a conventional message at all")
	f.Add("")

	f.Fuzz(func(_ *testing.T, message string) {
		if _, err := convcommit.Parse(message); err != nil {
			return // a refusal is an answer; only a panic is a finding
		}
	})
}
