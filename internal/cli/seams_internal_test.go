// What the swappable seams are when nobody has swapped them.
//
// Every verb here reaches the network, the toolchain or the working
// tree through a package-level variable that tests replace. That makes
// the tests hermetic and leaves exactly one thing unasserted: the
// PRODUCTION value. A stub left behind as a default would not fail a
// single test in this package — every one of them installs its own —
// and would ship a binary that derives empty inventories, reads no
// rules, and resolves no publication times, all of it looking like a
// clean run.
//
// The token lookup is asserted for the same reason. Two spellings are
// in use across the org's runners (GITHUB_TOKEN is what a workflow
// sets by default, GH_TOKEN what the CLI and a developer's shell use),
// and a client built with an empty token is anonymous — which does not
// fail, it just gets rate-limited into a degraded read that the walk
// then reports as CANNOT_JUDGE.

package cli

import (
	"testing"

	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/pkgtime"
)

// TestSeamsDefaultToProduction: each seam, unswapped, is the real
// thing rather than nil or a stand-in.
func TestSeamsDefaultToProduction(t *testing.T) {
	if _, ok := newVEXScanner().(osv.Runner); !ok {
		t.Errorf("newVEXScanner = %T, want the osv-scanner binary", newVEXScanner())
	}

	resolver, ok := newPkgTime().(*pkgtime.Client)
	if !ok {
		t.Fatalf("newPkgTime = %T, want the registry client", newPkgTime())
	}

	// The registry the package doc rests its trust argument on: the
	// same checksummed proxy a Go build already fetches through, never
	// a host this tool introduced.
	if resolver.GoProxy != "https://proxy.golang.org" {
		t.Errorf("newPkgTime resolves against %q", resolver.GoProxy)
	}

	if newForge() == nil {
		t.Error("newForge produced no forge client")
	}
}

// TestForgeClientsReadEitherTokenSpelling. GITHUB_TOKEN is what a
// workflow gets for free; GH_TOKEN is what the CLI and a developer's
// shell set. Both clients must accept either, and prefer the first
// where both are present — an anonymous client does not fail loudly,
// it degrades into rate-limited reads that surface much later as an
// unjudgeable population.
func TestForgeClientsReadEitherTokenSpelling(t *testing.T) {
	for _, tt := range []struct {
		name              string
		github, gh, plain string
	}{
		{"the workflow's spelling", "from-github-token", "", "from-github-token"},
		{"the shell's spelling", "", "from-gh-token", "from-gh-token"},
		{"both, the workflow's wins", "from-github-token", "from-gh-token", "from-github-token"},
		{"neither, which is anonymous", "", "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GITHUB_TOKEN", tt.github)
			t.Setenv("GH_TOKEN", tt.gh)

			if got := newRulesClient(); got == nil {
				t.Fatal("newRulesClient produced no client")
			}

			if got := newMetaClient("https://github.example"); got == nil {
				t.Fatal("newMetaClient produced no client")
			}
		})
	}
}

// TestOpenFactsGitReadsARealCheckout: the released checkout is opened
// through the same git boundary every other verb uses, so a directory
// that is not a repository refuses here rather than producing facts
// about nothing.
func TestOpenFactsGitReadsARealCheckout(t *testing.T) {
	t.Parallel()

	if _, err := openFactsGit(t.TempDir()); err == nil {
		t.Error("openFactsGit accepted a directory git does not recognise")
	}
}
