// The production wiring itself: the effect seams every other test
// swaps away, plus the adapters between this layer and the trust
// boundary. Nothing here is a stand-in — the trusted roots and
// bundles are upstream's own signed material, and the git repository
// is a real one — because a seam proven only through its fake proves
// the fake.

package cli

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/data"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/ghstore"
	"github.com/monumental-archive/stele/internal/oci"
	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/trust"
)

// The othername bundle is a real cosign blob signature over a sha256
// digest, issued by the scaffolding CA — upstream's own material, and
// the only shipped bundle whose subject digest is the algorithm this
// adapter speaks.
const (
	othernameSAN    = "foo!oidc.local"
	othernameIssuer = "http://oidc.local:8080"
	othernameDigest = "bc103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b"
)

// upstreamRoot marshals one of upstream's trusted roots back to the
// JSON the seam reads.
func upstreamRoot(t *testing.T, name string) []byte {
	t.Helper()

	out, err := data.TrustedRoot(t, name).MarshalJSON()
	if err != nil {
		t.Fatalf("marshalling %s: %v", name, err)
	}

	return out
}

// upstreamBundle marshals one of upstream's bundles back to JSON.
func upstreamBundle(t *testing.T, name string) []byte {
	t.Helper()

	out, err := data.Bundle(t, name).MarshalJSON()
	if err != nil {
		t.Fatalf("marshalling %s: %v", name, err)
	}

	return out
}

// TestNewBundleVerifier drives the real constructor: a trusted root
// that parses builds the adapter, and one that does not refuses by
// name rather than handing back a verifier that trusts nothing.
func TestNewBundleVerifier(t *testing.T) {
	t.Parallel()

	bv, err := newBundleVerifier(upstreamRoot(t, "public-good.json"))
	if err != nil {
		t.Fatalf("newBundleVerifier = %v", err)
	}

	if _, ok := bv.(trustAdapter); !ok {
		t.Fatalf("newBundleVerifier returned %T, want the trust adapter", bv)
	}

	if _, err := newBundleVerifier([]byte("not json")); err == nil ||
		!strings.Contains(err.Error(), "trusted root") {
		t.Fatalf("newBundleVerifier(junk) = %v, want the trusted-root refusal", err)
	}
}

// TestTrustAdapterBlob proves the adapter end to end over real signed
// material: the blob bundle verifies against the CA that issued it,
// under the identity in its certificate and the digest in its
// message signature. Every hop is the production one.
func TestTrustAdapterBlob(t *testing.T) {
	t.Parallel()

	bv, err := newBundleVerifier(upstreamRoot(t, "scaffolding.json"))
	if err != nil {
		t.Fatalf("newBundleVerifier = %v", err)
	}

	bundleJSON := upstreamBundle(t, "othername.sigstore.json")
	id := trust.Identity{SAN: othernameSAN, Issuer: othernameIssuer}

	verified, err := bv.Blob(bundleJSON, id, othernameDigest)
	if err != nil {
		t.Fatalf("Blob = %v", err)
	}

	if verified.SAN != othernameSAN {
		t.Errorf("SAN = %q, want %q", verified.SAN, othernameSAN)
	}

	if verified.Payload != nil {
		t.Errorf("Payload = %q — a blob signature covers the artifact, not a payload", verified.Payload)
	}

	// One digit of the digest changed: the same bundle, a different
	// artifact, and the adapter must refuse.
	other := "ac" + othernameDigest[2:]
	if _, err := bv.Blob(bundleJSON, id, other); err == nil || !strings.Contains(err.Error(), "blob") {
		t.Fatalf("Blob over a different digest = %v, want the refusal", err)
	}
}

// TestTrustAdapterRefusals walks the adapter's own guards: bytes that
// are not a bundle refuse at parse, under each of the three
// operations, so a caller can tell which read failed.
func TestTrustAdapterRefusals(t *testing.T) {
	t.Parallel()

	bv, err := newBundleVerifier(upstreamRoot(t, "public-good.json"))
	if err != nil {
		t.Fatalf("newBundleVerifier = %v", err)
	}

	id := trust.Identity{SAN: othernameSAN, Issuer: othernameIssuer}
	junk := []byte("not a bundle")

	if _, err := bv.Attestation(junk, id, othernameDigest); err == nil ||
		!strings.Contains(err.Error(), "attestation") {
		t.Errorf("Attestation(junk) = %v, want the attestation refusal", err)
	}

	if _, err := bv.Blob(junk, id, othernameDigest); err == nil || !strings.Contains(err.Error(), "blob") {
		t.Errorf("Blob(junk) = %v, want the blob refusal", err)
	}

	if _, err := bv.Peek(junk); err == nil || !strings.Contains(err.Error(), "peek") {
		t.Errorf("Peek(junk) = %v, want the peek refusal", err)
	}

	// A real DSSE bundle whose statement names a different artifact:
	// the bundle parses, the verification refuses.
	dsseBundle := upstreamBundle(t, "dsse.sigstore.json")
	if _, err := bv.Attestation(dsseBundle, id, othernameDigest); err == nil ||
		!strings.Contains(err.Error(), "attestation") {
		t.Errorf("Attestation over a foreign subject = %v, want the refusal", err)
	}
}

// TestTrustAdapterPeek: the selection read returns the envelope's own
// payload without verifying anything, which is exactly why nothing
// read through it may inform a verdict.
func TestTrustAdapterPeek(t *testing.T) {
	t.Parallel()

	bv, err := newBundleVerifier(upstreamRoot(t, "public-good.json"))
	if err != nil {
		t.Fatalf("newBundleVerifier = %v", err)
	}

	payload, err := bv.Peek(upstreamBundle(t, "dsse.sigstore.json"))
	if err != nil {
		t.Fatalf("Peek = %v", err)
	}

	if !strings.Contains(string(payload), `"predicateType"`) {
		t.Errorf("Peek = %q, want the statement body", payload)
	}
}

// TestNewStore pins the store seam's two decisions: which token the
// environment supplies, and the auditor stance behind --no-retry.
func TestNewStore(t *testing.T) {
	tokens := []struct {
		name             string
		gitHubTok, ghTok string
		want             string
	}{
		{"GITHUB_TOKEN is read", "primary", "", "primary"},
		{"GH_TOKEN is the fallback", "", "secondary", "secondary"},
		{"GITHUB_TOKEN wins", "primary", "secondary", "primary"},
		{"neither is anonymous", "", "", ""},
	}

	for _, tc := range tokens {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GITHUB_TOKEN", tc.gitHubTok)
			t.Setenv("GH_TOKEN", tc.ghTok)

			c, ok := newStore(false).(*ghstore.Client)
			if !ok {
				t.Fatalf("newStore returned %T, want the API client", c)
			}

			if c.Token != tc.want {
				t.Errorf("Token = %q, want %q", c.Token, tc.want)
			}

			if c.Attempts != ghstore.DefaultAttempts {
				t.Errorf("Attempts = %d, want the propagation ladder", c.Attempts)
			}
		})
	}

	t.Run("--no-retry is one look", func(t *testing.T) {
		t.Setenv("GITHUB_TOKEN", "")
		t.Setenv("GH_TOKEN", "")

		c, ok := newStore(true).(*ghstore.Client)
		if !ok {
			t.Fatalf("newStore returned %T, want the API client", c)
		}

		if c.Attempts != 1 {
			t.Errorf("Attempts = %d, want 1 — auditing history fails fast", c.Attempts)
		}
	})
}

// TestNewForge pins the same token contract on the forge seam.
func TestNewForge(t *testing.T) {
	for _, tc := range []struct {
		name             string
		gitHubTok, ghTok string
		want             string
	}{
		{"GITHUB_TOKEN is read", "primary", "", "primary"},
		{"GH_TOKEN is the fallback", "", "secondary", "secondary"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GITHUB_TOKEN", tc.gitHubTok)
			t.Setenv("GH_TOKEN", tc.ghTok)

			c, ok := newForge().(*gh.Client)
			if !ok {
				t.Fatalf("newForge returned %T, want the API client", c)
			}

			if c.Token != tc.want {
				t.Errorf("Token = %q, want %q", c.Token, tc.want)
			}
		})
	}
}

// TestDefaultSeamsAreTheLiveImplementations: the zero configuration
// must be the production one. A seam left nil would panic on its
// first use, and a seam pointing at a test double would ship a binary
// that judges nothing.
func TestDefaultSeamsAreTheLiveImplementations(t *testing.T) {
	t.Parallel()

	if _, ok := newOCIReader().(oci.Client); !ok {
		t.Errorf("newOCIReader = %T, want the live registry client", newOCIReader())
	}

	if _, ok := newScanner().(osv.Runner); !ok {
		t.Errorf("newScanner = %T, want the osv-scanner runner", newScanner())
	}
}

// gitWorld builds a real one-commit repository — the git boundary is
// what these seams open, and a fake git here would leave the seam
// untested.
func gitWorld(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	git := func(args ...string) {
		t.Helper()

		cmd := exec.Command("git", //nolint:gosec,noctx // fixed executable, test-owned args
			append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_CONFIG_SYSTEM=/dev/null",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		)

		var out bytes.Buffer

		cmd.Stdout, cmd.Stderr = &out, &out

		if err := cmd.Run(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out.String())
		}
	}

	git("init", "-q", "-b", "main")

	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}

	git("add", "f")
	git("commit", "-q", "-m", "one")

	return dir
}

// TestGitSeamsOpenRealRepositories: both git seams open a real clone
// and refuse a directory that is not one — the walk's first input is
// the checkout, and "no history" must be a refusal rather than an
// empty walk that reports coverage over nothing.
func TestGitSeamsOpenRealRepositories(t *testing.T) {
	t.Parallel()

	dir := gitWorld(t)

	if _, err := openHistory(dir, "refs/notes/commits"); err != nil {
		t.Errorf("openHistory over a real clone = %v", err)
	}

	if _, err := openDeriveGit(dir); err != nil {
		t.Errorf("openDeriveGit over a real clone = %v", err)
	}

	notARepo := t.TempDir()

	if _, err := openHistory(notARepo, "refs/notes/commits"); err == nil {
		t.Error("openHistory accepted a directory that is not a clone")
	}

	if _, err := openDeriveGit(notARepo); err == nil {
		t.Error("openDeriveGit accepted a directory that is not a clone")
	}
}

// fakeCosign writes a stand-in cosign onto PATH. body is the shell
// after the shebang, so each case scripts one signer behaviour.
func fakeCosign(t *testing.T, body string) {
	t.Helper()

	dir := t.TempDir()

	//nolint:gosec // a test script must execute
	if err := os.WriteFile(filepath.Join(dir, "cosign"), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", dir)
}

// TestCosignSignerGuards covers the signer's remaining guards beside
// the round trip in emit_internal_test.go: preflight against a cosign
// that runs, against none at all, and — the one that matters — a
// cosign that exits ZERO and leaves no bundle behind. A signer that
// reported success there would append an unsigned link.
func TestCosignSignerGuards(t *testing.T) {
	t.Run("preflight accepts a cosign that runs", func(t *testing.T) {
		fakeCosign(t, `exit 0`)

		if err := newSigner(t.TempDir()).Check(); err != nil {
			t.Fatalf("Check = %v", err)
		}
	})

	t.Run("preflight refuses an absent cosign by name", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())

		if err := newSigner(t.TempDir()).Check(); err == nil ||
			!strings.Contains(err.Error(), "not usable on PATH") {
			t.Fatalf("Check = %v, want the preflight refusal", err)
		}
	})

	t.Run("a cosign that writes no bundle refuses", func(t *testing.T) {
		fakeCosign(t, `exit 0`)

		if _, err := newSigner(t.TempDir()).Sign([]byte("{}")); err == nil ||
			!strings.Contains(err.Error(), "reading the signed bundle") {
			t.Fatalf("Sign = %v, want the missing-bundle refusal", err)
		}
	})

	t.Run("a staging directory that does not exist refuses", func(t *testing.T) {
		fakeCosign(t, `exit 0`)

		signer := newSigner(filepath.Join(t.TempDir(), "absent"))

		if _, err := signer.Sign([]byte("{}")); err == nil ||
			!strings.Contains(err.Error(), "staging the payload") {
			t.Fatalf("Sign = %v, want the staging refusal", err)
		}
	})
}

// TestOthernameDigestIsHex keeps the pinned digest honest: a constant
// that is not hex would make every assertion above vacuous.
func TestOthernameDigestIsHex(t *testing.T) {
	t.Parallel()

	if _, err := hex.DecodeString(othernameDigest); err != nil {
		t.Fatalf("the pinned digest is not hex: %v", err)
	}
}
