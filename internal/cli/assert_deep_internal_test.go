// The full-depth wiring's own guards: the store adapter's slug shape,
// the trust-authority loader's refusals, and the engine delegation's
// fail-closed validation (the engine itself is proven in
// internal/verify).

package cli

import (
	"bytes"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/verify"
)

func TestForgeStore(t *testing.T) {
	t.Parallel()

	t.Run("a slug that is not owner/repo refuses", func(t *testing.T) {
		t.Parallel()

		if _, err := (forgeStore{forge: &storeForge{}}).Bundles("solo", strings.Repeat("a", 64)); err == nil {
			t.Fatal("Bundles accepted a slug with no owner")
		}
	})

	t.Run("bundles arrive addressed", func(t *testing.T) {
		t.Parallel()

		f := &storeForge{bundles: []jsonx.Raw{jsonx.Raw(`{"a":1}`), jsonx.Raw(`{"b":2}`)}}

		out, err := (forgeStore{forge: f}).Bundles("acme/widget", strings.Repeat("a", 64))
		if err != nil || len(out) != 2 {
			t.Fatalf("Bundles = %d, %v", len(out), err)
		}

		if !strings.HasPrefix(out[0].URI, "store://acme/widget/sha256:") {
			t.Fatalf("URI = %q — the verdict must be able to name its evidence by address", out[0].URI)
		}
	})
}

func TestLoadFullDepth(t *testing.T) {
	t.Parallel()

	t.Run("an unreadable verify policy refuses", func(t *testing.T) {
		t.Parallel()

		if _, err := loadFullDepth("/no/such/verify-policy.json", "/no/such/root.json", &storeForge{}); err == nil {
			t.Fatal("loadFullDepth accepted a missing verify policy")
		}
	})

	t.Run("a malformed verify policy refuses", func(t *testing.T) {
		t.Parallel()

		p := filepath.Join(t.TempDir(), "vp.json")
		if err := os.WriteFile(p, []byte(`{"schema": 1}`), 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := loadFullDepth(p, "/no/such/root.json", &storeForge{}); err == nil {
			t.Fatal("loadFullDepth accepted a policy with no trust section")
		}
	})
}

// TestLoadFullDepthHappyPath proves the wiring assembles when the
// trust authority is readable — the crypto seam is swapped, the
// policy is real.
func TestLoadFullDepthHappyPath(t *testing.T) {
	dir := t.TempDir()

	vp := filepath.Join(dir, "vp.json")
	if err := os.WriteFile(vp, []byte(testPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(dir, "root.json")
	if err := os.WriteFile(root, []byte(`{"any": "bytes"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	orig := newBundleVerifier
	newBundleVerifier = func([]byte) (verify.BundleVerifier, error) { return attestorBV{}, nil }

	t.Cleanup(func() { newBundleVerifier = orig })

	full, err := loadFullDepth(vp, root, &storeForge{})
	if err != nil {
		t.Fatalf("loadFullDepth = %v", err)
	}

	if full.CanonOwner != "acme" || full.CanonRepo != "canon" {
		t.Fatalf("roots = %s/%s, want the verifier workflow's own repository", full.CanonOwner, full.CanonRepo)
	}

	if _, err := loadFullDepth(vp, filepath.Join(dir, "absent"), &storeForge{}); err == nil {
		t.Fatal("loadFullDepth accepted a missing trusted root")
	}
}

// passDeep accepts everything — the walk's own branch is under test.
type passDeep struct{}

func (passDeep) Release(verify.Coords, []verify.Subject, []verify.Subject, verify.Pins, bool) error {
	return nil
}
func (passDeep) VSA(verify.Coords, []verify.Subject, verify.Pins) error { return nil }

// TestAssertEvidenceFullDepth drives the whole CLI at --depth full
// over a snapshot, with the engine seam scripted to pass — the flag
// path, the trust-authority load and the walk's deep branch in one
// stroke.
func TestAssertEvidenceFullDepth(t *testing.T) {
	snap, policyPath := evidenceSnapshot(t)
	dir := filepath.Dir(snap)

	// The deep branch reads the checksum manifest and the pin trees.
	// Snapshot FileAt stores the path as one escaped segment.
	digest := strings.Repeat("5", 64)
	wfSeg := url.PathEscape(".github/workflows/publish.yml")
	files := map[string]string{
		"acme/widget/releases/v1.0.0/assets/checksums.txt": digest + "  app\n",
		"acme/widget/files/v1.0.0/" + wfSeg: "uses: acme/canon/.github/workflows/publish.yml@" +
			strings.Repeat("a", 40) + "\n",
		"acme/canon/files/" + strings.Repeat("a", 40) + "/" + wfSeg: "uses: acme/signer/.github/workflows/sign.yml@" +
			strings.Repeat("b", 40) + "\n",
	}
	for p, c := range files {
		full := filepath.Join(snap, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(full, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	vp := filepath.Join(dir, "vp.json")
	if err := os.WriteFile(vp, []byte(testPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(dir, "root.json")
	if err := os.WriteFile(root, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	origBV, origDeep := newBundleVerifier, newDeepVerifier
	newBundleVerifier = func([]byte) (verify.BundleVerifier, error) { return attestorBV{}, nil }
	newDeepVerifier = func(vp *policy.Policy, _ gh.Forge, _ verify.BundleVerifier) (*assert.FullDepth, error) {
		return assert.NewFullDepth(passDeep{}, *vp.Trust.Verdict.VerifierWorkflow, *vp.Trust.Provenance.SignerWorkflow)
	}

	t.Cleanup(func() { newBundleVerifier, newDeepVerifier = origBV, origDeep })

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "evidence", "--org", "acme", "--policy", policyPath, "--snapshot", snap,
		"--trusted-root", root, "--verify-policy", vp, "--depth", "full",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	if !strings.Contains(stderr.String()+stdout.String(), "full depth") {
		t.Fatalf("output names no deep leg:\n%s%s", stdout.String(), stderr.String())
	}
}

// TestEngineVerifierFailsClosed pins the delegation: the engine's own
// input validation refuses before any network or crypto, so an empty
// subject list can never verify.
func TestEngineVerifierFailsClosed(t *testing.T) {
	t.Parallel()

	vp, err := policy.Load(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}

	ev := &engineVerifier{vp: vp, store: forgeStore{forge: &storeForge{}}, bv: attestorBV{}}
	c := verify.Coords{Owner: "acme", Repo: "widget", Tag: "v1.0.0"}
	pins := verify.Pins{Canon: strings.Repeat("a", 40), Signer: strings.Repeat("b", 40)}

	if rerr := ev.Release(c, nil, nil, pins, true); rerr == nil {
		t.Fatal("Release verified an empty subject list")
	}

	if verr := ev.VSA(c, nil, pins); verr == nil {
		t.Fatal("VSA verified an empty subject list")
	}

	if perr := ev.Release(c, nil, nil, pins, false); perr == nil {
		t.Fatal("provenance-only Release verified an empty subject list")
	}
}
