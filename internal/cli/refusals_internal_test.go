// The refusals and the two forge modes that the end-to-end tests do
// not reach: bad flags, exclusive flags, unreadable and unparsable
// inputs, capture-through, and the loaders' own guards. Each row
// breaks exactly one thing and names the refusal it must produce — a
// usage error that silently became a shallower walk is the failure
// mode these guards exist for.

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/verify"
)

// baseImagesPolicy loads a policy declaring the base-approval half,
// which is what makes the store halves' inputs required.
func baseImagesPolicy(t *testing.T, pinFile string) *assert.Policy {
	t.Helper()

	content := `{"schema": 4, "issuer": "https://token.example.com",
	  "evidence": {"sbomSuffix": ".spdx.json", "checksums": "checksums.txt",
	    "umbrellaBundle": "attestations.intoto.jsonl", "manifestAsset": "evidence-manifest.json",
	    "debtFile": "no-such-debt.txt",
	    "classes": {"oci-image": {"bundles": ["b.jsonl"]}},
	    "baseImages": {"pinFile": "` + pinFile + `", "attestorRepo": ".github",
	      "attestorIdentity": "https://github.com/acme/.github/.github/workflows/base-attest.yml@refs/heads/main",
	      "predicateType": "https://acme.example/approval/v1"}}}`

	pol, err := assert.LoadPolicy(strings.NewReader(content))
	if err != nil {
		t.Fatalf("loading the base-images policy: %v", err)
	}

	return pol
}

// swapForge installs a scripted forge for one test, so --capture wraps
// something that answers without reaching the network.
func swapForge(t *testing.T, f gh.Forge) {
	t.Helper()

	orig := newForge
	newForge = func() gh.Forge { return f }

	t.Cleanup(func() { newForge = orig })
}

// TestAssertCaptureThrough pins the capture mode on all three walking
// targets: the walk answers AND leaves a snapshot behind. A capture
// that recorded nothing would still exit 0, so the directory is the
// assertion.
func TestAssertCaptureThrough(t *testing.T) {
	t.Run("evidence", func(t *testing.T) {
		snap, policy := evidenceSnapshot(t)
		swapForge(t, gh.Snapshot{Dir: snap})

		into := filepath.Join(t.TempDir(), "capture")

		var stdout, stderr bytes.Buffer

		if code := Run([]string{"assert", "evidence", "--org", "acme", "--policy", policy, "--capture", into},
			&stdout, &stderr); code != exitOK {
			t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}

		assertRecorded(t, into)
	})

	t.Run("blast-radius", func(t *testing.T) {
		snap, policy, vex := blastSnapshot(t)
		swapForge(t, gh.Snapshot{Dir: snap})
		// The policy declares a canary, so the scan must report it:
		// anything else is CANNOT_JUDGE, and the capture would not be
		// what failed.
		swapScanner(t, cliScanner{out: `{"results": [{"packages": [{
		  "package": {"name": "serde_cbor", "version": "0.11.2", "ecosystem": "crates.io"},
		  "vulnerabilities": [{"id": "RUSTSEC-2021-0127", "affected": []}]}]}]}`})

		into := filepath.Join(t.TempDir(), "capture")

		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"assert", "blast-radius", "--org", "acme", "--policy", policy, "--vex", vex, "--capture", into,
		}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}

		assertRecorded(t, into)
	})

	t.Run("tags", func(t *testing.T) {
		snap, policy := tagsSnapshot(t)
		swapForge(t, gh.Snapshot{Dir: snap})
		swapTagVerifier(t, scriptedTagVerifier{})

		root := filepath.Join(t.TempDir(), "root.json")
		if err := os.WriteFile(root, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}

		into := filepath.Join(t.TempDir(), "capture")

		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"assert", "tags", "--repo", "acme/widget", "--policy", policy,
			"--trusted-root", root, "--capture", into,
		}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}

		assertRecorded(t, into)
	})
}

// assertRecorded fails unless the capture directory holds something.
func assertRecorded(t *testing.T, dir string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("the capture wrote no directory: %v", err)
	}

	if len(entries) == 0 {
		t.Fatal("the capture directory is empty — the walk recorded nothing it read")
	}
}

// TestAssertTagsForgeCannotReadTags: the tag audit needs a forge that
// reads refs, and one that cannot must refuse by name rather than
// walk an empty tag list to PASS.
func TestAssertTagsForgeCannotReadTags(t *testing.T) {
	_, policy := tagsSnapshot(t)
	swapForge(t, &storeForge{})
	swapTagVerifier(t, scriptedTagVerifier{})

	root := filepath.Join(t.TempDir(), "root.json")
	if err := os.WriteFile(root, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "tags", "--repo", "acme/widget", "--policy", policy, "--trusted-root", root,
	}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("Run = %d, want %d", code, exitUsage)
	}

	if !strings.Contains(stderr.String(), "cannot read tags") {
		t.Errorf("stderr = %q, want the tag-reader refusal", stderr.String())
	}
}

// TestAssertUsageMatrix walks the flag guards of the three walking
// targets in one table: each row is one broken flag combination and
// the refusal it must name.
func TestAssertUsageMatrix(t *testing.T) {
	dir := t.TempDir()

	notAPolicy := filepath.Join(dir, "not-a-policy.json")
	if err := os.WriteFile(notAPolicy, []byte(`{"schema": 4}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, evidencePolicy := evidenceSnapshot(t)
	_, blastPolicy, vex := blastSnapshot(t)
	_, tagsPolicy := tagsSnapshot(t)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"evidence: a bad flag", []string{"assert", "evidence", "--conjure"}, ""},
		{
			"evidence: both populations",
			[]string{"assert", "evidence", "--org", "acme", "--repo", "acme/widget", "--policy", evidencePolicy},
			"exclusive",
		},
		{
			"evidence: a repo without an owner",
			[]string{"assert", "evidence", "--repo", "widget", "--policy", evidencePolicy},
			"owner/name",
		},
		{
			"evidence: snapshot and capture together",
			[]string{
				"assert", "evidence", "--org", "acme", "--policy", evidencePolicy,
				"--snapshot", dir, "--capture", dir,
			},
			"exclusive",
		},
		{
			"evidence: an unknown depth",
			[]string{"assert", "evidence", "--org", "acme", "--policy", evidencePolicy, "--depth", "deepish"},
			"is not a depth",
		},
		{
			"evidence: full depth without a verify policy",
			[]string{"assert", "evidence", "--org", "acme", "--policy", evidencePolicy, "--depth", "full"},
			"--verify-policy is required",
		},
		{
			"evidence: full depth resolves a root rather than skipping",
			[]string{
				"assert", "evidence", "--org", "acme", "--policy", evidencePolicy,
				"--depth", "full", "--verify-policy", evidencePolicy,
			},
			"tuf ",
		},
		{
			"evidence: an unreadable policy",
			[]string{"assert", "evidence", "--org", "acme", "--policy", filepath.Join(dir, "absent.json")},
			"absent.json",
		},
		{
			"evidence: a policy that is not one",
			[]string{"assert", "evidence", "--org", "acme", "--policy", notAPolicy},
			"evidence",
		},
		{
			"evidence: full depth over an unreadable verify policy",
			[]string{
				"assert", "evidence", "--org", "acme", "--policy", evidencePolicy, "--depth", "full",
				"--verify-policy", filepath.Join(dir, "absent-vp.json"), "--trusted-root", notAPolicy,
			},
			"absent-vp.json",
		},
		{"blast-radius: a bad flag", []string{"assert", "blast-radius", "--conjure"}, ""},
		{
			"blast-radius: both populations",
			[]string{
				"assert", "blast-radius", "--org", "acme", "--repo", "acme/widget",
				"--policy", blastPolicy, "--vex", vex,
			},
			"exclusive",
		},
		{
			"blast-radius: a repo without an owner",
			[]string{"assert", "blast-radius", "--repo", "widget", "--policy", blastPolicy, "--vex", vex},
			"owner/name",
		},
		{
			"blast-radius: an unreadable policy",
			[]string{
				"assert", "blast-radius", "--org", "acme",
				"--policy", filepath.Join(dir, "absent.json"), "--vex", vex,
			},
			"absent.json",
		},
		{
			"blast-radius: a policy that is not one",
			[]string{"assert", "blast-radius", "--org", "acme", "--policy", notAPolicy, "--vex", vex},
			"evidence",
		},
		{
			"tags: a policy that is not one",
			[]string{"assert", "tags", "--org", "acme", "--policy", notAPolicy},
			"evidence",
		},
		{
			"tags: an unreadable trusted root",
			[]string{
				"assert", "tags", "--repo", "acme/widget", "--policy", tagsPolicy,
				"--trusted-root", filepath.Join(dir, "absent-root.json"),
			},
			"absent-root.json",
		},
		{
			"tags: signing epochs resolve a root rather than skipping",
			[]string{"assert", "tags", "--repo", "acme/widget", "--policy", tagsPolicy},
			"tuf ",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := Run(tc.args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitUsage, stderr.String())
			}

			if tc.want != "" && !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("stderr = %q, want it to name %q", stderr.String(), tc.want)
			}
		})
	}
}

// TestLoadTagVerifierPendingOnly: a policy whose every epoch is
// pending declares no signing obligation, so no trusted root is
// needed and the walk gets no verifier — the declaration decides,
// never a default.
func TestLoadTagVerifierPendingOnly(t *testing.T) {
	t.Parallel()

	pol := &assert.Policy{Tags: &assert.TagsPolicy{Epochs: map[string]string{
		"widget": assert.EpochPending,
		"gadget": assert.EpochPending,
	}}}

	var stderr bytes.Buffer

	tv, code := loadTagVerifier(pol, &rootFlags{}, &stderr)
	if code != exitOK {
		t.Fatalf("loadTagVerifier = %d, want exitOK: %s", code, stderr.String())
	}

	if tv != nil {
		t.Fatalf("loadTagVerifier returned %T — nothing to verify means no verifier", tv)
	}
}

// TestLoadTagVerifierRefusesABrokenRoot: the trusted root is read and
// bound here, so bytes that are not a root refuse at load rather than
// at the first signature.
func TestLoadTagVerifierRefusesABrokenRoot(t *testing.T) {
	t.Parallel()

	pattern, issuer := "^https://github\\.com/acme/", "https://token.example.com"
	pol := &assert.Policy{
		Issuer: &issuer,
		Tags: &assert.TagsPolicy{
			IdentityPattern: &pattern,
			Epochs:          map[string]string{"widget": "v0.1.0"},
		},
	}

	root := filepath.Join(t.TempDir(), "root.json")
	if err := os.WriteFile(root, []byte("not a trusted root"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer

	if _, code := loadTagVerifier(pol, &rootFlags{file: root}, &stderr); code != exitUsage {
		t.Fatalf("loadTagVerifier = %d, want exitUsage", code)
	}

	if !strings.Contains(stderr.String(), "trusted root") {
		t.Errorf("stderr = %q, want the trusted-root refusal", stderr.String())
	}
}

// TestLoadDebtParses pins the debt loader's success path: a committed
// file that parses becomes declared exceptions, so the walk excuses
// exactly what was reviewed.
func TestLoadDebtParses(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "debt.txt")
	content := "# reviewed 2026-08-01\nacme/widget@v1.0.0(sbom)\n\nacme/gadget@v2.0.0(checksums)\n"

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer

	got, code := loadDebt(path, &stderr)
	if code != exitOK {
		t.Fatalf("loadDebt = %d: %s", code, stderr.String())
	}

	if len(got) != 2 {
		t.Fatalf("loadDebt parsed %d exceptions, want the two declared", len(got))
	}
}

// TestLoadVEXDirectoryGuards walks the decision loader's own reads: a
// path that is not a directory refuses, non-VEX entries are skipped
// rather than parsed, and an entry that cannot be read refuses.
func TestLoadVEXDirectoryGuards(t *testing.T) {
	t.Parallel()

	t.Run("a path that is not a directory refuses", func(t *testing.T) {
		t.Parallel()

		notADir := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}

		var stderr bytes.Buffer

		if _, code := loadVEX(notADir, &stderr); code != exitUsage {
			t.Fatalf("loadVEX = %d, want exitUsage", code)
		}
	})

	t.Run("non-VEX entries are skipped", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()

		// A directory, and a file that is not a decision document:
		// neither is triage, and neither may abort the load.
		if err := os.MkdirAll(filepath.Join(dir, "sub.openvex.json.d"), 0o750); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not a decision"), 0o600); err != nil {
			t.Fatal(err)
		}

		var stderr bytes.Buffer

		got, code := loadVEX(dir, &stderr)
		if code != exitOK {
			t.Fatalf("loadVEX = %d: %s", code, stderr.String())
		}

		if got.Len() != 0 {
			t.Fatalf("loadVEX decided %d — a directory of no decisions decides nothing", got.Len())
		}
	})

	t.Run("an unreadable decision refuses", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()

		// A decision document that is a link to nothing: the listing
		// names it, the read cannot resolve it. Skipping it would
		// silently drop reviewed triage.
		if err := os.Symlink(filepath.Join(dir, "gone"), filepath.Join(dir, "acme.openvex.json")); err != nil {
			t.Fatal(err)
		}

		var stderr bytes.Buffer

		if _, code := loadVEX(dir, &stderr); code != exitUsage {
			t.Fatalf("loadVEX = %d, want exitUsage", code)
		}
	})
}

// TestStoreAttestorWithoutCandidates: a subject with stored bundles
// but no candidate identity has nothing to verify against, and the
// refusal must name the empty store rather than pass by exhausting an
// empty loop.
func TestStoreAttestorWithoutCandidates(t *testing.T) {
	t.Parallel()

	a := storeAttestor{
		forge:  &storeForge{bundles: []jsonx.Raw{jsonx.Raw(`{}`)}},
		bv:     attestorBV{},
		issuer: "https://token.example.com",
	}

	err := a.Verify("acme", "widget", assertDigest, nil, "")
	if !errors.Is(err, errNoAttestation) {
		t.Fatalf("Verify = %v, want errNoAttestation", err)
	}
}

// TestLoadStoreInputsGuards: the store halves are cryptographic, so
// every input they need refuses at load — a broken root, and a pin
// file whose path cannot be read at all (distinct from absent, which
// has its own refusal).
// Not parallel: the pin-file row swaps the trust seam, and a package
// seam written while the parallel group reads it is a data race — the
// house rule every other seam-swapping test here follows.
func TestLoadStoreInputsGuards(t *testing.T) {
	dir := t.TempDir()
	root := []byte("not a trusted root")

	t.Run("a root that is not one refuses", func(t *testing.T) {
		if _, _, err := loadStoreInputs(baseImagesPolicy(t, "no-such-pins.toml"), &storeForge{}, root, ""); err == nil {
			t.Fatal("loadStoreInputs accepted a root that is not one")
		}
	})

	t.Run("a pin file that cannot be read refuses", func(t *testing.T) {
		pins := filepath.Join(dir, "pins.txt")
		if err := os.MkdirAll(pins, 0o750); err != nil {
			t.Fatal(err)
		}

		orig := newBundleVerifier
		newBundleVerifier = func([]byte) (verify.BundleVerifier, error) { return attestorBV{}, nil }

		t.Cleanup(func() { newBundleVerifier = orig })

		_, _, err := loadStoreInputs(baseImagesPolicy(t, pins), &storeForge{}, root, pins)
		if err == nil || strings.Contains(err.Error(), "absent from this checkout") {
			t.Fatalf("loadStoreInputs = %v, want the read refusal, not the absence one", err)
		}
	})
}

// TestLoadFullDepthRefusesABrokenRoot: the deep leg's own trust
// boundary, refused at load with the real constructor in place.
func TestLoadFullDepthRefusesABrokenRoot(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	vp := filepath.Join(dir, "vp.json")
	if err := os.WriteFile(vp, []byte(testPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadFullDepth(vp, []byte("not a trusted root"), &storeForge{}); err == nil {
		t.Fatal("loadFullDepth accepted a root that is not one")
	}
}

// TestForgeStoreCarriesTheForgeRefusal: the deep leg reads the store
// through the walk's forge, so a forge that cannot read must surface
// as a refusal, never as an empty bundle list read as "nothing
// attested".
func TestForgeStoreCarriesTheForgeRefusal(t *testing.T) {
	t.Parallel()

	f := &storeForge{err: errors.New("store torn")}

	if _, err := (forgeStore{forge: f}).Bundles("acme/widget", strings.Repeat("a", 64)); err == nil {
		t.Fatal("Bundles reported an empty store over a forge that refused")
	}
}
