// `emit manifest` at the command surface: the declared contract is
// complete or refused — a manifest missing any field would excuse
// obligations silently on the assert side, which is why nothing here
// is defaulted — and every published asset leaves TYPED, stamped from
// the org's declared vocabulary at the one moment that knowledge
// exists natively (stele#156).

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// manifestPolicyJSON is the evidence vocabulary the stamping reads.
const manifestPolicyJSON = `{
  "schema": 5,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "storeVsaFromVersion": "1.13.0",
    "evidenceSuffixes": [".openvex.json"],
    "classes": {"go-binary": {"bundles": ["attestations-go-binaries.intoto.jsonl"]}}
  }
}`

const manifestDigest = "3333333333333333333333333333333333333333333333333333333333333333"

// manifestInputs writes an asset manifest and the policy that types
// it, returning both paths.
func manifestInputs(t *testing.T, assets string) (string, string) { //nolint:gocritic // two paths
	t.Helper()

	dir := t.TempDir()
	assetPath := filepath.Join(dir, "checksums.txt")
	policyPath := filepath.Join(dir, "assert-policy.json")

	if err := os.WriteFile(assetPath, []byte(assets), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(policyPath, []byte(manifestPolicyJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	return assetPath, policyPath
}

// theReleaseShape is one artifact and the documents published beside
// it — the asset list a real release hands this command.
const theReleaseShape = manifestDigest + "  widget-linux-amd64.tar.gz\n" +
	manifestDigest + "  attestations-go-binaries.intoto.jsonl\n" +
	manifestDigest + "  widget-1.0.0.spdx.json\n" +
	manifestDigest + "  decisions.openvex.json\n"

func TestEmitManifestWritesTheDeclaredContract(t *testing.T) {
	t.Parallel()

	assets, policy := manifestInputs(t, theReleaseShape)

	var stdout, stderr bytes.Buffer

	args := []string{
		"manifest", "--classes", "go-binary,oci-image", "--store-vsa", "true",
		"--machinery-version", "1.40.0", "--assets", assets, "--assert-policy", policy,
	}
	if got := emitCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("emitCmd = %d (stderr: %s)", got, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		`"schema":2`,
		`"classes":["go-binary","oci-image"]`,
		`"storeVsa":true`,
		`"machineryVersion":"1.40.0"`,
		// The artifact is a build subject; the bundle, the inventory
		// and the triage decision are documents about the release.
		`{"name":"widget-linux-amd64.tar.gz","sha256":"` + manifestDigest + `","type":"build-subject"}`,
		`{"name":"attestations-go-binaries.intoto.jsonl","sha256":"` + manifestDigest + `","type":"evidence"}`,
		`{"name":"widget-1.0.0.spdx.json","sha256":"` + manifestDigest + `","type":"evidence"}`,
		`{"name":"decisions.openvex.json","sha256":"` + manifestDigest + `","type":"evidence"}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manifest lacks %s:\n%s", want, out)
		}
	}
}

func TestEmitManifestUsage(t *testing.T) {
	t.Parallel()

	assets, policy := manifestInputs(t, theReleaseShape)
	junk, _ := manifestInputs(t, "not a sha256sum record\n")

	tests := []struct {
		name string
		args []string
	}{
		{"no classes", []string{
			"manifest", "--store-vsa", "true", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", policy,
		}},
		{"no layout", []string{
			"manifest", "--classes", "a", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", policy,
		}},
		{"a layout outside true/false", []string{
			"manifest", "--classes", "a", "--store-vsa", "store", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", policy,
		}},
		{"no machinery version", []string{
			"manifest", "--classes", "a", "--store-vsa", "false", "--assets", assets, "--assert-policy", policy,
		}},
		{"no assets", []string{
			"manifest", "--classes", "a", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assert-policy", policy,
		}},
		{"no policy", []string{
			"manifest", "--classes", "a", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", assets,
		}},
		{"an unreadable asset manifest", []string{
			"manifest", "--classes", "a", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", "/no/such", "--assert-policy", policy,
		}},
		{"an asset manifest that is not one", []string{
			"manifest", "--classes", "a", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", junk, "--assert-policy", policy,
		}},
		{"an unreadable policy", []string{
			"manifest", "--classes", "a", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", "/no/such",
		}},
		{"a policy this build refuses", []string{
			"manifest", "--classes", "a", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", assets,
		}},
		{"unknown flag", []string{"manifest", "--nope"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			if got := emitCmd(tt.args, &stdout, &stderr); got != exitUsage {
				t.Errorf("emitCmd(%v) = %d, want %d (stderr: %s)", tt.args, got, exitUsage, stderr.String())
			}
		})
	}
}

// The shape rules live in internal/evidence and refuse through this
// surface too — a duplicate class reaches the shared Validate, not a
// second copy of it here.
func TestEmitManifestRefusesThroughTheSharedDefinition(t *testing.T) {
	t.Parallel()

	assets, policy := manifestInputs(t, theReleaseShape)

	var stdout, stderr bytes.Buffer

	args := []string{
		"manifest", "--classes", "a,a", "--store-vsa", "true", "--machinery-version", "1.0.0",
		"--assets", assets, "--assert-policy", policy,
	}
	if got := emitCmd(args, &stdout, &stderr); got != exitRefused {
		t.Fatalf("emitCmd = %d, want %d", got, exitRefused)
	}

	if !strings.Contains(stderr.String(), "declared twice") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

// An empty asset manifest refuses at the format: a manifest listing
// nothing says nothing about what the release published, and the
// refusal comes from the shared definition rather than a check here.
func TestEmitManifestRefusesAnEmptyAssetList(t *testing.T) {
	t.Parallel()

	assets, policy := manifestInputs(t, "")

	var stdout, stderr bytes.Buffer

	args := []string{
		"manifest", "--classes", "go-binary", "--store-vsa", "true", "--machinery-version", "1.0.0",
		"--assets", assets, "--assert-policy", policy,
	}
	if got := emitCmd(args, &stdout, &stderr); got != exitRefused {
		t.Fatalf("emitCmd = %d, want %d (stderr: %s)", got, exitRefused, stderr.String())
	}

	if !strings.Contains(stderr.String(), "lists nothing") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
