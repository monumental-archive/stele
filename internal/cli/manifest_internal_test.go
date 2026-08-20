// `emit manifest` at the command surface: the declared contract is
// complete or refused — a manifest missing any field would excuse
// obligations silently on the assert side, which is why nothing here
// is defaulted — and every published asset leaves TYPED, stamped from
// the org's declared vocabulary at the one moment that knowledge
// exists natively (stele#156), each artifact carrying the class that
// built it (stele#185) and the target that produced it (stele#223).
//
// The leg join is the one thing no vocabulary can answer, so every
// way its two statements about a release can disagree gets a row: an
// artifact claimed by nobody, by two legs, by a leg naming bytes the
// release never shipped, or naming a document instead of an artifact.

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
  "schema": 6,
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

// subjectsOf writes one build leg's subject manifest and returns the
// --leg-subjects value naming it.
func subjectsOf(t *testing.T, class, target, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), class+"-"+target+".sha256")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return class + ":" + target + "=" + path
}

// goBinaryLeg is what the go-binary build job for one target
// produced: the one artifact in theReleaseShape below.
func goBinaryLeg(t *testing.T) string {
	t.Helper()

	return subjectsOf(t, "go-binary", "linux-amd64", manifestDigest+"  widget-linux-amd64.tar.gz\n")
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
		"--leg-subjects", goBinaryLeg(t),
	}
	if got := emitCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("emitCmd = %d (stderr: %s)", got, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		`"schema":4`,
		`"classes":["go-binary","oci-image"]`,
		`"storeVsa":true`,
		`"machineryVersion":"1.40.0"`,
		// The artifact is a build subject and names the leg that built
		// it; the bundle, the inventory and the triage decision are
		// documents about the release and name no class at all.
		`{"name":"widget-linux-amd64.tar.gz","sha256":"` + manifestDigest +
			`","type":"build-subject","class":"go-binary","target":"linux-amd64"}`,
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
	leg := goBinaryLeg(t)

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
		// Every way the caller's class split can disagree with the
		// assets the release actually published. Each is a distinct
		// route to an artifact judged by the wrong population, or by
		// none — which is what the field exists to prevent.
		{"an artifact no build leg claims", []string{
			"manifest", "--classes", "go-binary", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", policy,
		}},
		{"a leg-subjects value that is not <class>:<target>=<path>", []string{
			"manifest", "--classes", "go-binary", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", policy, "--leg-subjects", "go-binary",
		}},
		{"a leg-subjects value naming no class", []string{
			"manifest", "--classes", "go-binary", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", policy, "--leg-subjects", ":linux-amd64=/some/path",
		}},
		{"a leg-subjects value naming no target at all", []string{
			"manifest", "--classes", "go-binary", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", policy, "--leg-subjects", "go-binary=/some/path",
		}},
		{"a leg-subjects value whose target is empty", []string{
			"manifest", "--classes", "go-binary", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", policy, "--leg-subjects", "go-binary:=/some/path",
		}},
		{"a leg-subjects value naming no path", []string{
			"manifest", "--classes", "go-binary", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", policy, "--leg-subjects", "go-binary:linux-amd64=",
		}},
		{"one build leg named twice", []string{
			"manifest", "--classes", "go-binary", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", policy, "--leg-subjects", leg, "--leg-subjects", leg,
		}},
		{"an unreadable subject manifest", []string{
			"manifest", "--classes", "go-binary", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", policy, "--leg-subjects", "go-binary:linux-amd64=/no/such",
		}},
		{"a subject manifest that is not one", []string{
			"manifest", "--classes", "go-binary", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", policy, "--leg-subjects", "go-binary:linux-amd64=" + junk,
		}},
		{"a class claiming bytes the release never published", []string{
			"manifest", "--classes", "go-binary", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", policy,
			"--leg-subjects", subjectsOf(t, "go-binary", "linux-amd64", manifestDigest+"  never-shipped.tar.gz\n"),
		}},
		{"a class pinning one artifact at another digest", []string{
			"manifest", "--classes", "go-binary", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", policy,
			"--leg-subjects", subjectsOf(t, "go-binary", "linux-amd64",
				strings.Repeat("b", 64)+"  widget-linux-amd64.tar.gz\n"),
		}},
		{"a class claiming a document about the release", []string{
			"manifest", "--classes", "go-binary", "--store-vsa", "false", "--machinery-version", "1.0.0",
			"--assets", assets, "--assert-policy", policy,
			"--leg-subjects", subjectsOf(t, "go-binary", "linux-amd64",
				manifestDigest+"  widget-linux-amd64.tar.gz\n"+manifestDigest+"  widget-1.0.0.spdx.json\n"),
		}},
		{"one artifact claimed by two build legs", []string{
			"manifest", "--classes", "go-binary,oci-image", "--store-vsa", "false",
			"--machinery-version", "1.0.0", "--assets", assets, "--assert-policy", policy,
			"--leg-subjects", leg,
			"--leg-subjects", subjectsOf(t, "oci-image", "linux-amd64",
				manifestDigest+"  widget-linux-amd64.tar.gz\n"),
		}},
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
		"manifest", "--classes", "go-binary,go-binary", "--store-vsa", "true", "--machinery-version", "1.0.0",
		"--assets", assets, "--assert-policy", policy, "--leg-subjects", goBinaryLeg(t),
	}
	if got := emitCmd(args, &stdout, &stderr); got != exitRefused {
		t.Fatalf("emitCmd = %d, want %d (stderr: %s)", got, exitRefused, stderr.String())
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

// A class the release never declared refuses through the SHARED
// definition, not a second reading here: which classes an entry may
// claim is the manifest format's rule, and the surface that would
// re-implement it is the drift the one definition exists to remove.
func TestEmitManifestRefusesAnUndeclaredEntryClass(t *testing.T) {
	t.Parallel()

	assets, policy := manifestInputs(t, theReleaseShape)

	var stdout, stderr bytes.Buffer

	args := []string{
		"manifest", "--classes", "oci-image", "--store-vsa", "true", "--machinery-version", "1.0.0",
		"--assets", assets, "--assert-policy", policy, "--leg-subjects", goBinaryLeg(t),
	}
	if got := emitCmd(args, &stdout, &stderr); got != exitRefused {
		t.Fatalf("emitCmd = %d, want %d (stderr: %s)", got, exitRefused, stderr.String())
	}

	if !strings.Contains(stderr.String(), "is not one this release declared") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

// A release that ships only documents about itself needs no leg
// split at all: --leg-subjects is owed by artifacts, and a release
// whose classes all publish elsewhere (a registry, a package index)
// has none to claim.
func TestEmitManifestNeedsNoLegWhenNothingWasBuiltHere(t *testing.T) {
	t.Parallel()

	assets, policy := manifestInputs(t,
		manifestDigest+"  attestations-go-binaries.intoto.jsonl\n"+
			manifestDigest+"  widget-1.0.0.spdx.json\n")

	var stdout, stderr bytes.Buffer

	args := []string{
		"manifest", "--classes", "oci-image", "--store-vsa", "true", "--machinery-version", "1.0.0",
		"--assets", assets, "--assert-policy", policy,
	}
	if got := emitCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("emitCmd = %d (stderr: %s)", got, stderr.String())
	}

	if strings.Contains(stdout.String(), `"class"`) {
		t.Errorf("a document about the release took a class: %s", stdout.String())
	}

	if strings.Contains(stdout.String(), `"target"`) {
		t.Errorf("a document about the release took a target: %s", stdout.String())
	}
}

// One class, two targets: the shape a per-class rebuild could not
// scope (stele#223). Each artifact leaves carrying the target of the
// leg that produced it — not the class's, which is the same for both
// — because that is what lets a rebuild covering one of them be
// judged against one of them.
func TestEmitManifestTypesEachTargetOfOneClass(t *testing.T) {
	t.Parallel()

	const linux = "widget-linux-amd64.tar.gz"

	const darwin = "widget-darwin-arm64.tar.gz"

	assets, policy := manifestInputs(t,
		manifestDigest+"  "+linux+"\n"+manifestDigest+"  "+darwin+"\n"+
			manifestDigest+"  attestations-go-binaries.intoto.jsonl\n")

	var stdout, stderr bytes.Buffer

	args := []string{
		"manifest", "--classes", "go-binary", "--store-vsa", "true", "--machinery-version", "1.49.0",
		"--assets", assets, "--assert-policy", policy,
		"--leg-subjects", subjectsOf(t, "go-binary", "linux-amd64", manifestDigest+"  "+linux+"\n"),
		"--leg-subjects", subjectsOf(t, "go-binary", "darwin-arm64", manifestDigest+"  "+darwin+"\n"),
	}
	if got := emitCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("emitCmd = %d (stderr: %s)", got, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		`{"name":"` + linux + `","sha256":"` + manifestDigest +
			`","type":"build-subject","class":"go-binary","target":"linux-amd64"}`,
		`{"name":"` + darwin + `","sha256":"` + manifestDigest +
			`","type":"build-subject","class":"go-binary","target":"darwin-arm64"}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manifest lacks %s:\n%s", want, out)
		}
	}
}
