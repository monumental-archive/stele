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
//
// Every input is the run's own (stele#400): a directory of what ships,
// a directory of bundles placed into it, a machinery tree, and each
// class's lines. Every row builds its own, because placing bundles
// moves files.

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// manifestPolicyJSON is the evidence vocabulary the stamping reads.
const manifestPolicyJSON = `{
  "schema": 9,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "storeVsaFromVersion": "1.13.0",
    "evidenceSuffixes": [".openvex.json"],
    "classes": {
      "go-binary": {"bundles": ["attestations-go-binaries.intoto.jsonl"]},
      "oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}
    }
  }
}`

// manifestCitation is the machinery tree's version mirror.
const manifestCitation = "cff-version: 1.2.0\nversion: 1.40.0\ndate-released: 2026-11-17\n"

// The one artifact the release shape builds, and its bytes.
const (
	widget     = "widget-linux-amd64.tar.gz"
	widgetBody = "widget\n"
	goBundle   = "attestations-go-binaries.intoto.jsonl"
)

// sumOf is what `sha256sum` prints for body.
func sumOf(body string) string {
	h := sha256.Sum256([]byte(body))

	return hex.EncodeToString(h[:])
}

// releaseFixture is one run's inputs on disk.
type releaseFixture struct {
	assets, bundles, policy, tree string
}

// newRelease writes what ships, the bundles (one directory each,
// named for what it is placed as), the policy and the machinery tree.
func newRelease(t *testing.T, files, bundles map[string]string) releaseFixture {
	t.Helper()

	root := t.TempDir()
	r := releaseFixture{
		assets:  filepath.Join(root, "dist"),
		bundles: filepath.Join(root, "bundle"),
		policy:  filepath.Join(root, "assert-policy.json"),
		tree:    filepath.Join(root, "canon"),
	}

	for _, dir := range []string{r.assets, r.bundles, r.tree} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	write := func(path, body string) {
		t.Helper()

		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for name, body := range files {
		write(filepath.Join(r.assets, name), body)
	}

	for name, body := range bundles {
		if err := os.Mkdir(filepath.Join(r.bundles, name), 0o700); err != nil {
			t.Fatal(err)
		}

		write(filepath.Join(r.bundles, name, "bundle.jsonl"), body)
	}

	write(r.policy, manifestPolicyJSON)
	write(filepath.Join(r.tree, "CITATION.cff"), manifestCitation)

	return r
}

// args is the command with this fixture's inputs, then extra.
func (r releaseFixture) args(classes string, extra ...string) []string {
	return append([]string{
		"manifest", "--classes", classes, "--store-vsa", "true", "--machinery-tree", r.tree,
		"--assets-dir", r.assets, "--bundles-dir", r.bundles, "--assert-policy", r.policy,
	}, extra...)
}

// theRelease is one artifact, the documents published beside it and
// its class's bundle — the shape a real release hands this command.
func theRelease(t *testing.T) releaseFixture {
	t.Helper()

	return newRelease(t, map[string]string{
		widget:                   widgetBody,
		"widget-1.0.0.spdx.json": "sbom\n",
		"decisions.openvex.json": "vex\n",
	}, map[string]string{goBundle: "bundle\n"})
}

// legLine is one subject line as a build leg emits it.
func legLine(target, name, body string) string {
	return target + " " + sumOf(body) + "  " + name + "\n"
}

// writeClassLines writes one class's lines and returns the flag value.
func writeClassLines(t *testing.T, class, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "lines")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return class + "=" + path
}

// goBinaryLines is what the go-binary class's one leg emitted.
func goBinaryLines(t *testing.T) string {
	t.Helper()

	return writeClassLines(t, "go-binary", legLine("linux-amd64", widget, widgetBody))
}

// emitWants runs emit manifest and checks the exit code.
func emitWants(t *testing.T, args []string, code int) (string, string) { //nolint:gocritic // stdout, stderr
	t.Helper()

	var stdout, stderr bytes.Buffer
	if got := emitCmd(args, &stdout, &stderr); got != code {
		t.Fatalf("emitCmd = %d, want %d (stderr: %s)", got, code, stderr.String())
	}

	return stdout.String(), stderr.String()
}

func TestEmitManifestWritesTheDeclaredContract(t *testing.T) {
	t.Parallel()

	r := theRelease(t)
	out, _ := emitWants(t, r.args("go-binary,oci-image", "--leg-lines", goBinaryLines(t)), exitOK)

	for _, want := range []string{
		`"schema":5`,
		`"classes":["go-binary","oci-image"]`,
		`"storeVsa":true`,
		// From the machinery tree's CITATION.cff, not a flag.
		`"machineryVersion":"1.40.0"`,
		// The artifact is a build subject and names the leg that built
		// it; the bundle, the inventory and the triage decision are
		// documents about the release and name no class at all.
		`{"name":"` + widget + `","sha256":"` + sumOf(widgetBody) +
			`","type":"build-subject","class":"go-binary","target":"linux-amd64"}`,
		`{"name":"` + goBundle + `","sha256":"` + sumOf("bundle\n") + `","type":"evidence"}`,
		`{"name":"widget-1.0.0.spdx.json","sha256":"` + sumOf("sbom\n") + `","type":"evidence"}`,
		`{"name":"decisions.openvex.json","sha256":"` + sumOf("vex\n") + `","type":"evidence"}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manifest lacks %s:\n%s", want, out)
		}
	}

	// Placed, not copied: the bundle ships from the asset directory.
	if _, err := os.Stat(filepath.Join(r.assets, goBundle)); err != nil {
		t.Errorf("the bundle was not placed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(r.bundles, goBundle, "bundle.jsonl")); !os.IsNotExist(err) {
		t.Errorf("the bundle is still in --bundles-dir (stat: %v)", err)
	}
}

func TestEmitManifestUsage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args func(t *testing.T, r releaseFixture) []string
		want string
	}{
		{"no classes", func(_ *testing.T, r releaseFixture) []string {
			return dropFlag(r.args("go-binary"), "--classes")
		}, "--classes is required"},
		{"no layout", func(_ *testing.T, r releaseFixture) []string {
			return dropFlag(r.args("go-binary"), "--store-vsa")
		}, "--store-vsa is required"},
		{"a layout outside true/false", func(_ *testing.T, r releaseFixture) []string {
			return setFlag(r.args("go-binary"), "--store-vsa", "store")
		}, `--store-vsa "store" is not true or false`},
		{"no machinery tree", func(_ *testing.T, r releaseFixture) []string {
			return dropFlag(r.args("go-binary"), "--machinery-tree")
		}, "--machinery-tree is required"},
		{"no asset directory", func(_ *testing.T, r releaseFixture) []string {
			return dropFlag(r.args("go-binary"), "--assets-dir")
		}, "--assets-dir is required"},
		{"no bundle directory", func(_ *testing.T, r releaseFixture) []string {
			return dropFlag(r.args("go-binary"), "--bundles-dir")
		}, "--bundles-dir is required"},
		{"no policy", func(_ *testing.T, r releaseFixture) []string {
			return dropFlag(r.args("go-binary"), "--assert-policy")
		}, "--assert-policy is required"},
		{"a stray argument", func(_ *testing.T, r releaseFixture) []string {
			return append(r.args("go-binary"), "extra")
		}, `unexpected argument "extra"`},
		{"unknown flag", func(_ *testing.T, r releaseFixture) []string {
			return append(r.args("go-binary"), "--assets", "x")
		}, "flag provided but not defined: -assets"},
		{"an unreadable policy", func(_ *testing.T, r releaseFixture) []string {
			return setFlag(r.args("go-binary"), "--assert-policy", "/no/such/policy.json")
		}, "/no/such/policy.json"},
		{"a policy this build refuses", func(t *testing.T, r releaseFixture) []string {
			t.Helper()

			return setFlag(r.args("go-binary"), "--assert-policy", filepath.Join(r.tree, "CITATION.cff"))
		}, "stele emit manifest: "},
		{"a policy with no evidence vocabulary", func(t *testing.T, r releaseFixture) []string {
			t.Helper()

			bare := filepath.Join(t.TempDir(), "policy.json")
			if err := os.WriteFile(bare, []byte(`{"schema": 9}`), 0o600); err != nil {
				t.Fatal(err)
			}

			return setFlag(r.args("go-binary"), "--assert-policy", bare)
		}, "assert: policy: evidence is absent"},
		// Every way the caller's class split can disagree with the
		// assets the release actually published. Each is a distinct
		// route to an artifact judged by the wrong population, or by
		// none — which is what the field exists to prevent.
		{"an artifact no build leg claims", func(_ *testing.T, r releaseFixture) []string {
			return r.args("go-binary")
		}, widget + " is a build subject no --leg-lines line claims"},
		{"a class claiming bytes the release never published", func(t *testing.T, r releaseFixture) []string {
			t.Helper()

			return r.args("go-binary", "--leg-lines", writeClassLines(t, "go-binary",
				legLine("linux-amd64", widget, widgetBody)+legLine("linux-amd64", "never-shipped.tar.gz", "x")))
		}, "--leg-lines go-binary:linux-amd64 names never-shipped.tar.gz, which this release does not publish"},
		{"a class pinning one artifact at another digest", func(t *testing.T, r releaseFixture) []string {
			t.Helper()

			return r.args("go-binary", "--leg-lines", writeClassLines(t, "go-binary",
				legLine("linux-amd64", widget, "other bytes")))
		}, "--leg-lines go-binary:linux-amd64 pins " + widget + " at " + sumOf("other bytes")},
		{"a class claiming a document about the release", func(t *testing.T, r releaseFixture) []string {
			t.Helper()

			return r.args("go-binary", "--leg-lines", writeClassLines(t, "go-binary",
				legLine("linux-amd64", widget, widgetBody)+legLine("linux-amd64", "widget-1.0.0.spdx.json", "sbom\n")))
		}, "names widget-1.0.0.spdx.json, which the evidence vocabulary calls a document ABOUT the release"},
		{"one artifact claimed by two build legs", func(t *testing.T, r releaseFixture) []string {
			t.Helper()

			return r.args("go-binary,oci-image", "--leg-lines", goBinaryLines(t),
				"--leg-lines", writeClassLines(t, "oci-image", legLine("linux-amd64", widget, widgetBody)))
		}, widget + " is claimed by both go-binary:linux-amd64 and oci-image:linux-amd64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, stderr := emitWants(t, tt.args(t, theRelease(t)), exitUsage)
			if !strings.Contains(stderr, tt.want) {
				t.Errorf("stderr %q\nlacks %q", stderr, tt.want)
			}
		})
	}
}

// dropFlag removes a flag and its value from args.
func dropFlag(args []string, name string) []string {
	out := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		if args[i] == name {
			i++

			continue
		}

		out = append(out, args[i])
	}

	return out
}

// setFlag replaces a flag's value in args.
func setFlag(args []string, name, value string) []string {
	out := append([]string(nil), args...)

	for i := range out {
		if out[i] == name && i+1 < len(out) {
			out[i+1] = value
		}
	}

	return out
}

// The shape rules live in internal/evidence and refuse through this
// surface too — a duplicate class reaches the shared Validate, not a
// second copy of it here.
func TestEmitManifestRefusesThroughTheSharedDefinition(t *testing.T) {
	t.Parallel()

	r := theRelease(t)

	_, stderr := emitWants(t, r.args("go-binary,go-binary", "--leg-lines", goBinaryLines(t)), exitRefused)
	if !strings.Contains(stderr, "declared twice") {
		t.Fatalf("stderr = %q", stderr)
	}
}

// A class the release never declared refuses through the SHARED
// definition, not a second reading here: which classes an entry may
// claim is the manifest format's rule, and the surface that would
// re-implement it is the drift the one definition exists to remove.
func TestEmitManifestRefusesAnUndeclaredEntryClass(t *testing.T) {
	t.Parallel()

	r := theRelease(t)

	_, stderr := emitWants(t, r.args("oci-image", "--leg-lines", goBinaryLines(t)), exitRefused)
	if !strings.Contains(stderr, "is not one this release declared") {
		t.Fatalf("stderr = %q", stderr)
	}
}

// A release that ships only documents about itself needs no leg
// split at all: --leg-lines is owed by artifacts, and a release whose
// classes all publish elsewhere (a registry, a package index) has none
// to claim.
func TestEmitManifestNeedsNoLegWhenNothingWasBuiltHere(t *testing.T) {
	t.Parallel()

	r := newRelease(t, map[string]string{"widget-1.0.0.spdx.json": "sbom\n"}, map[string]string{goBundle: "b\n"})

	out, _ := emitWants(t, r.args("oci-image"), exitOK)

	if strings.Contains(out, `"class"`) {
		t.Errorf("a document about the release took a class: %s", out)
	}

	if strings.Contains(out, `"target"`) {
		t.Errorf("a document about the release took a target: %s", out)
	}
}

// One class, two targets: the shape a per-class rebuild could not
// scope (stele#223). One class's lines carry both, and each artifact
// leaves carrying the target of the leg that produced it — not the
// class's, which is the same for both.
func TestEmitManifestTypesEachTargetOfOneClass(t *testing.T) {
	t.Parallel()

	const darwin = "widget-darwin-arm64.tar.gz"

	r := newRelease(t, map[string]string{widget: widgetBody, darwin: "darwin\n"}, map[string]string{goBundle: "b\n"})
	lines := writeClassLines(t, "go-binary", legLine("linux-amd64", widget, widgetBody)+
		legLine("darwin-arm64", darwin, "darwin\n"))

	out, _ := emitWants(t, r.args("go-binary", "--leg-lines", lines), exitOK)

	for _, want := range []string{
		`{"name":"` + widget + `","sha256":"` + sumOf(widgetBody) +
			`","type":"build-subject","class":"go-binary","target":"linux-amd64"}`,
		`{"name":"` + darwin + `","sha256":"` + sumOf("darwin\n") +
			`","type":"build-subject","class":"go-binary","target":"darwin-arm64"}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manifest lacks %s:\n%s", want, out)
		}
	}
}

// The image-only release (stele#329): every artifact lives in a
// registry, so the asset directory holds only documents and the
// manifest used to list no artifact at all. --registry-lines is where
// the publisher says what it shipped there — one repository at two
// digests is two subjects — and each leaves typed, attributed, and
// outside the build subjects a rebuild compares against the release's
// assets.
func TestEmitManifestNamesWhatARegistryHolds(t *testing.T) {
	t.Parallel()

	const image = "ghcr.io/acme/widget"

	r := newRelease(t, map[string]string{"widget-1.0.0.spdx.json": "sbom\n"},
		map[string]string{"attestations-image.intoto.jsonl": "b\n"})
	lines := writeClassLines(t, "oci-image", legLine("pg16", image, "sixteen")+legLine("pg17", image, "seventeen"))

	// With --out the document has a file of its own and progress keeps
	// stdout.
	progress, _ := emitWants(t, r.args("oci-image", "--registry-lines", lines, "--out",
		filepath.Join(t.TempDir(), "m.json")), exitOK)

	if !strings.Contains(progress, "0 build subject(s) and 2 registry subject(s)") {
		t.Errorf("the progress line does not count the registry subjects: %s", progress)
	}

	r = newRelease(t, map[string]string{"widget-1.0.0.spdx.json": "sbom\n"},
		map[string]string{"attestations-image.intoto.jsonl": "b\n"})
	out, _ := emitWants(t, r.args("oci-image", "--registry-lines", lines), exitOK)

	for _, want := range []string{
		`{"name":"` + image + `","sha256":"` + sumOf("sixteen") +
			`","type":"registry-subject","class":"oci-image","target":"pg16"}`,
		`{"name":"` + image + `","sha256":"` + sumOf("seventeen") +
			`","type":"registry-subject","class":"oci-image","target":"pg17"}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manifest lacks %s:\n%s", want, out)
		}
	}
}

// Every way --registry-lines can be wrong refuses by name. The join it
// cannot make — against a list of what the registry holds — is exactly
// why the flag exists, so the guards are the ones that remain: the
// grammar, one set of lines per class, readable lines, and the rule
// that keeps the two populations apart.
func TestEmitManifestRegistrySubjectRefusals(t *testing.T) {
	t.Parallel()

	const image = "ghcr.io/acme/widget"

	tests := []struct {
		name     string
		registry func(t *testing.T) []string
		code     int
		want     string
	}{
		{
			"a value that is not <class>=<file>",
			func(*testing.T) []string { return []string{"oci-image"} },
			exitUsage, `invalid value "oci-image" for flag -registry-lines: "oci-image" is not <class>=<file>`,
		},
		{
			"one class's lines twice",
			func(t *testing.T) []string {
				t.Helper()

				lines := writeClassLines(t, "go-binary", legLine("image", image, "i"))

				return []string{lines, lines}
			},
			exitUsage, "--registry-lines names go-binary twice",
		},
		{
			"lines that are not there",
			func(*testing.T) []string { return []string{"go-binary=/nowhere/at/all.lines"} },
			exitUsage, "no such file",
		},
		{
			"a registry subject the release also publishes as an asset",
			func(t *testing.T) []string {
				t.Helper()

				return []string{writeClassLines(t, "go-binary", legLine("image", widget, widgetBody))}
			},
			exitUsage, "--registry-lines go-binary:image names " + widget + ", which this release publishes as" +
				" an asset — an asset is claimed by --leg-lines, and one artifact lives in one place",
		},
		{
			"a class the release did not declare",
			func(t *testing.T) []string {
				t.Helper()

				return []string{writeClassLines(t, "oci-image", legLine("image", image, "i"))}
			},
			exitRefused, "is not one this release declared",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			args := theRelease(t).args("go-binary", "--leg-lines", goBinaryLines(t))
			for _, v := range tt.registry(t) {
				args = append(args, "--registry-lines", v)
			}

			_, stderr := emitWants(t, args, tt.code)
			if !strings.Contains(stderr, tt.want) {
				t.Errorf("stderr %q\nlacks %q", stderr, tt.want)
			}
		})
	}
}
