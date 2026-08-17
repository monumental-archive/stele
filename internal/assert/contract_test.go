// Contract sources: the manifest is the declared future, the
// workflow adapter is the quarantined history read, and a release
// neither speaks for is legacy. Every branch of the adapter's
// convention (reusable→stub indirection, pin-comment version, the
// canon's own local reference) is a row.

package assert_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
)

func TestManifestSource(t *testing.T) {
	t.Parallel()

	f := completeRelease()
	src := assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"}

	c, ok, err := src.Contract("acme", "widget", "v1.0.0")
	if err != nil || !ok {
		t.Fatalf("Contract: ok=%v err=%v", ok, err)
	}

	if len(c.Classes) != 1 || c.Classes[0] != "oci-image" || !c.StoreVSA {
		t.Fatalf("contract = %+v", c)
	}

	// No manifest asset → not this source's release.
	f2 := completeRelease()
	f2.assets["widget@v1.0.0"] = drop(f2.assets["widget@v1.0.0"], "evidence-manifest.json")

	if _, ok, err := (assert.ManifestSource{Forge: f2, Asset: "evidence-manifest.json"}).
		Contract("acme", "widget", "v1.0.0"); ok || err != nil {
		t.Fatalf("absent manifest: ok=%v err=%v, want false/nil", ok, err)
	}

	// A malformed manifest is an error, never a silent fall-through:
	// the release DECLARED a contract and the declaration is broken.
	f3 := completeRelease()
	f3.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = `{"schema": 1}`

	if _, _, err := (assert.ManifestSource{Forge: f3, Asset: "evidence-manifest.json"}).
		Contract("acme", "widget", "v1.0.0"); err == nil {
		t.Fatal("a malformed manifest did not refuse")
	}
}

func workflowForge(publishYML, selfPublishYML string) *fakeForge {
	files := map[string]string{}
	if publishYML != "" {
		files["widget:v1.0.0:.github/workflows/publish.yml"] = publishYML
	}

	if selfPublishYML != "" {
		files["widget:v1.0.0:.github/workflows/self-publish.yml"] = selfPublishYML
	}

	return &fakeForge{files: files}
}

func TestWorkflowSource(t *testing.T) {
	t.Parallel()

	pol := loadTestPolicy(t)

	tests := []struct {
		name     string
		forge    *fakeForge
		wantOK   bool
		classes  string
		storeVSA bool
	}{
		{
			"entry workflow with a pin comment past the epoch",
			workflowForge(
				"jobs:\n  publish:\n    uses: acme/canon/.github/workflows/publish.yml@abc123 # v1.14.0\n"+
					"    with:\n      classes: oci-image,rust-crate\n", ""),
			true, "oci-image rust-crate", true,
		},
		{
			"the class list is comma-separated, spaces and quotes are noise",
			workflowForge(
				"jobs:\n  publish:\n    uses: acme/canon/.github/workflows/publish.yml@abc123 # v1.14.0\n"+
					"    with:\n      classes: \"oci-image, rust-crate ,, wasm-npm\"\n", ""),
			true, "oci-image rust-crate wasm-npm", true,
		},
		{
			"a single class needs no separator",
			workflowForge(
				"jobs:\n  publish:\n    uses: acme/canon/.github/workflows/publish.yml@abc123 # v1.14.0\n"+
					"    with:\n      classes: oci-image\n", ""),
			true, "oci-image", true,
		},
		{
			"entry workflow pinned before the epoch",
			workflowForge(
				"jobs:\n  publish:\n    uses: acme/canon/.github/workflows/publish.yml@abc123 # v1.12.0\n"+
					"    with:\n      classes: rust-crate\n", ""),
			true, "rust-crate", false,
		},
		{
			"reusable publish.yml defers to the self-publish stub",
			workflowForge(
				"on:\n  workflow_call:\n    inputs:\n      classes: {type: string}\n",
				"jobs:\n  publish:\n    uses: ./.github/workflows/publish.yml\n    with:\n      classes: source-archive\n"),
			true, "source-archive", true, // canon's own stub: version = the tag (1.0.0 < 1.13.0)... asserted below
		},
		{
			"no publish workflow at the tag means no contract",
			workflowForge("", ""),
			false, "", false,
		},
		{
			"a workflow with no classes line means no contract",
			workflowForge("jobs:\n  publish:\n    uses: acme/canon/.github/workflows/publish.yml@abc123 # v1.14.0\n", ""),
			false, "", false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			src := assert.WorkflowSource{Forge: tt.forge, Policy: pol.Evidence}

			c, ok, err := src.Contract("acme", "widget", "v1.0.0")
			if err != nil {
				t.Fatalf("Contract: %v", err)
			}

			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}

			if !ok {
				return
			}

			if got := strings.Join(c.Classes, " "); got != tt.classes {
				t.Fatalf("classes = %q, want %q", got, tt.classes)
			}
		})
	}
}

// TestWorkflowSourceLocalReferenceVersion pins the canon's own-stub
// rule: with no pin comment, the canon version is the tag itself —
// v1.0.0 predates the 1.13.0 epoch, so verdicts are NOT
// store-resident.
func TestWorkflowSourceLocalReferenceVersion(t *testing.T) {
	t.Parallel()

	src := assert.WorkflowSource{
		Forge: workflowForge(
			"on:\n  workflow_call:\n    inputs:\n      classes: {type: string}\n",
			"jobs:\n  publish:\n    uses: ./.github/workflows/publish.yml\n    with:\n      classes: source-archive\n"),
		Policy: loadTestPolicy(t).Evidence,
	}

	c, ok, err := src.Contract("acme", "widget", "v1.0.0")
	if err != nil || !ok {
		t.Fatalf("Contract: ok=%v err=%v", ok, err)
	}

	if c.StoreVSA {
		t.Fatal("a v1.0.0 local-reference stub predates the 1.13.0 epoch — storeVSA must be false")
	}
}

// TestSourcesOrder pins manifest-first: a release carrying both a
// manifest and a workflow contract is judged by its manifest.
func TestSourcesOrder(t *testing.T) {
	t.Parallel()

	f := completeRelease()
	f.files = map[string]string{
		"widget:v1.0.0:.github/workflows/publish.yml": "jobs:\n  p:\n" +
			"    uses: acme/canon/.github/workflows/publish.yml@a # v1.14.0\n" +
			"    with:\n      classes: rust-crate\n",
	}

	pol := loadTestPolicy(t)
	src := assert.Sources{
		assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"},
		assert.WorkflowSource{Forge: f, Policy: pol.Evidence},
	}

	c, ok, err := src.Contract("acme", "widget", "v1.0.0")
	if err != nil || !ok {
		t.Fatalf("Contract: ok=%v err=%v", ok, err)
	}

	if len(c.Classes) != 1 || c.Classes[0] != "oci-image" {
		t.Fatalf("classes = %v, want the manifest's oci-image, not the workflow's", c.Classes)
	}
}
