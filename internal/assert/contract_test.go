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

	pol := loadTestPolicy(t)

	f := completeRelease()
	src := assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}

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

	if _, ok, err := (assert.ManifestSource{Forge: f2, Policy: pol.Evidence, Asset: "evidence-manifest.json"}).
		Contract("acme", "widget", "v1.0.0"); ok || err != nil {
		t.Fatalf("absent manifest: ok=%v err=%v, want false/nil", ok, err)
	}

	// A broken declaration is an error, never a silent fall-through —
	// each required field's absence is its own guard row, and the
	// machineryVersion rows are the stele#109 point: without it the
	// obligations cannot be derived, and deriving is the only mode.
	for name, doc := range map[string]string{
		"empty manifest":           `{"schema": 2}`,
		"missing machineryVersion": `{"schema": 2, "classes": ["oci-image"], "storeVsa": true}`,
		"unparsable machineryVersion": `{"schema": 2, "classes": ["oci-image"], "storeVsa": true, ` +
			`"machineryVersion": "not-a-version", "entries": [` + manifestEntry("a.tar.gz", "build-subject") + `]}`,
		"no entries": `{"schema": 2, "classes": ["oci-image"], "storeVsa": true, ` +
			`"machineryVersion": "1.0.0"}`,
		"an entry typed outside the vocabulary": `{"schema": 2, "classes": ["oci-image"], "storeVsa": true, ` +
			`"machineryVersion": "1.0.0", "entries": [` + manifestEntry("a.tar.gz", "artefact") + `]}`,
		// Pre-v1 there is no dual-version reader: the manifests
		// published under schema 1 re-emit typed at the canon train,
		// and this reader refuses them until they do (stele#156).
		"the retired schema": `{"schema": 1, "classes": ["oci-image"], "storeVsa": true, ` +
			`"machineryVersion": "1.0.0"}`,
	} {
		f3 := completeRelease()
		f3.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = doc

		if _, _, err := (assert.ManifestSource{Forge: f3, Policy: pol.Evidence, Asset: "evidence-manifest.json"}).
			Contract("acme", "widget", "v1.0.0"); err == nil {
			t.Fatalf("%s did not refuse", name)
		}
	}
}

// TestManifestSourceEpochs pins that the manifest path DERIVES every
// obligation from the declared machinery version through the shared
// epoch semantics — never asserts one. The retired hardcode
// ("manifest-era releases postdate every machinery epoch by
// construction") was true of past epochs and false for any epoch
// still in the future, which is stele#109's finding.
func TestManifestSourceEpochs(t *testing.T) {
	t.Parallel()

	past, future := "1.0.0", "2.0.0"

	tests := []struct {
		name           string
		decisionFrom   *string
		enrichmentFrom *string
		machinery      string
		wantDecision   bool
		wantEnrichment bool
	}{
		{"no epochs declared: every obligation always held", nil, nil, "0.0.1", true, true},
		{"pre-epoch manifest release is exempt", &future, &future, "1.5.0", false, false},
		{"the epoch itself owes (inclusive)", &past, &past, "1.0.0", true, true},
		{"a future epoch exempts current manifests", &past, &future, "1.5.0", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pol := loadTestPolicy(t)
			pol.Evidence.DecisionFromVersion = tt.decisionFrom
			pol.Evidence.EnrichmentFromVersion = tt.enrichmentFrom

			f := completeRelease()
			f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = `{"schema": 2, ` +
				`"classes": ["oci-image"], "storeVsa": true, "machineryVersion": "` + tt.machinery + `", ` +
				`"entries": [` + manifestEntry("widget-x86_64.tar.gz", "build-subject") + `]}`

			c, ok, err := (assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}).
				Contract("acme", "widget", "v1.0.0")
			if err != nil || !ok {
				t.Fatalf("Contract: ok=%v err=%v", ok, err)
			}

			if c.Decision != tt.wantDecision || c.Enrichment != tt.wantEnrichment {
				t.Fatalf("decision=%v enrichment=%v, want %v/%v",
					c.Decision, c.Enrichment, tt.wantDecision, tt.wantEnrichment)
			}
		})
	}
}

// TestWorkflowSourceEnrichmentEpoch pins the workflow path's leg of
// the same derivation: the pin-comment machinery version answers the
// enrichment epoch exactly as it answers the decision one.
func TestWorkflowSourceEnrichmentEpoch(t *testing.T) {
	t.Parallel()

	epoch := "2.0.0"
	pol := loadTestPolicy(t)
	pol.Evidence.EnrichmentFromVersion = &epoch

	src := assert.WorkflowSource{
		Forge: workflowForge(
			"jobs:\n  publish:\n    uses: acme/canon/.github/workflows/publish.yml@abc123 # v1.14.0\n"+
				"    with:\n      classes: rust-crate\n", ""),
		Policy: pol.Evidence,
	}

	c, ok, err := src.Contract("acme", "widget", "v1.0.0")
	if err != nil || !ok {
		t.Fatalf("Contract: ok=%v err=%v", ok, err)
	}

	if c.Enrichment {
		t.Fatal("a v1.14.0 pin predates the 2.0.0 enrichment epoch — enrichment must be false")
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
		assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"},
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
