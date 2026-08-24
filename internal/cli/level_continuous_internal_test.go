// The continuous-digest surface's guard branches, one row each.
//
// Every read this leg makes can fail, come back empty, or come back
// with something that is not what was asked for, and all three look
// alike from downstream: no inventory. A guard that skips when it
// should run looks exactly like success, so each is exercised here
// with no network and no registry.
//
// The rows that matter most are the absent shapes — a rolling tag
// naming nothing, a store holding nothing, a store holding somebody
// else's signature — because those are the states a live proof cannot
// stage and the ones a stream spends its first weeks in.

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/level"
	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/population"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

// The stream this file measures. Foreign names throughout: nothing
// about a publish surface may be one organisation's shape, and a
// fixture wearing the author's own registry proves nothing about a
// stranger.
const (
	streamRegistry = "registry.example.test/atelier/loom"
	streamTag      = "rolling"
	streamSigner   = `^https://forge\.example\.test/atelier/keeper/`
	streamSAN      = "https://forge.example.test/atelier/keeper/.forge/flows/seal.yml@" +
		"9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c"

	indexDigest = "sha256:" +
		"1111111111111111111111111111111111111111111111111111111111111111"
	amdDigest = "sha256:" +
		"2222222222222222222222222222222222222222222222222222222222222222"
	armDigest = "sha256:" +
		"3333333333333333333333333333333333333333333333333333333333333333"
)

// twoArchIndex is what a multi-platform stream publishes: an index
// naming one manifest per architecture.
const twoArchIndex = `{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[` +
	`{"digest":"` + amdDigest + `","platform":{"architecture":"amd64","os":"linux"}},` +
	`{"digest":"` + armDigest + `","platform":{"architecture":"arm64","os":"linux"}}]}`

// The attested documents. Each names itself inside its own bytes,
// which is how both surfaces recognise them.
const (
	spdxStatement = `{"predicateType":"https://spdx.dev/Document","predicate":` +
		`{"spdxVersion":"SPDX-2.3","packages":[{"name":"loom-core",` +
		`"externalRefs":[{"referenceLocator":"pkg:cargo/loom-core@0.1.0"}]}]}}`
	emptySPDXStatement = `{"predicateType":"https://spdx.dev/Document","predicate":` +
		`{"spdxVersion":"SPDX-2.3","packages":[]}}`
	cycloneStatement = `{"predicateType":"https://cyclonedx.org/bom","predicate":` +
		`{"bomFormat":"CycloneDX","components":[{"purl":"pkg:cargo/loom-core@0.1.0"}]}}`
	vexStatement = `{"predicateType":"https://openvex.dev/ns/v0.2.0","predicate":` +
		`{"@context":"https://openvex.dev/ns/v0.2.0","timestamp":"2026-08-24T00:45:24Z","statements":[` +
		`{"vulnerability":{"name":"GHSA-loom"},"status":"not_affected",` +
		`"justification":"vulnerable_code_not_present",` +
		`"products":[{"@id":"pkg:cargo/loom-core@0.1.0"}]}]}}`
	brokenVEXStatement = `{"predicateType":"https://openvex.dev/ns/v0.2.0","predicate":` +
		`{"@context":"https://openvex.dev/ns/v0.2.0","timestamp":"2026-08-24T00:45:24Z","statements":[` +
		`{"status":"not_affected"}]}}`
	// A verified attestation that is neither: the provenance every
	// publish already carries. It must classify as nothing at all,
	// because counting it would let a build claim answer a dependency
	// question.
	provenanceStatementDoc = `{"predicateType":"https://slsa.dev/provenance/v1","predicate":` +
		`{"buildDefinition":{"buildType":"https://example.test/loom/v1"}}}`
	// A statement whose predicate is absent: the envelope arrived and
	// the document it was about did not.
	predicatelessStatement = `{"predicateType":"https://spdx.dev/Document"}`
)

// streamSurface is the declaration this stream publishes under.
func streamSurface() population.Surface {
	kind := population.SurfaceContinuousDigest
	registry, tag, identity := streamRegistry, streamTag, streamSigner

	return population.Surface{Kind: &kind, Registry: &registry, Tag: &tag, Identity: &identity}
}

// storeForgeStream serves the attestation store by subject digest.
// The keys are BARE hex, the shape the forge's own door takes.
type storeForgeStream struct {
	levelForge

	bundles map[string][]jsonx.Raw
	attErr  error
}

func (f *storeForgeStream) Attestations(_, _, hex string) ([]jsonx.Raw, error) {
	if f.attErr != nil {
		return nil, f.attErr
	}

	return f.bundles[hex], nil
}

// bare strips the algorithm off a digest, which is how the store's
// door is keyed.
func bare(digest string) string { return strings.TrimPrefix(digest, "sha256:") }

// scriptedMeasurer proves exactly the bundles it was given, and
// reports the identity each was signed under. A bundle it does not
// know does not verify — which is the honest stand-in for a signature
// that fails, and the branch that must never become evidence.
type scriptedMeasurer struct {
	verify.BundleVerifier

	proven map[string]*trust.Verified
}

func (m scriptedMeasurer) MeasureAttestation(raw []byte, _ string) (*trust.Verified, error) {
	if v, ok := m.proven[string(raw)]; ok {
		return v, nil
	}

	return nil, errScriptedVerifier
}

func (m scriptedMeasurer) MeasureBlob([]byte, string) (*trust.Verified, error) {
	return nil, errScriptedVerifier
}

// signedBy returns the bundle name and the verification it proves,
// always under the stream's own declared signer — the identity that
// does NOT match is written out at its one row, where the point is
// that it does not match.
func signedBy(name, statement string) (jsonx.Raw, *trust.Verified) {
	return jsonx.Raw(name), &trust.Verified{SAN: streamSAN, Payload: []byte(statement)}
}

// streamScanner reports one finding against the stream's own package,
// so a decision over it can be joined.
type streamScanner struct{}

func (streamScanner) Scan([]byte) ([]byte, error) {
	return []byte(`{"results":[{"packages":[{` +
		`"package":{"name":"loom-core","version":"0.1.0","ecosystem":"cargo"},` +
		`"vulnerabilities":[{"id":"GHSA-loom"}]}]}]}`), nil
}

// swapStreamSeams points the continuous leg at a scripted registry,
// store and verifier.
func swapStreamSeams(t *testing.T, forge gh.Forge, reader scriptedOCI, proven map[string]*trust.Verified) {
	t.Helper()

	swapLevelSeams(t, forge, nil)
	swapOCI(t, reader)

	origScan, origVerifier := newScanner, newBundleVerifier
	newScanner = func() osv.Scanner { return streamScanner{} }
	newBundleVerifier = func([]byte) (verify.BundleVerifier, error) {
		return scriptedMeasurer{proven: proven}, nil
	}

	t.Cleanup(func() { newScanner, newBundleVerifier = origScan, origVerifier })
}

// TestContinuousSurfaceAbsences walks every way a stream's evidence
// can fail to arrive, and holds each to the account it owes.
//
//nolint:maintidx // one table, one row per guard: splitting it would hide the set
func TestContinuousSurfaceAbsences(t *testing.T) {
	invBundle, invVerified := signedBy("inventory", spdxStatement)
	vexBundle, vexVerified := signedBy("decision", vexStatement)

	for _, tc := range []struct {
		name string
		// reader is the registry this run reads.
		reader scriptedOCI
		// bundles is the attestation store, by bare subject digest.
		bundles map[string][]jsonx.Raw
		attErr  error
		proven  map[string]*trust.Verified
		// want are clauses the surface's account must carry; none is
		// the assertion that the surface was reached whole.
		want []string
		// inventoried is how many artifacts came out inventoried.
		inventoried int
	}{
		{
			name:   "the registry cannot be asked what the tag names",
			reader: scriptedOCI{resolveErr: errors.New("registry unreachable")},
			want:   []string{"the registry could not be asked what " + streamRegistry + ":" + streamTag + " names"},
		},
		{
			name:   "the rolling tag names nothing yet",
			reader: scriptedOCI{},
			want:   []string{"the registry holds nothing under the rolling tag " + streamRegistry + ":" + streamTag},
		},
		{
			name:   "the manifest the tag names cannot be read",
			reader: scriptedOCI{resolved: indexDigest, indexErr: errors.New("manifest unreachable")},
			want:   []string{"that manifest could not be read"},
		},
		{
			name:   "the manifest the tag names is not readable JSON",
			reader: scriptedOCI{resolved: indexDigest, index: "not a manifest"},
			want:   []string{"that manifest could not be parsed"},
		},
		{
			name:    "a published index whose store holds nothing at all",
			reader:  scriptedOCI{resolved: indexDigest, index: twoArchIndex},
			bundles: map[string][]jsonx.Raw{},
			want: []string{
				"carries a dependency inventory (an SPDX or CycloneDX document)",
				"carries a triage decision (an OpenVEX document)",
				"2 of the 2 artifact digest(s) the publish names carry no attestation at all",
			},
		},
		{
			name:    "the store itself refuses",
			reader:  scriptedOCI{resolved: indexDigest, index: twoArchIndex},
			attErr:  errors.New("store unreachable"),
			bundles: map[string][]jsonx.Raw{},
			want: []string{
				"carries a dependency inventory (an SPDX or CycloneDX document)",
				"carries a triage decision (an OpenVEX document)",
			},
		},
		{
			name:   "an attestation that does not verify is not evidence",
			reader: scriptedOCI{resolved: indexDigest, index: twoArchIndex},
			bundles: map[string][]jsonx.Raw{
				bare(amdDigest): {jsonx.Raw("forged")},
				bare(armDigest): {jsonx.Raw("forged")},
			},
			proven: map[string]*trust.Verified{},
			want: []string{
				"carries a dependency inventory (an SPDX or CycloneDX document)",
				"none verifies under the declared signer",
			},
		},
		{
			name:   "an attestation under somebody else's identity",
			reader: scriptedOCI{resolved: indexDigest, index: twoArchIndex},
			bundles: map[string][]jsonx.Raw{
				bare(amdDigest): {jsonx.Raw("stranger")},
				bare(armDigest): {jsonx.Raw("stranger")},
			},
			proven: map[string]*trust.Verified{
				"stranger": {SAN: "https://forge.example.test/someone-else/flows/sign.yml@abc", Payload: []byte(spdxStatement)},
			},
			want: []string{
				"carries a dependency inventory (an SPDX or CycloneDX document)",
				"2 attestation(s) were held over these digests and none verifies under the declared signer",
			},
		},
		{
			name:   "a verified attestation that is neither an inventory nor a decision",
			reader: scriptedOCI{resolved: indexDigest, index: twoArchIndex},
			bundles: map[string][]jsonx.Raw{
				bare(indexDigest): {jsonx.Raw("provenance")},
				bare(amdDigest):   {jsonx.Raw("provenance")},
				bare(armDigest):   {jsonx.Raw("provenance")},
			},
			proven: map[string]*trust.Verified{
				"provenance": {SAN: streamSAN, Payload: []byte(provenanceStatementDoc)},
			},
			want: []string{
				"carries a dependency inventory (an SPDX or CycloneDX document)",
				"carries a triage decision (an OpenVEX document)",
			},
		},
		{
			name:   "a verified attestation carrying no predicate at all",
			reader: scriptedOCI{resolved: indexDigest, index: twoArchIndex},
			bundles: map[string][]jsonx.Raw{
				bare(indexDigest): {jsonx.Raw("empty")},
				bare(amdDigest):   {jsonx.Raw("empty")},
				bare(armDigest):   {jsonx.Raw("empty")},
			},
			proven: map[string]*trust.Verified{
				"empty": {SAN: streamSAN, Payload: []byte(predicatelessStatement)},
			},
			want: []string{"carries a dependency inventory (an SPDX or CycloneDX document)"},
		},
		{
			name:   "an inventory but no decision",
			reader: scriptedOCI{resolved: indexDigest, index: twoArchIndex},
			bundles: map[string][]jsonx.Raw{
				bare(indexDigest): {invBundle},
				bare(amdDigest):   {invBundle},
				bare(armDigest):   {invBundle},
			},
			proven:      map[string]*trust.Verified{"inventory": invVerified},
			want:        []string{"carries a triage decision (an OpenVEX document)"},
			inventoried: 2,
		},
		{
			name:   "a decision this run cannot read",
			reader: scriptedOCI{resolved: indexDigest, index: twoArchIndex},
			bundles: map[string][]jsonx.Raw{
				bare(indexDigest): {invBundle, jsonx.Raw("broken")},
				bare(amdDigest):   {invBundle},
				bare(armDigest):   {invBundle},
			},
			proven: map[string]*trust.Verified{
				"inventory": invVerified,
				"broken":    {SAN: streamSAN, Payload: []byte(brokenVEXStatement)},
			},
			want:        []string{"carries a triage decision (an OpenVEX document)"},
			inventoried: 2,
		},
		{
			name:   "both, over every digest the publish names",
			reader: scriptedOCI{resolved: indexDigest, index: twoArchIndex},
			bundles: map[string][]jsonx.Raw{
				bare(indexDigest): {vexBundle},
				bare(amdDigest):   {invBundle},
				bare(armDigest):   {invBundle},
			},
			proven: map[string]*trust.Verified{
				"inventory": invVerified,
				"decision":  vexVerified,
			},
			inventoried: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forge := &storeForgeStream{bundles: tc.bundles, attErr: tc.attErr}
			swapStreamSeams(t, forge, tc.reader, tc.proven)

			ev := &level.Evidence{Owner: "atelier", Repo: "loom"}
			surface := level.PublishSurface{Name: streamSurface().Name()}
			la := &levelArgs{track: trackDependency, owner: "atelier", name: "loom", repo: "atelier/loom"}

			la.dependencyOnContinuous(ev, &surface, streamSurface(), forge, &latch{w: &bytes.Buffer{}})

			account := strings.Join(surface.Missing, " | ")

			for _, want := range tc.want {
				if !strings.Contains(account, want) {
					t.Errorf("the account does not carry %q:\n%s", want, account)
				}
			}

			if len(tc.want) == 0 && len(surface.Missing) > 0 {
				t.Errorf("a whole publish still reported absences:\n%s", account)
			}

			if got := len(ev.Inventoried); got != tc.inventoried {
				t.Errorf("%d artifact(s) inventoried, want %d (%v)", got, tc.inventoried, ev.Inventoried)
			}
		})
	}
}

// TestContinuousSurfaceYieldsALevel is the shape the whole issue is
// for: a repository whose only publish is a rolling digest, whose
// inventory and triage decision are attested over that digest, reaches
// a computed dependency level with no release anywhere.
func TestContinuousSurfaceYieldsALevel(t *testing.T) {
	invBundle, invVerified := signedBy("inventory", spdxStatement)
	vexBundle, vexVerified := signedBy("decision", vexStatement)

	forge := &storeForgeStream{bundles: map[string][]jsonx.Raw{
		bare(indexDigest): {vexBundle},
		bare(amdDigest):   {invBundle},
		bare(armDigest):   {invBundle},
	}}

	swapStreamSeams(t,
		forge,
		scriptedOCI{resolved: indexDigest, index: twoArchIndex},
		map[string]*trust.Verified{"inventory": invVerified, "decision": vexVerified},
	)

	ev := &level.Evidence{Owner: "atelier", Repo: "loom"}
	la := &levelArgs{
		track: trackDependency, owner: "atelier", name: "loom", repo: "atelier/loom",
		surfaces: []population.Surface{streamSurface()},
	}

	la.gatherDependency(ev, forge, &latch{w: &bytes.Buffer{}})

	switch {
	case len(ev.Inventoried) != 2:
		t.Fatalf("inventoried = %v, want both architecture digests", ev.Inventoried)
	case !ev.Scanned:
		t.Fatal("the stream's inventories were not scanned")
	case ev.Findings != 2:
		t.Fatalf("findings = %d, want one per inventory", ev.Findings)
	case ev.Triaged != ev.Findings:
		t.Fatalf("triaged = %d of %d — the attested decision did not join", ev.Triaged, ev.Findings)
	}

	got := level.Assess(level.TrackDependency, ev).Level()
	if got != "SLSA_DEPENDENCY_LEVEL_2" {
		t.Errorf("level = %s, want the two rungs a stream's own evidence establishes", got)
	}

	// The subjects are named by the digests a consumer pulls, so a
	// finding about one can be acted on without this run's logs.
	if !strings.Contains(strings.Join(ev.Inventoried, " "), streamRegistry+"@"+amdDigest) {
		t.Errorf("inventoried = %v, want each artifact named by its own digest", ev.Inventoried)
	}
}

// TestContinuousInventoryCoveringNothing: an inventory that names no
// package inventories nothing, and the artifacts it was published
// beside are uninventoried rather than covered. The same union rule
// the release surface applies, applied here.
func TestContinuousInventoryCoveringNothing(t *testing.T) {
	empty, emptyVerified := signedBy("empty-inventory", emptySPDXStatement)

	forge := &storeForgeStream{bundles: map[string][]jsonx.Raw{
		bare(amdDigest): {empty},
		bare(armDigest): {empty},
	}}

	swapStreamSeams(t, forge,
		scriptedOCI{resolved: indexDigest, index: twoArchIndex},
		map[string]*trust.Verified{"empty-inventory": emptyVerified})

	ev := &level.Evidence{Owner: "atelier", Repo: "loom"}
	surface := level.PublishSurface{}
	la := &levelArgs{track: trackDependency, owner: "atelier", name: "loom", repo: "atelier/loom"}

	la.dependencyOnContinuous(ev, &surface, streamSurface(), forge, &latch{w: &bytes.Buffer{}})

	if len(ev.Uninventoried) != 2 || len(ev.Inventoried) != 0 {
		t.Fatalf("inventoried = %v, uninventoried = %v — an inventory naming nothing covers nothing",
			ev.Inventoried, ev.Uninventoried)
	}
}

// TestContinuousSingleManifest: a stream publishing one platform
// publishes one artifact, and the tag names it directly rather than
// naming an index. The manifest simply carries no children, which is
// why this reads the shape rather than a media type.
func TestContinuousSingleManifest(t *testing.T) {
	invBundle, invVerified := signedBy("inventory", cycloneStatement)

	forge := &storeForgeStream{bundles: map[string][]jsonx.Raw{
		bare(indexDigest): {invBundle},
	}}

	swapStreamSeams(t, forge,
		scriptedOCI{resolved: indexDigest, index: `{"mediaType":"application/vnd.oci.image.manifest.v1+json"}`},
		map[string]*trust.Verified{"inventory": invVerified})

	ev := &level.Evidence{Owner: "atelier", Repo: "loom"}
	surface := level.PublishSurface{}
	la := &levelArgs{track: trackDependency, owner: "atelier", name: "loom", repo: "atelier/loom"}

	la.dependencyOnContinuous(ev, &surface, streamSurface(), forge, &latch{w: &bytes.Buffer{}})

	if len(ev.Inventoried) != 1 || ev.Inventoried[0] != streamRegistry+"@"+indexDigest {
		t.Fatalf("inventoried = %v, want the one artifact the tag names", ev.Inventoried)
	}
}

// TestContinuousUnusableSigner: the declaration's pattern is refused
// at load, so this branch is only reachable by a caller holding a
// hand-built surface — and it must still report rather than panic.
func TestContinuousUnusableSigner(t *testing.T) {
	forge := &storeForgeStream{}
	swapStreamSeams(t, forge, scriptedOCI{resolved: indexDigest, index: twoArchIndex}, nil)

	s := streamSurface()
	broken := "^https://forge(.example"
	s.Identity = &broken

	ev := &level.Evidence{Owner: "atelier", Repo: "loom"}
	surface := level.PublishSurface{}
	la := &levelArgs{track: trackDependency, owner: "atelier", name: "loom", repo: "atelier/loom"}

	la.dependencyOnContinuous(ev, &surface, s, forge, &latch{w: &bytes.Buffer{}})

	if len(surface.Missing) != 1 || !strings.Contains(surface.Missing[0], "does not compile") {
		t.Fatalf("missing = %v, want the unusable pattern reported", surface.Missing)
	}
}

// TestContinuousWithoutTrustMaterial: nothing the store holds can be
// proven without a trusted root, and a run in that state has looked at
// nothing rather than found nothing.
func TestContinuousWithoutTrustMaterial(t *testing.T) {
	forge := &storeForgeStream{}
	swapStreamSeams(t, forge, scriptedOCI{resolved: indexDigest, index: twoArchIndex}, nil)

	orig := resolveTrustedRoot
	resolveTrustedRoot = func(trust.RootPlan) ([]byte, error) { return nil, errors.New("no root") }

	t.Cleanup(func() { resolveTrustedRoot = orig })

	ev := &level.Evidence{Owner: "atelier", Repo: "loom"}
	surface := level.PublishSurface{}
	la := &levelArgs{track: trackDependency, owner: "atelier", name: "loom", repo: "atelier/loom"}

	la.dependencyOnContinuous(ev, &surface, streamSurface(), forge, &latch{w: &bytes.Buffer{}})

	if len(surface.Missing) != 1 || !strings.Contains(surface.Missing[0], "no trust material") {
		t.Fatalf("missing = %v, want the run to say it could prove nothing", surface.Missing)
	}
}

// TestSurfaceSetShapes: what the gather looks at for each shape of
// declaration, including the two absent ones.
func TestSurfaceSetShapes(t *testing.T) {
	release := population.Surface{Kind: func() *population.SurfaceKind {
		k := population.SurfaceRelease

		return &k
	}()}

	for _, tc := range []struct {
		name     string
		surfaces []population.Surface
		declared bool
		want     []string
	}{
		{
			// No declaration is the default expression, and the default
			// is exactly today's behaviour: a repository cutting releases
			// keeps being measured on them with no policy at all.
			name: "no declaration takes the release surface",
			want: []string{"release: this repository has published no release this tool can order"},
		},
		{
			// A declared empty set is the opposite of an absent one:
			// nothing is looked at, and the rung says so.
			name:     "a declared empty set looks at nothing",
			surfaces: []population.Surface{},
			declared: true,
			want:     []string{},
		},
		{
			// The both-absent case: both accounts are owed, because
			// clearing one leaves the other true.
			name:     "both surfaces declared and neither published on",
			surfaces: []population.Surface{release, streamSurface()},
			declared: true,
			want: []string{
				"release: this repository has published no release this tool can order",
				"the registry holds nothing under the rolling tag",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forge := &storeForgeStream{}
			swapStreamSeams(t, forge, scriptedOCI{}, nil)

			ev := &level.Evidence{Owner: "atelier", Repo: "loom"}
			la := &levelArgs{track: trackDependency, owner: "atelier", name: "loom", repo: "atelier/loom"}

			if tc.declared {
				la.surfaces = tc.surfaces
			}

			la.gatherDependency(ev, forge, &latch{w: &bytes.Buffer{}})

			if got := len(ev.PublishSurfaces); got != len(tc.want) {
				t.Fatalf("%d surface(s) looked at, want %d: %+v", got, len(tc.want), ev.PublishSurfaces)
			}

			var account []string
			for _, s := range ev.PublishSurfaces {
				account = append(account, s.Name+": "+strings.Join(s.Missing, "; "))
			}

			joined := strings.Join(account, " | ")

			for _, want := range tc.want {
				if !strings.Contains(joined, want) {
					t.Errorf("the account does not carry %q:\n%s", want, joined)
				}
			}
		})
	}
}

// TestNoFallbackBetweenSurfaces: a repository declaring both is judged
// on both. A release gather that found nothing may never be answered
// by a continuous one — absence read as compliance is the failure mode
// that costs more than a missing rung, so the empty release surface
// stays in the account even while the stream is whole.
func TestNoFallbackBetweenSurfaces(t *testing.T) {
	invBundle, invVerified := signedBy("inventory", spdxStatement)
	vexBundle, vexVerified := signedBy("decision", vexStatement)

	forge := &storeForgeStream{bundles: map[string][]jsonx.Raw{
		bare(indexDigest): {vexBundle},
		bare(amdDigest):   {invBundle},
		bare(armDigest):   {invBundle},
	}}

	swapStreamSeams(t, forge,
		scriptedOCI{resolved: indexDigest, index: twoArchIndex},
		map[string]*trust.Verified{"inventory": invVerified, "decision": vexVerified})

	kind := population.SurfaceRelease
	ev := &level.Evidence{Owner: "atelier", Repo: "loom"}
	la := &levelArgs{
		track: trackDependency, owner: "atelier", name: "loom", repo: "atelier/loom",
		surfaces: []population.Surface{{Kind: &kind}, streamSurface()},
	}

	la.gatherDependency(ev, forge, &latch{w: &bytes.Buffer{}})

	if len(ev.PublishSurfaces) != 2 {
		t.Fatalf("%d surface(s) looked at, want both", len(ev.PublishSurfaces))
	}

	if ev.PublishSurfaces[0].Reached() {
		t.Error("the release surface reported nothing missing, and this repository cuts no release")
	}

	if !ev.PublishSurfaces[1].Reached() {
		t.Errorf("the stream reported absences: %v", ev.PublishSurfaces[1].Missing)
	}
}

// strangerStreamPolicy is a minimal assert policy from an adopter this tool
// has never heard of: one repository, publishing only digests, foreign
// names throughout. It must LOAD and it must JUDGE with no edit to
// this engine — the stranger condition, executed rather than asserted.
const strangerStreamPolicy = `{
  "schema": 7,
  "population": {"repositories": [
    {"repo": "loom", "surfaces": [
      {"kind": "continuous-digest",
       "registry": "registry.example.test/atelier/loom",
       "tag": "rolling",
       "identity": "^https://forge\\.example\\.test/atelier/keeper/"}
    ]}
  ]},
  "evidence": {
    "sbomSuffix": ".spdx.json", "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl", "manifestAsset": "evidence-manifest.json",
    "storeVsaFromVersion": "1.0.0",
    "classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}
  }
}`

// TestStrangerDeclaresItsOwnSurface runs the whole path a fresh
// adopter takes: a committed policy naming its stream, a board over
// the one repository it owns, and a dependency cell computed from what
// its publish actually attested.
func TestStrangerDeclaresItsOwnSurface(t *testing.T) {
	invBundle, invVerified := signedBy("inventory", spdxStatement)
	vexBundle, vexVerified := signedBy("decision", vexStatement)

	forge := &storeForgeStream{bundles: map[string][]jsonx.Raw{
		bare(indexDigest): {vexBundle},
		bare(amdDigest):   {invBundle},
		bare(armDigest):   {invBundle},
	}}

	swapStreamSeams(t, forge,
		scriptedOCI{resolved: indexDigest, index: twoArchIndex},
		map[string]*trust.Verified{"inventory": invVerified, "decision": vexVerified})

	dir := t.TempDir()
	path := filepath.Join(dir, "assert-policy.json")

	if err := os.WriteFile(path, []byte(strangerStreamPolicy), 0o600); err != nil {
		t.Fatalf("writing the policy: %v", err)
	}

	outDir := filepath.Join(dir, "board")

	var stdout, stderr bytes.Buffer

	if code := Run([]string{
		"level", "--repo", "atelier/loom", "--policy", path, "--out-dir", outDir,
	}, &stdout, &stderr); code != exitOK {
		t.Fatalf("the stranger's board exited %d:\n%s\n%s", code, stdout.String(), stderr.String())
	}

	//nolint:gosec // the path is this test's own temporary directory
	doc, err := os.ReadFile(filepath.Join(outDir, "loom", "dependency.report.json"))
	if err != nil {
		t.Fatalf("reading the published cell: %v", err)
	}

	for _, want := range []string{
		`"SLSA_DEPENDENCY_LEVEL_2"`,
		"a published inventory covers all 2 published artifact(s)",
		"all 2 advisory finding(s) carry a published triage decision",
	} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("the stranger's dependency cell does not carry %q:\n%s", want, doc)
		}
	}
}
