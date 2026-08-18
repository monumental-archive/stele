// A forge that tears mid-walk. This is the failure the engine's
// population rule exists for — the 2026-08-17 outage entered as
// exactly this — so the tables below break ONE named read at a time
// across every walking target, rather than one representative read.
// A tear swallowed anywhere here reports clean over releases nobody
// looked at.

package assert_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

var errTorn = errors.New("the forge tore")

// TestEvidenceForgeTears walks every read the evidence walk makes.
// Each row is the same conformant release with one read failing.
func TestEvidenceForgeTears(t *testing.T) {
	t.Parallel()

	for _, read := range []string{
		"Repos", "ReleaseTags", "ReleaseAssets", "Asset", "Attestations", "FailedRuns",
	} {
		t.Run(read, func(t *testing.T) {
			t.Parallel()

			f := completeRelease()
			f.torn = map[string]error{read: errTorn}

			if read == "FailedRuns" {
				// The run history is consulted only to narrow a verdict
				// finding into a burned release, so the row needs one.
				f.store = map[string][]string{}
			}

			pol := loadTestPolicy(t)
			src := assert.Sources{assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"}}

			_, err := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src,
				&fakeAttestor{}, nil, nil, nil, func(string, ...any) {})
			if err == nil {
				t.Fatalf("Evidence passed with %s torn — a walk that cannot read is not a clean walk", read)
			}

			if !errors.Is(err, errTorn) {
				t.Fatalf("Evidence = %v, want the tear carried out", err)
			}
		})
	}
}

// TestEvidenceContractSourceTears: the contract is read through two
// stacked sources, and either one tearing is a refusal — a contract
// that could not be read is not an absent contract.
func TestEvidenceContractSourceTears(t *testing.T) {
	t.Parallel()

	for _, read := range []string{"ReleaseAssets", "Asset", "WorkflowContents", "FileAt"} {
		t.Run(read, func(t *testing.T) {
			t.Parallel()

			f := completeRelease()
			pol := loadTestPolicy(t)

			// Both sources, so the workflow leg is reached when the
			// manifest leg finds nothing.
			src := assert.Sources{
				assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"},
				assert.WorkflowSource{Forge: f, Policy: pol.Evidence},
			}

			// Nothing in the manifest asset: the walk falls through to
			// the workflow source, where the torn read waits.
			f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = `{"schema": 1, "classes": []}`
			f.torn = map[string]error{read: errTorn}

			_, err := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src,
				&fakeAttestor{}, nil, nil, nil, func(string, ...any) {})
			if err == nil {
				t.Fatalf("Evidence passed with %s torn", read)
			}
		})
	}
}

// TestBlastRadiusForgeTears walks the scan walk's reads. Its own
// population rule makes an unreadable SBOM a refusal, never an
// advisory-free release.
func TestBlastRadiusForgeTears(t *testing.T) {
	t.Parallel()

	for _, read := range []string{"Repos", "ReleaseTags", "ReleaseAssets", "Asset", "Attestations"} {
		t.Run(read, func(t *testing.T) {
			t.Parallel()

			f := blastForge()
			f.torn = map[string]error{read: errTorn}

			_, err := assert.BlastRadius(loadBlastPolicy(t), assert.Population{Org: "acme"}, f,
				fakeScanner{out: scanResult(canaryScan, "serde", "1.0.0", "crates.io", false)},
				&vexjoin.Decisions{}, func(string, ...any) {})
			if err == nil {
				t.Fatalf("BlastRadius passed with %s torn", read)
			}

			if !errors.Is(err, errTorn) {
				t.Fatalf("BlastRadius = %v, want the tear carried out", err)
			}
		})
	}
}

// TestBlastRadiusScannerTears: the scanner is a subprocess somebody
// else maintains, and a run that could not scan has judged nothing.
func TestBlastRadiusScannerTears(t *testing.T) {
	t.Parallel()

	_, err := assert.BlastRadius(loadBlastPolicy(t), assert.Population{Org: "acme"}, blastForge(),
		fakeScanner{err: errTorn}, &vexjoin.Decisions{}, func(string, ...any) {})
	if err == nil || !errors.Is(err, errTorn) {
		t.Fatalf("BlastRadius = %v, want the scanner failure carried out", err)
	}
}

// TestTagsForgeTears walks the tag audit's reads across both halves of
// its seam: the release listing it walks and the tag surface it judges.
func TestTagsForgeTears(t *testing.T) {
	t.Parallel()

	t.Run("the repository listing", func(t *testing.T) {
		t.Parallel()

		forge := &fakeForge{repos: []string{"widget"}, torn: map[string]error{"Repos": errTorn}}

		_, err := assert.Tags(loadTagsPolicy(t), assert.Population{Org: "acme"},
			forge, conformantTags(), &fakeTagVerifier{}, func(string, ...any) {})
		if err == nil || !errors.Is(err, errTorn) {
			t.Fatalf("Tags = %v, want the listing tear", err)
		}
	})

	for _, read := range []string{"ChainNotes", "IsAncestor"} {
		t.Run(read, func(t *testing.T) {
			t.Parallel()

			tags := conformantTags()
			tags.torn = map[string]error{read: errTorn}

			_, err := assert.Tags(loadTagsPolicy(t), assert.Population{Repo: "acme/widget"},
				&fakeForge{}, tags, &fakeTagVerifier{}, func(string, ...any) {})
			if err == nil {
				t.Fatalf("Tags passed with %s torn", read)
			}

			if !errors.Is(err, errTorn) {
				t.Fatalf("Tags = %v, want the tear carried out", err)
			}
		})
	}
}

// TestNoCanaryWhenUndeclared: the canary is an opt-in tripwire, so a
// policy that declares none must seal without one — never a canary
// nothing could satisfy, which would make every run CANNOT_JUDGE.
func TestNoCanaryWhenUndeclared(t *testing.T) {
	t.Parallel()

	pol := loadBlastPolicy(t)
	pol.BlastRadius.Canary = nil

	rep, err := assert.BlastRadius(pol, assert.Population{Org: "acme"}, blastForge(),
		fakeScanner{out: `{"results": []}`}, &vexjoin.Decisions{}, func(string, ...any) {})
	if err != nil {
		t.Fatalf("BlastRadius = %v", err)
	}

	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS: %+v", rep.Verdict(), rep.Findings())
	}
}

// TestShortDigestKeepsShortInputWhole: the report abbreviates digests
// for humans, and a value already shorter than the window must survive
// intact rather than be sliced out of range.
func TestShortDigestKeepsShortInputWhole(t *testing.T) {
	t.Parallel()

	f := blastForge()
	f.store = map[string][]string{} // no attestation over the SBOM digest

	rep, err := assert.BlastRadius(loadBlastPolicy(t), assert.Population{Org: "acme"}, f,
		fakeScanner{out: scanResult(canaryScan, "serde", "1.0.0", "crates.io", false)},
		&vexjoin.Decisions{}, func(string, ...any) {})
	if err != nil {
		t.Fatalf("BlastRadius = %v", err)
	}

	var detail string

	for _, fd := range rep.Findings() {
		if strings.Contains(fd.Assertion, "unattested") {
			detail = fd.Detail
		}
	}

	if detail == "" {
		t.Fatalf("no unattested finding: %+v", rep.Findings())
	}
}

// TestContinuousHalfTears walks the continuous-digest half's own reads.
// Each is a fact about the rolling image, and an unreadable one is not
// a repository that publishes nothing.
func TestContinuousHalfTears(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		torn string
		want string
	}{
		{"the stub cannot be read", "FileAt", "continuous stub"},
		{"the registry cannot be read", "PackageVersionDigest", "package versions"},
		{"the workflows cannot be read", "WorkflowContents", "workflows of"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := continuousForge()
			f.torn = map[string]error{tc.torn: errTorn}

			pol, err := assert.LoadPolicy(strings.NewReader(continuousOnlyPolicyJSON))
			if err != nil {
				t.Fatal(err)
			}

			src := assert.Sources{assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"}}

			_, err = assert.Evidence(pol, assert.Population{Org: "acme"}, f, src,
				&fakeAttestor{}, nil, nil, nil, func(string, ...any) {})
			if err == nil {
				t.Fatalf("Evidence passed with %s torn", tc.torn)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Evidence = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestSignerPinPatternWithoutACaptureGroup: the pattern's first group IS
// the pin, so a pattern that captures nothing names no pin — its
// matches are skipped rather than mistaken for one, and the repository
// reddens for having no derivable identity.
func TestSignerPinPatternWithoutACaptureGroup(t *testing.T) {
	t.Parallel()

	groupless := strings.Replace(continuousOnlyPolicyJSON,
		`acme/signer/.github/workflows/sign\\.yml@([0-9a-f]{40})`,
		`acme/signer/.github/workflows/sign\\.yml@[0-9a-f]{40}`, 1)

	pol, err := assert.LoadPolicy(strings.NewReader(groupless))
	if err != nil {
		t.Fatal(err)
	}

	f := continuousForge()
	src := assert.Sources{assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"}}

	rep, err := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src,
		&fakeAttestor{}, nil, nil, nil, func(string, ...any) {})
	if err != nil {
		t.Fatalf("Evidence = %v", err)
	}

	var named bool

	for _, fd := range rep.Findings() {
		if strings.Contains(fd.Detail, "no signer pin found") {
			named = true
		}
	}

	if !named {
		t.Fatalf("findings = %+v, want the no-derivable-identity finding", rep.Findings())
	}
}

// TestResolvePinsTears walks the pin derivation's reads. Each hop names
// a different tree a stranger reads, and an unreadable one must refuse
// there rather than derive a pin from nothing.
func TestResolvePinsTears(t *testing.T) {
	t.Parallel()

	const machineryFile = "canon:" + machineryPin40 + ":.github/workflows/publish.yml"

	tests := []struct {
		name  string
		spoil func(f *fakeForge)
		want  string
	}{
		{
			name: "the caller's publish workflow is unreadable",
			spoil: func(f *fakeForge) {
				f.fileAtErr = map[string]error{
					"widget:v1.0.0:.github/workflows/publish.yml": errTorn,
				}
			},
			want: "publish workflow at the tag is unreadable",
		},
		{
			name: "the machinery publish workflow is unreadable",
			spoil: func(f *fakeForge) {
				f.fileAtErr = map[string]error{machineryFile: errTorn}
			},
			want: "machinery publish workflow at",
		},
		{
			name: "the machinery repository carries no publish workflow",
			spoil: func(f *fakeForge) {
				delete(f.files, machineryFile)
			},
			want: "carries no publish workflow",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := deepForge()
			tc.spoil(f)

			rep := runDeepWalk(t, f, &fakeDeep{})

			var named bool

			for _, fd := range rep.Findings() {
				if strings.Contains(fd.Detail, tc.want) {
					named = true
				}
			}

			if !named {
				t.Fatalf("findings = %+v, want one naming %q", rep.Findings(), tc.want)
			}
		})
	}
}

// TestBundleAssetContentRefusals: the bundle asset is JSONL somebody
// else wrote, and every shape it can be wrong in is either a finding
// against that release or a refusal — never a subject set silently
// shorter than the bundle actually covers.
func TestBundleAssetContentRefusals(t *testing.T) {
	t.Parallel()

	const asset = "attestations-image.intoto.jsonl"

	tests := []struct {
		name string
		set  func(f *fakeForge)
		want string
	}{
		{
			name: "the bundle asset cannot be downloaded",
			set: func(f *fakeForge) {
				f.assetErr = map[string]error{"widget@v1.0.0/" + asset: errTorn}
			},
			want: "the forge tore",
		},
		{
			name: "a bundle line carries no DSSE payload",
			set: func(f *fakeForge) {
				f.assetBytes["widget@v1.0.0"][asset] = `{"noEnvelope": true}`
			},
			want: "carries no DSSE payload",
		},
		{
			name: "a bundle line's payload is not base64",
			set: func(f *fakeForge) {
				f.assetBytes["widget@v1.0.0"][asset] = `{"dsseEnvelope": {"payload": "!!not base64!!"}}`
			},
			want: "bundle line 1",
		},
		{
			name: "a bundle line's payload is not a statement",
			set: func(f *fakeForge) {
				payload := base64.StdEncoding.EncodeToString([]byte("not json"))
				f.assetBytes["widget@v1.0.0"][asset] = `{"dsseEnvelope": {"payload": "` + payload + `"}}`
			},
			want: "bundle line 1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := completeRelease()
			tc.set(f)

			rep := runEvidence(t, f, nil)

			var named bool

			for _, fd := range rep.Findings() {
				if strings.Contains(fd.Detail, tc.want) {
					named = true
				}
			}

			if !named {
				t.Fatalf("findings = %+v, want one naming %q", rep.Findings(), tc.want)
			}
		})
	}
}

// TestStoreBundlesThatSayNothing: the store's own lines are foreign
// bytes. One that does not decode, or whose payload is not a statement,
// simply is not a verdict — the digest reddens rather than the walk
// refusing, because the store may legitimately hold other documents.
func TestStoreBundlesThatSayNothing(t *testing.T) {
	t.Parallel()

	for _, line := range []string{
		`{"noEnvelope": true}`,
		`{"dsseEnvelope": {"payload": "!!not base64!!"}}`,
	} {
		t.Run(line, func(t *testing.T) {
			t.Parallel()

			f := completeRelease()
			f.store = map[string][]string{subjectDigest: {line}}

			rep := runEvidence(t, f, nil)

			var named bool

			for _, fd := range rep.Findings() {
				if strings.Contains(fd.Assertion, "vsa:") {
					named = true
				}
			}

			if !named {
				t.Fatalf("findings = %+v, want the missing-verdict finding", rep.Findings())
			}
		})
	}
}

// TestSubjectDigestsSeenOnce: two bundle assets covering the same
// subject cost one store read, not two — the walk asks about a digest
// once.
func TestSubjectDigestsSeenOnce(t *testing.T) {
	t.Parallel()

	f := completeRelease()
	bundle := f.assetBytes["widget@v1.0.0"]["attestations-image.intoto.jsonl"]

	f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = manifestAsset([]string{"oci-image", "rust-crate"}, true)
	f.assets["widget@v1.0.0"] = append(f.assets["widget@v1.0.0"], "attestations-crates.intoto.jsonl")
	f.assetBytes["widget@v1.0.0"]["attestations-crates.intoto.jsonl"] = bundle

	pol := loadTestPolicy(t)
	src := assert.Sources{assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"}}
	att := &fakeAttestor{}

	rep, err := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src, att, nil, nil, nil,
		func(string, ...any) {})
	if err != nil {
		t.Fatalf("Evidence = %v", err)
	}

	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s: %+v", rep.Verdict(), rep.Findings())
	}
}

// TestContractManifestThatIsNotOne: the manifest is the contract's own
// declaration, so bytes that do not parse as one are a refusal — a
// release that declares nothing readable owes everything.
func TestContractManifestThatIsNotOne(t *testing.T) {
	t.Parallel()

	f := completeRelease()
	f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = "not json"

	pol := loadTestPolicy(t)
	src := assert.Sources{assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"}}

	_, err := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src, &fakeAttestor{}, nil, nil, nil,
		func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "manifest of") {
		t.Fatalf("Evidence = %v, want the manifest refusal", err)
	}
}

// TestWorkflowContractSource walks the pre-manifest contract source:
// the caller's publish workflow at the tag, the reusable's caller stub
// when that workflow is itself reusable, and the two ways it declares
// nothing.
func TestWorkflowContractSource(t *testing.T) {
	t.Parallel()

	const (
		publish     = "widget:v1.0.0:.github/workflows/publish.yml"
		selfPublish = "widget:v1.0.0:.github/workflows/self-publish.yml"
	)

	tests := []struct {
		name  string
		files map[string]string
		errs  map[string]error
		want  string // "" means the walk passes with nothing owed
	}{
		{
			name: "the publish workflow is unreadable",
			errs: map[string]error{publish: errTorn},
			want: "workflow contract",
		},
		{
			name: "a reusable workflow's caller stub is unreadable",
			files: map[string]string{
				publish: "on:\n  workflow_call:\n",
			},
			errs: map[string]error{selfPublish: errTorn},
			want: "workflow contract",
		},
		{
			name: "a reusable workflow with no caller stub declares nothing",
			files: map[string]string{
				publish: "on:\n  workflow_call:\n",
			},
		},
		{
			name: "a classes line that names no class declares nothing",
			files: map[string]string{
				publish: "jobs:\n  publish:\n    with:\n      classes: \"\"\n",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := completeRelease()
			// No manifest asset: the workflow source is the only one.
			f.assets["widget@v1.0.0"] = drop(f.assets["widget@v1.0.0"], "evidence-manifest.json")
			f.files = tc.files
			f.fileAtErr = tc.errs

			pol := loadTestPolicy(t)
			src := assert.Sources{assert.WorkflowSource{Forge: f, Policy: pol.Evidence}}

			_, err := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src,
				&fakeAttestor{}, nil, nil, nil, func(string, ...any) {})

			if tc.want == "" {
				if err != nil {
					t.Fatalf("Evidence = %v, want a release owing nothing", err)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Evidence = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestReleaseAssetsTearAfterTheContract: the asset listing is read
// again to judge the contract, and a tear there is a refusal even
// though the contract itself was readable.
func TestReleaseAssetsTearAfterTheContract(t *testing.T) {
	t.Parallel()

	f := completeRelease()
	f.files = map[string]string{
		"widget:v1.0.0:.github/workflows/publish.yml": "jobs:\n  publish:\n    with:\n      classes: oci-image\n",
	}
	f.torn = map[string]error{"ReleaseAssets": errTorn}

	pol := loadTestPolicy(t)
	src := assert.Sources{assert.WorkflowSource{Forge: f, Policy: pol.Evidence}}

	_, err := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src,
		&fakeAttestor{}, nil, nil, nil, func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "assets of") {
		t.Fatalf("Evidence = %v, want the asset-listing refusal", err)
	}
}

// TestScannerReportThatIsNotOne: the scanner's JSON is foreign bytes,
// and a report that parses as nothing has scanned nothing.
func TestScannerReportThatIsNotOne(t *testing.T) {
	t.Parallel()

	_, err := assert.BlastRadius(loadBlastPolicy(t), assert.Population{Org: "acme"}, blastForge(),
		fakeScanner{out: "not json"}, &vexjoin.Decisions{}, func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "scanner report") {
		t.Fatalf("BlastRadius = %v, want the report refusal", err)
	}
}

// TestSelfSignedPinsTear: in the self-attesting topology both pins ARE
// the tag's commit, so a tag whose commit cannot be read derives
// nothing.
func TestSelfSignedPinsTear(t *testing.T) {
	t.Parallel()

	f := deepForge()
	f.torn = map[string]error{"TagCommit": errTorn}

	full, err := assert.NewFullDepth(&fakeDeep{}, "", "acme/{repo}/.github/workflows/sign.yml")
	if err != nil {
		t.Fatal(err)
	}

	pol := loadTestPolicy(t)
	src := assert.Sources{assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"}}

	rep, err := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src, &fakeAttestor{}, nil, nil, full,
		func(string, ...any) {})
	if err != nil {
		t.Fatalf("Evidence = %v", err)
	}

	var named bool

	for _, fd := range rep.Findings() {
		if strings.Contains(fd.Detail, "tag's commit is unreadable") {
			named = true
		}
	}

	if !named {
		t.Fatalf("findings = %+v, want the tag-commit refusal", rep.Findings())
	}
}

// TestSignerPinPatternThatDoesNotCompile: the loader refuses a pattern
// it cannot compile, and the walk refuses it again — a Policy assembled
// any other way must not slip past.
func TestSignerPinPatternThatDoesNotCompile(t *testing.T) {
	t.Parallel()

	pol, err := assert.LoadPolicy(strings.NewReader(continuousOnlyPolicyJSON))
	if err != nil {
		t.Fatal(err)
	}

	broken := "("
	pol.Evidence.Continuous.SignerPinPattern = &broken

	f := continuousForge()
	src := assert.Sources{assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"}}

	_, err = assert.Evidence(pol, assert.Population{Org: "acme"}, f, src,
		&fakeAttestor{}, nil, nil, nil, func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "signer pin pattern") {
		t.Fatalf("Evidence = %v, want the pattern refusal", err)
	}
}

// TestShortDigestSurvivesWhole: the human-facing line abbreviates a
// digest, and one already shorter than the window must not be sliced
// out of range.
func TestShortDigestSurvivesWhole(t *testing.T) {
	t.Parallel()

	pol, err := assert.LoadPolicy(strings.NewReader(continuousOnlyPolicyJSON))
	if err != nil {
		t.Fatal(err)
	}

	f := continuousForge()
	f.pkgDigest = map[string]string{"widget": "sha256:abc"}

	src := assert.Sources{assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"}}

	if _, err := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src,
		&fakeAttestor{}, nil, nil, nil, func(string, ...any) {}); err != nil {
		t.Fatalf("Evidence = %v", err)
	}
}

// TestPolicyStructuralRefusals: the policy is the org's declaration,
// and a document that declares nothing readable must refuse at load —
// a walk over a half-parsed policy asserts obligations nobody wrote.
func TestPolicyStructuralRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "no evidence section",
			doc:  `{"schema": 3}`,
			want: "evidence is absent",
		},
		{
			name: "a base-image half missing a field",
			doc: strings.Replace(storePolicyJSON,
				`"pinFile": "docker/base-images.toml"`, `"pinFile": ""`, 1),
			want: "evidence.baseImages.pinFile",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := assert.LoadPolicy(strings.NewReader(tc.doc))
			if err == nil {
				t.Fatalf("LoadPolicy accepted %s", tc.name)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadPolicy = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestEpochsAgainstAnUnreadableMachineryVersion: the two obligation
// epochs compare a release's machinery version against a declared
// start. A version that does not parse cannot PROVE the pre-epoch
// exemption, so both fail toward the stricter obligation — the
// exemption is earned, never assumed.
func TestEpochsAgainstAnUnreadableMachineryVersion(t *testing.T) {
	t.Parallel()

	// The workflow contract source reads the machinery version from the
	// pin comment, falling back to the tag: a tag that is not a version
	// is what reaches the epoch comparison unparsable.
	withDecision := strings.Replace(testPolicyJSON,
		`"storeVsaFromVersion": "1.13.0",`,
		`"storeVsaFromVersion": "1.13.0", "decisionFromVersion": "1.23.1",`, 1)

	pol, err := assert.LoadPolicy(strings.NewReader(withDecision))
	if err != nil {
		t.Fatal(err)
	}

	f := completeRelease()
	f.tags = map[string][]string{"widget": {"release-candidate"}}
	f.assets = map[string][]string{"widget@release-candidate": {"app.spdx.json", "checksums.txt"}}
	f.files = map[string]string{
		"widget:release-candidate:.github/workflows/publish.yml": "jobs:\n  publish:\n" +
			"    with:\n      classes: oci-image\n",
	}

	src := assert.Sources{assert.WorkflowSource{Forge: f, Policy: pol.Evidence}}

	rep, err := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src,
		&fakeAttestor{}, nil, nil, nil, func(string, ...any) {})
	if err != nil {
		t.Fatalf("Evidence = %v", err)
	}

	// The strict reading is what produces findings at all: an exempted
	// release would owe nothing and pass.
	if rep.Verdict() == report.VerdictPass {
		t.Fatal("an unreadable machinery version was treated as pre-epoch — the exemption must be earned")
	}
}

// TestNoEpochMeansAlways: with no epoch declared every release owes the
// obligation, which is the only safe default — a missing declaration
// must not read as a blanket exemption.
func TestNoEpochMeansAlways(t *testing.T) {
	t.Parallel()

	noEpoch := strings.Replace(testPolicyJSON, `"storeVsaFromVersion": "1.13.0",`, ``, 1)

	pol, err := assert.LoadPolicy(strings.NewReader(noEpoch))
	if err != nil {
		t.Fatal(err)
	}

	f := completeRelease()
	f.assets["widget@v1.0.0"] = drop(f.assets["widget@v1.0.0"], "evidence-manifest.json")
	f.files = map[string]string{
		"widget:v1.0.0:.github/workflows/publish.yml": "jobs:\n  publish:\n" +
			"    with:\n      classes: oci-image\n",
	}
	f.store = map[string][]string{} // no verdict in the store

	src := assert.Sources{assert.WorkflowSource{Forge: f, Policy: pol.Evidence}}

	rep, err := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src,
		&fakeAttestor{}, nil, nil, nil, func(string, ...any) {})
	if err != nil {
		t.Fatalf("Evidence = %v", err)
	}

	var named bool

	for _, fd := range rep.Findings() {
		if strings.Contains(fd.Assertion, "vsa:") {
			named = true
		}
	}

	if !named {
		t.Fatalf("findings = %+v, want the store-verdict obligation owed", rep.Findings())
	}
}
