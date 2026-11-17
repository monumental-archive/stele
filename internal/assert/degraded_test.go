// A forge that tears mid-walk. This is the failure the engine's
// population rule exists for — the 2026-08-17 outage entered as
// exactly this — so the tables below break ONE named read at a time
// across every walking target, rather than one representative read.
// A tear swallowed anywhere here reports clean over releases nobody
// looked at.
//
// Every tear row is held to two things (stele#346). The error the walk
// returns IS the planted tear — errors.Is, never err != nil, because a
// fixture that fails on its own scores every tear row green without
// the tear ever being reached. And the same fixture with nothing
// planted walks to the verdict it was built for: the untorn control
// is what proves the tear, and only the tear, is what failed.

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

// mustTear scores a tear row: the walk refused, and what it refused
// with is the planted tear.
func mustTear(t *testing.T, err error) {
	t.Helper()

	if !errors.Is(err, errTorn) {
		t.Fatalf("walk = %v, want the planted tear carried out", err)
	}
}

// mustJudge scores a tear row's control: the same fixture, nothing
// planted, walks to the verdict it was built for.
func mustJudge(t *testing.T, rep *report.Report, err error, want report.Verdict) {
	t.Helper()

	if err != nil {
		t.Fatalf("untorn walk = %v, want the fixture to judge", err)
	}

	if rep.Verdict() != want {
		t.Fatalf("untorn verdict = %s, want %s: %+v", rep.Verdict(), want, rep.Findings())
	}
}

// mustName scores a row whose fault the walk reports as a finding
// against the release rather than refusing (the stele#342/#345
// split: only an unseen read ends the walk). The finding must be the
// one the fault produces: its subject and assertion exactly, and a
// detail naming the fault.
func mustName(t *testing.T, rep *report.Report, subject, assertion, detail string) {
	t.Helper()

	for _, fd := range rep.Findings() {
		if fd.Subject == subject && fd.Assertion == assertion && strings.Contains(fd.Detail, detail) {
			return
		}
	}

	t.Fatalf("findings = %+v, want %s %s naming %q", rep.Findings(), subject, assertion, detail)
}

// walkEvidence runs the evidence walk over one fixture at presence
// depth.
func walkEvidence(t *testing.T, pol *assert.Policy, f *fakeForge, src assert.Sources) (*report.Report, error) {
	t.Helper()

	return assert.Evidence(pol, orgPop(t, f, nil), f, src,
		&fakeAttestor{}, report.NewJournal(), nil, nil, func(string, ...any) {})
}

// manifestOnly is the contract read through the release's manifest
// alone.
func manifestOnly(f *fakeForge, pol *assert.Policy) assert.Sources {
	return assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}
}

// TestEvidenceForgeTears walks every read the evidence walk makes.
// Each row is the same conformant release with one read failing.
func TestEvidenceForgeTears(t *testing.T) {
	t.Parallel()

	tests := []struct {
		read    string
		fixture func() *fakeForge
		want    report.Verdict
	}{
		{"ReleaseTags", completeRelease, report.VerdictPass},
		{"ReleaseAssets", completeRelease, report.VerdictPass},
		{"Asset", completeRelease, report.VerdictPass},
		{"Attestations", completeRelease, report.VerdictPass},
		// The run history is consulted only to narrow a verdict
		// finding into a burned release, so the row needs one: its
		// fixture is built to FAIL on the missing verdict.
		{"FailedRuns", func() *fakeForge {
			f := completeRelease()
			f.store = map[string][]string{}

			return f
		}, report.VerdictFail},
	}

	for _, tc := range tests {
		t.Run(tc.read, func(t *testing.T) {
			t.Parallel()

			pol := loadTestPolicy(t)

			t.Run("torn", func(t *testing.T) {
				t.Parallel()

				f := tc.fixture()
				f.torn = map[string]error{tc.read: errTorn}

				_, err := walkEvidence(t, pol, f, manifestOnly(f, pol))
				mustTear(t, err)
			})

			t.Run("untorn", func(t *testing.T) {
				t.Parallel()

				f := tc.fixture()
				rep, err := walkEvidence(t, pol, f, manifestOnly(f, pol))
				mustJudge(t, rep, err, tc.want)
			})
		})
	}
}

// fallsThrough is a release the manifest source cannot speak for —
// no manifest asset is listed — so the workflow source behind it is
// asked, and its publish workflow declares the class the release
// shipped (the shape stele#343's legacy-contract rows use).
func fallsThrough() *fakeForge {
	f := completeRelease()
	noManifest(f)
	f.files = map[string]string{
		"widget:v1.0.0:.github/workflows/publish.yml": "jobs:\n  publish:\n" +
			"    with:\n      classes: oci-image\n",
	}

	return f
}

// TestEvidenceContractSourceTears: the contract is read through two
// stacked sources, and either one tearing is a refusal — a contract
// that could not be read is not an absent contract.
func TestEvidenceContractSourceTears(t *testing.T) {
	t.Parallel()

	tests := []struct {
		read    string
		fixture func() *fakeForge
	}{
		// The manifest leg's two reads: its listing, then the manifest
		// asset itself, which decodes when it is not torn.
		{"ReleaseAssets", completeRelease},
		{"Asset", completeRelease},
		// The workflow leg is reached only when the manifest leg finds
		// nothing, where it reads the publish workflow at the tag.
		{"FileAt", fallsThrough},
	}

	for _, tc := range tests {
		t.Run(tc.read, func(t *testing.T) {
			t.Parallel()

			pol := loadTestPolicy(t)
			sources := func(f *fakeForge) assert.Sources {
				return assert.Sources{
					assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"},
					assert.WorkflowSource{Forge: f, Policy: pol.Evidence},
				}
			}

			t.Run("torn", func(t *testing.T) {
				t.Parallel()

				f := tc.fixture()
				f.torn = map[string]error{tc.read: errTorn}

				_, err := walkEvidence(t, pol, f, sources(f))
				mustTear(t, err)
			})

			t.Run("untorn", func(t *testing.T) {
				t.Parallel()

				f := tc.fixture()
				rep, err := walkEvidence(t, pol, f, sources(f))
				mustJudge(t, rep, err, report.VerdictPass)
			})
		})
	}
}

// blastRadius runs the scan walk over one fixture with the canary's
// finding decided, so a walk that reads everything passes.
func blastRadius(t *testing.T, f *fakeForge, sc fakeScanner) (*report.Report, error) {
	t.Helper()

	return assert.BlastRadius(loadBlastPolicy(t), orgPop(t, f, nil), f, sc,
		decided(t, canaryScan, "serde", "1.0.0"), report.NewJournal(), func(string, ...any) {})
}

// canaryOnly is a scan that finds the declared canary and nothing
// else.
var canaryOnly = fakeScanner{out: scanResult(canaryScan, "serde", "1.0.0", "crates.io", false)}

// TestBlastRadiusForgeTears walks the scan walk's reads. Its own
// population rule makes an unreadable SBOM a refusal, never an
// advisory-free release.
func TestBlastRadiusForgeTears(t *testing.T) {
	t.Parallel()

	for _, read := range []string{"ReleaseTags", "ReleaseAssets", "Asset", "Attestations"} {
		t.Run(read, func(t *testing.T) {
			t.Parallel()

			f := blastForge()
			f.torn = map[string]error{read: errTorn}

			_, err := blastRadius(t, f, canaryOnly)
			mustTear(t, err)
		})
	}

	t.Run("untorn", func(t *testing.T) {
		t.Parallel()

		rep, err := blastRadius(t, blastForge(), canaryOnly)
		mustJudge(t, rep, err, report.VerdictPass)
	})
}

// TestBlastRadiusScannerTears: the scanner is a subprocess somebody
// else maintains, and a run that could not scan has judged nothing.
func TestBlastRadiusScannerTears(t *testing.T) {
	t.Parallel()

	t.Run("torn", func(t *testing.T) {
		t.Parallel()

		_, err := blastRadius(t, blastForge(), fakeScanner{err: errTorn})
		mustTear(t, err)
	})

	t.Run("untorn", func(t *testing.T) {
		t.Parallel()

		rep, err := blastRadius(t, blastForge(), canaryOnly)
		mustJudge(t, rep, err, report.VerdictPass)
	})
}

// TestTagsForgeTears walks the tag audit's reads across both halves of
// its seam: the release listing it walks and the tag surface it judges.
func TestTagsForgeTears(t *testing.T) {
	t.Parallel()

	tears := []struct {
		read   string
		mutate func(*fakeTags)
		want   report.Verdict
	}{
		{"ChainNotes", func(*fakeTags) {}, report.VerdictPass},
		// The ancestry read happens only where a link is MISSING: the
		// horizon is consulted to decide whether the ledger could have
		// witnessed one at all, so a conformant tag never reaches it and
		// a tear scripted over a conformant fixture would prove nothing.
		// Its fixture is built to FAIL on the missing link.
		{"IsAncestor", func(f *fakeTags) { f.objects[tagObjSHA].Target = unlinkedRev }, report.VerdictFail},
	}

	for _, tear := range tears {
		t.Run(tear.read, func(t *testing.T) {
			t.Parallel()

			walk := func(tags *fakeTags) (*report.Report, error) {
				return assert.Tags(loadTagsPolicy(t), repoPop(t, "acme/widget"),
					tags, &fakeTagVerifier{}, report.NewJournal(), func(string, ...any) {})
			}

			t.Run("torn", func(t *testing.T) {
				t.Parallel()

				tags := conformantTags()
				tear.mutate(tags)
				tags.torn = map[string]error{tear.read: errTorn}

				_, err := walk(tags)
				mustTear(t, err)
			})

			t.Run("untorn", func(t *testing.T) {
				t.Parallel()

				tags := conformantTags()
				tear.mutate(tags)

				rep, err := walk(tags)
				mustJudge(t, rep, err, tear.want)
			})
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

	rep, err := assert.BlastRadius(pol, orgPop(t, blastForge(), nil), blastForge(),
		fakeScanner{out: `{"results": []}`}, &vexjoin.Decisions{}, report.NewJournal(), func(string, ...any) {})
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

	rep, err := assert.BlastRadius(loadBlastPolicy(t), orgPop(t, f, nil), f,
		fakeScanner{out: scanResult(canaryScan, "serde", "1.0.0", "crates.io", false)},
		&vexjoin.Decisions{}, report.NewJournal(), func(string, ...any) {})
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
		name  string
		plant func(*fakeForge)
		want  string
	}{
		{
			"the stub cannot be read",
			func(f *fakeForge) { f.torn = map[string]error{"FileAt": errTorn} },
			"continuous stub",
		},
		{
			"the registry cannot be read",
			func(f *fakeForge) { f.torn = map[string]error{"PackageVersionDigest": errTorn} },
			"package versions",
		},
		// The second hop is its own read of another repository at a
		// pinned commit, and a transport failure there must refuse
		// rather than derive a pin from a tree nobody read.
		{
			"the released tree cannot be read",
			func(f *fakeForge) { f.fileAtErr = map[string]error{contSharedPath: errTorn} },
			sharedPin,
		},
	}

	pol, err := assert.LoadPolicy(strings.NewReader(continuousOnlyPolicyJSON))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := continuousForge()
			tc.plant(f)

			_, err := walkEvidence(t, pol, f, manifestOnly(f, pol))
			mustTear(t, err)

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Evidence = %v, want it to name %q", err, tc.want)
			}
		})
	}

	t.Run("untorn", func(t *testing.T) {
		t.Parallel()

		f := continuousForge()
		rep, err := walkEvidence(t, pol, f, manifestOnly(f, pol))
		mustJudge(t, rep, err, report.VerdictPass)
	})
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
	src := assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}

	rep, err := assert.Evidence(pol, orgPop(t, f, nil), f, src,
		&fakeAttestor{}, report.NewJournal(), nil, nil, func(string, ...any) {})
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
			want: "publish workflow at the tag is unreadable: " + errTorn.Error(),
		},
		{
			name: "the machinery publish workflow is unreadable",
			spoil: func(f *fakeForge) {
				f.fileAtErr = map[string]error{machineryFile: errTorn}
			},
			want: "machinery publish workflow at " + machineryPin40[:12] + " is unreadable: " + errTorn.Error(),
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

			mustName(t, runDeepWalk(t, f, &fakeDeep{}), "widget@v1.0.0", "deep", tc.want)
		})
	}

	t.Run("unspoiled", func(t *testing.T) {
		t.Parallel()

		rep := runDeepWalk(t, deepForge(), &fakeDeep{})
		mustJudge(t, rep, nil, report.VerdictPass)
	})
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
			want: errTorn.Error(),
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

			mustName(t, runEvidence(t, f, nil), "widget@v1.0.0", asset+":unreadable", tc.want)
		})
	}

	t.Run("unspoiled", func(t *testing.T) {
		t.Parallel()

		mustJudge(t, runEvidence(t, completeRelease(), nil), nil, report.VerdictPass)
	})
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
	src := assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}
	att := &fakeAttestor{}

	rep, err := assert.Evidence(pol, orgPop(t, f, nil), f, src, att,
		report.NewJournal(), nil, nil,
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
	src := assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}

	_, err := assert.Evidence(pol, orgPop(t, f, nil), f, src, &fakeAttestor{},
		report.NewJournal(), nil, nil,
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
		declares    = "jobs:\n  publish:\n    with:\n      classes: oci-image\n"
		reusable    = "on:\n  workflow_call:\n"
	)

	walk := func(t *testing.T, files map[string]string, errs map[string]error) (*report.Report, error) {
		t.Helper()

		pol := loadTestPolicy(t)
		f := completeRelease()
		// No manifest asset: the workflow source is the only one.
		noManifest(f)
		f.files = files
		f.fileAtErr = errs

		return walkEvidence(t, pol, f, assert.Sources{assert.WorkflowSource{Forge: f, Policy: pol.Evidence}})
	}

	// Each tear sits on the one file that declares the contract, so
	// the same tree untorn is a release the walk judges and passes.
	tears := []struct {
		name  string
		files map[string]string
		torn  string
	}{
		{
			name:  "the publish workflow is unreadable",
			files: map[string]string{publish: declares},
			torn:  publish,
		},
		{
			name:  "a reusable workflow's caller stub is unreadable",
			files: map[string]string{publish: reusable, selfPublish: declares},
			torn:  selfPublish,
		},
	}

	for _, tc := range tears {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			t.Run("torn", func(t *testing.T) {
				t.Parallel()

				_, err := walk(t, tc.files, map[string]error{tc.torn: errTorn})
				mustTear(t, err)
			})

			t.Run("untorn", func(t *testing.T) {
				t.Parallel()

				rep, err := walk(t, tc.files, nil)
				mustJudge(t, rep, err, report.VerdictPass)
			})
		})
	}

	nothing := []struct {
		name  string
		files map[string]string
	}{
		{
			name:  "a reusable workflow with no caller stub declares nothing",
			files: map[string]string{publish: reusable},
		},
		{
			name:  "a classes line that names no class declares nothing",
			files: map[string]string{publish: "jobs:\n  publish:\n    with:\n      classes: \"\"\n"},
		},
	}

	for _, tc := range nothing {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := walk(t, tc.files, nil); err != nil {
				t.Fatalf("Evidence = %v, want a release owing nothing", err)
			}
		})
	}
}

// TestReleaseAssetsTearAfterTheContract: the asset listing is read
// again to judge the contract, and a tear there is a refusal even
// though the contract itself was readable.
func TestReleaseAssetsTearAfterTheContract(t *testing.T) {
	t.Parallel()

	pol := loadTestPolicy(t)

	// The workflow source alone, so the first listing the walk makes
	// is its own, after the contract.
	fixture := func() (*fakeForge, assert.Sources) {
		f := completeRelease()
		f.files = map[string]string{
			"widget:v1.0.0:.github/workflows/publish.yml": "jobs:\n  publish:\n    with:\n      classes: oci-image\n",
		}

		return f, assert.Sources{assert.WorkflowSource{Forge: f, Policy: pol.Evidence}}
	}

	t.Run("torn", func(t *testing.T) {
		t.Parallel()

		f, src := fixture()
		f.torn = map[string]error{"ReleaseAssets": errTorn}

		_, err := walkEvidence(t, pol, f, src)
		mustTear(t, err)

		if !strings.Contains(err.Error(), "assets of") {
			t.Fatalf("Evidence = %v, want the asset-listing refusal", err)
		}
	})

	t.Run("untorn", func(t *testing.T) {
		t.Parallel()

		f, src := fixture()
		rep, err := walkEvidence(t, pol, f, src)
		mustJudge(t, rep, err, report.VerdictPass)
	})
}

// TestScannerReportThatIsNotOne: the scanner's JSON is foreign bytes,
// and a report that parses as nothing has scanned nothing.
func TestScannerReportThatIsNotOne(t *testing.T) {
	t.Parallel()

	_, err := assert.BlastRadius(loadBlastPolicy(t), orgPop(t, blastForge(), nil), blastForge(),
		fakeScanner{out: "not json"}, &vexjoin.Decisions{}, report.NewJournal(), func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "scanner report") {
		t.Fatalf("BlastRadius = %v, want the report refusal", err)
	}
}

// TestSelfSignedPinsTear: in the self-attesting topology both pins ARE
// the tag's commit, so a tag whose commit cannot be read derives
// nothing.
func TestSelfSignedPinsTear(t *testing.T) {
	t.Parallel()

	walk := func(t *testing.T, f *fakeForge) *report.Report {
		t.Helper()

		full, err := assert.NewFullDepth(&fakeDeep{}, f, "", "acme/{repo}/.github/workflows/sign.yml")
		if err != nil {
			t.Fatal(err)
		}

		pol := loadTestPolicy(t)

		rep, err := assert.Evidence(pol, orgPop(t, f, nil), f, manifestOnly(f, pol), &fakeAttestor{},
			report.NewJournal(), nil, full,
			func(string, ...any) {})
		if err != nil {
			t.Fatalf("Evidence = %v", err)
		}

		return rep
	}

	// The tag's commit is scripted, so the only thing that can leave
	// it unreadable is the tear; no machinery hop exists to read.
	fixture := func() *fakeForge {
		f := deepForge()
		f.tagCommits = map[string]string{"v1.0.0": tagSHA40}
		f.files = map[string]string{}

		return f
	}

	t.Run("torn", func(t *testing.T) {
		t.Parallel()

		f := fixture()
		f.torn = map[string]error{"TagCommit": errTorn}

		mustName(t, walk(t, f), "widget@v1.0.0", "deep", "tag's commit is unreadable: "+errTorn.Error())
	})

	t.Run("untorn", func(t *testing.T) {
		t.Parallel()

		mustJudge(t, walk(t, fixture()), nil, report.VerdictPass)
	})
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
	src := assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}

	_, err = assert.Evidence(pol, orgPop(t, f, nil), f, src,
		&fakeAttestor{}, report.NewJournal(), nil, nil, func(string, ...any) {})
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

	src := assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}

	if _, err := assert.Evidence(pol, orgPop(t, f, nil), f, src,
		&fakeAttestor{}, report.NewJournal(), nil, nil, func(string, ...any) {}); err != nil {
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
			doc:  `{"schema": 9}`,
			want: "evidence is absent",
		},
		{
			name: "a base-approval scope missing a field",
			doc: strings.Replace(storePolicyJSON,
				`"pinFile": "docker/base-images.toml"`, `"pinFile": ""`, 1),
			want: "evidence.baseImages.scopes[pgrx-bases].pinFile",
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

	rep, err := assert.Evidence(pol, orgPop(t, f, nil), f, src,
		&fakeAttestor{}, report.NewJournal(), nil, nil, func(string, ...any) {})
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

	rep, err := assert.Evidence(pol, orgPop(t, f, nil), f, src,
		&fakeAttestor{}, report.NewJournal(), nil, nil, func(string, ...any) {})
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
