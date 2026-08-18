// The evidence walk's table: every completeness defect class, every
// exception category with its asymmetry (debt excuses what it names,
// burned excuses only vsa findings and only on failed-run tags), the
// population guards, and the walk-dies-loudly rows.

package assert_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/report"
)

const testPolicyJSON = `{
  "schema": 1,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "storeVsaFromVersion": "1.13.0",
    "evidenceSuffixes": [".openvex.json"],
    "debtFile": "security/attestation-debt.txt",
    "classes": {
      "rust-crate": {
        "bundles": ["attestations-crates.intoto.jsonl"],
        "legacyVsaBundles": ["attestations-vsa-crates.intoto.jsonl"]
      },
      "oci-image": {"bundles": ["attestations-image.intoto.jsonl"]},
      "pgrx-extension": {
        "bundles": ["attestations-extensions.intoto.jsonl"],
        "assetPrefixes": ["attestations-extimg-pg"]
      }
    }
  }
}`

const subjectDigest = "5555555555555555555555555555555555555555555555555555555555555555"

func loadTestPolicy(t *testing.T) *assert.Policy {
	t.Helper()

	p, err := assert.LoadPolicy(strings.NewReader(testPolicyJSON))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	return p
}

// bundleJSONL renders one Sigstore-bundle line whose statement names
// subjectDigest, with the given predicate type.
func bundleJSONL(predicateType string) string {
	stmt := `{"_type": "https://in-toto.io/Statement/v1",` +
		`"subject": [{"name": "app", "digest": {"sha256": "` + subjectDigest + `"}}],` +
		`"predicateType": "` + predicateType + `", "predicate": {}}`

	return `{"dsseEnvelope": {"payload": "` + base64.StdEncoding.EncodeToString([]byte(stmt)) + `"}}`
}

func manifestAsset(classes []string, storeVSA bool) string {
	sv := "false"
	if storeVSA {
		sv = "true"
	}

	return `{"schema": 1, "classes": ["` + strings.Join(classes, `", "`) + `"], "storeVsa": ` + sv + `}`
}

// fakeForge scripts the whole forge for one org.
type fakeForge struct {
	tagCommits map[string]string
	repos      []string
	reposErr   error
	tags       map[string][]string
	assets     map[string][]string          // key repo@tag
	assetBytes map[string]map[string]string // repo@tag → name → content
	store      map[string][]string          // digest → bundle JSON lines
	failedRuns map[string][]string          // repo@tag → failed workflow names
	files      map[string]string            // repo:ref:path → content
	pkgDigest  map[string]string            // repo → digest under the rolling tag
	workflows  map[string][][]byte          // repo → workflow file contents
	// torn fails one named read. The 2026-08-17 forge outage entered
	// the engine as exactly this, and a walk that swallowed it would
	// report clean over releases nobody looked at.
	torn map[string]error
	// fileAtErr fails ONE file read, keyed repo:ref:path — the pin
	// derivation reads several in sequence, and which one tears
	// decides which refusal a caller sees.
	fileAtErr map[string]error
	// assetErr fails ONE asset download, keyed repo@tag/name: a
	// contract manifest and a bundle asset are separate reads, and
	// only one of them being unreadable is a different verdict.
	assetErr map[string]error
}

func (f *fakeForge) Repos(string) ([]string, error) {
	if f.reposErr != nil {
		return nil, f.reposErr
	}

	return f.repos, f.tear("Repos")
}

func (f *fakeForge) ReleaseTags(_, repo string) ([]string, error) {
	return f.tags[repo], f.tear("ReleaseTags")
}

func (f *fakeForge) ReleaseAssets(_, repo, tag string) ([]string, error) {
	return f.assets[repo+"@"+tag], f.tear("ReleaseAssets")
}

func (f *fakeForge) Asset(_, repo, tag, name string) ([]byte, error) {
	if err := f.tear("Asset"); err != nil {
		return nil, err
	}

	if err := f.assetErr[repo+"@"+tag+"/"+name]; err != nil {
		return nil, err
	}

	content, ok := f.assetBytes[repo+"@"+tag][name]
	if !ok {
		return nil, errors.New("no such asset")
	}

	return []byte(content), nil
}

func (f *fakeForge) TagCommit(_, _, tag string) (string, error) {
	if err := f.tear("TagCommit"); err != nil {
		return "", err
	}

	if f.tagCommits == nil {
		return "", errors.New("no tag commit scripted for " + tag)
	}

	return f.tagCommits[tag], nil
}

//nolint:gocritic // unnamedResult: the Forge interface documents the results
func (f *fakeForge) FileAt(_, repo, path, ref string) ([]byte, bool, error) {
	if err := f.tear("FileAt"); err != nil {
		return nil, false, err
	}

	if err := f.fileAtErr[repo+":"+ref+":"+path]; err != nil {
		return nil, false, err
	}

	content, ok := f.files[repo+":"+ref+":"+path]

	return []byte(content), ok, nil
}

func (f *fakeForge) Attestations(_, _, digest string) ([]jsonx.Raw, error) {
	if err := f.tear("Attestations"); err != nil {
		return nil, err
	}

	var out []jsonx.Raw
	for _, b := range f.store[digest] {
		out = append(out, jsonx.Raw(b))
	}

	return out, nil
}

func (f *fakeForge) PackageVersionDigest(_, pkg, _ string) (string, error) {
	return f.pkgDigest[pkg], f.tear("PackageVersionDigest")
}

func (f *fakeForge) WorkflowContents(_, repo string) ([][]byte, error) {
	return f.workflows[repo], f.tear("WorkflowContents")
}

func (f *fakeForge) FailedRuns(_, repo, branch string) ([]string, error) {
	return f.failedRuns[repo+"@"+branch], f.tear("FailedRuns")
}

// tear reports the scripted failure for one named read, if any.
func (f *fakeForge) tear(read string) error { return f.torn[read] }

const vsaType = "https://slsa.dev/verification_summary/v1"

// completeRelease scripts one fully conformant release of repo widget
// at v1.0.0: manifest contract, sbom, checksums, image bundle whose
// subject carries a store VSA.
func completeRelease() *fakeForge {
	bundle := bundleJSONL("https://example.com/provenance/v1")

	return &fakeForge{
		repos: []string{"widget"},
		tags:  map[string][]string{"widget": {"v1.0.0"}},
		assets: map[string][]string{
			"widget@v1.0.0": {
				"evidence-manifest.json", "app.spdx.json", "checksums.txt",
				"attestations-image.intoto.jsonl",
			},
		},
		assetBytes: map[string]map[string]string{
			"widget@v1.0.0": {
				"evidence-manifest.json":          manifestAsset([]string{"oci-image"}, true),
				"attestations-image.intoto.jsonl": bundle,
			},
		},
		store: map[string][]string{subjectDigest: {bundleJSONL(vsaType)}},
	}
}

// fakeAttestor scripts the store verification seam: verifies unless
// the digest is listed as refusing.
type fakeAttestor struct {
	refuse     map[string]error
	seen       []string
	candidates []assert.Candidate
}

func (a *fakeAttestor) Verify(_, _, digest string, candidates []assert.Candidate, _ string) error {
	a.seen = append(a.seen, digest)
	a.candidates = append(a.candidates, candidates...)

	return a.refuse[digest]
}

func runEvidence(t *testing.T, f *fakeForge, debt []report.Exception) *report.Report {
	t.Helper()

	pol := loadTestPolicy(t)
	src := assert.Sources{
		assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"},
		assert.WorkflowSource{Forge: f, Policy: pol.Evidence},
	}

	rep, err := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src, &fakeAttestor{}, debt, nil, nil,
		func(string, ...any) {})
	if err != nil {
		t.Fatalf("Evidence: %v", err)
	}

	return rep
}

func TestEvidenceCompleteReleasePasses(t *testing.T) {
	t.Parallel()

	rep := runEvidence(t, completeRelease(), nil)
	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
	}
}

func TestEvidenceDefects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mutate    func(*fakeForge)
		assertion string
	}{
		{
			"a missing SBOM asset reddens",
			func(f *fakeForge) {
				f.assets["widget@v1.0.0"] = drop(f.assets["widget@v1.0.0"], "app.spdx.json")
			},
			"sbom",
		},
		{
			"a missing checksum manifest reddens",
			func(f *fakeForge) {
				f.assets["widget@v1.0.0"] = drop(f.assets["widget@v1.0.0"], "checksums.txt")
			},
			"checksums.txt",
		},
		{
			"a missing class bundle reddens",
			func(f *fakeForge) {
				f.assets["widget@v1.0.0"] = drop(f.assets["widget@v1.0.0"], "attestations-image.intoto.jsonl")
			},
			"attestations-image.intoto.jsonl",
		},
		{
			"a contract class the policy does not define reddens",
			func(f *fakeForge) {
				f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = manifestAsset([]string{"mystery"}, true)
			},
			"class:mystery",
		},
		{
			"a covered subject with no store VSA reddens",
			func(f *fakeForge) { f.store = nil },
			"vsa:" + subjectDigest[:12],
		},
		{
			"a store bundle that is not a VSA does not satisfy the verdict",
			func(f *fakeForge) {
				f.store = map[string][]string{subjectDigest: {bundleJSONL("https://example.com/other/v1")}}
			},
			"vsa:" + subjectDigest[:12],
		},
		{
			"an unreadable bundle asset reddens rather than skipping",
			func(f *fakeForge) {
				f.assetBytes["widget@v1.0.0"]["attestations-image.intoto.jsonl"] = "not json"
			},
			"attestations-image.intoto.jsonl:unreadable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := completeRelease()
			tt.mutate(f)

			rep := runEvidence(t, f, nil)
			if rep.Verdict() != report.VerdictFail {
				t.Fatalf("verdict = %s, want FAIL\nfindings: %+v", rep.Verdict(), rep.Findings())
			}

			for _, fd := range rep.Findings() {
				if fd.Assertion == tt.assertion {
					return
				}
			}

			t.Fatalf("no finding with assertion %q: %+v", tt.assertion, rep.Findings())
		})
	}
}

func drop(items []string, name string) []string {
	var out []string

	for _, s := range items {
		if s != name {
			out = append(out, s)
		}
	}

	return out
}

func TestEvidenceDebtExcusesExactly(t *testing.T) {
	t.Parallel()

	f := completeRelease()
	f.assets["widget@v1.0.0"] = drop(f.assets["widget@v1.0.0"], "app.spdx.json")

	debt, err := assert.ParseDebt([]byte("widget@v1.0.0(sbom)\n"), "debt.txt")
	if err != nil {
		t.Fatalf("debt: %v", err)
	}

	if rep := runEvidence(t, f, debt); rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS via debt\nfindings: %+v", rep.Verdict(), rep.Findings())
	}

	// The same debt against a DIFFERENT defect excuses nothing.
	f2 := completeRelease()
	f2.assets["widget@v1.0.0"] = drop(f2.assets["widget@v1.0.0"], "checksums.txt")

	if rep := runEvidence(t, f2, debt); rep.Verdict() != report.VerdictFail {
		t.Fatalf("verdict = %s, want FAIL — debt for sbom must not excuse checksums", rep.Verdict())
	}
}

func TestEvidenceBurnedIsNarrow(t *testing.T) {
	t.Parallel()

	// A missing verdict on a tag whose run history shows failure is
	// burned: derived, excused.
	f := completeRelease()
	f.store = nil
	f.failedRuns = map[string][]string{"widget@v1.0.0": {"publish"}}

	if rep := runEvidence(t, f, nil); rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS via the burned derivation\nfindings: %+v", rep.Verdict(), rep.Findings())
	}

	// The same failed run must NOT excuse a missing SBOM — burned
	// covers vsa findings alone.
	f2 := completeRelease()
	f2.assets["widget@v1.0.0"] = drop(f2.assets["widget@v1.0.0"], "app.spdx.json")
	f2.failedRuns = map[string][]string{"widget@v1.0.0": {"publish"}}

	if rep := runEvidence(t, f2, nil); rep.Verdict() != report.VerdictFail {
		t.Fatalf("verdict = %s, want FAIL — burned must not excuse a missing SBOM", rep.Verdict())
	}

	// An UNRELATED failed workflow must not burn anything once the
	// policy names the publishing workflows — otherwise one flaky run
	// mutes a genuinely missing verdict.
	f4 := completeRelease()
	f4.store = nil
	f4.failedRuns = map[string][]string{"widget@v1.0.0": {"scorecard"}}

	pol := loadTestPolicy(t)
	pol.Evidence.PublishWorkflows = []string{"publish", "self-publish"}
	src4 := assert.Sources{assert.ManifestSource{Forge: f4, Asset: "evidence-manifest.json"}}

	rep4, err := assert.Evidence(pol, assert.Population{Org: "acme"}, f4, src4, &fakeAttestor{}, nil, nil, nil,
		func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}

	if rep4.Verdict() != report.VerdictFail {
		t.Fatalf("verdict = %s, want FAIL — a flaky unrelated workflow must not burn a release", rep4.Verdict())
	}

	// The named publishing workflow still burns.
	f5 := completeRelease()
	f5.store = nil
	f5.failedRuns = map[string][]string{"widget@v1.0.0": {"scorecard", "publish"}}
	src5 := assert.Sources{assert.ManifestSource{Forge: f5, Asset: "evidence-manifest.json"}}

	rep5, err := assert.Evidence(pol, assert.Population{Org: "acme"}, f5, src5, &fakeAttestor{}, nil, nil, nil,
		func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}

	if rep5.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS — the named publish failure burns", rep5.Verdict())
	}

	// And a missing verdict on a CLEAN tag stays red.
	f3 := completeRelease()
	f3.store = nil

	if rep := runEvidence(t, f3, nil); rep.Verdict() != report.VerdictFail {
		t.Fatalf("verdict = %s, want FAIL — a clean publish with no verdict is a regression", rep.Verdict())
	}
}

func TestEvidenceLegacyAndPopulation(t *testing.T) {
	t.Parallel()

	// A release no source speaks for is legacy: recorded, not failed —
	// but an org of ONLY legacy releases has judged nothing.
	f := &fakeForge{
		repos:  []string{"widget"},
		tags:   map[string][]string{"widget": {"v0.0.1"}},
		assets: map[string][]string{"widget@v0.0.1": {"whatever.tar.gz"}},
	}

	rep := runEvidence(t, f, nil)
	if rep.Verdict() != report.VerdictCannotJudge {
		t.Fatalf("verdict = %s, want CANNOT_JUDGE for an all-legacy walk", rep.Verdict())
	}

	// One conforming release beside the legacy one judges fine.
	f2 := completeRelease()
	f2.tags["widget"] = append(f2.tags["widget"], "v0.0.1")
	f2.assets["widget@v0.0.1"] = []string{"whatever.tar.gz"}

	if rep := runEvidence(t, f2, nil); rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS with the legacy release recorded", rep.Verdict())
	}
}

func TestEvidenceUmbrellaBundle(t *testing.T) {
	t.Parallel()

	f := completeRelease()
	f.assets["widget@v1.0.0"] = []string{
		"evidence-manifest.json", "app.spdx.json", "checksums.txt", "attestations.intoto.jsonl",
	}
	image := f.assetBytes["widget@v1.0.0"]["attestations-image.intoto.jsonl"]
	f.assetBytes["widget@v1.0.0"]["attestations.intoto.jsonl"] = image

	if rep := runEvidence(t, f, nil); rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS via the umbrella name\nfindings: %+v", rep.Verdict(), rep.Findings())
	}
}

func TestEvidenceLegacyVSABundlesPreEpoch(t *testing.T) {
	t.Parallel()

	f := completeRelease()
	f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = manifestAsset([]string{"rust-crate"}, false)
	f.assets["widget@v1.0.0"] = []string{
		"evidence-manifest.json", "app.spdx.json", "checksums.txt",
		"attestations-crates.intoto.jsonl",
	}

	rep := runEvidence(t, f, nil)
	if rep.Verdict() != report.VerdictFail {
		t.Fatalf("verdict = %s, want FAIL — pre-epoch releases owe their VSA bundle as an asset", rep.Verdict())
	}
}

// TestEvidenceSingleRepoPopulation proves the single-repository
// population (#79): the same walk over exactly one owner/name, no org
// listing consulted, the report subject the repo itself.
func TestEvidenceSingleRepoPopulation(t *testing.T) {
	t.Parallel()

	f := completeRelease()
	f.reposErr = errors.New("the listing must not be consulted for a single-repo population")

	pol := loadTestPolicy(t)
	src := assert.Sources{
		assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"},
		assert.WorkflowSource{Forge: f, Policy: pol.Evidence},
	}

	rep, err := assert.Evidence(pol, assert.Population{Repo: "acme/widget"}, f, src,
		&fakeAttestor{}, nil, nil, nil, func(string, ...any) {})
	if err != nil {
		t.Fatalf("Evidence: %v", err)
	}

	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
	}
}

// TestEvidenceSingleRepoRefusals: the guard branches the single-repo
// population adds — a declared org population cannot apply, and a
// population that is not owner/name cannot resolve.
func TestEvidenceSingleRepoRefusals(t *testing.T) {
	t.Parallel()

	pol := loadTestPolicy(t)
	f := completeRelease()
	src := assert.Sources{assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"}}
	silent := func(string, ...any) {}

	expected := 1
	pol.Evidence.ExpectedRepos = &expected

	_, err := assert.Evidence(pol, assert.Population{Repo: "acme/widget"}, f, src, &fakeAttestor{}, nil, nil, nil, silent)
	if err == nil || !strings.Contains(err.Error(), "expectedRepos") {
		t.Fatalf("error = %v, want the expectedRepos-over-one-repo refusal", err)
	}

	pol.Evidence.ExpectedRepos = nil

	for _, bad := range []string{"solo", "/name", "owner/"} {
		if _, err := assert.Evidence(pol, assert.Population{Repo: bad}, f, src,
			&fakeAttestor{}, nil, nil, nil, silent); err == nil ||
			!strings.Contains(err.Error(), "owner/name") {
			t.Fatalf("population %q: error = %v, want the owner/name refusal", bad, err)
		}
	}
}

func TestEvidenceRefusals(t *testing.T) {
	t.Parallel()

	pol := loadTestPolicy(t)
	expected := 2
	pol.Evidence.ExpectedRepos = &expected

	f := completeRelease() // one repo, expectation says two

	src := assert.Sources{assert.ManifestSource{Forge: f, Asset: "evidence-manifest.json"}}

	_, err := assert.Evidence(pol, assert.Population{Org: "acme"}, f, src, &fakeAttestor{}, nil, nil, nil,
		func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "declared population") {
		t.Fatalf("error = %v, want the population guard", err)
	}

	broken := &fakeForge{reposErr: errors.New("listing torn")}

	_, err = assert.Evidence(
		loadTestPolicy(t), assert.Population{Org: "acme"}, broken, src, &fakeAttestor{}, nil, nil, nil,
		func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "listing torn") {
		t.Fatalf("error = %v, want the listing failure", err)
	}
}

// TestEvidencePrefixAssets pins the assetPrefixes obligation both
// ways: present passes, absent reddens by the prefix's own name.
func TestEvidencePrefixAssets(t *testing.T) {
	t.Parallel()

	f := completeRelease()
	f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = manifestAsset([]string{"pgrx-extension"}, true)
	f.assets["widget@v1.0.0"] = []string{
		"evidence-manifest.json", "app.spdx.json", "checksums.txt",
		"attestations-extensions.intoto.jsonl", "attestations-extimg-pg16.intoto.jsonl",
	}
	image := f.assetBytes["widget@v1.0.0"]["attestations-image.intoto.jsonl"]
	f.assetBytes["widget@v1.0.0"]["attestations-extensions.intoto.jsonl"] = image

	if rep := runEvidence(t, f, nil); rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS\nfindings: %+v", rep.Verdict(), rep.Findings())
	}

	f.assets["widget@v1.0.0"] = drop(f.assets["widget@v1.0.0"], "attestations-extimg-pg16.intoto.jsonl")

	rep := runEvidence(t, f, nil)
	if rep.Verdict() != report.VerdictFail {
		t.Fatalf("verdict = %s, want FAIL for the missing prefix asset", rep.Verdict())
	}
}
