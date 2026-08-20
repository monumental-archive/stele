// The evidence walk's table: every completeness defect class, every
// exception category with its asymmetry (debt excuses what it names,
// burned excuses only vsa findings and only on failed-run tags), the
// population guards, and the walk-dies-loudly rows.

package assert_test

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/evidence"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/population"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/workflow"
)

const testPolicyJSON = `{
  "schema": 6,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "storeVsaFromVersion": "1.13.0",
    "evidenceSuffixes": [".openvex.json"],
    "classes": {
      "rust-crate": {
        "bundles": ["attestations-crates.intoto.jsonl"],
        "legacyVsaBundles": ["attestations-vsa-crates.intoto.jsonl"]
      },
      "oci-image": {"bundles": ["attestations-image.intoto.jsonl"]},
      "pgrx-extension": {
        "bundles": ["attestations-extensions.intoto.jsonl"],
        "assetPrefixes": [{"prefix": "attestations-extimg-pg"}]
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

// manifestEntry renders one typed entry — the fixtures carry the
// typing the format requires (stele#156), so a manifest a test builds
// is one the writer could have written: an artifact names the class
// that built it and the target that produced it, a document names
// neither. Both are passed rather than defaulted, because a fixture
// at an OLDER schema must carry neither, and a helper that stamped
// them anyway would build documents that lie about their own format.
func manifestEntry(name, entryType, class, target string) string {
	return manifestEntryPinned(name, entryType, class, target, strings.Repeat("a", 64))
}

// manifestEntryPinned is manifestEntry with the pinned bytes chosen —
// the fixture control the checksum cross-check needs (stele#219),
// where a name's digest in this document either matches the checksum
// manifest's or is the disagreement under test.
func manifestEntryPinned(name, entryType, class, target, digest string) string {
	entry := `{"name": "` + name + `", "sha256": "` + digest + `", "type": "` + entryType + `"`
	if class != "" {
		entry += `, "class": "` + class + `"`
	}

	if target != "" {
		entry += `, "target": "` + target + `"`
	}

	return entry + `}`
}

// manifestAsset renders the fixture release's manifest. It attributes
// the artifact the checksum manifest pins, because a release's two
// documents describe one release: an evidence manifest naming an
// artifact the checksums do not is the disagreement the attribution
// finding exists to report (stele#206), not the fixture's baseline.
// It pins the same bytes for it too, for the same reason: a healthy
// release's two documents agree by digest (stele#219).
func manifestAsset(classes []string, storeVSA bool) string {
	sv := "false"
	if storeVSA {
		sv = "true"
	}

	return `{"schema": ` + strconv.Itoa(evidence.Schema) + `, "classes": ["` + strings.Join(classes, `", "`) +
		`"], "storeVsa": ` + sv + `, "machineryVersion": "9.9.9", "entries": [` +
		manifestEntryPinned("widget-v1.0.0.tar.gz", "build-subject", classes[0], "linux-amd64",
			subjectDigest) + `]}`
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
	workflows  map[string][]workflow.File   // repo → workflow files
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

func (f *fakeForge) ListRepos(string) ([]gh.Repo, error) {
	if f.reposErr != nil {
		return nil, f.reposErr
	}

	out := make([]gh.Repo, 0, len(f.repos))
	for _, name := range f.repos {
		out = append(out, gh.Repo{Name: name})
	}

	return out, f.tear("ListRepos")
}

// testOrg is the organisation every fixture in this package sits
// under; the population's own tests cover the name varying.
const testOrg = "acme"

// orgPop resolves an organisation the way the binary does — through
// the one component allowed to enumerate one — so a test walks the
// population the CLI would hand it, never one assembled beside it.
func orgPop(t *testing.T, lister gh.RepoLister, d *population.Declaration) *population.Set {
	t.Helper()

	set, err := population.Scope{Org: testOrg}.Resolve(lister, d)
	if err != nil {
		t.Fatalf("resolving the %s population: %v", testOrg, err)
	}

	return set
}

// repoPop is the single-repository population (stele#79).
func repoPop(t *testing.T, repo string) *population.Set {
	t.Helper()

	set, err := population.Scope{Repo: repo}.Resolve(nil, nil)
	if err != nil {
		t.Fatalf("resolving the %s population: %v", repo, err)
	}

	return set
}

func (f *fakeForge) ReleaseTags(_, repo string) ([]string, error) {
	return f.tags[repo], f.tear("ReleaseTags")
}

func (f *fakeForge) ReleaseDate(_, _, _ string) (time.Time, error) {
	return time.Time{}, errors.New("this fixture serves no release date")
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

func (f *fakeForge) Workflows(_, repo string) ([]workflow.File, error) {
	return f.workflows[repo], f.tear("Workflows")
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

	return runEvidenceWith(t, f, debt, testPolicyJSON)
}

func runEvidenceWith(t *testing.T, f *fakeForge, debt []report.Exception, policyJSON string) *report.Report {
	t.Helper()
	t.Helper()

	pol, err := assert.LoadPolicy(strings.NewReader(policyJSON))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	src := assert.Sources{
		assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"},
		assert.WorkflowSource{Forge: f, Policy: pol.Evidence},
	}

	rep, err := assert.Evidence(pol, orgPop(t, f, nil), f, src, &fakeAttestor{},
		report.NewJournal(debt...), nil, nil, func(string, ...any) {})
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

	debt, err := report.ParseDebt([]byte("widget@v1.0.0(sbom)\n"), "debt.txt")
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
	src4 := assert.Sources{assert.ManifestSource{Forge: f4, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}

	rep4, err := assert.Evidence(pol, orgPop(t, f4, nil), f4, src4, &fakeAttestor{},
		report.NewJournal(), nil, nil,
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
	src5 := assert.Sources{assert.ManifestSource{Forge: f5, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}

	rep5, err := assert.Evidence(pol, orgPop(t, f5, nil), f5, src5, &fakeAttestor{},
		report.NewJournal(), nil, nil,
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
		assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"},
		assert.WorkflowSource{Forge: f, Policy: pol.Evidence},
	}

	rep, err := assert.Evidence(pol, repoPop(t, "acme/widget"), f, src,
		&fakeAttestor{}, report.NewJournal(), nil, nil, func(string, ...any) {})
	if err != nil {
		t.Fatalf("Evidence: %v", err)
	}

	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
	}
}

// TestEvidenceOutsideItsTrack: a repository the policy declares
// outside the build track is not walked here, and naming ONE such
// repository is a contradiction the walk reports rather than answers
// with an empty pass. The population's own guards live in
// internal/population; this pins that the evidence walk asks it.
func TestEvidenceOutsideItsTrack(t *testing.T) {
	t.Parallel()

	pol := loadTestPolicy(t)
	f := completeRelease()
	src := assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}
	silent := func(string, ...any) {}

	sourceOnly := &population.Declaration{Repositories: []population.Entry{
		{Repo: new("widget"), Tracks: &[]string{"source"}, Reason: new("publishes no releases")},
	}}

	// Over the organisation and over the one repository alike: what
	// owes nothing on this track has nothing for this walk to judge,
	// and the walk says which track rather than sealing a verdict.
	set, serr := population.Scope{Repo: "acme/widget"}.Resolve(nil, sourceOnly)
	if serr != nil {
		t.Fatalf("resolving the single-repository population: %v", serr)
	}

	for name, pop := range map[string]*population.Set{
		"organisation": orgPop(t, f, sourceOnly),
		"repository":   set,
	} {
		_, err := assert.Evidence(pol, pop, f, src, &fakeAttestor{}, report.NewJournal(), nil, nil, silent)
		if err == nil || !strings.Contains(err.Error(), "outside the build track") {
			t.Fatalf("%s scope: error = %v, want the track contradiction", name, err)
		}
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

// TestEvidencePrefixEpoch pins the per-obligation epoch (stele#128):
// a class asset the machinery only began publishing at some release
// is owed from that release inclusive, and history before it stays
// green — the same measured-at-cutover shape as enrichmentFromVersion.
// The fixture manifest declares machinery version 9.9.9.
func TestEvidencePrefixEpoch(t *testing.T) {
	t.Parallel()

	// The release ships everything EXCEPT the prefix asset.
	fixture := func() *fakeForge {
		f := completeRelease()
		f.assetBytes["widget@v1.0.0"]["evidence-manifest.json"] = manifestAsset([]string{"pgrx-extension"}, true)
		f.assets["widget@v1.0.0"] = []string{
			"evidence-manifest.json", "app.spdx.json", "checksums.txt",
			"attestations-extensions.intoto.jsonl",
		}
		image := f.assetBytes["widget@v1.0.0"]["attestations-image.intoto.jsonl"]
		f.assetBytes["widget@v1.0.0"]["attestations-extensions.intoto.jsonl"] = image

		return f
	}

	withEpoch := func(epoch string) string {
		return strings.Replace(testPolicyJSON,
			`"assetPrefixes": [{"prefix": "attestations-extimg-pg"}]`,
			`"assetPrefixes": [{"prefix": "attestations-extimg-pg", "owedFrom": "`+epoch+`"}]`, 1)
	}

	t.Run("a release before the epoch does not owe the asset", func(t *testing.T) {
		t.Parallel()

		rep := runEvidenceWith(t, fixture(), nil, withEpoch("10.0.0"))
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, want PASS for pre-epoch history\nfindings: %+v", rep.Verdict(), rep.Findings())
		}
	})

	t.Run("the epoch itself owes (inclusive)", func(t *testing.T) {
		t.Parallel()

		rep := runEvidenceWith(t, fixture(), nil, withEpoch("9.9.9"))
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s, want FAIL from the epoch inclusive", rep.Verdict())
		}
	})

	t.Run("absent owedFrom is always owed", func(t *testing.T) {
		t.Parallel()

		rep := runEvidenceWith(t, fixture(), nil, testPolicyJSON)
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s, want FAIL with no epoch declared", rep.Verdict())
		}
	})
}
