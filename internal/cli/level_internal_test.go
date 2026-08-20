package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/pkgtime"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

// levelForge is a scripted release: a digest manifest found by
// content, an inventory beside each artifact, and nothing else.
type levelForge struct {
	storeForge

	repos    []string
	tags     []string
	assets   []string
	files    map[string][]byte
	released time.Time
	err      error
}

func (f *levelForge) ListRepos(string) ([]gh.Repo, error) {
	out := make([]gh.Repo, 0, len(f.repos))
	for _, name := range f.repos {
		out = append(out, gh.Repo{Name: name})
	}

	return out, f.err
}

func (f *levelForge) ReleaseTags(_, _ string) ([]string, error) { return f.tags, f.err }

func (f *levelForge) ReleaseAssets(_, _, _ string) ([]string, error) { return f.assets, f.err }

func (f *levelForge) ReleaseDate(_, _, _ string) (time.Time, error) {
	if f.released.IsZero() {
		return time.Time{}, errNoReleaseDate
	}

	return f.released, nil
}

func (f *levelForge) Asset(_, _, _, name string) ([]byte, error) {
	if got, ok := f.files[name]; ok {
		return got, nil
	}

	return nil, errors.New("no such asset")
}

func (f *levelForge) Attestations(_, _, _ string) ([]jsonx.Raw, error) { return nil, nil }

// scriptedPkgTime answers publication times without a network.
type scriptedPkgTime struct {
	when map[string]time.Time
}

func (s scriptedPkgTime) Published(purl string) (time.Time, bool, error) {
	got, ok := s.when[purl]

	return got, ok, nil
}

// scriptedScanner reports one finding against the inventory's package.
type scriptedScanner struct{}

func (scriptedScanner) Scan([]byte) ([]byte, error) {
	return []byte(`{"results":[{"packages":[{` +
		`"package":{"name":"example.com/dep","version":"v1.0.0"},` +
		`"vulnerabilities":[{"id":"GHSA-xxxx"}]}]}]}`), nil
}

// scriptedVerifier stands in for the cryptographic boundary: it proves
// nothing, so a subject reads as carrying no provenance. That is the
// right shape for these tests, which are about which assets become
// subjects at all.
type scriptedVerifier struct{ verify.BundleVerifier }

func (scriptedVerifier) MeasureBlob([]byte, string) (*trust.Verified, error) {
	return nil, errScriptedVerifier
}

func (scriptedVerifier) MeasureAttestation([]byte, string) (*trust.Verified, error) {
	return nil, errScriptedVerifier
}

var errScriptedVerifier = errors.New("this fixture proves nothing")

// swapLevelSeams points the verb at a scripted world, including the
// trust material, so no test reaches the network.
func swapLevelSeams(t *testing.T, f gh.Forge, times map[string]time.Time) {
	t.Helper()

	origForge, origClock, origTime := newForge, clock, newPkgTime
	origScan, origRoot, origVerifier := newScanner, resolveTrustedRoot, newBundleVerifier

	newForge = func() gh.Forge { return f }
	clock = func() time.Time { return time.Unix(0, 0).UTC() }
	newPkgTime = func() pkgtime.Resolver { return scriptedPkgTime{when: times} }
	newScanner = func() osv.Scanner { return scriptedScanner{} }
	resolveTrustedRoot = func(trust.RootPlan) ([]byte, error) { return []byte("{}"), nil }
	newBundleVerifier = func([]byte) (verify.BundleVerifier, error) { return scriptedVerifier{}, nil }

	t.Cleanup(func() {
		newForge, clock, newPkgTime = origForge, origClock, origTime
		newScanner, resolveTrustedRoot, newBundleVerifier = origScan, origRoot, origVerifier
	})
}

// TestLevelUsage covers the dispatch guards: a verb that cannot tell
// which track or which subject it was asked about must say so rather
// than measure something.
func TestLevelUsage(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want int
	}{
		{name: "no track", args: []string{"level"}, want: exitUsage},
		{name: "unknown track", args: []string{"level", "provenance"}, want: exitUsage},
		{name: "no subject", args: []string{"level", "source"}, want: exitUsage},
		{name: "malformed repo", args: []string{"level", "source", "--repo", "widget"}, want: exitUsage},
		{
			name: "two populations",
			args: []string{"level", "source", "--repo", "acme/widget", "--org", "acme"},
			want: exitUsage,
		},
		{name: "unknown flag", args: []string{"level", "source", "--policy", "p.json"}, want: exitUsage},
	} {
		var stdout, stderr bytes.Buffer

		if got := Run(tt.args, &stdout, &stderr); got != tt.want {
			t.Errorf("%s: Run = %d, want %d\nstderr: %s", tt.name, got, tt.want, stderr.String())
		}
	}
}

// TestLevelDependencyFromAScriptedRelease drives the whole verb: it
// finds the digest manifest BY CONTENT, matches inventories to
// artifacts, resolves publication times, and seals a report — with no
// policy, no clone and no trusted root anywhere in the invocation.
func TestLevelDependencyFromAScriptedRelease(t *testing.T) {
	const (
		artifact = "widget_linux_amd64"
		digest   = "1111111111111111111111111111111111111111111111111111111111111111"
		purl     = "pkg:golang/example.com/dep@v1.0.0?repository_url=https://github.com/acme/mirror"
	)

	released := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	swapLevelSeams(t, &levelForge{
		tags: []string{"v0.9.0", "v1.0.0"},
		assets: []string{
			"README.md", "checksums.txt", artifact + ".spdx.json", "decisions.openvex.json",
		},
		released: released,
		files: map[string][]byte{
			// Not a manifest: the search must reject it on content.
			"README.md":     []byte("# widget\n"),
			"checksums.txt": []byte(digest + "  " + artifact + "\n"),
			artifact + ".spdx.json": []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"externalRefs":[` +
				`{"referenceLocator":"` + purl + `"}],` +
				`"downloadLocation":"https://mirror.example/acme/widget/dep"}]}`),
			"decisions.openvex.json": []byte(`{"@context":"https://openvex.dev/ns/v0.2.0",` +
				`"timestamp":"2026-01-01T00:00:00Z",` +
				`"statements":[{"vulnerability":{"name":"GHSA-xxxx"},` +
				`"products":[{"@id":"` + purl + `"}],` +
				`"status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}]}`),
		},
	}, map[string]time.Time{
		// Published a month before the release: a real quarantine floor.
		purl: released.AddDate(0, -1, 0),
	})

	var stdout, stderr bytes.Buffer

	code := Run([]string{"level", "dependency", "--repo", "acme/widget", "--json"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d — level three is established, and blindness above a floor is not a refusal\n"+
			"stdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	doc := stdout.String()

	// Levels one to three established from the release's own published
	// artifacts: an inventory, a scan of it, a decision for the finding,
	// a producer-controlled source. Level four is UNDETERMINED on
	// purpose: a positive quarantine floor is indistinguishable from a
	// slow release cadence, so the scalar is three and the boundary
	// above it is honestly blind rather than confidently either way.
	for _, want := range []string{
		`"level","value":"SLSA_DEPENDENCY_LEVEL_3"`,
		`"specStatus","value":"draft"`,
		"UNDETERMINED: no dependency shipped sooner than",
		"HELD: all 1 advisory finding(s) carry a published triage decision",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the report does not carry %s:\n%s", want, doc)
		}
	}

	// The newest release by semver, never whichever the listing
	// happened to return first.
	if !strings.Contains(stderr.String(), "v1.0.0") {
		t.Errorf("stderr does not name the release measured:\n%s", stderr.String())
	}
}

// TestLevelWithNoReleaseCannotJudge: a repository that has published
// nothing supports no claim, and the verb says so rather than
// answering zero.
func TestLevelWithNoReleaseCannotJudge(t *testing.T) {
	swapLevelSeams(t, &levelForge{}, nil)

	var stdout, stderr bytes.Buffer

	if got := Run([]string{"level", "build", "--repo", "acme/widget"}, &stdout, &stderr); got != exitBlind {
		t.Errorf("Run = %d, want %d (could-not-judge)\nstderr: %s", got, exitBlind, stderr.String())
	}
}

// TestLevelOrgFoldsThePopulation: --org measures the forge's own
// listing, which is evidence, and folds to the weakest member.
func TestLevelOrgFoldsThePopulation(t *testing.T) {
	swapLevelSeams(t, &levelForge{repos: []string{"widget", "gadget"}}, nil)

	var stdout, stderr bytes.Buffer

	code := Run([]string{"level", "build", "--org", "acme", "--json"}, &stdout, &stderr)
	if code != exitBlind {
		t.Fatalf("Run = %d, want could-not-judge\nstderr: %s", code, stderr.String())
	}

	if !strings.Contains(stdout.String(), "2 repositories") {
		t.Errorf("the report does not name the population:\n%s", stdout.String())
	}
}

// TestLevelOrgDeclaredPopulation: --policy decides WHO IS ASKED, per
// repository and per track. A repository declared outside a track is
// absent from that board — not measured, not counted, not a grey cell
// — while the track it does bear evidence on still names it.
func TestLevelOrgDeclaredPopulation(t *testing.T) {
	swapLevelSeams(t, &levelForge{repos: []string{"widget", "signer"}}, nil)

	dir := t.TempDir()
	path := filepath.Join(dir, "assert-policy.json")
	policy := `{
	  "schema": 6,
	  "population": {"repositories": [
	    {"repo": "widget"},
	    {"repo": "signer", "tracks": ["source"], "reason": "publishes no releases"}
	  ]},
	  "evidence": {
	    "sbomSuffix": ".spdx.json", "checksums": "checksums.txt",
	    "umbrellaBundle": "attestations.intoto.jsonl", "manifestAsset": "evidence-manifest.json",
	    "storeVsaFromVersion": "1.0.0",
	    "classes": {"go-binary": {"bundles": ["attestations-go-binaries.intoto.jsonl"]}}
	  }
	}`

	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatalf("writing the policy: %v", err)
	}

	for _, tc := range []struct {
		track string
		want  string
	}{
		{"build", "1 repositories"},
		{"source", "2 repositories"},
	} {
		t.Run(tc.track, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			Run([]string{"level", tc.track, "--org", "acme", "--policy", path, "--json"}, &stdout, &stderr)

			if !strings.Contains(stdout.String(), tc.want) {
				t.Errorf("the %s board does not carry %q:\n%s", tc.track, tc.want, stdout.String())
			}
		})
	}
}

// TestLevelPolicyRefusals: the declaration's guard branches at the
// command surface — a population over the one repository a caller
// named could only veto the question, and a policy that will not load
// is a refusal, never a walk over whatever arrived.
func TestLevelPolicyRefusals(t *testing.T) {
	swapLevelSeams(t, &levelForge{repos: []string{"widget"}}, nil)

	for _, tc := range []struct {
		name string
		args []string
		want int
		doc  string
	}{
		{
			name: "a declared population cannot apply to one repository",
			args: []string{"level", "build", "--repo", "acme/widget", "--policy", "any.json"},
			want: exitUsage,
		},
		{
			name: "a policy that is not there is not a population",
			args: []string{"level", "build", "--org", "acme", "--policy", "absent.json"},
			want: exitBlind,
			// The cause rides IN the document: a board consumer must be
			// able to tell "nobody could look" from "nobody is here".
			doc: "absent.json",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if got := Run(append(tc.args, "--json"), &stdout, &stderr); got != tc.want {
				t.Errorf("Run = %d, want %d\nstderr: %s", got, tc.want, stderr.String())
			}

			if tc.doc != "" && !strings.Contains(stdout.String(), tc.doc) {
				t.Errorf("the report does not carry the cause %q:\n%s", tc.doc, stdout.String())
			}
		})
	}
}

// TestLevelShieldWritesBesideTheReport: the endpoint document comes
// from the same seal, so no copy of the level can drift from another.
func TestLevelShieldWritesBesideTheReport(t *testing.T) {
	swapLevelSeams(t, &levelForge{}, nil)

	path := filepath.Join(t.TempDir(), "shield.json")

	var stdout, stderr bytes.Buffer

	Run([]string{"level", "source", "--repo", "acme/widget", "--shield", path}, &stdout, &stderr)

	got, err := os.ReadFile(path) //nolint:gosec // the path is this test's own temp dir
	if err != nil {
		t.Fatalf("the shield was not written: %v", err)
	}

	for _, want := range []string{`"schemaVersion":1`, `"label":"SLSA Source"`} {
		if !strings.Contains(string(got), want) {
			t.Errorf("the shield does not carry %s: %s", want, got)
		}
	}
}

// TestLevelShieldRefusesAnUnwritablePath: a verb that cannot write
// what it was asked for must not report success.
func TestLevelShieldRefusesAnUnwritablePath(t *testing.T) {
	swapLevelSeams(t, &levelForge{}, nil)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"level", "source", "--repo", "acme/widget",
		"--shield", filepath.Join(t.TempDir(), "no-such-dir", "shield.json"),
	}, &stdout, &stderr)

	if code != exitIO {
		t.Errorf("Run = %d, want %d — an unwritable shield is an output failure", code, exitIO)
	}
}

// TestLevelDependencyDegradedReads: each fetch the dependency track
// makes can fail on its own, and each failure must leave its
// requirement unevaluated rather than failing the run or, worse,
// passing it.
func TestLevelDependencyDegradedReads(t *testing.T) {
	for _, tt := range []struct {
		name  string
		forge *levelForge
		want  string
		code  int
	}{
		{
			name:  "the release listing is unreadable",
			forge: &levelForge{err: errors.New("the forge is down")},
			want:  "releases unreadable",
			code:  exitBlind,
		},
		{
			name: "no asset lists artifact digests",
			forge: &levelForge{
				tags: []string{"v1.0.0"}, assets: []string{"README.md"},
				files: map[string][]byte{"README.md": []byte("# widget")},
			},
			want: "no asset lists artifact digests",
			code: exitBlind,
		},
		{
			name: "the release carries no publication date",
			forge: &levelForge{
				tags: []string{"v1.0.0"}, assets: []string{"checksums.txt"},
				files: map[string][]byte{
					"checksums.txt": []byte(strings.Repeat("a", 64) + "  widget\n"),
				},
			},
			// An artifact with no inventory beside it is a confident
			// level zero, not a blindness: the tool looked, and a
			// measured zero is an answer.
			want: "publication date unreadable",
			code: exitOK,
		},
	} {
		swapLevelSeams(t, tt.forge, nil)

		var stdout, stderr bytes.Buffer

		if code := Run([]string{"level", "dependency", "--repo", "acme/widget"}, &stdout, &stderr); code != tt.code {
			t.Errorf("%s: Run = %d, want %d", tt.name, code, tt.code)
		}

		if !strings.Contains(stdout.String()+stderr.String(), tt.want) {
			t.Errorf("%s: output does not name the failed read %q:\n%s%s",
				tt.name, tt.want, stdout.String(), stderr.String())
		}
	}
}

// TestLevelSourceWithoutAChain: a repository whose branch carries no
// notes is Source Level 0, and the verb says which requirement settled
// it rather than reporting a bare number.
func TestLevelSourceWithoutAChain(t *testing.T) {
	swapLevelSeams(t, &levelForge{}, nil)

	var stdout, stderr bytes.Buffer

	Run([]string{"level", "source", "--repo", "acme/widget", "--json"}, &stdout, &stderr)

	if !strings.Contains(stdout.String(), "SLSA_SOURCE_SCS_REPO_ID") {
		t.Errorf("the report does not name the requirements it judged:\n%s", stdout.String())
	}
}

// TestEvidenceDocumentsAreNotBuildSubjects: a release ships evidence
// beside its artifacts, and a bundle cannot carry provenance about
// itself. Judged from the bytes — measured against a real release,
// the attestation bundle listed in the digest manifest read as an
// artifact shipped unattested and refuted the whole build track.
func TestEvidenceDocumentsAreNotBuildSubjects(t *testing.T) {
	const digest = "1111111111111111111111111111111111111111111111111111111111111111"

	for _, tt := range []struct {
		name    string
		content string
		subject bool
	}{
		{name: "an attestation bundle", content: `{"dsseEnvelope":{"payload":"e30="}}`},
		{name: "an inventory", content: `{"spdxVersion":"SPDX-2.3","packages":[]}`},
		{name: "a cyclonedx inventory", content: `{"bomFormat":"CycloneDX"}`},
		{name: "a triage decision", content: `{"@context":"https://openvex.dev/ns/v0.2.0"}`},
		{name: "a digest manifest", content: digest + "  widget\n"},
		{name: "an actual artifact", content: "\x7fELF binary bytes", subject: true},
	} {
		swapLevelSeams(t, &levelForge{
			tags:   []string{"v1.0.0"},
			assets: []string{"checksums.txt", "thing"},
			files: map[string][]byte{
				"checksums.txt": []byte(digest + "  thing\n"),
				"thing":         []byte(tt.content),
			},
		}, nil)

		var stdout, stderr bytes.Buffer

		Run([]string{"level", "build", "--repo", "acme/widget", "--json"}, &stdout, &stderr)

		// A subject with no provenance refutes; an evidence document
		// leaves the population empty, which cannot be judged.
		refuted := strings.Contains(stdout.String(), "carry no provenance identifying them")
		if refuted != tt.subject {
			t.Errorf("%s: judged as a build subject = %v, want %v\n%s",
				tt.name, refuted, tt.subject, stdout.String())
		}
	}
}

// TestTheReleasesOwnModuleIsNotADependency: an inventory names the
// artifact's own module beside what it depends on, and its publication
// time IS the release's — counting it would put every quarantine floor
// at zero and refute a producer that quarantines properly.
func TestTheReleasesOwnModuleIsNotADependency(t *testing.T) {
	const (
		digest = "2222222222222222222222222222222222222222222222222222222222222222"
		own    = "pkg:golang/github.com/acme/widget@v1.0.0"
		dep    = "pkg:golang/example.com/dep@v1.0.0"
	)

	released := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	swapLevelSeams(t, &levelForge{
		tags:     []string{"v1.0.0"},
		assets:   []string{"checksums.txt", "widget.spdx.json"},
		released: released,
		files: map[string][]byte{
			"checksums.txt": []byte(digest + "  widget\n"),
			"widget.spdx.json": []byte(`{"spdxVersion":"SPDX-2.3","packages":[` +
				`{"externalRefs":[{"referenceLocator":"` + own + `"}]},` +
				`{"externalRefs":[{"referenceLocator":"` + dep + `"}]}]}`),
		},
	}, map[string]time.Time{
		own: released,                   // published with the release
		dep: released.AddDate(0, -1, 0), // a real dependency, quarantined
	})

	var stdout, stderr bytes.Buffer

	Run([]string{"level", "dependency", "--repo", "acme/widget", "--json"}, &stdout, &stderr)

	// The own module's zero interval must not appear: were it counted,
	// the rung would read CONTRADICTED ("taken at or before its
	// publication time") instead of the honest positive-floor report.
	if !strings.Contains(stdout.String(), "UNDETERMINED: no dependency shipped sooner than") {
		t.Errorf("the release's own module was counted as a dependency:\n%s", stdout.String())
	}
}

// TestUnionInventoryCoversEveryArtifact: the draft asks a producer to
// inventory the dependencies of every version they RELEASE, so one
// complete document covers each of that release's artifacts.
func TestUnionInventoryCoversEveryArtifact(t *testing.T) {
	const (
		one = "3333333333333333333333333333333333333333333333333333333333333333"
		two = "4444444444444444444444444444444444444444444444444444444444444444"
	)

	swapLevelSeams(t, &levelForge{
		tags:     []string{"v1.0.0"},
		assets:   []string{"checksums.txt", "widget.spdx.json"},
		released: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		files: map[string][]byte{
			"checksums.txt": []byte(one + "  widget_linux\n" + two + "  widget_darwin\n"),
			"widget.spdx.json": []byte(`{"spdxVersion":"SPDX-2.3","packages":[` +
				`{"externalRefs":[{"referenceLocator":"pkg:golang/example.com/dep@v1.0.0"}]}]}`),
		},
	}, nil)

	var stdout, stderr bytes.Buffer

	Run([]string{"level", "dependency", "--repo", "acme/widget", "--json"}, &stdout, &stderr)

	if !strings.Contains(stdout.String(), "a published inventory covers all 2 released artifact(s)") {
		t.Errorf("one union inventory did not cover the release's artifacts:\n%s", stdout.String())
	}
}

// TestSplitWorkflowURI: the certificate names the workflow that held
// the signing capability, and the boundary check has to find it.
func TestSplitWorkflowURI(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		uri               string
		owner, repo, path string
		ok                bool
	}{
		{
			uri:   "https://github.com/acme/signer/.github/workflows/sign.yml@refs/heads/main",
			owner: "acme", repo: "signer", path: ".github/workflows/sign.yml", ok: true,
		},
		{
			// No scheme, and a ref that is a tag rather than a branch.
			uri:   "github.com/acme/signer/.github/workflows/sign.yml@refs/tags/v1.0.0",
			owner: "acme", repo: "signer", path: ".github/workflows/sign.yml", ok: true,
		},
		{uri: "https://github.com/acme@refs/heads/main"},
		{uri: "not a uri"},
		{uri: ""},
	} {
		owner, repo, path, ok := splitWorkflowURI(tt.uri)
		if ok != tt.ok || owner != tt.owner || repo != tt.repo || path != tt.path {
			t.Errorf("splitWorkflowURI(%q) = %q, %q, %q, %v — want %q, %q, %q, %v",
				tt.uri, owner, repo, path, ok, tt.owner, tt.repo, tt.path, tt.ok)
		}
	}
}

// TestRunsTenantCode is Build L3's capability boundary, and the
// distinction it draws is the one a first regex here got backwards.
func TestRunsTenantCode(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name     string
		workflow string
		tenant   bool
	}{
		{
			// The recommended hardening: the caller's value reaches the
			// script as an environment variable, never as shell text. A
			// check that flagged this would refuse the workflows that
			// got it right.
			name: "a caller value passed through env is not tenant code",
			workflow: "jobs:\n  sign:\n    steps:\n      - env:\n" +
				"          UNTRUSTED: ${{ inputs.subjects }}\n        run: |\n          echo \"$UNTRUSTED\"\n",
		},
		{
			name: "a caller value expanded into the run body is",
			workflow: "jobs:\n  sign:\n    steps:\n      - run: |\n" +
				"          echo ${{ inputs.subjects }}\n",
			tenant: true,
		},
		{
			name:     "an action resolved from a caller value is",
			workflow: "jobs:\n  sign:\n    steps:\n      - uses: ${{ inputs.action }}\n",
			tenant:   true,
		},
		{
			name:     "an event value expanded into a run body is",
			workflow: "jobs:\n  sign:\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n",
			tenant:   true,
		},
		{
			name:     "a pinned action and a literal script is not",
			workflow: "jobs:\n  sign:\n    steps:\n      - uses: actions/checkout@v4\n      - run: make sign\n",
		},
		{
			// Unreadable is not safe: a workflow this check cannot parse
			// is one it cannot clear.
			name:     "a workflow that does not parse is not cleared",
			workflow: "jobs: [this is not: a mapping",
			tenant:   true,
		},
	} {
		if got := runsTenantCode([]byte(tt.workflow)); got != tt.tenant {
			t.Errorf("%s: runsTenantCode = %v, want %v", tt.name, got, tt.tenant)
		}
	}
}

// TestProvenanceShape reads what a build declared about itself, and
// refuses to read it off anything that is not build provenance.
func TestProvenanceShape(t *testing.T) {
	t.Parallel()

	const workflowType = "https://actions.github.io/buildtypes/workflow/v1"

	for _, tt := range []struct {
		name         string
		statement    string
		buildType    string
		unrecognised []string
		isProvenance bool
	}{
		{
			name: "provenance whose parameters match its buildType",
			statement: `{"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{` +
				`"buildType":"` + workflowType + `","externalParameters":{"workflow":{},"inputs":{}}}}}`,
			buildType: workflowType, isProvenance: true,
		},
		{
			name: "a parameter outside the published schema",
			statement: `{"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{` +
				`"buildType":"` + workflowType + `","externalParameters":{"workflow":{},"surprise":{}}}}}`,
			buildType: workflowType, unrecognised: []string{"surprise"}, isProvenance: true,
		},
		{
			name: "a buildType this tool has no schema for is unjudged",
			statement: `{"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{` +
				`"buildType":"https://example.invalid/buildtype/v1","externalParameters":{"anything":{}}}}}`,
			isProvenance: true,
		},
		{
			// The verdict summarising the provenance is not the
			// provenance: reading the build track's facts off whichever
			// attestation verified first is how a verifier's identity
			// stood in for a builder's.
			name:      "a verification summary is not provenance",
			statement: `{"predicateType":"https://slsa.dev/verification_summary/v1","predicate":{}}`,
		},
		{name: "not a statement at all", statement: "{{{"},
	} {
		buildType, unrecognised, isProvenance := provenanceShape([]byte(tt.statement))
		if isProvenance != tt.isProvenance || buildType != tt.buildType {
			t.Errorf("%s: provenanceShape = %q, %v, %v — want %q, %v",
				tt.name, buildType, unrecognised, isProvenance, tt.buildType, tt.isProvenance)
		}

		if len(unrecognised) != len(tt.unrecognised) {
			t.Errorf("%s: unrecognised = %v, want %v", tt.name, unrecognised, tt.unrecognised)
		}
	}
}

// TestCapabilityBoundaryReads: the boundary check fetches the workflow
// the certificate names, and each way that read can fail leaves the
// requirement unevaluated rather than cleared.
func TestCapabilityBoundaryReads(t *testing.T) {
	t.Parallel()

	la := &levelArgs{owner: "acme", name: "widget"}

	for _, tt := range []struct {
		name    string
		uri     string
		files   map[string][]byte
		wantErr bool
		tenant  bool
	}{
		{
			name:  "a clean signer clears the boundary",
			uri:   "https://github.com/acme/signer/.github/workflows/sign.yml@refs/heads/main",
			files: map[string][]byte{".github/workflows/sign.yml": []byte("jobs:\n  s:\n    steps:\n      - run: sign\n")},
		},
		{
			name: "a signer running caller code does not",
			uri:  "https://github.com/acme/signer/.github/workflows/sign.yml@refs/heads/main",
			files: map[string][]byte{
				".github/workflows/sign.yml": []byte("jobs:\n  s:\n    steps:\n      - run: echo ${{ inputs.x }}\n"),
			},
			tenant: true,
		},
		{
			name:    "an identity that names no workflow",
			uri:     "https://github.com/acme@refs/heads/main",
			wantErr: true,
		},
		{
			name:    "a workflow the forge does not serve",
			uri:     "https://github.com/acme/signer/.github/workflows/sign.yml@refs/heads/main",
			files:   map[string][]byte{},
			wantErr: true,
		},
	} {
		boundary := la.capabilityBoundary(&fileForge{files: tt.files})

		tenant, err := boundary(tt.uri, "1111111111111111111111111111111111111111")
		if (err != nil) != tt.wantErr {
			t.Errorf("%s: err = %v, want error = %v", tt.name, err, tt.wantErr)
		}

		if err == nil && tenant != tt.tenant {
			t.Errorf("%s: tenant code = %v, want %v", tt.name, tenant, tt.tenant)
		}
	}
}

// fileForge serves repository files and nothing else.
type fileForge struct {
	levelForge

	files map[string][]byte
}

//nolint:gocritic // unnamedResult: content, found, error — the Forge contract
func (f *fileForge) FileAt(_, _, path, _ string) ([]byte, bool, error) {
	if f.files == nil {
		return nil, false, errors.New("the forge is unreachable")
	}

	got, ok := f.files[path]

	return got, ok, nil
}

// TestLevelSourceReadsTheForgeNotAClone: the source track needs no
// local checkout, so a forge that cannot serve history leaves the
// track unevaluated rather than crashing or demanding a clone.
func TestLevelSourceReadsTheForgeNotAClone(t *testing.T) {
	swapLevelSeams(t, &levelForge{}, nil)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"level", "source", "--repo", "acme/widget", "--ref", "refs/heads/trunk", "--json",
	}, &stdout, &stderr)

	if code != exitBlind {
		t.Errorf("Run = %d, want could-not-judge", code)
	}

	// The requirements needing no chain still hold, which is what makes
	// the tri-state per requirement rather than per run.
	if !strings.Contains(stdout.String(), "SLSA_SOURCE_SCS_REPO_ID") {
		t.Errorf("the report does not name what it did establish:\n%s", stdout.String())
	}
}

// TestLevelBuildWithoutTrustMaterial: a run that cannot obtain a trust
// root proves nothing, and must say so rather than reporting a level.
func TestLevelBuildWithoutTrustMaterial(t *testing.T) {
	swapLevelSeams(t, &levelForge{tags: []string{"v1.0.0"}}, nil)

	orig := resolveTrustedRoot
	resolveTrustedRoot = func(trust.RootPlan) ([]byte, error) {
		return nil, errors.New("no trust material is reachable")
	}

	t.Cleanup(func() { resolveTrustedRoot = orig })

	var stdout, stderr bytes.Buffer

	if code := Run([]string{"level", "build", "--repo", "acme/widget"}, &stdout, &stderr); code != exitBlind {
		t.Errorf("Run = %d, want could-not-judge without trust material", code)
	}
}
