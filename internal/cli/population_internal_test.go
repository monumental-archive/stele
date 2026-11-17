// `derive population` at the command surface (stele#388).

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/population"
)

// popForge is a forge whose listing answers with names, or tears.
type popForge struct {
	storeForge

	repos   []gh.Repo
	listErr error
}

func (f *popForge) ListRepos(string) ([]gh.Repo, error) { return f.repos, f.listErr }

// popOrg is three live repositories, an archive and a fork.
func popOrg() *popForge {
	return &popForge{repos: []gh.Repo{
		{Name: "canon"},
		{Name: "lab"},
		{Name: "signer"},
		{Name: "attic", Archived: true},
		{Name: "mirror", Fork: true},
	}}
}

// popRoster is the declared population: canon by default, lab excluded,
// signer on source alone.
const popRoster = `"population": {"repositories": [
    {"repo": "canon"},
    {"repo": "lab", "tracks": [], "reason": "a laboratory: it publishes nothing"},
    {"repo": "signer", "tracks": ["source"], "reason": "the signing workflow repository"}
  ]},`

// popPolicy writes an assert policy carrying the given population
// section ("" for none).
func popPolicy(t *testing.T, section string) string {
	t.Helper()

	doc := `{"schema": 9, ` + section + `
  "evidence": {"sbomSuffix": ".spdx.json", "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl", "manifestAsset": "evidence-manifest.json",
    "classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}}}`

	path := filepath.Join(t.TempDir(), "assert-policy.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func swapPopForge(t *testing.T, f gh.Forge) {
	t.Helper()

	orig := newForge
	newForge = func() gh.Forge { return f }

	t.Cleanup(func() { newForge = orig })
}

type popRun struct {
	code           int
	stdout, stderr string
}

func derivePop(args ...string) popRun {
	var stdout, stderr bytes.Buffer

	code := deriveCmd(append([]string{"population"}, args...), &stdout, &stderr)

	return popRun{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func decodePop(t *testing.T, s string) population.Document {
	t.Helper()

	doc, err := jsonx.DecodeBytes[population.Document]([]byte(s))
	if err != nil {
		t.Fatalf("not a population document: %v\n%s", err, s)
	}

	return *doc
}

// TestDerivePopulationPrintsTheSet: the organisation's population, one
// member per declared repository with its resolved tracks.
func TestDerivePopulationPrintsTheSet(t *testing.T) {
	swapPopForge(t, popOrg())

	run := derivePop("--policy", popPolicy(t, popRoster), "--org", "acme")
	if run.code != exitOK {
		t.Fatalf("code = %d, stderr %q", run.code, run.stderr)
	}

	doc := decodePop(t, run.stdout)

	var got []string
	for _, m := range doc.Members {
		got = append(got, m.Repo+":"+strings.Join(m.Tracks, "+"))
	}

	if !slices.Equal(got, []string{"canon:build+source+dependency", "lab:", "signer:source"}) {
		t.Fatalf("members = %v", got)
	}
}

// TestDerivePopulationIsTheAssertPopulation: the verb prints exactly
// what resolvePopulation — the one door every assert target walks
// through — returns for the same forge and policy.
func TestDerivePopulationIsTheAssertPopulation(t *testing.T) {
	f := popOrg()
	swapPopForge(t, f)

	policyPath := popPolicy(t, popRoster)

	pol, err := loadAssertPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}

	set, err := resolvePopulation(population.Scope{Org: "acme"}, f, pol.Population)
	if err != nil {
		t.Fatal(err)
	}

	want, err := jsonx.Marshal(set.Document())
	if err != nil {
		t.Fatal(err)
	}

	run := derivePop("--policy", policyPath, "--org", "acme")
	if strings.TrimSpace(run.stdout) != string(want) {
		t.Fatalf("printed %s\nassert's %s", run.stdout, want)
	}
}

// TestDerivePopulationExitCodes: disagreement is 1 and prints both
// directions by name; a listing that cannot be read is 4.
func TestDerivePopulationExitCodes(t *testing.T) {
	tests := []struct {
		name    string
		forge   gh.Forge
		section string
		code    int
		want    string
	}{
		{
			"a declared member the listing does not show", &popForge{repos: []gh.Repo{{Name: "canon"}, {Name: "lab"}}},
			popRoster, exitRefused, "the declared population names signer, which the listing does not show",
		},
		{
			"a listed repository nobody declared", &popForge{repos: append(popOrg().repos, gh.Repo{Name: "new"})},
			popRoster, exitRefused, "the listing shows new, which the declared population does not account for",
		},
		{
			"an unreadable listing", &popForge{listErr: errors.New("403 the credential cannot list")}, popRoster,
			exitBlind, "403 the credential cannot list",
		},
		{"a forge that cannot list at all", &storeForge{}, popRoster, exitBlind, "this forge cannot list acme"},
		{
			"an empty listing under the default predicate", &popForge{}, "", exitBlind,
			"holds no repository the population admits",
		},
		{"only archives and forks under the default predicate", &popForge{repos: []gh.Repo{
			{Name: "attic", Archived: true}, {Name: "mirror", Fork: true},
		}}, "", exitBlind, "holds no repository the population admits"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swapPopForge(t, tt.forge)

			run := derivePop("--policy", popPolicy(t, tt.section), "--org", "acme")
			if run.code != tt.code || !strings.Contains(run.stderr, tt.want) {
				t.Fatalf("code = %d, stderr %q — want %d and %q", run.code, run.stderr, tt.code, tt.want)
			}
		})
	}
}

// TestDerivePopulationPrintsTheDisagreement: a refused reconciliation
// still prints both directions, and no members.
func TestDerivePopulationPrintsTheDisagreement(t *testing.T) {
	swapPopForge(t, &popForge{repos: []gh.Repo{{Name: "canon"}, {Name: "lab"}, {Name: "new"}}})

	run := derivePop("--policy", popPolicy(t, popRoster), "--org", "acme")
	if run.code != exitRefused {
		t.Fatalf("code = %d, stderr %q", run.code, run.stderr)
	}

	doc := decodePop(t, run.stdout)
	if len(doc.Members) != 0 || !slices.Equal(doc.Reconciliation.Undeclared, []string{"new"}) ||
		!slices.Equal(doc.Reconciliation.Unlisted, []string{"signer"}) {
		t.Fatalf("document = %+v", doc)
	}
}

// TestDerivePopulationOneRepository: the --repo question's pass and its
// refusals by name.
func TestDerivePopulationOneRepository(t *testing.T) {
	swapPopForge(t, popOrg())

	declared := popPolicy(t, popRoster)
	undeclared := popPolicy(t, "")

	tests := []struct {
		name   string
		policy string
		repo   string
		tracks string
		code   int
		want   string
	}{
		{"a member stating its declared tracks", declared, "acme/signer", "source", exitOK, ""},
		{"a member whose roster names no tracks, stating some", declared, "acme/canon", "build,source", exitOK, ""},
		{"stated in any order and separator", declared, "acme/canon", "dependency build\tsource", exitOK, ""},
		{"no declaration: the default predicate admits it", undeclared, "acme/canon", "build", exitOK, ""},
		{
			"not a member", declared, "acme/stranger", "build", exitRefused,
			"acme/stranger is not in the declared population",
		},
		{"no tracks stated", declared, "acme/signer", "", exitRefused, "no tracks stated"},
		{
			"a mismatch with the roster", declared, "acme/signer", "build source", exitRefused,
			"acme/signer states the tracks [build source], but the roster declares [source]",
		},
		{
			"an exclusion stating any track", declared, "acme/lab", "build", exitRefused,
			"but the roster declares []",
		},
		{"an unknown track", declared, "acme/canon", "release", exitRefused, `the stated track "release" is no track`},
		{
			"a track named twice", declared, "acme/canon", "build,build", exitRefused,
			`the stated track "build" is named twice`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := derivePop("--policy", tt.policy, "--repo", tt.repo, "--tracks", tt.tracks)
			if run.code != tt.code || !strings.Contains(run.stderr, tt.want) {
				t.Fatalf("code = %d, stderr %q — want %d and %q", run.code, run.stderr, tt.code, tt.want)
			}

			if tt.code == exitOK {
				doc := decodePop(t, run.stdout)
				if len(doc.Members) != 1 || "acme/"+doc.Members[0].Repo != tt.repo {
					t.Fatalf("document = %+v, want the one member", doc)
				}
			}
		})
	}
}

// TestDerivePopulationUsage: the flag surface's refusals.
func TestDerivePopulationUsage(t *testing.T) {
	swapPopForge(t, popOrg())

	policy := popPolicy(t, popRoster)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no policy", []string{"--org", "acme"}, "--policy is required"},
		{"no scope", []string{"--policy", policy}, "--org or --repo is required"},
		{"both scopes", []string{"--policy", policy, "--org", "acme", "--repo", "acme/canon"}, "exclusive"},
		{"a repo that is not owner/name", []string{"--policy", policy, "--repo", "canon"}, "owner/name"},
		{
			"tracks for an organisation",
			[]string{"--policy", policy, "--org", "acme", "--tracks", "build"},
			"--tracks is stated for one repository",
		},
		{"an unreadable policy", []string{"--policy", "/nonexistent", "--org", "acme"}, "nonexistent"},
		{"an unknown flag", []string{"--nope"}, "flag provided but not defined"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := derivePop(tt.args...)
			if run.code != exitUsage || !strings.Contains(run.stderr, tt.want) {
				t.Fatalf("code = %d, stderr %q — want %q", run.code, run.stderr, tt.want)
			}
		})
	}
}

// TestDerivePopulationWritesWhereAsked: --out writes the document; a
// path that cannot be written is the stream failure's code.
func TestDerivePopulationWritesWhereAsked(t *testing.T) {
	swapPopForge(t, popOrg())

	policy := popPolicy(t, popRoster)
	out := filepath.Join(t.TempDir(), "population.json")

	if run := derivePop("--policy", policy, "--org", "acme", "--out", out); run.code != exitOK || run.stdout != "" {
		t.Fatalf("run = %+v", run)
	}

	b, err := os.ReadFile(out) //nolint:gosec // a path this test named
	if err != nil {
		t.Fatal(err)
	}

	decodePop(t, string(b))

	run := derivePop("--policy", policy, "--org", "acme", "--out", filepath.Join(t.TempDir(), "no", "such", "x"))
	if run.code != exitIO {
		t.Fatalf("code = %d, want %d", run.code, exitIO)
	}
}
