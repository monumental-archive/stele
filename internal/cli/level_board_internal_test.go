// The board form end to end: what publishes, what does not, and what
// a run that could not judge is allowed to erase.

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// boardPolicy writes an assert policy declaring a population, and
// returns its path.
func boardPolicy(t *testing.T, population string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "assert-policy.json")
	doc := `{
	  "schema": 7,
	  ` + population + `
	  "evidence": {
	    "sbomSuffix": ".spdx.json", "checksums": "checksums.txt",
	    "umbrellaBundle": "attestations.intoto.jsonl", "manifestAsset": "evidence-manifest.json",
	    "storeVsaFromVersion": "1.0.0",
	    "classes": {"go-binary": {"bundles": ["attestations-go-binaries.intoto.jsonl"]}}
	  }
	}`

	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing the policy: %v", err)
	}

	return path
}

func cellPath(dir, repo, track, suffix string) string {
	return filepath.Join(dir, repo, track+suffix)
}

func exists(t *testing.T, path string) bool {
	t.Helper()

	_, err := os.Stat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %s: %v", path, err)
	}

	return err == nil
}

// TestLevelBoardPublishesTheDeclaredGrid: every cell the population
// holds gets its two documents, and a cell it does not hold gets no
// file at all — not grey, not red, not there.
func TestLevelBoardPublishesTheDeclaredGrid(t *testing.T) {
	swapLevelSeams(t, &levelForge{repos: []string{"widget", "signer"}}, nil)

	dir := t.TempDir()
	policy := boardPolicy(t, `"population": {"repositories": [
	    {"repo": "widget"},
	    {"repo": "signer", "tracks": ["source"], "reason": "publishes no releases"}
	  ]},`)

	var stdout, stderr bytes.Buffer

	// Nothing measures against this fixture, so every published cell
	// is grey — and grey onto absence is information, never a finding.
	if got := Run([]string{"level", "--org", "acme", "--out-dir", dir, "--policy", policy},
		&stdout, &stderr); got != exitOK {
		t.Fatalf("Run = %d, want 0 — grey onto absence must not page\nstderr: %s", got, stderr.String())
	}

	for _, track := range []string{"build", "source", "dependency"} {
		for _, suffix := range []string{".report.json", ".shield.json"} {
			if !exists(t, cellPath(dir, "widget", track, suffix)) {
				t.Errorf("widget %s%s was not published", track, suffix)
			}
		}
	}

	if !exists(t, cellPath(dir, "signer", "source", ".report.json")) {
		t.Error("signer's source cell was not published — it is in the declared population")
	}

	// The whole point of stele#153 arriving before this: signer will
	// never publish a release, so a permanently grey build cell is a
	// board nobody reads.
	for _, track := range []string{"build", "dependency"} {
		for _, suffix := range []string{".report.json", ".shield.json"} {
			if exists(t, cellPath(dir, "signer", track, suffix)) {
				t.Errorf("signer %s%s was published — the population declares it out", track, suffix)
			}
		}
	}
}

// TestLevelBoardNeverOverwritesALevel is stele#135 through the whole
// verb: a run that cannot judge leaves the proven level alone and
// goes red, because something that could be proven no longer can.
func TestLevelBoardNeverOverwritesALevel(t *testing.T) {
	swapLevelSeams(t, &levelForge{repos: []string{"widget"}}, nil)

	dir := t.TempDir()
	proven := `{"schemaVersion":1,"label":"SLSA Source","message":"L3","color":"brightgreen"}`

	if err := os.MkdirAll(filepath.Join(dir, "widget"), 0o750); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(cellPath(dir, "widget", "source", ".shield.json"), []byte(proven), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	if got := Run([]string{"level", "--org", "acme", "--out-dir", dir}, &stdout, &stderr); got != exitBlind {
		t.Fatalf("Run = %d, want %d — a cell that regressed must be loud\nstderr: %s",
			got, exitBlind, stderr.String())
	}

	held, err := os.ReadFile(cellPath(dir, "widget", "source", ".shield.json"))
	if err != nil || string(held) != proven {
		t.Fatalf("the proven level was overwritten: %s (%v)", held, err)
	}

	if !strings.Contains(stderr.String(), "judged before and cannot be judged now") {
		t.Errorf("stderr does not name the regression:\n%s", stderr.String())
	}

	// The tracks that were never measured still publish grey beside
	// it: one regressed cell does not silence the rest of the board.
	if !exists(t, cellPath(dir, "widget", "build", ".shield.json")) {
		t.Error("the build cell was not published")
	}
}

// TestLevelBoardPrunesWhatLeftThePopulation: a cell a previous run
// published and the population no longer holds is removed, and the
// removal is named.
func TestLevelBoardPrunesWhatLeftThePopulation(t *testing.T) {
	swapLevelSeams(t, &levelForge{repos: []string{"widget"}}, nil)

	dir := t.TempDir()
	stale := cellPath(dir, "retired", "build", ".report.json")

	if err := os.MkdirAll(filepath.Dir(stale), 0o750); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(stale, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	if got := Run([]string{"level", "--org", "acme", "--out-dir", dir}, &stdout, &stderr); got != exitOK {
		t.Fatalf("Run = %d\nstderr: %s", got, stderr.String())
	}

	if exists(t, stale) {
		t.Error("a cell the population no longer holds survived")
	}

	if !strings.Contains(stdout.String(), "outside the declared population") {
		t.Errorf("the run does not name the removal:\n%s", stdout.String())
	}
}

// TestLevelBoardRefusals: the guard branches at the command surface
// and around the population, each named rather than answered with an
// empty board.
func TestLevelBoardRefusals(t *testing.T) {
	dir := t.TempDir()

	for _, tc := range []struct {
		name  string
		forge *levelForge
		args  []string
		want  int
		says  string
	}{
		{
			name:  "--out-dir publishes somebody's board, and nobody was named",
			forge: &levelForge{},
			args:  []string{"level", "--out-dir", dir},
			want:  exitUsage, says: "--org or --repo is required",
		},
		{
			name:  "two populations is two questions",
			forge: &levelForge{},
			args:  []string{"level", "--org", "acme", "--repo", "acme/widget", "--out-dir", dir},
			want:  exitUsage, says: "two different populations",
		},
		{
			name:  "a repository scope names one repository",
			forge: &levelForge{},
			args:  []string{"level", "--repo", "widget", "--out-dir", dir},
			want:  exitUsage, says: "--repo must be owner/repo",
		},
		{
			name:  "--org with no track and nowhere to put the answer",
			forge: &levelForge{},
			args:  []string{"level", "--org", "acme"},
			want:  exitUsage, says: "a track is required",
		},
		{
			name:  "a listing that tore is not an organisation with no repositories",
			forge: &levelForge{err: errors.New("the forge tore")},
			args:  []string{"level", "--org", "acme", "--out-dir", dir},
			want:  exitBlind, says: "could not be enumerated",
		},
		{
			name:  "a board over nobody publishes nothing",
			forge: &levelForge{},
			args:  []string{"level", "--org", "acme", "--out-dir", dir},
			want:  exitBlind, says: "holds no cell",
		},
		{
			name:  "a policy that is not there is not a population",
			forge: &levelForge{repos: []string{"widget"}},
			args:  []string{"level", "--org", "acme", "--out-dir", dir, "--policy", "absent.json"},
			// Attributed to the verb that ran: the loader is shared with
			// `derive vex-subjects` and once lent that verb's name to a
			// board run nobody had asked it for (stele#260).
			want: exitBlind, says: "level: open absent.json",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swapLevelSeams(t, tc.forge, nil)

			var stdout, stderr bytes.Buffer

			if got := Run(tc.args, &stdout, &stderr); got != tc.want {
				t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s",
					got, tc.want, stdout.String(), stderr.String())
			}

			if !strings.Contains(stdout.String()+stderr.String(), tc.says) {
				t.Errorf("the refusal does not say %q:\nstdout: %s\nstderr: %s",
					tc.says, stdout.String(), stderr.String())
			}
		})
	}
}

// TestLevelBoardWriterFails: a board that cannot be written is an
// IO failure named as one, never a run that quietly published less
// than it measured.
func TestLevelBoardWriterFails(t *testing.T) {
	swapLevelSeams(t, &levelForge{repos: []string{"widget"}}, nil)

	dir := t.TempDir()

	// A file where the repository's directory belongs.
	if err := os.WriteFile(filepath.Join(dir, "widget"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	if got := Run([]string{"level", "--org", "acme", "--out-dir", dir}, &stdout, &stderr); got != exitIO {
		t.Fatalf("Run = %d, want %d\nstderr: %s", got, exitIO, stderr.String())
	}
}

// noOrgListing is the credential the defect was measured with: it can
// read the repository it belongs to and cannot enumerate the
// organisation that repository sits in.
func noOrgListing() *levelForge {
	return &levelForge{
		repos:   []string{"widget", "signer"},
		listErr: errors.New("Resource not accessible by integration"),
	}
}

// TestLevelBoardPerRepoNeedsNoOrgListing (stele#252) is the whole
// first half: a repository publishes its own cells with a credential
// over itself. The listing seam refuses throughout — so if this mode
// enumerated anything at all, the run would end blind instead of
// publishing.
func TestLevelBoardPerRepoNeedsNoOrgListing(t *testing.T) {
	swapLevelSeams(t, noOrgListing(), nil)

	dir := t.TempDir()

	// A neighbour's cell, published by the run that owns it. This run
	// says nothing whatever about it.
	neighbour := cellPath(dir, "signer", "source", ".shield.json")
	if err := os.MkdirAll(filepath.Dir(neighbour), 0o750); err != nil {
		t.Fatal(err)
	}

	proven := `{"schemaVersion":1,"label":"SLSA Source","message":"L3","color":"brightgreen"}`
	if err := os.WriteFile(neighbour, []byte(proven), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	if got := Run([]string{"level", "--repo", "acme/widget", "--out-dir", dir}, &stdout, &stderr); got != exitOK {
		t.Fatalf("Run = %d, want 0 — a repository judging itself enumerates nothing\nstderr: %s",
			got, stderr.String())
	}

	for _, track := range []string{"build", "source", "dependency"} {
		for _, suffix := range []string{".report.json", ".shield.json"} {
			if !exists(t, cellPath(dir, "widget", track, suffix)) {
				t.Errorf("widget %s%s was not published", track, suffix)
			}
		}
	}

	held, err := os.ReadFile(cellPath(dir, "signer", "source", ".shield.json"))
	if err != nil || string(held) != proven {
		t.Fatalf("a run over one repository touched another's cell: %s (%v)", held, err)
	}
}

// TestLevelBoardPerRepoTakesItsRowFromThePolicy: the declaration
// SELECTS this repository's rows here, where the single-cell form
// refuses it. Nothing about the rest of the roster is consulted —
// there is no reconciliation to fail, which is what lets one canon
// policy serve every repository's own run.
func TestLevelBoardPerRepoTakesItsRowFromThePolicy(t *testing.T) {
	swapLevelSeams(t, noOrgListing(), nil)

	dir := t.TempDir()
	policy := boardPolicy(t, `"population": {"repositories": [
	    {"repo": "widget", "tracks": ["source"], "reason": "publishes no releases"},
	    {"repo": "signer"},
	    {"repo": "vault", "visibility": "private"}
	  ]},`)

	var stdout, stderr bytes.Buffer

	if got := Run([]string{"level", "--repo", "acme/widget", "--out-dir", dir, "--policy", policy},
		&stdout, &stderr); got != exitOK {
		t.Fatalf("Run = %d\nstderr: %s", got, stderr.String())
	}

	if !exists(t, cellPath(dir, "widget", "source", ".report.json")) {
		t.Error("the row this repository declares was not published")
	}

	for _, track := range []string{"build", "dependency"} {
		if exists(t, cellPath(dir, "widget", track, ".report.json")) {
			t.Errorf("widget %s was published — the declaration says it bears no evidence there", track)
		}
	}

	if exists(t, cellPath(dir, "signer", "source", ".report.json")) {
		t.Error("a run over one repository published another repository's cell")
	}
}

// TestLevelBoardPerRepoBearingNothing: a repository the policy
// declares out of every track publishes nothing and exits clean — an
// exclusion produces no finding, no count, no cell and no exit code
// — while still clearing the cells that declaration used to hold, and
// still leaving every other repository's alone.
func TestLevelBoardPerRepoBearingNothing(t *testing.T) {
	swapLevelSeams(t, noOrgListing(), nil)

	dir := t.TempDir()
	policy := boardPolicy(t, `"population": {"repositories": [
	    {"repo": "widget", "tracks": [], "reason": "the product site; it bears no evidence"},
	    {"repo": "signer"}
	  ]},`)

	mine := cellPath(dir, "widget", "source", ".report.json")
	neighbour := cellPath(dir, "signer", "source", ".report.json")

	for _, path := range []string{mine, neighbour} {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer

	if got := Run([]string{"level", "--repo", "acme/widget", "--out-dir", dir, "--policy", policy},
		&stdout, &stderr); got != exitOK {
		t.Fatalf("Run = %d, want 0 — a declared exclusion is a fact, not a fault\nstderr: %s",
			got, stderr.String())
	}

	if exists(t, mine) {
		t.Error("a cell this repository stopped declaring survived its own run")
	}

	if !exists(t, neighbour) {
		t.Error("a repository that publishes nothing deleted somebody else's cell")
	}

	if !strings.Contains(stdout.String(), "bears evidence on no track") {
		t.Errorf("the run does not say why it published nothing:\n%s", stdout.String())
	}
}

// TestLevelBoardSparesWhatItCouldNotSee (stele#252, second half): an
// org-wide run whose declared coverage does not reach a declared
// member publishes the rest, names the one it could not look at, and
// leaves that repository's published cells exactly where it found
// them. A narrowed enumeration deleting a proven level is the
// never-overwrite law evaded by the back door.
func TestLevelBoardSparesWhatItCouldNotSee(t *testing.T) {
	swapLevelSeams(t, &levelForge{repos: []string{"widget"}}, nil)

	dir := t.TempDir()
	policy := boardPolicy(t, `"population": {
	    "coverage": {"visibility": ["public"]},
	    "repositories": [
	      {"repo": "widget"},
	      {"repo": "vault", "visibility": "private"}
	    ]
	  },`)

	proven := `{"schemaVersion":1,"label":"SLSA Source","message":"L3","color":"brightgreen"}`
	held := cellPath(dir, "vault", "source", ".shield.json")

	if err := os.MkdirAll(filepath.Dir(held), 0o750); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(held, []byte(proven), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	if got := Run([]string{"level", "--org", "acme", "--out-dir", dir, "--policy", policy},
		&stdout, &stderr); got != exitOK {
		t.Fatalf("Run = %d, want 0 — a member outside the coverage is declared, not degraded\nstderr: %s",
			got, stderr.String())
	}

	if !exists(t, cellPath(dir, "widget", "source", ".report.json")) {
		t.Error("the member the run could see was not published")
	}

	got, err := os.ReadFile(cellPath(dir, "vault", "source", ".shield.json"))
	if err != nil || string(got) != proven {
		t.Fatalf("the cell of a repository nobody looked at changed: %s (%v)", got, err)
	}

	if !strings.Contains(stdout.String(), "vault: not looked at") {
		t.Errorf("the run does not name what it could not see:\n%s", stdout.String())
	}
}

// strangerPolicy is the adopter the universality law is tested
// against: two repositories declared out of a forty-repository
// organisation, public-only enumeration, and thirty-eight private
// members that are neither declared nor listed. Nothing about this
// shape is the home org's, and nothing about it requires an edit to
// this tool.
func strangerPolicy(t *testing.T) string {
	t.Helper()

	return boardPolicy(t, `"population": {
	    "coverage": {"visibility": ["public"]},
	    "repositories": [{"repo": "widget"}, {"repo": "signer"}]
	  },`)
}

// TestStrangerExpressesBothModes: the stranger condition, both modes,
// one minimal policy.
func TestStrangerExpressesBothModes(t *testing.T) {
	policy := strangerPolicy(t)

	t.Run("the org-wide mode reconciles what its enumeration covers", func(t *testing.T) {
		// The listing is what a public-only credential returns: the two
		// declared repositories, and no sign of the other thirty-eight.
		swapLevelSeams(t, &levelForge{repos: []string{"widget", "signer"}}, nil)

		dir := t.TempDir()

		var stdout, stderr bytes.Buffer

		if got := Run([]string{"level", "--org", "acme", "--out-dir", dir, "--policy", policy},
			&stdout, &stderr); got != exitOK {
			t.Fatalf("Run = %d, want 0 — two repositories of forty is a normal adopter\nstderr: %s",
				got, stderr.String())
		}

		for _, repo := range []string{"widget", "signer"} {
			if !exists(t, cellPath(dir, repo, "source", ".report.json")) {
				t.Errorf("%s's cell was not published", repo)
			}
		}
	})

	t.Run("the per-repository mode needs no enumeration at all", func(t *testing.T) {
		swapLevelSeams(t, noOrgListing(), nil)

		dir := t.TempDir()

		var stdout, stderr bytes.Buffer

		if got := Run([]string{"level", "--repo", "acme/widget", "--out-dir", dir, "--policy", policy},
			&stdout, &stderr); got != exitOK {
			t.Fatalf("Run = %d, want 0 — publishing your own cells must not need an org-read credential\nstderr: %s",
				got, stderr.String())
		}

		if !exists(t, cellPath(dir, "widget", "source", ".report.json")) {
			t.Error("the repository's own cell was not published")
		}

		if exists(t, cellPath(dir, "signer", "source", ".report.json")) {
			t.Error("a run over one repository published another's cell")
		}
	})
}
