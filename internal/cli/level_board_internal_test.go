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
			name:  "--out-dir publishes an organisation's board",
			forge: &levelForge{},
			args:  []string{"level", "--out-dir", dir},
			want:  exitUsage, says: "--org is required",
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
			want:  exitBlind, says: "absent.json",
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
