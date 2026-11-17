// The board form with --published (stele#418): measure over the board
// as published, then name every cell on which the two disagree. The
// fixture's forge measures nothing, so every cell a run publishes is
// grey — which is exactly what makes a published LEVEL the one state a
// run here cannot reproduce, and so the one the never-overwrite rule
// must keep.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// publishedBoard is the board a previous run published, over the same
// fixture org.
func publishedBoard(t *testing.T) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "published")

	var stdout, stderr bytes.Buffer

	if got := Run([]string{"level", "--org", "acme", "--out-dir", dir}, &stdout, &stderr); got != exitOK {
		t.Fatalf("publishing the fixture board = %d\nstderr: %s", got, stderr.String())
	}

	return dir
}

func writeCellFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestLevelBoardComparesThePublishedBoard: each row a published board
// built in the test, the verb run over it, and the exit and findings
// it must give. The first row is the one that fails before this
// change, when --published was an unknown flag (exit 2).
func TestLevelBoardComparesThePublishedBoard(t *testing.T) {
	const proven = `{"schemaVersion":1,"label":"SLSA Source","message":"L3","color":"brightgreen"}` + "\n"

	for _, tt := range []struct {
		name string
		// published returns the published board's directory.
		published func(t *testing.T) string
		code      int
		drift     []string
		quiet     bool
		check     func(t *testing.T, published, measured string)
	}{
		{
			name:      "identical boards",
			published: publishedBoard,
			code:      exitOK,
			quiet:     true,
		},
		{
			name: "a measured cell never published",
			published: func(t *testing.T) string {
				t.Helper()

				dir := publishedBoard(t)
				for _, suffix := range []string{".report.json", ".shield.json"} {
					if err := os.Remove(cellPath(dir, "widget", "build", suffix)); err != nil {
						t.Fatal(err)
					}
				}

				return dir
			},
			code:  exitRefused,
			drift: []string{"widget build: measured, never published"},
		},
		{
			name: "a differing cell names both messages",
			published: func(t *testing.T) string {
				t.Helper()

				dir := publishedBoard(t)
				writeCellFile(t, cellPath(dir, "widget", "build", ".shield.json"),
					`{"schemaVersion":1,"label":"SLSA Build","message":"stale","color":"lightgrey"}`+"\n")

				return dir
			},
			code:  exitRefused,
			drift: []string{"widget build: published stale, measured "},
		},
		{
			name: "a published cell outside the population",
			published: func(t *testing.T) string {
				t.Helper()

				dir := publishedBoard(t)
				writeCellFile(t, cellPath(dir, "retired", "build", ".shield.json"), proven)
				writeCellFile(t, cellPath(dir, "retired", "build", ".report.json"), "{}")

				return dir
			},
			code:  exitRefused,
			drift: []string{"retired build: published, outside the declared population"},
		},
		{
			name: "a previously judged cell that cannot be judged",
			published: func(t *testing.T) string {
				t.Helper()

				dir := publishedBoard(t)
				writeCellFile(t, cellPath(dir, "widget", "source", ".shield.json"), proven)

				return dir
			},
			code:  exitBlind,
			quiet: true,
			check: func(t *testing.T, published, measured string) {
				t.Helper()

				for _, dir := range []string{published, measured} {
					held, err := os.ReadFile(cellPath(dir, "widget", "source", ".shield.json"))
					if err != nil || string(held) != proven {
						t.Errorf("%s: the proven level did not stand: %s (%v)", dir, held, err)
					}
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			swapLevelSeams(t, &levelForge{repos: []string{"widget"}}, nil)

			published := tt.published(t)
			measured := filepath.Join(t.TempDir(), "measured")

			var stdout, stderr bytes.Buffer

			got := Run([]string{"level", "--org", "acme", "--out-dir", measured, "--published", published},
				&stdout, &stderr)
			if got != tt.code {
				t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s", got, tt.code, stdout.String(), stderr.String())
			}

			for _, d := range tt.drift {
				if !strings.Contains(stdout.String(), "level: drift: "+d) {
					t.Errorf("stdout does not name the drift %q:\n%s", d, stdout.String())
				}
			}

			if tt.quiet && strings.Contains(stdout.String(), "level: drift:") {
				t.Errorf("drift reported where there is none:\n%s", stdout.String())
			}

			if tt.check != nil {
				tt.check(t, published, measured)
			}
		})
	}
}

// TestLevelBoardCompareRefusals: the comparison's own guards — a
// directory compared with itself, and a measured directory that
// already holds another run's cells.
func TestLevelBoardCompareRefusals(t *testing.T) {
	swapLevelSeams(t, &levelForge{repos: []string{"widget"}}, nil)

	published := publishedBoard(t)

	busy := t.TempDir()
	writeCellFile(t, filepath.Join(busy, "stray"), "")

	for _, tt := range []struct {
		name string
		args []string
		code int
		says string
	}{
		{
			name: "one directory twice",
			args: []string{"level", "--org", "acme", "--out-dir", published, "--published", published + "/."},
			code: exitUsage,
			says: "--published and --out-dir are one directory",
		},
		{
			name: "a measured directory that is not empty",
			args: []string{"level", "--org", "acme", "--out-dir", busy, "--published", published},
			code: exitUsage,
			says: "the directory to seed is not empty",
		},
		{
			name: "a published board that cannot be read",
			args: []string{
				"level", "--org", "acme", "--out-dir", filepath.Join(t.TempDir(), "m"),
				"--published", filepath.Join(busy, "stray"),
			},
			code: exitIO,
			says: "board: reading",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if got := Run(tt.args, &stdout, &stderr); got != tt.code {
				t.Fatalf("Run = %d, want %d\nstderr: %s", got, tt.code, stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.says) {
				t.Errorf("stderr = %q, want it to say %q", stderr.String(), tt.says)
			}
		})
	}
}
