package standin_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/standin"
)

func TestMain(m *testing.M) {
	os.Exit(standin.Main(m))
}

// TestPlantedStandInActsItsSpec runs a planted stand-in the way every
// runner does — a real exec of the symlink — and reads back each part
// of the spec.
func TestPlantedStandInActsItsSpec(t *testing.T) {
	t.Parallel()

	dir := standin.Plant(t, "tool", &standin.Spec{
		Stdout:     "out\n",
		Stderr:     "err\n",
		Exit:       3,
		Marker:     "ran-here",
		WriteAfter: "--bundle",
		Write:      `{"stub":"bundle"}`,
	})
	work := t.TempDir()
	bundle := filepath.Join(work, "bundle.json")

	var stdout, stderr bytes.Buffer

	//nolint:gosec // the stand-in this test just planted
	cmd := exec.CommandContext(context.Background(), filepath.Join(dir, "tool"), "sign", "--bundle", bundle, "a b")
	cmd.Dir = work
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	var exitErr *exec.ExitError
	if err := cmd.Run(); !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
		t.Fatalf("Run = %v (stderr %q), want exit 3", err, stderr.String())
	}

	if stdout.String() != "out\n" || stderr.String() != "err\n" {
		t.Errorf("streams = %q / %q", stdout.String(), stderr.String())
	}

	if got := strings.Join(standin.Argv(t, dir), "|"); got != "sign|--bundle|"+bundle+"|a b" {
		t.Errorf("argv = %q", got)
	}

	if _, err := os.Stat(filepath.Join(work, "ran-here")); err != nil {
		t.Errorf("no marker in the working directory: %v", err)
	}

	//nolint:gosec // G304: this test's own temp dir
	if raw, err := os.ReadFile(bundle); err != nil || string(raw) != `{"stub":"bundle"}` {
		t.Errorf("bundle = %q, %v", raw, err)
	}
}

// TestBareNameResolvesThroughPATH: a runner with no explicit path
// starts the tool by bare name, so os.Args[0] carries no directory and
// the stand-in must find its data the way the exec layer found it.
func TestBareNameResolvesThroughPATH(t *testing.T) {
	dir := standin.Plant(t, "tool", &standin.Spec{Stdout: "via PATH"})
	t.Setenv("PATH", dir)

	var stdout, stderr bytes.Buffer
	if code := standin.Act("tool", []string{"x"}, &stdout, &stderr); code != 0 {
		t.Fatalf("Act = %d: %s", code, stderr.String())
	}

	if stdout.String() != "via PATH" {
		t.Errorf("stdout = %q", stdout.String())
	}
}

// failWriter refuses every write.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("dead stream") }

// TestStandInGuards: every way a stand-in can fail to act is its own
// exit code, never a scripted answer a test could mistake for the
// tool's.
func TestStandInGuards(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T, dir string) (argv0 string, args []string)
		dead  string
		want  int
		says  string
	}{
		{
			name: "a bare name nowhere on PATH is lost",
			setup: func(*testing.T, string) (string, []string) {
				return "stele-standin-no-such-tool", nil
			},
			want: 125, says: "cannot find myself",
		},
		{
			name: "a missing data file is a broken spec",
			setup: func(t *testing.T, dir string) (string, []string) {
				t.Helper()
				remove(t, filepath.Join(dir, "stdout"))

				return filepath.Join(dir, "tool"), nil
			},
			want: 126, says: "reading the spec",
		},
		{
			name: "an exit file that is not a number is a broken spec",
			setup: func(t *testing.T, dir string) (string, []string) {
				t.Helper()
				write(t, filepath.Join(dir, "exit"), "zero")

				return filepath.Join(dir, "tool"), nil
			},
			want: 126, says: "the exit file",
		},
		{
			name: "an argv record that cannot be written",
			setup: func(t *testing.T, dir string) (string, []string) {
				t.Helper()
				mkdir(t, filepath.Join(dir, "argv"))

				return filepath.Join(dir, "tool"), nil
			},
			want: 126, says: "recording argv",
		},
		{
			name: "a marker that cannot be dropped",
			setup: func(t *testing.T, dir string) (string, []string) {
				t.Helper()
				write(t, filepath.Join(dir, "marker"), filepath.Join(dir, "absent", "marker"))

				return filepath.Join(dir, "tool"), nil
			},
			want: 126, says: "dropping the marker",
		},
		{
			name: "a dead stdout",
			setup: func(_ *testing.T, dir string) (string, []string) {
				return filepath.Join(dir, "tool"), nil
			},
			dead: "stdout", want: 126, says: "replaying stdout",
		},
		{
			name: "a dead stderr",
			setup: func(_ *testing.T, dir string) (string, []string) {
				return filepath.Join(dir, "tool"), nil
			},
			dead: "stderr", want: 126,
		},
		{
			name: "a write flag with no path after it",
			setup: func(t *testing.T, dir string) (string, []string) {
				t.Helper()
				write(t, filepath.Join(dir, "write-after"), "--bundle")

				return filepath.Join(dir, "tool"), []string{"--bundle"}
			},
			want: 126, says: "no path after --bundle",
		},
		{
			name: "a write flag the argv never carries",
			setup: func(t *testing.T, dir string) (string, []string) {
				t.Helper()
				write(t, filepath.Join(dir, "write-after"), "--bundle")

				return filepath.Join(dir, "tool"), []string{"other"}
			},
			want: 126, says: "no path after --bundle",
		},
		{
			name: "a write target that cannot be written",
			setup: func(t *testing.T, dir string) (string, []string) {
				t.Helper()
				write(t, filepath.Join(dir, "write-after"), "--bundle")

				return filepath.Join(dir, "tool"), []string{"--bundle", filepath.Join(dir, "absent", "b")}
			},
			want: 126, says: "writing after --bundle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := standin.Plant(t, "tool", &standin.Spec{Stdout: "o", Stderr: "e"})
			argv0, args := tt.setup(t, dir)

			var stdout, stderr bytes.Buffer

			var outW, errW io.Writer = &stdout, &stderr

			switch tt.dead {
			case "stdout":
				outW = failWriter{}
			case "stderr":
				errW = failWriter{}
			}

			if code := standin.Act(argv0, args, outW, errW); code != tt.want {
				t.Fatalf("Act = %d, want %d (stderr %q)", code, tt.want, stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.says) {
				t.Errorf("stderr = %q, want it to say %q", stderr.String(), tt.says)
			}
		})
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func remove(t *testing.T, path string) {
	t.Helper()

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()

	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
}
