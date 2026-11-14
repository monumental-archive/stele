// Package standin is test support: a stand-in for an external tool
// (cargo, npm, osv-scanner, cosign) that no test has to write as an
// executable.
//
// A test that writes a shell script and then execs it races on Linux
// (stele#320): os.WriteFile holds a write descriptor on the script, a
// concurrent test forks while it is open, the child inherits the
// descriptor, and the exec of the script fails with "text file busy".
// The race is removed rather than retried around: the stand-in is the
// test binary itself, reached through a SYMLINK named for the tool.
// Creating a symlink opens no write descriptor, so there is nothing
// for a concurrent fork to inherit.
//
// Each package that plants a stand-in calls Main from its TestMain.
// When the test binary was started as a stand-in, Main acts and the
// tests never run; otherwise it marks the environment so that every
// child of this binary acts, and runs the tests. What a stand-in does
// is read from plain data files beside the symlink — never from the
// environment, because parallel tests cannot set it — and the stand-in
// finds them from the name it was started under, os.Args[0].
package standin

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Env is the variable that tells a test binary it was started as a
// stand-in. Main sets it before the tests run, so every process a test
// starts inherits it; a runner that scrubbed its child's environment
// would lose it, and none here does.
const Env = "STELE_TEST_STANDIN"

// The data files a planted stand-in reads, and the one it writes.
const (
	fileStdout     = "stdout"
	fileStderr     = "stderr"
	fileExit       = "exit"
	fileMarker     = "marker"
	fileWriteAfter = "write-after"
	fileWrite      = "write"

	// FileArgv is where a stand-in records the arguments it was called
	// with, one per line, in its own directory.
	FileArgv = "argv"
)

// Exit codes a stand-in uses for its OWN faults, distinct from any
// scripted exit so a broken fixture never reads as the tool's answer.
const (
	exitLost    = 125
	exitBadSpec = 126
)

// ownerRW is the mode of every file a stand-in or its planting writes:
// data, never anything executed.
const ownerRW = 0o600

// Spec is what one stand-in does when run, in this order: record its
// argv, drop Marker into the directory it was run in, replay Stdout
// and Stderr, write Write to the path that follows the WriteAfter flag
// in its argv, and exit with Exit. The zero Spec records its argv and
// exits 0.
type Spec struct {
	Stdout string
	Stderr string
	Exit   int

	// Marker, when set, is a file name the stand-in creates in its
	// working directory — the proof of WHERE the tool ran.
	Marker string

	// WriteAfter names a flag (e.g. "--bundle"); when set, Write is
	// written to the path given as the argument after it, the way a
	// signer leaves its output where it was told to.
	WriteAfter string
	Write      string
}

// Main is a package's TestMain body: os.Exit(standin.Main(m)).
func Main(m *testing.M) int {
	if os.Getenv(Env) != "" {
		return Act(os.Args[0], os.Args[1:], os.Stdout, os.Stderr)
	}

	if err := os.Setenv(Env, "1"); err != nil {
		fmt.Fprintf(os.Stderr, "standin: marking the environment: %v\n", err)

		return 1
	}

	return m.Run()
}

// Plant puts a stand-in named name into a fresh temporary directory —
// its data files, then a symlink to this test binary — and returns the
// directory, which serves both a runner given the path and a PATH
// lookup.
func Plant(tb testing.TB, name string, s *Spec) string {
	tb.Helper()

	exe, err := os.Executable()
	if err != nil {
		tb.Fatalf("standin: locating the test binary: %v", err)
	}

	dir := tb.TempDir()

	for file, content := range map[string]string{
		fileStdout:     s.Stdout,
		fileStderr:     s.Stderr,
		fileExit:       strconv.Itoa(s.Exit),
		fileMarker:     s.Marker,
		fileWriteAfter: s.WriteAfter,
		fileWrite:      s.Write,
	} {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(content), ownerRW); err != nil {
			tb.Fatalf("standin: %v", err)
		}
	}

	if err := os.Symlink(exe, filepath.Join(dir, name)); err != nil {
		tb.Fatalf("standin: %v", err)
	}

	return dir
}

// Argv reads back the arguments the stand-in in dir was called with.
func Argv(tb testing.TB, dir string) []string {
	tb.Helper()

	//nolint:gosec // G304: a path the test planted in its own temp dir
	raw, err := os.ReadFile(filepath.Join(dir, FileArgv))
	if err != nil {
		tb.Fatalf("the stand-in in %s was never run: %v", dir, err)
	}

	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

// Act is the stand-in: argv0 is the name it was started under, from
// which it finds its directory exactly as the exec layer found it.
func Act(argv0 string, args []string, stdout, stderr io.Writer) int {
	dir, err := locate(argv0)
	if err != nil {
		return fault(stderr, exitLost, fmt.Errorf("cannot find myself from %q: %w", argv0, err))
	}

	code, err := act(dir, args, stdout, stderr)
	if err != nil {
		return fault(stderr, exitBadSpec, err)
	}

	return code
}

// fault reports a stand-in's own failure and returns its code. The
// code alone carries the fault when stderr is dead too.
func fault(stderr io.Writer, code int, err error) int {
	if _, werr := fmt.Fprintf(stderr, "standin: %v\n", err); werr != nil {
		return code
	}

	return code
}

// locate resolves the directory the stand-in was planted in. A name
// with a separator is a path; a bare name was resolved through PATH,
// which this process inherited, so it is resolved again the same way.
// The symlink itself is never followed: it points at the test binary,
// not at the data.
func locate(argv0 string) (string, error) {
	if strings.ContainsRune(argv0, filepath.Separator) {
		return filepath.Dir(argv0), nil
	}

	path, err := exec.LookPath(argv0)
	if err != nil {
		return "", fmt.Errorf("resolving through PATH: %w", err)
	}

	return filepath.Dir(path), nil
}

func act(dir string, args []string, stdout, stderr io.Writer) (int, error) {
	files := map[string]string{}

	for _, name := range []string{fileStdout, fileStderr, fileExit, fileMarker, fileWriteAfter, fileWrite} {
		//nolint:gosec // G304: the stand-in's own planted data
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return 0, fmt.Errorf("reading the spec: %w", err)
		}

		files[name] = string(raw)
	}

	exit, err := strconv.Atoi(files[fileExit])
	if err != nil {
		return 0, fmt.Errorf("the exit file: %w", err)
	}

	var record strings.Builder
	for _, a := range args {
		record.WriteString(a + "\n")
	}

	//nolint:gosec // G703: the stand-in's own planted directory
	if err := os.WriteFile(filepath.Join(dir, FileArgv), []byte(record.String()), ownerRW); err != nil {
		return 0, fmt.Errorf("recording argv: %w", err)
	}

	if m := files[fileMarker]; m != "" {
		if err := os.WriteFile(m, nil, ownerRW); err != nil {
			return 0, fmt.Errorf("dropping the marker: %w", err)
		}
	}

	if _, err := io.WriteString(stdout, files[fileStdout]); err != nil {
		return 0, fmt.Errorf("replaying stdout: %w", err)
	}

	if _, err := io.WriteString(stderr, files[fileStderr]); err != nil {
		return 0, fmt.Errorf("replaying stderr: %w", err)
	}

	if flag := files[fileWriteAfter]; flag != "" {
		if err := writeAfter(args, flag, files[fileWrite]); err != nil {
			return 0, err
		}
	}

	return exit, nil
}

// writeAfter writes content to the path that follows flag in args.
func writeAfter(args []string, flag, content string) error {
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		return errors.New("argv carries no path after " + flag)
	}

	//nolint:gosec // G703: the path the test handed the tool, as the real tool takes it
	if err := os.WriteFile(args[i+1], []byte(content), ownerRW); err != nil {
		return fmt.Errorf("writing after %s: %w", flag, err)
	}

	return nil
}
