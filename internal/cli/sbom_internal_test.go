package cli

import (
	"bytes"
	"errors"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

// releaseInfo is one release-shaped leg, as the toolchain would stamp
// it. The refusal branches live in internal/sbom and are tabled there;
// these tests exercise the command surface around them.
func releaseInfo(goos, goarch string) *debug.BuildInfo {
	return &debug.BuildInfo{
		GoVersion: "go1.26.6",
		Main:      debug.Module{Path: "github.com/monumental-archive/stele", Version: "v0.3.0"},
		Deps:      []*debug.Module{{Path: "golang.org/x/mod", Version: "v0.38.0"}},
		Settings: []debug.BuildSetting{
			{Key: "GOOS", Value: goos},
			{Key: "GOARCH", Value: goarch},
			{Key: "vcs.revision", Value: "aaaabbbbccccddddeeeeffff0000111122223333"},
			{Key: "vcs.time", Value: "2026-08-17T10:00:00Z"},
			{Key: "vcs.modified", Value: "false"},
		},
	}
}

// withBinaries swaps the binary-reading seam: each named path resolves
// to a canned build info, everything else to err.
func withBinaries(t *testing.T, infos map[string]*debug.BuildInfo, err error) {
	t.Helper()

	previous := readBinary
	readBinary = func(path string) (*debug.BuildInfo, error) {
		if info, ok := infos[path]; ok {
			return info, nil
		}

		return nil, err
	}

	t.Cleanup(func() { readBinary = previous })
}

func TestDeriveSBOMUsage(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "no binaries", args: []string{"sbom"}},
		{name: "unknown flag", args: []string{"sbom", "--nope", "bin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if got := deriveCmd(tc.args, &stdout, &stderr); got != exitUsage {
				t.Errorf("deriveCmd(%v) = %d, want %d (stderr: %s)", tc.args, got, exitUsage, stderr.String())
			}
		})
	}
}

func TestDeriveSBOMPrintsTheUnion(t *testing.T) {
	withBinaries(t, map[string]*debug.BuildInfo{
		"dist/a": releaseInfo("linux", "amd64"),
		"dist/b": releaseInfo("darwin", "arm64"),
	}, nil)

	var stdout, stderr bytes.Buffer

	if got := deriveCmd([]string{"sbom", "dist/a", "dist/b"}, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	text := stdout.String()
	for _, want := range []string{
		`"spdxVersion":"SPDX-2.3"`,
		"pkg:golang/github.com/monumental-archive/stele@v0.3.0",
		"github.com/monumental-archive/stele@v0.3.0: 2 packages, 2 platform(s)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("stdout lacks %q:\n%s", want, text)
		}
	}
}

func TestDeriveSBOMWritesTheOutFile(t *testing.T) {
	withBinaries(t, map[string]*debug.BuildInfo{"bin": releaseInfo("linux", "amd64")}, nil)

	out := filepath.Join(t.TempDir(), "stele.spdx.json")

	var stdout, stderr bytes.Buffer

	if got := deriveCmd([]string{"sbom", "--out", out, "bin"}, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	// The document went to the file; stdout carries only the summary.
	if strings.Contains(stdout.String(), "spdxVersion") {
		t.Errorf("document leaked to stdout: %s", stdout.String())
	}

	doc := readFile(t, out)
	if !strings.Contains(doc, `"SPDXID":"SPDXRef-DOCUMENT"`) {
		t.Errorf("out file is not the document:\n%s", doc)
	}
}

func TestDeriveSBOMRefusals(t *testing.T) {
	sentinel := errors.New("not a go binary")

	devel := releaseInfo("linux", "amd64")
	devel.Main.Version = "(devel)"

	for _, tc := range []struct {
		name  string
		args  []string
		infos map[string]*debug.BuildInfo
		match string
	}{
		{
			name:  "unreadable binary",
			args:  []string{"sbom", "missing"},
			match: "not a go binary",
		},
		{
			name:  "engine refusal surfaces",
			args:  []string{"sbom", "bin"},
			infos: map[string]*debug.BuildInfo{"bin": devel},
			match: "no release version",
		},
		{
			name:  "expect-version mismatch",
			args:  []string{"sbom", "--expect-version", "0.9.9", "bin"},
			infos: map[string]*debug.BuildInfo{"bin": releaseInfo("linux", "amd64")},
			match: "did not check out the tag",
		},
		{
			name:  "unwritable out file",
			args:  []string{"sbom", "--out", filepath.Join(t.TempDir(), "no", "such", "dir", "x.json"), "bin"},
			infos: map[string]*debug.BuildInfo{"bin": releaseInfo("linux", "amd64")},
			match: "no such file or directory",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withBinaries(t, tc.infos, sentinel)

			var stdout, stderr bytes.Buffer

			if got := deriveCmd(tc.args, &stdout, &stderr); got != exitRefused {
				t.Fatalf("deriveCmd(%v) = %d, want %d", tc.args, got, exitRefused)
			}

			if !strings.Contains(stderr.String(), tc.match) {
				t.Errorf("stderr %q does not name %q", stderr.String(), tc.match)
			}
		})
	}
}

// The pipeline's belief may arrive bare or v-prefixed; both are the
// same tag, and neither is what the document reports — that stays the
// artifact's own stamp.
func TestDeriveSBOMExpectVersionForms(t *testing.T) {
	for _, expect := range []string{"0.3.0", "v0.3.0"} {
		t.Run(expect, func(t *testing.T) {
			withBinaries(t, map[string]*debug.BuildInfo{"bin": releaseInfo("linux", "amd64")}, nil)

			var stdout, stderr bytes.Buffer

			if got := deriveCmd([]string{"sbom", "--expect-version", expect, "bin"}, &stdout, &stderr); got != exitOK {
				t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
			}
		})
	}
}

// A tool whose job is asserting facts must not report success after
// failing to write them — for both things this mode writes: the
// document stream and the summary line.
func TestDeriveSBOMFailingWriter(t *testing.T) {
	withBinaries(t, map[string]*debug.BuildInfo{"bin": releaseInfo("linux", "amd64")}, nil)

	t.Run("document to stdout", func(t *testing.T) {
		var stderr bytes.Buffer

		if got := deriveCmd([]string{"sbom", "bin"}, failWriterI{}, &stderr); got != exitIO {
			t.Fatalf("deriveCmd = %d, want %d", got, exitIO)
		}
	})

	t.Run("summary after --out", func(t *testing.T) {
		var stderr bytes.Buffer

		out := filepath.Join(t.TempDir(), "x.json")

		if got := deriveCmd([]string{"sbom", "--out", out, "bin"}, failWriterI{}, &stderr); got != exitIO {
			t.Fatalf("deriveCmd = %d, want %d", got, exitIO)
		}
	})
}
