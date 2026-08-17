// Package osv runs the osv-scanner binary — the one accepted
// subprocess in the assert verb. The scanner is a database plus
// matching logic somebody else maintains, the same relationship the
// org has to cosign: stele orchestrates and judges, it does not
// reimplement. Exit semantics are typed here so the engine's guards
// are table-testable: 0 and 1 are answers (clean, findings), 128 is
// the loud zero-packages fault the bash refused, anything else is a
// scanner failure.
package osv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// ErrZeroPackages reports an SBOM that parsed to zero packages — a
// scan that reads nothing must not report clean.
var ErrZeroPackages = errors.New("osv: the SBOM parsed to zero packages")

// Scanner scans one SBOM's bytes and returns the scanner's JSON.
type Scanner interface {
	Scan(sbom []byte) ([]byte, error)
}

// zeroPackagesExit is osv-scanner's exit code for an input that
// yielded no packages; findingsExit is its exit code when
// vulnerabilities were found (an answer, not an error).
const (
	findingsExit     = 1
	zeroPackagesExit = 128
)

// Runner is the production Scanner over the osv-scanner binary.
type Runner struct {
	Bin string
}

// Scan implements Scanner: the SBOM bytes go to a scratch file (the
// scanner reads paths), the JSON report comes back.
func (r Runner) Scan(sbom []byte) ([]byte, error) {
	bin := r.Bin
	if bin == "" {
		bin = "osv-scanner"
	}

	f, err := os.CreateTemp("", "stele-sbom-*.spdx.json")
	if err != nil {
		return nil, fmt.Errorf("osv: scratch file: %w", err)
	}

	defer os.Remove(f.Name()) //nolint:errcheck // scratch cleanup has nothing to report

	if _, werr := f.Write(sbom); werr != nil {
		return nil, fmt.Errorf("osv: writing scratch SBOM: %w", werr)
	}

	if cerr := f.Close(); cerr != nil {
		return nil, fmt.Errorf("osv: closing scratch SBOM: %w", cerr)
	}

	var stdout bytes.Buffer

	// The CLI has no cancellation surface; context.Background is the
	// honest parent.
	//nolint:gosec // the binary name is operator configuration
	cmd := exec.CommandContext(context.Background(), bin, "scan", "source", "-L", f.Name(), "--format", "json")
	cmd.Stdout = &stdout

	err = cmd.Run()

	var exitErr *exec.ExitError

	switch {
	case err == nil:
		return stdout.Bytes(), nil
	case errors.As(err, &exitErr) && exitErr.ExitCode() == findingsExit:
		return stdout.Bytes(), nil
	case errors.As(err, &exitErr) && exitErr.ExitCode() == zeroPackagesExit:
		return nil, ErrZeroPackages
	default:
		return nil, fmt.Errorf("osv: scanner: %w", err)
	}
}
