package cli_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/cli"
)

var errSink = errors.New("sink closed")

// failWriter fails every write — the output-stream guard branches are
// the least exercised paths in any CLI, and a guard that cannot fire
// in a test looks exactly like success (#392, the table-test rule).
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errSink }

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantOut    string
		wantErrOut string
	}{
		{name: "no args prints usage to stderr", args: nil, wantCode: 2, wantErrOut: "usage:"},
		{name: "help prints usage to stdout", args: []string{"help"}, wantCode: 0, wantOut: "usage:"},
		{name: "version reports the module version", args: []string{"version"}, wantCode: 0, wantOut: "stele "},
		{
			name: "unknown command is a usage error", args: []string{"conjure"},
			wantCode: 2, wantErrOut: `unknown command "conjure"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			got := cli.Run(tt.args, &stdout, &stderr)
			if got != tt.wantCode {
				t.Fatalf("Run(%v) = %d, want %d", tt.args, got, tt.wantCode)
			}

			if !strings.Contains(stdout.String(), tt.wantOut) {
				t.Fatalf("stdout = %q, want it to contain %q", stdout.String(), tt.wantOut)
			}

			if !strings.Contains(stderr.String(), tt.wantErrOut) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr.String(), tt.wantErrOut)
			}
		})
	}
}

func TestRunOutputFailure(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "usage to a dead stream", args: nil},
		{name: "help to a dead stream", args: []string{"help"}},
		{name: "version to a dead stream", args: []string{"version"}},
		{name: "unknown-command report to a dead stream", args: []string{"conjure"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cli.Run(tt.args, failWriter{}, failWriter{}); got != 3 {
				t.Fatalf("Run(%v) with failing writers = %d, want 3", tt.args, got)
			}
		})
	}
}
