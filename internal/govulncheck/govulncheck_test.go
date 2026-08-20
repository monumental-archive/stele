// What the stream says, and what it must never be read as saying.
//
// The load-bearing law here is ErrNoConfig: every failure mode of a
// scan that did not happen — an empty file, a truncated stream, the
// output of some other tool — arrives as zero findings, and zero
// findings is the shape of a clean run. A reader that returned
// "clean" for any of them would report a scan nobody performed.

package govulncheck_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/govulncheck"
)

// configMsg is the shape govulncheck v1.7.0 opens a stream with,
// measured from a real run rather than written from the docs.
const configMsg = `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck",` +
	`"scanner_version":"v1.7.0","db":"https://vuln.go.dev","db_last_modified":"2026-08-19T17:06:06Z",` +
	`"go_version":"go1.26.6","scan_level":"symbol","scan_mode":"source"}}`

func TestReadsTheScannerConfig(t *testing.T) {
	t.Parallel()

	scan, err := govulncheck.Read(strings.NewReader(configMsg))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	for _, tt := range []struct{ name, got, want string }{
		{"scanner", scan.Scanner, "govulncheck"},
		{"version", scan.Version, "v1.7.0"},
		{"db", scan.DB, "https://vuln.go.dev"},
		{"dbTime", scan.DBTime, "2026-08-19T17:06:06Z"},
		{"scanLevel", scan.ScanLevel, "symbol"},
	} {
		if tt.got != tt.want {
			t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
		}
	}

	if len(scan.Findings) != 0 {
		t.Errorf("findings = %v, want none", scan.Findings)
	}
}

// A scan that did not happen must never read as a scan that found
// nothing. Every row is a stream carrying no config message, and each
// one is a real way this input arrives broken.
func TestAScanThatDidNotRunIsRefused(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		input string
	}{
		{"an empty file", ""},
		{"whitespace only", "  \n\t\n"},
		{"another tool's JSON", `{"results": []}`},
		{"findings with no config — a stream that lost its head", `{"finding":{"osv":"GO-1",` +
			`"trace":[{"module":"example.com/dep","version":"v1.0.0"}]}}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := govulncheck.Read(strings.NewReader(tt.input))
			if !errors.Is(err, govulncheck.ErrNoConfig) {
				t.Fatalf("Read = %v, want ErrNoConfig", err)
			}
		})
	}
}

// A truncated stream is a producer that stopped. Returning the values
// read so far would report a partial scan as a complete one, so the
// read fails whole — including when the config message already
// arrived and the truncation is later.
func TestATruncatedStreamFailsWhole(t *testing.T) {
	t.Parallel()

	_, err := govulncheck.Read(strings.NewReader(configMsg + `{"finding":{"osv":"GO-1","trace":[{"mod`))
	if err == nil {
		t.Fatal("a truncated stream read as a complete scan")
	}

	if errors.Is(err, govulncheck.ErrNoConfig) {
		t.Fatalf("err = %v, want the decode failure, not the no-config law", err)
	}
}

// The level is read from trace[0] — the vulnerable frame — and it is
// the only thing that decides whether a finding gates.
func TestLevelComesFromTheVulnerableFrame(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name   string
		frame  string
		want   govulncheck.Level
		called bool
	}{
		{
			name:  "a module in the graph, nothing imported",
			frame: `"module":"example.com/dep","version":"v1.0.0"`,
			want:  govulncheck.LevelRequired,
		},
		{
			name:  "a package imported, no vulnerable symbol reached",
			frame: `"module":"example.com/dep","version":"v1.0.0","package":"example.com/dep/pkg"`,
			want:  govulncheck.LevelImported,
		},
		{
			name: "a vulnerable symbol reachable — the only level that gates",
			frame: `"module":"example.com/dep","version":"v1.0.0",` +
				`"package":"example.com/dep/pkg","function":"Vulnerable"`,
			want:   govulncheck.LevelCalled,
			called: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scan, err := govulncheck.Read(strings.NewReader(
				configMsg + `{"finding":{"osv":"GO-1","trace":[{` + tt.frame + `}]}}`))
			if err != nil {
				t.Fatalf("Read: %v", err)
			}

			if len(scan.Findings) != 1 {
				t.Fatalf("findings = %v, want one", scan.Findings)
			}

			if got := scan.Findings[0].Level; got != tt.want {
				t.Errorf("level = %q, want %q", got, tt.want)
			}

			if got := scan.Findings[0].Called(); got != tt.called {
				t.Errorf("Called() = %v, want %v", got, tt.called)
			}
		})
	}
}

// govulncheck reports a finding once per trace, so one module reached
// several ways arrives several times. The strongest reach is the fact
// that matters — and the merge must not depend on the order the
// messages happen to arrive in, or a report would rank a module by
// which path the scanner walked first.
func TestOneRecordPerTripleAtTheHighestLevel(t *testing.T) {
	t.Parallel()

	const (
		required = `{"finding":{"osv":"GO-1","trace":[{"module":"example.com/dep","version":"v1.0.0"}]}}`
		called   = `{"finding":{"osv":"GO-1","trace":[{"module":"example.com/dep","version":"v1.0.0",` +
			`"package":"example.com/dep/pkg","function":"Vulnerable"}]}}`
	)

	for _, tt := range []struct {
		name  string
		order string
	}{
		{"weakest first", required + called},
		{"strongest first", called + required},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scan, err := govulncheck.Read(strings.NewReader(configMsg + tt.order))
			if err != nil {
				t.Fatalf("Read: %v", err)
			}

			if len(scan.Findings) != 1 {
				t.Fatalf("findings = %v, want the two traces merged into one record", scan.Findings)
			}

			if got := scan.Findings[0].Level; got != govulncheck.LevelCalled {
				t.Errorf("level = %q, want the highest reached", got)
			}
		})
	}
}

// A finding naming no module or no advisory keys nothing, so there is
// nothing to report and nothing to join. It must not abort the read:
// the rest of the stream is a real scan.
func TestFindingsWithNothingToKeyOnAreSkipped(t *testing.T) {
	t.Parallel()

	scan, err := govulncheck.Read(strings.NewReader(configMsg +
		`{"finding":{"osv":"GO-1"}}` +
		`{"finding":{"osv":"","trace":[{"module":"example.com/dep","version":"v1.0.0"}]}}` +
		`{"finding":{"osv":"GO-2","trace":[{"version":"v1.0.0"}]}}` +
		`{"finding":{"osv":"GO-3","trace":[{"module":"example.com/real","version":"v2.0.0"}]}}`))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if len(scan.Findings) != 1 || scan.Findings[0].Advisory != "GO-3" {
		t.Fatalf("findings = %v, want only the one that names both", scan.Findings)
	}
}

// Two reads of one stream produce the same list, so a report is a
// function of the scan and not of Go's map iteration.
func TestFindingsAreOrdered(t *testing.T) {
	t.Parallel()

	stream := configMsg +
		`{"finding":{"osv":"GO-9","trace":[{"module":"example.com/z","version":"v1.0.0"}]}}` +
		`{"finding":{"osv":"GO-1","trace":[{"module":"example.com/a","version":"v1.0.0"}]}}` +
		`{"finding":{"osv":"GO-5","trace":[{"module":"example.com/m","version":"v1.0.0"}]}}`

	want := []string{
		"GO-1:example.com/a@v1.0.0",
		"GO-5:example.com/m@v1.0.0",
		"GO-9:example.com/z@v1.0.0",
	}

	for range 2 {
		scan, err := govulncheck.Read(strings.NewReader(stream))
		if err != nil {
			t.Fatalf("Read: %v", err)
		}

		for i := range scan.Findings {
			if got := scan.Findings[i].String(); got != want[i] {
				t.Fatalf("finding %d = %q, want %q", i, got, want[i])
			}
		}
	}
}

// Unknown message kinds and unknown fields are tolerated: govulncheck
// owns this schema and extends it (v1.7.0 added SBOM and progress
// messages), and a reader that refused them would break on an upgrade
// that changed nothing this package reads.
func TestUnknownMessagesAreTolerated(t *testing.T) {
	t.Parallel()

	scan, err := govulncheck.Read(strings.NewReader(configMsg +
		`{"progress":{"message":"Scanning..."}}` +
		`{"SBOM":{"modules":[]}}` +
		`{"osv":{"id":"GO-1","summary":"something"}}` +
		`{"finding":{"osv":"GO-1","trace":[{"module":"example.com/dep","version":"v1.0.0"}],` +
		`"fixed_version":"v1.1.0"}}`))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if len(scan.Findings) != 1 {
		t.Fatalf("findings = %v, want the one finding among the noise", scan.Findings)
	}
}
