// `derive vex` at the command surface.
//
// The row that carries the leg's design is the plural one: two
// subjects, each with its own inventory, each statement naming the
// artifact a consumer actually holds. It passes today with one pair
// and will pass unchanged with N, which is the whole reason the input
// is pairs rather than a glob.

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/osv"
)

// fakeScanner answers per inventory content, so one run can give two
// subjects different findings.
type fakeScanner struct {
	byInventory map[string]string
	err         error
}

func (f fakeScanner) Scan(inventory []byte) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}

	if report, ok := f.byInventory[strings.TrimSpace(string(inventory))]; ok {
		return []byte(report), nil
	}

	return []byte(`{"results": []}`), nil
}

func withScanner(t *testing.T, s osv.Scanner) {
	t.Helper()

	previous := newVEXScanner
	newVEXScanner = func() osv.Scanner { return s }

	t.Cleanup(func() { newVEXScanner = previous })
}

// finding renders a scanner report naming one advisory.
func finding(advisory, pkg, version, ecosystem string) string {
	return `{"results": [{"packages": [{"package": {"name": "` + pkg +
		`", "version": "` + version + `", "ecosystem": "` + ecosystem +
		`"}, "vulnerabilities": [{"id": "` + advisory + `"}]}]}]}`
}

// vexFixture lays out inventories and a decision directory.
func vexFixture(t *testing.T, decisions string) string {
	t.Helper()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "vex"), 0o750); err != nil {
		t.Fatal(err)
	}

	if decisions != "" {
		if err := os.WriteFile(filepath.Join(dir, "vex", "d.openvex.json"), []byte(decisions), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return dir
}

func inventory(t *testing.T, dir, name, body string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

const decidedLeftPad = `{"timestamp": "2026-01-02T03:04:05Z",
  "statements": [{"vulnerability": {"name": "CVE-1"},
   "status": "not_affected", "justification": "vulnerable_code_not_present",
   "products": [{"@id": "pkg:npm/left-pad@1.0.0"}]}]}`

func vexArgsFor(dir string, subjects ...string) []string {
	return []string{
		"vex",
		"--subjects", strings.Join(subjects, ","),
		"--vex", filepath.Join(dir, "vex"),
		"--author", "acme",
		"--id", "https://example.test/vex/1",
		"--released", "2026-08-18T12:00:00Z",
	}
}

func TestDeriveVEXUsage(t *testing.T) {
	dir := vexFixture(t, "")

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no subjects", []string{"vex", "--vex", dir, "--author", "a", "--id", "i", "--released", "2026-01-01T00:00:00Z"}},
		{"no decisions directory", []string{
			"vex", "--subjects", "p=i", "--author", "a", "--id", "i", "--released", "2026-01-01T00:00:00Z",
		}},
		{"no author", []string{
			"vex", "--subjects", "p=i", "--vex", dir, "--id", "i", "--released", "2026-01-01T00:00:00Z",
		}},
		{"no id", []string{
			"vex", "--subjects", "p=i", "--vex", dir, "--author", "a", "--released", "2026-01-01T00:00:00Z",
		}},
		{"no release instant", []string{"vex", "--subjects", "p=i", "--vex", dir, "--author", "a", "--id", "i"}},
		{"unknown flag", []string{"vex", "--nope"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if got := deriveCmd(tc.args, &stdout, &stderr); got != exitUsage {
				t.Errorf("deriveCmd(%v) = %d, want %d", tc.args, got, exitUsage)
			}
		})
	}
}

// The design row: two artifacts, two inventories, statements naming
// the artifact each finding actually belongs to.
func TestDeriveVEXIsPerArtifact(t *testing.T) {
	dir := vexFixture(t, decidedLeftPad+"\n")

	binary := inventory(t, dir, "binary.spdx.json", "BINARY")
	pkgInv := inventory(t, dir, "npm.spdx.json", "NPM")

	withScanner(t, fakeScanner{byInventory: map[string]string{
		"BINARY": `{"results": []}`,
		"NPM":    finding("CVE-1", "left-pad", "1.0.0", "npm"),
	}})

	var stdout, stderr bytes.Buffer

	args := vexArgsFor(dir, "pkg:github/acme/widget@v1#bin="+binary, "pkg:npm/widget@1.0.0="+pkgInv)
	if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	out := stdout.String()

	// The statement names the npm package, not the release: the
	// binary's inventory carries no such finding.
	if !strings.Contains(out, `"@id":"pkg:npm/widget@1.0.0"`) {
		t.Errorf("the statement does not name the artifact that ships it:\n%s", out)
	}

	if strings.Contains(out, `"@id":"pkg:github/acme/widget@v1#bin"`) {
		t.Errorf("a statement was attributed to an artifact with no such finding:\n%s", out)
	}

	// The subcomponent is the purl the human recorded, verbatim.
	if !strings.Contains(out, `"subcomponents":[{"@id":"pkg:npm/left-pad@1.0.0"}]`) {
		t.Errorf("the subcomponent is not the recorded purl:\n%s", out)
	}

	// The statement is dated by the JUDGMENT, the document by the
	// RELEASE — so the same inputs render the same bytes.
	if !strings.Contains(out, `"timestamp":"2026-01-02T03:04:05Z"`) {
		t.Errorf("the statement is not dated by the decision:\n%s", out)
	}

	if !strings.Contains(out, `"timestamp":"2026-08-18T12:00:00Z"`) {
		t.Errorf("the document is not dated by the release:\n%s", out)
	}
}

// A gate-class finding with no decision refuses the derivation: a
// coverage document for an untriaged release would be a false claim.
func TestDeriveVEXRefusesUndecided(t *testing.T) {
	dir := vexFixture(t, "")
	inv := inventory(t, dir, "a.spdx.json", "A")

	withScanner(t, fakeScanner{byInventory: map[string]string{"A": finding("CVE-9", "x", "1", "npm")}})

	var stdout, stderr bytes.Buffer

	if got := deriveCmd(vexArgsFor(dir, "p="+inv), &stdout, &stderr); got != exitRefused {
		t.Fatalf("deriveCmd = %d, want %d", got, exitRefused)
	}

	if !strings.Contains(stderr.String(), "CVE-9:x@1") || !strings.Contains(stderr.String(), "triage before releasing") {
		t.Fatalf("stderr = %q", stderr.String())
	}

	if stdout.Len() != 0 {
		t.Fatalf("a refused derivation still wrote a document: %q", stdout.String())
	}
}

// A base-layer finding with no published fix is reported, never
// gated: there is nothing to upgrade to, so a decision would decide
// nothing.
func TestDeriveVEXReportsTheRebuildCadence(t *testing.T) {
	dir := vexFixture(t, "")
	inv := inventory(t, dir, "a.spdx.json", "A")

	withScanner(t, fakeScanner{byInventory: map[string]string{"A": finding("CVE-9", "libc", "1", "Debian:12")}})

	var stdout, stderr bytes.Buffer

	args := append(vexArgsFor(dir, "p="+inv), "--base-ecosystems", "debian")
	if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	// Nothing decided, so nothing to render — reported in
	// machine-readable form so the caller need not glob for a file.
	if !strings.Contains(stderr.String(), "derived=false") {
		t.Fatalf("stderr = %q, want the no-coverage report", stderr.String())
	}
}

func TestDeriveVEXRefusals(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		scanner osv.Scanner
		want    string
	}{
		{
			name:    "a subject that is not product=path",
			subject: "justapath",
			scanner: fakeScanner{},
			want:    "is not <product-id>=<inventory-path>",
		},
		{
			name:    "an inventory that does not exist",
			subject: "p=/nonexistent/a.spdx.json",
			scanner: fakeScanner{},
			want:    "no such file",
		},
		{
			name:    "an inventory that parses to zero packages",
			scanner: fakeScanner{err: osv.ErrZeroPackages},
			want:    "parsed to zero packages",
		},
		{
			name:    "a scanner that died",
			scanner: fakeScanner{err: errors.New("scanner exploded")},
			want:    "scanner exploded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := vexFixture(t, "")
			inv := inventory(t, dir, "a.spdx.json", "A")
			withScanner(t, tt.scanner)

			subject := tt.subject
			if subject == "" {
				subject = "p=" + inv
			}

			var stdout, stderr bytes.Buffer

			if got := deriveCmd(vexArgsFor(dir, subject), &stdout, &stderr); got != exitRefused {
				t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, exitRefused, stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("stderr = %q, want it to mention %q", stderr.String(), tt.want)
			}
		})
	}
}

// A release instant that is not RFC 3339 is refused: the document's
// date is a fact, and a renderer that shrugged would substitute a
// clock.
func TestDeriveVEXRefusesABadInstant(t *testing.T) {
	dir := vexFixture(t, "")
	inv := inventory(t, dir, "a.spdx.json", "A")
	withScanner(t, fakeScanner{})

	args := vexArgsFor(dir, "p="+inv)
	for i, a := range args {
		if a == "2026-08-18T12:00:00Z" {
			args[i] = "last tuesday"
		}
	}

	var stdout, stderr bytes.Buffer

	if got := deriveCmd(args, &stdout, &stderr); got != exitRefused {
		t.Fatalf("deriveCmd = %d, want %d", got, exitRefused)
	}

	if !strings.Contains(stderr.String(), "not RFC 3339") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
