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

	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(vexPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	return dir
}

// vexPolicy is the assert policy the derivation reads: the base-layer
// ecosystems and the author come from blastRadius, the inventory
// suffix from evidence.
const vexPolicy = `{"schema": 9,
  "evidence": {"sbomSuffix": ".spdx.json", "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl", "manifestAsset": "evidence-manifest.json",
    "classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}},
  "blastRadius": {"osEcosystems": ["debian", "alpine"], "vexAuthor": "acme"}}`

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
		"--policy", filepath.Join(dir, "policy.json"),
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
		{"no subjects", []string{"vex", "--vex", dir, "--policy", "p", "--id", "i", "--released", "2026-01-01T00:00:00Z"}},
		{"no decisions directory", []string{
			"vex", "--subjects", "p=i", "--policy", "p", "--id", "i", "--released", "2026-01-01T00:00:00Z",
		}},
		{"no policy", []string{
			"vex", "--subjects", "p=i", "--vex", dir, "--id", "i", "--released", "2026-01-01T00:00:00Z",
		}},
		{"no id", []string{
			"vex", "--subjects", "p=i", "--vex", dir, "--policy", "p", "--released", "2026-01-01T00:00:00Z",
		}},
		{"no release instant", []string{"vex", "--subjects", "p=i", "--vex", dir, "--policy", "p", "--id", "i"}},
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

// coveredRelease is the fixture the rows below break one fact of: one
// artifact, one finding, and a recorded decision that covers it — so
// the derivation reaches the renderer with something to say.
//
//nolint:gocritic // unnamedResult: the fixture dir and its one subject spec
func coveredRelease(t *testing.T) (string, string) {
	t.Helper()

	dir := vexFixture(t, decidedLeftPad+"\n")
	inv := inventory(t, dir, "npm.spdx.json", "NPM")

	withScanner(t, fakeScanner{byInventory: map[string]string{
		"NPM": finding("CVE-1", "left-pad", "1.0.0", "npm"),
	}})

	return dir, "pkg:npm/widget@1.0.0=" + inv
}

// TestDeriveVEXRefusesAnUnreadableDecisionSet: the decisions are the
// human judgments this document exists to publish. A directory holding
// one that will not parse must stop the run — deriving from the rest
// would publish a coverage document that silently omits a decision
// somebody made, and the finding it covered would resurface as
// untriaged on the next release.
func TestDeriveVEXRefusesAnUnreadableDecisionSet(t *testing.T) {
	dir, subject := coveredRelease(t)

	broken := filepath.Join(dir, "vex", "broken.openvex.json")
	if err := os.WriteFile(broken, []byte("{not openvex"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer

	if got := deriveCmd(vexArgsFor(dir, subject), &stdout, &stderr); got != exitRefused {
		t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, exitRefused, stderr.String())
	}

	if !strings.Contains(stderr.String(), "reading decisions from") {
		t.Errorf("stderr = %q, want the decision set named", stderr.String())
	}
}

// TestDeriveVEXRefusesTheZeroInstant: the zero time parses as RFC 3339
// but is not a release instant. The document is dated by the release
// it describes precisely so two renders agree; a document stamped with
// the epoch is one whose date means nothing, and the renderer refuses
// it rather than publishing a reproducible lie.
func TestDeriveVEXRefusesTheZeroInstant(t *testing.T) {
	dir, subject := coveredRelease(t)

	args := vexArgsFor(dir, subject)
	for i, a := range args {
		if a == "2026-08-18T12:00:00Z" {
			args[i] = "0001-01-01T00:00:00Z"
		}
	}

	var stdout, stderr bytes.Buffer

	if got := deriveCmd(args, &stdout, &stderr); got != exitRefused {
		t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, exitRefused, stderr.String())
	}

	if !strings.Contains(stderr.String(), "release instant is required") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// TestDeriveVEXWriteFailure: a coverage document that could not be
// written must fail the run. Reporting success would leave the
// previous release's decisions in place while telling the release its
// VEX had been refreshed.
func TestDeriveVEXWriteFailure(t *testing.T) {
	dir, subject := coveredRelease(t)

	args := append(vexArgsFor(dir, subject),
		"--out", filepath.Join(dir, "absent-dir", "v.openvex.json"))

	var stdout, stderr bytes.Buffer

	if got := deriveCmd(args, &stdout, &stderr); got == exitOK {
		t.Fatalf("deriveCmd reported success writing into a directory that is not there (stderr: %s)",
			stderr.String())
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

	args := vexArgsFor(dir, "p="+inv)
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
		{
			// The list is assembled by a shell, so a bare comma is an
			// empty entry rather than a subject at the empty path — but
			// a list of NOTHING but empties names no subject, and a
			// document describing nothing covers nothing.
			name:    "a subject list that is all separators",
			subject: " , ,",
			scanner: fakeScanner{},
			want:    "no subjects",
		},
		{
			name:    "a subject with no product",
			subject: "=/tmp/a.spdx.json",
			scanner: fakeScanner{},
			want:    "is not <product-id>=<inventory-path>",
		},
		{
			name:    "a subject with no inventory",
			subject: "p=",
			scanner: fakeScanner{},
			want:    "is not <product-id>=<inventory-path>",
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

// vexPolicyWith writes an assert policy beside the fixture, replacing
// the blastRadius section.
func vexPolicyWith(t *testing.T, dir, blastRadius string) string {
	t.Helper()

	doc := vexPolicy
	if i := strings.Index(doc, `,
  "blastRadius"`); i >= 0 {
		doc = doc[:i] + blastRadius + "}"
	}

	path := filepath.Join(dir, "custom-policy.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func withPolicy(args []string, path string) []string {
	out := append([]string{}, args...)
	for i := range out {
		if out[i] == "--policy" {
			out[i+1] = path
		}
	}

	return out
}

// TestDeriveVEXReadsThePolicy (stele#397): the ecosystems and the
// author are the assert policy's, and a policy that does not carry
// them is refused by name rather than read as an empty answer.
func TestDeriveVEXReadsThePolicy(t *testing.T) {
	base := finding("CVE-9", "libc", "1", "Debian:12")

	tests := []struct {
		name        string
		blastRadius string
		code        int
		want        string
	}{
		{
			"debian declared a base layer: reported, never gated",
			`, "blastRadius": {"osEcosystems": ["debian"], "vexAuthor": "acme"}`, exitOK, "derived=false",
		},
		{
			"debian not declared: the same finding gates",
			`, "blastRadius": {"osEcosystems": ["alpine"], "vexAuthor": "acme"}`, exitRefused, "CVE-9",
		},
		{
			"no blastRadius section", "", exitRefused,
			"declares no blastRadius section — the base-layer classification this derivation reads has no source",
		},
		{
			"no author", `, "blastRadius": {"osEcosystems": ["debian"]}`, exitRefused,
			"declares no blastRadius.vexAuthor",
		},
		{
			"an empty author", `, "blastRadius": {"osEcosystems": ["debian"], "vexAuthor": ""}`, exitRefused,
			"blastRadius.vexAuthor is empty",
		},
		{
			"no ecosystems", `, "blastRadius": {"osEcosystems": [], "vexAuthor": "acme"}`, exitRefused,
			"blastRadius.osEcosystems is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := vexFixture(t, "")
			inv := inventory(t, dir, "a.spdx.json", "A")
			withScanner(t, fakeScanner{byInventory: map[string]string{"A": base}})

			args := withPolicy(vexArgsFor(dir, "p="+inv), vexPolicyWith(t, dir, tt.blastRadius))

			var stdout, stderr bytes.Buffer

			if got := deriveCmd(args, &stdout, &stderr); got != tt.code || !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("deriveCmd = %d, stderr %q — want %d and %q", got, stderr.String(), tt.code, tt.want)
			}
		})
	}
}

// TestDeriveVEXNamesThePolicyAuthor: the rendered document names the
// policy's author.
func TestDeriveVEXNamesThePolicyAuthor(t *testing.T) {
	dir := vexFixture(t, decidedLeftPad+"\n")
	inv := inventory(t, dir, "a.spdx.json", "A")
	withScanner(t, fakeScanner{byInventory: map[string]string{"A": finding("CVE-1", "left-pad", "1.0.0", "npm")}})

	args := withPolicy(vexArgsFor(dir, "p="+inv), vexPolicyWith(t, dir,
		`, "blastRadius": {"osEcosystems": ["debian"], "vexAuthor": "Example Org"}`))

	var stdout, stderr bytes.Buffer

	if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	if !strings.Contains(stdout.String(), `"author":"Example Org"`) {
		t.Fatalf("document = %s, want the policy's author", stdout.String())
	}
}

// TestDeriveVEXRemovedFlags: the two values the policy now carries are
// no longer flags — a caller still passing one is refused as unknown,
// never silently ignored beside the policy's answer.
func TestDeriveVEXRemovedFlags(t *testing.T) {
	for _, flag := range []string{"--base-ecosystems", "--author"} {
		t.Run(flag, func(t *testing.T) {
			dir := vexFixture(t, "")
			inv := inventory(t, dir, "a.spdx.json", "A")

			var stdout, stderr bytes.Buffer

			args := append(vexArgsFor(dir, "p="+inv), flag, "x")
			if got := deriveCmd(args, &stdout, &stderr); got != exitUsage ||
				!strings.Contains(stderr.String(), "flag provided but not defined: "+strings.TrimPrefix(flag, "-")) {
				t.Fatalf("deriveCmd = %d, stderr %q — want the unknown flag refused", got, stderr.String())
			}
		})
	}
}

// inventoriesArgs is vexArgsFor with the subject list discovered from
// a directory instead.
func inventoriesArgs(dir, inventories string) []string {
	args := vexArgsFor(dir)

	for i := range args {
		if args[i] == "--subjects" {
			args[i], args[i+1] = "--inventories", inventories
		}
	}

	return args
}

// spdx renders a minimal inventory document carrying a name.
func spdx(name string) string { return `{"spdxVersion": "SPDX-2.3", "name": "` + name + `"}` }

// TestDeriveVEXDiscoversInventories (stele#397): every file carrying
// the policy's SBOM suffix is a subject, in name order, under its own
// document name — the product a consumer holds, never a name composed
// beside it. Other files and directories are not inventories.
func TestDeriveVEXDiscoversInventories(t *testing.T) {
	dir := vexFixture(t, "")
	invs := filepath.Join(dir, "dist")

	if err := os.MkdirAll(filepath.Join(invs, "nested.spdx.json"), 0o750); err != nil {
		t.Fatal(err)
	}

	inventory(t, invs, "zeta.spdx.json", spdx("ghcr.io/acme/widget@sha256:"+strings.Repeat("b", 64)))
	inventory(t, invs, "alpha.spdx.json", spdx("widget-alpha"))
	inventory(t, invs, "notes.txt", "not an inventory")
	inventory(t, invs, "release.vex.openvex.json", `{"statements": []}`)

	withScanner(t, fakeScanner{})

	var stdout, stderr bytes.Buffer

	if got := deriveCmd(inventoriesArgs(dir, invs), &stdout, &stderr); got != exitOK {
		t.Fatalf("deriveCmd = %d (stderr: %s)", got, stderr.String())
	}

	log := stderr.String()

	alpha := strings.Index(log, "widget-alpha: ")
	zeta := strings.Index(log, "ghcr.io/acme/widget@sha256:"+strings.Repeat("b", 64)+": ")

	if alpha < 0 || zeta < 0 || alpha > zeta {
		t.Fatalf("log = %q — want both inventories under their own names, in name order", log)
	}

	if strings.Count(log, " decided, ") != 2 {
		t.Fatalf("log = %q — want exactly the two inventories, nothing else in the directory", log)
	}
}

// TestDeriveVEXDiscoveryRefusals: each discovery guard refuses by name.
func TestDeriveVEXDiscoveryRefusals(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		dir   string
		want  string
	}{
		{
			"a nameless inventory",
			map[string]string{"a.spdx.json": `{"spdxVersion": "SPDX-2.3"}`},
			"",
			"a.spdx.json carries no name — its statements would name no product",
		},
		{
			"a blank name",
			map[string]string{"a.spdx.json": spdx("  ")},
			"",
			"a.spdx.json carries no name",
		},
		{
			"an inventory that is not JSON",
			map[string]string{"a.spdx.json": "<xml/>"},
			"",
			"a.spdx.json is not an inventory document",
		},
		{
			"a directory holding no inventory",
			map[string]string{"notes.txt": "x"},
			"",
			"holds no *.spdx.json inventory — a document describing nothing covers nothing",
		},
		{"a directory that does not exist", nil, "/nonexistent/dist", "--inventories:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := vexFixture(t, "")
			invs := filepath.Join(dir, "dist")

			if err := os.MkdirAll(invs, 0o750); err != nil {
				t.Fatal(err)
			}

			for name, body := range tt.files {
				inventory(t, invs, name, body)
			}

			if tt.dir != "" {
				invs = tt.dir
			}

			withScanner(t, fakeScanner{})

			var stdout, stderr bytes.Buffer

			if got := deriveCmd(inventoriesArgs(dir, invs), &stdout, &stderr); got != exitRefused ||
				!strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("deriveCmd = %d, stderr %q — want %q", got, stderr.String(), tt.want)
			}
		})
	}
}

// TestDeriveVEXSubjectSourceUsage: one subject list, named once.
func TestDeriveVEXSubjectSourceUsage(t *testing.T) {
	dir := vexFixture(t, "")

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"both", append(vexArgsFor(dir, "p=i"), "--inventories", dir), "--subjects and --inventories are exclusive"},
		{"neither", inventoriesArgs(dir, ""), "--subjects or --inventories is required"},
		{
			"no policy",
			[]string{"vex", "--subjects", "p=i", "--vex", dir, "--id", "i", "--released", "x"},
			"--policy is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if got := deriveCmd(tt.args, &stdout, &stderr); got != exitUsage || !strings.Contains(stderr.String(), tt.want) {
				t.Fatalf("deriveCmd = %d, stderr %q — want %q", got, stderr.String(), tt.want)
			}
		})
	}
}

// TestDeriveVEXRefusesAnUnreadablePolicy: the policy is loaded through
// the assert loader, whose refusal is the run's.
func TestDeriveVEXRefusesAnUnreadablePolicy(t *testing.T) {
	dir := vexFixture(t, "")
	inv := inventory(t, dir, "a.spdx.json", "A")

	var stdout, stderr bytes.Buffer

	args := withPolicy(vexArgsFor(dir, "p="+inv), "/nonexistent/policy.json")
	if got := deriveCmd(args, &stdout, &stderr); got != exitRefused || !strings.Contains(stderr.String(), "derive vex:") {
		t.Fatalf("deriveCmd = %d, stderr %q", got, stderr.String())
	}
}
