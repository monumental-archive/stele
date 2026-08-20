// The classification and the join, row by row.
//
// The rule under test everywhere: a finding is gateable unless it is
// BOTH base-layer and unfixable. That is total and it is code — you
// cannot require a remediation that does not exist — while the
// ecosystem list it consults is policy.

package triage_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/triage"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

// report renders one scanner finding. The advisory is fixed at
// CVE-1 because every row varies the package or the ecosystem, not
// the identifier.
func report(name, version, ecosystem string, fixed bool) string {
	const advisory = "CVE-1"

	events := `[{"introduced": "0"}]`
	if fixed {
		events = `[{"fixed": "9.9.9"}]`
	}

	return `{"results": [{"packages": [{"package": {"name": "` + name +
		`", "version": "` + version + `", "ecosystem": "` + ecosystem +
		`"}, "vulnerabilities": [{"id": "` + advisory +
		`", "affected": [{"ranges": [{"events": ` + events + `}]}]}]}]}]}`
}

func policy() *triage.Policy {
	return &triage.Policy{BaseEcosystems: []string{"debian", "alpine"}}
}

func TestClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		ecosystem string
		fixed     bool
		want      triage.Class
	}{
		{"an ecosystem package gates", "crates.io", false, triage.ClassGate},
		{"an ecosystem package with a fix gates", "npm", true, triage.ClassGate},
		{"a base package WITH a fix still gates", "Debian:12", true, triage.ClassGate},
		{"a base package with no fix is the rebuild cadence", "Debian:12", false, triage.ClassRebuild},
		{"matching is case-insensitive", "DEBIAN:13", false, triage.ClassRebuild},
		{"an unlisted OS is not a base layer this org declared", "Rocky:9", false, triage.ClassGate},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := policy().Findings([]byte(report("p", "1", tt.ecosystem, tt.fixed)))
			if err != nil {
				t.Fatalf("Findings = %v", err)
			}

			if len(got) != 1 || got[0].Class != tt.want {
				t.Fatalf("Findings = %+v, want one %s", got, tt.want)
			}
		})
	}
}

// An org declaring no base layer has nothing that cannot be acted on:
// every finding gates. A legitimate answer for an org shipping no
// images, and the reason the list is policy rather than a default.
func TestNoDeclaredBaseLayer(t *testing.T) {
	t.Parallel()

	empty := &triage.Policy{}

	got, err := empty.Findings([]byte(report("p", "1", "Debian:12", false)))
	if err != nil {
		t.Fatalf("Findings = %v", err)
	}

	if got[0].Class != triage.ClassGate {
		t.Fatalf("class = %s, want every finding actionable", got[0].Class)
	}
}

// Two runs over one inventory produce one list: deduplicated, ordered,
// and refusing a report that is not the scanner's shape.
func TestFindingsAreStable(t *testing.T) {
	t.Parallel()

	doubled := `{"results": [{"packages": [
	  {"package": {"name": "b", "version": "2", "ecosystem": "npm"},
	   "vulnerabilities": [{"id": "CVE-2"}]},
	  {"package": {"name": "a", "version": "1", "ecosystem": "npm"},
	   "vulnerabilities": [{"id": "CVE-1"}, {"id": "CVE-1"}]}]}]}`

	got, err := policy().Findings([]byte(doubled))
	if err != nil {
		t.Fatalf("Findings = %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("Findings = %+v, want the duplicate collapsed", got)
	}

	if got[0].String() != "CVE-1:a@1" || got[1].String() != "CVE-2:b@2" {
		t.Fatalf("Findings = %v, want them ordered", []string{got[0].String(), got[1].String()})
	}

	if _, err := policy().Findings([]byte("not json")); err == nil {
		t.Fatal("Findings accepted a report that is not JSON")
	}
}

// decisions parses a set from one document.
func decisions(t *testing.T, doc string) *vexjoin.Decisions {
	t.Helper()

	d := &vexjoin.Decisions{}
	if err := vexjoin.Parse(d, []byte(doc), "test.openvex.json"); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	return d
}

const decidedDoc = `{"timestamp": "2026-01-01T00:00:00Z",
  "statements": [{"vulnerability": {"name": "CVE-1"},
   "status": "not_affected", "justification": "vulnerable_code_not_present",
   "products": [{"@id": "pkg:npm/a@1"}]}]}`

// The split is exhaustive and disjoint: every finding lands in exactly
// one bucket, so a caller cannot mislay one between two filters.
func TestJoinSplitsExhaustively(t *testing.T) {
	t.Parallel()

	findings, err := policy().Findings([]byte(`{"results": [{"packages": [
	  {"package": {"name": "a", "version": "1", "ecosystem": "npm"},
	   "vulnerabilities": [{"id": "CVE-1"}]},
	  {"package": {"name": "b", "version": "2", "ecosystem": "npm"},
	   "vulnerabilities": [{"id": "CVE-2"}]},
	  {"package": {"name": "c", "version": "3", "ecosystem": "Debian:12"},
	   "vulnerabilities": [{"id": "CVE-3"}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}

	split := triage.Join(findings, decisions(t, decidedDoc))

	if len(split.Decided) != 1 || split.Decided[0].Finding.String() != "CVE-1:a@1" {
		t.Errorf("decided = %+v", split.Decided)
	}

	if len(split.Undecided) != 1 || split.Undecided[0].String() != "CVE-2:b@2" {
		t.Errorf("undecided = %+v", split.Undecided)
	}

	if len(split.Rebuild) != 1 || split.Rebuild[0].String() != "CVE-3:c@3" {
		t.Errorf("rebuild = %+v", split.Rebuild)
	}

	if n := len(split.Decided) + len(split.Undecided) + len(split.Rebuild); n != len(findings) {
		t.Errorf("the split holds %d of %d findings", n, len(findings))
	}

	// The judgment travels with the decision, so a derived document can
	// carry the human's words rather than paraphrase them.
	got := split.Decided[0].Decision
	if got.Status != "not_affected" || got.Justification != "vulnerable_code_not_present" {
		t.Errorf("decision = %+v, want the recorded judgment", got)
	}

	if got.Decided.IsZero() {
		t.Error("the decision carries no moment")
	}
}

// A decision covers only the exact triple, which is what makes a
// bumped dependency surface for fresh judgment instead of inheriting
// the old verdict.
func TestJoinMatchesTheExactTriple(t *testing.T) {
	t.Parallel()

	bumped, err := policy().Findings([]byte(report("a", "2", "npm", false)))
	if err != nil {
		t.Fatal(err)
	}

	split := triage.Join(bumped, decisions(t, decidedDoc))
	if len(split.Undecided) != 1 {
		t.Fatalf("a bumped version inherited its predecessor's decision: %+v", split)
	}
}

// A decision matching nothing is a retirement candidate, named.
func TestStale(t *testing.T) {
	t.Parallel()

	none := triage.Stale(nil, decisions(t, decidedDoc))
	if len(none) != 1 || none[0].Key.Advisory() != "CVE-1" {
		t.Fatalf("Stale = %+v, want the unmatched decision", none)
	}

	matched, err := policy().Findings([]byte(report("a", "1", "npm", false)))
	if err != nil {
		t.Fatal(err)
	}

	if got := triage.Stale(matched, decisions(t, decidedDoc)); len(got) != 0 {
		t.Fatalf("Stale = %+v, want nothing once it matches", got)
	}
}

// The stale list is a retirement worklist a human reads and edits a
// VEX document from, so it is ordered rather than delivered in
// whatever order the decisions were parsed. Both keys are needed to
// order it: two decisions about one advisory differ only by package,
// and two about one package only by advisory.
func TestStaleIsOrdered(t *testing.T) {
	t.Parallel()

	const several = `{"timestamp": "2026-01-01T00:00:00Z", "statements": [
	  {"vulnerability": {"name": "CVE-9"}, "status": "not_affected",
	   "justification": "vulnerable_code_not_present", "products": [{"@id": "pkg:npm/a@1"}]},
	  {"vulnerability": {"name": "CVE-1"}, "status": "not_affected",
	   "justification": "vulnerable_code_not_present", "products": [{"@id": "pkg:npm/z@1"}]},
	  {"vulnerability": {"name": "CVE-1"}, "status": "not_affected",
	   "justification": "vulnerable_code_not_present", "products": [{"@id": "pkg:npm/b@1"}]}]}`

	got := triage.Stale(nil, decisions(t, several))
	if len(got) != 3 {
		t.Fatalf("Stale = %+v, want all three unmatched decisions", got)
	}

	var spelled []string
	for i := range got {
		spelled = append(spelled, got[i].Key.String())
	}

	want := []string{"CVE-1:b@1", "CVE-1:z@1", "CVE-9:a@1"}
	if strings.Join(spelled, ",") != strings.Join(want, ",") {
		t.Fatalf("Stale = %v, want %v", spelled, want)
	}
}

// An empty decision set decides nothing — never everything.
func TestEmptyDecisionsDecideNothing(t *testing.T) {
	t.Parallel()

	findings, err := policy().Findings([]byte(report("a", "1", "npm", false)))
	if err != nil {
		t.Fatal(err)
	}

	split := triage.Join(findings, &vexjoin.Decisions{})
	if len(split.Decided) != 0 || len(split.Undecided) != 1 {
		t.Fatalf("an empty decision set covered something: %+v", split)
	}
}

// A statement with no status or no readable moment is refused at
// parse: a decision that decides nothing, or one whose moment must be
// invented, cannot be carried into a derived document honestly.
func TestDecisionRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			"no status",
			`{"timestamp": "2026-01-01T00:00:00Z", "statements": [{"vulnerability": {"name": "X"},
			  "products": [{"@id": "pkg:npm/a@1"}]}]}`,
			"carries no status",
		},
		{
			"no moment anywhere",
			`{"statements": [{"vulnerability": {"name": "X"}, "status": "not_affected",
			  "products": [{"@id": "pkg:npm/a@1"}]}]}`,
			"no timestamp",
		},
		{
			"a moment that is not RFC 3339",
			`{"timestamp": "last tuesday", "statements": [{"vulnerability": {"name": "X"},
			  "status": "not_affected", "products": [{"@id": "pkg:npm/a@1"}]}]}`,
			"not RFC 3339",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := vexjoin.Parse(&vexjoin.Decisions{}, []byte(tt.doc), "x.json")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// A statement dates itself where it can, and inherits its document's
// moment where it cannot — the shape real documents actually take.
func TestStatementInheritsTheDocumentMoment(t *testing.T) {
	t.Parallel()

	d := decisions(t, `{"timestamp": "2026-01-01T00:00:00Z",
	  "statements": [{"vulnerability": {"name": "X"}, "status": "affected",
	   "action_statement": "upgrade", "products": [{"@id": "pkg:npm/a@1"}]},
	  {"vulnerability": {"name": "Y"}, "status": "not_affected",
	   "timestamp": "2026-06-01T00:00:00Z", "products": [{"@id": "pkg:npm/b@1"}]}]}`)

	byAdvisory := map[string]string{}
	for _, dec := range d.All() {
		byAdvisory[dec.Key.Advisory()] = dec.Decided.UTC().Format("2006-01-02")
	}

	if byAdvisory["X"] != "2026-01-01" {
		t.Errorf("X dated %s, want the document's moment", byAdvisory["X"])
	}

	if byAdvisory["Y"] != "2026-06-01" {
		t.Errorf("Y dated %s, want its own moment", byAdvisory["Y"])
	}
}

// TestAPublishedPurlDecidesTheModuleItNames walks the whole join for
// a mixed-case Go module: a scanner report naming the module as it is
// written, and a decision whose product purl is the one a stele SBOM
// publishes for it (lowercased, the purl golang type's canonical
// form — docs/vex-join.md).
//
// This is the pairing the defect made impossible. The two sides never
// meet in one package elsewhere, so the fold is only proven where
// they do: findings from a scanner, decisions from a document.
func TestAPublishedPurlDecidesTheModuleItNames(t *testing.T) {
	t.Parallel()

	const (
		module    = "github.com/Masterminds/semver/v3"
		published = "pkg:golang/github.com/masterminds/semver/v3@v3.5.0"
	)

	findings, err := policy().Findings([]byte(report(module, "v3.5.0", "Go", true)))
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}

	// The finding carries the module path as the scanner wrote it, so
	// a report names what a reader will find in go.mod; the key
	// carries the canonical form, which is what joins.
	if got := findings[0].Package; got != module {
		t.Errorf("Finding.Package = %q, want the scanner's own spelling %q", got, module)
	}

	// Spelled out, not computed: an expectation derived by the same
	// operation the code under test performs agrees with itself
	// whatever that operation is.
	if got, want := findings[0].Key.Package(), "github.com/masterminds/semver/v3"; got != want {
		t.Errorf("Key.Package() = %q, want the canonical form %q", got, want)
	}

	doc := `{"timestamp": "2026-08-20T00:00:00Z",
	  "statements": [{"vulnerability": {"name": "CVE-1"},
	   "status": "not_affected", "justification": "vulnerable_code_not_present",
	   "products": [{"@id": "` + published + `"}]}]}`

	split := triage.Join(findings, decisions(t, doc))
	if len(split.Decided) != 1 || len(split.Undecided) != 0 {
		t.Fatalf("Join = %d decided, %d undecided; the published purl decided nothing",
			len(split.Decided), len(split.Undecided))
	}

	// The same decision must not read as a retirement candidate: a
	// join that matched and a staleness check that did not would be
	// two answers to one question.
	if stale := triage.Stale(findings, decisions(t, doc)); len(stale) != 0 {
		t.Fatalf("Stale = %+v, want none — the decision matched a live finding", stale)
	}
}
