// The level join reads PUBLISHED decisions (stele#356): a release's or
// a stream's OpenVEX names the shipped artifact and decides the
// dependency inside it, repeats one decision per artifact, and may
// carry statements this join cannot read — which are named, never
// silently dropped, and never stop the read.

package cli

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/vex"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

// findingsReport renders a scanner report holding the given findings,
// in the shape joinFindings reads.
func findingsReport(findings ...[4]string) []byte {
	var pkgs []string

	for _, f := range findings {
		pkgs = append(pkgs, `{"package":{"name":"`+f[1]+`","version":"`+f[2]+`","ecosystem":"`+f[3]+`"},`+
			`"vulnerabilities":[{"id":"`+f[0]+`"}]}`)
	}

	return []byte(`{"results":[{"packages":[` + strings.Join(pkgs, ",") + `]}]}`)
}

// TestPublishedDecisionsRoundTripTheWriter: a document `derive vex`'s
// renderer writes — shipped artifacts as products, the decided
// dependency as each one's subcomponent — read back through the level
// join decides every finding it covers, and nothing it does not.
func TestPublishedDecisionsRoundTripTheWriter(t *testing.T) {
	decided := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)

	var coverage []vex.Coverage

	for _, product := range []string{"widget-pg14@1.0.0", "widget-pg15@1.0.0", "pkg:github/acme/widget@v1.0.0"} {
		coverage = append(coverage,
			vex.Coverage{
				Product: product, Subcomponent: "pkg:cargo/serde_cbor@0.11.2", Advisory: "RUSTSEC-2021-0127",
				Status: "not_affected", Justification: "vulnerable_code_not_present", Decided: decided,
			},
			vex.Coverage{
				Product: product, Subcomponent: "pkg:golang/github.com/masterminds/semver/v3@v3.5.0",
				Advisory: "GO-2026-0001", Status: "affected", ActionStatement: "upgrade", Decided: decided,
			},
		)
	}

	complete, err := vex.Cover(coverage, nil)
	if err != nil {
		t.Fatal(err)
	}

	doc, err := vex.Render(vex.Options{ID: "https://example.test/vex", Author: "acme", Released: decided}, complete)
	if err != nil {
		t.Fatal(err)
	}

	var rendered bytes.Buffer
	if err := doc.Encode(&rendered); err != nil {
		t.Fatal(err)
	}

	forge := &levelForge{files: map[string][]byte{"widget.vex.openvex.json": rendered.Bytes()}}

	var log bytes.Buffer

	decisions := publishedDecisions(&levelArgs{owner: "acme", name: "widget"}, forge, "v1.0.0",
		[]string{"widget.vex.openvex.json"}, &latch{w: &log})

	if log.Len() != 0 {
		t.Errorf("the writer's own document logged:\n%s", log.String())
	}

	// The scanner reports the module path as written; the join folds
	// it (docs/vex-join.md). The `affected` statement is a triage: the
	// rung asks Has, never Excuses.
	found, triaged := joinFindings(findingsReport(
		[4]string{"RUSTSEC-2021-0127", "serde_cbor", "0.11.2", "crates.io"},
		[4]string{"GO-2026-0001", "github.com/Masterminds/semver/v3", "v3.5.0", "Go"},
		[4]string{"RUSTSEC-2099-0001", "half", "1.8.2", "crates.io"},
	), decisions)

	if found != 3 || triaged != 2 {
		t.Errorf("found %d, triaged %d — want 3 and 2: both covered findings decided, the uncovered one not",
			found, triaged)
	}
}

// TestPublishedDecisionsLogsWhatCannotJoin: a statement whose deciding
// component is not a versioned purl is logged by name, the rest of the
// document still decides, and an unreadable document is logged and
// does not stop the next one being read.
func TestPublishedDecisionsLogsWhatCannotJoin(t *testing.T) {
	const (
		mixed = `{"@context":"https://openvex.dev/ns/v0.2.0","timestamp":"2026-08-12T00:00:00Z","statements":[` +
			`{"vulnerability":{"name":"RUSTSEC-2021-0127"},"status":"not_affected",` +
			`"products":[{"@id":"widget@1.0.0","subcomponents":[{"@id":"pkg:cargo/serde_cbor@0.11.2"}]}]},` +
			`{"vulnerability":{"name":"CVE-2026-0001"},"status":"not_affected",` +
			`"products":[{"@id":"widget@1.0.0"}]}]}`
		broken = `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"status":"not_affected"}]}`
	)

	forge := &levelForge{files: map[string][]byte{
		"a-broken.openvex.json": []byte(broken),
		"b-mixed.openvex.json":  []byte(mixed),
		"notes.txt":             []byte("not a decision"),
	}}

	var log bytes.Buffer

	decisions := publishedDecisions(&levelArgs{owner: "acme", name: "widget"}, forge, "v1.0.0",
		[]string{"a-broken.openvex.json", "notes.txt", "b-mixed.openvex.json", "missing.openvex.json"},
		&latch{w: &log})

	want := "level: triage document a-broken.openvex.json unreadable: vexjoin: a-broken.openvex.json:" +
		" statement 0 names no vulnerability\n" +
		"level: triage document b-mixed.openvex.json statement 1: product widget@1.0.0 is not a" +
		" versioned package URL\n"
	if log.String() != want {
		t.Errorf("log =\n%s\nwant\n%s", log.String(), want)
	}

	if !decisions.Has(vexjoin.KeyFromFinding("RUSTSEC-2021-0127", "crates.io", "serde_cbor", "0.11.2")) {
		t.Error("the joinable statement beside the unjoinable one decided nothing")
	}
}

// TestKeepReadsAPublishedDecisionPerDigest: the continuous gather
// reads an attested OpenVEX the same way. One document attested over
// every digest of a publish — the same decision, once per artifact —
// is one decided triple, never a contradiction, and a statement it
// cannot join is logged by the digest it was attested over.
func TestKeepReadsAPublishedDecisionPerDigest(t *testing.T) {
	const statement = `{"predicateType":"https://openvex.dev/ns/v0.2.0","predicate":` +
		`{"@context":"https://openvex.dev/ns/v0.2.0","timestamp":"2026-08-24T00:45:24Z","statements":[` +
		`{"vulnerability":{"name":"GHSA-loom"},"status":"not_affected",` +
		`"products":[{"@id":"loom@sha256:aaaa","subcomponents":[{"@id":"pkg:cargo/loom-core@0.1.0"}]}]},` +
		`{"vulnerability":{"name":"GHSA-other"},"status":"not_affected",` +
		`"products":[{"@id":"loom@sha256:aaaa"}]}]}}`

	bundle, verified := signedBy("decision", statement)
	measurer := scriptedMeasurer{proven: map[string]*trust.Verified{"decision": verified}}
	identity := regexp.MustCompile(streamSigner)

	held := stored{inventories: map[string][]byte{}, decisions: &vexjoin.Decisions{}}

	var log bytes.Buffer

	for _, digest := range []string{"sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("b", 64)} {
		held.keep(bundle, digest, identity, measurer, &latch{w: &log})
	}

	if held.decided != 2 {
		t.Errorf("decided = %d, want 2 — the second digest's copy of the decisions refused", held.decided)
	}

	if !held.decisions.Has(vexjoin.KeyFromFinding("GHSA-loom", "crates.io", "loom-core", "0.1.0")) {
		t.Error("the attested decision does not decide its subcomponent")
	}

	want := "level: triage document aaaaaaaaaaaa statement 1: product loom@sha256:aaaa is not a versioned" +
		" package URL\n" +
		"level: triage document bbbbbbbbbbbb statement 1: product loom@sha256:aaaa is not a versioned" +
		" package URL\n"
	if log.String() != want {
		t.Errorf("log =\n%s\nwant\n%s", log.String(), want)
	}
}
