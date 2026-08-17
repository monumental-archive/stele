// The blast-radius table: decided passes, undecided gates, the
// os/eco split with its fixable asymmetry, the canary, the stale
// decisions, and the loud faults (empty scan, unattested SBOM).

package assert_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

const blastPolicyJSON = `{
  "schema": 1,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "debtFile": "security/attestation-debt.txt",
    "classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}
  },
  "blastRadius": {
    "osEcosystems": ["debian", "alpine"],
    "canary": {"repo": "widget", "tag": "v1.0.0", "advisory": "RUSTSEC-2021-0127"}
  }
}`

const sbomContent = `{"spdxVersion": "SPDX-2.3"}`

// scanResult renders one osv-scanner report with one finding. The
// advisory is always the canary so each row satisfies the canary and
// isolates its own axis.
//
//nolint:unparam // the fixed advisory is the point, see above
func scanResult(advisory, pkg, version, ecosystem string, fix bool) string {
	fixed := ""
	if fix {
		fixed = `{"fixed": "` + version + `-fixed"}`
	}

	return `{"results": [{"packages": [{
	  "package": {"name": "` + pkg + `", "version": "` + version + `", "ecosystem": "` + ecosystem + `"},
	  "vulnerabilities": [{"id": "` + advisory + `",
	    "affected": [{"ranges": [{"events": [` + fixed + `]}]}]}]}]}]}`
}

type fakeScanner struct {
	out string
	err error
}

func (f fakeScanner) Scan([]byte) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}

	return []byte(f.out), nil
}

// blastForge scripts one release of widget carrying an attested SBOM.
func blastForge() *fakeForge {
	return &fakeForge{
		repos:  []string{"widget"},
		tags:   map[string][]string{"widget": {"v1.0.0"}},
		assets: map[string][]string{"widget@v1.0.0": {"app.spdx.json"}},
		assetBytes: map[string]map[string]string{
			"widget@v1.0.0": {"app.spdx.json": sbomContent},
		},
		store: map[string][]string{chain.SHA256Hex([]byte(sbomContent)): {`{"bundle": 1}`}},
	}
}

func decided(t *testing.T, advisory, pkg, version string) *vexjoin.Decisions {
	t.Helper()

	d := &vexjoin.Decisions{}
	doc := `{"statements": [{"vulnerability": {"name": "` + advisory + `"},
	  "products": [{"@id": "pkg:cargo/` + pkg + `@` + version + `"}]}]}`

	if err := vexjoin.Parse(d, []byte(doc), "test.openvex.json"); err != nil {
		t.Fatal(err)
	}

	return d
}

func runBlast(t *testing.T, f *fakeForge, scanner osv.Scanner, d *vexjoin.Decisions) *report.Report {
	t.Helper()

	pol, err := assert.LoadPolicy(strings.NewReader(blastPolicyJSON))
	if err != nil {
		t.Fatal(err)
	}

	rep, err := assert.BlastRadius(pol, "acme", f, scanner, d, func(string, ...any) {})
	if err != nil {
		t.Fatalf("BlastRadius: %v", err)
	}

	return rep
}

// The canary advisory doubles as the scripted finding in most rows,
// so the canary is satisfied and the row under test is isolated.
const canaryScan = `RUSTSEC-2021-0127`

func TestBlastRadiusVerdicts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		scan      string
		decisions *vexjoin.Decisions
		want      report.Verdict
	}{
		{
			"a decided finding passes",
			scanResult(canaryScan, "serde_cbor", "0.11.2", "crates.io", false),
			decided(t, canaryScan, "serde_cbor", "0.11.2"),
			report.VerdictPass,
		},
		{
			"an undecided ecosystem finding gates",
			scanResult(canaryScan, "serde_cbor", "0.11.2", "crates.io", false),
			&vexjoin.Decisions{},
			report.VerdictFail,
		},
		{
			"a decision for another version does not extend",
			scanResult(canaryScan, "serde_cbor", "0.11.3", "crates.io", false),
			decided(t, canaryScan, "serde_cbor", "0.11.2"),
			report.VerdictFail,
		},
		{
			"an unfixed OS package is the rebuild cadence's input, not red",
			scanResult(canaryScan, "libssl", "1.1.1", "Debian:12", false),
			&vexjoin.Decisions{},
			report.VerdictPass,
		},
		{
			"an OS package WITH a shipped fix gates like everything else",
			scanResult(canaryScan, "libssl", "1.1.1", "Debian:12", true),
			&vexjoin.Decisions{},
			report.VerdictFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rep := runBlast(t, blastForge(), fakeScanner{out: tt.scan}, tt.decisions)
			if rep.Verdict() != tt.want {
				t.Fatalf("verdict = %s, want %s\nfindings: %+v", rep.Verdict(), tt.want, rep.Findings())
			}
		})
	}
}

func TestBlastRadiusCanaryMissed(t *testing.T) {
	t.Parallel()

	// A scan that never yields the canary advisory cannot see —
	// CANNOT_JUDGE even though nothing gated.
	rep := runBlast(t, blastForge(),
		fakeScanner{out: `{"results": []}`}, &vexjoin.Decisions{})
	if rep.Verdict() != report.VerdictCannotJudge {
		t.Fatalf("verdict = %s, want CANNOT_JUDGE for the missed canary", rep.Verdict())
	}
}

func TestBlastRadiusLoudFaults(t *testing.T) {
	t.Parallel()

	t.Run("an unattested SBOM reddens before scanning", func(t *testing.T) {
		t.Parallel()

		f := blastForge()
		f.store = nil

		rep := runBlast(t, f, fakeScanner{out: `{"results": []}`}, &vexjoin.Decisions{})
		if rep.Verdict() == report.VerdictPass {
			t.Fatal("an SBOM the store does not vouch for passed")
		}

		found := false

		for _, fd := range rep.Findings() {
			if strings.Contains(fd.Assertion, "unattested") {
				found = true
			}
		}

		if !found {
			t.Fatalf("no unattested finding: %+v", rep.Findings())
		}
	})

	t.Run("a zero-package scan reddens rather than reporting clean", func(t *testing.T) {
		t.Parallel()

		rep := runBlast(t, blastForge(), fakeScanner{err: osv.ErrZeroPackages}, &vexjoin.Decisions{})
		if rep.Verdict() == report.VerdictPass {
			t.Fatal("a scan that read nothing reported clean")
		}
	})

	t.Run("zero SBOMs scanned cannot judge", func(t *testing.T) {
		t.Parallel()

		f := blastForge()
		f.assets = map[string][]string{"widget@v1.0.0": {"whatever.tar.gz"}}

		rep := runBlast(t, f, fakeScanner{out: `{"results": []}`}, &vexjoin.Decisions{})
		if rep.Verdict() != report.VerdictCannotJudge {
			t.Fatalf("verdict = %s, want CANNOT_JUDGE", rep.Verdict())
		}
	})
}

// TestBlastRadiusStaleDecision pins the retirement rule: a decision
// matching no current finding is carried as a stale exception, and
// the verdict is untouched by it.
func TestBlastRadiusStaleDecision(t *testing.T) {
	t.Parallel()

	d := decided(t, "RUSTSEC-2000-0001", "gone_pkg", "0.0.1")
	extra := decided(t, canaryScan, "serde_cbor", "0.11.2")

	for _, dec := range extra.All() {
		doc := `{"statements": [{"vulnerability": {"name": "` + dec.Key.Advisory + `"},
		  "products": [{"@id": "pkg:cargo/` + dec.Key.Package + `@` + dec.Key.Version + `"}]}]}`
		if err := vexjoin.Parse(d, []byte(doc), dec.Origin); err != nil {
			t.Fatal(err)
		}
	}

	rep := runBlast(t, blastForge(),
		fakeScanner{out: scanResult(canaryScan, "serde_cbor", "0.11.2", "crates.io", false)}, d)
	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS with the stale decision listed", rep.Verdict())
	}
}

// TestBlastRadiusPolicyRefusals pins the section's own guards.
func TestBlastRadiusPolicyRefusals(t *testing.T) {
	t.Parallel()

	empty := strings.Replace(blastPolicyJSON, `"osEcosystems": ["debian", "alpine"]`, `"osEcosystems": []`, 1)
	if _, err := assert.LoadPolicy(strings.NewReader(empty)); err == nil ||
		!strings.Contains(err.Error(), "osEcosystems") {
		t.Fatalf("error = %v, want the empty-ecosystems refusal", err)
	}

	partial := strings.Replace(blastPolicyJSON, `"repo": "widget", `, "", 1)
	if _, err := assert.LoadPolicy(strings.NewReader(partial)); err == nil ||
		!strings.Contains(err.Error(), "canary") {
		t.Fatalf("error = %v, want the incomplete-canary refusal", err)
	}

	// A policy with no blastRadius section refuses the walk by name.
	noSection, err := assert.LoadPolicy(strings.NewReader(testPolicyJSON))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := assert.BlastRadius(noSection, "acme", blastForge(), fakeScanner{out: "{}"},
		&vexjoin.Decisions{}, func(string, ...any) {}); err == nil {
		t.Fatal("a policy with no blastRadius section did not refuse")
	}
}
