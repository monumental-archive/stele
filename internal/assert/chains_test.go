// The chain audit's table (stele#94): the population rule, the
// declared-exception contract, the founded/unactivated boundary, and
// the one structural guarantee worth its own case — an opt-out can
// never excuse a founded chain that fails to verify.

package assert_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/report"
)

const chainsPolicyJSON = `{
  "schema": 4,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "debtFile": "security/attestation-debt.txt",
    "classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}
  },
  "chains": {
    "exceptions": [{"repo": "lab", "reason": "lab-first activation, tracked in acme#1"}]
  }
}`

func loadChainsPolicy(t *testing.T) *assert.Policy {
	t.Helper()

	p, err := assert.LoadPolicy(strings.NewReader(chainsPolicyJSON))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	return p
}

// fakeChainVerifier scripts the verification seam per repo.
type fakeChainVerifier struct {
	links  map[string]int   // repo → links
	broken map[string]error // repo → refusal
	calls  []string
}

func (v *fakeChainVerifier) Verify(_, repo, ref string) (int, error) {
	v.calls = append(v.calls, repo+" "+ref)

	if err := v.broken[repo]; err != nil {
		return 0, err
	}

	return v.links[repo], nil
}

const (
	notesRef = "refs/notes/commits"
	mainRef  = "refs/heads/main"
)

// chainNotes builds one repo's notes map entry: a link-shaped note.
func linkNotes() []gh.ChainNote {
	return []gh.ChainNote{{Rev: linkedRev, Note: []byte(link)}}
}

func runChains(
	t *testing.T, pol *assert.Policy, pop assert.Population, forge *fakeForge, tags *fakeTags,
	cv *fakeChainVerifier,
) (*report.Report, error) {
	t.Helper()

	return assert.Chains(pol, pop, forge, tags, cv, notesRef, []string{mainRef}, func(string, ...any) {})
}

func TestChainsVerifiedPopulation(t *testing.T) {
	t.Parallel()

	forge := &fakeForge{repos: []string{"widget", "lab"}}
	tags := &fakeTags{notes: map[string][]gh.ChainNote{"widget": linkNotes()}}
	cv := &fakeChainVerifier{links: map[string]int{"widget": 3}}

	rep, err := runChains(t, loadChainsPolicy(t), assert.Population{Org: "acme"}, forge, tags, cv)
	if err != nil {
		t.Fatalf("Chains = %v", err)
	}

	// widget verifies; lab is unactivated but declared. PASS, with the
	// excuse visible in the document rather than silent.
	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, want PASS: %+v", rep.Verdict(), rep.Findings())
	}

	if len(cv.calls) != 1 || cv.calls[0] != "widget "+mainRef {
		t.Fatalf("verifier calls = %v, want the founded repo alone on the protected ref", cv.calls)
	}
}

func TestChainsUnactivatedWithoutExceptionIsRed(t *testing.T) {
	t.Parallel()

	forge := &fakeForge{repos: []string{"widget", "gadget"}}
	tags := &fakeTags{notes: map[string][]gh.ChainNote{"widget": linkNotes()}}
	cv := &fakeChainVerifier{links: map[string]int{"widget": 1}}

	rep, err := runChains(t, loadChainsPolicy(t), assert.Population{Org: "acme"}, forge, tags, cv)
	if err != nil {
		t.Fatalf("Chains = %v", err)
	}

	if rep.Verdict() != report.VerdictFail {
		t.Fatalf("verdict = %s, want FAIL — an unactivated repo with no declared exception is a finding", rep.Verdict())
	}

	findings := rep.Findings()
	if len(findings) != 1 || findings[0].Subject != "acme/gadget" || findings[0].Assertion != "unactivated" {
		t.Fatalf("findings = %+v, want the unactivated finding on acme/gadget", findings)
	}
}

func TestChainsOptOutCannotExcuseABrokenChain(t *testing.T) {
	t.Parallel()

	// lab HAS founded a chain — and it fails to verify. The declared
	// opt-out matches the subject but carries the unactivated
	// assertion alone, so the defect stays red and the excuse goes
	// stale, both visible.
	forge := &fakeForge{repos: []string{"lab"}}
	tags := &fakeTags{notes: map[string][]gh.ChainNote{"lab": linkNotes()}}
	cv := &fakeChainVerifier{broken: map[string]error{"lab": errors.New("link 2: signature refused")}}

	rep, err := runChains(t, loadChainsPolicy(t), assert.Population{Org: "acme"}, forge, tags, cv)
	if err != nil {
		t.Fatalf("Chains = %v", err)
	}

	if rep.Verdict() != report.VerdictFail {
		t.Fatalf("verdict = %s, want FAIL — an opt-out excuses absence, never a defect", rep.Verdict())
	}

	findings := rep.Findings()
	if len(findings) != 1 || findings[0].Assertion != "chains" ||
		!strings.Contains(findings[0].Detail, "signature refused") {
		t.Fatalf("findings = %+v, want the chain defect carried through", findings)
	}
}

func TestChainsScaffoldingNotesAreNotAFoundedChain(t *testing.T) {
	t.Parallel()

	// Notes exist but none is link-shaped: unactivated, and the
	// engine is never asked to walk what is not there.
	forge := &fakeForge{repos: []string{"gadget"}}
	tags := &fakeTags{notes: map[string][]gh.ChainNote{
		"gadget": {{Rev: linkedRev, Note: []byte(`{"scaffold": true}`)}},
	}}
	cv := &fakeChainVerifier{}

	rep, err := runChains(t, loadChainsPolicy(t), assert.Population{Org: "acme"}, forge, tags, cv)
	if err != nil {
		t.Fatalf("Chains = %v", err)
	}

	if rep.Verdict() != report.VerdictFail {
		t.Fatalf("verdict = %s, want FAIL", rep.Verdict())
	}

	if len(cv.calls) != 0 {
		t.Fatalf("verifier calls = %v, want none — absence is judged before the engine", cv.calls)
	}
}

func TestChainsZeroPopulationCannotJudge(t *testing.T) {
	t.Parallel()

	// The 2026-08-17 outage shape: the listing answers, and answers
	// nothing. Refusing to judge is the only honest verdict.
	forge := &fakeForge{repos: nil}

	rep, err := runChains(t, loadChainsPolicy(t), assert.Population{Org: "acme"}, forge, &fakeTags{},
		&fakeChainVerifier{})
	if err != nil {
		t.Fatalf("Chains = %v", err)
	}

	if rep.Verdict() != report.VerdictCannotJudge {
		t.Fatalf("verdict = %s, want CANNOT_JUDGE over an empty listing", rep.Verdict())
	}
}

func TestChainsRefusals(t *testing.T) {
	t.Parallel()

	pol := loadChainsPolicy(t)

	noSection, err := assert.LoadPolicy(strings.NewReader(strings.Replace(chainsPolicyJSON,
		`"chains": {
    "exceptions": [{"repo": "lab", "reason": "lab-first activation, tracked in acme#1"}]
  }`, `"chains": {"exceptions": []}`, 1)))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	noSection.Chains = nil

	for _, tc := range []struct {
		name     string
		pol      *assert.Policy
		notesRef string
		refs     []string
		want     string
	}{
		{
			name: "no chains section", pol: noSection, notesRef: notesRef, refs: []string{mainRef},
			want: "no chains section",
		},
		{name: "no notes ref", pol: pol, notesRef: "", refs: []string{mainRef}, want: "notes ref"},
		{name: "no protected branches", pol: pol, notesRef: notesRef, refs: nil, want: "protected branch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, rerr := assert.Chains(tc.pol, assert.Population{Org: "acme"}, &fakeForge{repos: []string{"widget"}},
				&fakeTags{}, &fakeChainVerifier{}, tc.notesRef, tc.refs, func(string, ...any) {})
			if rerr == nil || !strings.Contains(rerr.Error(), tc.want) {
				t.Fatalf("Chains = %v, want a refusal naming %q", rerr, tc.want)
			}
		})
	}
}

func TestChainsNotesTearRefusesTheWalk(t *testing.T) {
	t.Parallel()

	tags := &fakeTags{torn: map[string]error{"ChainNotes": errTorn}}

	_, err := assert.Chains(loadChainsPolicy(t), assert.Population{Org: "acme"},
		&fakeForge{repos: []string{"widget"}}, tags, &fakeChainVerifier{}, notesRef, []string{mainRef},
		func(string, ...any) {})
	if err == nil || !errors.Is(err, errTorn) {
		t.Fatalf("Chains = %v, want the tear carried out — partial sight is never a verdict", err)
	}
}

func TestChainsListingTearRefusesTheWalk(t *testing.T) {
	t.Parallel()

	forge := &fakeForge{reposErr: errTorn}

	_, err := assert.Chains(loadChainsPolicy(t), assert.Population{Org: "acme"}, forge, &fakeTags{},
		&fakeChainVerifier{}, notesRef, []string{mainRef}, func(string, ...any) {})
	if err == nil || !errors.Is(err, errTorn) {
		t.Fatalf("Chains = %v, want the listing tear", err)
	}
}

func TestChainsPolicyValidation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		section string
		want    string
	}{
		{
			name: "empty repo", section: `{"exceptions": [{"repo": "", "reason": "r"}]}`,
			want: "repo is absent or empty",
		},
		{
			name: "missing reason", section: `{"exceptions": [{"repo": "lab", "reason": ""}]}`,
			want: "reason is absent or empty",
		},
		{
			name:    "duplicate repo",
			section: `{"exceptions": [{"repo": "lab", "reason": "a"}, {"repo": "lab", "reason": "b"}]}`,
			want:    "twice",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc := strings.Replace(chainsPolicyJSON,
				`{
    "exceptions": [{"repo": "lab", "reason": "lab-first activation, tracked in acme#1"}]
  }`, tc.section, 1)

			_, err := assert.LoadPolicy(strings.NewReader(doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadPolicy = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
}
