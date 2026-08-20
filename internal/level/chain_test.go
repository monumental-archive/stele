// The source track measured from a real chain.
//
// Every detector in detect_source.go is a pure function of an
// Evidence, and the field that decides almost all of them is
// Measured — the source chain as the measurement walk found it. There
// is no constructor for one: it comes out of verify.MeasureChain and
// nowhere else, deliberately, so a chain the walk would refuse cannot
// be handed to a judge. That is the right design and it is why these
// tests build chains rather than structs.
//
// The fixture is deliberately minimal. The walk's cryptography lives
// behind the Measurer seam, and the stand-in here proves nothing and
// reports a scripted signer — which is exactly the seam's purpose,
// because whether a signature is genuine is internal/trust's question
// and is answered against real signed material there. What is left is
// the note FORMAT and the walk's structural reading, and those are
// what the source ladder actually turns on: a chain that reaches
// genesis, a chain that does not, one carrying a lapse, one whose
// links record no control, one nobody signed.

package level_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/level"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

const (
	revTip     = "2222222222222222222222222222222222222222"
	revGenesis = "1111111111111111111111111111111111111111"
	revMiddle  = "3333333333333333333333333333333333333333"

	sourceRef      = "refs/heads/main"
	sourcePredType = "https://acme.example/attestations/source-provenance/v1"
	vsaPredType    = "https://slsa.dev/verification_summary/v1"
	statementType  = "application/vnd.in-toto+json"

	linkSigner = "https://github.com/acme/widget/.github/workflows/source-attest.yml@refs/heads/main"
	gatedProp  = "ORG_SOURCE_GATED"
)

// chainHistory is the object store the walk reads: a ref to its tip,
// a first-parent line, and a note per revision.
type chainHistory struct {
	tips    map[string]string
	parents map[string]string
	notes   map[string][]byte
}

func (h chainHistory) Tip(ref string) (string, error) {
	tip, ok := h.tips[ref]
	if !ok {
		return "", errors.New("no such ref " + ref)
	}

	return tip, nil
}

func (h chainHistory) Parent(rev string) (string, error) { return h.parents[rev], nil }

func (h chainHistory) Note(rev string) ([]byte, error) { return h.notes[rev], nil }

func (h chainHistory) Noted() ([]string, error) {
	out := make([]string, 0, len(h.notes))
	for rev := range h.notes {
		out = append(out, rev)
	}

	return out, nil
}

// scriptedSigner stands in for the trust boundary. It proves nothing
// and reports a scripted identity, which is the seam's whole point:
// the walk's job is to read WHAT was signed, and whether a signature
// is genuine belongs to internal/trust, where it is answered against
// real signed material rather than a fixture.
type scriptedSigner struct{ san string }

func (s scriptedSigner) MeasureBlob([]byte, string) (*trust.Verified, error) {
	return &trust.Verified{SAN: s.san}, nil
}

func (s scriptedSigner) MeasureAttestation(b []byte, d string) (*trust.Verified, error) {
	return s.MeasureBlob(b, d)
}

// linkOpts is one link's content — everything the source ladder reads
// out of a note.
type linkOpts struct {
	rev        string
	prev       string // "" means genesis
	controls   []string
	commitTime string
	repaired   bool
	levels     string // the VSA's verifiedLevels array body
}

// note renders one link. The bundle is a placeholder: the stand-in
// signer never looks at it, and the format only requires it to be
// present.
func note(o *linkOpts) []byte {
	ledger := "null"
	if o.prev != "" {
		ledger = `{"revision": "` + o.prev + `", "noteSha256": "` + strings.Repeat("a", 64) + `"}`
	}

	controls := make([]string, 0, len(o.controls))
	for _, c := range o.controls {
		controls = append(controls, `{"property": "`+c+`", "evidence": {}}`)
	}

	repaired := ""
	if o.repaired {
		repaired = `, "repaired": {"at": "2026-05-02T00:00:00Z"}`
	}

	when := o.commitTime
	if when == "" {
		when = "2026-05-01T12:00:00Z"
	}

	commitTime := `, "commitTime": "` + when + `"`
	if o.commitTime == "-" {
		commitTime = "" // the link records none at all
	}

	prov := `{"_type": "https://in-toto.io/Statement/v1",` +
		` "subject": [{"digest": {"gitCommit": "` + o.rev + `"}}],` +
		` "predicateType": "` + sourcePredType + `",` +
		` "predicate": {"repository": "acme/widget", "ref": "` + sourceRef + `"` + commitTime +
		`, "controls": [` + strings.Join(controls, ",") + `], "ledgerPrev": ` + ledger + repaired + `}}`

	levels := o.levels
	if levels == "" {
		levels = `"SLSA_SOURCE_LEVEL_3"`
	}

	vsa := `{"_type": "https://in-toto.io/Statement/v1",` +
		` "subject": [{"digest": {"gitCommit": "` + o.rev + `"}}],` +
		` "predicateType": "` + vsaPredType + `",` +
		` "predicate": {"verifier": {"id": "` + linkSigner + `"},` +
		` "resourceUri": "git+https://github.com/acme/widget",` +
		` "policy": {"uri": "https://github.com/acme/canon/tree/v1.0.0"},` +
		` "verificationResult": "PASSED", "verifiedLevels": [` + levels + `]}}`

	return []byte(`{"version": 3, "provenance": ` + half(prov) + `, "vsa": ` + half(vsa) + `}`)
}

// half wraps one statement as the note's envelope.
func half(statement string) string {
	return `{"payloadType": "` + statementType + `",` +
		` "statement": "` + base64.StdEncoding.EncodeToString([]byte(statement)) + `",` +
		` "bundle": {"unused": "the stand-in signer proves nothing"}}`
}

// measured walks the given links and returns what the walk found.
// signer empty means no link carries an attributable identity.
func measured(t *testing.T, signer string, links ...linkOpts) *verify.Measured {
	t.Helper()

	h := chainHistory{
		tips:    map[string]string{sourceRef: links[0].rev},
		parents: map[string]string{},
		notes:   map[string][]byte{},
	}

	for i, l := range links {
		h.notes[l.rev] = note(&l)
		if i+1 < len(links) {
			h.parents[l.rev] = links[i+1].rev
		}
	}

	got, err := verify.MeasureChain(
		verify.Coords{Owner: "acme", Repo: "widget"}, sourceRef, h,
		scriptedSigner{san: signer}, func(string, ...any) {})
	if err != nil {
		t.Fatalf("MeasureChain = %v", err)
	}

	return got
}

// wholeChain is the shape a repository running the org's controls
// has: two links, tip to genesis, each recording one control.
func wholeChain(t *testing.T) *verify.Measured {
	t.Helper()

	return measured(t, linkSigner,
		linkOpts{rev: revTip, prev: revGenesis, controls: []string{gatedProp}},
		linkOpts{rev: revGenesis, controls: []string{gatedProp}})
}

// sourceEvidence is one repository's source-track evidence over a
// measured chain, with the forge's live rules corroborating.
func sourceEvidence(m *verify.Measured, live *level.LiveRules) *level.Evidence {
	return &level.Evidence{
		Owner: "acme", Repo: "widget", Ref: sourceRef,
		Measured: m, Live: live, Now: epoch,
		Revisions: []level.Revision{
			{ID: revTip, Subject: "feat: the tip", Parents: 1, Time: epoch},
			{ID: revGenesis, Subject: "feat: the genesis", Parents: 0, Time: epoch},
		},
	}
}

// restrictive is the forge answering that the branch really is
// protected — the independent half every control rung needs.
func restrictive() *level.LiveRules {
	return &level.LiveRules{Restrictive: true, ForcePushBlocked: true, RequiredApprovals: 2}
}

// TestSourceLadderFromAWholeChain: the ladder a clean chain supports,
// and the sentences it rests on. A chain that walks tip to genesis is
// a cryptographic record that the branch only ever moved to
// descendants — that is the history requirement established from
// artifacts rather than from a settings read, and it is the claim
// this file exists to hold.
func TestSourceLadderFromAWholeChain(t *testing.T) {
	t.Parallel()

	a := level.Assess(level.TrackSource, sourceEvidence(wholeChain(t), restrictive()))
	doc := reasons(t, a)

	for _, want := range []string{
		// The chain itself, and what it proves about movement.
		"a chain of 2 link(s) records this branch from its genesis to its tip",
		"every revision from genesis to the tip carries a link, with no lapse recorded",
		"the branch moved only to descendants, so nothing was expunged",
		// The summary half, and the identity that signed the links.
		"a source verification summary attestation covers revision",
		linkSigner,
		// The controls, corroborated by the forge rather than taken on
		// the repository's own word.
		"the forge's effective rules corroborate",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the report does not carry %q:\n%s", want, doc)
		}
	}

	// A control rung held on the SCS's own record is marked as such, so
	// a reader can see which parts of a level rest on it.
	if !strings.Contains(doc, "HELD (attested)") {
		t.Errorf("no requirement is marked as resting on the SCS's record:\n%s", doc)
	}
}

// TestControlsNeedTheForgeToAgree is the corroboration law at the
// ladder. A chain link is emitted and signed by the repository's own
// workflow identity, so a record a subject issues about itself cannot
// alone establish the controls it names — that is self-attestation
// wearing a signature, and holding a level on it would let any
// repository mint its own.
func TestControlsNeedTheForgeToAgree(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		live *level.LiveRules
		want string
	}{
		{
			// Rules unreadable: not the same as a forge that answered
			// with no rules, and neither is a refutation.
			"rules that could not be read leave the control unevaluated",
			nil,
			"UNDETERMINED",
		},
		{
			// The forge says nothing restricts the branch while the
			// record claims controls. Rules legitimately change between
			// a revision landing and this run looking, so the honest
			// answer is undetermined rather than a refutation.
			"a forge that contradicts the record does not refute it",
			&level.LiveRules{},
			"UNDETERMINED",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := reasons(t, level.Assess(level.TrackSource, sourceEvidence(wholeChain(t), tt.live)))
			if !strings.Contains(doc, tt.want) {
				t.Errorf("the report does not carry %q:\n%s", tt.want, doc)
			}

			// And in neither case may a control rung be claimed.
			if strings.Contains(doc, "HELD (attested)") {
				t.Errorf("a control held without the forge corroborating it:\n%s", doc)
			}
		})
	}
}

// TestSourceLadderFromADegradedChain walks the shapes a real ledger
// takes when something went wrong. Each is a different fact about the
// branch, and the ladder must tell them apart — a chain that stops
// short, one that lapsed and recovered, one that lapsed at the tip,
// one nobody signed, one recording no control at all.
func TestSourceLadderFromADegradedChain(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		ev   func(t *testing.T) *level.Evidence
		want []string
	}{
		{
			// The genesis link is missing its ledger terminator, so the
			// walk reaches a link whose predecessor it cannot account
			// for: a partial record, not a founded branch.
			name: "a chain that does not reach a founding link",
			ev: func(t *testing.T) *level.Evidence {
				t.Helper()

				return sourceEvidence(measured(t, linkSigner,
					linkOpts{rev: revTip, prev: revGenesis, controls: []string{gatedProp}},
					linkOpts{rev: revGenesis, prev: revMiddle, controls: []string{gatedProp}},
				), restrictive())
			},
			want: []string{"does not run back to a founding link"},
		},
		{
			// A lapse the chain recovered from is not permanent damage:
			// the spec restarts continuity from a new revision, so what
			// a reader is owed is the date it restarted.
			name: "a chain that lapsed and has since run clean",
			ev: func(t *testing.T) *level.Evidence {
				t.Helper()

				return sourceEvidence(measured(t, linkSigner,
					linkOpts{rev: revTip, prev: revMiddle, controls: []string{gatedProp}},
					linkOpts{rev: revMiddle, prev: revGenesis, controls: []string{gatedProp}, repaired: true},
					linkOpts{rev: revGenesis, controls: []string{gatedProp}},
				), restrictive())
			},
			want: []string{"continuity is unbroken since revision", "restarted after a recorded"},
		},
		{
			// The lapse is the CURRENT revision: continuity has not yet
			// run for a single revision since it restarted.
			name: "a chain repaired at its own tip",
			ev: func(t *testing.T) *level.Evidence {
				t.Helper()

				return sourceEvidence(measured(t, linkSigner,
					linkOpts{rev: revTip, prev: revGenesis, controls: []string{gatedProp}, repaired: true},
					linkOpts{rev: revGenesis, controls: []string{gatedProp}},
				), restrictive())
			},
			want: []string{"the tip link is marked repaired", "have not yet run unbroken for any revision"},
		},
		{
			// A revision between two links carrying none: the controls
			// lapsed across it, whatever the links either side claim.
			// The walk reports the gap rather than refusing, and the
			// judge decides what the description is worth.
			name: "a chain with a revision between links carrying none",
			ev: func(t *testing.T) *level.Evidence {
				t.Helper()

				h := chainHistory{
					tips:    map[string]string{sourceRef: revTip},
					parents: map[string]string{revTip: revMiddle, revMiddle: revGenesis},
					notes: map[string][]byte{
						revTip: note(&linkOpts{rev: revTip, prev: revGenesis, controls: []string{gatedProp}}),
						// revMiddle carries no note: the hole.
						revGenesis: note(&linkOpts{rev: revGenesis, controls: []string{gatedProp}}),
					},
				}

				m, err := verify.MeasureChain(
					verify.Coords{Owner: "acme", Repo: "widget"}, sourceRef, h,
					scriptedSigner{san: linkSigner}, func(string, ...any) {})
				if err != nil {
					t.Fatalf("MeasureChain = %v", err)
				}

				return sourceEvidence(m, restrictive())
			},
			want: []string{"carry none, so the controls lapsed across them"},
		},
		{
			// Safe expunging is normally established from the chain
			// itself — git has no expunge operation, so a branch that
			// only ever moved to descendants had no path to one. Where
			// the chain cannot establish that, the recorded control is
			// the fallback, and the forge's force-push prohibition is
			// what corroborates it.
			name: "safe expunging falling back to the recorded control",
			ev: func(t *testing.T) *level.Evidence {
				t.Helper()

				const expunge = "ORG_SOURCE_SAFE_EXPUNGE"

				return sourceEvidence(measured(t, linkSigner,
					linkOpts{rev: revTip, prev: revGenesis, controls: []string{expunge}},
					linkOpts{rev: revGenesis, prev: revMiddle, controls: []string{expunge}},
				), restrictive())
			},
			want: []string{"the forge's effective rules corroborate"},
		},
		{
			name: "a chain whose links carry no certificate identity",
			ev: func(t *testing.T) *level.Evidence {
				t.Helper()

				return sourceEvidence(measured(t, "",
					linkOpts{rev: revTip, prev: revGenesis, controls: []string{gatedProp}},
					linkOpts{rev: revGenesis, controls: []string{gatedProp}},
				), restrictive())
			},
			want: []string{"no link carries a certificate identity, so no actor is attributable"},
		},
		{
			// The links exist and record nothing: there is no restriction
			// on sensitive operations to evidence, which the forge's
			// agreement cannot supply on its own.
			name: "a chain recording no control at all",
			ev: func(t *testing.T) *level.Evidence {
				t.Helper()

				return sourceEvidence(measured(t, linkSigner,
					linkOpts{rev: revTip, prev: revGenesis},
					linkOpts{rev: revGenesis},
				), restrictive())
			},
			want: []string{"records no control at revision", "no restriction on sensitive operations is evidenced"},
		},
		{
			name: "a tip link recording no commit time",
			ev: func(t *testing.T) *level.Evidence {
				t.Helper()

				return sourceEvidence(measured(t, linkSigner,
					linkOpts{rev: revTip, prev: revGenesis, controls: []string{gatedProp}, commitTime: "-"},
					linkOpts{rev: revGenesis, controls: []string{gatedProp}},
				), restrictive())
			},
			want: []string{"records no commit time, so contemporaneity cannot be judged"},
		},
		{
			name: "a tip link whose commit time cannot be read",
			ev: func(t *testing.T) *level.Evidence {
				t.Helper()

				return sourceEvidence(measured(t, linkSigner,
					linkOpts{
						rev: revTip, prev: revGenesis,
						controls: []string{gatedProp}, commitTime: "last tuesday",
					},
					linkOpts{rev: revGenesis, controls: []string{gatedProp}},
				), restrictive())
			},
			want: []string{"is unreadable"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := reasons(t, level.Assess(level.TrackSource, tt.ev(t)))
			for _, want := range tt.want {
				if !strings.Contains(doc, want) {
					t.Errorf("the report does not carry %q:\n%s", want, doc)
				}
			}
		})
	}
}

// TestTwoPartyReviewPrefersTheRecord: where the control plane attests
// that it enforced two-party review, that is the contemporaneous
// evidence and approvals visible today are a weaker echo of it. The
// review history is read only when the record does not settle the
// question — which is also what keeps a whole history walk off every
// run of a repository that records the control.
func TestTwoPartyReviewPrefersTheRecord(t *testing.T) {
	t.Parallel()

	m := measured(t, linkSigner,
		linkOpts{rev: revTip, prev: revGenesis, controls: []string{"ORG_SOURCE_TWO_PARTY_REVIEW"}},
		linkOpts{rev: revGenesis, controls: []string{"ORG_SOURCE_TWO_PARTY_REVIEW"}})

	// No Approvals map at all: the record plus the forge's live rules
	// must settle it without one.
	ev := sourceEvidence(m, restrictive())

	doc := reasons(t, level.Assess(level.TrackSource, ev))
	if !strings.Contains(doc, "two-party review") {
		t.Errorf("the record's two-party control was not read:\n%s", doc)
	}
}
