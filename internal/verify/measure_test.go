package verify_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/level"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

// fakeMeasurer stands in for the trust boundary: it proves nothing
// cryptographically and reports a scripted identity, which is exactly
// the seam the measurement walk needs — the walk's job is to read what
// was signed, and whether a signature is genuine is the trust layer's.
type fakeMeasurer struct {
	san string
	err error
}

func (f fakeMeasurer) MeasureBlob([]byte, string) (*trust.Verified, error) {
	if f.err != nil {
		return nil, f.err
	}

	san := f.san
	if san == "" {
		san = "https://github.com/acme/widget/.github/workflows/attest.yml@refs/heads/main"
	}

	return &trust.Verified{SAN: san}, nil
}

func (f fakeMeasurer) MeasureAttestation(b []byte, d string) (*trust.Verified, error) {
	return f.MeasureBlob(b, d)
}

func measure(t *testing.T, h fakeHistory, m verify.Measurer) (*verify.Measured, error) {
	t.Helper()

	return verify.MeasureChain(
		verify.Coords{Owner: "acme", Repo: "widget"}, "refs/heads/main", h, m, func(string, ...any) {})
}

// TestMeasureChainAssertsNoIdentity is the point of the measurement
// walk: it reports who signed rather than demanding it, so a stranger
// gets an answer without first being told what to expect.
func TestMeasureChainAssertsNoIdentity(t *testing.T) {
	t.Parallel()

	const stranger = "https://gitlab.example/someone/else/.gitlab-ci.yml@refs/heads/trunk"

	got, err := measure(t, defaultChain(t), fakeMeasurer{san: stranger})
	if err != nil {
		t.Fatalf("MeasureChain = %v — an unfamiliar signer is a fact to report, not a refusal", err)
	}

	if signers := got.Signers(); len(signers) != 1 || signers[0] != stranger {
		t.Errorf("Signers = %v, want the identity read from the certificate", signers)
	}

	if got.Links() != 2 || !got.ReachedGenesis() {
		t.Errorf("Links = %d, genesis = %v — want the whole chain walked", got.Links(), got.ReachedGenesis())
	}

	tip, ok := got.Tip()
	if !ok || !tip.HasProperty("ORG_SOURCE_GATED") {
		t.Errorf("the tip's controls did not read back: %v", tip)
	}
}

// TestMeasureChainRefusals: every guard, and the one that must be a
// sentinel because the judge treats it as a level rather than a fault.
func TestMeasureChainRefusals(t *testing.T) {
	t.Parallel()

	t.Run("a branch with no links is the no-chain sentinel", func(t *testing.T) {
		t.Parallel()

		h := fakeHistory{
			tips:    map[string]string{"refs/heads/main": revC2},
			parents: map[string]string{revC2: revC1},
			notes:   map[string][]byte{},
		}

		_, err := measure(t, h, fakeMeasurer{})
		if !errors.Is(err, verify.ErrNoChain) {
			t.Errorf("MeasureChain = %v, want ErrNoChain — the judge reads this as level zero, not as a fault", err)
		}
	})

	t.Run("a half that does not verify refuses", func(t *testing.T) {
		t.Parallel()

		_, err := measure(t, defaultChain(t), fakeMeasurer{err: errors.New("no such signature")})
		if err == nil || !strings.Contains(err.Error(), "did not verify") {
			t.Errorf("MeasureChain = %v, want the verification refusal", err)
		}
	})

	t.Run("a malformed ref refuses before any read", func(t *testing.T) {
		t.Parallel()

		_, err := verify.MeasureChain(
			verify.Coords{Owner: "acme", Repo: "widget"}, "main", defaultChain(t),
			fakeMeasurer{}, func(string, ...any) {})
		if err == nil || !strings.Contains(err.Error(), "fully qualified") {
			t.Errorf("MeasureChain = %v, want the ref refusal", err)
		}
	})

	t.Run("implausible coordinates refuse", func(t *testing.T) {
		t.Parallel()

		_, err := verify.MeasureChain(
			verify.Coords{Owner: "", Repo: ""}, "refs/heads/main", defaultChain(t),
			fakeMeasurer{}, func(string, ...any) {})
		if err == nil || !strings.Contains(err.Error(), "plausible repository") {
			t.Errorf("MeasureChain = %v, want the coordinate refusal", err)
		}
	})

	t.Run("an unreadable tip refuses", func(t *testing.T) {
		t.Parallel()

		h := defaultChain(t)
		h.tipErr = errors.New("the ref is gone")

		if _, err := measure(t, h, fakeMeasurer{}); err == nil {
			t.Error("MeasureChain accepted a branch whose tip could not be resolved")
		}
	})
}

// TestMeasureChainRecordsHoles: a revision between links carrying none
// is the gap a continuity claim has to answer for, and the walk
// reports it rather than refusing — measurement describes, and the
// judge decides what the description is worth.
func TestMeasureChainRecordsHoles(t *testing.T) {
	t.Parallel()

	w := chainWorld{t: t}
	genesis := w.note(3,
		w.linkStmt(revC1, "ledgerPrev", nil, []string{"ORG_SOURCE_GATED"}, false),
		w.vsaStmt(revC1, []any{"SLSA_SOURCE_LEVEL_3"}))
	tip := w.note(3,
		w.linkStmt(revC3, "ledgerPrev", map[string]any{
			"revision": revC1, "noteSha256": digestHex(genesis),
		}, []string{"ORG_SOURCE_GATED"}, false),
		w.vsaStmt(revC3, []any{"SLSA_SOURCE_LEVEL_3"}))

	// revC2 sits between the two links and carries nothing.
	h := fakeHistory{
		tips:    map[string]string{"refs/heads/main": revC3},
		parents: map[string]string{revC3: revC2, revC2: revC1},
		notes:   map[string][]byte{revC3: tip, revC1: genesis},
	}

	got, err := measure(t, h, fakeMeasurer{})
	if err != nil {
		t.Fatalf("MeasureChain = %v", err)
	}

	if holes := got.Holes(); len(holes) != 1 || holes[0] != revC2 {
		t.Errorf("Holes = %v, want the unattested revision between links", holes)
	}
}

// TestMeasuredChainReachesSourceLevelThree is the end-to-end answer to
// "can a consumer establish Source L3 from evidence". The chain is
// built by the same world the walk tests use, measured with no
// expected identity, and judged with no policy.
func TestMeasuredChainReachesSourceLevelThree(t *testing.T) {
	t.Parallel()

	const rev = revC2

	// The controls the SCS recorded at this revision, in the
	// ecosystem's vocabulary.
	controls := []string{
		"SLSA_SOURCE_ORG_ACCESS_CONTROL",
		"SLSA_SOURCE_SCS_PROTECTED_REFS",
	}

	w := chainWorld{t: t}
	genesis := w.note(3,
		w.linkStmt(revC1, "ledgerPrev", nil, controls, false),
		w.vsaStmt(revC1, []any{"SLSA_SOURCE_LEVEL_3"}))
	tip := w.note(3,
		w.linkStmt(rev, "ledgerPrev", map[string]any{
			"revision": revC1, "noteSha256": digestHex(genesis),
		}, controls, false),
		w.vsaStmt(rev, []any{"SLSA_SOURCE_LEVEL_3"}))

	measured, err := measure(t, fakeHistory{
		tips:    map[string]string{"refs/heads/main": rev},
		parents: map[string]string{rev: revC1},
		notes:   map[string][]byte{rev: tip, revC1: genesis},
	}, fakeMeasurer{})
	if err != nil {
		t.Fatalf("MeasureChain = %v", err)
	}

	a := level.Assess(level.TrackSource, &level.Evidence{
		Owner: "acme", Repo: "widget", Ref: "refs/heads/main",
		Measured:  measured,
		Revisions: []level.Revision{{ID: rev, Subject: "feat: one", Parents: 1}},
		Live:      &level.LiveRules{Restrictive: true, ForcePushBlocked: true},
		Now:       time.Unix(0, 0).UTC(),
	})

	if got := a.Level(); got != "SLSA_SOURCE_LEVEL_3" {
		t.Errorf("level = %q, want SLSA_SOURCE_LEVEL_3\n%s", got, a.Ladder())
	}

	// Level 4 is not claimed by these controls and no approvals were
	// read, so it must be undetermined rather than either answer.
	for _, r := range a.Rungs() {
		if r.Level == 4 && r.Determination != level.Undetermined {
			t.Errorf("level 4 = %q, want UNDETERMINED: %s", r.Determination, r.Reason)
		}
	}
}

// TestMeasuredChainDrivesTheSourceLadder walks the source detectors
// against real measured chains, one broken fact per row. These live
// here because only this package can build a Measured: its fields are
// unexported and the walk is its one constructor, so a foreign package
// cannot hand the judge a chain nobody proved.
func TestMeasuredChainDrivesTheSourceLadder(t *testing.T) {
	t.Parallel()

	build := func(t *testing.T, controls []string, repaired, hole bool) *verify.Measured {
		t.Helper()

		w := chainWorld{t: t}
		genesis := w.note(3,
			w.linkStmt(revC1, "ledgerPrev", nil, controls, false),
			w.vsaStmt(revC1, []any{"SLSA_SOURCE_LEVEL_3"}))

		tipRev, parents := revC2, map[string]string{revC2: revC1}
		if hole {
			// revC2 sits between the links and carries nothing.
			tipRev, parents = revC3, map[string]string{revC3: revC2, revC2: revC1}
		}

		tip := w.note(3,
			w.linkStmt(tipRev, "ledgerPrev", map[string]any{
				"revision": revC1, "noteSha256": digestHex(genesis),
			}, controls, repaired),
			w.vsaStmt(tipRev, []any{"SLSA_SOURCE_LEVEL_3"}))

		got, err := measure(t, fakeHistory{
			tips:    map[string]string{"refs/heads/main": tipRev},
			parents: parents,
			notes:   map[string][]byte{tipRev: tip, revC1: genesis},
		}, fakeMeasurer{})
		if err != nil {
			t.Fatalf("MeasureChain = %v", err)
		}

		return got
	}

	const (
		access    = "SLSA_SOURCE_ORG_ACCESS_CONTROL"
		review    = "SLSA_SOURCE_SCS_TWO_PARTY_REVIEW"
		unrelated = "ORG_SOURCE_GATED"
	)

	// The forge's own live answer, corroborating everything a link
	// could record; rows below vary it to pin the anti-self-attestation
	// rule.
	corroborating := &level.LiveRules{Restrictive: true, ForcePushBlocked: true, RequiredApprovals: 1}

	for _, tt := range []struct {
		name     string
		controls []string
		live     *level.LiveRules
		repaired bool
		hole     bool
		want     string
	}{
		{
			name:     "recorded controls corroborated by the forge reach level three",
			controls: []string{access},
			live:     corroborating,
			want:     "SLSA_SOURCE_LEVEL_3",
		},
		{
			name:     "the review control the SCS recorded reaches level four",
			controls: []string{access, review},
			live:     corroborating,
			want:     "SLSA_SOURCE_LEVEL_4",
		},
		{
			// THE rule this verb exists for: a chain the repository
			// signed about itself, claiming every control there is,
			// mints nothing when the forge's own rules were not read.
			// Self-attestation must not become a level.
			name:     "recorded controls without the forge's corroboration mint nothing",
			controls: []string{access, review},
			live:     nil,
			want:     "SLSA_SOURCE_LEVEL_1",
		},
		{
			// And a forge that answers "nothing is restricted" leaves a
			// grand record equally unproven.
			name:     "a record the forge's rules do not back stays unproven",
			controls: []string{access, review},
			live:     &level.LiveRules{Restrictive: false},
			want:     "SLSA_SOURCE_LEVEL_1",
		},
		{
			name:     "a repaired tip records a lapse, so continuity does not hold",
			controls: []string{access},
			live:     corroborating,
			repaired: true,
			want:     "SLSA_SOURCE_LEVEL_1",
		},
		{
			name:     "a revision between links carrying none is a lapse",
			controls: []string{access},
			live:     corroborating,
			hole:     true,
			want:     "SLSA_SOURCE_LEVEL_1",
		},
		{
			// An organisation's own control names establish the
			// requirement: the specification asks that access controls
			// be configured, not that they be spelled a particular way.
			name:     "an organisation's own control names still establish the category",
			controls: []string{unrelated},
			live:     corroborating,
			want:     "SLSA_SOURCE_LEVEL_3",
		},
		{
			name:     "a link recording no control at all bounds the track at one",
			controls: nil,
			live:     corroborating,
			want:     "SLSA_SOURCE_LEVEL_1",
		},
	} {
		a := level.Assess(level.TrackSource, &level.Evidence{
			Owner: "acme", Repo: "widget", Ref: "refs/heads/main",
			Measured:  build(t, tt.controls, tt.repaired, tt.hole),
			Revisions: []level.Revision{{ID: revC2, Subject: "feat: one", Parents: 1}},
			Live:      tt.live,
			Now:       time.Unix(0, 0).UTC(),
		})

		if got := a.Level(); got != tt.want {
			t.Errorf("%s: level = %q, want %q\n%s", tt.name, got, tt.want, a.Ladder())
		}
	}
}

// TestControlNamesFromAForeignControlPlane: a chain whose SCS prefixes
// its controls differently must still read, because the specification
// leaves the prefix to the SCS and a consumer that only understood one
// spelling could only read its own chains.
func TestControlNamesFromAForeignControlPlane(t *testing.T) {
	t.Parallel()

	w := chainWorld{t: t}
	foreign := []string{"ORG_SOURCE_ACCESS_CONTROL"}

	genesis := w.note(3,
		w.linkStmt(revC1, "ledgerPrev", nil, foreign, false),
		w.vsaStmt(revC1, []any{"SLSA_SOURCE_LEVEL_3"}))
	tip := w.note(3,
		w.linkStmt(revC2, "ledgerPrev", map[string]any{
			"revision": revC1, "noteSha256": digestHex(genesis),
		}, foreign, false),
		w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"}))

	measured, err := measure(t, fakeHistory{
		tips:    map[string]string{"refs/heads/main": revC2},
		parents: map[string]string{revC2: revC1},
		notes:   map[string][]byte{revC2: tip, revC1: genesis},
	}, fakeMeasurer{})
	if err != nil {
		t.Fatalf("MeasureChain = %v", err)
	}

	a := level.Assess(level.TrackSource, &level.Evidence{
		Owner: "acme", Repo: "widget", Ref: "refs/heads/main",
		Measured:  measured,
		Revisions: []level.Revision{{ID: revC2, Subject: "feat: one", Parents: 1}},
		Live:      &level.LiveRules{Restrictive: true, ForcePushBlocked: true},
		Now:       time.Unix(0, 0).UTC(),
	})

	if got := a.Level(); got != "SLSA_SOURCE_LEVEL_3" {
		t.Errorf("level = %q, want level three from a foreign control spelling\n%s", got, a.Ladder())
	}
}
