package emit_test

import (
	"bytes"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/dsse"
	"github.com/monumental-archive/stele/internal/emit"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

// The test org is acme — zero real org names. The proof bar for the
// emitter is the verify engine itself: everything Chain writes must
// walk clean under verify.Chain with the same policy, because an
// emitted link the walker refuses is the defect class this port
// exists to end.
const (
	issuer     = "https://token.actions.githubusercontent.com"
	sourceType = "https://acme.example/attestations/source-provenance/v1"
	identity   = "https://github.com/acme/widget/.github/workflows/source-attest.yml@refs/heads/main"

	machineryPin = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	policyURI    = "https://github.com/acme/canon/blob/" + machineryPin + "/slsa/verify-policy.json"

	rev1 = "1111111111111111111111111111111111111111"
	rev2 = "2222222222222222222222222222222222222222"
	rev3 = "3333333333333333333333333333333333333333"
	rev4 = "4444444444444444444444444444444444444444"
)

const policyJSON = `{
  "schema": 2,
  "issuer": "` + issuer + `",
  "trust": {
    "provenance": {"signerWorkflow": "acme/signer/.github/workflows/sign.yml"},
    "verdict": {"verifierWorkflow": "acme/canon/.github/workflows/verify-release.yml", "legacyVerdicts": []},
    "decision": {
      "signerWorkflow": "acme/canon/.github/workflows/publish.yml",
      "predicateType": "https://acme.example/attestations/release-decision/v1",
      "requiredConclusion": "OPEN"
    }
  },
  "build": {
    "buildTypes": {
      "https://actions.github.io/buildtypes/workflow/v1": {"externalParameterKeys": ["workflow", "inputs"]}
    },
    "resourceUri": "pkg:github/{owner}/{repo}@v{version}",
    "sourceRepository": "https://github.com/{owner}/{repo}",
    "targetLevel": "SLSA_BUILD_LEVEL_3",
    "denySelfHostedRunners": true
  },
  "source": {
    "identity": "https://github.com/{owner}/{repo}/.github/workflows/source-attest.yml@refs/heads/main",
    "notesRef": "refs/notes/commits",
    "provenancePredicateType": "` + sourceType + `",
    "propertyPrefix": "ORG_SOURCE_",
    "resourceUri": "git+https://github.com/{owner}/{repo}",
    "protectedBranches": [
      {
        "name": "main",
        "targetLevel": "SLSA_SOURCE_LEVEL_3",
        "requiredProperties": [
          {"name": "ORG_SOURCE_GATED", "since": "2020-01-01T00:00:00Z"},
          {"name": "ORG_SOURCE_FUTURE", "since": "2099-01-01T00:00:00Z"}
        ]
      }
    ],
    "healedContinuity": true,
    "underclaimLevel": "SLSA_SOURCE_LEVEL_2",
    "legacyLeaves": []
  }
}`

func loadPolicy(t *testing.T) *policy.Policy {
	t.Helper()

	p, err := policy.Load(strings.NewReader(policyJSON))
	if err != nil {
		t.Fatalf("policy.Load = %v", err)
	}

	return p
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()

	b, err := jsonx.Marshal(v)
	if err != nil {
		t.Fatalf("jsonx.Marshal = %v", err)
	}

	return b
}

// fakeGit is a linear history (order[0] is the root) with a notes
// table. AddNote emulates git's stripspace normalisation — a note
// lands with exactly one trailing newline regardless of what was
// written — because that divergence between written and stored bytes
// is precisely what the read-back rule exists for.
// notes is the local state; remote is what a push publishes and what
// FetchNotes force-resets local state to — the engine's rebuild after
// a rejected push depends on exactly that reset.
type fakeGit struct {
	order  []string
	times  map[string]string
	notes  map[string][]byte
	remote map[string][]byte
	ref    string
	onPush func(g *fakeGit) error
	pushes int
	// readErr fails one named store operation — "Note:<rev>", "Noted"
	// or "AddNote". The emitter reads the object store several times
	// per link, and WHICH read tears decides which refusal it makes.
	readErr map[string]error
	// mangle is what the store hands back for a revision instead of
	// what was written: storage that rewrites a note into something
	// else must refuse at the read-back, not verify red later.
	mangle map[string][]byte
	// mangleAfter delays that substitution by a number of successful
	// reads, so a note can be whole when the chain is discovered and
	// broken when the tail is proven — the emitter reads it twice.
	mangleAfter map[string]*int
}

func newFakeGit() *fakeGit {
	return &fakeGit{
		order: []string{rev1, rev2, rev3, rev4},
		times: map[string]string{
			rev1: "2026-08-01T00:00:00Z",
			rev2: "2026-08-02T00:00:00Z",
			rev3: "2026-08-03T00:00:00Z",
			rev4: "2026-08-04T00:00:00Z",
		},
		notes:  map[string][]byte{},
		remote: map[string][]byte{},
		ref:    "refs/heads/main",
	}
}

func cloneNotes(m map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		out[k] = bytes.Clone(v)
	}

	return out
}

func (g *fakeGit) Tip(ref string) (string, error) {
	if ref != g.ref {
		return "", fakeError("unknown ref " + ref)
	}

	return g.order[len(g.order)-1], nil
}

func (g *fakeGit) Parent(rev string) (string, error) {
	i := g.index(rev)
	if i < 0 {
		return "", fakeError("unknown revision " + rev)
	}

	if i == 0 {
		return "", nil
	}

	return g.order[i-1], nil
}

func (g *fakeGit) Parents(rev string) ([]string, error) {
	p, err := g.Parent(rev)
	if err != nil || p == "" {
		return nil, err
	}

	return []string{p}, nil
}

func (g *fakeGit) Note(rev string) ([]byte, error) {
	if err := g.readErr["Note:"+rev]; err != nil {
		return nil, err
	}

	if mangled, ok := g.mangle[rev]; ok {
		left, delayed := g.mangleAfter[rev]
		if !delayed || *left <= 0 {
			return bytes.Clone(mangled), nil
		}

		*left--
	}

	n, ok := g.notes[rev]
	if !ok {
		return nil, nil
	}

	return bytes.Clone(n), nil
}

func (g *fakeGit) Noted() ([]string, error) {
	if err := g.readErr["Noted"]; err != nil {
		return nil, err
	}

	var revs []string
	for rev := range g.notes {
		revs = append(revs, rev)
	}

	return revs, nil
}

func (g *fakeGit) CommitTime(rev string) (string, error) {
	ct, ok := g.times[rev]
	if !ok {
		return "", fakeError("unknown revision " + rev)
	}

	return ct, nil
}

func (g *fakeGit) IsAncestor(rev, ref string) (bool, error) {
	if ref != g.ref {
		return false, fakeError("unknown ref " + ref)
	}

	return g.index(rev) >= 0, nil
}

func (g *fakeGit) AddNote(rev string, note []byte) error {
	if err := g.readErr["AddNote"]; err != nil {
		return err
	}

	stored := bytes.TrimRight(bytes.Clone(note), "\n")
	stored = append(stored, '\n') // stripspace: stored bytes differ from written bytes

	g.notes[rev] = stored

	return nil
}

func (g *fakeGit) CommitterIdent() error { return nil }

func (g *fakeGit) DryRunPushNotes(string) error { return nil }

func (g *fakeGit) FetchNotes() error {
	g.notes = cloneNotes(g.remote)

	return nil
}

func (g *fakeGit) PushNotes() error {
	g.pushes++

	if g.onPush != nil {
		if err := g.onPush(g); err != nil {
			return err
		}
	}

	g.remote = cloneNotes(g.notes)

	return nil
}

func (g *fakeGit) index(rev string) int { return slices.Index(g.order, rev) }

type fakeError string

func (e fakeError) Error() string { return string(e) }

// fakeBundle/fakeSigner/fakeBV: the signer wraps a payload with the
// identity it would certify and the payload digest; the verifier
// enforces exactly what the real trust boundary enforces — identity
// equality and digest membership.
type fakeBundle struct {
	SAN     string   `json:"san"`
	Issuer  string   `json:"issuer"`
	Digests []string `json:"digests"`
}

type fakeSigner struct {
	t   *testing.T
	san string
}

func (s fakeSigner) Check() error { return nil }

func (s fakeSigner) Sign(payload []byte) ([]byte, error) {
	return mustJSON(s.t, fakeBundle{SAN: s.san, Issuer: issuer, Digests: []string{chain.SHA256Hex(payload)}}), nil
}

type fakeBV struct{}

func (f fakeBV) Blob(b []byte, id trust.Identity, d string) (*trust.Verified, error) {
	return f.check(b, id, d)
}

func (f fakeBV) Attestation(b []byte, id trust.Identity, d string) (*trust.Verified, error) {
	return f.check(b, id, d)
}

func (fakeBV) Peek([]byte) ([]byte, error) { return nil, fakeError("peek is never judged here") }

func (fakeBV) check(bundleJSON []byte, id trust.Identity, sha256Hex string) (*trust.Verified, error) {
	fb, err := jsonx.DecodeForeign[fakeBundle](bundleJSON)
	if err != nil {
		return nil, fakeError("unparsable bundle")
	}

	if fb.SAN != id.SAN || fb.Issuer != id.Issuer {
		return nil, fakeError("identity mismatch")
	}

	if !slices.Contains(fb.Digests, sha256Hex) {
		return nil, fakeError("digest not covered")
	}

	return &trust.Verified{SAN: fb.SAN}, nil
}

func discardLog(string, ...any) {}

func fixedNow() time.Time { return time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC) }

// world bundles one emission scenario.
type world struct {
	p  *policy.Policy
	g  *fakeGit
	in emit.ChainInputs
	s  fakeSigner
}

func newWorld(t *testing.T) *world {
	t.Helper()

	return &world{
		p: loadPolicy(t),
		g: newFakeGit(),
		s: fakeSigner{t: t, san: identity},
		in: emit.ChainInputs{
			Owner: "acme", Repo: "widget",
			Ref: "refs/heads/main", Rev: rev4,
			WorkflowRef: "acme/widget/.github/workflows/source-attest.yml@refs/heads/main",
			ActorLogin:  "octocat", ActorID: "583231",
			MachineryRef: machineryPin, PolicyURI: policyURI,
			Claims: claims([]int64{1000000}, "ORG_SOURCE_GATED", "ORG_SOURCE_SIGNED"),
		},
	}
}

func claims(epochs []int64, properties ...string) *emit.Claims {
	readAt := "2026-08-15T00:00:00Z"
	controls := make([]chain.Control, 0, len(properties))

	for _, prop := range properties {
		p := prop
		controls = append(controls, chain.Control{Property: &p, Evidence: jsonx.Raw(`[{"rule":"live"}]`)})
	}

	return &emit.Claims{RulesReadAt: &readAt, RulesetsUpdatedAt: &epochs, Controls: &controls}
}

func (w *world) emit(t *testing.T) error {
	t.Helper()

	return emit.Chain(w.p, &w.in, w.g, w.s, fakeBV{}, fixedNow, discardLog)
}

// found runs a genesis emission at rev1 so later tests extend a real
// chain — built by the engine under test, which is the point: the
// fixture and the production path cannot drift.
func (w *world) found(t *testing.T) {
	t.Helper()

	in := w.in
	in.Rev = rev1
	in.Genesis = true

	if err := emit.Chain(w.p, &in, w.g, w.s, fakeBV{}, fixedNow, discardLog); err != nil {
		t.Fatalf("genesis emission = %v", err)
	}
}

// walk proves the emitted chain with the CONSUMER engine and returns
// its verdict — the emitter's real bar.
func (w *world) walk(t *testing.T) *verify.ChainVerdict {
	t.Helper()

	coords := verify.Coords{Owner: "acme", Repo: "widget"}

	verdict, err := verify.Chain(w.p, coords, "refs/heads/main", w.g, fakeBV{}, discardLog)
	if err != nil {
		t.Fatalf("verify.Chain over the emitted chain = %v", err)
	}

	return verdict
}

func TestChainGenesis(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.found(t)

	if len(w.g.notes) != 1 || w.g.notes[rev1] == nil {
		t.Fatalf("genesis wrote notes on %d revision(s), want exactly rev1", len(w.g.notes))
	}

	link, ok := decodeLink(t, w.g.notes[rev1])
	if !ok {
		t.Fatal("the genesis note does not decode as a chain link")
	}

	if *link.Version != chain.NoteV3 {
		t.Errorf("genesis link version = %d, want 2", *link.Version)
	}

	if w.g.pushes != 1 {
		t.Errorf("pushes = %d, want 1", w.g.pushes)
	}
}

func TestChainEmitAndWalk(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.found(t)

	// Ordinary pushes: rev2, then rev3 — each links immediately.
	for _, rev := range []string{rev2, rev3} {
		w.in.Rev = rev
		if err := w.emit(t); err != nil {
			t.Fatalf("emit at %s = %v", rev, err)
		}
	}

	w.in.Rev = rev4
	if err := w.emit(t); err != nil {
		t.Fatalf("emit at tip = %v", err)
	}

	verdict := w.walk(t)
	if verdict.Links() != 4 {
		t.Errorf("verified links = %d, want 4", verdict.Links())
	}

	lvl, err := verdict.SourceLevel(w.p, "main")
	if err != nil {
		t.Fatalf("SourceLevel = %v", err)
	}

	if lvl != "SLSA_SOURCE_LEVEL_3" {
		t.Errorf("SourceLevel = %s, want the target — emitter and verifier must agree", lvl)
	}
}

func TestChainHeals(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.found(t)

	// rev2 and rev3 lapsed; the rev4 push heals them, oldest first,
	// with repaired markers — and the whole chain still walks clean.
	if err := w.emit(t); err != nil {
		t.Fatalf("healing emit = %v", err)
	}

	if verdict := w.walk(t); verdict.Links() != 4 {
		t.Errorf("verified links = %d, want 4", verdict.Links())
	}

	for _, tt := range []struct {
		rev    string
		healed bool
	}{{rev2, true}, {rev3, true}, {rev4, false}} {
		pred := provenancePredicate(t, w.g.notes[tt.rev])
		if got := pred.Repaired != nil; got != tt.healed {
			t.Errorf("%s repaired marker = %v, want %v", tt.rev, got, tt.healed)
		}
	}

	// Continuity provable (epochs long before the commits), so healed
	// links keep the target level.
	lvl, err := w.walk(t).SourceLevel(w.p, "main")
	if err != nil || lvl != "SLSA_SOURCE_LEVEL_3" {
		t.Errorf("SourceLevel = %s, %v — healed links with proven continuity keep the target", lvl, err)
	}
}

func TestChainLedgerPrevHashesStoredBytes(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.found(t)

	w.in.Rev = rev2
	if err := w.emit(t); err != nil {
		t.Fatalf("emit = %v", err)
	}

	pred := provenancePredicate(t, w.g.notes[rev2])

	ptr, genesis, err := pred.Ledger()
	if err != nil || genesis {
		t.Fatalf("Ledger = %v, genesis=%v", err, genesis)
	}

	if *ptr.Revision != rev1 {
		t.Fatalf("ledgerPrev.revision = %s, want rev1", *ptr.Revision)
	}

	// The hash must cover the STORED bytes — the fake's stripspace
	// appends a newline the written bytes did not have, exactly the
	// divergence that minted .github#434's 32 broken links.
	stored := w.g.notes[rev1]
	if got := *ptr.NoteSHA256; got != chain.SHA256Hex(stored) {
		t.Errorf("ledgerPrev.noteSha256 = %s, want the digest of the stored blob (trailing newline included)", got)
	}

	if got := *ptr.NoteSHA256; got == chain.SHA256Hex(bytes.TrimRight(stored, "\n")) {
		t.Error("ledgerPrev.noteSha256 matches the newline-stripped form — the .github#434 defect reproduced")
	}
}

func TestChainCompareAndSwap(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.found(t)

	// The first push is rejected; before the retry, the remote ledger
	// gained a link at rev2 (as if a concurrent run landed). The
	// rebuilt emission must chain on the NEW tail — the predecessor
	// hash is computed inside the attempt that wins.
	w.in.Rev = rev3
	rejected := false
	w.g.onPush = func(g *fakeGit) error {
		if rejected {
			return nil
		}

		rejected = true

		// The competing run's link at rev2, landing on the REMOTE:
		// emitted through a second engine against the remote's state —
		// a real link, not a hand-rolled one.
		other := newWorld(t)
		other.g.notes = cloneNotes(g.remote)
		other.in.Rev = rev2

		if err := other.emit(t); err != nil {
			t.Fatalf("competing emission = %v", err)
		}

		g.remote[rev2] = other.g.notes[rev2]

		return fakeError("rejected: fetch first")
	}

	if err := w.emit(t); err != nil {
		t.Fatalf("emit with one rejection = %v", err)
	}

	if w.g.pushes != 3 { // genesis, rejected, winning
		t.Errorf("pushes = %d, want 3", w.g.pushes)
	}

	ptr, _, err := provenancePredicate(t, w.g.notes[rev3]).Ledger()
	if err != nil {
		t.Fatalf("Ledger = %v", err)
	}

	if *ptr.Revision != rev2 {
		t.Errorf("rebuilt link's ledgerPrev = %s, want rev2 — the tail that won the race", *ptr.Revision)
	}

	if *ptr.NoteSHA256 != chain.SHA256Hex(w.g.notes[rev2]) {
		t.Error("rebuilt link's predecessor hash does not cover the winning tail's stored bytes")
	}

	if verdict := w.walk(t); verdict.Links() != 3 {
		t.Errorf("verified links = %d, want 3", verdict.Links())
	}
}

func TestChainPushExhaustion(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.found(t)

	w.in.Rev = rev2
	w.g.onPush = func(*fakeGit) error { return fakeError("rejected") }

	err := w.emit(t)
	if err == nil || !strings.Contains(err.Error(), "would not fast-forward") {
		t.Errorf("emit = %v, want the exhaustion refusal", err)
	}
}

func TestChainLevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(w *world)
		want   string
	}{
		{
			"all live properties present claims the target",
			func(*world) {},
			"SLSA_SOURCE_LEVEL_3",
		},
		{
			"a missing required property under-claims",
			func(w *world) {
				w.in.Claims = claims([]int64{1000000}, "ORG_SOURCE_SIGNED")
			},
			"SLSA_SOURCE_LEVEL_2",
		},
		{
			"a property required only in the future is not required yet",
			func(w *world) {
				w.in.Claims = claims([]int64{1000000}, "ORG_SOURCE_GATED")
			},
			"SLSA_SOURCE_LEVEL_3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newWorld(t)
			w.found(t)
			tt.mutate(w)

			w.in.Rev = rev2
			if err := w.emit(t); err != nil {
				t.Fatalf("emit = %v", err)
			}

			if got := claimedSourceLevel(t, w.g.notes[rev2]); got != tt.want {
				t.Errorf("claimed level = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestChainHealedContinuity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		epochs []int64
		want   string
	}{
		{"continuity proven keeps the target", []int64{1000000}, "SLSA_SOURCE_LEVEL_3"},
		{"no readable change times under-claims", []int64{}, "SLSA_SOURCE_LEVEL_2"},
		{"a ruleset changed after the commit under-claims", []int64{4102444800}, "SLSA_SOURCE_LEVEL_2"},
		{"the NEWEST change time governs the horizon", []int64{1000000, 4102444800}, "SLSA_SOURCE_LEVEL_2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newWorld(t)
			w.found(t)
			w.in.Claims = claims(tt.epochs, "ORG_SOURCE_GATED")

			// rev4 is the push; rev2 and rev3 are healed. Judge rev2.
			if err := w.emit(t); err != nil {
				t.Fatalf("emit = %v", err)
			}

			if got := claimedSourceLevel(t, w.g.notes[rev2]); got != tt.want {
				t.Errorf("healed link level = %s, want %s", got, tt.want)
			}

			// The pushed revision itself is never healed: it keeps the
			// target regardless of the continuity horizon.
			if got := claimedSourceLevel(t, w.g.notes[rev4]); got != "SLSA_SOURCE_LEVEL_3" {
				t.Errorf("pushed link level = %s, want the target", got)
			}
		})
	}
}

func TestChainRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(w *world)
		want   string
	}{
		{
			"genesis refused once a link exists",
			func(w *world) { w.found(t); w.in.Genesis = true },
			"genesis refused",
		},
		{
			"no genesis on the history",
			func(*world) {},
			"no genesis link on this history",
		},
		{
			"malformed revision",
			func(w *world) { w.found(t); w.in.Rev = "not-a-revision" },
			"not a full commit digest",
		},
		{
			"tail whose bundle certifies a foreign identity",
			func(w *world) {
				w.found(t)
				tamperTailIdentity(t, w.g, rev1, "https://github.com/mallory/widget/attest.yml@refs/heads/main")
				w.in.Rev = rev2
			},
			"refusing to extend a chain that fails the published root of trust",
		},
		{
			"signer that cannot satisfy the published identity",
			func(w *world) {
				w.found(t)
				w.s = fakeSigner{t: t, san: "https://github.com/mallory/widget/attest.yml@refs/heads/main"}
				w.in.Rev = rev2
			},
			"not the published contract",
		},
		{
			"branch outside the policy",
			func(w *world) { w.g.ref = "refs/heads/next"; w.in.Ref = "refs/heads/next" },
			"not a protected branch",
		},
		{
			"malformed canon pin",
			func(w *world) { w.in.MachineryRef = "v1.2.3" },
			"pinned by full SHA",
		},
		{
			"empty policy URI",
			func(w *world) { w.in.PolicyURI = "" },
			"policy URI is required",
		},
		{
			"absent actor",
			func(w *world) { w.in.ActorLogin = "" },
			"actor is required",
		},
		{
			"absent claims",
			func(w *world) { w.in.Claims = nil },
			"claims payload is required",
		},
		{
			"implausible repository",
			func(w *world) { w.in.Owner = "ac me" },
			"not a plausible repository",
		},
		{
			"unqualified ref",
			func(w *world) { w.in.Ref = "main" },
			"not fully qualified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newWorld(t)
			tt.mutate(w)

			err := w.emit(t)
			if err == nil {
				t.Fatal("Chain accepted what it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Chain error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

func TestChainRevisionNotOnBranch(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.found(t)
	w.g.order = w.g.order[:3] // rev4 no longer on the branch
	w.in.Rev = rev4
	w.g.times[rev4] = "2026-08-04T00:00:00Z"

	err := w.emit(t)
	if err == nil || !strings.Contains(err.Error(), "protected-ref revisions only") {
		t.Errorf("Chain = %v, want the off-branch refusal", err)
	}
}

func TestChainNothingToEmit(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.found(t)

	w.in.Rev = rev2
	if err := w.emit(t); err != nil {
		t.Fatalf("emit = %v", err)
	}

	pushed := w.g.pushes

	// The same push again: everything is linked, nothing to push.
	if err := w.emit(t); err != nil {
		t.Fatalf("redundant emit = %v", err)
	}

	if w.g.pushes != pushed {
		t.Errorf("a redundant run pushed — %d → %d", pushed, w.g.pushes)
	}
}

func TestClaimsValidate(t *testing.T) {
	t.Parallel()

	readAt := "2026-08-15T00:00:00Z"
	badTime := "yesterday"
	gated := "ORG_SOURCE_GATED"
	epochs := []int64{}
	controls := []chain.Control{}

	tests := []struct {
		name   string
		claims emit.Claims
		want   string
	}{
		{"absent rulesReadAt", emit.Claims{RulesetsUpdatedAt: &epochs, Controls: &controls}, "rulesReadAt is absent"},
		{
			"unparsable rulesReadAt",
			emit.Claims{RulesReadAt: &badTime, RulesetsUpdatedAt: &epochs, Controls: &controls},
			"rulesReadAt",
		},
		{
			"absent rulesetsUpdatedAt",
			emit.Claims{RulesReadAt: &readAt, Controls: &controls},
			"rulesetsUpdatedAt is absent",
		},
		{
			"absent controls",
			emit.Claims{RulesReadAt: &readAt, RulesetsUpdatedAt: &epochs},
			"controls is absent",
		},
		{
			"control without a property",
			emit.Claims{
				RulesReadAt: &readAt, RulesetsUpdatedAt: &epochs,
				Controls: &[]chain.Control{{Evidence: jsonx.Raw(`{}`)}},
			},
			"property is absent",
		},
		{
			"control without evidence",
			emit.Claims{
				RulesReadAt: &readAt, RulesetsUpdatedAt: &epochs,
				Controls: &[]chain.Control{{Property: &gated}},
			},
			"no evidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.claims.Validate()
			if err == nil {
				t.Fatal("Validate accepted what it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Validate error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

// tamperTailIdentity swaps a stored link's provenance bundle for one
// certifying a foreign identity over the same statement bytes — the
// state a stranger's chain would present.
func tamperTailIdentity(t *testing.T, g *fakeGit, rev, san string) {
	t.Helper()

	link, ok := decodeLink(t, g.notes[rev])
	if !ok {
		t.Fatal("tamper target does not decode as a chain link")
	}

	stmtBytes := mustDecodeB64(t, *link.Provenance.Statement)
	link.Provenance.Bundle = mustJSON(t, fakeBundle{
		SAN: san, Issuer: issuer,
		Digests: []string{chain.SHA256Hex(dsse.PAE(chain.StatementType, stmtBytes))},
	})

	note := append(mustJSON(t, link), '\n')
	g.notes[rev] = note
	g.remote[rev] = bytes.Clone(note)
}

// decodeLink reads note bytes as a chain link the way a consumer
// does.
func decodeLink(t *testing.T, note []byte) (*chain.Note, bool) {
	t.Helper()

	link, err := jsonx.DecodeBytes[chain.Note](note)
	if err != nil {
		return nil, false
	}

	if err := link.Validate(); err != nil {
		return nil, false
	}

	return link, true
}

// provenancePredicate opens a link's provenance half.
func provenancePredicate(t *testing.T, note []byte) *chain.Predicate {
	t.Helper()

	link, ok := decodeLink(t, note)
	if !ok {
		t.Fatal("note does not decode as a chain link")
	}

	stmt := statementOf(t, *link.Provenance.Statement)

	pred, err := jsonx.DecodeBytes[chain.Predicate](stmt.Predicate)
	if err != nil {
		t.Fatalf("chain predicate: %v", err)
	}

	return pred
}

// claimedSourceLevel reads the SOURCE level a link's own VSA claims.
func claimedSourceLevel(t *testing.T, note []byte) string {
	t.Helper()

	link, ok := decodeLink(t, note)
	if !ok {
		t.Fatal("note does not decode as a chain link")
	}

	stmt := statementOf(t, *link.VSA.Statement)

	pred, err := jsonx.DecodeBytes[vsaPredicate](stmt.Predicate)
	if err != nil {
		t.Fatalf("vsa predicate: %v", err)
	}

	for _, l := range pred.VerifiedLevels {
		if strings.HasPrefix(l, "SLSA_SOURCE_LEVEL_") {
			return l
		}
	}

	t.Fatal("the vsa claims no source level")

	return ""
}

// vsaPredicate is the narrow read these tests need.
type vsaPredicate struct {
	Verifier           jsonx.Raw `json:"verifier"`
	TimeVerified       *string   `json:"timeVerified"`
	ResourceURI        *string   `json:"resourceUri"`
	Policy             jsonx.Raw `json:"policy"`
	VerificationResult *string   `json:"verificationResult"`
	VerifiedLevels     []string  `json:"verifiedLevels"`
	SlsaVersion        *string   `json:"slsaVersion"`
}

// statementOf decodes a base64 statement.
func statementOf(t *testing.T, b64 string) *stmtDoc {
	t.Helper()

	raw, err := jsonx.DecodeBytes[stmtDoc](mustDecodeB64(t, b64))
	if err != nil {
		t.Fatalf("statement: %v", err)
	}

	return raw
}

type stmtDoc struct {
	Type          *string   `json:"_type"`
	Subject       jsonx.Raw `json:"subject"`
	PredicateType *string   `json:"predicateType"`
	Predicate     jsonx.Raw `json:"predicate"`
}

func mustDecodeB64(t *testing.T, s string) []byte {
	t.Helper()

	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}

	return b
}

// failGit wraps the fixture history with one scripted failpoint — the
// guard-branch law: guards that fire only in degraded states are the
// least exercised code in the org, so each one is a table row here.
type failGit struct {
	*fakeGit

	failOn string
}

func (g *failGit) Note(rev string) ([]byte, error) {
	if g.fail("note") {
		return nil, fakeError("object store torn")
	}

	return g.fakeGit.Note(rev)
}

func (g *failGit) Parent(rev string) (string, error) {
	if g.fail("parent") {
		return "", fakeError("object store torn")
	}

	return g.fakeGit.Parent(rev)
}

func (g *failGit) Parents(rev string) ([]string, error) {
	if g.fail("parents") {
		return nil, fakeError("object store torn")
	}

	return g.fakeGit.Parents(rev)
}

func (g *failGit) CommitTime(rev string) (string, error) {
	if g.fail("committime") {
		return "", fakeError("object store torn")
	}

	if g.fail("badtime") {
		return "yesterday", nil
	}

	return g.fakeGit.CommitTime(rev)
}

func (g *failGit) IsAncestor(rev, ref string) (bool, error) {
	if g.fail("ancestor") {
		return false, fakeError("object store torn")
	}

	return g.fakeGit.IsAncestor(rev, ref)
}

func (g *failGit) AddNote(rev string, note []byte) error {
	if g.fail("addnote") {
		return fakeError("object store torn")
	}

	return g.fakeGit.AddNote(rev, note)
}

func (g *failGit) FetchNotes() error {
	if g.fail("fetch") {
		return fakeError("network torn")
	}

	return g.fakeGit.FetchNotes()
}

func (g *failGit) fail(op string) bool { return g.failOn == op }

// failSigner refuses to sign.
//
//nolint:unused // interface completeness
type checkOK struct{}

type failSigner struct{}

func (failSigner) Sign([]byte) ([]byte, error) { return nil, fakeError("no identity") }

func (failSigner) Check() error { return nil }

func TestChainDegradedStates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		failOn string
		want   string
	}{
		{"note read fails during discovery", "note", "object store torn"},
		{"parent walk fails", "parent", "object store torn"},
		{"parents read fails during assembly", "parents", "object store torn"},
		{"commit time read fails", "committime", "object store torn"},
		{"commit time is not ISO 8601", "badtime", "commit time"},
		{"ancestry check fails", "ancestor", "object store torn"},
		{"note write fails", "addnote", "object store torn"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newWorld(t)
			w.found(t)
			w.in.Rev = rev2

			fg := &failGit{fakeGit: w.g, failOn: tt.failOn}

			err := emit.Chain(w.p, &w.in, fg, w.s, fakeBV{}, fixedNow, discardLog)
			if err == nil {
				t.Fatal("Chain succeeded in a degraded state")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Chain error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

func TestChainFetchFailureOnRetry(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.found(t)
	w.in.Rev = rev2
	w.g.onPush = func(*fakeGit) error { return fakeError("rejected") }

	fg := &failGit{fakeGit: w.g, failOn: "fetch"}

	err := emit.Chain(w.p, &w.in, fg, w.s, fakeBV{}, fixedNow, discardLog)
	if err == nil || !strings.Contains(err.Error(), "refetching the notes ref") {
		t.Errorf("Chain = %v, want the refetch failure", err)
	}
}

func TestChainSignerFailure(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.found(t)
	w.in.Rev = rev2

	err := emit.Chain(w.p, &w.in, w.g, failSigner{}, fakeBV{}, fixedNow, discardLog)
	if err == nil || !strings.Contains(err.Error(), "signing") {
		t.Errorf("Chain = %v, want the signing failure", err)
	}
}

func TestChainNilInputs(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	if err := emit.Chain(w.p, nil, w.g, w.s, fakeBV{}, fixedNow, discardLog); err == nil {
		t.Error("Chain accepted nil inputs")
	}
}

// TestChainTailTampers covers the tail guards a stranger's state can
// trigger: a statement whose payload is not a statement, and a
// subject naming another revision.
func TestChainTailTampers(t *testing.T) {
	t.Parallel()

	t.Run("tail statement decodes to a non-statement", func(t *testing.T) {
		t.Parallel()

		w := newWorld(t)
		w.found(t)
		tamperTailStatement(t, w.g, rev1, []byte(`[]`))
		w.in.Rev = rev2

		err := w.emit(t)
		if err == nil {
			t.Fatal("Chain extended a tail whose statement is not a statement")
		}
	})

	t.Run("tail subject names another revision", func(t *testing.T) {
		t.Parallel()

		w := newWorld(t)
		w.found(t)

		swapped := []byte(strings.ReplaceAll(string(tailStatement(t, w.g, rev1)), rev1, rev3))
		tamperTailStatement(t, w.g, rev1, swapped)
		w.in.Rev = rev2

		err := w.emit(t)
		if err == nil || !strings.Contains(err.Error(), "attests a different revision") {
			t.Errorf("Chain = %v, want the subject refusal", err)
		}
	})
}

// tailStatement reads a stored link's provenance statement bytes.
func tailStatement(t *testing.T, g *fakeGit, rev string) []byte {
	t.Helper()

	link, ok := decodeLink(t, g.notes[rev])
	if !ok {
		t.Fatal("target does not decode as a chain link")
	}

	return mustDecodeB64(t, *link.Provenance.Statement)
}

// tamperTailStatement swaps a stored link's provenance statement for
// arbitrary bytes, re-signed so the signature check passes and the
// deeper guards are the ones exercised.
func tamperTailStatement(t *testing.T, g *fakeGit, rev string, stmt []byte) {
	t.Helper()

	link, ok := decodeLink(t, g.notes[rev])
	if !ok {
		t.Fatal("tamper target does not decode as a chain link")
	}

	b64 := base64.StdEncoding.EncodeToString(stmt)
	link.Provenance.Statement = &b64
	link.Provenance.Bundle = mustJSON(t, fakeBundle{
		SAN: identity, Issuer: issuer,
		Digests: []string{chain.SHA256Hex(dsse.PAE(chain.StatementType, stmt))},
	})

	note := append(mustJSON(t, link), '\n')
	g.notes[rev] = note
	g.remote[rev] = bytes.Clone(note)
}

// Preflight fakes: each fails exactly one proof.

type badIdentGit struct{ *fakeGit }

func (badIdentGit) CommitterIdent() error { return fakeError("no committer identity") }

type badPushGit struct{ *fakeGit }

func (badPushGit) DryRunPushNotes(string) error { return fakeError("push proof rejected") }

type badCheckSigner struct{ fakeSigner }

func (badCheckSigner) Check() error { return fakeError("cosign is not usable") }

// TestChainPreflight pins the fold of preflight.sh into the engine:
// every proof refuses by name BEFORE anything signs, the identity
// guard holds the reserved path, and genesis skips only the push
// proof (there is no ledger to prove against yet).
func TestChainPreflight(t *testing.T) {
	t.Parallel()

	t.Run("no workflow identity at all refuses by name", func(t *testing.T) {
		t.Parallel()

		w := newWorld(t)
		w.found(t)
		w.in.Rev = rev2
		w.in.WorkflowRef = ""

		err := w.emit(t)
		if err == nil || !strings.Contains(err.Error(), "GITHUB_WORKFLOW_REF") {
			t.Fatalf("err = %v, want the missing-identity refusal — an unprovable identity must not sign", err)
		}
	})

	t.Run("a foreign workflow identity refuses", func(t *testing.T) {
		t.Parallel()

		w := newWorld(t)
		w.found(t)
		w.in.Rev = rev2
		w.in.WorkflowRef = "mallory/widget/.github/workflows/source-attest.yml@refs/heads/main"

		err := w.emit(t)
		if err == nil || !strings.Contains(err.Error(), "reserved identity") {
			t.Fatalf("err = %v, want the identity refusal", err)
		}
	})

	t.Run("the reserved workflow identity passes the guard", func(t *testing.T) {
		t.Parallel()

		w := newWorld(t)
		w.found(t)
		w.in.Rev = rev2
		w.in.WorkflowRef = "acme/widget/.github/workflows/source-attest.yml@refs/heads/main"

		if err := w.emit(t); err != nil {
			t.Fatalf("emit under the reserved identity: %v", err)
		}
	})

	t.Run("an unusable signer refuses before signing", func(t *testing.T) {
		t.Parallel()

		w := newWorld(t)
		w.found(t)
		w.in.Rev = rev2

		err := emit.Chain(w.p, &w.in, w.g, badCheckSigner{w.s}, fakeBV{}, fixedNow, discardLog)
		if err == nil || !strings.Contains(err.Error(), "cosign is not usable") {
			t.Fatalf("err = %v, want the signer refusal", err)
		}
	})

	t.Run("a missing committer identity refuses", func(t *testing.T) {
		t.Parallel()

		w := newWorld(t)
		w.found(t)
		w.in.Rev = rev2

		err := emit.Chain(w.p, &w.in, badIdentGit{w.g}, w.s, fakeBV{}, fixedNow, discardLog)
		if err == nil || !strings.Contains(err.Error(), "committer identity") {
			t.Fatalf("err = %v, want the identity refusal", err)
		}
	})

	t.Run("a rejected push proof refuses before signing", func(t *testing.T) {
		t.Parallel()

		w := newWorld(t)
		w.found(t)
		w.in.Rev = rev2

		err := emit.Chain(w.p, &w.in, badPushGit{w.g}, w.s, fakeBV{}, fixedNow, discardLog)
		if err == nil || !strings.Contains(err.Error(), "push proof rejected") {
			t.Fatalf("err = %v, want the push-proof refusal", err)
		}
	})

	t.Run("genesis skips only the push proof", func(t *testing.T) {
		t.Parallel()

		w := newWorld(t)
		w.in.Genesis = true

		if err := emit.Chain(w.p, &w.in, badPushGit{w.g}, w.s, fakeBV{}, fixedNow, discardLog); err != nil {
			t.Fatalf("genesis with a failing push proof: %v — there is no ledger to prove against yet", err)
		}
	})
}
