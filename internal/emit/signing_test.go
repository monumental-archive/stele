// The source-signing identity change through the emitter (stele#389):
// the link a run extends is judged by the chain verifier's rule, so
// the rows the verify walk holds hold here too, through the check of
// the previous link before the append.

package emit_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/emit"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

const (
	// sharedIdentity is the move's destination: one shared signing
	// workflow. The per-repository `identity` becomes the legacy one.
	sharedIdentity    = "https://github.com/acme/signer/.github/workflows/source-sign.yml@refs/heads/main"
	sharedWorkflowRef = "acme/signer/.github/workflows/source-sign.yml@refs/heads/main"
	foreignIdentity   = "https://github.com/mallory/widget/.github/workflows/source-attest.yml@refs/heads/main"

	legacyUntil = "2026-11-17T12:00:00Z"
	beforeUntil = "2026-11-16T09:00:00Z"
	afterUntil  = "2026-11-18T09:00:00Z"
)

// movedPolicy is the policy after the move. legacy=false drops the
// legacyIdentity key (the shared signer alone); until empty omits it.
func movedPolicy(t *testing.T, legacy bool, until string) *policy.Policy {
	t.Helper()

	old := `"identity": "https://github.com/{owner}/{repo}/.github/workflows/source-attest.yml@refs/heads/main",`
	if !strings.Contains(policyJSON, old) {
		t.Fatal("the test policy no longer carries the source identity this fixture rewrites")
	}

	repl := `"identity": "` + sharedIdentity + `",`
	if legacy {
		repl += ` "legacyIdentity": {"identity": "https://github.com/{owner}/{repo}` +
			`/.github/workflows/source-attest.yml@refs/heads/main"`
		if until != "" {
			repl += `, "until": "` + until + `"`
		}

		repl += `},`
	}

	p, err := policy.Load(strings.NewReader(strings.Replace(policyJSON, old, repl, 1)))
	if err != nil {
		t.Fatalf("policy.Load = %v", err)
	}

	return p
}

// signer is one existing link's signer and its logged instant.
type signer struct{ san, loggedAt string }

func cur() signer           { return signer{san: sharedIdentity, loggedAt: afterUntil} }
func leg(at string) signer  { return signer{san: identity, loggedAt: at} }
func unknownSigner() signer { return signer{san: foreignIdentity, loggedAt: beforeUntil} }

// emittedAt is the revision link i sits on: the fixture history is
// rev1..rev4, oldest first.
func emittedAt(i int) string { return []string{rev1, rev2, rev3, rev4}[i] }

// anyIdentityBV verifies digests and nothing about identity: it lets a
// fixture build a history no honest run could — a reversal among them
// — with the production emitter, so the row's judgment is made on the
// same bytes the engine writes.
type anyIdentityBV struct{ fakeBV }

func (b anyIdentityBV) Blob(raw []byte, _ trust.Identity, d string) (*trust.Verified, error) {
	fb, err := decodeFakeBundle(raw)
	if err != nil {
		return nil, err
	}

	return b.fakeBV.Blob(raw, trust.Identity{SAN: fb.SAN, Issuer: fb.Issuer}, d)
}

func decodeFakeBundle(raw []byte) (*fakeBundle, error) {
	fb, err := jsonx.DecodeForeign[fakeBundle](raw)
	if err != nil {
		return nil, fakeError("unparsable bundle")
	}

	return fb, nil
}

// buildSigned emits links on rev1.. in order, link i signed by
// links[i]; each signs under the policy in force when it was signed,
// so a current link's summary names the shared signer and a legacy
// link's names the per-repository workflow.
func buildSigned(t *testing.T, w *world, links []signer) {
	t.Helper()

	for i, l := range links {
		in := w.in
		in.Rev = emittedAt(i)
		in.Genesis = i == 0

		p := loadPolicy(t)
		if l.san == sharedIdentity {
			p = movedPolicy(t, false, "")
			in.WorkflowRef = sharedWorkflowRef
		}

		s := fakeSigner{t: t, san: l.san, loggedAt: l.loggedAt}
		if err := emit.Chain(p, &in, w.g, s, anyIdentityBV{}, fixedNow, discardLog); err != nil {
			t.Fatalf("building link %d = %v", i, err)
		}
	}
}

// extend runs the row's emission: the next revision, under the given
// policy, signed by the shared signer, judged by the strict verifier.
func extend(t *testing.T, w *world, p *policy.Policy, g emit.Git, at int) ([]string, error) {
	t.Helper()

	var lines []string

	logf := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }

	in := w.in
	in.Rev = emittedAt(at)
	in.WorkflowRef = sharedWorkflowRef

	s := fakeSigner{t: t, san: sharedIdentity, loggedAt: afterUntil}

	return lines, emit.Chain(p, &in, g, s, fakeBV{}, fixedNow, logf)
}

// TestChainExtendsAcrossAnIdentityChange holds the walk's rows through
// the previous-link check: each refusal asserts its message, each pass
// asserts where the run says the chain changed signer, and every pass
// is then walked by the consumer engine under the same policy.
func TestChainExtendsAcrossAnIdentityChange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		policy  func(t *testing.T) *policy.Policy
		links   []signer
		changed string // the revision the run names; "" = none
		walked  string // the revision the consumer walk names after the append
		want    string
	}{
		{
			name: "every link under the current identity, no legacy declared (as today)",
			policy: func(t *testing.T) *policy.Policy {
				t.Helper()

				return movedPolicy(t, false, "")
			},
			links: []signer{cur(), cur(), cur()},
		},
		{
			name: "every link under the current identity, legacy declared",
			policy: func(t *testing.T) *policy.Policy {
				t.Helper()

				return movedPolicy(t, true, legacyUntil)
			},
			links: []signer{cur(), cur()},
		},
		{
			name: "legacy links then current links",
			policy: func(t *testing.T) *policy.Policy {
				t.Helper()

				return movedPolicy(t, true, legacyUntil)
			},
			links:   []signer{leg(beforeUntil), leg(beforeUntil), cur()},
			changed: rev3,
			walked:  rev3,
		},
		{
			name: "until absent: a legacy tail logged however late is extended",
			policy: func(t *testing.T) *policy.Policy {
				t.Helper()

				return movedPolicy(t, true, "")
			},
			links:  []signer{leg(beforeUntil), leg("2099-01-01T00:00:00Z")},
			walked: rev3,
		},
		{
			name: "a legacy link after a current one",
			policy: func(t *testing.T) *policy.Policy {
				t.Helper()

				return movedPolicy(t, true, legacyUntil)
			},
			links: []signer{leg(beforeUntil), cur(), leg(beforeUntil)},
			want: "emit: refusing to extend the chain: link at " + rev3 + " is signed under the legacy identity " +
				identity + " after link at " + rev2 + " was signed under the current identity " + sharedIdentity +
				" — a chain changes its signing identity once and never goes back",
		},
		{
			name: "a legacy tail signed after until",
			policy: func(t *testing.T) *policy.Policy {
				t.Helper()

				return movedPolicy(t, true, legacyUntil)
			},
			links: []signer{leg(beforeUntil), leg(afterUntil)},
			want: "emit: link at " + rev2 + " does not verify against " + sharedIdentity +
				" — refusing to extend a chain that fails the published root of trust: signed under the legacy identity " +
				identity + " at " + afterUntil + ", after its until " + legacyUntil +
				" — the legacy identity signs nothing past its until",
		},
		{
			name: "an older legacy link signed after until",
			policy: func(t *testing.T) *policy.Policy {
				t.Helper()

				return movedPolicy(t, true, legacyUntil)
			},
			links: []signer{leg(afterUntil), cur()},
			want:  "emit: link at " + rev1 + " does not verify against " + sharedIdentity,
		},
		{
			name: "a legacy tail with no logged instant, until declared",
			policy: func(t *testing.T) *policy.Policy {
				t.Helper()

				return movedPolicy(t, true, legacyUntil)
			},
			links: []signer{leg(beforeUntil), leg("")},
			want: "signed under the legacy identity " + identity +
				", which carries an until, and the signing has no logged instant to judge it by: no log instant scripted",
		},
		{
			name: "no legacyIdentity and a legacy tail (as an unknown identity fails today)",
			policy: func(t *testing.T) *policy.Policy {
				t.Helper()

				return movedPolicy(t, false, "")
			},
			links: []signer{leg(beforeUntil), leg(beforeUntil)},
			want: "emit: link at " + rev2 + " does not verify against " + sharedIdentity +
				" — refusing to extend a chain that fails the published root of trust: identity mismatch",
		},
		{
			name: "an older link under neither identity",
			policy: func(t *testing.T) *policy.Policy {
				t.Helper()

				return movedPolicy(t, true, legacyUntil)
			},
			links: []signer{unknownSigner(), cur()},
			want: "emit: link at " + rev1 + " does not verify against " + sharedIdentity +
				" — refusing to extend a chain that fails the published root of trust: identity mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newWorld(t)
			buildSigned(t, w, tt.links)

			p := tt.policy(t)

			lines, err := extend(t, w, p, w.g, len(tt.links))

			if tt.want != "" {
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("Chain = %v\nwant a refusal carrying %q", err, tt.want)
				}

				return
			}

			if err != nil {
				t.Fatalf("Chain = %v", err)
			}

			assertNamed(t, lines, "emit: source signing identity changed at ", tt.changed)

			verdict, werr := verify.Chain(p, verify.Coords{Owner: "acme", Repo: "widget"}, "refs/heads/main",
				w.g, fakeBV{}, discardLog)
			if werr != nil {
				t.Fatalf("verify.Chain over the extended chain = %v", werr)
			}

			if verdict.IdentityChangedAt() != tt.walked {
				t.Errorf("walk IdentityChangedAt = %q, want %q", verdict.IdentityChangedAt(), tt.walked)
			}
		})
	}
}

// assertNamed: exactly one line names the change at want, or none
// names a change when want is empty.
func assertNamed(t *testing.T, lines []string, prefix, want string) {
	t.Helper()

	var named []string

	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			named = append(named, l)
		}
	}

	switch {
	case want == "" && len(named) != 0:
		t.Errorf("log names a change %q, want none", named)
	case want != "" && (len(named) != 1 || named[0] != prefix+want):
		t.Errorf("log = %q\nwant exactly one %q", lines, prefix+want)
	}
}

// tornGit tears one revision's reads AFTER discovery has read it:
// the order walk re-reads links discovery already passed, so a store
// that changes between the two reads must refuse there, by name.
type tornGit struct {
	*fakeGit

	rev   string
	op    string // "note" or "parent"
	after int    // successful reads of rev before the tear
	note  []byte // what a torn note read returns; nil with err = absent
	err   error
	seen  int
}

func (g *tornGit) Note(rev string) ([]byte, error) {
	if g.torn("note", rev) {
		return g.note, g.err
	}

	return g.fakeGit.Note(rev)
}

func (g *tornGit) Parent(rev string) (string, error) {
	if g.torn("parent", rev) {
		return "", g.err
	}

	return g.fakeGit.Parent(rev)
}

func (g *tornGit) torn(op, rev string) bool {
	if op != g.op || rev != g.rev {
		return false
	}

	g.seen++

	return g.seen > g.after
}

// TestChainOrderWalkDegraded: every guard in the order walk, reached
// by a store that answers discovery and then tears.
func TestChainOrderWalkDegraded(t *testing.T) {
	t.Parallel()

	brokenPredicate := func(t *testing.T) []byte {
		t.Helper()

		stmt := linkStatement(t, rev1, map[string]any{"repository": "acme/widget"})

		return handNote(t, stmt, stmt)
	}

	tests := []struct {
		name string
		torn func(t *testing.T, g *fakeGit) *tornGit
		want string
	}{
		{
			name: "an older link's note cannot be re-read",
			torn: func(t *testing.T, g *fakeGit) *tornGit {
				t.Helper()

				return &tornGit{fakeGit: g, rev: rev1, op: "note", after: 1, err: fakeError("object store torn")}
			},
			want: "emit: note for " + rev1 + ": object store torn",
		},
		{
			name: "the parent walk cannot be re-read",
			torn: func(t *testing.T, g *fakeGit) *tornGit {
				t.Helper()

				return &tornGit{fakeGit: g, rev: rev2, op: "parent", after: 1, err: fakeError("object store torn")}
			},
			want: "emit: parent of " + rev2 + ": object store torn",
		},
		{
			name: "the genesis link is gone on the second read",
			torn: func(t *testing.T, g *fakeGit) *tornGit {
				t.Helper()

				return &tornGit{fakeGit: g, rev: rev1, op: "note", after: 1}
			},
			want: "emit: the walk from " + rev2 + " ended before a genesis link",
		},
		{
			name: "an older link's ledger is unreadable on the second read",
			torn: func(t *testing.T, g *fakeGit) *tornGit {
				t.Helper()

				return &tornGit{fakeGit: g, rev: rev1, op: "note", after: 1, note: brokenPredicate(t)}
			},
			want: "emit: link at " + rev1 + ": ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newWorld(t)
			buildSigned(t, w, []signer{leg(beforeUntil), cur()})

			// until absent: the hand-signed note scripts no log instant,
			// and the row is about the walk, not the date.
			_, err := extend(t, w, movedPolicy(t, true, ""), tt.torn(t, w.g), 2)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Chain = %v\nwant a refusal carrying %q", err, tt.want)
			}
		})
	}
}
