package verify_test

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/verify"
)

// The source-signing identity change (stele#389): links signed under
// the legacy identity, then links signed under the current one, once
// and in order. The shape is the first consumer's move — each
// repository's own source-attest workflow (the legacy identity) to
// one shared signing workflow (the current one) — with zero real
// org names.
const (
	sharedSAN   = "https://github.com/acme/signer/.github/workflows/source-sign.yml@refs/heads/main"
	foreignSAN  = "https://github.com/mallory/widget/.github/workflows/source-attest.yml@refs/heads/main"
	legacyUntil = "2026-11-17T12:00:00Z"
	beforeUntil = "2026-11-16T09:00:00Z"
	atUntil     = legacyUntil
	afterUntil  = "2026-11-18T09:00:00Z"
)

// changedPolicy is the test policy after the move: the shared signer
// is current, the per-repository workflow is legacy. until is the
// optional key's value; empty omits it.
func changedPolicy(t *testing.T, until string) *policy.Policy {
	t.Helper()

	legacy := `"legacyIdentity": {"identity": "https://github.com/{owner}/{repo}` +
		`/.github/workflows/source-attest.yml@refs/heads/main"`
	if until != "" {
		legacy += `, "until": "` + until + `"`
	}

	legacy += `},`

	old := `"identity": "https://github.com/{owner}/{repo}/.github/workflows/source-attest.yml@refs/heads/main",`
	if !strings.Contains(policyJSON, old) {
		t.Fatal("the test policy no longer carries the source identity this fixture rewrites")
	}

	doc := strings.Replace(policyJSON, old, `"identity": "`+sharedSAN+`", `+legacy, 1)

	p, err := policy.Load(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("policy.Load = %v", err)
	}

	return p
}

// signed is one link's signer and the instant the log observed it.
type signed struct {
	san      string
	loggedAt string
}

func current() signed         { return signed{san: sharedSAN, loggedAt: afterUntil} }
func legacy(at string) signed { return signed{san: linkSAN, loggedAt: at} }
func foreign() signed         { return signed{san: foreignSAN, loggedAt: beforeUntil} }
func chainRev(i int) string   { return strings.Repeat(strconv.Itoa(i+1), 40) }

// signedChain builds a linear chain, GENESIS FIRST: link i sits on
// chainRev(i), its ledger pointer names link i-1's stored bytes, and
// both halves are signed by links[i].
func signedChain(t *testing.T, links ...signed) fakeHistory {
	t.Helper()

	h := fakeHistory{
		tips:    map[string]string{"refs/heads/main": chainRev(len(links) - 1)},
		parents: map[string]string{},
		notes:   map[string][]byte{},
	}

	for i, l := range links {
		cw := chainWorld{t: t, san: l.san, loggedAt: l.loggedAt}
		rev := chainRev(i)

		var pointer map[string]any

		if i > 0 {
			prev := chainRev(i - 1)
			h.parents[rev] = prev
			pointer = map[string]any{"revision": prev, "noteSha256": digestHex(h.notes[prev])}
		}

		h.notes[rev] = cw.note(3,
			cw.linkStmt(rev, "ledgerPrev", pointer, []string{"ORG_SOURCE_GATED"}, false),
			cw.vsaStmt(rev, []any{"SLSA_SOURCE_LEVEL_3"}))
	}

	return h
}

// TestChainSourceIdentityChange holds the rule row by row: every row
// that refuses asserts the message, and every row that passes asserts
// where the walk says the chain changed signer — and that it says so
// exactly once.
func TestChainSourceIdentityChange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		policy  func(t *testing.T) *policy.Policy
		links   []signed
		changed int // index of the first current link; -1 = no change named
		want    []string
	}{
		{
			name:    "every link under the current identity, no legacy declared (as today)",
			policy:  loadPolicy,
			links:   []signed{legacy(beforeUntil), legacy(beforeUntil), legacy(beforeUntil)},
			changed: -1,
		},
		{
			name:    "every link under the current identity, legacy declared",
			policy:  func(t *testing.T) *policy.Policy { t.Helper(); return changedPolicy(t, legacyUntil) },
			links:   []signed{current(), current(), current()},
			changed: -1,
		},
		{
			name:    "legacy links then current links",
			policy:  func(t *testing.T) *policy.Policy { t.Helper(); return changedPolicy(t, legacyUntil) },
			links:   []signed{legacy(beforeUntil), legacy(beforeUntil), current(), current()},
			changed: 2,
		},
		{
			name:    "the change at the tip",
			policy:  func(t *testing.T) *policy.Policy { t.Helper(); return changedPolicy(t, legacyUntil) },
			links:   []signed{legacy(beforeUntil), current()},
			changed: 1,
		},
		{
			name:    "every link legacy — the change has not happened yet",
			policy:  func(t *testing.T) *policy.Policy { t.Helper(); return changedPolicy(t, "") },
			links:   []signed{legacy(beforeUntil), legacy(afterUntil)},
			changed: -1,
		},
		{
			name:    "a legacy link logged exactly at until",
			policy:  func(t *testing.T) *policy.Policy { t.Helper(); return changedPolicy(t, legacyUntil) },
			links:   []signed{legacy(atUntil), current()},
			changed: 1,
		},
		{
			name:    "until absent: legacy accepted however late, until the first current link",
			policy:  func(t *testing.T) *policy.Policy { t.Helper(); return changedPolicy(t, "") },
			links:   []signed{legacy(beforeUntil), legacy("2099-01-01T00:00:00Z"), current()},
			changed: 2,
		},
		{
			name:   "a legacy link after a current one",
			policy: func(t *testing.T) *policy.Policy { t.Helper(); return changedPolicy(t, legacyUntil) },
			links:  []signed{legacy(beforeUntil), current(), legacy(beforeUntil), current()},
			want: []string{
				"verify: link at " + chainRev(2) + " is signed under the legacy identity " + linkSAN +
					" after link at " + chainRev(1) + " was signed under the current identity " + sharedSAN +
					" — a chain changes its signing identity once and never goes back",
			},
		},
		{
			name:   "a legacy link after a current genesis",
			policy: func(t *testing.T) *policy.Policy { t.Helper(); return changedPolicy(t, "") },
			links:  []signed{current(), legacy(beforeUntil)},
			want: []string{
				"link at " + chainRev(1) + " is signed under the legacy identity",
				"after link at " + chainRev(0) + " was signed under the current identity",
				"never goes back",
			},
		},
		{
			name:   "a legacy link signed after until",
			policy: func(t *testing.T) *policy.Policy { t.Helper(); return changedPolicy(t, legacyUntil) },
			links:  []signed{legacy(beforeUntil), legacy(afterUntil), current()},
			want: []string{
				"verify: link at " + chainRev(1) + ": provenance refused: signed under the legacy identity " + linkSAN +
					" at " + afterUntil + ", after its until " + legacyUntil +
					" — the legacy identity signs nothing past its until",
			},
		},
		{
			name:   "a legacy link with no logged instant, until declared",
			policy: func(t *testing.T) *policy.Policy { t.Helper(); return changedPolicy(t, legacyUntil) },
			links:  []signed{legacy(""), current()},
			want: []string{
				"verify: link at " + chainRev(0) + ": provenance refused: signed under the legacy identity " + linkSAN +
					", which carries an until, and the signing has no logged instant to judge it by: no log instant scripted",
			},
		},
		{
			name:   "no legacyIdentity and a link under another identity (as an unknown identity fails today)",
			policy: loadPolicy,
			links:  []signed{legacy(beforeUntil), current()},
			want:   []string{"verify: link at " + chainRev(1) + ": provenance refused: identity mismatch"},
		},
		{
			name:   "an unknown identity with legacy declared fails as it does today",
			policy: func(t *testing.T) *policy.Policy { t.Helper(); return changedPolicy(t, legacyUntil) },
			links:  []signed{legacy(beforeUntil), foreign(), current()},
			want:   []string{"verify: link at " + chainRev(1) + ": provenance refused: identity mismatch"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var lines []string

			logf := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }

			verdict, err := verify.Chain(tt.policy(t), verify.Coords{Owner: "acme", Repo: "widget"},
				"refs/heads/main", signedChain(t, tt.links...), fakeBV{}, logf)

			if len(tt.want) > 0 {
				if err == nil {
					t.Fatalf("Chain = nil, want a refusal carrying %q", tt.want)
				}

				for _, w := range tt.want {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("Chain error = %q\nwant it to carry %q", err, w)
					}
				}

				return
			}

			if err != nil {
				t.Fatalf("Chain = %v", err)
			}

			if verdict.Links() != len(tt.links) {
				t.Errorf("Links = %d, want %d", verdict.Links(), len(tt.links))
			}

			assertChangeNamed(t, verdict, lines, tt.changed)
		})
	}
}

// assertChangeNamed: the verdict and the log name the first current
// link exactly once, or neither names a change.
func assertChangeNamed(t *testing.T, verdict *verify.ChainVerdict, lines []string, changed int) {
	t.Helper()

	named := 0

	for _, l := range lines {
		if strings.Contains(l, "source signing identity changed") {
			named++
		}
	}

	if changed < 0 {
		if verdict.IdentityChangedAt() != "" || named != 0 {
			t.Errorf("IdentityChangedAt = %q, %d log line(s); want no change named",
				verdict.IdentityChangedAt(), named)
		}

		return
	}

	want := chainRev(changed)
	if verdict.IdentityChangedAt() != want {
		t.Errorf("IdentityChangedAt = %q, want %q", verdict.IdentityChangedAt(), want)
	}

	line := "verify: chain acme/widget: source signing identity changed at " + want
	if named != 1 || !slices.Contains(lines, line) {
		t.Errorf("log = %q\nwant exactly one %q", lines, line)
	}
}
