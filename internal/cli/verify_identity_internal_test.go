package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/claims"
	"github.com/monumental-archive/stele/internal/emit"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
)

// The report fact naming where a chain changed its source-signing
// identity (stele#389). With --json the walk's log line goes to
// stderr, so the report itself must carry the revision for a ledger
// to record — and must carry nothing when the chain never changed.

const (
	tipRev = "2222222222222222222222222222222222222222"

	perRepoSAN = "https://github.com/acme/widget/.github/workflows/source-attest.yml@refs/heads/main"
	sharedSAN  = "https://github.com/acme/signer/.github/workflows/source-sign.yml@refs/heads/main"
)

// twoRevGit is emitRev (root) then tipRev, both on the branch.
type twoRevGit struct{ fakeEmitGit }

func (g *twoRevGit) Tip(string) (string, error) { return tipRev, nil }

func (g *twoRevGit) Parent(rev string) (string, error) {
	if rev == tipRev {
		return emitRev, nil
	}

	return "", nil
}

func (g *twoRevGit) Parents(rev string) ([]string, error) {
	if rev == tipRev {
		return []string{emitRev}, nil
	}

	return nil, nil
}

// sanBundle names the identity that signed it.
type sanBundle struct {
	SAN string `json:"san"`
}

type sanSigner struct{ san string }

func (s sanSigner) Sign([]byte) ([]byte, error) { return jsonx.Marshal(sanBundle{SAN: s.san}) }

func (sanSigner) Check() error { return nil }

// sanBV verifies exactly the identity a bundle names: the one fact
// the source-signing rule classifies by.
type sanBV struct{}

func (sanBV) Blob(raw []byte, id trust.Identity, _ string) (*trust.Verified, error) {
	b, err := jsonx.DecodeForeign[sanBundle](raw)
	if err != nil || b.SAN != id.SAN {
		return nil, errUnusedSeam
	}

	return &trust.Verified{SAN: b.SAN}, nil
}

func (sanBV) Attestation([]byte, trust.Identity, string) (*trust.Verified, error) {
	return nil, errUnusedSeam
}

func (sanBV) Peek([]byte) ([]byte, error) { return nil, errUnusedSeam }

func (sanBV) LoggedAt(v *trust.Verified) (time.Time, error) { return v.LoggedAt() }

// identityPolicy renders the shared test policy with source.identity
// set to current and, when legacy is set, a legacyIdentity.
func identityPolicy(t *testing.T, current, legacy string) string {
	t.Helper()

	old := `"identity": "https://github.com/{owner}/{repo}/.github/workflows/source-attest.yml@refs/heads/main",`
	if !strings.Contains(testPolicy, old) {
		t.Fatal("the test policy no longer carries the source identity this fixture rewrites")
	}

	repl := `"identity": "` + current + `",`
	if legacy != "" {
		repl += ` "legacyIdentity": {"identity": "` + legacy + `"},`
	}

	return strings.Replace(testPolicy, old, repl, 1)
}

// writePolicy puts a rendered policy where the verify verb reads it.
func writePolicy(t *testing.T, doc string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(doc), ownerRW); err != nil {
		t.Fatal(err)
	}

	return path
}

// emitSigned appends one link on rev, signed by san under the given
// policy — the production emitter, so the walk reads what it writes.
func emitSigned(t *testing.T, g emit.Git, doc, rev, san string, genesis bool) {
	t.Helper()

	p, err := policy.Load(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("policy.Load = %v", err)
	}

	readAt := "2026-08-15T00:00:00Z"
	prop := "ORG_SOURCE_GATED"
	ctl := []chain.Control{{Property: &prop, Evidence: jsonx.Raw(`[{"rule":"live"}]`)}}

	in := &emit.ChainInputs{
		Owner: "acme", Repo: "widget", Ref: "refs/heads/main", Rev: rev, Genesis: genesis,
		WorkflowRef:  strings.TrimPrefix(san, "https://github.com/"),
		ActorLogin:   "octocat",
		ActorID:      "583231",
		MachineryRef: strings.Repeat("b", 40),
		PolicyURI:    "https://github.com/acme/canon/blob/x/slsa/verify-policy.json",
		Claims:       &claims.Payload{RulesReadAt: &readAt, RulesetsUpdatedAt: &[]int64{1000000}, Controls: &ctl},
	}

	now := func() time.Time { return time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC) }

	if err := emit.Chain(p, in, g, sanSigner{san: san}, sanBV{}, now, func(string, ...any) {}); err != nil {
		t.Fatalf("emitting %s signed by %s = %v", rev[:7], san, err)
	}
}

func TestVerifyChainReportsTheIdentityChange(t *testing.T) {
	tests := []struct {
		name   string
		genSAN string // the genesis link's signer; the tip is always the shared signer
		legacy string // the verify policy's legacyIdentity; "" = none declared
		want   string // the identityChangedAt fact; "" = absent
	}{
		{name: "the chain changed signer", genSAN: perRepoSAN, legacy: perRepoSAN, want: tipRev},
		{name: "the chain never changed", genSAN: sharedSAN, legacy: perRepoSAN},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swap(t, sanBV{}, scriptedStore{})

			g := &twoRevGit{fakeEmitGit{notes: map[string][]byte{}}}

			// Each link signs under the policy in force when it was
			// signed; the walk then judges both under the moved one.
			emitSigned(t, g, identityPolicy(t, tt.genSAN, ""), emitRev, tt.genSAN, true)

			moved := identityPolicy(t, sharedSAN, tt.legacy)
			emitSigned(t, g, moved, tipRev, sharedSAN, false)

			swapHistory(t, g)

			px := files(t)

			var stdout, stderr bytes.Buffer

			code := Run([]string{
				"verify", "chain", "--json",
				"--policy", writePolicy(t, moved), "--trusted-root", px.root,
				"--repo", "acme/widget", "--git-dir", "ignored-by-the-seam",
			}, &stdout, &stderr)
			if code != exitOK {
				t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
			}

			doc := decodeReport(t, &stdout)

			if got := factOf(doc, "links"); got != "2" {
				t.Errorf("links = %q, want 2", got)
			}

			named := 0

			for _, f := range doc.Facts {
				if f.Name == "identityChangedAt" {
					named++
				}
			}

			switch {
			case tt.want == "" && named != 0:
				t.Errorf("identityChangedAt present (%q) on a chain that never changed", factOf(doc, "identityChangedAt"))
			case tt.want != "" && (named != 1 || factOf(doc, "identityChangedAt") != tt.want):
				t.Errorf("identityChangedAt = %q (%d fact(s)), want exactly one %q",
					factOf(doc, "identityChangedAt"), named, tt.want)
			}
		})
	}
}
