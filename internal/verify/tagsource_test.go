package verify_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/dsse"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

const (
	sourcePolicyURI = "https://github.com/acme/canon/blob/x/slsa/verify-policy.json"
	sourceWhen      = "2026-11-17T12:00:00Z"
	// verdictSAN is the verdict identity at the machinery pin: the
	// verifier workflow lives outside the repository under verification,
	// so its certificate carries the commit-pinned ref.
	verdictSAN = "https://github.com/" + verifierWF + "@" + machineryPin
)

// goldenSourceVerdict is the reviewed statement for the default chain's
// genesis link (an interior link, not the tip) under tag v1.2.3.
var goldenSourceVerdict = filepath.Join("testdata", "source-verdict.golden.json")

// tagProof is a verified tag signature — the trust package's verdict
// shape, as the cli hands it over after VerifyTag passed.
func tagProof() *trust.TagVerdict {
	return &trust.TagVerdict{SAN: "https://github.com/acme/minter", Depth: trust.TagFloorCertificateTransparency}
}

// chainLinks walks the default chain and returns its verdict.
func chainLinks(t *testing.T, h fakeHistory) *verify.ChainVerdict {
	t.Helper()

	v, err := runChain(t, h)
	if err != nil {
		t.Fatalf("Chain = %v", err)
	}

	return v
}

// genesisLink is the verified facts of the chain's founding link —
// an interior link of the default chain, never its tip.
func genesisLink(t *testing.T, h fakeHistory) *verify.TipFacts {
	t.Helper()

	link, ok := chainLinks(t, h).Link(revC1)
	if !ok {
		t.Fatal("Link(genesis) = _, false")
	}

	return link
}

func sourceStatement(t *testing.T, link *verify.TipFacts) []byte {
	t.Helper()

	v, err := verify.NewSourceVerdict(coords, revC1, revC1, tagProof(), link)
	if err != nil {
		t.Fatalf("NewSourceVerdict = %v", err)
	}

	stmt, err := v.Statement(loadPolicy(t), coords, sourcePolicyURI, machineryPin, sourceWhen)
	if err != nil {
		t.Fatalf("Statement = %v", err)
	}

	return stmt
}

// TestChainLinkAccessor: every link the walk verified is reachable by
// revision with the same facts the tip carries; a revision the walk
// never verified is an absence, not a zero.
func TestChainLinkAccessor(t *testing.T) {
	t.Parallel()

	v := chainLinks(t, defaultChain(t))

	tip, _ := v.Tip()

	got, ok := v.Link(revC2)
	if !ok || got != tip {
		t.Errorf("Link(tip) = %v, %v — want the tip's own facts", got, ok)
	}

	genesis, ok := v.Link(revC1)
	if !ok || genesis.Revision() != revC1 {
		t.Fatalf("Link(genesis) = %v, %v", genesis, ok)
	}

	halves := genesis.Halves()
	if len(halves) != 2 ||
		halves[0].URI != "git+https://github.com/acme/widget@refs/notes/commits#"+revC1+"/provenance" ||
		halves[1].URI != "git+https://github.com/acme/widget@refs/notes/commits#"+revC1+"/vsa" {
		t.Errorf("Halves = %+v, want the provenance then the summary half, by ledger address", halves)
	}

	if _, ok := v.Link(revC9); ok {
		t.Error("Link(unwalked) = _, true — the walk verified nothing there")
	}
}

// TestSourceVerdictStatementGolden pins every field of the emitted
// statement: the commit subject with the tag in sourceRefs, the
// source resource, the verdict identity as verifier, the levels
// copied from the link, and the link's halves as inputAttestations.
// The golden file is the reviewed document, formatted for reading;
// the comparison is of the JSON values, so layout is not a field.
func TestSourceVerdictStatementGolden(t *testing.T) {
	t.Parallel()

	stmt := sourceStatement(t, genesisLink(t, defaultChain(t)))

	want, err := os.ReadFile(goldenSourceVerdict) //nolint:gosec // G304: a fixed path under testdata
	if err != nil {
		t.Fatal(err)
	}

	gotValue, err := jsonx.Value(stmt)
	if err != nil {
		t.Fatal(err)
	}

	wantValue, err := jsonx.Value(want)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Errorf("statement drifted from %s:\n%s", goldenSourceVerdict, stmt)
	}
}

func TestNewSourceVerdictRefusals(t *testing.T) {
	t.Parallel()

	h := defaultChain(t)
	genesis := genesisLink(t, h)

	cw := chainWorld{t: t}
	levelless := defaultChain(t)
	levelless.notes = map[string][]byte{revC1: cw.note(3,
		cw.linkStmt(revC1, "ledgerPrev", nil, nil, false), cw.vsaStmt(revC1, []any{}))}
	levelless.tips = map[string]string{"refs/heads/main": revC1}
	empty := genesisLink(t, levelless)

	tests := []struct {
		name    string
		c       verify.Coords
		release string
		target  string
		tag     *trust.TagVerdict
		link    *verify.TipFacts
		want    string
	}{
		{
			"implausible tag",
			verify.Coords{Owner: "acme", Repo: "widget", Tag: "nope"},
			revC1, revC1, tagProof(), genesis, `tag "nope" is not a plausible release tag`,
		},
		{
			"release revision not a commit", coords, "HEAD", revC1, tagProof(), genesis,
			`release revision "HEAD" is not a commit digest`,
		},
		{
			"the tag's signature failed", coords, revC1, revC1, nil, genesis,
			"the tag carries no verified signature",
		},
		{
			"the tag points elsewhere", coords, revC1, revC2, tagProof(), genesis,
			"the tag points at " + revC2 + ", not " + revC1,
		},
		{
			"the commit has no verifying link", coords, revC1, revC1, tagProof(), nil,
			"commit " + revC1 + " carries no verified chain link",
		},
		{
			"a link from another commit", coords, revC2, revC2, tagProof(), genesis,
			"the link verified at " + revC1 + ", the tag's commit is " + revC2,
		},
		{
			"a link with no level", coords, revC1, revC1, tagProof(), empty,
			"claims no level to copy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := verify.NewSourceVerdict(tt.c, tt.release, tt.target, tt.tag, tt.link)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("NewSourceVerdict = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestSourceVerdictStatementRefusals(t *testing.T) {
	t.Parallel()

	v, err := verify.NewSourceVerdict(coords, revC1, revC1, tagProof(), genesisLink(t, defaultChain(t)))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		mutate    func(p *policy.Policy)
		machinery string
		want      string
	}{
		{
			"no verdict identity", func(p *policy.Policy) { p.Trust.Verdict = nil }, machineryPin,
			"declares no trust.verdict",
		},
		{
			"no source section", func(p *policy.Policy) { p.Source = nil }, machineryPin,
			"declares no source section",
		},
		{"unpinned policy", func(*policy.Policy) {}, "main", "not a full commit digest"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := loadPolicy(t)
			tt.mutate(p)

			_, err := v.Statement(p, coords, sourcePolicyURI, tt.machinery, sourceWhen)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Statement = %v, want %q", err, tt.want)
			}
		})
	}
}

// sourceEnvelope signs a statement as the verdict identity would and
// packs it: the bundle scripts the identity, the pin and the digest of
// PAE over the exact statement bytes.
func sourceEnvelope(t *testing.T, stmt []byte, mutate func(*fakeBundle)) []byte {
	t.Helper()

	fb := fakeBundle{
		SAN: verdictSAN, Issuer: issuer,
		Digests: []string{digestHex(dsse.PAE(chain.StatementType, stmt))},
		Ext:     certificate.Extensions{BuildSignerDigest: machineryPin},
	}
	if mutate != nil {
		mutate(&fb)
	}

	env, err := verify.SourceVerdictEnvelope(stmt, fb.bytes(t))
	if err != nil {
		t.Fatal(err)
	}

	return env
}

// restatement edits the default statement as a map and re-renders it.
func restatement(t *testing.T, stmt []byte, edit func(m map[string]any)) []byte {
	t.Helper()

	m, err := jsonx.DecodeBytes[map[string]any](stmt)
	if err != nil {
		t.Fatal(err)
	}

	edit(*m)

	return mustJSON(t, *m)
}

func predicateOf(m map[string]any) map[string]any { return asMap(m["predicate"]) }

func subjectOf(m map[string]any) map[string]any { return asMap(asList(m["subject"])[0]) }

func TestSourceVSA(t *testing.T) {
	t.Parallel()

	h := defaultChain(t)
	link := genesisLink(t, h)
	env := sourceEnvelope(t, sourceStatement(t, link), nil)

	got, err := verify.SourceVSA(loadPolicy(t), coords, pins, revC1, link, env, fakeBV{})
	if err != nil {
		t.Fatalf("SourceVSA = %v", err)
	}

	if got.Commit() != revC1 || strings.Join(got.Levels(), " ") != "SLSA_SOURCE_LEVEL_3" {
		t.Errorf("SourceVSA = %s %v", got.Commit(), got.Levels())
	}
}

// TestSourceVSARefusals is one row per guard of the read, each
// asserting the refusal's message.
func TestSourceVSARefusals(t *testing.T) {
	t.Parallel()

	h := defaultChain(t)
	link := genesisLink(t, h)
	stmt := sourceStatement(t, link)

	cw := chainWorld{t: t}
	lower := defaultChain(t)
	lower.notes = map[string][]byte{revC1: cw.note(3,
		cw.linkStmt(revC1, "ledgerPrev", nil, nil, false), cw.vsaStmt(revC1, []any{"SLSA_SOURCE_LEVEL_2"}))}
	lower.tips = map[string]string{"refs/heads/main": revC1}
	lowLink := genesisLink(t, lower)

	propertied := restatement(t, stmt, func(m map[string]any) {
		predicateOf(m)["verifiedLevels"] = []any{"SLSA_SOURCE_LEVEL_3", "ORG_SOURCE_GATED"}
	})

	envOf := func(edit func(m map[string]any)) []byte {
		return sourceEnvelope(t, restatement(t, stmt, edit), nil)
	}

	rawEnvelope := func(doc map[string]any) []byte { return mustJSON(t, doc) }

	goodBundle := jsonRaw(t, fakeBundle{SAN: verdictSAN, Issuer: issuer})

	tests := []struct {
		name   string
		c      verify.Coords
		commit string
		link   *verify.TipFacts
		noLink bool
		env    []byte
		mutate func(*policy.Policy)
		pins   verify.Pins
		want   string
	}{
		{
			name: "implausible tag", c: verify.Coords{Owner: "acme", Repo: "widget", Tag: "x"},
			env: sourceEnvelope(t, stmt, nil), want: `tag "x" is not a plausible release tag`,
		},
		{
			name: "no verdict identity", env: sourceEnvelope(t, stmt, nil),
			mutate: func(p *policy.Policy) { p.Trust.Verdict = nil }, want: "the policy lacks one",
		},
		{
			name: "unpinned machinery", env: sourceEnvelope(t, stmt, nil),
			pins: verify.Pins{Signer: signerPin, Machinery: "main"}, want: "machinery digest is not a 40-hex commit",
		},
		{
			name: "the commit has no link today", env: sourceEnvelope(t, stmt, nil), noLink: true,
			want: "carries no verified chain link today",
		},
		{name: "not an envelope", env: []byte("not json"), want: "envelope:"},
		{name: "foreign payload type", env: rawEnvelope(map[string]any{
			"payloadType": "text/plain", "statement": b64(stmt), "bundle": goodBundle,
		}), want: "payloadType is not " + chain.StatementType},
		{name: "empty statement", env: rawEnvelope(map[string]any{
			"payloadType": chain.StatementType, "statement": "", "bundle": goodBundle,
		}), want: "statement is absent or empty"},
		{name: "no bundle", env: rawEnvelope(map[string]any{
			"payloadType": chain.StatementType, "statement": b64(stmt),
		}), want: "bundle is absent"},
		{name: "statement not base64", env: rawEnvelope(map[string]any{
			"payloadType": chain.StatementType, "statement": "!!!", "bundle": goodBundle,
		}), want: "statement:"},
		{name: "signed by another identity", env: sourceEnvelope(t, stmt, func(fb *fakeBundle) {
			fb.SAN = "https://github.com/acme/widget/.github/workflows/source-attest.yml@refs/heads/main"
		}), want: "signature refused under " + verdictSAN},
		{name: "signature over other bytes", env: sourceEnvelope(t, stmt, func(fb *fakeBundle) {
			fb.Digests = []string{strings.Repeat("e", 64)}
		}), want: "signature refused"},
		{name: "signed at another pin", env: sourceEnvelope(t, stmt, func(fb *fakeBundle) {
			fb.Ext.BuildSignerDigest = signerPin
		}), want: `signed at "` + signerPin + `", pin is "` + machineryPin + `"`},
		{name: "not a statement", env: sourceEnvelope(t, []byte(`{"_type": 1}`), nil), want: "statement:"},
		{
			name: "invalid statement", env: envOf(func(m map[string]any) { m["subject"] = []any{} }),
			want: "source verdict for v1.2.3:",
		},
		{name: "not a verification summary", env: envOf(func(m map[string]any) {
			m["predicateType"] = sourceType
		}), want: "is not the VSA type"},
		{name: "two subjects", env: envOf(func(m map[string]any) {
			m["subject"] = append(asList(m["subject"]), map[string]any{"digest": map[string]any{"gitCommit": revC2}})
		}), want: "2 subjects — the verdict speaks for one commit"},
		{
			name: "subject is not the tag's commit", commit: revC2, env: sourceEnvelope(t, stmt, nil),
			want: `subject attests commit "` + revC1 + `", the tag's commit is ` + revC2,
		},
		{
			name: "no annotations", env: envOf(func(m map[string]any) { delete(subjectOf(m), "annotations") }),
			want: "the subject carries no sourceRefs",
		},
		{name: "annotations without sourceRefs", env: envOf(func(m map[string]any) {
			subjectOf(m)["annotations"] = map[string]any{"other": true}
		}), want: "the subject carries no sourceRefs"},
		{name: "sourceRefs not a list", env: envOf(func(m map[string]any) {
			subjectOf(m)["annotations"] = map[string]any{"sourceRefs": "refs/tags/v1.2.3"}
		}), want: "sourceRefs:"},
		{name: "a verdict naming another tag", env: envOf(func(m map[string]any) {
			subjectOf(m)["annotations"] = map[string]any{"sourceRefs": []any{"refs/tags/v9.9.9"}}
		}), want: "sourceRefs names \"[refs/tags/v9.9.9]\", not exactly refs/tags/v1.2.3"},
		{name: "a verdict naming the tag and a branch", env: envOf(func(m map[string]any) {
			subjectOf(m)["annotations"] = map[string]any{"sourceRefs": []any{"refs/tags/v1.2.3", "refs/heads/main"}}
		}), want: "not exactly refs/tags/v1.2.3"},
		{name: "predicate not a VSA", env: envOf(func(m map[string]any) {
			m["predicate"] = map[string]any{"surprise": true}
		}), want: "predicate:"},
		{name: "predicate breaks the format", env: envOf(func(m map[string]any) {
			predicateOf(m)["verificationResult"] = "MAYBE"
		}), want: `verificationResult "MAYBE" is neither`},
		{name: "another verifier claimed", env: envOf(func(m map[string]any) {
			predicateOf(m)["verifier"] = map[string]any{"id": linkSAN}
		}), want: "is not the signing identity"},
		{name: "another resource", env: envOf(func(m map[string]any) {
			predicateOf(m)["resourceUri"] = "git+https://github.com/acme/other"
		}), want: `names resource "git+https://github.com/acme/other"`},
		{name: "a failed verdict", env: envOf(func(m map[string]any) {
			predicateOf(m)["verificationResult"] = "FAILED"
		}), want: `verificationResult is "FAILED", not PASSED`},
		{
			name: "higher than the link shows today", link: lowLink, env: sourceEnvelope(t, stmt, nil),
			want: "claims SLSA_SOURCE_LEVEL_3, higher than the commit's link shows (SLSA_SOURCE_LEVEL_2)",
		},
		{
			name: "a property the link no longer carries", env: sourceEnvelope(t, propertied, nil),
			want: `claims "ORG_SOURCE_GATED", which the commit's link no longer carries`,
		},
		{name: "a track the link shows no level for", env: envOf(func(m map[string]any) {
			predicateOf(m)["verifiedLevels"] = []any{"SLSA_BUILD_LEVEL_1"}
		}), want: "the commit's link shows no BUILD level"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := loadPolicy(t)
			if tt.mutate != nil {
				tt.mutate(p)
			}

			c, commit, rowPins := tt.c, tt.commit, tt.pins
			if c == (verify.Coords{}) {
				c = coords
			}

			if commit == "" {
				commit = revC1
			}

			if rowPins == (verify.Pins{}) {
				rowPins = pins
			}

			l := tt.link
			switch {
			case tt.noLink:
				l = nil
			case l == nil:
				l = link
			}

			_, err := verify.SourceVSA(p, c, rowPins, commit, l, tt.env, fakeBV{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("SourceVSA = %v, want %q", err, tt.want)
			}
		})
	}
}
