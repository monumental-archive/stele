package assert_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/report"
)

// The source-verdict obligation (stele#391): from its machinery
// epoch, a release whose tag its repository signs owes the named
// asset; presence asks that it exists, full depth that it verifies.

const sourceAsset = "source-verdict.json"

// sourcePolicyJSON is the evidence fixture policy owing source verdicts
// from the given machinery version, beside a tags section declaring
// the given epochs. The fixture release's machinery version is 9.9.9.
func sourcePolicyJSON(from, epochs string) string {
	doc := strings.Replace(testPolicyJSON, `"schema": 9,`, `"schema": 9,
  "issuer": "https://token.example.com",
  "tags": {"tagPattern": "^v[0-9]", "taggerName": "mint[bot]",
    "identityPattern": "^https://github\\.com/acme/", "proofFloor": {"floor": "certificate-transparency"},
    "notesRef": "refs/notes/commits", "epochs": `+epochs+`},`, 1)

	return strings.Replace(doc, `"storeVsaFromVersion": "1.13.0",`,
		fmt.Sprintf(`"storeVsaFromVersion": "1.13.0", "sourceVerdictFromVersion": %q, "sourceVerdictBundle": %q,`,
			from, sourceAsset), 1)
}

// sourcePolicy is the policy owing source verdicts from the given
// version, over a repository that signs the fixture tag.
func sourcePolicy(t *testing.T, from string) *assert.Policy {
	t.Helper()

	p, err := assert.LoadPolicy(strings.NewReader(sourcePolicyJSON(from, `{"widget": "v0.1.0"}`)))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	return p
}

// withSourceVerdict publishes the verdict asset on the fixture release.
func withSourceVerdict(f *fakeForge) *fakeForge {
	f.assets["widget@v1.0.0"] = append(f.assets["widget@v1.0.0"], sourceAsset)
	f.assetBytes["widget@v1.0.0"][sourceAsset] = `{"the": "envelope"}`

	return f
}

func TestEvidenceSourceVerdictPresence(t *testing.T) {
	t.Parallel()

	const signing = `{"widget": "v0.1.0"}`

	tests := []struct {
		name      string
		from      string
		epochs    string
		published bool
		// absent names the finding a release owing the verdict and
		// missing it carries; "" means the release passes.
		absent bool
	}{
		{name: "at or past the epoch without the verdict fails by name", from: "1.70.0", epochs: signing, absent: true},
		{name: "at or past the epoch with the verdict passes", from: "1.70.0", epochs: signing, published: true},
		{name: "exactly at the epoch owes it", from: "9.9.9", epochs: signing, absent: true},
		{name: "before the epoch owes none", from: "10.0.0", epochs: signing},
		{name: "a repository declared unsigned owes none", from: "1.70.0", epochs: `{"widget": "pending"}`},
		{name: "a repository with no signing epoch owes none", from: "1.70.0", epochs: `{"gadget": "v0.1.0"}`},
		{
			name: "a tag before its repository's signing epoch owes none", from: "1.70.0",
			epochs: `{"widget": "v2.0.0"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := completeRelease()
			if tt.published {
				f = withSourceVerdict(f)
			}

			rep := runEvidenceWith(t, f, nil, sourcePolicyJSON(tt.from, tt.epochs))

			if tt.absent {
				if !hasFinding(rep, sourceAsset, "the source verdict for the tag is absent — owed from machinery "+tt.from) {
					t.Fatalf("findings = %+v, want the absent source verdict by name", rep.Findings())
				}

				return
			}

			if rep.Verdict() != report.VerdictPass {
				t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
			}
		})
	}
}

// TestEvidenceSourceVerdictDeep: full depth runs the verify engine's
// source-verdict read over the asset's bytes at the release's derived
// pins — the release decision's depth split, applied to this verdict.
func TestEvidenceSourceVerdictDeep(t *testing.T) {
	t.Parallel()

	t.Run("a present verdict is verified over its bytes at the derived pins", func(t *testing.T) {
		t.Parallel()

		deep := &fakeDeep{}

		rep := runDeepWalkPolicy(t, withSourceVerdict(deepForge()), deep, sourcePolicy(t, "1.70.0"))
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		if len(deep.sourceEnvelopes) != 1 || deep.sourceEnvelopes[0] != `{"the": "envelope"}` {
			t.Fatalf("SourceVSA saw %q, want the asset's bytes once", deep.sourceEnvelopes)
		}

		if p := deep.sourcePins[0]; p.Machinery != machineryPin40 || p.Signer != signerPin40 {
			t.Errorf("pins = %+v, want the release's derived pins", p)
		}
	})

	t.Run("a verdict that does not verify fails by name", func(t *testing.T) {
		t.Parallel()

		deep := &fakeDeep{sourceErr: errors.New("verify: source verdict for v1.0.0: sourceRefs names another tag")}

		rep := runDeepWalkPolicy(t, withSourceVerdict(deepForge()), deep, sourcePolicy(t, "1.70.0"))
		if !hasFinding(rep, sourceAsset+":deep", "sourceRefs names another tag") {
			t.Fatalf("findings = %+v, want the deep refusal by name", rep.Findings())
		}
	})

	t.Run("an absent verdict is a presence finding and is never read", func(t *testing.T) {
		t.Parallel()

		deep := &fakeDeep{}

		rep := runDeepWalkPolicy(t, deepForge(), deep, sourcePolicy(t, "1.70.0"))
		if !hasFinding(rep, sourceAsset, "absent") || len(deep.sourceEnvelopes) != 0 {
			t.Fatalf("findings = %+v, reads %d — want presence alone", rep.Findings(), len(deep.sourceEnvelopes))
		}
	})

	t.Run("a verdict before the epoch is never read", func(t *testing.T) {
		t.Parallel()

		deep := &fakeDeep{}

		rep := runDeepWalkPolicy(t, withSourceVerdict(deepForge()), deep, sourcePolicy(t, "10.0.0"))
		if rep.Verdict() != report.VerdictPass || len(deep.sourceEnvelopes) != 0 {
			t.Fatalf("verdict %s, reads %d — a release that owes none is asked nothing",
				rep.Verdict(), len(deep.sourceEnvelopes))
		}
	})

	t.Run("an unreadable verdict asset is a deep finding", func(t *testing.T) {
		t.Parallel()

		f := withSourceVerdict(deepForge())
		f.assetErr = map[string]error{"widget@v1.0.0/" + sourceAsset: errors.New("asset vanished")}

		rep := runDeepWalkPolicy(t, f, &fakeDeep{}, sourcePolicy(t, "1.70.0"))
		if !hasFinding(rep, sourceAsset+":deep", "asset vanished") {
			t.Fatalf("findings = %+v, want the unreadable asset under the deep check", rep.Findings())
		}
	})

	t.Run("pins that cannot be derived are a deep finding", func(t *testing.T) {
		t.Parallel()

		f := withSourceVerdict(deepForge())
		f.fileAtErr = map[string]error{"widget:v1.0.0:.github/workflows/publish.yml": errors.New("tree torn")}

		rep := runDeepWalkPolicy(t, f, &fakeDeep{}, sourcePolicy(t, "1.70.0"))
		if !hasFinding(rep, sourceAsset+":deep", "tree torn") {
			t.Fatalf("findings = %+v, want the pin failure under the deep check", rep.Findings())
		}
	})
}

// TestEvidenceSourceVerdictBlind: a read the run could not make is
// never a finding about the release — the walk refuses, naming what it
// never got to see.
func TestEvidenceSourceVerdictBlind(t *testing.T) {
	t.Parallel()

	forbidden := fmt.Errorf("listing: %w", gh.ErrForbidden)

	tests := []struct {
		name  string
		shape func(f *fakeForge, d *fakeDeep)
		want  string
	}{
		{"the asset read is forbidden", func(f *fakeForge, _ *fakeDeep) {
			f.assetErr = map[string]error{"widget@v1.0.0/" + sourceAsset: forbidden}
		}, "deep source verdict check of widget@v1.0.0: the credential cannot read widget@v1.0.0's " + sourceAsset},
		{"the engine's read is forbidden", func(_ *fakeForge, d *fakeDeep) {
			d.sourceErr = forbidden
		}, "deep source verdict check of widget@v1.0.0: the credential cannot read widget@v1.0.0's source verdict"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f, deep := withSourceVerdict(deepForge()), &fakeDeep{}
			tt.shape(f, deep)

			pol := sourcePolicy(t, "1.70.0")

			full, err := assert.NewFullDepth(deep, f,
				"acme/canon/.github/workflows/verify-release.yml", "acme/signer/.github/workflows/sign.yml")
			if err != nil {
				t.Fatal(err)
			}

			src := assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}

			_, err = assert.Evidence(pol, orgPop(t, f, nil), f, src, &fakeAttestor{},
				report.NewJournal(), nil, full, func(string, ...any) {})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Evidence = %v, want %q", err, tt.want)
			}
		})
	}
}

// TestSourceVerdictOwed is the one predicate's table (stele#468): every
// arm, with the reason a refusal carries. The machinery version is the
// release machinery's, never the tag's — the last row is a 0.x tag on
// machinery past the epoch, which owes.
func TestSourceVerdictOwed(t *testing.T) {
	t.Parallel()

	signing := sourcePolicy(t, "1.70.0")
	noEpoch, err := assert.LoadPolicy(strings.NewReader(testPolicyJSON))
	if err != nil {
		t.Fatal(err)
	}

	pending, err := assert.LoadPolicy(strings.NewReader(sourcePolicyJSON("1.70.0", `{"widget": "pending"}`)))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		pol       *assert.Policy
		tag       string
		machinery string
		owed      bool
		why       string
	}{
		{
			"no epoch declared", noEpoch, "v1.0.0", "9.9.9", false,
			"the assert policy declares no evidence.sourceVerdictFromVersion",
		},
		{
			"machinery before the epoch", signing, "v1.0.0", "1.69.9", false,
			"machinery 1.69.9 predates evidence.sourceVerdictFromVersion 1.70.0",
		},
		{
			"a repository declared unsigned", pending, "v1.0.0", "1.70.0", false,
			"the tags section owes no signature on widget@v1.0.0",
		},
		{"at the epoch on a signed tag", signing, "v1.0.0", "1.70.0", true, ""},
		{"a 0.x tag on machinery past the epoch", signing, "v0.2.0", "1.71.0", true, ""},
		{"an unparsable machinery version fails toward the obligation", signing, "v1.0.0", "main", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			owed, why := assert.SourceVerdictOwed(tt.pol.Evidence, tt.pol.Tags, "widget", tt.tag, tt.machinery)
			if owed != tt.owed || why != tt.why {
				t.Fatalf("SourceVerdictOwed = %v %q, want %v %q", owed, why, tt.owed, tt.why)
			}
		})
	}

	// A policy owing nothing because it declares no tags section is
	// refused at load (the epoch needs the tag obligation), so the arm
	// is reached only by passing no tags section at all.
	if owed, why := assert.SourceVerdictOwed(signing.Evidence, nil, "widget", "v1.0.0", "1.70.0"); owed ||
		why != "the assert policy declares no tags section" {
		t.Fatalf("SourceVerdictOwed without tags = %v %q", owed, why)
	}
}
