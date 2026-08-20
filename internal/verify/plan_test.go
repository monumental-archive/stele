// The release decision borne per planned inventory (stele#158): a
// release shipping per-artifact inventories (.github#492) owes one
// decision per planned document, and the verdict aggregates over the
// plan. The world below is the shape release-lab v0.25.3 published —
// several planned inventories, a union view beside them, and one
// asset (the image inventory, assembled after the commit point) that
// no plan named and no decision covers.

package verify_test

import (
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/monumental-archive/stele/internal/verify"
)

// planWorld is one mutable, fully valid release with a plan: two
// planned inventories, each bearing its own decision, plus the two
// SBOM assets no plan names. Tests mutate one fact and assert the
// guard that fires.
type planWorld struct {
	appSHA   string
	subjects []verify.Subject
	// The SBOM assets, by role.
	inventories []verify.Subject
	unplanned   []verify.Subject
	// decStmt is one decision statement per planned inventory, keyed
	// by the inventory's name — so a row can rewrite exactly one.
	decStmt map[string]map[string]any
	// decFor maps an inventory name to the decision bundle serving
	// it: rows drop an entry to leave an inventory undecided, or
	// point two inventories at one bundle to stage an umbrella.
	decFor   map[string]string
	decSAN   string
	provStmt map[string]any

	store fakeStore
}

const (
	npmDoc   = "sbom-npm-widget-wasm-1.2.3.spdx.json"
	pgrxDoc  = "sbom-pgrx-widget-pg16-1.2.3.spdx.json"
	unionDoc = "widget-1.2.3.spdx.json"
	imageDoc = "widget-1.2.3-image.spdx.json"
)

func newPlanWorld() *planWorld {
	appSHA := digestHex([]byte("app bytes"))

	inv := func(name string) verify.Subject {
		return verify.Subject{Name: name, SHA256: digestHex([]byte(name))}
	}

	w := &planWorld{
		appSHA:      appSHA,
		subjects:    []verify.Subject{{Name: "app.tar.gz", SHA256: appSHA}},
		inventories: []verify.Subject{inv(npmDoc), inv(pgrxDoc)},
		unplanned:   []verify.Subject{inv(unionDoc), inv(imageDoc)},
		decSAN:      "https://github.com/" + publishWF + "@" + machineryPin,
		decStmt:     map[string]map[string]any{},
		decFor:      map[string]string{npmDoc: npmDoc, pgrxDoc: pgrxDoc},
	}

	for _, i := range w.inventories {
		w.decStmt[i.Name] = decisionStatement(i)
	}

	w.provStmt = map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []any{
			map[string]any{"name": "app.tar.gz", "digest": map[string]any{"sha256": appSHA}},
		},
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"buildType": buildType,
				"externalParameters": map[string]any{
					"workflow": map[string]any{
						"repository": "https://github.com/acme/widget",
						"ref":        "refs/tags/v1.2.3",
						"path":       ".github/workflows/publish.yml",
					},
				},
				"resolvedDependencies": []any{
					map[string]any{
						"uri":    "git+https://github.com/acme/widget@refs/tags/v1.2.3",
						"digest": map[string]any{"gitCommit": srcRev},
					},
				},
			},
			"runDetails": map[string]any{
				"builder": map[string]any{"id": "https://github.com/" + signerWF + "@" + signerPin},
			},
		},
	}

	return w
}

// decisionStatement is one decision over exactly the subjects given —
// the per-inventory shape the canon's commit point mints once the
// plan is the denominator.
func decisionStatement(subjects ...verify.Subject) map[string]any {
	named := make([]any, 0, len(subjects))
	for _, s := range subjects {
		named = append(named, map[string]any{
			"name": s.Name, "digest": map[string]any{"sha256": s.SHA256},
		})
	}

	return map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       named,
		"predicateType": decisionType,
		"predicate": map[string]any{
			"tag":        "v1.2.3",
			"classes":    []any{"wasm-npm", "pgrx-extension"},
			"conclusion": "OPEN",
			"decidedAt":  "2026-08-19T00:00:00Z",
			"proofs":     map[string]any{},
		},
	}
}

// sboms renders the release's whole SBOM asset list — the planned
// inventories and the documents no plan named, in one manifest, the
// way a release's assets arrive.
func (w *planWorld) sboms() []verify.Subject {
	return append(append([]verify.Subject{}, w.inventories...), w.unplanned...)
}

func (w *planWorld) build(t *testing.T) {
	t.Helper()

	prov := (&fakeBundle{
		Stmt:    mustJSON(t, w.provStmt),
		SAN:     "https://github.com/" + signerWF + "@" + signerPin,
		Issuer:  issuer,
		Digests: []string{w.appSHA},
		Ext: certificate.Extensions{
			BuildSignerDigest:   signerPin,
			RunnerEnvironment:   "github-hosted",
			SourceRepositoryURI: "https://github.com/acme/widget",
			BuildConfigURI: "https://github.com/acme/widget/.github/workflows/publish.yml@" +
				"refs/tags/v1.2.3",
		},
	}).bytes(t)

	bundles := map[string][]verify.StoredBundle{
		w.appSHA: {{URI: "https://store.example/app", Bundle: prov}},
	}

	// Every SBOM asset holds at least the forge's own release
	// attestation — measured on the live release: the store never
	// answers "nothing" for a published asset, and a decision is one
	// bundle among others.
	for _, s := range w.sboms() {
		bundles[s.SHA256] = []verify.StoredBundle{
			{URI: "https://store.example/release/" + s.Name, Bundle: releaseAttestation(t, s)},
		}
	}

	// The decisions, each stored against every digest it names — the
	// attestation API keys by subject digest, so an umbrella bundle
	// answers for each of its subjects.
	minted := map[string][]byte{}

	for _, name := range sortedKeys(w.decFor) {
		stmt, ok := w.decStmt[w.decFor[name]]
		if !ok {
			continue
		}

		key := w.decFor[name]
		if _, done := minted[key]; !done {
			minted[key] = (&fakeBundle{
				Stmt:    mustJSON(t, stmt),
				SAN:     w.decSAN,
				Issuer:  issuer,
				Digests: statementDigests(stmt),
				Ext:     certificate.Extensions{BuildSignerDigest: machineryPin},
			}).bytes(t)
		}

		for _, d := range statementDigests(stmt) {
			bundles[d] = append(bundles[d],
				verify.StoredBundle{URI: "https://store.example/decision/" + key, Bundle: minted[key]})
		}
	}

	w.store = fakeStore{bundles: bundles}
}

// releaseAttestation is the forge's own release attestation over one
// asset: a bundle of another predicate type, so the selection leg is
// exercised on every candidate rather than assumed.
func releaseAttestation(t *testing.T, s verify.Subject) []byte {
	t.Helper()

	return (&fakeBundle{
		Stmt: mustJSON(t, map[string]any{
			"_type": "https://in-toto.io/Statement/v1",
			"subject": []any{
				map[string]any{"name": s.Name, "digest": map[string]any{"sha256": s.SHA256}},
			},
			"predicateType": "https://in-toto.io/attestation/release/v0.2",
			"predicate":     map[string]any{},
		}),
		SAN:     w0ReleaseSAN,
		Issuer:  issuer,
		Digests: []string{s.SHA256},
	}).bytes(t)
}

const w0ReleaseSAN = "https://github.com/acme/widget/.github/workflows/publish.yml@refs/tags/v1.2.3"

// statementDigests reads the sha256 of every subject a statement
// names — the digests the store would key that bundle under.
func statementDigests(stmt map[string]any) []string {
	var out []string

	for _, sub := range asList(stmt["subject"]) {
		// A subject the fixture deliberately left without a sha256 is
		// keyed under nothing — the store's own shape.
		if d, ok := asMap(asMap(sub)["digest"])["sha256"].(string); ok {
			out = append(out, d)
		}
	}

	return out
}

// sortedKeys keeps the fixture's store assembly deterministic — a
// map walk that reorders bundles would make a passing run a coin.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}

	return out
}

func (w *planWorld) run(t *testing.T) (*verify.ReleaseVerdict, error) {
	t.Helper()
	w.build(t)

	return verify.Release(loadPolicy(t), coords, w.subjects,
		verify.SBOMs{Assets: w.sboms(), Planned: w.inventories},
		pins, w.store, fakeBV{}, discardLog)
}

// TestReleasePerInventoryDecisions is the whole point of stele#158:
// N inventories, N decisions, one aggregate verdict — and the union
// view and the image inventory beside them, named by no plan and
// decided by nothing, which is not a defect.
func TestReleasePerInventoryDecisions(t *testing.T) {
	t.Parallel()

	w := newPlanWorld()

	verdict, err := w.run(t)
	if err != nil {
		t.Fatalf("Release = %v", err)
	}

	// One provenance bundle plus one decision per planned inventory:
	// the verdict rests on exactly what it opened.
	if got := verdict.InputAttestations(); len(got) != 3 {
		t.Errorf("InputAttestations = %d entries, want the provenance and both decisions", len(got))
	}

	if got := verdict.SourceRevision(); got != srcRev {
		t.Errorf("SourceRevision = %q, want %q", got, srcRev)
	}
}

// TestReleaseOneDecisionCoveringEveryPlannedInventory pins the shape
// a release may legally take on the way to per-artifact decisions:
// one attestation naming exactly the planned inventories and nothing
// else satisfies the plan, and is listed ONCE however many
// inventories it answers for.
func TestReleaseOneDecisionCoveringEveryPlannedInventory(t *testing.T) {
	t.Parallel()

	w := newPlanWorld()
	umbrella := decisionStatement(w.inventories...)
	w.decStmt = map[string]map[string]any{"umbrella": umbrella}
	w.decFor = map[string]string{npmDoc: "umbrella", pgrxDoc: "umbrella"}

	verdict, err := w.run(t)
	if err != nil {
		t.Fatalf("Release = %v", err)
	}

	if got := verdict.InputAttestations(); len(got) != 2 {
		t.Errorf("InputAttestations = %d entries, want the provenance and the one decision", len(got))
	}
}

// TestReleasePlanRefusals is the guard table: every way the plan and
// the decisions can disagree, each row flipping exactly one fact.
func TestReleasePlanRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(w *planWorld)
		want   string
	}{
		{
			"a planned inventory bears no decision",
			func(w *planWorld) { delete(w.decFor, pgrxDoc) },
			"the release plans this inventory but no verified decision covers it",
		},
		{
			"the release-wide decision of the pre-plan machinery",
			func(w *planWorld) {
				umbrella := decisionStatement(append(w.sboms(), w.subjects...)...)
				w.decStmt = map[string]map[string]any{"umbrella": umbrella}
				w.decFor = map[string]string{npmDoc: "umbrella", pgrxDoc: "umbrella"}
			},
			"which the release's plan does not",
		},
		{
			"a decision naming the union view beside its inventory",
			func(w *planWorld) {
				w.decStmt[npmDoc] = decisionStatement(w.inventories[0], w.unplanned[0])
			},
			"names " + unionDoc + ", which the release's plan does not",
		},
		{
			"a decision naming a subject with no sha256",
			func(w *planWorld) {
				w.decStmt[npmDoc]["subject"] = append(asList(w.decStmt[npmDoc]["subject"]),
					map[string]any{"name": "odd", "digest": map[string]any{"gitCommit": srcRev}})
			},
			"carries no sha256 digest",
		},
		{
			"one inventory's decision names another tag",
			func(w *planWorld) { dig(w.decStmt[pgrxDoc], "predicate")["tag"] = "v9.9.9" },
			"does not name tag v1.2.3",
		},
		{
			"one inventory's decision is not open",
			func(w *planWorld) { dig(w.decStmt[npmDoc], "predicate")["conclusion"] = "CLOSED" },
			"does not name conclusion OPEN",
		},
		{
			"a decision signed under another identity",
			func(w *planWorld) { w.decSAN = "https://github.com/mallory/canon/publish.yml@" + machineryPin },
			"decision bundle refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newPlanWorld()
			tt.mutate(w)

			if _, err := w.run(t); err == nil {
				t.Fatal("Release accepted what it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Release error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestReleasePlanInputRefusals pins the denominator's own shape: a
// plan is a subset of what shipped, spelled the way the release
// spells it.
func TestReleasePlanInputRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		planned func(w *planWorld) []verify.Subject
		want    string
	}{
		{
			"a planned document the release does not carry",
			func(w *planWorld) []verify.Subject {
				return append(append([]verify.Subject{}, w.inventories...),
					verify.Subject{Name: "sbom-pgrx-widget-pg17-1.2.3.spdx.json", SHA256: digestHex([]byte("absent"))})
			},
			"which is not among the release's SBOM assets",
		},
		{
			"a planned document at another digest",
			func(w *planWorld) []verify.Subject {
				drifted := w.inventories[0]
				drifted.SHA256 = digestHex([]byte("rebuilt"))

				return []verify.Subject{drifted}
			},
			"which is not among the release's SBOM assets",
		},
		{
			"a plan entry that is not a sha256sum record",
			func(*planWorld) []verify.Subject {
				return []verify.Subject{{Name: npmDoc, SHA256: "not-a-digest"}}
			},
			"the plan is the decision's denominator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newPlanWorld()
			w.build(t)

			_, err := verify.Release(loadPolicy(t), coords, w.subjects,
				verify.SBOMs{Assets: w.sboms(), Planned: tt.planned(w)},
				pins, w.store, fakeBV{}, discardLog)
			if err == nil {
				t.Fatal("Release accepted what it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Release error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}
