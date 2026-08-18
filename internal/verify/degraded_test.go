// The walks over degraded evidence: a store that tears mid-run, a
// note whose signature holds over bytes that are not a statement, a
// ledger that names something no link occupies. Every row breaks
// exactly one fact and names the refusal, because each of these read
// as an empty answer would ship a green verdict over evidence nobody
// could read.

package verify_test

import (
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/monumental-archive/stele/internal/verify"
)

// TestChainDegradedHistory walks the ways the object store itself can
// fail a chain walk. A history read that returns nothing must never be
// read as "no chain here".
func TestChainDegradedHistory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func(t *testing.T) fakeHistory
		want  string
	}{
		{
			"the parent read fails",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				h.readErr = map[string]error{"parent": fakeError("ancestry unreadable")}

				return h
			},
			"ancestry unreadable",
		},
		{
			"the note listing fails",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				h.readErr = map[string]error{"noted": fakeError("notes ref unreadable")}

				return h
			},
			"listing notes",
		},
		{
			"a member's note cannot be read",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				// Off the first-parent walk, so only the ledger's
				// member census reads it.
				h.notes[revC9] = w.note(3,
					w.linkStmt(revC9, "ledgerPrev", nil, []string{"ORG_SOURCE_GATED"}, false),
					w.vsaStmt(revC9, []any{"SLSA_SOURCE_LEVEL_3"}))
				h.noteErr = map[string]error{revC9: fakeError("blob unreadable")}

				return h
			},
			"blob unreadable",
		},
		{
			"the store tears between the coverage walk and the ledger walk",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				// The tip's note is read once by coverage, once by the
				// member census, and again by the ledger step.
				reads := 2
				h.noteErrAfter = map[string]*int{revC2: &reads}

				return h
			},
			"io torn re-reading",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := runChain(t, tc.build(t))
			if err == nil {
				t.Fatalf("Chain accepted a history that could not answer, want %q", tc.want)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Chain = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestChainSignedNonsense: the signature is the easy half. Each note
// here is correctly signed over bytes that are not what a link needs,
// so the refusal has to come from JUDGING the content — the boundary
// between "this was signed" and "this says what it must".
func TestChainSignedNonsense(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func(t *testing.T) fakeHistory
		want  string
	}{
		{
			"the provenance half is signed over non-JSON",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				h.notes[revC2] = w.noteHalves(
					w.rawHalf([]byte("not json")),
					w.half(w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"})))

				return h
			},
			"provenance statement",
		},
		{
			"the provenance half is signed over an empty object",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				h.notes[revC2] = w.noteHalves(
					w.rawHalf([]byte(`{}`)),
					w.half(w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"})))

				return h
			},
			"provenance",
		},
		{
			"the summary half is signed over non-JSON",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				prov := w.half(w.linkStmt(revC2, "ledgerPrev", map[string]any{
					"revision": revC1, "noteSha256": digestHex(h.notes[revC1]),
				}, []string{"ORG_SOURCE_GATED"}, false))
				h.notes[revC2] = w.noteHalves(prov, w.rawHalf([]byte("not json")))

				return h
			},
			"vsa statement",
		},
		{
			"the summary predicate is not an object",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				prov := w.half(w.linkStmt(revC2, "ledgerPrev", map[string]any{
					"revision": revC1, "noteSha256": digestHex(h.notes[revC1]),
				}, []string{"ORG_SOURCE_GATED"}, false))
				stmt := w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"})
				stmt["predicate"] = []any{}
				h.notes[revC2] = w.noteHalves(prov, w.half(stmt))

				return h
			},
			"vsa predicate",
		},
		{
			"the summary predicate says nothing",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				prov := w.half(w.linkStmt(revC2, "ledgerPrev", map[string]any{
					"revision": revC1, "noteSha256": digestHex(h.notes[revC1]),
				}, []string{"ORG_SOURCE_GATED"}, false))
				stmt := w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"})
				stmt["predicate"] = map[string]any{}
				h.notes[revC2] = w.noteHalves(prov, w.half(stmt))

				return h
			},
			"verifier.id is absent",
		},
		{
			"the ledger pointer is half-written",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				// A revision with no note digest beside it: absent and
				// genesis-null are different facts, and so is half of one.
				h.notes[revC2] = w.note(3,
					w.linkStmt(revC2, "ledgerPrev", map[string]any{"revision": revC1},
						[]string{"ORG_SOURCE_GATED"}, false),
					w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"}))

				return h
			},
			"noteSha256 must be 64 lowercase hex",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := runChain(t, tc.build(t))
			if err == nil {
				t.Fatalf("Chain accepted signed nonsense, want %q", tc.want)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Chain = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestChainLedgerStepRefusals walks the ledger's own hop. Coverage
// proves the first-parent history; the ledger proves the pointers, and
// a pointer that lands on something unreadable must refuse there —
// this is the property nothing checked before the ledger walk existed.
func TestChainLedgerStepRefusals(t *testing.T) {
	t.Parallel()

	// Each case re-points the tip's ledgerPrev at revC3 and puts
	// something different there. Coverage never reads revC3 (it is off
	// the first-parent walk), so only the ledger step judges it.
	tests := []struct {
		name    string
		atRevC3 func(t *testing.T, w chainWorld) []byte
		want    string
	}{
		{
			"the pointer names scaffolding, not a link",
			func(t *testing.T, _ chainWorld) []byte {
				t.Helper()

				return []byte("activation scaffolding, not a link")
			},
			"no link exists there",
		},
		{
			"the pointer's link is signed over non-JSON",
			func(t *testing.T, w chainWorld) []byte {
				t.Helper()

				return w.noteHalves(
					w.rawHalf([]byte("not json")),
					w.half(w.vsaStmt(revC3, []any{"SLSA_SOURCE_LEVEL_3"})))
			},
			"statement",
		},
		{
			"the pointer's link carries no ledger predicate",
			func(t *testing.T, w chainWorld) []byte {
				t.Helper()

				stmt := w.linkStmt(revC3, "ledgerPrev", nil, []string{"ORG_SOURCE_GATED"}, false)
				stmt["predicate"] = []any{}

				return w.noteHalves(w.half(stmt), w.half(w.vsaStmt(revC3, []any{"SLSA_SOURCE_LEVEL_3"})))
			},
			"predicate",
		},
		{
			"the pointer's link has no ledgerPrev at all",
			func(t *testing.T, w chainWorld) []byte {
				t.Helper()

				stmt := w.linkStmt(revC3, "ledgerPrev", nil, []string{"ORG_SOURCE_GATED"}, false)
				delete(asMap(stmt["predicate"]), "ledgerPrev")

				return w.noteHalves(w.half(stmt), w.half(w.vsaStmt(revC3, []any{"SLSA_SOURCE_LEVEL_3"})))
			},
			"ledgerPrev is absent",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := defaultChain(t)
			w := chainWorld{t: t}

			at3 := tc.atRevC3(t, w)
			h.notes[revC3] = at3

			// The tip's ledger pointer now names revC3, hashed exactly.
			h.notes[revC2] = w.note(3,
				w.linkStmt(revC2, "ledgerPrev", map[string]any{
					"revision": revC3, "noteSha256": digestHex(at3),
				}, []string{"ORG_SOURCE_GATED"}, false),
				w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"}))

			_, err := runChain(t, h)
			if err == nil {
				t.Fatalf("Chain accepted a ledger step it could not read, want %q", tc.want)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Chain = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestChainLedgerPointerUnreadable: the pointer names a revision whose
// note read fails outright. Distinct from "no note there" — one is a
// fact about the chain, the other about the store.
func TestChainLedgerPointerUnreadable(t *testing.T) {
	t.Parallel()

	h := defaultChain(t)
	w := chainWorld{t: t}

	h.notes[revC2] = w.note(3,
		w.linkStmt(revC2, "ledgerPrev", map[string]any{
			"revision": revC9, "noteSha256": strings.Repeat("0", 64),
		}, []string{"ORG_SOURCE_GATED"}, false),
		w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"}))
	h.noteErr = map[string]error{revC9: fakeError("blob unreadable")}

	if _, err := runChain(t, h); err == nil || !strings.Contains(err.Error(), "blob unreadable") {
		t.Fatalf("Chain = %v, want the pointer-read refusal", err)
	}
}

// TestChainCoordsRefusal: the walk names its subject in the identity it
// verifies against, so coordinates it cannot expand are refused before
// any read.
func TestChainCoordsRefusal(t *testing.T) {
	t.Parallel()

	h := defaultChain(t)

	_, err := verify.Chain(loadPolicy(t), verify.Coords{Repo: "widget"}, "refs/heads/main", h, fakeBV{}, discardLog)
	if err == nil {
		t.Fatal("Chain accepted coordinates with no owner")
	}
}

// TestSourceLevelUnreadableCommitTime: the level computation compares
// the policy's continuity start against the tip link's own commit
// time, so a time it cannot parse is a refusal — never a level
// computed as if the property had always been required.
func TestSourceLevelUnreadableCommitTime(t *testing.T) {
	t.Parallel()

	h := defaultChain(t)
	w := chainWorld{t: t}

	stmt := w.linkStmt(revC2, "ledgerPrev", map[string]any{
		"revision": revC1, "noteSha256": digestHex(h.notes[revC1]),
	}, []string{"ORG_SOURCE_GATED"}, false)
	asMap(stmt["predicate"])["commitTime"] = "yesterday"
	h.notes[revC2] = w.noteHalves(w.half(stmt), w.half(w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"})))

	verdict, err := runChain(t, h)
	if err != nil {
		t.Fatalf("Chain = %v — the walk itself does not read the time", err)
	}

	if _, err := verdict.SourceLevel(loadPolicy(t), "main"); err == nil ||
		!strings.Contains(err.Error(), "commitTime") {
		t.Fatalf("SourceLevel = %v, want the commit-time refusal", err)
	}
}

// TestVSAInputRefusals: the consumer read's own preconditions, refused
// before any store is touched.
func TestVSAInputRefusals(t *testing.T) {
	t.Parallel()

	t.Run("a policy with no build section", func(t *testing.T) {
		t.Parallel()

		p := loadPolicy(t)
		p.Build = nil

		if _, err := verify.VSA(p, coords, []verify.Subject{{Name: "a", SHA256: strings.Repeat("a", 64)}},
			pins, fakeStore{}, fakeBV{}, discardLog, &verify.EnrichmentDemand{}); err == nil ||
			!strings.Contains(err.Error(), "no build section") {
			t.Fatalf("VSA = %v, want the missing-build refusal", err)
		}
	})

	t.Run("no subjects", func(t *testing.T) {
		t.Parallel()

		if _, err := verify.VSA(loadPolicy(t), coords, nil, pins,
			fakeStore{}, fakeBV{}, discardLog, &verify.EnrichmentDemand{}); err == nil {
			t.Fatal("VSA verified an empty subject list")
		}
	})
}

// TestChainRetiredNoteFormat: version 2 was retired whole with its
// ledger, so a v2 note is not a link at all — scaffolding. What it must
// never be is a ledger member, because a v2 leaf would fork the ledger.
func TestChainRetiredNoteFormat(t *testing.T) {
	t.Parallel()

	h := defaultChain(t)
	w := chainWorld{t: t}

	h.notes[revC9] = w.note(2,
		w.linkStmt(revC9, "ledgerPrev", nil, []string{"ORG_SOURCE_GATED"}, false),
		w.vsaStmt(revC9, []any{"SLSA_SOURCE_LEVEL_3"}))

	verdict, err := runChain(t, h)
	if err != nil {
		t.Fatalf("Chain = %v — a retired-format note is scaffolding, not a fault", err)
	}

	if verdict.Links() != 2 {
		t.Errorf("Links = %d, want 2 — a v2 note is not a link", verdict.Links())
	}
}

// vsaBundle builds one stored verdict bundle from its parts, so a row
// can break exactly one of them.
func vsaBundle(t *testing.T, fb *fakeBundle) fakeStore {
	t.Helper()

	return fakeStore{bundles: map[string][]verify.StoredBundle{
		digestHex([]byte("app bytes")): {{URI: "https://store.example/vsa", Bundle: fb.bytes(t)}},
	}}
}

// TestVSADegradedStore walks the consumer read's store and bundle
// failures. Every one of them read as "no verdict here" would turn an
// unreadable store into an unverified release reported as verified.
func TestVSADegradedStore(t *testing.T) {
	t.Parallel()

	appSHA := digestHex([]byte("app bytes"))
	subjects := []verify.Subject{{Name: "app.tar.gz", SHA256: appSHA}}
	verdictSAN := "https://github.com/" + verifierWF + "@" + machineryPin

	valid := mustJSON(t, newVSAWorld().stmt)

	tests := []struct {
		name  string
		store fakeStore
		want  string
	}{
		{
			name:  "the store cannot serve the digest",
			store: fakeStore{},
			want:  "no attestation retrievable",
		},
		{
			name: "the bundle cannot be read",
			store: vsaBundle(t, &fakeBundle{
				Broken: true, SAN: verdictSAN, Issuer: issuer, Digests: []string{appSHA},
			}),
			want: "unreadable bundle",
		},
		{
			name: "the bundle payload is not a statement",
			store: vsaBundle(t, &fakeBundle{
				PeekStmt: []byte(`[]`), Stmt: valid,
				SAN: verdictSAN, Issuer: issuer, Digests: []string{appSHA},
			}),
			want: "not a statement",
		},
		{
			name: "the verdict is signed at the wrong pin",
			store: vsaBundle(t, &fakeBundle{
				Stmt: valid, SAN: verdictSAN, Issuer: issuer, Digests: []string{appSHA},
				Ext: certificate.Extensions{BuildSignerDigest: strings.Repeat("f", 40)},
			}),
			want: "verdict signed at",
		},
		{
			// The peek selects, the verified bytes judge: a store that
			// serves one document to the selector and another to the
			// verifier must be caught by re-judging what was verified.
			name: "the verified payload is not a statement",
			store: vsaBundle(t, &fakeBundle{
				PeekStmt: valid, Stmt: []byte(`[]`),
				SAN: verdictSAN, Issuer: issuer, Digests: []string{appSHA},
				Ext: certificate.Extensions{BuildSignerDigest: machineryPin},
			}),
			want: "verified payload is not a statement",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := verify.VSA(loadPolicy(t), coords, subjects, pins, tc.store, fakeBV{}, discardLog,
				&verify.EnrichmentDemand{})
			if err == nil {
				t.Fatalf("VSA accepted a degraded store, want %q", tc.want)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("VSA = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestReleaseVSAPredicateNeedsAPolicyURI: the verdict must name where a
// stranger reads the policy it was judged against, so a render with
// nothing to name refuses rather than emitting an uncheckable verdict.
func TestReleaseVSAPredicateNeedsAPolicyURI(t *testing.T) {
	t.Parallel()

	w := newReleaseWorld()

	verdict, err := w.run(t)
	if err != nil {
		t.Fatalf("Release = %v", err)
	}

	if _, err := verdict.VSAPredicate(loadPolicy(t), coords, "", machineryPin, "2026-08-01T00:00:00Z"); err == nil ||
		!strings.Contains(err.Error(), "verdict predicate") {
		t.Fatalf("VSAPredicate = %v, want the render refusal", err)
	}
}

// TestReleaseProvenanceContentRefusals: the bundle verifies and its
// peeked statement selects it as provenance, but the VERIFIED bytes say
// something a release cannot be judged on. The peek selects; only the
// verified content judges, so every row here has to be caught after
// verification.
func TestReleaseProvenanceContentRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// stmt returns the VERIFIED payload; the peek stays valid.
		stmt func(t *testing.T, w *releaseWorld) []byte
		want string
	}{
		{
			name: "the verified payload is not a statement at all",
			stmt: func(t *testing.T, _ *releaseWorld) []byte {
				t.Helper()

				return []byte(`[]`)
			},
			want: "verified payload is not a statement",
		},
		{
			name: "the provenance predicate names no builder",
			stmt: func(t *testing.T, w *releaseWorld) []byte {
				t.Helper()

				stmt := w.provStmt
				delete(asMap(stmt["predicate"]), "runDetails")

				return mustJSON(t, stmt)
			},
			want: "runDetails is absent",
		},
		{
			name: "externalParameters is not an object",
			stmt: func(t *testing.T, w *releaseWorld) []byte {
				t.Helper()

				dig(w.provStmt, "predicate", "buildDefinition")["externalParameters"] = []any{"not an object"}

				return mustJSON(t, w.provStmt)
			},
			want: "externalParameters",
		},
		{
			name: "the workflow parameter is not an object",
			stmt: func(t *testing.T, w *releaseWorld) []byte {
				t.Helper()

				dig(w.provStmt, "predicate", "buildDefinition")["externalParameters"] = map[string]any{
					"workflow": "not an object",
					"inputs":   map[string]any{},
				}

				return mustJSON(t, w.provStmt)
			},
			want: "externalParameters.workflow",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newReleaseWorld()
			w.build(t)

			peek := mustJSON(t, w.provStmt)
			bundle := (&fakeBundle{
				Stmt: tc.stmt(t, w), PeekStmt: peek,
				SAN: w.provSAN, Issuer: issuer,
				Digests: []string{w.appSHA, w.sbomSHA}, Ext: w.provExt,
			}).bytes(t)
			w.store.bundles[w.appSHA] = []verify.StoredBundle{{URI: "u", Bundle: bundle}}

			_, err := verify.Release(loadPolicy(t), coords, w.subjects, w.sboms, pins, w.store, fakeBV{}, discardLog)
			if err == nil {
				t.Fatalf("Release accepted verified content it cannot judge, want %q", tc.want)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Release = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestReleaseDecisionStoreRefusals: the decision is a SECOND store read
// with the same failure modes as the provenance pass, and every one of
// them must refuse there too. The extra SBOM subject is what makes the
// decision read reach a digest the provenance pass never touched.
func TestReleaseDecisionStoreRefusals(t *testing.T) {
	t.Parallel()

	extraSHA := digestHex([]byte("second sbom bytes"))

	tests := []struct {
		name string
		// at returns what the store holds for the extra SBOM digest;
		// nil means the store cannot serve it at all.
		at   func(t *testing.T, w *releaseWorld) []verify.StoredBundle
		want string
	}{
		{
			name: "the store cannot serve the digest",
			at:   func(*testing.T, *releaseWorld) []verify.StoredBundle { return nil },
			want: "no attestation retrievable",
		},
		{
			name: "the bundle cannot be read",
			at: func(t *testing.T, w *releaseWorld) []verify.StoredBundle {
				t.Helper()

				b := (&fakeBundle{Broken: true, SAN: w.decSAN, Issuer: issuer}).bytes(t)

				return []verify.StoredBundle{{URI: "u", Bundle: b}}
			},
			want: "unreadable bundle",
		},
		{
			name: "the bundle payload is not a statement",
			at: func(t *testing.T, w *releaseWorld) []verify.StoredBundle {
				t.Helper()

				b := (&fakeBundle{
					PeekStmt: []byte(`[]`), Stmt: mustJSON(t, w.decStmt),
					SAN: w.decSAN, Issuer: issuer, Digests: []string{extraSHA},
				}).bytes(t)

				return []verify.StoredBundle{{URI: "u", Bundle: b}}
			},
			want: "not a statement",
		},
		{
			name: "the decision is signed at the wrong pin",
			at: func(t *testing.T, w *releaseWorld) []verify.StoredBundle {
				t.Helper()

				b := (&fakeBundle{
					Stmt: mustJSON(t, w.decStmt),
					SAN:  w.decSAN, Issuer: issuer, Digests: []string{extraSHA},
					Ext: certificate.Extensions{BuildSignerDigest: strings.Repeat("f", 40)},
				}).bytes(t)

				return []verify.StoredBundle{{URI: "u", Bundle: b}}
			},
			want: "decision signed at",
		},
		{
			name: "the verified payload is not a statement",
			at: func(t *testing.T, w *releaseWorld) []verify.StoredBundle {
				t.Helper()

				b := (&fakeBundle{
					PeekStmt: mustJSON(t, w.decStmt), Stmt: []byte(`[]`),
					SAN: w.decSAN, Issuer: issuer, Digests: []string{extraSHA},
					Ext: certificate.Extensions{BuildSignerDigest: machineryPin},
				}).bytes(t)

				return []verify.StoredBundle{{URI: "u", Bundle: b}}
			},
			want: "verified payload is not a statement",
		},
		{
			name: "the verified statement is not a valid one",
			at: func(t *testing.T, w *releaseWorld) []verify.StoredBundle {
				t.Helper()

				b := (&fakeBundle{
					PeekStmt: mustJSON(t, w.decStmt), Stmt: []byte(`{"_type": "x"}`),
					SAN: w.decSAN, Issuer: issuer, Digests: []string{extraSHA},
					Ext: certificate.Extensions{BuildSignerDigest: machineryPin},
				}).bytes(t)

				return []verify.StoredBundle{{URI: "u", Bundle: b}}
			},
			want: "intoto",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newReleaseWorld()
			w.build(t)

			// A second SBOM asset the provenance pass never reads: the
			// decision walk is the only leg that opens its digest.
			w.sboms = append(w.sboms, verify.Subject{Name: "extra.spdx.json", SHA256: extraSHA})

			if at := tc.at(t, w); at != nil {
				w.store.bundles[extraSHA] = at
			}

			_, err := verify.Release(loadPolicy(t), coords, w.subjects, w.sboms, pins, w.store, fakeBV{}, discardLog)
			if err == nil {
				t.Fatalf("Release accepted a degraded decision read, want %q", tc.want)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Release = %v, want it to name %q", err, tc.want)
			}
		})
	}
}
