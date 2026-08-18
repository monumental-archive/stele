package verify_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/dsse"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/verify"
)

// Revisions of the default two-link chain: c2 is the tip, c1 the
// genesis. c9 exists for grafted leaves.
const (
	revC1 = "1111111111111111111111111111111111111111"
	revC2 = "2222222222222222222222222222222222222222"
	revC3 = "3333333333333333333333333333333333333333"
	revC9 = "9999999999999999999999999999999999999999"
)

const linkSAN = "https://github.com/acme/widget/.github/workflows/source-attest.yml@refs/heads/main"

type fakeHistory struct {
	tips    map[string]string
	parents map[string]string
	notes   map[string][]byte
	tipErr  error
	noteErr map[string]error
	// readErr fails one named read — "parent" or "noted". Keyed rather
	// than a field each so this fixture stays small enough to pass by
	// value: every variant below is a COPY of the default world.
	readErr map[string]error
	// noteErrAfter fails a revision's note read once the counter runs
	// out — a store that tears BETWEEN the coverage walk and the
	// ledger walk, which reads the same revisions again.
	noteErrAfter map[string]*int
}

func (h fakeHistory) Tip(ref string) (string, error) {
	if h.tipErr != nil {
		return "", h.tipErr
	}

	tip, ok := h.tips[ref]
	if !ok {
		return "", fakeError("no such ref " + ref)
	}

	return tip, nil
}

func (h fakeHistory) Parent(rev string) (string, error) {
	if err := h.readErr["parent"]; err != nil {
		return "", err
	}

	return h.parents[rev], nil
}

func (h fakeHistory) Note(rev string) ([]byte, error) {
	if err := h.noteErr[rev]; err != nil {
		return nil, err
	}

	if left, ok := h.noteErrAfter[rev]; ok {
		if *left <= 0 {
			return nil, fakeError("io torn re-reading " + rev)
		}

		*left--
	}

	return h.notes[rev], nil
}

func (h fakeHistory) Noted() ([]string, error) {
	if err := h.readErr["noted"]; err != nil {
		return nil, err
	}

	out := make([]string, 0, len(h.notes))
	for rev := range h.notes {
		out = append(out, rev)
	}

	sort.Strings(out)

	return out, nil
}

// chainWorld builds link notes whose halves the fake verifier will
// accept: statements travel base64 inside the note, bundles script
// the identity and the statement digest.
type chainWorld struct {
	t *testing.T
}

// linkStmt renders one source-provenance statement. ledgerKey is
// "ledgerPrev" (v2) or "prev" (v1); pointer nil means genesis (the
// key PRESENT and null).
func (cw chainWorld) linkStmt(
	rev, ledgerKey string, pointer map[string]any, controls []string, repaired bool,
) map[string]any {
	ctl := make([]any, 0, len(controls))
	for _, c := range controls {
		ctl = append(ctl, map[string]any{"property": c, "evidence": map[string]any{}})
	}

	pred := map[string]any{
		"repository": "acme/widget",
		"ref":        "refs/heads/main",
		"commitTime": "2024-05-01T12:00:00Z",
		"controls":   ctl,
		ledgerKey:    pointer,
	}
	if pointer == nil {
		pred[ledgerKey] = nil
	}

	if repaired {
		pred["repaired"] = map[string]any{"at": "2024-05-02T00:00:00Z"}
	}

	return map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"digest": map[string]any{"gitCommit": rev}}},
		"predicateType": sourceType,
		"predicate":     pred,
	}
}

func (cw chainWorld) vsaStmt(rev string, levels []any) map[string]any {
	return map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"digest": map[string]any{"gitCommit": rev}}},
		"predicateType": "https://slsa.dev/verification_summary/v1",
		"predicate": map[string]any{
			"verifier":           map[string]any{"id": linkSAN},
			"resourceUri":        "git+https://github.com/acme/widget",
			"policy":             map[string]any{"uri": "https://github.com/acme/canon/tree/v1.0.0"},
			"verificationResult": "PASSED",
			"verifiedLevels":     levels,
		},
	}
}

// half packs a statement into a note envelope: base64 statement plus
// a blob bundle over exactly those bytes.
func (cw chainWorld) half(stmt map[string]any) map[string]any {
	raw := mustJSON(cw.t, stmt)

	// The signature covers the DSSE pre-authentication encoding, the
	// exact bytes the walk must reconstruct and verify.
	bundle := fakeBundle{
		SAN: linkSAN, Issuer: issuer,
		Digests: []string{digestHex(dsse.PAE(chain.StatementType, raw))},
	}

	return map[string]any{
		"payloadType": chain.StatementType,
		"statement":   b64(raw),
		"bundle":      jsonRaw(cw.t, bundle),
	}
}

func jsonRaw(t *testing.T, v any) map[string]any {
	t.Helper()

	// Round-trip through jsonx so the note carries the bundle inline.
	out, err := jsonx.DecodeBytes[map[string]any](mustJSON(t, v))
	if err != nil {
		t.Fatalf("round-trip: %v", err)
	}

	return *out
}

func (cw chainWorld) note(version int, prov, vsa map[string]any) []byte {
	return mustJSON(cw.t, map[string]any{
		"version":    version,
		"provenance": cw.half(prov),
		"vsa":        cw.half(vsa),
	})
}

// defaultChain is the happy world: c2 (tip, v2 link) → c1 (v2
// genesis), both fully signed, levels claimed at target. Note bytes
// are reachable through the returned history's notes map.
func defaultChain(t *testing.T) fakeHistory {
	t.Helper()

	cw := chainWorld{t: t}

	genesis := cw.note(3,
		cw.linkStmt(revC1, "ledgerPrev", nil, []string{"ORG_SOURCE_GATED"}, false),
		cw.vsaStmt(revC1, []any{"SLSA_SOURCE_LEVEL_3"}))

	tip := cw.note(3,
		cw.linkStmt(revC2, "ledgerPrev", map[string]any{
			"revision": revC1, "noteSha256": digestHex(genesis),
		}, []string{"ORG_SOURCE_GATED"}, false),
		cw.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"}))

	return fakeHistory{
		tips:    map[string]string{"refs/heads/main": revC2},
		parents: map[string]string{revC2: revC1},
		notes:   map[string][]byte{revC2: tip, revC1: genesis},
	}
}

func runChain(t *testing.T, h fakeHistory) (*verify.ChainVerdict, error) {
	t.Helper()

	c := verify.Coords{Owner: "acme", Repo: "widget"}

	return verify.Chain(loadPolicy(t), c, "refs/heads/main", h, fakeBV{}, discardLog)
}

func TestChain(t *testing.T) {
	t.Parallel()

	h := defaultChain(t)

	verdict, err := runChain(t, h)
	if err != nil {
		t.Fatalf("Chain = %v", err)
	}

	if verdict.Links() != 2 {
		t.Errorf("Links = %d, want 2", verdict.Links())
	}

	level, err := verdict.SourceLevel(loadPolicy(t), "main")
	if err != nil {
		t.Fatalf("SourceLevel = %v", err)
	}

	if level != "SLSA_SOURCE_LEVEL_3" {
		t.Errorf("SourceLevel = %q, want SLSA_SOURCE_LEVEL_3", level)
	}
}

func TestChainRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build func(t *testing.T) fakeHistory
		want  string
	}{
		{
			"no chain founded",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				h.notes = map[string][]byte{}

				return h
			},
			"no chain founded",
		},
		{
			"walk ends before genesis",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				delete(h.notes, revC1)

				return h
			},
			"before a genesis link",
		},
		{
			"a hole between links",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				// c3 becomes the tip, carrying the old tip's note
				// re-pointed... simpler: tip at c3 with a fresh link,
				// c2 loses its note, genesis at c1 stays.
				w := chainWorld{t: t}
				tip3 := w.note(3,
					w.linkStmt(revC3, "ledgerPrev", map[string]any{
						"revision": revC1, "noteSha256": digestHex(h.notes[revC1]),
					}, []string{"ORG_SOURCE_GATED"}, false),
					w.vsaStmt(revC3, []any{"SLSA_SOURCE_LEVEL_3"}))
				h.tips["refs/heads/main"] = revC3
				h.parents = map[string]string{revC3: revC2, revC2: revC1}
				genesis := h.notes[revC1]
				h.notes = map[string][]byte{revC3: tip3, revC1: genesis}

				return h
			},
			"unattested revision",
		},
		{
			"tampered statement",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				// The tip's provenance statement re-signed over other
				// bytes: digest binding must refuse.
				stmt := w.linkStmt(revC2, "ledgerPrev", map[string]any{
					"revision": revC1, "noteSha256": digestHex(h.notes[revC1]),
				}, []string{"ORG_SOURCE_GATED"}, false)
				half := w.half(stmt)
				half["statement"] = b64(append(mustJSON(t, stmt), ' '))
				h.notes[revC2] = mustJSON(t, map[string]any{
					"version": 3, "provenance": half,
					"vsa": w.half(w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"})),
				})

				return h
			},
			"provenance refused",
		},
		{
			"foreign predicate type in the provenance half",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				stmt := w.linkStmt(revC1, "ledgerPrev", nil, []string{"ORG_SOURCE_GATED"}, false)
				stmt["predicateType"] = "https://example.com/other/v1"
				h.notes[revC1] = w.note(3, stmt, w.vsaStmt(revC1, []any{"SLSA_SOURCE_LEVEL_3"}))
				// The tip's pointer must keep matching the new bytes.
				tip := w.note(3,
					w.linkStmt(revC2, "ledgerPrev", map[string]any{
						"revision": revC1, "noteSha256": digestHex(h.notes[revC1]),
					}, []string{"ORG_SOURCE_GATED"}, false),
					w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"}))
				h.notes[revC2] = tip

				return h
			},
			"provenance predicate type",
		},
		{
			"link attesting another revision",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				tip := w.note(3,
					w.linkStmt(revC3, "ledgerPrev", map[string]any{
						"revision": revC1, "noteSha256": digestHex(h.notes[revC1]),
					}, []string{"ORG_SOURCE_GATED"}, false),
					w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"}))
				h.notes[revC2] = tip

				return h
			},
			"attests revision",
		},
		{
			"link attesting no revision",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				stmt := w.linkStmt(revC2, "ledgerPrev", map[string]any{
					"revision": revC1, "noteSha256": digestHex(h.notes[revC1]),
				}, []string{"ORG_SOURCE_GATED"}, false)
				stmt["subject"] = []any{map[string]any{"digest": map[string]any{"sha256": digestHex([]byte("x"))}}}
				h.notes[revC2] = w.note(3, stmt, w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"}))

				return h
			},
			"attests no revision",
		},
		{
			"summary half is not a VSA",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				bad := w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"})
				bad["predicateType"] = "https://example.com/other/v1"
				h.notes[revC2] = w.note(3,
					w.linkStmt(revC2, "ledgerPrev", map[string]any{
						"revision": revC1, "noteSha256": digestHex(h.notes[revC1]),
					}, []string{"ORG_SOURCE_GATED"}, false), bad)

				return h
			},
			"not the VSA type",
		},
		{
			"summary claims a foreign verifier identity",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				bad := w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"})
				dig(bad, "predicate")["verifier"] = map[string]any{
					"id": "https://github.com/mallory/widget/.github/workflows/source-attest.yml@refs/heads/main",
				}
				h.notes[revC2] = w.note(3,
					w.linkStmt(revC2, "ledgerPrev", map[string]any{
						"revision": revC1, "noteSha256": digestHex(h.notes[revC1]),
					}, []string{"ORG_SOURCE_GATED"}, false), bad)

				return h
			},
			"not the link signing identity",
		},
		{
			"summary names another resource",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				bad := w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"})
				dig(bad, "predicate")["resourceUri"] = "git+https://github.com/mallory/widget"
				h.notes[revC2] = w.note(3,
					w.linkStmt(revC2, "ledgerPrev", map[string]any{
						"revision": revC1, "noteSha256": digestHex(h.notes[revC1]),
					}, []string{"ORG_SOURCE_GATED"}, false), bad)

				return h
			},
			"names resource",
		},
		{
			"version-gated pointer broken",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				// A note whose predicate carries the retired v1 prev
				// key: the strict decode refuses it as an unknown field
				// — the retired format is unrepresentable, not merely
				// rejected.
				h.notes[revC2] = w.note(3,
					w.linkStmt(revC2, "prev", map[string]any{
						"revision": revC1, "noteSha256": digestHex(h.notes[revC1]),
					}, []string{"ORG_SOURCE_GATED"}, false),
					w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"}))

				return h
			},
			"unknown field",
		},
		{
			"ledger hash mismatch",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				h.notes[revC2] = w.note(3,
					w.linkStmt(revC2, "ledgerPrev", map[string]any{
						"revision": revC1, "noteSha256": digestHex([]byte("wrong")),
					}, []string{"ORG_SOURCE_GATED"}, false),
					w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"}))

				return h
			},
			"ledger hash mismatch",
		},
		{
			"ledger names a revision with no note",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				h.notes[revC2] = w.note(3,
					w.linkStmt(revC2, "ledgerPrev", map[string]any{
						"revision": revC9, "noteSha256": digestHex(h.notes[revC1]),
					}, []string{"ORG_SOURCE_GATED"}, false),
					w.vsaStmt(revC2, []any{"SLSA_SOURCE_LEVEL_3"}))

				return h
			},
			"which has no note",
		},
		{
			"an unreachable leaf outside the enumeration refuses",
			func(t *testing.T) fakeHistory {
				t.Helper()
				h := defaultChain(t)
				w := chainWorld{t: t}
				h.notes[revC9] = w.note(3,
					w.linkStmt(revC9, "ledgerPrev", nil, []string{"ORG_SOURCE_GATED"}, false),
					w.vsaStmt(revC9, []any{"SLSA_SOURCE_LEVEL_3"}))

				return h
			},
			"not enumerated in source.legacyLeaves",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := runChain(t, tt.build(t)); err == nil {
				t.Fatal("Chain accepted what it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Chain error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestChainEnumeratedLeaf pins the exception path: the ONE v1 leaf
// the policy enumerates for this repository passes as named history.
func TestChainEnumeratedLeaf(t *testing.T) {
	t.Parallel()

	h := defaultChain(t)
	w := chainWorld{t: t}

	// A v3 link, off the ledger and off the first-parent walk: the ONLY
	// thing that makes it acceptable is its enumeration in the policy.
	// (This note was a v1 link until the format retirement, which made
	// it scaffolding — not a link at all — and the assertion passed for
	// the wrong reason.)
	h.notes[leafRev] = w.note(3,
		w.linkStmt(leafRev, "ledgerPrev", nil, []string{"ORG_SOURCE_GATED"}, false),
		w.vsaStmt(leafRev, []any{"SLSA_SOURCE_LEVEL_3"}))

	verdict, err := runChain(t, h)
	if err != nil {
		t.Fatalf("Chain = %v, want the enumerated leaf accepted", err)
	}

	// The leaf is off the first-parent walk, so it is a ledger member
	// without being a coverage link.
	if verdict.Links() != 2 {
		t.Errorf("Links = %d, want the two links on the walked history", verdict.Links())
	}
}

// TestChainUnenumeratedLeafRefused is the other half: the same
// off-ledger link at a revision the policy does not name must refuse —
// an exception to a cryptographic walk is itself named, or the ledger
// forks silently.
func TestChainUnenumeratedLeafRefused(t *testing.T) {
	t.Parallel()

	h := defaultChain(t)
	w := chainWorld{t: t}
	h.notes[revC9] = w.note(3,
		w.linkStmt(revC9, "ledgerPrev", nil, []string{"ORG_SOURCE_GATED"}, false),
		w.vsaStmt(revC9, []any{"SLSA_SOURCE_LEVEL_3"}))

	if _, err := runChain(t, h); err == nil ||
		!strings.Contains(err.Error(), "not enumerated in source.legacyLeaves") {
		t.Fatalf("Chain = %v, want the unenumerated-leaf refusal", err)
	}
}

// TestChainScaffoldingNote pins that a non-link note (the seeded
// activation text) is scaffolding — never a link, never a hole at
// the tip, never a ledger member.
func TestChainScaffoldingNote(t *testing.T) {
	t.Parallel()

	h := defaultChain(t)
	h.notes[revC3] = []byte("activation scaffolding, not a link")
	h.tips["refs/heads/main"] = revC3
	h.parents = map[string]string{revC3: revC2, revC2: revC1}

	verdict, err := runChain(t, h)
	if err != nil {
		t.Fatalf("Chain = %v", err)
	}

	if verdict.Links() != 2 {
		t.Errorf("Links = %d, want 2 — scaffolding is not a link", verdict.Links())
	}
}

func TestChainInputRefusals(t *testing.T) {
	t.Parallel()

	h := defaultChain(t)

	t.Run("unqualified ref", func(t *testing.T) {
		t.Parallel()

		c := verify.Coords{Owner: "acme", Repo: "widget"}
		if _, err := verify.Chain(loadPolicy(t), c, "main", h, fakeBV{}, discardLog); err == nil ||
			!strings.Contains(err.Error(), "fully qualified") {
			t.Errorf("Chain = %v, want the unqualified-ref refusal", err)
		}
	})

	t.Run("unresolvable tip", func(t *testing.T) {
		t.Parallel()

		bad := h
		bad.tipErr = fakeError("no such ref")

		if _, err := runChain(t, bad); err == nil || !strings.Contains(err.Error(), "no such ref") {
			t.Errorf("Chain = %v, want the tip failure", err)
		}
	})

	t.Run("note read failure", func(t *testing.T) {
		t.Parallel()

		bad := h
		bad.noteErr = map[string]error{revC2: fakeError("io torn")}

		if _, err := runChain(t, bad); err == nil || !strings.Contains(err.Error(), "io torn") {
			t.Errorf("Chain = %v, want the note failure", err)
		}
	})
}

func TestSourceLevel(t *testing.T) {
	t.Parallel()

	build := func(t *testing.T, controls []string, repaired bool, claimed []any) *verify.ChainVerdict {
		t.Helper()

		w := chainWorld{t: t}
		genesis := w.note(3, w.linkStmt(revC1, "ledgerPrev", nil, controls, repaired), w.vsaStmt(revC1, claimed))
		tip := w.note(3,
			w.linkStmt(revC2, "ledgerPrev", map[string]any{
				"revision": revC1, "noteSha256": digestHex(genesis),
			}, controls, repaired),
			w.vsaStmt(revC2, claimed))

		h := fakeHistory{
			tips:    map[string]string{"refs/heads/main": revC2},
			parents: map[string]string{revC2: revC1},
			notes:   map[string][]byte{revC2: tip, revC1: genesis},
		}

		verdict, err := runChain(t, h)
		if err != nil {
			t.Fatalf("Chain = %v", err)
		}

		return verdict
	}

	t.Run("all required properties present claims the target", func(t *testing.T) {
		t.Parallel()

		verdict := build(t, []string{"ORG_SOURCE_GATED"}, false, []any{"SLSA_SOURCE_LEVEL_3"})

		level, err := verdict.SourceLevel(loadPolicy(t), "main")
		if err != nil || level != "SLSA_SOURCE_LEVEL_3" {
			t.Errorf("SourceLevel = %q, %v — want the target level", level, err)
		}
	})

	t.Run("a missing property under-claims", func(t *testing.T) {
		t.Parallel()

		verdict := build(t, []string{"ORG_SOURCE_OTHER"}, false, []any{"SLSA_SOURCE_LEVEL_2"})

		level, err := verdict.SourceLevel(loadPolicy(t), "main")
		if err != nil || level != "SLSA_SOURCE_LEVEL_2" {
			t.Errorf("SourceLevel = %q, %v — want the under-claim", level, err)
		}
	})

	t.Run("an overclaiming link is a refusal", func(t *testing.T) {
		t.Parallel()

		verdict := build(t, []string{"ORG_SOURCE_OTHER"}, false, []any{"SLSA_SOURCE_LEVEL_3"})

		if _, err := verdict.SourceLevel(loadPolicy(t), "main"); err == nil ||
			!strings.Contains(err.Error(), "disagree") {
			t.Errorf("SourceLevel = %v, want the disagreement refusal", err)
		}
	})

	t.Run("a healed link keeps the target under healedContinuity", func(t *testing.T) {
		t.Parallel()

		verdict := build(t, []string{"ORG_SOURCE_GATED"}, true, []any{"SLSA_SOURCE_LEVEL_3"})

		level, err := verdict.SourceLevel(loadPolicy(t), "main")
		if err != nil || level != "SLSA_SOURCE_LEVEL_3" {
			t.Errorf("SourceLevel = %q, %v — want the continuity argument accepted", level, err)
		}
	})

	t.Run("a healed link under-claims when the stance refuses continuity", func(t *testing.T) {
		t.Parallel()

		verdict := build(t, []string{"ORG_SOURCE_GATED"}, true, []any{"SLSA_SOURCE_LEVEL_2"})

		p := loadPolicy(t)
		refused := false
		p.Source.HealedContinuity = &refused

		level, err := verdict.SourceLevel(p, "main")
		if err != nil || level != "SLSA_SOURCE_LEVEL_2" {
			t.Errorf("SourceLevel = %q, %v — want the under-claim", level, err)
		}
	})

	t.Run("an unprotected branch is a refusal", func(t *testing.T) {
		t.Parallel()

		verdict := build(t, []string{"ORG_SOURCE_GATED"}, false, []any{"SLSA_SOURCE_LEVEL_3"})

		if _, err := verdict.SourceLevel(loadPolicy(t), "trunk"); err == nil ||
			!strings.Contains(err.Error(), "not a protected branch") {
			t.Errorf("SourceLevel = %v, want the unprotected-branch refusal", err)
		}
	})

	t.Run("a zero verdict has no tip to compute from", func(t *testing.T) {
		t.Parallel()

		var zero verify.ChainVerdict
		if _, err := zero.SourceLevel(loadPolicy(t), "main"); err == nil ||
			!strings.Contains(err.Error(), "no tip link") {
			t.Errorf("SourceLevel = %v, want the no-tip refusal", err)
		}
	})

	t.Run("a malformed since in a hand-built policy is a refusal", func(t *testing.T) {
		t.Parallel()

		verdict := build(t, []string{"ORG_SOURCE_GATED"}, false, []any{"SLSA_SOURCE_LEVEL_3"})

		p := loadPolicy(t)
		bad := "not-a-time"
		p.Source.ProtectedBranches[0].RequiredProperties[0].Since = &bad

		if _, err := verdict.SourceLevel(p, "main"); err == nil ||
			!strings.Contains(err.Error(), "since") {
			t.Errorf("SourceLevel = %v, want the since parse refusal", err)
		}
	})
}

// rawHalf packs arbitrary payload bytes as one signed half: the
// signature covers exactly those bytes, so the CONTENT is what the
// walk has to refuse — never the signature. The counterpart of half(),
// which always packs a well-formed statement.
func (cw chainWorld) rawHalf(payload []byte) map[string]any {
	bundle := fakeBundle{
		SAN: linkSAN, Issuer: issuer,
		Digests: []string{digestHex(dsse.PAE(chain.StatementType, payload))},
	}

	return map[string]any{
		"payloadType": chain.StatementType,
		"statement":   b64(payload),
		"bundle":      jsonRaw(cw.t, bundle),
	}
}

// noteHalves assembles a v3 note from two prepared halves.
func (cw chainWorld) noteHalves(prov, summary map[string]any) []byte {
	return mustJSON(cw.t, map[string]any{"version": 3, "provenance": prov, "vsa": summary})
}
