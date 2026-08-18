// The emitter refusing rather than appending. Extending a chain is the
// one irreversible act in this tool, so everything the emitter cannot
// prove — the tail's own contract, the store's answers, the policy's
// arithmetic — has to stop the run before a link lands. Each row below
// breaks exactly one of those.

package emit_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/dsse"
	"github.com/monumental-archive/stele/internal/emit"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// handNote assembles a v3 note from arbitrary statement bytes, signed
// the way the emitter signs — so a row can put in the tail content the
// emitter itself would never write, with the signature still holding
// over it. What must be refused is the CONTENT.
func handNote(t *testing.T, provStmt, summaryStmt []byte) []byte {
	t.Helper()

	half := func(stmt []byte) map[string]any {
		pae := dsse.PAE(chain.StatementType, stmt)
		bundle := fakeBundle{SAN: identity, Issuer: issuer, Digests: []string{chain.SHA256Hex(pae)}}

		raw, err := jsonx.DecodeBytes[map[string]any](mustJSON(t, bundle))
		if err != nil {
			t.Fatalf("round-tripping the bundle: %v", err)
		}

		return map[string]any{
			"payloadType": chain.StatementType,
			"statement":   base64.StdEncoding.EncodeToString(stmt),
			"bundle":      *raw,
		}
	}

	return mustJSON(t, map[string]any{
		"version":    3,
		"provenance": half(provStmt),
		"vsa":        half(summaryStmt),
	})
}

// linkStatement renders a chain-link provenance statement whose
// predicate the caller supplies, so a row can break one field of it.
func linkStatement(t *testing.T, rev string, predicate any) []byte {
	t.Helper()

	return mustJSON(t, map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"digest": map[string]any{"gitCommit": rev}}},
		"predicateType": sourceType,
		"predicate":     predicate,
	})
}

// TestChainRefusesAnUnprovableTail: the tail is the link this run signs
// on top of, proven with exactly a stranger's inputs. Anything the
// emitter cannot prove about it stops the run — extending past a link
// that fails the published contract is never a fallback.
func TestChainRefusesAnUnprovableTail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		spoil func(t *testing.T, w *world)
		want  string
	}{
		{
			name: "the tail's note cannot be read",
			spoil: func(t *testing.T, w *world) {
				t.Helper()
				w.g.readErr = map[string]error{"Note:" + rev1: fakeError("blob unreadable")}
			},
			want: "blob unreadable",
		},
		{
			name: "the tail's note stops being JSON between the two reads",
			spoil: func(t *testing.T, w *world) {
				t.Helper()
				// Whole when the chain is discovered, broken when the
				// tail is proven: the emitter reads the note twice.
				once := 1
				w.g.mangle = map[string][]byte{rev1: []byte("not json")}
				w.g.mangleAfter = map[string]*int{rev1: &once}
			},
			want: "is not a chain link",
		},
		{
			name: "the tail's note becomes a retired format",
			spoil: func(t *testing.T, w *world) {
				t.Helper()
				once := 1
				w.g.mangle = map[string][]byte{rev1: []byte(`{"version": 1}`)}
				w.g.mangleAfter = map[string]*int{rev1: &once}
			},
			want: "is not a chain link",
		},
		{
			name: "the tail's statement is not a statement",
			spoil: func(t *testing.T, w *world) {
				t.Helper()
				w.g.mangle = map[string][]byte{
					rev1: handNote(t, []byte("not json"), []byte("not json")),
				}
			},
			want: "statement",
		},
		{
			name: "the tail attests no revision at all",
			spoil: func(t *testing.T, w *world) {
				t.Helper()
				stmt := mustJSON(t, map[string]any{
					"_type":         "https://in-toto.io/Statement/v1",
					"subject":       []any{map[string]any{"digest": map[string]any{"sha256": strings.Repeat("a", 64)}}},
					"predicateType": sourceType,
					"predicate":     map[string]any{"ledgerPrev": nil},
				})
				w.g.mangle = map[string][]byte{rev1: handNote(t, stmt, stmt)}
			},
			want: "no subject carries a gitCommit digest",
		},
		{
			name: "the tail attests a different revision",
			spoil: func(t *testing.T, w *world) {
				t.Helper()
				stmt := linkStatement(t, rev4, map[string]any{"ledgerPrev": nil})
				w.g.mangle = map[string][]byte{rev1: handNote(t, stmt, stmt)}
			},
			want: "attests a different revision",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newWorld(t)
			w.found(t) // a real genesis link at rev1, by the engine itself

			tc.spoil(t, w)

			err := w.emit(t)
			if err == nil {
				t.Fatalf("the emitter extended a tail it could not prove, want %q", tc.want)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Chain = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestChainRefusesAnUnreadableLedgerState: the ledger pointer covers
// the predecessor's STORED bytes, so every read that produces those
// bytes has to succeed or the pointer would name something unhashed.
func TestChainRefusesAnUnreadableLedgerState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		spoil func(w *world)
		want  string
	}{
		{
			name: "the note cannot be written",
			spoil: func(w *world) {
				w.g.readErr = map[string]error{"AddNote": fakeError("object store full")}
			},
			want: "object store full",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newWorld(t)
			w.found(t)
			tc.spoil(w)

			err := w.emit(t)
			if err == nil {
				t.Fatalf("the emitter proceeded over %s, want %q", tc.name, tc.want)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Chain = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestChainRefusesMangledStorage: what the next link's ledgerPrev hashes
// is the STORED bytes, so a store that rewrites the note into something
// that is no longer a link must refuse here — not verify red later.
func TestChainRefusesMangledStorage(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.in.Rev = rev1
	w.in.Genesis = true
	w.g.mangle = map[string][]byte{rev1: []byte("storage ate the note")}

	err := w.emit(t)
	if err == nil || !strings.Contains(err.Error(), "no longer decodes as a link") {
		t.Fatalf("Chain = %v, want the read-back refusal", err)
	}
}

// TestChainRefusesAPolicyWithoutSource: the chain emitter's whole
// subject is the source track, so a policy that declares none has
// nothing to emit against.
func TestChainRefusesAPolicyWithoutSource(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.p.Source = nil

	if err := w.emit(t); err == nil || !strings.Contains(err.Error(), "no source section") {
		t.Fatalf("Chain = %v, want the missing-source refusal", err)
	}
}

// TestChainRefusesIncompleteClaims: the claims stage's payload is the
// run's own evidence, and one that says nothing cannot be signed into a
// link that claims something.
func TestChainRefusesIncompleteClaims(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.in.Claims = &emit.Claims{}
	w.in.Genesis = true
	w.in.Rev = rev1

	if err := w.emit(t); err == nil {
		t.Fatal("the emitter signed a link over claims that declare nothing")
	}
}

// TestLevelRefusesAnUnreadablePolicySince: the level computation
// compares each required property's continuity start against the
// commit, so a start it cannot parse computes no level.
func TestLevelRefusesAnUnreadablePolicySince(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.in.Genesis = true
	w.in.Rev = rev1

	bad := "yesterday"
	w.p.Source.ProtectedBranches[0].RequiredProperties[0].Since = &bad

	if err := w.emit(t); err == nil || !strings.Contains(err.Error(), "policy since") {
		t.Fatalf("Chain = %v, want the since refusal", err)
	}
}
