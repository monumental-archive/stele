package chain_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/jsonx"
)

const (
	revHex  = "e1ad2dde9fd24fc521b4b37453dac052e655212b"
	noteHex = "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"
	// "e30=" is base64 for "{}" — a decodable statement placeholder.
	b64 = "e30="
)

const validNote = `{
  "version": 2,
  "provenance": {"statement": "` + b64 + `", "bundle": {"dsseEnvelope": {}}},
  "vsa": {"statement": "` + b64 + `", "bundle": {"dsseEnvelope": {}}}
}`

func decodeNote(t *testing.T, doc string) *chain.Note {
	t.Helper()

	n, err := jsonx.Decode[chain.Note](strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Decode = %v", err)
	}

	return n
}

func TestNoteValidate(t *testing.T) {
	t.Parallel()

	if err := decodeNote(t, validNote).Validate(); err != nil {
		t.Fatalf("Validate(valid) = %v", err)
	}
}

func TestNoteValidateRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		from string
		to   string
		want string
	}{
		{"version absent", `"version": 2,`, ``, "version is absent"},
		{"version unknown", `"version": 2`, `"version": 3`, "neither 1 nor 2"},
		{
			"provenance absent",
			`"provenance": {"statement": "` + b64 + `", "bundle": {"dsseEnvelope": {}}},`,
			`"provenance": null,`,
			"provenance is absent",
		},
		{
			"vsa absent",
			`"vsa": {"statement": "` + b64 + `", "bundle": {"dsseEnvelope": {}}}`,
			`"vsa": null`,
			"vsa is absent",
		},
		{
			"statement empty",
			`"vsa": {"statement": "` + b64 + `"`,
			`"vsa": {"statement": ""`,
			"vsa.statement is absent or empty",
		},
		{
			"statement not base64",
			`"vsa": {"statement": "` + b64 + `"`,
			`"vsa": {"statement": "!!!"`,
			"vsa.statement",
		},
		{
			"bundle absent",
			`"vsa": {"statement": "` + b64 + `", "bundle": {"dsseEnvelope": {}}}`,
			`"vsa": {"statement": "` + b64 + `"}`,
			"vsa.bundle is absent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if n := strings.Count(validNote, tt.from); n != 1 {
				t.Fatalf("mutation target %q occurs %d times, want exactly 1", tt.from, n)
			}

			doc := strings.Replace(validNote, tt.from, tt.to, 1)

			if err := decodeNote(t, doc).Validate(); err == nil {
				t.Fatal("Validate accepted a note it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Validate error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

func decodePredicate(t *testing.T, doc string) *chain.Predicate {
	t.Helper()

	p, err := jsonx.Decode[chain.Predicate](strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Decode = %v", err)
	}

	return p
}

const pointer = `{"revision": "` + revHex + `", "noteSha256": "` + noteHex + `"}`

func TestLedgerStep(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		doc     string
		version int
	}{
		{"v2 step", `{"ledgerPrev": ` + pointer + `}`, chain.NoteV2},
		{"v1 step", `{"prev": ` + pointer + `}`, chain.NoteV1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ptr, genesis, err := decodePredicate(t, tt.doc).Ledger(tt.version)
			if err != nil {
				t.Fatalf("Ledger = %v", err)
			}

			if genesis || ptr == nil {
				t.Fatal("Ledger = genesis, want a step")
			}

			if *ptr.Revision != revHex || *ptr.NoteSHA256 != noteHex {
				t.Errorf("Ledger = {%s %s}, want the pointer's values", *ptr.Revision, *ptr.NoteSHA256)
			}
		})
	}
}

func TestLedgerGenesis(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		doc     string
		version int
	}{
		{"v2 genesis", `{"ledgerPrev": null}`, chain.NoteV2},
		{"v1 genesis", `{"prev": null}`, chain.NoteV1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ptr, genesis, err := decodePredicate(t, tt.doc).Ledger(tt.version)
			if err != nil {
				t.Fatalf("Ledger = %v", err)
			}

			if !genesis || ptr != nil {
				t.Errorf("Ledger = %+v genesis=%v, want genesis", ptr, genesis)
			}
		})
	}
}

func TestLedgerRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		doc     string
		version int
		want    string
	}{
		// The #349 S3 lesson, pinned from both directions: absence is
		// never genesis, and the wrong key for the version is never
		// read — a v1 walk that would read ledgerPrev, or a v2 walk
		// that would read prev, is walking the other version's chain.
		{"v2 key absent is not genesis", `{}`, chain.NoteV2, "ledgerPrev is absent"},
		{"v1 key absent is not genesis", `{}`, chain.NoteV1, "prev is absent"},
		{"v2 must not carry prev", `{"ledgerPrev": null, "prev": null}`, chain.NoteV2, "must not carry prev"},
		{"v1 must not carry ledgerPrev", `{"ledgerPrev": null, "prev": null}`, chain.NoteV1, "must not carry ledgerPrev"},
		{"unknown version", `{"ledgerPrev": null}`, 3, "neither 1 nor 2"},
		{
			"pointer not an object",
			`{"ledgerPrev": "` + revHex + `"}`,
			chain.NoteV2,
			"ledgerPrev",
		},
		{
			"revision abbreviated",
			`{"ledgerPrev": {"revision": "e1ad2dde", "noteSha256": "` + noteHex + `"}}`,
			chain.NoteV2,
			"full 40-hex",
		},
		{
			"noteSha256 malformed",
			`{"ledgerPrev": {"revision": "` + revHex + `", "noteSha256": "abc"}}`,
			chain.NoteV2,
			"64 lowercase hex",
		},
		{
			"pointer with unknown field",
			`{"ledgerPrev": {"revision": "` + revHex + `", "noteSha256": "` + noteHex + `", "extra": 1}}`,
			chain.NoteV2,
			"unknown field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, _, err := decodePredicate(t, tt.doc).Ledger(tt.version); err == nil {
				t.Fatal("Ledger accepted a predicate it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Ledger error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestPredicateFullDecode pins the whole documented field set on one
// realistic v2 predicate, healed-link marker included.
func TestPredicateFullDecode(t *testing.T) {
	t.Parallel()

	doc := `{
  "repository": "https://github.com/acme/widget",
  "ref": "refs/heads/main",
  "parents": ["` + revHex + `"],
  "actor": {"login": "octocat", "id": 583231},
  "commitTime": "2026-08-15T12:00:00+01:00",
  "rulesReadAt": "2026-08-15T12:00:05+01:00",
  "controls": [{"property": "ACME_SOURCE_GATED", "evidence": {"rule": "required_status_checks"}}],
  "ledgerPrev": ` + pointer + `,
  "revisionParent": "` + revHex + `",
  "canonRef": "` + revHex + `",
  "repaired": {"at": "2026-08-16T09:00:00+01:00"}
}`

	p := decodePredicate(t, doc)

	ptr, genesis, err := p.Ledger(chain.NoteV2)
	if err != nil {
		t.Fatalf("Ledger = %v", err)
	}

	if genesis || ptr == nil || *ptr.Revision != revHex {
		t.Errorf("Ledger = %+v, want the pointer", ptr)
	}

	if p.Repaired == nil || p.Repaired.At == nil {
		t.Error("Repaired lost in decode — the healed-link marker is load-bearing")
	}

	if len(p.Controls) != 1 || *p.Controls[0].Property != "ACME_SOURCE_GATED" {
		t.Errorf("Controls = %+v, want the one property", p.Controls)
	}
}

// The known answers are computed OUTSIDE this module
// (`printf '{"k":"v"}\n' | sha256sum` and the same without the
// newline), because a golden value the implementation computes for
// itself lets the emit and verify legs drift together — the exact
// mechanism of .github#434. The stripped form is asserted as the
// named wrong answer so that regression has a face here.
const (
	kvRawSHA256      = "85fbce622d07ebfc3e81b7f7b842482ff0b5b24273a371f56537a4a654d4f139"
	kvStrippedSHA256 = "666c1aa02e8068c6d5cc1d3295009432c16790bec28ec8ce119d0d1a18d61319"
)

func TestSHA256HexKnownAnswer(t *testing.T) {
	t.Parallel()

	if got := chain.SHA256Hex([]byte("{\"k\":\"v\"}\n")); got != kvRawSHA256 {
		t.Errorf("SHA256Hex = %s, want %s (the externally computed answer)", got, kvRawSHA256)
	}

	if got := chain.SHA256Hex([]byte(`{"k":"v"}`)); got != kvStrippedSHA256 {
		t.Errorf("SHA256Hex(stripped) = %s, want %s — the two forms must stay distinguishable", got, kvStrippedSHA256)
	}
}
