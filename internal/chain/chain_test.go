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

const payloadType = "application/vnd.in-toto+json"

const validNote = `{
  "version": 3,
  "provenance": {"payloadType": "` + payloadType + `", "statement": "` + b64 + `", "bundle": {"dsseEnvelope": {}}},
  "vsa": {"payloadType": "` + payloadType + `", "statement": "` + b64 + `", "bundle": {"dsseEnvelope": {}}}
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
		{"version absent", `"version": 3,`, ``, "version is absent"},
		{"version retired", `"version": 3`, `"version": 2`, "is not 3"},
		{
			"payloadType wrong",
			`"provenance": {"payloadType": "` + payloadType + `"`,
			`"provenance": {"payloadType": "text/plain"`,
			"payloadType is not",
		},
		{
			"provenance absent",
			`"provenance": {"payloadType": "` + payloadType + `", "statement": "` + b64 + `", "bundle": {"dsseEnvelope": {}}},`,
			`"provenance": null,`,
			"provenance is absent",
		},
		{
			"vsa absent",
			`"vsa": {"payloadType": "` + payloadType + `", "statement": "` + b64 + `", "bundle": {"dsseEnvelope": {}}}`,
			`"vsa": null`,
			"vsa is absent",
		},
		{
			"statement empty",
			`"statement": "` + b64 + `", "bundle": {"dsseEnvelope": {}}}
}`,
			`"statement": "", "bundle": {"dsseEnvelope": {}}}
}`,
			"vsa.statement is absent or empty",
		},
		{
			"statement not base64",
			`"statement": "` + b64 + `", "bundle": {"dsseEnvelope": {}}}
}`,
			`"statement": "!!!", "bundle": {"dsseEnvelope": {}}}
}`,
			"vsa.statement",
		},
		{
			"bundle absent",
			`"statement": "` + b64 + `", "bundle": {"dsseEnvelope": {}}}
}`,
			`"statement": "` + b64 + `"}
}`,
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

	ptr, genesis, err := decodePredicate(t, `{"ledgerPrev": `+pointer+`}`).Ledger()
	if err != nil {
		t.Fatalf("Ledger = %v", err)
	}

	if genesis || ptr == nil {
		t.Fatal("Ledger = genesis, want a step")
	}

	if *ptr.Revision != revHex || *ptr.NoteSHA256 != noteHex {
		t.Errorf("Ledger = {%s %s}, want the pointer's values", *ptr.Revision, *ptr.NoteSHA256)
	}
}

func TestLedgerGenesis(t *testing.T) {
	t.Parallel()

	ptr, genesis, err := decodePredicate(t, `{"ledgerPrev": null}`).Ledger()
	if err != nil {
		t.Fatalf("Ledger = %v", err)
	}

	if !genesis || ptr != nil {
		t.Errorf("Ledger = %+v genesis=%v, want genesis", ptr, genesis)
	}
}

func TestLedgerRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  string
		want string
	}{
		// The #349 S3 lesson: absence is never genesis — presence and
		// nullness are judged separately.
		{"key absent is not genesis", `{}`, "ledgerPrev is absent"},
		{
			"pointer not an object",
			`{"ledgerPrev": "` + revHex + `"}`,
			"ledgerPrev",
		},
		{
			"revision abbreviated",
			`{"ledgerPrev": {"revision": "e1ad2dde", "noteSha256": "` + noteHex + `"}}`,
			"full 40-hex",
		},
		{
			"noteSha256 malformed",
			`{"ledgerPrev": {"revision": "` + revHex + `", "noteSha256": "abc"}}`,
			"64 lowercase hex",
		},
		{
			"pointer with unknown field",
			`{"ledgerPrev": {"revision": "` + revHex + `", "noteSha256": "` + noteHex + `", "extra": 1}}`,
			"unknown field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, _, err := decodePredicate(t, tt.doc).Ledger(); err == nil {
				t.Fatal("Ledger accepted a predicate it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Ledger error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestPredicateFullDecode pins the whole documented field set on one
// realistic v3 predicate, healed-link marker included.
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
  "machineryRef": "` + revHex + `",
  "repaired": {"at": "2026-08-16T09:00:00+01:00"}
}`

	p := decodePredicate(t, doc)

	ptr, genesis, err := p.Ledger()
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
