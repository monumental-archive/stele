package convcommit_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/convcommit"
)

// Every refusal, one row each. A parser that accepts prose invents a
// commit type from any message containing a colon, and an invented type
// votes in the version decision.
func TestParseRefuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"empty message", ""},
		{"prose with no colon", "update the readme"},
		{"merge commit", "Merge branch 'main' into topic"},
		{"colon with no space", "feat:no space after the colon"},
		{"revert of a conventional commit is prose", `Revert "feat: add a thing"`},
		{"no description", "feat: "},
		{"whitespace-only description", "feat:    "},
		{"no type", "(api): add a thing"},
		{"unclosed scope", "feat(api: add a thing"},
		{"empty scope", "feat(): add a thing"},
		{"nested parentheses in scope", "feat((api)): add a thing"},
		{"type carries a space", "my feat: add a thing"},
		{"type carries punctuation", "feat.: add a thing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := convcommit.Parse(tc.in)
			if err == nil {
				t.Fatalf("Parse(%q) = %+v, want an error", tc.in, got)
			}

			if !errors.Is(err, convcommit.ErrNotConventional) {
				t.Errorf("Parse(%q) error = %v, want it to wrap ErrNotConventional", tc.in, err)
			}
		})
	}
}

// The spec's own header examples, plus the case rule (§15): type and
// scope are case-insensitive, so they are lowercased once here rather
// than compared case-insensitively at every later use.
func TestParseHeader(t *testing.T) {
	for _, tc := range []struct {
		name             string
		in               string
		typ, scope, desc string
		breaking         bool
	}{
		{
			name: "plain feat", in: "feat: allow provided config object to extend other configs",
			typ: "feat", desc: "allow provided config object to extend other configs",
		},
		{
			name: "scoped", in: "feat(lang): add Polish language",
			typ: "feat", scope: "lang", desc: "add Polish language",
		},
		{
			name: "breaking by bang", in: "feat!: send an email when a product is shipped",
			typ: "feat", desc: "send an email when a product is shipped", breaking: true,
		},
		{
			name: "breaking by bang, scoped", in: "feat(api)!: send an email when a product is shipped",
			typ: "feat", scope: "api", desc: "send an email when a product is shipped", breaking: true,
		},
		{
			name: "type is case-insensitive", in: "FEAT: shout",
			typ: "feat", desc: "shout",
		},
		{
			name: "scope is case-insensitive", in: "Fix(API): mixed case",
			typ: "fix", scope: "api", desc: "mixed case",
		},
		{
			name: "hyphenated type", in: "build-system: retune",
			typ: "build-system", desc: "retune",
		},
		{
			name: "description may contain a colon", in: "docs: release: describe the phases",
			typ: "docs", desc: "release: describe the phases",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := convcommit.Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.in, err)
			}

			if got.Type() != tc.typ {
				t.Errorf("Type() = %q, want %q", got.Type(), tc.typ)
			}

			if got.Scope() != tc.scope {
				t.Errorf("Scope() = %q, want %q", got.Scope(), tc.scope)
			}

			if got.Description() != tc.desc {
				t.Errorf("Description() = %q, want %q", got.Description(), tc.desc)
			}

			if got.IsBreaking() != tc.breaking {
				t.Errorf("IsBreaking() = %v, want %v", got.IsBreaking(), tc.breaking)
			}

			if got.Body() != "" {
				t.Errorf("Body() = %q, want empty for a header-only commit", got.Body())
			}

			if len(got.Footers()) != 0 {
				t.Errorf("Footers() = %v, want none for a header-only commit", got.Footers())
			}
		})
	}
}

// §12, §13 and §16: a break may be declared by "!" in the header or by a
// footer, and the footer token has two legal spellings. IsBreaking must
// answer the same for all of them — a reader that checks one mechanism
// ships a major change as a minor one.
func TestBreakingIsEitherMechanism(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in       string
		breaking bool
		desc     string
	}{
		{
			name:     "bang alone",
			in:       "chore!: drop support for Node 6",
			breaking: true,
		},
		{
			name:     "spaced footer token",
			in:       "chore: drop support for Node 6\n\nBREAKING CHANGE: use features unavailable in Node 6.",
			breaking: true,
			desc:     "use features unavailable in Node 6.",
		},
		{
			name:     "hyphenated footer token",
			in:       "chore: drop support for Node 6\n\nBREAKING-CHANGE: use features unavailable in Node 6.",
			breaking: true,
			desc:     "use features unavailable in Node 6.",
		},
		{
			name:     "both mechanisms agree",
			in:       "chore!: drop support for Node 6\n\nBREAKING CHANGE: node 6 is end of life.",
			breaking: true,
			desc:     "node 6 is end of life.",
		},
		// §15's one exception: BREAKING CHANGE is the single
		// case-sensitive unit. A lowercase token is an ordinary footer,
		// and reading it as a break would let a typo mint a major.
		{
			name:     "lowercase footer token is not a declaration",
			in:       "chore: drop support for Node 6\n\nbreaking-change: not uppercase",
			breaking: false,
		},
		{
			name:     "mixed-case footer token is not a declaration",
			in:       "chore: drop support for Node 6\n\nBreaking-Change: not uppercase",
			breaking: false,
		},
		{
			name:     "no declaration at all",
			in:       "fix: a small thing\n\nRefs: #1",
			breaking: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := convcommit.Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}

			if got.IsBreaking() != tc.breaking {
				t.Errorf("IsBreaking() = %v, want %v", got.IsBreaking(), tc.breaking)
			}

			if got.BreakingDescription() != tc.desc {
				t.Errorf("BreakingDescription() = %q, want %q", got.BreakingDescription(), tc.desc)
			}
		})
	}
}

// The spec's multi-paragraph worked example: body paragraphs are kept
// whole, and the footer section begins at the first token/separator pair.
func TestParseBodyAndFooters(t *testing.T) {
	const message = `fix: prevent racing of requests

Introduce a request id and a reference to latest request. Dismiss
incoming responses other than from latest request.

Remove timeouts which were used to mitigate the racing issue but are
obsolete now.

Reviewed-by: Z
Refs: #123`

	got, err := convcommit.Parse(message)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	wantBody := "Introduce a request id and a reference to latest request. Dismiss\n" +
		"incoming responses other than from latest request.\n\n" +
		"Remove timeouts which were used to mitigate the racing issue but are\n" +
		"obsolete now."
	if got.Body() != wantBody {
		t.Errorf("Body() = %q, want %q", got.Body(), wantBody)
	}

	want := []struct{ token, value string }{
		{"Reviewed-by", "Z"},
		{"Refs", "#123"},
	}

	footers := got.Footers()
	if len(footers) != len(want) {
		t.Fatalf("Footers() = %d footers, want %d", len(footers), len(want))
	}

	for i, w := range want {
		if footers[i].Token() != w.token || footers[i].Value() != w.value {
			t.Errorf("footer %d = %q: %q, want %q: %q",
				i, footers[i].Token(), footers[i].Value(), w.token, w.value)
		}
	}
}

// §8's second separator, and §10's rule that a footer value runs until
// the next token — including across newlines.
func TestFooterSeparatorsAndContinuation(t *testing.T) {
	const message = `feat: a thing

BREAKING CHANGE: the first line
and a continuation line
Closes #17
Signed-off-by: A Person <a@example.com>`

	got, err := convcommit.Parse(message)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if !got.IsBreaking() {
		t.Error("IsBreaking() = false, want true")
	}

	wantDesc := "the first line\nand a continuation line"
	if got.BreakingDescription() != wantDesc {
		t.Errorf("BreakingDescription() = %q, want %q", got.BreakingDescription(), wantDesc)
	}

	want := []struct{ token, value string }{
		{"BREAKING CHANGE", wantDesc},
		// The "#" belongs to the value: "Closes #17" refers to #17.
		{"Closes", "#17"},
		{"Signed-off-by", "A Person <a@example.com>"},
	}

	footers := got.Footers()
	if len(footers) != len(want) {
		t.Fatalf("Footers() = %d footers, want %d", len(footers), len(want))
	}

	for i, w := range want {
		if footers[i].Token() != w.token || footers[i].Value() != w.value {
			t.Errorf("footer %d = %q: %q, want %q: %q",
				i, footers[i].Token(), footers[i].Value(), w.token, w.value)
		}
	}
}

// A body with no footers at all, and CRLF input: git hands back whatever
// the committer's platform wrote, and a stray \r inside a token would
// silently stop it matching.
func TestBodyWithoutFootersAndCRLF(t *testing.T) {
	got, err := convcommit.Parse("fix: a thing\r\n\r\njust a body, no trailers\r\n\r\nRefs: #9")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if got.Body() != "just a body, no trailers" {
		t.Errorf("Body() = %q", got.Body())
	}

	if len(got.Footers()) != 1 || got.Footers()[0].Value() != "#9" {
		t.Errorf("Footers() = %v, want one Refs footer with value #9", got.Footers())
	}

	bodyOnly, err := convcommit.Parse("docs: a thing\n\nplain prose with no trailer lines at all")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(bodyOnly.Footers()) != 0 {
		t.Errorf("Footers() = %v, want none", bodyOnly.Footers())
	}

	if !strings.HasPrefix(bodyOnly.Body(), "plain prose") {
		t.Errorf("Body() = %q", bodyOnly.Body())
	}
}
