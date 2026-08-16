// Package convcommit parses Conventional Commits 1.0.0 messages into a
// type whose fields have already resolved the spec's awkward parts, so
// no caller has to resolve them again and reach a different answer.
//
// The defect this exists to make unwritable: a breaking change may be
// declared in TWO places — a "!" before the colon in the header (§13) or
// a "BREAKING CHANGE" footer (§12) — and a reader that checks one and
// forgets the other silently ships a major change as a minor one. Commit
// has no "!" accessor and no footer search for callers to get wrong;
// IsBreaking is computed once, from both sources, at parse.
//
// The other three the spec states and implementations drop:
//
//   - Type and scope are case-insensitive (§15). They are lowercased at
//     parse, so a downstream comparison cannot be case-sensitive.
//   - "BREAKING CHANGE" is the ONE case-sensitive unit (§15). A
//     lowercase "breaking-change:" footer is a perfectly good footer and
//     is NOT a breaking-change declaration; treating it as one lets a
//     typo mint a major version.
//   - A message that is not a conventional commit is its own outcome
//     (ErrNotConventional), never a Commit with an empty type. What to
//     do with an unconventional commit is a policy judgement, and a
//     zero-valued Commit would make it look like a decided one.
package convcommit

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrNotConventional reports a message with no conventional header. It
// is a sentinel because "this commit says nothing about versioning" is a
// routine, expected answer a caller must be able to test for without
// matching on diagnostic text.
var ErrNotConventional = errors.New("convcommit: message has no conventional commit header")

// A footer token is a word using "-" in place of whitespace (§9),
// separated by ": " or " #" (§8). "BREAKING CHANGE" is the single
// exception permitted to carry a space, and only in that exact casing —
// §15 makes it the one case-sensitive unit in the format.
var footerRE = regexp.MustCompile(`^(BREAKING CHANGE|[A-Za-z0-9-]+)(: | #)`)

// The two spellings of a breaking-change footer token (§12, §16), both
// uppercase by §15.
const (
	breakingSpaced   = "BREAKING CHANGE"
	breakingHyphened = "BREAKING-CHANGE"
)

// Commit is a parsed conventional commit. Fields are unexported: a
// Commit exists only by way of Parse, so every one a caller holds has
// already satisfied the format.
type Commit struct {
	typ          string
	scope        string
	description  string
	body         string
	footers      []Footer
	breaking     bool
	breakingDesc string
}

// Footer is one trailer: its token as written, and its value with any
// continuation lines joined.
type Footer struct {
	token string
	value string
}

// Token reports the footer's token as written.
func (f Footer) Token() string { return f.token }

// Value reports the footer's value, continuation lines included.
func (f Footer) Value() string { return f.value }

// Parse reads a full commit message — subject line, body and footers.
// A message with no conventional header returns ErrNotConventional.
func Parse(message string) (Commit, error) {
	normalised := strings.ReplaceAll(message, "\r\n", "\n")
	header, rest, _ := strings.Cut(normalised, "\n")

	commit, err := parseHeader(header)
	if err != nil {
		return Commit{}, err
	}

	commit.body, commit.footers = parseBody(rest)

	// §12 and §13 are alternatives, not a precedence: either declares the
	// change breaking. The footer additionally supplies a description,
	// which the header form does not (§13 says the commit description
	// serves instead).
	for _, f := range commit.footers {
		if f.token == breakingSpaced || f.token == breakingHyphened {
			commit.breaking = true
			commit.breakingDesc = f.value

			break
		}
	}

	return commit, nil
}

// parseHeader reads "type(scope)!: description" (§1, §4, §5).
func parseHeader(header string) (Commit, error) {
	// §1 requires a terminal colon AND space; "feat:x" is not a
	// conventional header, and accepting it would invent a type from any
	// message containing a colon.
	prefix, description, ok := strings.Cut(header, ": ")
	if !ok {
		return Commit{}, ErrNotConventional
	}

	description = strings.TrimSpace(description)
	if description == "" {
		return Commit{}, fmt.Errorf("%w: no description after the type", ErrNotConventional)
	}

	var breaking bool

	if strings.HasSuffix(prefix, "!") {
		breaking = true
		prefix = prefix[:len(prefix)-1]
	}

	ts, err := splitTypeScope(prefix)
	if err != nil {
		return Commit{}, err
	}

	return Commit{
		typ:         strings.ToLower(ts.typ),
		scope:       strings.ToLower(ts.scope),
		description: description,
		breaking:    breaking,
	}, nil
}

// typeScope keeps the header's two nouns together. They are the same
// kind of thing in the same order and would transpose silently as a
// positional pair — the reason semver's core is a struct too.
type typeScope struct {
	typ   string
	scope string
}

// splitTypeScope separates "type" from "type(scope)".
func splitTypeScope(prefix string) (typeScope, error) {
	ts := typeScope{typ: prefix}

	if open := strings.IndexByte(prefix, '('); open >= 0 {
		if !strings.HasSuffix(prefix, ")") {
			return typeScope{}, fmt.Errorf("%w: scope is not closed", ErrNotConventional)
		}

		ts = typeScope{typ: prefix[:open], scope: prefix[open+1 : len(prefix)-1]}
		if ts.scope == "" {
			return typeScope{}, fmt.Errorf("%w: scope is empty", ErrNotConventional)
		}

		if strings.ContainsAny(ts.scope, "()") {
			return typeScope{}, fmt.Errorf("%w: scope contains parentheses", ErrNotConventional)
		}
	}

	if ts.typ == "" {
		return typeScope{}, fmt.Errorf("%w: no type", ErrNotConventional)
	}

	// A noun (§1). Anything with whitespace or punctuation is prose that
	// happened to contain a colon — `Revert "feat: x"` is the message
	// this refusal exists for.
	for i := range len(ts.typ) {
		b := ts.typ[i]

		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '-':
		default:
			return typeScope{}, fmt.Errorf("%w: type %q is not a bare word", ErrNotConventional, ts.typ)
		}
	}

	return ts, nil
}

// parseBody splits everything after the header into the body and the
// footer section. The footer section begins at the first line that
// parses as a token/separator pair, which is §9's stated purpose for
// requiring "-" in place of whitespace in tokens: it is what
// distinguishes a trailer from one more body paragraph. A body line that
// happens to look like a trailer is therefore read as one — inherent to
// the format, not a choice made here.
func parseBody(rest string) (string, []Footer) {
	if strings.TrimSpace(rest) == "" {
		return "", nil
	}

	lines := strings.Split(rest, "\n")

	start := len(lines)

	for i, line := range lines {
		if footerRE.MatchString(line) {
			start = i

			break
		}
	}

	body := strings.TrimSpace(strings.Join(lines[:start], "\n"))

	return body, parseFooters(lines[start:])
}

// parseFooters accumulates each trailer's value until the next trailer
// begins (§10).
func parseFooters(lines []string) []Footer {
	var (
		footers []Footer
		current *Footer
	)

	for _, line := range lines {
		if m := footerRE.FindStringSubmatch(line); m != nil {
			if current != nil {
				footers = append(footers, *current)
			}

			token, sep := m[1], m[2]
			value := line[len(token)+len(sep):]

			// " #" is a separator whose "#" belongs to the value (§8):
			// "Closes #17" has the value "#17", not "17".
			if sep == " #" {
				value = "#" + value
			}

			current = &Footer{token: token, value: value}

			continue
		}

		if current != nil {
			current.value = strings.TrimRight(current.value+"\n"+line, "\n")
		}
	}

	if current != nil {
		footers = append(footers, *current)
	}

	return footers
}

// Type reports the commit type, lowercased (§15).
func (c *Commit) Type() string { return c.typ }

// Scope reports the commit scope, lowercased, empty when absent.
func (c *Commit) Scope() string { return c.scope }

// Description reports the header's description.
func (c *Commit) Description() string { return c.description }

// Body reports the message body, empty when absent.
func (c *Commit) Body() string { return c.body }

// Footers reports the trailers in the order written.
func (c *Commit) Footers() []Footer { return c.footers }

// IsBreaking reports whether this commit declares a breaking change, by
// EITHER of the spec's two mechanisms — the header's "!" (§13) or a
// BREAKING CHANGE footer (§12). There is deliberately no way to ask
// about only one of them.
func (c *Commit) IsBreaking() bool { return c.breaking }

// BreakingDescription reports the BREAKING CHANGE footer's text. It is
// empty for a commit that declared its break with "!" alone, where §13
// says the commit description serves as the description.
func (c *Commit) BreakingDescription() string { return c.breakingDesc }
