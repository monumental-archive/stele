# When a version identifier moves

One rule, applied everywhere a stele-owned format carries a version
identifier — never three local judgements (stele#107; the same
reasoning as "share the definition, never share the derivation"):

> **A version identifier moves when a reader of the old shape would
> misread the new one — and because stele's readers are deliberately
> strict, every key-set change is a misread. The number names the key
> set; the key set changes, the number moves.**

Removing, renaming, or repurposing a field moves it: an old reader
would bind the wrong meaning or refuse for the wrong reason. Adding
an optional section moves it too — the exemption "a reader ignores
what it does not know" was proposed on #107 and withdrawn there,
because it assumes tolerant readers and ours refuse unknown fields
by design (the jsonx contract): an old tool meeting a new optional
section does not ignore it, it dies on `unknown field`, which is a
refusal for the wrong reason. Additive growth is not free; it is
merely cheap — the bump rides the same PR as the section.

The boundary the number guards is **shipped documents meeting shipped
tools**, not pull requests meeting each other: one schema number
names the key set of a *released* vocabulary, so every key-set change
landing between two releases shares one bump. Schema 2 is whatever
the next stele release reads, however many PRs assembled it.

The identifier is a **refusal boundary, not a compatibility hint**.
Pre-v1 there are no shims and no dual readers (the standing law): a
reader implements exactly one version and refuses every other — but
it must refuse **as a version mismatch, by the gate**, never
incidentally as an unknown-field error from the strict decoder. The
gate therefore runs structurally first: `jsonx.DecodeVersioned` peeks
the declared version tolerantly before the strict decode, so both
legs of the refusal share one definition.

## The identifiers this rule governs

| identifier | lives in | current |
| --- | --- | --- |
| verify policy `schema` | `internal/policy`, [policy-schema.md](policy-schema.md) | 2 |
| assert policy `schema` | `internal/assert`, [assert-policy-schema.md](assert-policy-schema.md) | 2 |
| report `schema` | `internal/report`, [report-schema.md](report-schema.md) | 1 |
| note `version` | `internal/chain`, [chain-format.md](chain-format.md) | 3 |
| evidence-manifest `schema` | `internal/manifest` | 1 |
| org predicate type URIs | **policy data, never code** | see below |

History the rule reads back onto: the #84 vocabulary rename was a
key-set change, so the pre-#84 policies are schema 1 and the current
vocabulary is schema 2 — the bump #84 should have carried, applied
retroactively at #107 so the gate can finally fire for it. The note's
v1→v2→v3 ladder already followed the rule.

## Predicate type URIs

An org-owned predicate type URI (`…/attestations/<name>/v<N>`) is a
schema identifier for the predicate's field set — the one identifier
a *stranger* keys off inside a signed statement. The same rule
applies: a key-set change to the predicate moves the URI's version
segment.

Two consequences, both structural:

- **The URI is policy data, never a literal in stele code**
  (`source.provenancePredicateType`, `trust.decision.predicateType`,
  and kin). Moving it is a policy edit plus re-emission — zero code
  changes — and stele declares exactly one predicate type per
  obligation, so under a bumped URI an old-version claim is simply
  not found and the leg refuses with "no claim covers this subject".
  The URI bump and the re-emission are one action, not two.
- **Signed history is never healed to match.** Statements already
  signed under the old URI remain the accurate name of the old shape
  (the archived v2 ledger's `…/source-provenance/v1` claims stay as
  they are). Only the live side moves.

One predicate gets a stronger rule than "bump on key-set change": the
**source-provenance predicate's URI version segment mirrors the note
format version**, because the predicate is the note's statement
payload and its shape has only ever moved when the note's did
(`canonRef`→`machineryRef` happened at the v2→v3 cutover). One
number, defined once, read in two places — so the live URI is
`…/source-provenance/v3`, not a freshly invented `/v2` whose meaning
would collide with note-v2's. The historical URIs stay as signed.

## Explicitly out of scope

`in-toto.io/Statement/v1`, `slsa.dev/provenance/v1`,
`slsa.dev/verification_summary/v1` and every other spec-owned URI are
versioned by their owners. They are never bumped here, whatever their
field sets do.

## Obligations rhyme: when an obligation begins

A declared obligation needs an answer to "from when" for the same
reason a format needs a version: the corpus contains history from
before the mechanism existed. That question is tracked separately as
stele#109 — the direction there is that a new declared obligation
ships with its epoch field required, so "declared but unanswerable
over history" is unrepresentable. It also conditions predicate-URI
bumps: a bumped URI makes pre-bump attestations unfindable (one
predicate type per obligation, no dual reader), so the bump is free
only where the pre-bump releases carry an epoch exemption anyway.
