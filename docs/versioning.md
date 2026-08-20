# When a version identifier moves

One rule, applied everywhere a stele-owned format carries a version
identifier — never a local judgement per document (stele#107; the
same reasoning as "share the definition, never share the
derivation"):

> **A version identifier moves when a reader of the old shape would
> misread the new one. Because stele's readers are strict — unknown
> fields are refused, by the jsonx contract — every key-set change is
> a misread. The number names the key set.**

There is no additive exemption. "An old reader ignores a section it
does not know" was proposed and withdrawn on #107: ours does not
ignore it, it dies on `unknown field`, which is a refusal for the
wrong reason. Adding an optional section moves the number like any
other key-set change; the bump rides the same change that adds it.

The identifier is a **refusal boundary, not a compatibility hint**.
Pre-v1 there are no shims and no dual readers: a reader implements
exactly one version and refuses every other — but it must refuse **as
a version mismatch, by the gate**, never incidentally as an
unknown-field error from the strict decoder. The gate therefore runs
structurally first: `jsonx.DecodeVersioned` peeks the declared
version tolerantly before the strict decode, so both legs of the
refusal share one definition.

## One epoch for live-read documents

Every stele document that is **read live** carries the SAME number,
`schema`, currently **6**:

| document | where |
| --- | --- |
| verify policy | `internal/policy`, [policy-schema.md](policy-schema.md) |
| assert policy | `internal/assert`, [assert-policy-schema.md](assert-policy-schema.md) |
| report | `internal/report`, [report-schema.md](report-schema.md) |

Live-read means nothing historical carries the number: the policies
are read from the consuming tree as it stands now, and a report is
generated fresh by the run that emits it. Bumping them costs a text
edit and nothing else.

Per-document numbers were considered and rejected. They buy
tolerance no reader can use — there are no dual readers, so every
consumer already refuses anything but the one implemented number —
while costing exactly the failure #107 found: a human moves one
number and forgets another, and now an identifier names two shapes.
One number cannot drift from itself. It moves when ANY live-read
document's key set changes, and every document moves with it.

"One number" is also one definition: the constant lives beside the
gate that enforces it (`jsonx.Epoch`), and every document package
references it rather than carrying a copy — share the definition,
never share the derivation.

The boundary it guards is **shipped documents meeting shipped
tools**, not pull requests meeting each other: the number names the
key set of a *released* stele, so every key-set change landing
between two releases shares one bump.

## Identifiers written into history keep their own numbers

Two identifiers are NOT part of the epoch, because the documents
carrying them already exist and cannot be rewritten on demand:

| identifier | why it is separate |
| --- | --- |
| chain note `version` (`internal/chain`, [chain-format.md](chain-format.md)) | Notes live in a walked ledger. Moving the number means re-emitting every link; under one epoch, a report field gaining a key would force a ledger re-emission. |
| evidence-manifest `schema` (`internal/evidence`) | Manifests are published assets on releases that already shipped. Moving the number orphans every one of them until it is re-emitted, so under one epoch a report field gaining a key would force a re-emission across the corpus. It moved to 2 when entries gained their type (stele#156) and to 3 when they gained the class that built them (stele#185). |

Both therefore move only when their OWN shape moves, under the same
rule. History is honest about what it holds; it is never renumbered
to match a document it has nothing to do with.

Where the two differ is what can be done about the documents already
written. A chain note is mutable and unattested, so a number moving
means re-emitting the ledger. **A published manifest cannot be
re-emitted at all**: it is an immutable release asset, pinned by
digest in the release's checksum manifest and attested under the
signer's identity at release time. So the manifest's number is
carried by a declared epoch instead — the assert policy's
`manifestSchemaFromVersion` names the machinery version from which a
release owes the current schema, below which an older manifest is
read for exactly what its own schema promised (stele#185). That is
still not a dual-version reader: every field is decoded one way, and
the number selects which fields were PROMISED, never how any of them
is read. The reader refuses a manifest carrying a field its schema
never had as loudly as one missing a field its schema owed.

## Predicate type URIs

An org-owned predicate type URI (`…/attestations/<name>/v<N>`) is a
schema identifier for the predicate's field set — the one identifier
a *stranger* keys off inside a signed statement. The same rule
applies: a key-set change to the predicate moves the URI's version
segment.

Two consequences, both structural:

- **The URI is policy data, never a literal in stele code**
  (`source.provenancePredicateType`, `trust.decision.predicateType`,
  and kin). Moving it is a policy edit — zero code changes — and
  stele declares exactly one predicate type per obligation, so under
  a bumped URI an old-version claim is simply not found and the leg
  refuses with "no claim covers this subject". The URI bump and the
  re-emission that makes live evidence match are one action, not two.
- **Signed history is never healed to match.** Statements already
  signed under the old URI remain the accurate name of the shape they
  actually carry. Only the live side moves.

The **source-provenance predicate is a mirror**: its URI version
segment tracks the chain note version, because the predicate IS the
note's statement payload and the two have only ever changed
together. One number, defined once, read in two places — so an
adopter whose notes are at version 3 names that predicate `/v3` in
its own namespace. This is a mirror, not a naming mandate: the
namespace and spelling are the adopter's, only the number is fixed.

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
