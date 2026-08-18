# The chain link: note format, version 3

SLSA v1.2 leaves source provenance "undefined and up to the SCSs to
determine" — and then requires, normatively at L2+, that the SCS
document the format and intent of every source provenance attestation
it produces, and how each can be used to reason about the properties
in the summary attestation. **This document is that format
documentation.** It specifies the bytes: the git note that carries one
chain link, the two statements inside it, the signing rule, and the
ledger semantics. It is implemented by `internal/chain` (the types and
refusals), `internal/emit` (the producer), and `internal/verify` (the
walk); the example documents below are validated against the
implementation by `internal/chain/doc_test.go`, so this file cannot
describe a note the engine refuses.

The universality boundary, stated once: this file specifies the
**format**. Which predicate type URI names the provenance, which
identity signs, and which `resourceUri` template the VSA carries are
policy values (`docs/policy-schema.md`); which refs an organization
attests, who founded its chains and when, and its heal history are
that organization's narrative, recorded in its own documentation.
Examples below use `acme` placeholders; no organization name is
normative here.

## The note

One chain link is one git note on the attested revision in
`refs/notes/commits`. The note is a JSON document:

```json note
{
  "version": 3,
  "provenance": {
    "payloadType": "application/vnd.in-toto+json",
    "statement": "e30=",
    "bundle": {"dsseEnvelope": {}}
  },
  "vsa": {
    "payloadType": "application/vnd.in-toto+json",
    "statement": "e30=",
    "bundle": {"dsseEnvelope": {}}
  }
}
```

| Field | Rule |
| --- | --- |
| `version` | Must be present and must be `3`. There is no other readable version: earlier formats were retired whole with their ledgers, which were re-emitted at each format bump (the .github#434 healing precedent). A reader that finds another version refuses; it never falls back. |
| `provenance`, `vsa` | Both must be present. A link is provenance AND summary, never one alone. |
| `*.payloadType` | Must be `application/vnd.in-toto+json` — the in-toto statement media type, and the DSSE payload type the signature authenticates (below). |
| `*.statement` | The statement's exact JSON bytes, base64 (standard, padded) — base64 so the signed bytes survive any JSON re-encoding of the note. Must be present, non-empty, and decodable. |
| `*.bundle` | The Sigstore bundle proving the signature. Must be present. It travels as raw JSON: its verification belongs to the trust layer and its exact shape to Sigstore. |

Anything else — an unknown top-level field, a missing half, an
undecodable statement — is refused, not tolerated
(`chain.Note.Validate`, table-tested in `chain_test.go`).

## The signing rule

Each half's bundle signs

```text
PAE(payloadType, statement)
```

— DSSE's pre-authentication encoding over the payload type and the
decoded statement bytes, **never the bare statement bytes**. This is
the point of version 3: the signature authenticates what kind of
document it covers, so a signed statement cannot be replayed as a
different document type. Concretely,

```text
PAE(type, body) = "DSSEv1 " + len(type) + " " + type
                         + " " + len(body) + " " + body
```

with lengths as decimal byte counts (the DSSE spec's definition;
`internal/dsse` pins the spec's own worked example as a known-answer
test).

## The statements

Each statement is an in-toto Statement/v1 whose subject is the
**revision**:

| Field | Rule |
| --- | --- |
| `subject[].digest.gitCommit` | The attested revision — the source track's subject form. At least one subject must carry it, and it must name the revision the note annotates; content is judged, never array position. |
| `subject[].uri` | The revision's page for humans (`<server>/<owner>/<repo>/commit/<sha>`). |
| `subject[].annotations.sourceRefs` | The protected refs this attestation is about, e.g. `["refs/heads/main"]`. |
| `predicateType` | For the provenance half: the policy's `provenancePredicateType` — an org value, not specified here. For the VSA half: `https://slsa.dev/verification_summary/v1`. |

The VSA predicate is the spec's verification summary, derived from
the **verified** provenance only: the provenance is signed first,
self-verified with a stranger's inputs, and the level and properties
are read back out of the verified statement — never recomputed from
live state, which by then is a different moment. `verifiedLevels[0]`
is the computed source level; `verifiedLevels[1..]` are the
provenance's `controls[].property` values verbatim. The level
computation is shared code between the emitter and the verifier
(`internal/emit`, `internal/verify`) — by construction, not by
agreement.

## The provenance predicate

```json predicate
{
  "repository": "https://github.com/acme/widget",
  "ref": "refs/heads/main",
  "parents": ["e1ad2dde9fd24fc521b4b37453dac052e655212b"],
  "actor": {"login": "octocat", "id": 583231},
  "commitTime": "2026-08-15T12:00:00+01:00",
  "rulesReadAt": "2026-08-15T12:00:05+01:00",
  "controls": [
    {"property": "ACME_SOURCE_GATED", "evidence": {"rule": "required_status_checks"}}
  ],
  "ledgerPrev": {
    "revision": "e1ad2dde9fd24fc521b4b37453dac052e655212b",
    "noteSha256": "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"
  },
  "revisionParent": "e1ad2dde9fd24fc521b4b37453dac052e655212b",
  "machineryRef": "e1ad2dde9fd24fc521b4b37453dac052e655212b",
  "repaired": {"at": "2026-08-16T09:00:00+01:00"}
}
```

| Field | Meaning |
| --- | --- |
| `repository` | The attested repository, `<server>/<owner>/<repo>`. |
| `ref` | The protected ref the link attests. |
| `parents` | ALL parent SHAs of the revision (array; more than one for merges; empty array for a root commit — never absent). |
| `actor.login`, `actor.id` | Who triggered the emitting run. For a healed link this is the actor of the *healing* run, not of the original push: the push actor is unrecoverable once its run is lost, and a guessed value would be worse than an honest one. Consumers wanting push-actor identity gate on `repaired`. |
| `commitTime` | The revision's committer timestamp (ISO 8601) — a git fact, contemporaneous even when the signature is not. |
| `rulesReadAt` | When the enforcement state was read from the rules API — the moment the `controls` describe. |
| `controls[]` | `{property, evidence}` pairs: each live source-control property with the rule content that proves it, matched by content, never by ruleset name. A property whose rule is not live is simply absent, which is how a lapse under-claims. The property vocabulary is the organization's, carried by its policy and narrative docs. |
| `ledgerPrev` | The ledger pointer — see "The ledger", below. The key is **present on every link** and null exactly at genesis; it deliberately never omits. |
| `revisionParent` | The revision's git first-parent SHA, or `null` for a root commit — ancestry, semantic only, deliberately separate from `ledgerPrev`. |
| `machineryRef` | The commit of the machinery (action code and policy tree) that produced this link — always a full SHA. |
| `repaired` | Present **exactly on healed links**: `{at}`, the moment the late link was emitted. Its presence is the deviation marker consumers gate on; absent otherwise. |

Decoding is strict throughout: unknown fields are refused
(`internal/jsonx`), and absent is distinguished from null and from
zero — the decode types use pointer fields precisely so that
distinction survives.

## The ledger

`ledgerPrev` names the previous **emitted** note — emission order,
not git ancestry (ancestry travels in `revisionParent` and
`parents`). In the common per-push cadence the two agree; after a
heal they legitimately do not, and that divergence is the record of
the lapse, not a defect.

- `ledgerPrev.revision` — the revision whose note this link was
  signed on top of; the full 40-hex identifier, never abbreviated.
- `ledgerPrev.noteSha256` — 64 lowercase hex: the SHA-256 of that
  note's **raw blob bytes exactly as stored** in the notes ref.

**Stored bytes, not written bytes.** Git normalizes note content on
write (stripspace: a trailing newline is appended). The bytes a
predecessor hash covers are the bytes a later reader will fetch, so
the emitter computes `noteSha256` from the note **read back out of
the object store**, never from bytes it wrote — and the emit leg and
the verify walk render the digest through one shared function
(`chain.SHA256Hex`). Two copies of "the" digest is how the previous
implementation's legs drifted apart (.github#434: one hashed the
stored blob, the other a newline-stripped string, and no test
compared them); here the disagreement is unrepresentable.

A `noteSha256` mismatch proves the predecessor's note changed after
this link was emitted: either the note was rewritten (the notes ref
is world-readable history; a rewrite is visible) or the chain is
being presented out of order.

**Genesis.** The chain is founded exactly once: `ledgerPrev` is
present-and-null on the genesis link and on no other. Genesis is an
explicit founding act, refused forever after on that history — a gap
is debt, healed by late links extending the tail, never a
re-founding. An *absent* `ledgerPrev` key is not genesis; it is a
malformed link and is refused. Presence and nullness are judged
separately, because testing bare null ends a walk at the first
truncated link and calls the truncation clean (the #349 S3 lesson;
`chain.Predicate.Ledger` returns genesis as its own value, never a
nil pointer a caller could mistake for one more step).

**Healing.** Every emission walks from the pushed revision toward
genesis and emits a link for every revision that lacks one, oldest
first, so coverage is complete. A healed link extends the ledger
tail like any other link — the v2 ledger split made heals
tail-extensions instead of forks — and carries `repaired` plus the
honest `actor`.

## The emission contract

The producer's obligations, each of which a consumer may rely on:

- **Preflight before anything irreversible**: the storage identity,
  the signing tool, and a dry-run push are proven before the first
  signature is minted.
- **The tail is verified before it is extended**: the pre-existing
  link this run signs on top of must verify with exactly a
  stranger's inputs (the published identity, the exact statement
  bytes, a subject naming its revision). Extending past a link that
  fails the published contract is never a fallback.
- **Every bundle is self-verified before it is stored**, with the
  same stranger's inputs a consumer would use.
- **Read-back**: after writing, the stored note is read back and
  must still decode as this link, because the stored bytes are what
  the next link's `ledgerPrev` will hash.
- **One compare-and-swap attempt**: the whole
  discover→sign→append sequence targets one observed remote state; a
  rejected push refetches and **rebuilds** — the hash that lands was
  computed against the state that won, never patched up after.

## Verifying a chain

`stele verify` is the reference consumer. It proves two independent
properties, and names their defects separately:

- **Coverage** walks the branch first-parent from tip to the genesis
  link; any revision between links without a link of its own is a
  refusal.
- **Linkage** walks the ledger via its own pointers, proving each
  step's `noteSha256` against the target's stored note bytes, and
  requires every ledger member to be reachable — an unreachable
  member is a silent fork, refused.

Both halves of every link must verify under the pinned identity. To
verify one link by hand, with nothing this tool knows that a
stranger does not:

```sh
git fetch origin '+refs/notes/commits:refs/notes/commits'
note=$(git notes show <rev>)
jq -r '.provenance.statement' <<<"$note" | base64 -d > st.json
jq -c  '.provenance.bundle'   <<<"$note" > pb.json
# The signature covers PAE(payloadType, statement), not st.json:
t='application/vnd.in-toto+json'
{ printf 'DSSEv1 %d %s %d ' "${#t}" "$t" "$(wc -c < st.json)"
  cat st.json; } > pae.bin
cosign verify-blob --bundle pb.json \
  --certificate-identity "<the policy's link identity>" \
  --certificate-oidc-issuer "<the policy's issuer>" \
  pae.bin
```

— and the same with `.vsa.…` for the summary half. Verifying the
bare `st.json` fails by design: an implementation that signs the
statement without its payload type is emitting a pre-v3 format this
engine refuses.

## Refusals

The format's full refusal list, each entry table-tested:

- `version` absent, or any value other than `3`
- a missing `provenance` or `vsa` half
- a `payloadType` other than `application/vnd.in-toto+json`
- an absent, empty, or undecodable `statement`
- an absent `bundle`
- an absent `ledgerPrev` key (absent is never genesis)
- a `ledgerPrev` that is neither null nor a `{revision, noteSha256}`
  object, an abbreviated `revision`, a malformed `noteSha256`, or an
  unknown field in the pointer
- a statement whose subject does not name the annotated revision
  with a `gitCommit` digest
- unknown fields anywhere a typed decode reads
