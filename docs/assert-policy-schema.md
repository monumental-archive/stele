# The assert policy: schema, first cut

The committed data `stele assert` reads — the universality
boundary applied to the comparison verb: **everything org-shaped
lives here, zero org names in code**. Standard formats (Sigstore
bundle JSONL, in-toto statements, the VSA predicate type, sha256
digests) live in code; this file carries only what the walk cannot
know without being told: which evidence classes exist, what assets
each requires, when verdicts moved into the attestation store, where
the humans keep their written-down debt.

Four formats are defined here: the policy file, the release
evidence manifest, the debt file, and the inventory plan. A change to any is a reviewed
edit to this document first.

`schema` is the refusal boundary: current **6**, the one epoch shared
by this policy, the verify policy and the report, so a bump cannot
land on one document and miss another ([docs/versioning.md](versioning.md)).
The gate fires before strict decoding, so another schema refuses as a
version mismatch, never as an unknown-field error.

## The policy file

```json
{
  "schema": 6,
  "debtFile": "security/attestation-debt.txt",
  "population": {
    "repositories": [
      { "repo": ".github" },
      { "repo": "release-lab" },
      { "repo": "stele" },
      {
        "repo": "signer",
        "tracks": ["source"],
        "reason": "publishes no releases; it is the signing workflow repository"
      }
    ]
  },
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "storeVsaFromVersion": "1.13.0",
    "publishWorkflows": ["publish", "self-publish"],
    "classes": {
      "rust-crate": {
        "bundles": ["attestations-crates.intoto.jsonl"],
        "legacyVsaBundles": ["attestations-vsa-crates.intoto.jsonl"]
      },
      "oci-image": { "bundles": ["attestations-image.intoto.jsonl"] },
      "pgrx-extension": {
        "bundles": ["attestations-extensions.intoto.jsonl"],
        "assetPrefixes": [
          { "prefix": "attestations-extimg-pg" },
          { "prefix": "sbom-pgrx-", "owedFrom": "1.42.0" }
        ],
        "enrichment": ["pgrx-base-images", "pgrx-base"]
      }
    }
  }
}
```

- `classes` — each class the org publishes, with the bundle assets it
  requires. `legacyVsaBundles` are additionally required only BEFORE
  the store-VSA epoch; `assetPrefixes` are non-bundle assets required
  by prefix match on the release's asset names. An empty class is a
  validation error: it would assert nothing.
- `classes.<name>.assetPrefixes[].owedFrom` — the machinery version
  (inclusive) from which that one obligation holds, through the same
  shared epoch semantics as every top-level `*FromVersion` field
  (stele#128). Class obligations apply to every release of the class,
  and an asset the machinery only began publishing at some release
  (the per-artifact SBOM inventories, .github#529) would otherwise
  red all of history. The epoch rides on the entry because each
  obligation comes online at its own machinery release. Absent means
  always owed — the correct default for fresh adopters. Declared, it
  is measured at cutover: the first machinery version that publishes
  the asset. Prefixes within a class form a set; an empty prefix or
  an unparsable `owedFrom` refuses at load.
- `classes.<name>.assetPrefixes[].planned` — declares that one
  obligation's fulfillment channel: the document is derived from a
  build-leg inventory plan, so `assert plans` demands, BEFORE
  anything ships, that some plan names a document under this prefix
  (see [The inventory plan](#the-inventory-plan)). Declared, never
  inferred from the prefix's spelling — which obligations plans
  fulfil is an org fact, and one class can owe both a planned
  inventory and an unplanned attestation asset (the `pgrx-extension`
  shape). Absent means the obligation is judged only by the
  post-publish evidence walk.

  The declaration has a second consumer (stele#158): a planned
  document is one the release decision is borne per, so the evidence
  walk hands the verify engine the assets these obligations claim as
  the decision's denominator — one decision per planned inventory,
  and none for the per-release view. The epoch answers for history
  by construction: a release whose classes owed no planned prefix at
  its machinery version planned nothing, and keeps the whole-release
  decision invariant it was published under
  ([policy-schema.md](policy-schema.md#trustdecision-optional)).
- `classes.<name>.enrichment` — dependency names a release declaring
  this class owes its build-enrichment claim ON TOP of the verify
  policy's universal `required` set (stele#122): a `pgrx-extension`
  release must claim its base images, a `go-binary` release owes
  nothing extra, and subject shape cannot decide this — only the
  declaration from the class that ran the matrix can. The full-depth
  walk hands the engine a demand keyed PER ARTIFACT, each artifact
  owing the names of the class the release's evidence manifest says
  built it, sorted so what one artifact owes has one spelling
  (stele#206). A release's classes are a set of what it SHIPPED, not
  a property of every artifact in it: holding each artifact to the
  whole set asks a binary to answer for a database extension's build.
  Where the manifest cannot attribute — a schema below the class
  split, or no manifest at all — the artifact owes its
  class-independent obligations IN FULL and nothing class-specific,
  and every excused name is named in the walk's output. Never the
  reverse: an unknowable class owes nothing extra, because a judge
  that guesses upward invents an obligation the evidence never
  carried. Where the manifest COULD attribute and did not, the walk
  reds `manifest:attribution` and the artifact stays held to the
  whole declared set — omission must not buy the leniency that only
  structural silence earns. Every name must already live inside the
  verify policy's `required` ∪ `permitted` — one vocabulary, no
  second truth. This file cannot see that one, so the load only
  refuses empty and duplicated names; the subset rule is enforced by
  the engine, which refuses the RUN (never the release) when the two
  documents have drifted
  ([policy-schema.md](policy-schema.md#buildenrichment-optional)).
- `umbrellaBundle` — when a release requires exactly one bundle, that
  bundle may truthfully take the umbrella name instead.
- `storeVsaFromVersion` — the machinery version (inclusive) from
  which verdicts are store-resident. Absent means store-resident
  always. An unparsable pin on a release fails TOWARD the store
  obligation. The **machinery version** — defined once here, used by
  every epoch field — is the version of the shared release machinery
  a release pinned at its tag: the `uses:` pin comment on the
  caller's publish workflow. A repository carrying its own machinery
  has no pin comment, so its machinery version is its own tag. The
  pre-#79 names `storeVsaFromCanon`/`decisionFromCanon` are not
  understood at all: a pre-rename policy is schema 1 and the version
  gate refuses it as a version mismatch before strict decoding runs
  (stele#107; the rule is [docs/versioning.md](versioning.md)). One
  field, one name — no alias, no pointer, no shim (pre-v1,
  correctness wins every tie).
- `decisionFromVersion` — the machinery version (inclusive) from
  which a release owes a VERIFIABLE release decision; the full-depth
  leg runs pre-epoch releases through the provenance half alone
  (grandfathered history proves what it can). Same semantics as
  `storeVsaFromVersion`: absent means always, an unparsable pin
  fails strict. Measured for the first conforming org at 1.23.1 —
  the boundary release below which no decision verifies, exactly.
- `enrichmentFromVersion` — the machinery version (inclusive) from
  which a release owes a build-enrichment claim (stele#109). Same
  semantics as its two siblings — the three share one definition in
  code, so a fourth epoch cannot drift from the first three. The
  epoch lives here and not in the verify policy by design: verify
  judges the single release it is pointed at and stays epoch-free;
  whether HISTORY owes an obligation is the corpus walk's question,
  and the corpus walk is assert's — which already derives the
  machinery version this field is compared against. Absent means
  always; declare it before declaring `build.enrichment` in the
  verify policy, or the corpus walk turns red on every release that
  predates the mechanism.
- `manifestSchemaFromVersion` — the machinery version (inclusive)
  from which a release owes an evidence manifest at the schema this
  build writes (stele#185). Same semantics again, one more time from
  the one definition — and the only epoch that governs a *document's
  own format* rather than an obligation it carries. Below it, a
  manifest written under an older schema is read for exactly what
  that schema promised and named in the report as what it is; at it
  and above, the same document is a present-tense defect and
  refuses. **Absent means every manifest owes the current schema** —
  correct for an adopter with no history, and the reason an org that
  has already published older manifests must declare the version its
  machinery moved at. A published manifest is an immutable release
  asset attested by digest at its tag, so it cannot be re-emitted the
  way a mutable note can; the epoch is how history stays readable
  without a dual-version reader.
- `evidenceSuffixes` — extra asset-name suffixes marking a checksum
  entry as an evidence DOCUMENT rather than an artifact (an org's
  per-release VEX documents, for one). Documents are excluded from
  the full-depth provenance subject set — a document about the
  release is not a subject of its build; a bundle cannot vouch for
  itself. The policy-known documents (bundles, the umbrella, the
  contract manifest, prefixed assets) are always excluded; this field
  covers what only the org can name.
- `publishWorkflows` — the workflows whose failure can burn a release.
  Absent means ANY failed run on the tag counts, which is too broad:
  one flaky unrelated workflow would excuse a genuinely missing
  verdict, and the burned category must never become a mute button.
  Declare them.

## `population`

Which repositories bear evidence, and on which SLSA tracks. Optional,
at the ROOT rather than inside a section, because EVERY target
enumerates through it — a population declared inside one walk's
section would be a second population for the other five.

**Absent means the default predicate**: archived repositories and
forks are out, everything the listing shows is in, on every track.
That is what a uniform organisation needs and what a stranger gets
with no configuration at all.

```json
"population": {
  "repositories": [
    { "repo": ".github" },
    { "repo": "signer", "tracks": ["source"],
      "reason": "publishes no releases; it is the signing workflow repository" },
    { "repo": "www", "tracks": [],
      "reason": "the product site; it bears no evidence" }
  ]
}
```

- `repo` — the bare repository name within the population's owner.
  The owner is the population's, named once at the command line.
- `tracks` — the tracks this repository bears evidence on, spelled
  `build`, `source`, `dependency`. **Absent means every track,
  present and future** — the ordinary case, and the one that needs no
  words. An empty list means none of them. A name that is no track
  this release judges is REFUSED at load: `tracks` is stated
  positively, so a typo would otherwise narrow a population silently,
  and a repository must only ever leave a walk's sight by a statement
  that parsed.
- `reason` — why the membership is narrower than everything.
  Required whenever `tracks` is present. A narrowing nobody wrote a
  reason for is indistinguishable from a mistake, and this is the one
  field that tells a later reader which it was.

### Which door a target opens

A walk enumerates by the QUESTION IT ASKS, and which question each
target asks is a fact about the mechanism, not about any organisation.

A target measuring evidence asks a **track** question, and reads that
track's bearers: the evidence walk measures `build`; chains and tags
measure `source`; blast-radius (and `derive vex-subjects`, which
sweeps the same SBOMs) measures `dependency`. A repository declared
outside the track is invisible to it — not measured, not counted, not
a finding.

A target measuring something every repository has whatever it
publishes asks **no track question at all**, and reads the roster:
every entry in this section, in listing order. `assert permissions`
is that target today. The caller/callee join reads workflow files,
computes a requirement and compares it against a grant; it makes no
claim about any release and consumes no attestation, so no track
scopes it.

**Listing a repository here therefore means its workflow grants are
audited, even when the same entry excludes it from every evidence
track.** A repository that publishes nothing still has callers that
die as `startup_failure` at the next pin bump, and an organisation
must be able to say *this repository bears no build evidence* without
also saying *do not audit its workflow grants* (stele#181).

### Exclusions are not exceptions

The two vocabularies mean opposite things and the schema keeps them
apart on purpose. An **exclusion** here says a repository owes no
EVIDENCE: on the tracks it names it produces no member, no finding,
no stale entry, no count and no board cell — silence, because there
is nothing to say. It narrows evidence and evidence only; a target
that consumes none reads the roster past it. An **exception**
(`chains.exceptions`, the debt file) says a repository owes something
it has not got: dated, removal-conditioned, and loud until resolved.
There is no way to spell the second in this section, which is what
keeps "outside the scope" from decaying into "behind on the work".

An exclusion is also not an excuse. It decides who is ASKED, never
what the answer is — a repository that is in the population is judged
on the evidence and nothing a policy says can lift its verdict.

### The roster is closed

Declaring this section replaces the default predicate's open listing
with a roster, and a roster is reconciled against the listing in both
directions, **by name**:

- a repository the listing shows that the roster does not account for
  refuses the run — that is the onboarding signal working, not a
  defect to swallow;
- a repository the roster names that the listing does not show
  refuses the run — either a credential that cannot see it or a
  roster nobody updated when it was archived or deleted, and an
  unseen repository is unchecked, never clean.

A count cannot say which repository went missing, and the repository
that went missing is the whole finding. The declared population's
cardinality IS the expectation — nothing declares a total beside it,
because a derived number typed a second time is a number that drifts.

A roster entry OVERRIDES the default predicate for its repository, so
an organisation that keeps auditing a repository it archived says so
by naming it, and needs no change to this tool to do it.

Pointing a walk at a track the policy declares nobody in is a
contradiction, and it is refused by name rather than answered: a
walk with nothing to judge would otherwise seal `CANNOT_JUDGE` with
no cause, which reads exactly like a credential that could not look.
A listing that merely came back EMPTY is the opposite case and stays
`CANNOT_JUDGE` with the population at zero — an outage is not a usage
error. A target that reads the roster has no such contradiction to
report: it named no track, so there is none to be empty of, and an
empty roster is the outage case alone.

Single-repository runs (`--repo owner/name`) read the roster only
where it names that repository. A closed roster scopes an
organisation's listing; it has no standing to veto a target a caller
named explicitly, which is what lets the same walk point at a
repository the roster never heard of.

## `debtFile`

Where the humans keep their written-down defects (format below). It
sits at the ROOT of the policy, not inside a section, because EVERY
target reads it: excusability is a property of judgment, not of one
walk, and a defect the tag audit finds is no less writable-down than
one the evidence walk finds. Optional — an org that declares no file
has declared no exceptions, and every finding stands.

## The store-resident halves

Two optional sections cover artifacts that have no release to hang
evidence off, so the attestation store is the only durable record —
and for both, presence is not enough: the bundle must VERIFY under a
pinned identity, which is why declaring either requires a top-level
`issuer` and a `--trusted-root` at the CLI. A policy that declares
them without a root is a usage refusal, never a silent skip: the
whole point is that nobody else checks these artifacts.

```json
{
  "issuer": "https://token.actions.githubusercontent.com",
  "evidence": {
    "continuous": {
      "stubPath": ".github/workflows/continuous.yml",
      "stubUses": "monumental-archive/.github/",
      "registry": "ghcr.io",
      "tag": "latest",
      "signerWorkflow": "monumental-archive/signer/.github/workflows/sign.yml",
      "signerPinPattern": "monumental-archive/signer/.github/workflows/sign\\.yml@([0-9a-f]{40})"
    },
    "baseImages": {
      "pinFile": "docker/pgrx-base-images.toml",
      "attestorRepo": ".github",
      "attestorIdentity": "https://github.com/monumental-archive/.github/.github/workflows/base-attest.yml@refs/heads/main",
      "predicateType": "https://monumental-archive.github.io/attestations/base-image-approval/v1"
    }
  }
}
```

**continuous** — a repo whose `stubPath` calls `stubUses` publishes
rolling digests. The image under `tag` must carry an attestation
verifying under `signerWorkflow`'s identity at a pin that
`signerPinPattern` (capture group 1) finds. Identity and pin travel
together as one candidate: a workflow reached through a commit-pinned
`uses:` carries that commit as its certificate SAN ref AND as the
signer digest, so checking one without the other checks half the
binding.

The pin is DERIVED, never a policy literal — and derived from the
CONSUMING CHAIN, which is two hops: the stub's own `uses:` names the
shared reusable workflow at a commit, and THAT released tree names the
signer pin. Both hops are the same release, so the declared identity
and the signing surface move together; a signer bump on the shared
repository's main declares nothing until a release carrying it is
pinned by the consumer, which is exactly when artifacts start being
signed under it. Reading the consumer's own workflows instead is
wrong twice over: it is not the tree that signs, and any unrelated
workflow there naming the signer becomes the declared identity.
Multiple pins in the released tree are all declared, and the artifact
must verify under one of them.

Four things fail closed, each its own finding: a stub that publishes
but has no image under the tag, a stub declaring no commit-pinned
call (there is no released tree to derive from), a released tree that
is unreadable at its pin or declares no signer pin (the identity
cannot be derived, so the image cannot be vouched for), and an
attestation that refuses.

**baseImages** — every digest-pinned base reference in `pinFile` must
carry a `predicateType` attestation verifying under
`attestorIdentity`. A pin file present but pinning nothing is a
finding, not a clean answer: the walk was told to check something. A
declared pin file absent from the checkout is a usage refusal, like
the missing trusted root — the likelier cause is the wrong working
directory, and proceeding would judge nothing while looking green. An
org that pins no base images says so by omitting this section.

## The blastRadius section

Optional; required to run `stele assert blast-radius`:

```json
{
  "blastRadius": {
    "osEcosystems": ["debian", "alpine", "ubuntu", "rocky", "redhat", "rpm"],
    "canary": { "repo": "release-lab", "tag": "v0.17.0", "advisory": "RUSTSEC-2021-0127" }
  }
}
```

- `osEcosystems` — ecosystem substrings classed as OS base layers.
  An unfixed finding there is the rebuild cadence's input — reported
  as a derived exception, never red; a finding WITH a shipped fix
  means the image lags a fix and gates like everything else.
  Ecosystem findings (the repository's own code surface) always
  gate.
- `canary` — the pinned release that must yield its known advisory,
  or the scanner cannot see and the walk refuses to judge.

The VEX join is the exact `(advisory, package, version)` triple —
never the advisory alone, so a release that bumps a decided package's
version matches no decision and surfaces for a fresh judgment. Each
matched decision appears in the report as a declared exception whose
origin is the reviewed statement file; a decision matching no current
finding surfaces as stale — a retirement candidate, never an
archaeology project. An empty or absent VEX directory decides
NOTHING, never everything. When a decision and a finding name the same
package is its own question, answered once in
[vex-join.md](vex-join.md) — golang names compare case-insensitively,
everything else compares as written.

## The release evidence manifest

The declared contract, going forward: a release asset (named by the
policy's `manifestAsset`) the publish machinery writes with
`stele emit manifest` and attests, so the contract is immutable at
the tag and readable by a stranger with no knowledge of the
publisher's CI. Writer and reader share one definition
(`internal/evidence`) — a manifest the writer can produce and one
this reader admits cannot drift apart:

```json
{ "schema": 4, "classes": ["oci-image", "rust-crate"], "storeVsa": true,
  "machineryVersion": "1.40.0",
  "entries": [
    { "name": "widget-x86_64.tar.gz", "sha256": "1111…", "type": "build-subject",
      "class": "rust-crate", "target": "x86_64-unknown-linux-musl" },
    { "name": "attestations-image.intoto.jsonl", "sha256": "2222…", "type": "evidence" }
  ] }
```

All five fields are required. The manifest declares **facts** —
classes, verdict layout, the version of the publish machinery that
produced the release, and what the release published — never
obligations: whether the release owes a decision or an enrichment
claim is always *derived* from the policy's `*FromVersion` epochs
against `machineryVersion`, through the same epoch semantics the
workflow adapter uses. An adopter with no history declares no epochs,
and every obligation simply always holds. `machineryVersion` is the
attested spelling of the fact the workflow adapter regexes out of a
pin comment; a manifest that omits it, or carries an unparsable one,
refuses — a declaration that cannot answer the epochs excuses nothing
silently.

### Typed entries

`entries` pins every asset the release published and says what each
one **is**. The two types carry opposite obligations, which is the
whole reason the distinction is worth a field:

- `build-subject` — an artifact *of* the build. It must rebuild
  bit-for-bit.
- `evidence` — a document *about* the release: an attestation bundle,
  an inventory, a triage decision, a digest manifest. It **cannot**
  rebuild bit-for-bit, because a Sigstore signature embeds a fresh
  timestamp and certificate on every signing, and that
  non-reproducibility is a security property, not a defect.

The vocabulary is closed: an entry that is neither refuses the
manifest, because unknown defaulting into either population is the
failure this typing exists to prevent. So does an entry with no
digest, or the same asset twice.

### The checksum cross-check

A release carries two documents that pin its bytes — `checksums` and
the evidence manifest's `entries` — and each is internally
consistent, so a name carrying one digest in one and another digest
in the other passes every per-document check. At full depth, where
both documents are in hand, the walk asks whether they describe the
same bytes and reds `manifest:checksums` naming every disagreeing
asset and both digests (stele#219).

Only the **intersection** of names is judged. A name in one document
and not the other is sound and owned elsewhere: the evidence manifest
cannot pin itself, the checksum manifest does pin it, and asset
presence is the presence leg's own obligation. A manifest whose
schema carries no entries — or a release no manifest speaks for — is
a narrowing, stated in the walk's output and never recorded as a
check: an obligation the release could not meet would sit in the
journal forever, and an exception written against it would read as
stale from the day it was written.

The type is stamped by `stele emit manifest`, from the vocabulary
this policy already declares — `checksums`, `manifestAsset`,
`umbrellaBundle`, `sbomSuffix`, `evidenceSuffixes`, and each class's
`bundles`, `legacyVsaBundles` and `assetPrefixes`. That is the ONE
definition of the question (`internal/assert`'s `Classify`), and
emission is the one moment the knowledge exists natively. Every walk
downstream **reads** the answer: `stele verify repro` takes the
released manifest whole and judges its `build-subject` entries, and a
walk that re-derived the typing would be the second answer this field
exists to retire. The classifier's other job is a manifest that
arrives untyped — a legacy release, or a foreign one this org never
wrote — where it classifies a plain sha256sum manifest instead.

### The leg that built each artifact

Every `build-subject` entry names the evidence **class** whose build
leg produced it and the **target** that leg built; an `evidence` entry
names neither, because a document about the release belongs to no one
class, was produced by no leg, and a per-entry answer there would be a
second vocabulary. The class must be one the manifest's own `classes`
already declares — an entry claiming a class the release did not ship
is incoherent about its own document, and the check needs no policy to
make it. The target is not checked against anything: what a target IS
belongs to the publisher — a platform triple, a runtime major,
whatever its matrix varies — and a tool holding a vocabulary of them
would be asserting a fact about the world from one organisation's
build configuration.

This is the one fact `emit manifest` cannot compute: no declared
vocabulary names a release's build artifacts by the leg that produced
them. It arrives as one subject manifest per leg —
`--leg-subjects <class>:<target>=<path>`, repeatable — which is the
shape a publisher already holds, since every matrix job emits the
digests of what it produced. The join is checked in both directions
against `--assets`, because a caller's split is a second statement
about the same release: an artifact named by a leg but absent from the
release did not ship, one whose digest disagrees is not the same
bytes, one claimed by two legs has no answer, and a document is not an
artifact any leg built. **An artifact no leg claims refuses the
manifest**, rather than shipping unattributed — a scoped rebuild would
then judge a population that silently omitted it, which is the same
defect as an untyped entry one field over.

What it buys is scope, at both grains. `stele verify repro --class
<name>` narrows its population to the artifacts that class built, so a
rebuild covering one class stops reporting every other class as absent
from it. Measured on release-lab v0.25.3: one artifact reproduced,
thirteen falsely reported missing, two supply-chain issues filed for a
release that was fine. Narrowing does not mute — an artifact *of the
class under rebuild* that the rebuild failed to produce is still a
finding — and where the released manifest carries no class answer, the
population stays the whole release rather than wearing the class's
name.

The verdict says which it is in **two** facts, never one string a
reader has to split: `classScope` is the population's own scope (the
class name, or `whole-release`), and `classScopeUnmet` appears only
when a request went unhonoured, carrying why (`no-class-answer`). Its
absence is the answer in the honoured case. Which KIND of manifest
could not answer — one below the schema that types it, or one with no
typing at all — is already the `subjectTyping` fact beside them.

A rebuild's own unit is finer than a class: it is a target, and
`--targets <a>,<b>` is where the caller declares which ones it
covered. That declaration IS the judged population — reconciled
against the manifest's typing, never derived from what the rebuild
produced, because a population drawn from output passes a rebuild that
silently produced nothing. Measured on release-lab v0.26.0: a healthy
rebuild of one target of a four-artifact class returned FAIL over the
three artifacts nobody asked it to rebuild. The reconciliation runs
both ways, and the two directions may never share a vocabulary: a
target nobody declared produces **nothing** — no finding, no count, no
cell — while a declared target this release cannot place is
`CANNOT_JUDGE`, named in a `repro/target-not-typed` finding that
carries the cause (a release published before targets were typed, or a
target it never built). Inside the declaration nothing is muted: an
artifact of a declared target that the rebuild did not produce, or
produced to other bytes, is as loud as it ever was.

A manifest cannot pin itself: a document carrying its own digest is
not a document. The entries are therefore the assets published
*beside* it, and nothing is lost — the manifest is an evidence
document, and so is the checksum manifest that pins it.

The manifest's `schema` is its own number, outside the live-document
epoch ([versioning.md](versioning.md)): manifests are published
release assets, immutable once shipped, so the number moves only
when this format's own key set changes against documents that exist.
It moved to `2` when entries gained their type, to `3` when they
gained their class, and to `4` when they gained their target.

A published manifest cannot be re-emitted. It is an immutable release
asset, pinned by digest in `checksums.txt` and attested under the
signer's identity at release time — the mutable-note precedent does
not transfer. So an older manifest is admitted by the **declared
epoch** above, `manifestSchemaFromVersion`, or not at all: below it
the manifest is read for exactly what its own schema promised, and at
or above it the same document refuses, because the epoch excuses
history and never the present. What an older manifest could not say,
the walk never asks it for — which assets a release published, and
which of them are artifacts, come from the checksum manifest and the
vocabulary this policy declares.

This is not a dual-version reader: every field is decoded exactly one
way, and what the number selects is which fields were **promised**,
never how any of them is read. A manifest carrying a field its schema
never had refuses as loudly as one missing a field its schema owed —
a document that lies about its own format reads worse than an old
one.

Releases without a manifest fall back to the workflow adapter — the
quarantined read of the first consumer's publish-workflow convention
at the tag (`classes:` input, machinery version from the `uses:` pin
comment), which is the only honest source for that history and
sunsets as manifests take over. A release neither source speaks for
is **legacy**: it predates the machinery, owes nothing, and is
recorded by name in the report's facts — a category derived from the
tag's own tree, deliberately not assertable by hand.

## The debt file

Human-declared exceptions, one per line, `#` comments allowed. One
file for every target — the tag audit's defects and the evidence
walk's are the same kind of thing, and the file is read through the
report layer both walks emit findings through:

```text
# subject(assertion) — see PR #NNN for the review that approved this
widget@v1.0.0(sbom)
widget@v1.0.0(attestations-crates.intoto.jsonl)
gadget@v0.2.0(vsa:abcdef012345)
gadget@v0.3.0(tag:signature)
```

The `assertion` is the finding's assertion string exactly, and each
target's vocabulary is its own:

| target | assertions |
| --- | --- |
| `evidence` | `sbom`, the checksum or bundle asset name, an `assetPrefixes` prefix, `class:<name>`, `<asset>:unreadable`, `vsa:<first 12 digest hex>`, `continuous-digest`, `base-image-approval`, and at full depth `deep`, `vsa:deep`, `manifest:attribution` and `manifest:checksums` |
| `tags` | `tag:epoch`, `tag:annotated`, `tag:tagger`, `tag:signature`, `tag:link` |
| `chains` | `chains` — a founded chain's defect is never excusable; absence is excused by the policy's `chains.exceptions`, never here |
| `blast-radius` | `<advisory>:<package>@<version>`, `<asset>:unattested`, `<asset>:empty-scan` |
| `plans` | `class`, `planned-obligation`, `plan-shape`, `plan-conflict`, `plan-drift`, `plan-orphan`, `plan-set` |
| `image-facts` | `fact-hygiene`, `index-media-type`, `index-annotations`, `config-labels` |
| `permissions` | `caller-grant`, `call-shape`, `callee-absent`, `callee-unreadable`, `callee-not-callable`, `workflow-shape` |

A malformed line is a refusal, not a skip — a reviewed file that
parses as nothing would excuse nothing silently. Neither half may be
blank: a line with no assertion is a blanket excuse that needs its own
review, and a line with no subject is the any-subject wildcard, which
is engine vocabulary (a triage decision judges a package version, not
the release carrying it) and never a file's to spell.

A line matching no finding is sorted by what the run could SEE
([report-schema.md](report-schema.md)):

- the check ran and was clean → **stale**, a retirement candidate;
- the check never ran in this run → **unexercised**, and the run says
  nothing about it. A single-repository walk answers only for that
  repository; a tag the signing epoch exempts was never asked for a
  signature at all.

Both are reported, neither fails: red means evidence is missing, not
that the paperwork lags.

A line that DID match is credited even where a derivation matched the
same coordinate — both appear in `excused`, and a line shown beside a
derivation is one the engine has made redundant: retire it. Only a
clean check makes a line stale (stele#220).

Burned releases (a verdict absent because the publish run died after
the release sealed) are NOT written here — they are derived from run
history by the walk itself, excuse only `vsa:` findings on the
affected tag, and (with `publishWorkflows` declared) only when the
failure was a PUBLISHING run. The asymmetry is the point: what a human may assert
and what only evidence may assert are different types.

## The inventory plan

The pre-publish half of the planned obligations (.github#544). A
build leg that ships an artifact emits its inventory plan — the
artifact-to-document mapping as data, stated exactly once, where and
when it is certain: in the job that built the artifact. The publish
leg derives the per-artifact SBOM documents from the plans; nothing
restates the mapping, so nothing can drift from it. A plan document
is one JSON array of entries, strict-decoded (an unknown field is
version skew, refused):

```json
[
  {
    "class": "wasm-npm",
    "doc": "sbom-npm-lab-wasm",
    "artifact": "lab-wasm.tgz",
    "params": {
      "cargoPackage": "lab-wasm",
      "features": ["pg16"],
      "noDefaultFeatures": true
    }
  }
]
```

- `class` (required) — the evidence class whose build leg emitted
  the entry, stated where it is certain: the leg IS the class. It is
  the judgment's join key (stele#143): the entry is judged against
  this one class's declared vocabulary and satisfies this one
  class's obligations, never another's by prefix coincidence.
- `doc` (required) — the release document's name, version- and
  suffix-less: the published asset becomes
  `<doc>-<version><sbomSuffix>`, so the policy's planned prefixes
  match `doc` directly. The prefix names what the artifact IS; the
  params name what it is MADE OF — the two disagreeing silently is
  exactly the .github#544 defect.
- `artifact` (optional) — the shipped file the document describes.
- `params` (optional) — the ecosystem-specific closure description:
  which package, which features, whatever the class's deriver
  needs. One JSON object, opaque to the judgment by design — which
  ecosystems exist is each adopter's fact, not this tool's, so
  stele guards the charset of every key and string value and
  canonicalises the object for comparison, and only the downstream
  leg that derives the document reads the content.

Every value is charset-guarded before it can reach a command line,
because plans originate on build legs that execute caller code.
Entries restating one identical mapping collapse by canonical
content (matrix legs); one `doc` claimed by two DIFFERENT entries —
different params, or different classes — is legs disagreeing about
what was built: refused, never last-writer-wins.

`stele assert plans --policy <assert-policy> --classes <declared>
--machinery-version <riding> [--out <path>] <plan files...>` judges
the plans against the planned obligations pre-publish, in the publish
guard. The judgment is bidirectional, and the two directions
deliberately ask two different questions (stele#143):

- **owed** — for each requested class's planned prefixes owed at the
  riding machinery version (the same policy and the same `owedFrom`
  semantics the evidence walk reads — one obligation list, two
  moments of looking): is there a plan OF THAT CLASS naming a
  document under the prefix? An unsatisfied owed prefix is a release
  that would publish green and red on the walk.
- **vocabulary** — for each plan entry: does its own class declare
  some planned prefix claiming the document, at ANY epoch? Whether a
  document is one a class could ever owe is a naming question, not a
  time question, so `owedFrom` never enters — a pre-epoch release
  emitting a correct plan is silent by construction. A document
  outside its class's vocabulary is an orphan (a misnamed
  obligation-bearer or an undeclared obligation); a class declaring
  no planned prefixes has declared no vocabulary, so its plans are
  outside the judgment, not refused by it; a plan naming a class the
  release does not declare is drift (a leg ran for an undeclared
  class).

### The judged set is what consumers iterate

The judgment emits the entry set it judged: collapsed, validated,
params canonicalised, ordered by document, and independent of the
order the plan files were named. It rides in the report document as
`judged` ([report-schema.md](report-schema.md)), and `--out <path>`
writes those same bytes as one JSON array — the plan format again,
merged. The derivation leg that produces the documents iterates THAT
file.

This is the rule, not a convenience (stele#151): a consumer must
never re-derive the plan set from the same raw files. Before this,
the publish guard judged the collapsed set while the loop beside it
re-collapsed the plans with `jq -s 'add | unique'` — two derivations
of one set from one set of bytes, agreeing until the day their
notions of "identical entry" parted. One rendering reaches the
report and the file, so a second reading of what was planned is
unrepresentable.

The file is written on `PASS` alone: the set exists to be iterated,
and one that failed judgment must not be there to iterate. The exit
code is one guard; a workflow that reads the file regardless finds
nothing rather than a plan the guard refused. A set that cannot be
placed is an output failure (exit 3), never a silent green.

Verdicts and exit codes are the assert verb's usual three
([report-schema.md](report-schema.md)); an unreadable plan path is a
usage refusal (a broken invocation), while a plan that will not
parse is a FAIL finding (a defective build leg).

## Verification depth

The walk defaults to presence depth: assets exist, bundles parse,
every covered subject has a VSA-typed attestation in the store.
`--depth full` (issue #4) is the corpus re-verification leg on this
same walk, not a second one: every covered release is handed to the
verify engine — provenance bundles, certificates, the decision, and
the store-resident verdict — under `--verify-policy`, the trust
authority. Pins are derived per release from the trees a stranger
reads: the caller's publish workflow at the tag carries the
machinery pin, the machinery repository's publish workflow at that
pin carries the signer pin, and the machinery repository's own
releases run at the tag commit. Refusals
land in the walk's own taxonomy: verdict refusals carry a
`vsa:`-prefixed assertion (so burn derivation and debt lines apply
exactly as at presence depth, and the deep verdict check yields
entirely where presence already found verdicts missing); everything
else reds under `deep`, excusable only by a written debt line.
Pre-store releases are held to presence depth for their verdicts —
grandfathered history under the verify policy's enumerated legacy
roots — and the bound is logged, never silent. Asking for full depth
without `--verify-policy` and `--trusted-root` is a usage refusal,
never a shallower walk that looks like the deep one.

## The tags section

Tag signing is a **declared obligation** (stele#79/#82/#83): the whole
section is absent for orgs that do not sign tags, never a
precondition. Declared means every field, validated strictly:

```json
"tags": {
  "tagPattern": "^v[0-9]",
  "taggerName": "tag-mint[bot]",
  "identityPattern": "^https://github\\.com/example-org/",
  "proofFloor": {
    "floor": "observer-timestamp",
    "from": {"widget": "v1.9.0"},
    "before": "certificate-transparency"
  },
  "notesRef": "refs/notes/commits",
  "epochs": {"widget": "v1.2.0", "gadget": "pending"}
}
```

- `tagPattern` — which tag refs are release tags.
- `taggerName` — the minting role's tagger name; an identity from
  policy, never a literal in code.
- `identityPattern` — the regular expression the signing
  certificate's SAN must match; the issuer is the policy's top-level
  `issuer`, required when this section is declared.
- `proofFloor` — how much countersigned proof a tag signature owes,
  the ORG's declaration and never the tool's decision (stele#173),
  and from which tag it owes it (stele#186).
  - `proofFloor.floor` — the floor itself.
    `certificate-transparency`: the signing certificate's issuance
    countersigned by a trusted CT log — what any Fulcio-minted
    signature can prove offline, whether or not the mint kept its
    receipts. `observer-timestamp`: additionally a transparency-log
    entry and an observer timestamp over the signature itself, which
    only a mint that embeds its Rekor entry (gitsign's offline mode)
    can meet. The verdict states the depth actually reached; the
    floor states the minimum that passes.
  - `proofFloor.from` — each repository's first tag owing `floor`,
    for the case a mint gains the capability partway through a
    repository's history. The key has three readings, and each is a
    stated rule a stranger's policy can rely on rather than an
    accident of map access:
    - **absent entirely** — `floor` binds every tag of every
      repository. `before` is then refused: a floor for tags before a
      point nobody named binds nothing.
    - **present, naming this repository** — its tags owe `floor` from
      the named tag onward, and `before` beneath it.
    - **present, not naming this repository** — it has not raised its
      floor, and every one of its tags owes `before`. That is the
      correct reading for a rollout partway through a population, and
      the one that keeps a partial switch from reddening the
      repositories that have not switched yet.
  - `proofFloor.before` — what tags earlier than the `from` tag owe.

  `from` and `before` are declared together or not at all: a rise
  from a point says nothing about the tags before it, and a floor for
  tags before a point that is never named binds nothing. An org whose
  floor never rose declares `floor` alone; an org that never minted
  without receipts declares `from` at its first tag. Neither edits
  this tool.

  This is a **floor with a from**, deliberately not a second epoch map
  beside `epochs`. They answer different questions about the same
  tags: `epochs` says when a repository began signing at all, this
  says when its floor rose. Raising a floor globally instead reddens
  every tag minted before the mint could meet it — the #128/#109
  failure the epoch vocabulary exists to prevent — and those tags are
  not defective, so they are excused BY THE BOUNDARY and never by
  debt lines.

  The two floors are not ordered here. A mint that REGRESSED is a
  real thing an org must be able to declare honestly, and a tool that
  only permits rises decides a policy fact. What no org can mean is a
  boundary carrying the same floor on both sides, and that refuses.
  So do a `from` naming a repository `epochs` does not, a `from` on a
  repository declared unsigned, and a `from` earlier than that
  repository's signing epoch — a heavier obligation on tags that owe
  no signature at all.

  A run whose policy declares a boundary reports
  `tagsProvenAt:<floor>` for each floor. A boundary is only proven by
  a run that proved tags on both sides of it, and without the counts a
  `from` naming a tag nobody minted reads exactly like one that binds.
  Refused tags are absent from the counts by construction — a tag that
  did not verify proves no regime, and its finding says so.
- `notesRef` — the source chain's notes ref, fully qualified.
- `epochs` — each releasing repository's first signed tag, or
  `pending` for declared-unsigned. **This is the population**
  (stele#208): the walk judges every release tag from the epoch
  onward, and a tag below it is an EXCLUSION — no check, no finding,
  no count, no line. A repository that releases tags without a line
  here seals CANNOT_JUDGE: an undeclared population member is
  unchecked, not clean.

  `pending` admits the whole listing. It says a repository signs no
  tags YET, which is a statement about ONE obligation — the tagger
  role and the chain link are owed whatever the mint has begun doing
  — and reading it as an empty population would let a declaration of
  scope quietly remove a repository from sight. A tag whose version
  does not parse is admitted, the same direction it fails in for the
  signing obligation.

The walk (`stele assert tags --org|--repo`): for every member, the
tagger is the declared role, the tag carries a gitsign signature
verified natively against the trusted root to at least the declared
floor — CMS over the tag payload, the certificate's embedded SCT
countersigned by a trusted CT log, the chain to the root's
certificate authorities observed at that countersigned instant, SAN
and issuer held to the policy, and the tagger clock consistent with
the countersigned issuance (no gitsign binary, and the forge's own
verification verdict is never consulted: it cannot judge
x509-in-the-PGP-slot). A tag carrying its mint's own Rekor receipt is
judged through the full observer stance — the same verifier every
bundle passes — regardless of floor, so a receipt that does not prove
refuses loudly. And the tag's target carries a source chain link.

### What the tag walk covered, and how it says so

Every member is judged or is **loudly unjudgeable**; a member is
never silently absent. The one obligation that can be unjudgeable is
the chain link, and the bound there is the LEDGER's rather than the
declaration's: a source ledger witnesses from its founded genesis —
the oldest link-noted revision whose first parent carries no link —
and says nothing before it. Where the genesis does not reach a tag's
target, the missing link is recorded as a finding carrying a DERIVED
exception naming that horizon, so the tag stays visible, stays
counted and never reddens. A missing link INSIDE the horizon is a
defect. A repository whose ledger founds no chain witnesses nothing
at all, and that absence is `assert chains`' finding (#266) — made
once, there, rather than reddening a whole listing here.

The distinction is load-bearing, and stele#208 is what it cost when
it was missing. The same genesis bounded the POPULATION until then: a
derived bound doing a declaration's job, and one that moves. When the
org's ledgers were re-emitted in note-format v3 on 2026-08-18, each
derived genesis moved forward by weeks and the judged set fell to 21
of 158 release tags while the run still printed `assert: PASS` and
nothing else. A derived bound may narrow an OBLIGATION; only a
declaration may narrow a population.

So the run reconciles the counts, per repository and in total, in its
own output and as facts beside the verdict:

```text
assert: tags: widget: 82 tag(s) listed, 41 excluded before epoch v1.23.1, 41 in population: 12 judged, 29 unjudgeable
assert: tags: widget@v1.29.0: tag:link unjudgeable — the ledger's founded genesis ecb42d6… does not reach target 8f3a1c…
```

| fact | |
| --- | --- |
| `tagsListed:<repo>` | release tags the forge listed |
| `tagsExcluded:<repo>` | tags below the declared epoch |
| `tagsJudged:<repo>` | members every obligation reached a verdict on |
| `tagsUnjudgeable:<repo>` | members the ledger could not answer for |

`listed = excluded + judged + unjudgeable` closes for every
repository whose epoch is declared, and the report's population is
`judged + unjudgeable` — what the declaration holds, never what the
walk managed to judge. A green naming its own scope is the whole
point: `PASS` over 21 of 158 tags is otherwise indistinguishable from
`PASS` over all of them.

## The chains section

The chain-coverage audit (stele#94): for every repository in the
population, either a founded source chain verifies end to end over
every protected branch, or the repository is a declared exception.
Declaring the section declares the obligation; the only content here
is the exception list, because where the ledger lives and which
branches it covers already live in the verify policy's `source`
section — one declaration, never restated:

```json
"chains": {
  "exceptions": [
    {"repo": "widget-lab", "reason": "lab-first activation, tracked in example-org/widget-lab#1"}
  ]
}
```

- `exceptions` — the declared opt-outs: repository names within the
  population's owner, each with a written reason. The list may be
  empty. An entry whose repository has since founded its chain is
  reported as a **stale exception** by the report engine — the
  remove-the-line-when-activated contract, made structural.

The walk (`stele assert chains --org|--repo`, with `--verify-policy`
and `--trusted-root`): the population is the org listing or the one
named repository — enumerated, never the enrolled set. A repository
with no link-shaped note on the declared notes ref is **unactivated**:
a finding unless a declared exception names it, because an
unactivated repository is silent by construction (#266). A founded
chain is walked and cryptographically verified through the verify
engine (`verify chain`, per protected branch, over the forge's own
API — no clone); a founded chain that fails to verify is a finding
that **no exception can excuse** — declared exceptions carry the
`unactivated` assertion alone, so an opt-out excuses absence,
structurally never a defect. A zero population seals CANNOT_JUDGE.

## The permissions section

The caller/callee permissions join (stele#148). The platform makes
`permissions:` caller-owned — a reusable workflow inherits its
caller's grant and can only narrow it — so a callee that gains a
capability is a breaking change to every caller, enforced at run time
as a startup failure with no jobs and no log. The requirement is
nevertheless statically computable: the union of the callee's job
grants is exactly what a caller must hold. Declaring the section
declares the obligation.

Everything here is a convention, and every convention is declared:

```json
"permissions": {
  "reusable": {"repo": "example-org/.github", "dir": ".github/workflows"},
  "callerDirs": [".github/workflows", "workflow-templates"]
}
```

- `reusable` — the shared-workflow tree this org publishes: `repo` is
  the `owner/name` a caller spells in `uses:`, and `dir` is that
  repository's own directory holding the workflows, which is also
  where the run reads them under `--tree`. Both halves are needed and
  neither implies the other: the reference is how callers NAME the
  tree, the directory is where a run can READ it. The whole object is
  optional — an adopter whose reusable workflows all live beside their
  callers declares none, and the join then covers local (`./…`) calls
  alone.
- `callerDirs` — the checkout-relative directories whose workflow
  files are read as callers, at least one. More than one because a
  tree may hold callers it does not run: an org's workflow templates
  are stubs destined for other repositories, and a stub's grant is
  exactly as breakable as a live caller's. A declared directory the
  checkout does not carry is an answer, not a defect — an org declares
  the directories its trees MAY use. Directories are checkout-relative
  and may not climb out of it; a policy that could is refused at load.

The join (`stele assert permissions --policy`, with `--tree` for the
reusable checkout and either `--callers` for a checkout or
`--org`/`--repo` for a population walked through the forge):

- a job's `uses:` is read through the platform's own grammar. A
  **local** reference resolves in the CALLER's own file set — a
  repository calling its own reusable workflow is judged against that
  workflow, never against the shared tree. A **remote** reference
  matching `reusable.repo` resolves in the declared tree. Anything
  else is another repository's workflow, which this run holds no tree
  for: outside the declared scope, counted in the
  `callsOutsideDeclaredTrees` fact rather than silently invisible.
- the requirement is the union of every job's effective grant — its
  own `permissions:` block, or the workflow-level default when it
  declares none. `uses:` jobs count too: a nested callee's ask chains
  up through the workflow to its caller.
- a **blanket** ask (`read-all`, `write-all`) is answered by a blanket
  grant alone. Proving an enumerated caller sufficient would need the
  platform's full scope vocabulary, and a vocabulary hardcoded in the
  tool goes stale the next time the platform adds a scope — silently,
  in the direction that under-reports. The join says so instead of
  guessing.
- every degraded shape is a finding, never a skip: a workflow file
  that will not parse (`workflow-shape`), a call the grammar cannot
  read (`call-shape`), a callee absent from the tree
  (`callee-absent`), present but unparsable (`callee-unreadable`), or
  present and declaring no `workflow_call` trigger
  (`callee-not-callable`). An unchecked grant reporting green is the
  failure class the join exists to remove.
- a run that examined no workflow file at all seals CANNOT_JUDGE: a
  wrong path, an empty checkout and a narrowed credential all look
  identical from inside, and none of them may exit like a pass. A
  declared reusable tree the run holds no file from is refused for the
  same reason.
