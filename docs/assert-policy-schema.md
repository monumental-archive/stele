# The assert policy: schema, first cut

The committed data `stele assert evidence` reads — the universality
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

`schema` is the refusal boundary: current **4**, the one epoch shared
by this policy, the verify policy and the report, so a bump cannot
land on one document and miss another ([docs/versioning.md](versioning.md)).
The gate fires before strict decoding, so another schema refuses as a
version mismatch, never as an unknown-field error.

## The policy file

```json
{
  "schema": 4,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "storeVsaFromVersion": "1.13.0",
    "debtFile": "security/attestation-debt.txt",
    "expectedRepos": 4,
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
- `classes.<name>.enrichment` — dependency names a release declaring
  this class owes its build-enrichment claim ON TOP of the verify
  policy's universal `required` set (stele#122): a `pgrx-extension`
  release must claim its base images, a `go-binary` release owes
  nothing extra, and subject shape cannot decide this — only the
  declaration from the class that ran the matrix can. The full-depth
  walk unions the declared classes' lists into the demand it hands
  the engine, sorted and deduplicated, so the demand is independent
  of declaration order. Every name must already live inside the
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
  always; declare it before the canon declares `build.enrichment`,
  or the Monday walk turns red on every release that predates the
  mechanism.
- `evidenceSuffixes` — extra asset-name suffixes marking a checksum
  entry as an evidence DOCUMENT rather than an artifact (the org's
  per-release VEX documents, for one). Documents are excluded from
  the full-depth provenance subject set — a document about the
  release is not a subject of its build; a bundle cannot vouch for
  itself. The policy-known documents (bundles, the umbrella, the
  contract manifest, prefixed assets) are always excluded; this field
  covers what only the org can name.
- `expectedRepos` — optional declared population. A listing that sees
  a different count refuses to judge: an unseen repo is unchecked,
  not clean, and a surplus one means this declaration is stale.
- `debtFile` — where the humans keep evidence debt (format below).
- `publishWorkflows` — the workflows whose failure can burn a release.
  Absent means ANY failed run on the tag counts, which is too broad:
  one flaky unrelated workflow would excuse a genuinely missing
  verdict, and the burned category must never become a mute button.
  Declare them.

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
verifying under `signerWorkflow`'s identity at a pin the repo's own
workflows declare (`signerPinPattern`, capture group 1). Identity and
pin travel together as one candidate: a workflow reached through a
commit-pinned `uses:` carries that commit as its certificate SAN ref
AND as the signer digest, so checking one without the other checks
half the binding. The pin is DERIVED from the consuming tree, never a
policy literal, because mid-bump a repo can carry one candidate per
branch state and the artifact must verify under one of them. Three
things fail closed, each its own finding: a stub that publishes but
has no image under the tag, a tree
declaring no pin at all (the identity cannot be derived, so the image
cannot be vouched for), and an attestation that refuses.

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
  Ecosystem findings (the org's own code surface) always gate.
- `canary` — the pinned release that must yield its known advisory,
  or the scanner cannot see and the walk refuses to judge.

The VEX join is the exact `(advisory, package, version)` triple —
never the advisory alone, so a release that bumps a decided package's
version matches no decision and surfaces for a fresh judgment. Each
matched decision appears in the report as a declared exception whose
origin is the reviewed statement file; a decision matching no current
finding surfaces as stale — a retirement candidate, never an
archaeology project. An empty or absent VEX directory decides
NOTHING, never everything.

## The release evidence manifest

The declared contract, going forward: a release asset (named by the
policy's `manifestAsset`) the publish machinery writes with
`stele emit manifest` and attests, so the contract is immutable at
the tag and readable by a stranger with no knowledge of the
publisher's CI. Writer and reader share one definition
(`internal/evidence`) — a manifest the writer can produce and one
this reader admits cannot drift apart:

```json
{ "schema": 1, "classes": ["oci-image", "rust-crate"], "storeVsa": true,
  "machineryVersion": "1.40.0" }
```

All four fields are required. The manifest declares **facts** —
classes, verdict layout, and the version of the publish machinery
that produced the release — never obligations: whether the release
owes a decision or an enrichment claim is always *derived* from the
policy's `*FromVersion` epochs against `machineryVersion`, through
the same epoch semantics the workflow adapter uses. An adopter with
no history declares no epochs, and every obligation simply always
holds. `machineryVersion` is the attested spelling of the fact the
workflow adapter regexes out of a pin comment; a manifest that omits
it, or carries an unparsable one, refuses — a declaration that
cannot answer the epochs excuses nothing silently.

The manifest's `schema` is its own number, outside the live-document
epoch ([versioning.md](versioning.md)): manifests are published
release assets, immutable once shipped, so the number moves only
when this format's own key set changes against documents that exist.

Releases without a manifest fall back to the workflow adapter — the
quarantined read of the first consumer's publish-workflow convention
at the tag (`classes:` input, machinery version from the `uses:` pin
comment), which is the only honest source for that history and
sunsets as manifests take over. A release neither source speaks for
is **legacy**: it predates the machinery, owes nothing, and is
recorded by name in the report's facts — a category derived from the
tag's own tree, deliberately not assertable by hand.

## The debt file

Human-declared exceptions, one per line, `#` comments allowed:

```text
# repo@tag(assertion) — see PR #NNN for the review that approved this
widget@v1.0.0(sbom)
widget@v1.0.0(attestations-crates.intoto.jsonl)
gadget@v0.2.0(vsa:abcdef012345)
```

The `assertion` is the finding's assertion string exactly: `sbom`,
the checksum or bundle asset name, an `assetPrefixes` prefix, or
`vsa:<first 12 digest hex>`. A malformed line is a refusal, not a
skip — a reviewed file that parses as nothing would excuse nothing
silently. A debt line matching no current finding surfaces in the
report as a stale exception: a retirement candidate, never quietly
carried.

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
--machinery-version <riding> <plan files...>` judges the plans
against the planned obligations pre-publish, in the publish guard.
The judgment is bidirectional, and the two directions deliberately
ask two different questions (stele#143):

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
- `notesRef` — the source chain's notes ref, fully qualified.
- `epochs` — each releasing repository's first signed tag, or
  `pending` for declared-unsigned. A repository that releases tags
  without a line here seals CANNOT_JUDGE: an undeclared population
  member is unchecked, not clean.

The walk (`stele assert tags --org|--repo`): for every matching tag,
the tagger is the declared role, the tag from the epoch onward
carries a gitsign signature verified natively against the trusted
root (CMS over the tag payload, chain to the root's certificate
authorities at the payload's tagger time, SAN and issuer held to the
policy — no gitsign binary, and the forge's own verification verdict
is never consulted: it cannot judge x509-in-the-PGP-slot), and the
tag's target carries a source chain link. The legacy bound is derived
from the chain itself: a target that does not descend from the chain
genesis predates the machinery and owes nothing, reported by name.

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
