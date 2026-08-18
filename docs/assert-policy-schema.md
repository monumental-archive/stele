# The assert policy: schema, first cut

The committed data `stele assert evidence` reads — the universality
boundary applied to the comparison verb: **everything org-shaped
lives here, zero org names in code**. Standard formats (Sigstore
bundle JSONL, in-toto statements, the VSA predicate type, sha256
digests) live in code; this file carries only what the walk cannot
know without being told: which evidence classes exist, what assets
each requires, when verdicts moved into the attestation store, where
the humans keep their written-down debt.

Three formats are defined here: the policy file, the release
evidence manifest, and the debt file. A change to any is a reviewed
edit to this document first.

## The policy file

```json
{
  "schema": 1,
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
        "assetPrefixes": ["attestations-extimg-pg"]
      }
    }
  }
}
```

- `classes` — each class the org publishes, with the bundle assets it
  requires. `legacyVsaBundles` are additionally required only BEFORE
  the store-VSA epoch; `assetPrefixes` are non-bundle assets required
  by prefix. An empty class is a validation error: it would assert
  nothing.
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
  pre-#79 names `storeVsaFromCanon`/`decisionFromCanon` are refused
  with a pointer, never aliased — one field, one name.
- `decisionFromVersion` — the machinery version (inclusive) from
  which a release owes a VERIFIABLE release decision; the full-depth
  leg runs pre-epoch releases through the provenance half alone
  (grandfathered history proves what it can). Same semantics as
  `storeVsaFromVersion`: absent means always, an unparsable pin
  fails strict. Measured for the first conforming org at 1.23.1 —
  the boundary release below which no decision verifies, exactly.
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
policy's `manifestAsset`) the publish machinery writes and attests,
so the contract is immutable at the tag and readable by a stranger
with no knowledge of the publisher's CI:

```json
{ "schema": 1, "classes": ["oci-image", "rust-crate"], "storeVsa": true }
```

All three fields are required. Releases without a manifest fall back
to the workflow adapter — the quarantined org-convention read of the
caller's publish workflow at the tag (`classes:` input, machinery
version from the `uses:` pin comment), which is the only honest source for
history and sunsets as manifests take over. A release neither source
speaks for is **legacy**: it predates the machinery, owes nothing,
and is recorded by name in the report's facts — a category derived
from the tag's own tree, deliberately not assertable by hand.

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
