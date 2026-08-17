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
    "storeVsaFromCanon": "1.13.0",
    "debtFile": "security/attestation-debt.txt",
    "expectedRepos": 4,
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
- `storeVsaFromCanon` — the canon version (inclusive) from which
  verdicts are store-resident. Absent means store-resident always.
  An unparsable pin on a release fails TOWARD the store obligation.
- `expectedRepos` — optional declared population. A listing that sees
  a different count refuses to judge: an unseen repo is unchecked,
  not clean, and a surplus one means this declaration is stale.
- `debtFile` — where the humans keep evidence debt (format below).

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
caller's publish workflow at the tag (`classes:` input, canon version
from the `uses:` pin comment), which is the only honest source for
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
history by the walk itself and excuse only `vsa:` findings on the
affected tag. The asymmetry is the point: what a human may assert
and what only evidence may assert are different types.

## Verification depth

The walk ships at presence depth: assets exist, bundles parse, every
covered subject has a VSA-typed attestation in the store. Full depth
— the same walk with every bundle cryptographically re-verified
through the verify engine — is the corpus re-verification leg
(issue #4) and arrives as a flag on this same walk, not a second one.
