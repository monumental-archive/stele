# The verify policy: schema, first cut

This file is the review artifact issue #3 requires before any code
consumes it. It defines the committed policy file `stele verify`
reads — the universality boundary: **everything org-shaped lives
here, zero org names in code**. Standard formats (in-toto
Statement/v1, DSSE and its PAE, the SLSA provenance and VSA
predicates, the `SLSA_<TRACK>_LEVEL_<N>` result syntax, sha256 and
gitCommit digest algorithms) are defined by public specs and live in
code; this file carries only what the specs leave open to the
verifier's policy.

Derivation rule, stated once: every field below cites either a spec
choice-point (the spec says the verifier decides) or an org
convention (the org decided). A field that is neither does not
belong in the policy and was not added.

## Shape

One JSON document, decoded strictly (unknown fields refused,
`internal/jsonx`). Must-be-present fields are pointers in the decode
type and nil is refused — absent and zero never conflate.

Templates use `{owner}`, `{repo}`, `{tag}`, `{version}` placeholders,
substituted verbatim, nothing else interpolated. A template is used
where the convention is per-repository (the source-attest identity)
or per-release (the resourceUri); a literal is used where the org
states one value (the signer workflow).

```json
{
  "schema": 1,

  "issuer": "https://token.actions.githubusercontent.com",

  "trust": {
    "provenance": {
      "signerWorkflow": "monumental-archive/signer/.github/workflows/sign.yml"
    },
    "verdict": {
      "verifierWorkflow": "monumental-archive/.github/.github/workflows/verify-release.yml",
      "legacyVerdicts": [
        { "repository": "monumental-archive/release-lab", "tag": "v0.16.3", "signerWorkflow": "monumental-archive/signer/.github/workflows/sign.yml" }
      ]
    },
    "decision": {
      "signerWorkflow": "monumental-archive/.github/.github/workflows/publish.yml",
      "predicateType": "https://monumental-archive.github.io/attestations/release-decision/v1",
      "requiredConclusion": "OPEN"
    }
  },

  "build": {
    "buildTypes": {
      "https://actions.github.io/buildtypes/workflow/v1": {
        "externalParameterKeys": ["workflow", "inputs"]
      }
    },
    "resourceUri": "pkg:github/{owner}/{repo}@v{version}",
    "sourceRepository": "https://github.com/{owner}/{repo}",
    "targetLevel": "SLSA_BUILD_LEVEL_3",
    "denySelfHostedRunners": true
  },

  "source": {
    "identity": "https://github.com/{owner}/{repo}/.github/workflows/source-attest.yml@refs/heads/main",
    "notesRef": "refs/notes/commits",
    "provenancePredicateType": "https://monumental-archive.github.io/attestations/source-provenance/v1",
    "propertyPrefix": "ORG_SOURCE_",
    "resourceUri": "git+https://github.com/{owner}/{repo}",
    "protectedBranches": [
      {
        "name": "main",
        "targetLevel": "SLSA_SOURCE_LEVEL_3",
        "requiredProperties": [
          { "name": "ORG_SOURCE_GATED", "since": "2026-08-10T21:41:46+01:00" },
          { "name": "ORG_SOURCE_DCO", "since": "2026-08-09T16:29:06+01:00" },
          { "name": "ORG_SOURCE_CAPABILITY_BOUNDARY", "since": "2026-08-09T16:29:06+01:00" },
          { "name": "ORG_SOURCE_HISTORY_PROTECTED", "since": "2026-08-09T16:29:06+01:00" },
          { "name": "ORG_SOURCE_SIGNED", "since": "2026-08-09T16:29:06+01:00" },
          { "name": "ORG_SOURCE_REVIEWED_THREADS", "since": "2026-08-10T21:41:46+01:00" },
          { "name": "ORG_SOURCE_TAG_IMMUTABLE", "since": "2026-08-09T16:29:06+01:00" },
          { "name": "ORG_SOURCE_RELEASE_TAG_MINTED", "since": "2026-08-09T16:29:06+01:00" }
        ]
      }
    ],
    "healedContinuity": true,
    "underclaimLevel": "SLSA_SOURCE_LEVEL_2",
    "legacyLeaves": [
      { "repository": "monumental-archive/.github", "revision": "e1ad2dde9fd24fc521b4b37453dac052e655212b", "reason": "pre-v2 healed fork, #349 finding 3" }
    ]
  }
}
```

## Field by field

### `schema`

Refusal boundary. A verifier reading a policy version it does not
implement refuses; it never best-efforts a newer schema.

### `issuer`

The OIDC issuer every Fulcio certificate in every trust root must
carry. Spec choice-point: Sigstore identity is (issuer, SAN) — the
pair is policy, per root of trust. One org value today; it sits at
top level and applies to all roots until a root needs its own.

### `trust.provenance`

The org's first root of trust: build provenance and producer
evidence verify against this workflow identity (the certificate's
signer workflow). **The commit-level pin is deliberately NOT in
this file.** The org convention (the #314 lesson, restated in the
canon runbook) is that the trusted signer digest is derived at run
time from the consuming tree's own `uses:` pins — a literal digest
in a config drifts from the pin the certificate actually carries.
`stele verify` therefore takes the pinned tree (or an explicit
digest) as an invocation input and asserts the derivation is
single-valued; the policy names only the identity that must match.

### `trust.verdict`

The second root of trust: VSAs verify against the verifier's own
workflow identity — `verifier.id` is the certificate subject, a
tautology rather than a field taken on faith.

`legacyVerdicts` handles the org's history — verdicts on releases
cut before canon v1.14.0 were signed by the org signer instead —
the same way `source.legacyLeaves` handles the chain fork: as a
named, enumerated exception list, one entry per grandfathered
release (repository, tag, the root it verifies under), frozen at
cutover. The set is closed forever, so it earns no live machinery:
an epoch rule keyed on "which canon version cut this release" was
considered and rejected because deciding it requires deriving the
canon pin from each tag's tree — permanent derivation, a network
dependency and a new refusal surface in every verification, in
service of a finite frozen list. A try-each identity fallback is
forbidden outright: a verifier that accepts whichever root happens
to verify has no boundary at all. A release absent from this list
verifies under the current root or refuses, loudly.

The enumeration happened at the verify cutover (stele#3 /
.github#436) and closed at exactly two entries — `.github v1.13.0`
and `release-lab v0.20.1` — each verified against its published
bytes as it was added; the committed list lives in the canon's
`slsa/verify-policy.json`. The epoch's shape, settled by that
shadow: a grandfathered verdict is SIGNED by the entry's
`signerWorkflow` but its predicate CLAIMS the current
`verifierWorkflow` as `verifier.id` — the signer signed on the
verifier's behalf, and the claim never moved. The verifier therefore
switches only the signing identity and its pin on a legacy match;
the claimed verifier URI is constant across both epochs.

### `trust.decision` (optional)

The release-decision gate: a release's SBOM must carry a decision
attestation, signed by this workflow, whose predicate names
`conclusion == requiredConclusion` for the release tag. The
predicate type is an org URI, so it lives here, not in code. The
selection rule (the decision-bearing SBOM is found by verifying
candidates, never by filename; two winners is a refusal) is
verifier logic, not policy — it stays in code.

**The whole section is optional**: a release decision is an
obligation an org declares, not a precondition of using the
verifier. A fresh adopter — or a single repository — with no such
mechanism omits the section and `verify release` proves the
provenance half whole, nothing invented beyond it. Declared means
every field of it, validated strictly; there is no partial
declaration.

### `build.buildTypes`

Spec choice-point: SLSA's verifying-artifacts page leaves accepted
buildTypes and expected externalParameters to the verifier's
expectations. A map so a second buildType is an entry, not a code
change. Per buildType, `externalParameterKeys` is the closed set —
the spec's SHOULD ("reject unrecognized fields in
externalParameters") is enforced as MUST here, which the org
already does. An empty key list would mean "reject all", never
"allow all"; allow-all is unrepresentable by design.

The *values* expected for externalParameters (workflow repository,
ref, path) are derived from the verification subject — the release
repository and tag under verification — not written here: the bash
derived them from its own run identity, which a stranger's verifier
does not have; the honest equivalent is derivation from the claimed
release coordinates, and any mismatch is a refusal.

### `build.sourceRepository`

The second of verifying-artifacts' four comparisons — the canonical
source repository, guarding against an unofficial fork building
under the right identity. A template because the org convention is
that a release's canonical source IS the repository under
verification; making it a policy field rather than an implicit
derivation keeps the comparison visible and lets an org whose
canonical source differs from its release repo say so. All four
comparisons are now named: builder identity (`trust.provenance`),
source repository (here), `buildType` and `externalParameters`
(`build.buildTypes`).

### `build.resourceUri`, `source.resourceUri`

Org conventions for the VSA's required `resourceUri`: a purl for
release verdicts, the SPDX download-location form for the source
track (the source form is a spec MUST in shape; the exact value is
the SCS's documented choice). Verified by exact match after
substitution.

### `build.targetLevel`, `source.protectedBranches[].targetLevel`

What the org claims when every check passes, and what `stele
verify` requires a fetched VSA's `verifiedLevels` to contain. The
`SLSA_<TRACK>_LEVEL_<N>` syntax and the one-level-per-track rule
are spec, in code; which level is policy.

### `build.denySelfHostedRunners`

The org runs verification with self-hosted runners refused. A named
knob because it is a real policy choice in the Sigstore/GitHub
verification model, and a universal tool cannot hardcode it.

### `source.identity`

The per-repo reserved workflow SAN — the frozen root-of-trust
contract for chain links. A template because the convention is
structural across repos; the ref is pinned inside the template
(`@refs/heads/main`) because the identity contract includes it.

### `source.notesRef`, `source.provenancePredicateType`, `source.propertyPrefix`

Where the ledger lives, the org's documented source-provenance
predicate URI, and the claims namespace. The chain-link note format
(version 1/2, `ledgerPrev` vs `prev`, noteSha256 over raw blob
bytes, genesis exactly once, coverage and linkage as independent
walks) is the org's *documented format* — it is data-model, and it
lives in code typed to the documentation, not in policy: a policy
cannot make an undocumented note format verifiable.

### `source.protectedBranches`

Carried over from the canon's `source-policies/default.json` with
the same semantics: the target level is claimed only when every
required property appears in the link's `controls[].property`;
otherwise the link under-claims `underclaimLevel`. `since` times
are continuity starts and only move backwards with evidence.
This section is the successor of that file, not a sibling: at
cutover `source-policies/default.json` is deleted and this file is
the org's one source-track policy. Until then the shadow diff
asserts the two agree — agreement is the proof bar, never the
steady state.

### `source.healedContinuity`

The org's documented deviation handling: a healed (late) link may
still claim the target level iff every contributing ruleset's
`updated_at` predates the revision's `commitTime`. `true` accepts
that continuity argument; `false` caps healed links at
`underclaimLevel`. Consumers gating on strict contemporaneity
already have `repaired` in the predicate; this knob is the
verifier's own stance.

### `source.legacyLeaves`

Named, bounded exceptions: ledger members unreachable from the
tail that are accepted as known history rather than refused. Each
entry names repository, revision and reason — the revision is the
full 40-hex identifier, abbreviations refused: an exception to a
cryptographic walk is itself named cryptographically. Silence is
unrepresentable, and an unreachable v2 link is always a refusal
regardless of this list (the v2 ledger must not fork; that rule is
code).

## What is deliberately absent

- **Signer commit digests** — derived from the consuming tree's
  pins at invocation, never written (above).
- **Registry byte-proof URLs** (crates.io/npm/release-asset
  templates) — that is `assert`'s domain (image facts, bundle
  completeness), not the read-only verifier's. Added to the schema
  when `assert` ports, as its own section.
- **Enrichment predicate contents** (toolbelt lock, base-image
  majors, lockfile names) — `emit`'s write-side concern.
- **Population enumeration** (which repos the org audit walks, the
  opt-out file) — orchestration, not verification: `stele verify`
  verifies what it is pointed at; the walk over the org stays in
  the caller until `assert` decides otherwise.
- **`slsaVersion`** — pinned `"1.2"` in code: it names the spec the
  implementation conforms to, and a policy cannot change what the
  code implements.

## Disagreements surfaced so far (method step 3)

1. **Positional source-revision read.** The bash reads the attested
   source revision from `resolvedDependencies[0].digest.gitCommit`.
   The provenance spec does not make `resolvedDependencies` ordered;
   the spec-derived implementation must select by content (the entry
   whose uri names the source repository), not by index. If real
   provenance ever carries a different first entry, the bash
   misreads — candidate live defect, to be confirmed in shadow mode.
2. **externalParameters expectations from run identity.** The bash
   asserts the provenance's workflow repository/ref/path equal its
   *own run's* — sound only because verifier and release share a
   run. A stranger's verifier cannot inherit that; deriving the
   expectation from the release coordinates (repo under
   verification, `refs/tags/{tag}`) is the spec-shaped equivalent
   and must agree with the bash on every real release. Any
   divergence is a finding, not a smoothing.
3. **Two policy files today.** `source-policies/default.json` and
   this schema's `source.protectedBranches` say the same thing. This
   file is the successor; the cutover deletes the other, and until
   then the shadow diff asserts they agree.
