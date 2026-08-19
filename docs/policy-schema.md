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

The example below elides one key, `source.claims`: it is the largest
section in the document and it is shown in full under its own
heading rather than copied into two places in one file, which is the
drift this schema exists to refuse.

```json
{
  "schema": 3,

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
    "denySelfHostedRunners": true,
    "enrichment": {
      "predicateType": "https://monumental-archive.github.io/attestations/build-enrichment/v2",
      "required": ["toolbelt-lock"],
      "permitted": ["pgrx-base-images", "pgrx-base", "Cargo.lock", "package-lock.json", "mise.toml"]
    }
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

## Declared obligations (the universality principle, #79/#82)

**Obligations are declared; identities are roles; only provenance is
intrinsic.** The minimal valid policy is `schema` + `issuer` +
`trust.provenance` — everything an adopter needs on day one, with
the provenance identity possibly templated to the repository itself.
`trust.verdict`, `trust.decision`, `build`, `build.enrichment` and
`source` are sections an org declares when it builds the mechanism:
absent means the obligation does not exist; declared means every
field of it, validated strictly. The verbs refuse at USE when the
section they need is undeclared (`verify release` needs `build`;
`verify vsa` needs `build` and `trust.verdict`; the chain walk and
emitter need `source`), so a missing section is a named refusal,
never a load failure and never a silent skip.

**The one load-time exception, and why it is not one.**
`build.enrichment` declared while `trust.verdict` is absent refuses
at LOAD. The rule above is about ABSENT sections; this is a DECLARED
obligation whose proof needs an identity nobody declared — the
enrichment verifies under the verdict identity, so the obligation
could never be met by any evidence whatsoever. That is a malformed
policy, not a missing one, and the honest place to say so is where
the document is read.

Workflow identity fields (`signerWorkflow`, `verifierWorkflow`)
accept `{owner}` and `{repo}` — and only those two — so "each
repository signs for itself" is expressible: a self-attesting
repository's certificate names its own workflow at the release tag,
and the SAN derivation composes through the same self-vs-foreign
rule every literal identity already follows. A placeholder outside
that vocabulary refuses at load: a per-tag identity would be a
wildcard, not a role.

## Field by field

### `schema`

Refusal boundary. A verifier reading a policy version it does not
implement refuses; it never best-efforts a newer schema — and it
refuses with a **version error from the gate**, which runs before
strict decoding, never incidentally with an unknown-field error
(stele#107). When the number moves is governed by
[docs/versioning.md](versioning.md). Current: **3** — ONE epoch
shared by the verify policy, the assert policy and the report, so a
bump cannot land on one document and miss another (the drift #107
found). Identifiers written into history — the chain note version,
the evidence-manifest schema — keep their own numbers, because they
cannot be re-emitted on demand.

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

### `build.enrichment` (optional)

The build-enrichment obligation: which resolved dependencies a signed
enrichment claim must carry, and which it may. The org signs a
build-enrichment predicate beside every verdict — the toolbelt
lock every tool version and checksum derives from, base-image digests
for the majors a build actually instantiated, the released
repository's lockfiles at the attested source revision — computed
entirely in the verification control plane, because SLSA makes
`resolvedDependencies` completeness a SHOULD and requires L3
provenance fields to be control-plane generated. Until stele#86
nothing consumer-side read it, and a signed claim nobody reads is
decoration with a signature on it.

- `predicateType` — an org URI, so it lives here, like
  `trust.decision.predicateType` and
  `source.provenancePredicateType`. The predicate's SHAPE is code
  (`internal/enrichment`), typed to its documentation, and shared with
  the emitter: a policy cannot make an undocumented predicate
  verifiable, and two definitions of one predicate would be two
  answers. The shape this implementation reads is the neutral one
  (`policy` as a resource descriptor, `sourceRevision.uri`), which is
  a key-set change from what the org signed before it — so the URI's
  version segment moves with it, per
  [versioning.md](versioning.md#predicate-type-uris). Pre-bump
  attestations stay signed under the old URI as the accurate name of
  the old shape, and are simply not found: which releases owe a claim
  at all is the epoch's question, not this field's.
- `required` — names that must appear. Empty is refused at load: an
  obligation requiring nothing would let a claim resolving nothing
  pass, which is the decoration this section ends.
- `permitted` — names that may appear. May be absent, meaning the
  required names are the whole set.

`required` ∪ `permitted` is a **closed set**, the same stance
`build.buildTypes[].externalParameterKeys` takes: a claim naming
anything outside it is refused, because a signed FALSE dependency is
worse than an omitted one — the org has the finding history to prove
it (a boolean once emitted the entire pinned base-image set for every
declaring class, `FROM scratch` images included). A name appearing in
both lists refuses at load: it is one set, and a name is in it once.

**From when.** The verify policy carries no epoch, deliberately:
`verify vsa` judges the one release it is pointed at, so a stranger
verifying today's release is owed the whole obligation. WHICH
historical releases owe a claim is the corpus walk's question, and it
is answered where the corpus is — `evidence.enrichmentFromVersion` in
the assert policy, derived through the same `owedFrom` the store-VSA
and decision epochs use, and carried to the engine on the evidence
contract. The engine takes it as one nilable demand rather than a
flag or a second entry point: `verify.VSA` receives an
`EnrichmentDemand` that is nil when the obligation is not owed at
all, empty when only the universal names are owed (a stranger, or a
class declaring nothing extra), and non-empty when the release's
declared classes owe more — three states a boolean cannot carry, and
a shape in which "not owed" and "owed nothing extra" cannot be
confused (the absent-vs-zero discipline the decode types already
keep). Withholding is whole — a pre-epoch release carrying a
malformed claim is not quietly held to a standard the walk decided it
does not owe.

**Where it is proven.** Inside `verify vsa`, not a mode of its own. A
mode a caller can decline is an obligation a caller can decline. It
costs no extra fetch — the attestation store returns the verdict and
the enrichment together, over the same subjects, under the same
identity — and it gives `verify vsa` a source revision a bare verdict
never carries, folded across subjects so disagreement refuses rather
than surviving.

**What it proves, and what it does not.** The leg proves the claim is
BOUND and COMPLETE: signed under the verdict identity at the
machinery pin, over the same subject, naming the declared resource
and source repository, carrying exactly the declared names with
well-formed digests. It never re-derives what those digests cover —
that needs the policy tree at the claimed pin, and a check that
re-runs the writer's derivation is the writer inverted, passing its
own exam. The `uri` on every entry is what makes the values checkable
by someone who trusts none of this.

**Not keyed by class here.** "Which dependencies for which evidence
class" needs a class, and `verify vsa` has none — a stranger cannot
supply one, so the CLI passes the empty demand and gets the whole
universal obligation. That half of the obligation is declared where
the class declaration already lives: the release's own evidence
manifest, read by `assert`, joined against `assert-policy.json`'s
`classes.<name>.enrichment` lists into the demand's extra names. The
extras extend only what is REQUIRED, never what is allowed: every
class name must already live inside this policy's `required` ∪
`permitted`, or class expectations and the closed set would be two
truths about one vocabulary. Neither policy file can see the other,
so the rule is enforced at the one place that holds both — `verify.
VSA` refuses the RUN before judging any subject, distinct in text
from any unmet obligation, because a drift between two policy
documents is never a finding pinned on a release that did nothing
wrong.

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

### `source.claims`

Where the frozen control table lives, and the reason this section
exists: until now the property *names* lived here (in
`protectedBranches[].requiredProperties`) while the rules that decide
whether each one is live lived in the canon's `claims.sh` and in
prose in `docs/source-track.md`. One vocabulary, three places,
coupled only by a human reading all three. Declaring the matchers
beside the requirement makes them one document, and the load-time
cross-check below makes disagreement refuse rather than under-claim
silently.

An org convention throughout — every property name, every rule
parameter and every actor id below is the org's, and none of it is
in code.

The section is an obligation like every other: absent means the org
does not derive claims with this tool. Declared means each property
carries a scope and a matcher, validated strictly.

```json
"claims": {
  "properties": [
    {
      "name": "ORG_SOURCE_HISTORY_PROTECTED",
      "scope": "branchRules",
      "match": { "$contains": [
        { "type": "deletion" },
        { "type": "non_fast_forward" },
        { "type": "required_linear_history" }
      ] }
    },
    {
      "name": "ORG_SOURCE_SIGNED",
      "scope": "branchRules",
      "match": { "$contains": [ { "type": "required_signatures" } ] }
    },
    {
      "name": "ORG_SOURCE_GATED",
      "scope": "branchRules",
      "match": { "$contains": [ {
        "type": "required_status_checks",
        "parameters": {
          "strict_required_status_checks_policy": true,
          "required_status_checks": { "$contains": [
            { "context": "ci / ci", "integration_id": 15368 }
          ] }
        }
      } ] }
    },
    {
      "name": "ORG_SOURCE_REVIEWED_THREADS",
      "scope": "branchRules",
      "match": { "$contains": [ {
        "type": "pull_request",
        "parameters": {
          "required_review_thread_resolution": true,
          "allowed_merge_methods": ["squash"]
        }
      } ] }
    },
    {
      "name": "ORG_SOURCE_TAG_IMMUTABLE",
      "scope": "tagRulesets",
      "match": { "$contains": [ {
        "conditions": { "ref_name": { "include": ["~ALL"], "exclude": [] } },
        "rules": { "$contains": [
          { "type": "update" }, { "type": "deletion" }, { "type": "non_fast_forward" }
        ] },
        "bypass_actors": []
      } ] }
    },
    {
      "name": "ORG_SOURCE_RELEASE_TAG_MINTED",
      "scope": "tagRulesets",
      "match": { "$contains": [ {
        "conditions": { "ref_name": { "include": ["refs/tags/v*"] } },
        "rules": { "$contains": [ { "type": "creation" } ] },
        "bypass_actors": [
          { "actor_id": 4534781, "actor_type": "Integration", "bypass_mode": "always" }
        ]
      } ] }
    },
    {
      "name": "ORG_SOURCE_DCO",
      "scope": "gatedTask",
      "requiresProperty": "ORG_SOURCE_GATED",
      "file": "mise/config.toml",
      "tablePath": ["tasks", "lint:dco"]
    },
    {
      "name": "ORG_SOURCE_CAPABILITY_BOUNDARY",
      "scope": "gatedTask",
      "requiresProperty": "ORG_SOURCE_GATED",
      "file": "mise/config.toml",
      "tablePath": ["tasks", "lint:capability-boundary"]
    }
  ]
}
```

#### Matching by content, never by name

Ground truth is the forge's rules API at emission time, never
configuration intent, and every property is matched by the
parameters that make the control what it is. A renamed ruleset still
enforces; a gutted one still carries the name. No matcher may
reference a ruleset's name or id, and the schema gives it nowhere to
put one.

#### The match language

A matcher is a JSON value, matched against a candidate value by four
rules and nothing else:

- **object** — the candidate must be an object, and every key in the
  matcher must be present in it and match recursively. A *subset*:
  fields the matcher does not name are not examined.
- **array** — the candidate must be an array of the same length,
  matched elementwise in order. *Exact*. This is where two of the
  controls actually live: `"bypass_actors": []` means **nobody
  bypasses**, and `"allowed_merge_methods": ["squash"]` means
  **squash and nothing else**. A subset reading of those would claim
  a control the org does not have.
- **scalar** — equality on the decoded JSON value.
- **`{"$contains": [...]}`** — the one escape: the candidate must be
  an array, and for *each* matcher in the list some element of it
  must match. This is "at least these", and it is what every
  property's top-level matcher uses, since a property asks whether
  the rules the org requires are among the rules that are live.

`$contains` is reserved vocabulary: an object carrying it may carry
nothing else, refused at load otherwise. A forge that one day serves
a field literally named `$contains` would be unmatchable; the
alternative is a general query language, and this is the
`build.buildTypes.externalParameterKeys` trade made again —
expressive enough for the table the org froze, too small to express
nonsense.

#### Scopes

- **`branchRules`** — the effective rules for the branch being
  claimed, as the forge computes them (all contributing rulesets
  already merged). The matcher runs against that whole array.
- **`tagRulesets`** — each active tag ruleset, fetched in full.
  Effective per-ref rules exist only for branches, so tag properties
  are matched against ruleset *content*: conditions, rules and
  bypass actors together.
- **`gatedTask`** — a control the org enforces inside its own gate
  rather than through a forge rule. Claimable exactly when the named
  property is claimed (`requiresProperty`, which must name a
  rules-scoped property in this same table — one level, no chains,
  validated at load) and the declared TOML table path exists in the
  declared file of the canon tree this run resolved. `tablePath` is
  a path, not a pattern: the file is parsed, never grepped, so a
  legitimately different spelling of the same table cannot
  under-claim.

#### Evidence is the matcher's witness

Each claim carries evidence, and the engine derives it: the matched
elements restricted to exactly the paths the matcher examined,
recorded as it traverses. Nothing that decided the claim is omitted
and nothing that did not is carried. A policy-declared projection
would be a second place to be wrong about what the claim rests on —
and one that omitted a deciding field would turn the evidence into
decoration. Evidence is therefore not in the schema at all.

#### Absence, blindness and failure are three outcomes

A property whose rule is not live is simply absent from the claim
set, which is how a lapse under-claims and resets its own clock by
construction. That is the *only* thing absence may mean, so the two
ways of not-knowing are refusals, and the second one derives from
this section rather than from any fact about a particular org:

- **failure** — the read errored, or a listed ruleset's detail was
  unreadable. Refused: claiming from a blind read asserts controls
  nobody checked.
- **blindness** — a scope some declared property matches against
  came back empty. Declaring a property against a scope *is* the
  statement that the scope is populated, so an empty read there is
  the credential proving its own incapability, not an absent
  control. Refused. A scope no property names is never read at all.

#### Load-time cross-check

Every `requiredProperties[].name` in `protectedBranches` must be
declared here. A required property with no matcher can never be
claimed, so the branch could never reach its target level — today
that is a silent permanent under-claim discoverable only by reading
two files and a shell script; here it refuses at load. The converse
is allowed: a property may be claimed without being required, since
claiming more than the target needs is honest.

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
- **Enrichment predicate CONTENTS** (which lock file, which
  base-image majors, how each digest is computed) — still `emit`'s
  write-side concern. `build.enrichment` declares only the
  EXPECTATIONS a reader holds the claim to: which names are owed and
  which are allowed. The distinction is the derivation boundary — a
  verifier that knew how to compute the contents would be the writer
  inverted (stele#86).
- **Population enumeration** (which repos the org audit walks, the
  opt-out file) — orchestration, not verification: `stele verify`
  verifies what it is pointed at; the walk over the org stays in
  the caller until `assert` decides otherwise.
- **Per-name digest discipline in `build.enrichment`** — whether a
  given claimed dependency owes a digest. A digestless entry is legal
  in the shape (identified by `uri` alone), which is how an image
  named by a separately-digested mapping file travels. Making that a
  policy field was considered and left out: it is one bit per name in
  service of a distinction no org has yet needed to draw, and the
  shape already refuses an entry with neither name nor address.
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

Items 4 to 7 come from the claims port (stele#40) and are recorded
under the same law: the bash is a reference, never an oracle, and
every divergence is written down rather than smoothed.

4. **Evidence was a hand-written projection.** `claims.sh` records
   matched tag rulesets as `{id, rules, conditions}` and belt-carried
   claims as `{via: "ci / ci", canon: <ref>}`. Both are written
   beside the matcher and can therefore omit a field that decided the
   claim — `bypass_actors` is absent from the immutability
   projection, and it is half of what that control *is*. The witness
   derivation carries exactly the examined paths, so the omission is
   unrepresentable.

   Measured, not predicted: run side by side against one recording of
   the live rules API for `monumental-archive/.github` (2026-08-18),
   both legs derive the same eight properties and the same continuity
   horizon, and the bash's `ORG_SOURCE_TAG_IMMUTABLE` evidence answers
   `has("bypass_actors") == false` where the witness answers `true`.
   Every published chain link carrying that property therefore records
   evidence that omits the field the claim rests on. Nothing consumes
   `controls[].evidence` programmatically — the emit and verify legs
   read `property` and require evidence to be non-empty — so this is a
   defect in what the ledger tells a reader, not in what it decided.
5. **Belt-carried controls were detected by grep.**
   `grep -q '^\[tasks."lint:dco"\]'` reads one legal spelling of a
   TOML table. Any other — different quoting, a dotted or inline
   table — under-claims. Fail-safe, still a defect, and the org
   already holds the opposing rule elsewhere (`resolve-oci-facts.sh`
   reads Cargo.toml with a parser, "the only reader that gets every
   form right").
6. **The blindness guard cited an org fact.** The bash refuses an
   empty tag read because *the org's* tag rulesets are known to
   exist. True, and unusable by anyone else. Declaring a property
   against a scope is the same statement in universal form, so the
   guard now derives from the policy and holds for every adopter.
7. **Continuity offsets were arithmetic in jq.** `updated_at`
   arrives with arbitrary UTC offsets and jq's date built-ins are
   UTC-only, so the bash applies the offset by hand from captured
   substrings. RFC 3339 parsing is a library call; the defect class
   goes with it.
