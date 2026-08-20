# Adopting stele: a single repository, no org, no canon

Everything in `docs/` up to here specifies formats. This page answers
a different question: what does a stranger's repository — different
shape, different controls, no organization behind it — actually need
in order to use this tool? The universality law says the answer must
never be "edit the code"; this page is that answer written down, and
its policy examples are executed by the test suite
(`internal/policy/doc_test.go`), so a floor this document claims and
the validator refuses is a red build, not drift.

## Day one: zero configuration

```sh
stele level --repo you/yours
```

No clone, no policy, no trusted root, no evidence-layout declaration.
`stele level` measures the SLSA levels a repository's live, publicly
fetchable evidence actually supports and reports them as information
— it takes no declaration and gates nothing. If you have never heard
of this tool before today, this is the whole first step, and its
output is the worklist for everything below.

## The delivery layer is replaceable

In its home org, stele arrives through a "canon" repository that
supplies three things. Each is trivially substituted; none is a
dependency:

- **The binary.** `go install
  github.com/monumental-archive/stele/cmd/stele@<tag>`, a release
  tarball (each release is attested — the runbook for verifying it
  before first use is the same walk `verify release` performs), or a
  container.
- **The policy.** A committed JSON document at a pinned,
  publicly readable URI. Commit your own; point `--policy-uri` at
  your own blob. The VSA records `policy.uri` + `policy.digest`, so a
  stranger re-reads the exact rules at the exact commit — nothing
  requires that commit to live in a separate repository, and
  [policy-schema](policy-schema.md) already anticipates the
  self-hosted case.
- **The workflow YAML.** One `run:` step per verb, values passed via
  `env:`. Orchestration is deliberately out of scope
  ([chain-format](chain-format.md) and the repo charter both say so);
  any CI that can run a binary under an OIDC identity can run this
  one.

## The policy floor

`policy.Load` validates by **declared obligation**: the minimal valid
document is a schema, an issuer, and the one intrinsic obligation —
who signs provenance. Every other section (`build`, `source`,
`trust.verdict`, `trust.decision`) is absent until you build the
mechanism it describes; a verb refuses **at use** when the section it
needs is undeclared, never at load for a section you don't. This is
the floor, and the test suite loads it verbatim:

```json policy-floor
{
  "schema": 5,
  "issuer": "https://token.actions.githubusercontent.com",
  "trust": {
    "provenance": {
      "signerWorkflow": "{owner}/{repo}/.github/workflows/release.yml"
    }
  }
}
```

The `{owner}`/`{repo}` placeholders make the identity a **role** —
"each repository signs for itself" — so this exact document works for
any repository without editing.

### The chain-emission floor

A repository that emits source chain links (`stele emit chain`) owes
one more section: `source`, whole. Every field the validator demands
there is one the emitter or its verifying leg genuinely reads — the
ledger ref, the signer identity, the protected branches and their
claimed levels — and none is derivable: guessed defaults would be a
second source of truth about your own claims. This is the smallest
chain-emitting policy, also loaded by the suite:

```json policy-floor
{
  "schema": 5,
  "issuer": "https://token.actions.githubusercontent.com",
  "trust": {
    "provenance": {
      "signerWorkflow": "{owner}/{repo}/.github/workflows/source-attest.yml"
    }
  },
  "source": {
    "identity": "https://github.com/{owner}/{repo}/.github/workflows/source-attest.yml@refs/heads/main",
    "notesRef": "refs/notes/commits",
    "provenancePredicateType": "https://slsa.dev/source-provenance/draft",
    "propertyPrefix": "MY_SOURCE_",
    "resourceUri": "git+https://github.com/{owner}/{repo}",
    "protectedBranches": [
      {
        "name": "main",
        "targetLevel": "SLSA_SOURCE_LEVEL_2",
        "levels": [
          {
            "level": "SLSA_SOURCE_LEVEL_2",
            "requiredProperties": [
              {"name": "MY_SOURCE_GATED", "since": "2026-01-01T00:00:00Z"}
            ]
          }
        ]
      }
    ],
    "healedContinuity": false,
    "underclaimLevel": "SLSA_SOURCE_LEVEL_1"
  }
}
```

What each declaration is doing, briefly: `identity` is who may sign
links (a role, templated); `protectedBranches[].levels` is **your**
claim about what your controls establish — the judge deliberately
does not fix requirements to rungs in code; `underclaimLevel` is the
level the emitter writes while a claim is not yet provable;
`healedContinuity: false` says your history carries no healed spans
(the home org's says `true`, because its does — bad history is
recorded, not designed around). Field semantics:
[policy-schema](policy-schema.md).

## The couplings that are real

Stated honestly rather than discovered:

- **`emit chain` execs `cosign sign-blob` under an ambient keyless
  identity.** Deliberate — the binary has no identity of its own; the
  capability boundary lives above this tool. Free in CI with OIDC;
  outside CI it is an interactive browser flow, and your
  `source.identity` must then admit a human identity.
- **`derive claims` reads GitHub's branch-protection rules API**, and
  `emit chain` requires `--claims`. On another forge you can
  hand-write the claims payload — the format is stele's, not
  GitHub's — but no deriver exists for you yet; that is an absent
  mechanism, not a refused one.
- **`assert` needs a forge with releases** (GitHub or GHES via
  `--server-url`). It is the org-corpus verb: it walks a population
  and holds it to a declared completeness contract. A single-repo
  adopter can run it with `--repo`, and mostly doesn't want it on
  day one.

  **You do not have to be uniform.** By default the population is
  every repository the listing shows, archived repositories and forks
  aside — no configuration. When your repositories are not all the
  same shape, the policy's `population` section says so per
  repository and per track, and a repository declared outside a track
  produces nothing there: no finding, no count, no cell. It is a
  statement about what you OWN, never an excuse for what you owe —
  see [assert-policy-schema.md](assert-policy-schema.md#population).
  The same section scopes a single repository that chases one track
  and not the others.

  The exception is **`assert permissions`**, which needs neither a
  forge nor a release: pointed at a checkout it reads workflow files
  off disk and holds every caller to what the workflow it calls asks
  for. A repository whose reusable workflows sit beside their callers
  declares no shared tree at all and gets the join over its own
  calls — see the `permissions` section in
  [assert-policy-schema.md](assert-policy-schema.md).

## What you can skip

- **All of `assert`**, until you have a corpus worth auditing.
- **The store-resident halves** (verdicts in the attestation store):
  the policy's epoch fields exist so an org with pre-mechanism
  history can mark where obligations began. **Absent means always
  owed** — which is exactly correct for a fresh repository with no
  history to excuse.
- **`trust.verdict` and `trust.decision`**, until something of yours
  emits VSAs or release decisions for something else of yours to
  check.

## What this org's docs are not

The remaining documents in `docs/` specify mechanisms — formats,
schemas, walks. Where one mentions the home organization it is as a
worked example, never a precondition; if you find a place where the
only way to express your claim is to edit this tool, that is a bug
in the layout, and the repository's first rule says so in writing.
