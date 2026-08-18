# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## What this is

`monumental-archive/stele` — a **universal SLSA evidence engine and its
verifier**, in Go. Standard formats live in code; org conventions live
in a committed policy file; the org is the first conforming consumer,
never a hardcoded name. Four verbs, which are the command surface:

- **derive** — versions from conventional commits, SBOM assembly, VEX
  from triage decisions, OCI image facts
- **assert** — image facts, evidence-bundle completeness (releases,
  continuous digests, base approvals), advisory blast radius, release
  tags (tagger role, gitsign signature from the declared epoch, chain
  link on the target).
  Repo-settings drift was in the original charter and is DROPPED by
  written decision: rulesets enforce; a setting that matters to
  evidence surfaces as a consequence in the evidence walk, and a
  baseline nobody enforces is a second source of truth. The OpenSSF
  questionnaire auto-fill is the same won't-do.
- **emit** — source-chain links, VSA predicates, evidence-bundle
  layout: the JSON that gets signed
- **verify** — every attestation against a pinned signer identity, the
  source chain walk, the VSA verdict; plus `level`, the honest current
  level computed from live evidence

Born from `.github#392`: it replaces ~8000 lines of bash spread across
the canon's scripts, workflow `run:` blocks and belt task bodies. The
port is the relocation — one language per file, each file where its
language's standard tools already walk.

## Port sequence (the standing order — follow it, do not reorder)

One authority handover at a time; each verb ships, shadow-proves, cuts
over whole, and only then does the next open. State and next step:

1. **verify — DONE, authoritative** (#3, closed at .github#436):
   `audit:source-vsa` runs this binary; the bash walk is deleted; the
   org policy is canon `slsa/verify-policy.json`.
2. **emit — DONE, authoritative** (#21, cut over at .github#437,
   closed at #24): the source-attest action and verify-release.yml
   call `stele emit`; chain.sh/emit.sh/lib.sh/append.sh,
   `source-policies/` and `release/vsa-predicate.jq` are deleted. The
   .github#434 digest class is structurally unrepresentable — one
   `chain.SHA256Hex` shared by the emit and verify legs, predecessor
   hashes taken from the note read back out of the object store, and
   a compare-and-swap append that rebuilds on rejection. The
   defective spans were deleted and re-emitted through this emitter
   (31 links on .github, 15 here). Note-format v3 (stele#19 item 6)
   DSSE-authenticates both halves — signatures cover
   PAE(payloadType, statement) — and retired v1/v2 reading whole:
   the org ledgers re-emit at the canon cutover (the #434 healing
   precedent), because pre-v1 nothing external consumes the old
   bytes and dual-version reading would be dead weight.
3. **release wiring — DONE** (#7): the `go-binary` class shipped and
   stele self-releases N-1 (v0.1.0 onward); the belt installs the
   released, attested binary and the `go run @<sha>` pins are
   retired. **derive version + notes — DONE** (#31, pulled forward as
   release wiring's input; sequencing note on #25).
4. **assert — DONE, authoritative** (#39 built it as #62/#63/#66,
   #69 landed the cutover): `audit:attestations`,
   `audit:blast-radius` and the image-facts pull-back checks each run
   one `stele assert` line against canon `slsa/assert-policy.json`;
   the task-body bash and `assert-image-facts.sh` are deleted. Every
   target was shadow-proven live before its handover, and the
   population rule answered a real degraded forge on day one (the
   2026-08-17 outage's 200-with-`[]` → CANNOT_JUDGE, stele#69). The
   emit residue moved into the engine: preflight and the
   reserved-identity guard, which refuses an absent workflow ref
   (#74).
5. **derive, the remainder — open as #40, the last leg**: claims,
   VEX, OCI facts (SBOM landed with #46). With it goes the clone
   prep, the last logic in the source-attest action.

Each handover also moves that mechanism's documentation: the canon doc
that used to specify the behavior shrinks to org narrative plus a
pointer, and the spec lives here (docs/, or the code and its tests).
The canon speaks for the org; stele speaks for the mechanism.

## Scope boundaries (settled in #392 — do not relitigate)

- **Not workflows.** Orchestration YAML stays in the canon: jobs,
  `permissions:`, OIDC grants, the job graph. Step bodies become one
  `stele <verb>` line with values passed via `env:`, never `${{ }}`
  interpolated into shell.
- **Not signing.** Minting stays on `actions/attest` / cosign / the
  signer repo. A binary has no identity in a Fulcio certificate — the
  capability boundary lives strictly above this tool, and the rewrite
  cannot touch Build L3's mechanism.
- **Not the belt.** This is a belt member, not a belt replacement.
- **No SLSA level is bought here.** The prize is a testable evidence
  layer and a verifier strangers execute. The repo's pinned build is a
  Build-track choice; it is deliberately NOT a Dependency L3 claim
  (the org row stays L2, #121 stays closed).

## Rules

- **A disabled rule needs a reason about the rule. If the reason is
  about reach, the layout is wrong.** "Wrong for this domain" is
  legitimate and permanent; "the tool cannot see this code" is a defect
  report against the layout — move the code, never write the extractor.
  `.golangci.yml` is the worked example; `nolintlint` enforces it at
  line granularity.
- **Every guard branch gets a table test** (carried from .github#364's
  closure). Guards that fire only in degraded states are the least
  exercised code in the org, and a guard that skips when it should run
  looks exactly like success. The failing-writer tests in
  `internal/cli` are the pattern.
- **`encoding/json` only inside `internal/jsonx`** (depguard-enforced).
  The stdlib decoder turns absent into zero silently; evidence code
  must distinguish them, so decode types use pointer fields and
  validation rejects nil explicitly.
- **Pinned build**: `CGO_ENABLED=0`, `GOTOOLCHAIN=local`, `-trimpath`.
  Dependencies are pinned by `go.sum` (byte-identical modules or a
  failed build) and fetched through the checksummed proxy — the one
  accepted network dependency in the gate. **A committed `vendor/`
  tree is deliberately refused** (decided 2026-08-15, reversing the
  original vendor law after one afternoon of it): vendoring made
  REUSE.toml's aggregate annotation a false licensing claim over
  upstream code, put per-module licence bookkeeping on every Renovate
  bump, and forced reach-shaped vendor exceptions into every org tool
  — by the disabled-rule law, a layout defect. What vendoring bought
  beyond go.sum was offline builds and upstream-deletion insurance;
  not worth that price.
- **Pre-v1, correctness wins every tie.** Until stele cuts a v1,
  nothing external depends on it: formats, schemas and vocabulary
  change to the correct-by-construction shape without compatibility
  shims, dual-version readers, or deprecation ladders. If a correct
  stele breaks the canon, the canon conforms to the tool — never the
  tool to the org's accumulated shape. Bad history is recorded
  honestly (healed links, legacy categories), not designed around.
- **The bash is a reference, not an oracle.** Ported logic runs beside
  it on identical inputs and divergence is investigated — but the bar
  is spec correctness (SLSA v1.2, in-toto/DSSE, git's actual storage
  semantics), never byte-equality with the bash. The bash carries
  defects (.github#434's newline digest bug among them) and homegrown
  quirks; reproducing them is transliteration wearing a proof. The
  real oracles are the published releases and chain links. Record
  divergence as a finding; never contort output to match bash bytes.
  Nothing is left half-ported as a standing state.
- **pgrx upgrade derivation ports last, or never** — a written
  sequencing decision (#392): `generate-pgrx-upgrade.sh` is proven SQL
  text derivation whose oracle a byte-diff cannot capture; it moves
  only after everything else is authoritative, with a lab pgrx release
  as its proof.
- Commits: conventional, imperative, lowercase, 72-column, DCO
  sign-off; scopes in `committed.toml`. PRs squash-merge through the
  org gate (`ci / ci`).
- Licence: Apache-2.0 (public Go infra convention — patent grant;
  0BSD stays canon-only). REUSE.toml declares; per-file headers are
  refused by design.

## Release

stele self-releases N-1 (version N built and attested by version
N-1, the .github#227 shape) through the canon's `go-binary` class,
live since v0.1.0. Its own versions and notes come from
`stele derive version` / `derive notes` — the tool eats first. The
org-wide git-cliff replacement (the three `git cliff` lines in the
canon's release scripts becoming `stele derive` calls, cliff.toml
retired) rides the canon cutover PR.

## Testing

`mise run ci` is the gate — the org belt (from the canon pin in
`.github/workflows/ci.yml`) plus this repo's `test`/`build` tasks.
`coverage:check` enforces `.coverage-floor` (ratchet: it only rises).
`mise run audit:go-vulns` is the scheduled advisory scan; network, so
never in the gate.
