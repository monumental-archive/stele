# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## What this is

`monumental-archive/stele` — a **universal SLSA evidence engine and its
verifier**, in Go. Standard formats live in code; org conventions live
in a committed policy file; the org is the first conforming consumer,
never a hardcoded name. Four verbs, which are the command surface (the mechanisms
enumerated under each describe what is BUILT today, not a closed
universe — the vocabulary stays open, per the first Rule):

- **derive** — versions from conventional commits, SBOM assembly, VEX
  from triage decisions, OCI image facts
- **assert** — image facts, evidence-bundle completeness (releases,
  continuous digests, base approvals), advisory blast radius, release
  tags (tagger role, gitsign signature from the declared epoch, chain
  link on the target), chain coverage of the whole population
  (founded and verified per protected branch, or a declared
  exception — cloneless, #94), the caller/callee `permissions:` join
  across a workflow tree (#148 — what a shared workflow's jobs ask
  for is what its callers must grant, computed through the one
  workflow reader in `internal/workflow`).
  Every one of them enumerates its subjects through
  `internal/population` and NOWHERE else (#153): the population is a
  declared object — per repository and per SLSA track, with the
  archived/fork rule demoted from code to its default expression —
  reconciled against the listing by name in both directions, and a
  forbidigo rule keeps the listing read out of every other package.
  Exclusion and exception may never share a vocabulary: an exclusion
  produces NOTHING (no finding, no count, no cell), an exception is
  dated and loud until resolved.
  Repo-settings drift was in the original charter and is DROPPED by
  written decision: rulesets enforce; a setting that matters to
  evidence surfaces as a consequence in the evidence walk, and a
  baseline nobody enforces is a second source of truth. The OpenSSF
  questionnaire auto-fill is the same won't-do.
- **emit** — source-chain links, VSA predicates, evidence-bundle
  layout: the JSON that gets signed
- **verify** — every attestation against a pinned signer identity, the
  source chain walk, the VSA verdict, the reproducibility rebuild's
  typed verdict (#96); beside it `level`, its own verb since #125:
  the honest current level measured from live evidence, taking no
  declaration — `--org` reads one, and only to decide WHO IS ASKED;
  `internal/level` still imports no policy, so nothing written down
  can reach a rung. `--org --out-dir` with no track publishes the
  whole board (#152), and `internal/board` owns the one rule about
  what may replace what: a cell that cannot be judged today never
  publishes over a level proven yesterday, grey lands only onto
  absence, and a cell the population no longer holds is removed

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
5. **derive, the remainder — MECHANISMS BUILT (#40), cutover
   pending**: claims, OCI facts, VEX and the per-artifact SBOM
   inventories all have engines and command surfaces; the clone prep
   moved into `emit chain --clone`, which fetches the refs the policy
   names rather than the ones a caller restated. Claims is
   shadow-proven live against the rules API (identical property set
   and continuity horizon, with the bash's tag-immutability evidence
   measured to omit `bypass_actors`). Facts and VEX are not yet
   shadow-proven: both want a release to point at, so they batch with
   the cutover.
6. **the final four — DONE (2026-08-19)**: `assert chains` (#94 at
   #137) retired the last evidence-audit bash's walk, cloneless, with
   opt-outs as declared policy exceptions that structurally cannot
   excuse a founded chain's defect; `verify repro` (#96 at #138)
   typed the reproducibility rebuild's verdict, deliberately unwired
   from `level` (nothing attests a local rebuild); the adopter guide
   (#131/#132 at #139) states both policy floors as fenced examples
   the test suite executes through `policy.Load`. The stele side of
   the port is COMPLETE; everything remaining is canon-side.
7. **`assert permissions` — BUILT (#148), cutover pending**: the last
   judgment-shaped script in the canon
   (`security/workflow-permissions.py`) is ported whole. Its three
   org-shaped literals — the shared repository's name, its tree's
   directory, the caller directories — are the policy's `permissions`
   section, and the fixed-indent line scanner is replaced by the one
   workflow parser (`internal/workflow`), which the release
   contract's legacy adapter now shares. Shadow-proven against the
   canon tree: the computed requirements are identical across all 39
   (workflow, scope, level) tuples, and 21 mutations of the callee
   side produce identical caller findings. Four measured divergences,
   all the port being more correct, are recorded on the issue. This
   batches into the same canon handover.

   The canon cutover is deliberately NOT per-leg. One batched
   handover, filed as .github#545, and inside it the stele pin bump
   lands BEFORE the policy edit — inverted from the canon's usual
   policy-then-pin, because `jsonx` disallows unknown fields and
   `policy.Load` version-gates before strict decode, so a policy
   declaring a new section against an older pinned stele fails
   belt-wide with a correct cause and a useless message.

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

- **Nothing this org happens to claim may be unclaimable by
  construction.** The judge implements the SPEC; the org declares
  what it claims; the two meet in the policy file and NOWHERE else.
  The test is one question, asked of every level, track, requirement
  and property: *could a stranger's repo — different shape, different
  controls, a brand-new org with a minimal policy — express its own
  claim without editing this tool?* If the answer is "they would have
  to change the code", the layout is wrong, and it is wrong in the
  same way a reach-shaped lint exception is wrong.

  "Our org does not do two-party review" / "we are L0 there" / "we
  refused vendoring" are POLICY facts. Written into code they become
  "nobody does this", which is the tool asserting a fact about the
  world from one repository's configuration. Recorded defects of this
  class: a source ladder whose level 4 no policy could declare, a
  dependency track whose upper levels the judge called unknowable
  because this org has no evidence for them, and a rung-to-requirement
  mapping fixed in code because our controls happen to sit there.
  A fourth member, found 2026-08-24: CARDINALITY baked into a
  schema — parameters declared in policy but the block singular and
  closed because this org currently has exactly one (a base-approval
  block one mechanism wide, stele#247; its recorded siblings are
  listed there). Plurality of mechanism is part of the stranger's
  claim: "how many of this thing exist" is policy, never code.
  Every one of them read as a reasonable comment at the time.

  A track or level this tool does not YET judge is absent, not
  refused: say so plainly and leave the vocabulary open. Never
  editorialise in a spec document about what this org claims — the
  canon speaks for the org, stele speaks for the mechanism.
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
- **Share the definition, never share the derivation.** Two rules the
  org has applied from opposite directions, stated as one. When two
  legs must agree on what a thing IS — the bytes a digest covers, where
  a version mirror lives — they share the code, so disagreement is
  unrepresentable (the one `chain.SHA256Hex` across emit and verify,
  the .github#434 fix; `internal/manifest`'s one reader across detect,
  preflight and post-write verify). When one leg CHECKS another's work,
  the check must not be the writer inverted — a derivation verified by
  its own inverse passes its own exam (`internal/manifest` re-reads the
  spliced bytes through the reader; it never trusts the splicer's
  bookkeeping).
- **Derived state is refused when stale, never silently repaired.**
  Version mirrors, upgrade scripts, lockfile copies of the version: all
  derived, never typed, and one found already wrong is evidence of a
  broken earlier release. Repairing it in passing destroys that
  evidence (the pgrx `--next.sql` refusal, #374's fuzz-lockfile lint,
  `derive bump`'s drift refusal). Surface, refuse, let a human read the
  wreckage.
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
  as its proof. Not to be confused with the pgrx-extension SBOM
  closure, which #40 built: one derives upgrade SQL, the other an
  inventory, and they share only a word.
- **Badge derivation stays canon — won't-do, recorded at #40.**
  `mise/derive-badges.sh` derives a RENDERING (a README block) whose
  oracle is a text diff; nothing attests it and no verifier consumes
  it. The correct split once `stele level` (#5) lands is that stele
  computes the honest level and the canon renders the badge.
- Commits: conventional, imperative, lowercase, 72-column, DCO
  sign-off; scopes in `committed.toml`. PRs squash-merge through the
  org gate (`ci / ci`).
- Issues: follow the org's mechanism template, which lives in the
  canon (`.github/ISSUE_TEMPLATE/mechanism.yml` there — this repo has
  no copy of its own) — Defect, Decided build, Canon consequence,
  Done when, Sequencing. GitHub applies it only in the web new-issue
  flow, so an issue filed through `gh` or the REST API arrives blank:
  write the five sections by hand.
- Licence: Apache-2.0 (public Go infra convention — patent grant;
  0BSD stays canon-only). REUSE.toml declares; per-file headers are
  refused by design.

## Release

stele self-releases N-1 (version N built and attested by version
N-1, the .github#227 shape) through the canon's `go-binary` class,
live since v0.1.0. Its own versions and notes come from
`stele derive version` / `derive notes` — the tool eats first. The
org-wide replacement landed with the canon cutover (.github#505/#507):
every repository's version and changelog now come from these modes,
and git-cliff has left the belt.

## Testing

`mise run ci` is the gate — the org belt (from the canon pin in
`.github/workflows/ci.yml`) plus this repo's `test`/`build` tasks.
`coverage:check` enforces `.coverage-floor` (ratchet: it only rises).
`mise run audit:go-vulns` is the scheduled advisory scan; network, so
never in the gate.
