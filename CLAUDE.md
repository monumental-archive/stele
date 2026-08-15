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
- **assert** — image facts, evidence-bundle completeness, repo-settings
  drift against a committed baseline
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
2. **emit — NEXT, open as #21.** Carries the verify-release.yml and
   source-attest emitter cutovers, the `source-policies/` deletion,
   the structural .github#434 fix, and the re-emission that turns the
   stele/.github chains green. Its non-negotiables are written in the
   issue; do not soften them. **Until it lands, every push to any org
   main mints another broken chain link through the live bash emitter
   (the newline digest defect) — red chains on pushed-to repos are
   CORRECT, and no heal may run through the bash emitter.**
3. **derive and assert — deliberately unopened.** Scope them only once
   emit is underway; their shape depends on what emit leaves behind.
4. **Release wiring (#7) activates after emit** — nothing worth
   shipping as a binary before the emitter is in it.

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
- **Shadow mode is the proof bar.** Ported logic runs beside the bash
  on identical inputs and must byte-match before it becomes
  authoritative; every published release and chain link is a real
  oracle. Nothing is left half-ported as a standing state.
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

## Release (not yet wired — deliberate)

There is no `cliff.toml` and no release/publish stub yet: the
`go-binary` release class does not exist in the canon, and wiring
release machinery before it can release anything would claim what
cannot be verified. Bootstrap sequence when it lands: `go run` from
the pinned toolchain needs no release class at all; the class arrives
with the first shippable subcommand; steady state is N-1 self-release
(version N built and attested by version N-1, the .github#227 shape).
CITATION.cff arrives with `mint-doi: true`, rendered by
`fix:citation`, never hand-filled.

## Testing

`mise run ci` is the gate — the org belt (from the canon pin in
`.github/workflows/ci.yml`) plus this repo's `test`/`build` tasks.
`coverage:check` enforces `.coverage-floor` (ratchet: it only rises).
`mise run audit:go-vulns` is the scheduled advisory scan; network, so
never in the gate.
