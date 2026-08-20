# stele

<!-- badges:begin -->
[![ci](https://github.com/monumental-archive/stele/actions/workflows/ci.yml/badge.svg)](https://github.com/monumental-archive/stele/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/monumental-archive/stele/badge)](https://scorecard.dev/viewer/?uri=github.com/monumental-archive/stele)
[![SLSA build](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fmonumental-archive%2Fstele%2Flevels%2Fstele%2Fbuild.shield.json)](https://raw.githubusercontent.com/monumental-archive/stele/levels/stele/build.report.json)
[![SLSA source](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fmonumental-archive%2Fstele%2Flevels%2Fstele%2Fsource.shield.json)](https://raw.githubusercontent.com/monumental-archive/stele/levels/stele/source.report.json)
[![SLSA dependency](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fmonumental-archive%2Fstele%2Flevels%2Fstele%2Fdependency.shield.json)](https://raw.githubusercontent.com/monumental-archive/stele/levels/stele/dependency.report.json)
<!-- pending (human step): OpenSSF Best Practices — answer the form from docs/best-practices.md, then set 'bestpractices <BP_ID>' in .badge-states and re-run fix:badges -->
<!-- pending (human step): REUSE — register at https://api.reuse.software/register (no account: name, email, project URL, confirmation link), then set 'reuse registered' in .badge-states and re-run fix:badges -->
[![coverage](https://codecov.io/gh/monumental-archive/stele/branch/main/graph/badge.svg)](https://codecov.io/gh/monumental-archive/stele)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21977176.svg)](https://doi.org/10.5281/zenodo.21977176)
[![fair-software](https://img.shields.io/badge/fair--software.eu-%E2%97%8F%20%E2%97%8F%20%E2%97%8B%20%E2%97%8F%20%E2%97%8B-orange)](https://fair-software.eu)
<!-- badges:end -->

A **universal SLSA evidence engine and verifier — and the release
engine that produces the evidence**. Both halves in one binary is
the point. It derives what a release ships (the version and
changelog from conventional commits — it retired git-cliff across
its home org — version-mirror bumps, per-artifact SBOMs, VEX),
emits the attestable JSON that gets signed, and then verifies that
evidence the way a stranger would, fail-closed: the thing that makes
a release and the thing that judges it share one set of types, so
neither can drift from the other. Standard formats live in code —
DSSE, in-toto, SLSA provenance and VSAs, OpenVEX, SPDX — with every
organisation-specific convention (signer identities, chain layout,
completeness policy, what a release owes) in a committed policy file
the tool consumes.
[monumental-archive](https://github.com/monumental-archive) is its
first conforming consumer, not a hardcoded name.

Four verbs and a judge:

| Command | Owns |
| --- | --- |
| `derive` | versions and changelogs from conventional commits, version-mirror bumps, per-artifact SBOMs (SPDX), VEX from triage decisions, OCI image facts, control claims from the forge's live enforcement state |
| `assert` | evidence against a declaration, over an org or one repo: image facts, evidence-bundle completeness, advisory blast radius against VEX, release tags, chain coverage of the whole population, pre-publish inventory plans against the same obligations the post-publish walk reads, and the caller/callee `permissions:` join across a workflow tree — exit 0 pass, 1 fail, 4 could-not-judge |
| `emit` | source-chain links, VSA predicates, the release evidence manifest — the JSON that gets signed |
| `verify` | every attestation against a pinned signer identity, the published verdict, the source-chain walk, and the reproducibility rebuild's typed verdict |
| `level` | what a repository's live, publicly fetchable evidence actually supports, per SLSA track — no clone, no policy, no trusted root, no declaration taken |

Workflows orchestrate, the platform signs, **stele computes and
checks**. It holds no key, mints no certificate, and never runs caller
code: the capability boundary lives strictly above it.

The tool eats first. Its own releases run entirely through it —
version and notes from `derive`, evidence from `emit`, each release
built and attested by the version before it, and the published
result verified by the same walk it asks of everyone else.

## Why a stranger would run it

Day one is one flag:

```bash
stele level --repo you/yours
```

It measures and reports; it gates nothing. From there, `stele verify`
is the verification recipe as an executable: point it at a release
and a policy, and it checks what the documentation says a stranger
can check — fail-closed, byte-for-byte the same data model the
emitter used, because verifier and emitter are one binary sharing one
set of types. Adopting it in a repository with no org behind it is
[docs/adoption.md](docs/adoption.md), whose minimal policies the test
suite executes.

## Status

stele began as the port of ~8,000 lines of release and audit bash in
its first consumer's org
([.github#392](https://github.com/monumental-archive/.github/issues/392)).
The port is **complete**: all four verbs plus `level` shipped verb by
verb under one bar — shadow mode against real artifacts before
authority — and every release and evidence-judging audit there now
runs this binary. The formats are pre-v1: correctness wins every tie,
and schemas change to the correct shape without compatibility shims.
The gate, the lint canon (`golangci-lint` at `default: all`),
coverage ratchet and hermetic build have been live since the first
commit.

## Documentation

[docs/adoption.md](docs/adoption.md) is the front door for anyone who
is not us — day one, the delivery layer, the policy floors (executed
by the test suite), the real couplings, what to skip. The rest of
[docs/](docs/) specifies mechanisms: the
[verify policy](docs/policy-schema.md) and
[assert policy](docs/assert-policy-schema.md) schemas, the
[chain note format](docs/chain-format.md), the
[report document](docs/report-schema.md) every judging verb speaks,
[how `level` judges](docs/level.md), the
[VEX join's identity rules](docs/vex-join.md), the
[trust anchor stance](docs/trusted-root.md),
[versioning](docs/versioning.md) and the
[binary SBOM design](docs/binary-sbom.md). `stele help` carries the
full flag reference.

## Building

```bash
mise trust && mise install && mise run hooks:install
mise run ci
```

Dependencies are pinned by `go.sum` — byte-identical modules or a
failed build — and fetched through the checksummed proxy, the one
network dependency in the gate. Everything else is a pure function of
this tree and the pinned toolchain: `CGO_ENABLED=0`,
`GOTOOLCHAIN=local`, `-trimpath`, and no committed `vendor/` by
[deliberate decision](CLAUDE.md).

## Licence

Apache-2.0. See [REUSE.toml](REUSE.toml) — per-file headers are
refused by design; the tree-level declaration governs.
