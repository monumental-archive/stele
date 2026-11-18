# stele

<!-- badges:begin -->
[![ci](https://github.com/monumental-archive/stele/actions/workflows/ci.yml/badge.svg)](https://github.com/monumental-archive/stele/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/monumental-archive/stele/badge)](https://scorecard.dev/viewer/?uri=github.com/monumental-archive/stele)
[![SLSA build](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fmonumental-archive%2Fstele%2Flevels%2Fstele%2Fbuild.shield.json)](https://raw.githubusercontent.com/monumental-archive/stele/levels/stele/build.report.json)
[![SLSA source](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fmonumental-archive%2Fstele%2Flevels%2Fstele%2Fsource.shield.json)](https://raw.githubusercontent.com/monumental-archive/stele/levels/stele/source.report.json)
[![SLSA dependency](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fmonumental-archive%2Fstele%2Flevels%2Fstele%2Fdependency.shield.json)](https://raw.githubusercontent.com/monumental-archive/stele/levels/stele/dependency.report.json)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16738/badge)](https://www.bestpractices.dev/projects/16738)
[![OpenSSF Baseline](https://www.bestpractices.dev/projects/16738/baseline)](https://www.bestpractices.dev/projects/16738)
[![REUSE status](https://api.reuse.software/badge/github.com/monumental-archive/stele)](https://api.reuse.software/info/github.com/monumental-archive/stele)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSES/)
[![coverage](https://codecov.io/gh/monumental-archive/stele/branch/main/graph/badge.svg)](https://codecov.io/gh/monumental-archive/stele)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21977176.svg)](https://doi.org/10.5281/zenodo.21977176)
[![release](https://img.shields.io/github/v/release/monumental-archive/stele)](https://github.com/monumental-archive/stele/releases/latest)
[![fair-software](https://img.shields.io/badge/fair--software.eu-%E2%97%8F%20%E2%97%8F%20%E2%97%8B%20%E2%97%8F%20%E2%97%8F-orange)](https://fair-software.eu)
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
| `derive` | versions and changelogs from conventional commits, version-mirror bumps and their drift check (`derive bump --check`, against a stated version with `--expect` and one Cargo package with `--manifest-dir`), per-artifact SBOMs (SPDX) and the inventory plans build legs state, every inventory read or written held to one admissibility rule, VEX from triage decisions (ecosystems and author read from the assert policy, inventories found by its SBOM suffix) and the signing plan for those decisions, OCI image facts, the evidence classes a release request declares (validated and expanded as the assert policy declares), control claims from the forge's live enforcement state, the population every assert target walks (`derive population`) |
| `assert` | evidence against a declaration, over an org or one repo: image facts, evidence-bundle completeness, advisory blast radius against VEX, release tags, chain coverage of the whole population, pre-publish inventory plans against the same obligations the post-publish walk reads, handed inventory documents against the one PURL admissibility rule, the caller/callee `permissions:` join across a workflow tree, and every signer certificate in a transparency log reconciled against a signing the population performed — exit 0 pass, 1 fail, 4 could-not-judge |
| `emit` | source-chain links, VSA predicates, a release tag's signed source verdict (`emit source-vsa`, before the release exists, its policy pinned by commit or by `--policy-ref` as `emit vsa`'s is), the release evidence manifest from the run's own asset directory, bundles and subject lines, the release decision a commit point signs — the JSON that gets signed; chain links in one piece (`emit chain`) or signed apart from the push (`emit chain --no-append`, then `emit chain-append` in a job holding no signing identity) |
| `verify` | every attestation against a pinned signer identity, the published verdict, the source verdict for a release tag, the source-chain walk, and the reproducibility rebuild's typed verdict, before publishing as well as after; for a published release the pins (`--signer-digest`, `--machinery-digest`) are derived from the trees at the tag when absent, through the release workflow the publisher's `--assert-policy` declares, and the subjects, SBOMs and plan (`--subjects`, `--sboms`, `--inventories`) from the release's own evidence given the publisher's `--assert-policy`; and every base a build is about to instantiate, before it does |
| `level` | what a repository's live, publicly fetchable evidence actually supports, per SLSA track — no policy, no trusted root, no declaration taken; it needs `git` and fetches the history itself, with no checkout, no source downloaded and nothing left behind; the board form (`--out-dir`) publishes every cell, and with `--published <dir>` compares the board as published with the one measured, naming each cell that drifts |

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
