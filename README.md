# stele

<!-- badges:begin -->
[![ci](https://github.com/monumental-archive/stele/actions/workflows/ci.yml/badge.svg)](https://github.com/monumental-archive/stele/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/monumental-archive/stele/badge)](https://scorecard.dev/viewer/?uri=github.com/monumental-archive/stele)
[![SLSA Build L3](https://img.shields.io/badge/SLSA-Build%20L3-2ea44f)](https://github.com/monumental-archive/.github/blob/main/docs/runbook.md#verifying-as-a-consumer-would)
[![SLSA Source L3](https://img.shields.io/badge/SLSA-Source%20L3-2ea44f)](https://github.com/monumental-archive/.github/blob/main/docs/source-track.md)
[![SLSA Dependencies L2](https://img.shields.io/badge/SLSA-Dependencies%20L2-2ea44f)](https://github.com/monumental-archive/.github/blob/main/docs/dependency-track.md)
<!-- pending (human step): OpenSSF Best Practices — answer the form from docs/best-practices.md, then set 'bestpractices <BP_ID>' in .badge-states and re-run fix:badges -->
<!-- pending (human step): REUSE — register at https://api.reuse.software/register (no account: name, email, project URL, confirmation link), then set 'reuse registered' in .badge-states and re-run fix:badges -->
[![coverage](https://codecov.io/gh/monumental-archive/stele/branch/main/graph/badge.svg)](https://codecov.io/gh/monumental-archive/stele)
[![fair-software](https://img.shields.io/badge/fair--software.eu-%E2%97%8F%20%E2%97%8F%20%E2%97%8B%20%E2%97%8B%20%E2%97%8B-orange)](https://fair-software.eu)
<!-- badges:end -->

A **universal SLSA evidence engine and verifier**. Standard formats in
code — DSSE, in-toto, SLSA provenance and VSAs, OpenVEX, SPDX — with
every organisation-specific convention (signer identities, chain
layout, completeness policy) in a committed policy file the tool
consumes. [monumental-archive](https://github.com/monumental-archive)
is its first conforming consumer, not a hardcoded name.

Four verbs:

| Verb | Owns |
| --- | --- |
| `derive` | versions from conventional commits, SBOM assembly, VEX from triage decisions, image facts |
| `assert` | image facts against claims, evidence-bundle completeness, settings drift against a baseline |
| `emit` | source-chain links, VSA predicates, evidence bundles — the JSON that gets signed |
| `verify` | every attestation against a pinned signer identity, the chain walk, the verdict — and `level`, the honest current level computed from live evidence |

Workflows orchestrate, the platform signs, **stele computes and
checks**. It holds no key, mints no certificate, and never runs caller
code: the capability boundary lives strictly above it.

## Why a stranger would run it

`stele verify` is the org's verification recipe as an executable:
point it at a release and a policy, and it checks what the
documentation says a stranger can check — fail-closed, byte-for-byte
the same data model the emitter used, because verifier and emitter
are one binary sharing one set of types.

## Status

`verify` is authoritative
([#3](https://github.com/monumental-archive/stele/issues/3), closed at
[.github#436](https://github.com/monumental-archive/.github/pull/436)):
release, vsa, chain and level modes shadow-proven against every
published class and both identity worlds, and the canon's source-track
audit runs this binary — the bash walk it replaced is deleted. The
port from the canon's bash
([.github#392](https://github.com/monumental-archive/.github/issues/392))
continues verb by verb under the same bar — shadow mode against real
artifacts before authority — with `emit` next
([#21](https://github.com/monumental-archive/stele/issues/21)). The
gate, lint canon (`golangci-lint` at `default: all`), coverage ratchet
and hermetic build have been live since the first commit.

## Building

```bash
mise trust && mise install && mise run hooks:install
mise run ci
```

Zero external dependencies; `GOPROXY=off` — the build is a pure
function of this tree and the pinned toolchain.

## Licence

Apache-2.0. See [REUSE.toml](REUSE.toml) — per-file headers are
refused by design; the tree-level declaration governs.
