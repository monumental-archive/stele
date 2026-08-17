# The binary-derived release SBOM

`stele derive sbom <binary>...` reads the module list the Go toolchain
embedded into each shipped binary at link time (`debug/buildinfo`, the
data `go version -m` prints) and renders one SPDX 2.3 document for the
release. This is the `go-binary` class's SBOM source (#46), replacing
the source-tree scan plus version-stamping stopgap
(monumental-archive/.github#476).

## Why the binary, not the tree

- **It describes what shipped.** A 1.17+ `go.mod` lists the whole
  module graph; the embedded list is the modules actually linked into
  the artifact. A tree scan over-claims.
- **The version is read out of the artifact.** The toolchain stamps
  the main module's version from the release tag when building a clean
  checkout of the tagged commit. The pipeline's belief about the
  version is only a cross-check (`--expect-version`), never the
  source — the stopgap's defect (stamping every module root with the
  release version, wrong for any multi-module repo with independent
  tags) is unrepresentable here.
- **Same evidence shape the org already trusts** for Rust images via
  cargo-auditable's `.dep-v0` section.

## One document, many legs

A release ships one binary per platform (GOOS × GOARCH), and the
linked module sets may legitimately differ — platform-conditional
imports pull platform-conditional modules. The release SBOM is the
**union** of the legs' inventories:

- Facts the legs must share — main module path and version,
  `vcs.revision`, `vcs.time` — are asserted equal across every leg.
  Divergence means the legs were not built from one source: refused,
  never merged.
- One module at two versions across legs is refused for the same
  reason — one `go.mod` resolves each path to exactly one version for
  every platform.
- A module linked into only some legs is recorded with
  `sourceInfo: "linked into: <platforms>"`, so the union never
  silently over-claims per-artifact.
- Several binaries per platform are legitimate — one module can hold
  several main packages, and each ships for every leg. What is refused
  is the same command twice on one platform: the same file handed in
  twice, or two builds of one thing.

## Refusals (all fail-closed)

- Main version absent, `(devel)`, or not a semantic version — the
  binary was not built from a clean checkout of a tagged commit, so
  the artifact cannot name its own version.
- No VCS stamp (`-buildvcs=false`, or built outside a checkout).
- `vcs.modified` anything but `false` — bytes matching no commit are
  not attestable.
- A dependency without a published module version (a directory
  `replace`).
- `--expect-version` given and disagreeing with the binaries — the
  build checked out something other than the tag being published.

## Document shape

SPDX 2.3. The root package is the main module
(`primaryPackagePurpose: APPLICATION`); each linked module is a
`LIBRARY` the root `DEPENDS_ON`. Every package carries exactly one
purl, `pkg:golang/<module path, lowercased>@<version>` — lowercasing
is the purl golang type's rule; the SPDX package `name` keeps the
module path's true case. Replaced modules are recorded as their
replacement — the code actually linked.

Deterministic by construction: `created` is `vcs.time` (never a wall
clock), packages are sorted (root first, then by path), identifiers
assigned in that order, and the document namespace derives from
name + revision. The same binaries render the same bytes in any
argument order.

## What this deliberately does not cover

Build-time tooling and unlinked graph entries. The scheduled
source-graph scan (`audit:go-vulns`) keeps watching the full module
graph; the release SBOM's job is the artifact.
