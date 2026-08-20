# Maintenance and compatibility surface

Versions of this repository follow semver over the surface consumers
actually depend on. A change is **breaking** when a caller of the
previous version breaks by taking the new one with no change of its own
— where "a caller" means a workflow step, a script, or a person running
the binary, never a Go import.

That definition is worth nothing without a referent, and this document
is it. It is held to the binary: `internal/cli/surface_test.go` asks
the dispatch itself which commands it accepts — every verb enumerates
its modes when one is missing, beside the switch that accepts them —
and fails the build if any is missing from the tables below, if any
table row names a command the binary does not dispatch, or if either
disagrees with `stele help`. The document drifted for two releases
before that test existed (stele#146), promising a `verify level` mode
retired at #125 while omitting the entire `assert` verb.

## The command surface

Verb, mode and flag names, and which flags are required. Removing or
renaming any of these is breaking; a new optional flag or a new mode is
a minor. The per-command flags are printed by `stele help`, which is
the same statement as this one and tested against it.

| Command | Owns |
| --- | --- |
| `stele help` | the synopsis: every verb, mode, flag and exit code |
| `stele version` | the build's module version, read back from the binary |
| `stele verify` | published evidence, judged as a stranger would, fail-closed |
| `stele verify release` | every attestation of one release against the pinned signer identity, the verifying-artifacts comparisons, subject coverage, the release decision |
| `stele verify vsa` | the published verdict, as the spec's consumer procedure |
| `stele verify chain` | the source chain: coverage tip→genesis, and the ledger |
| `stele verify repro` | the reproducibility rebuild's typed verdict, one finding per artifact that failed to reproduce |
| `stele verify policy` | one committed policy document run through this engine's own loader, offline: exit 0 if it loads, else the loader's refusal verbatim |
| `stele derive` | facts turned into claims |
| `stele derive version` | the release a history's conventional commits call for, within one tag namespace; `--release-as` declares one instead, judged against the derived base and the names the namespace has taken |
| `stele derive notes` | that release's changelog section, printed or spliced into a file |
| `stele derive bump` | that release's version written into the tree's version mirrors; `--check` asserts them instead |
| `stele derive release-plan` | the release decisions as one document a forge executor runs: version, notes, commit contents, branch, tag; `--prepare` writes the tree it names |
| `stele derive sbom` | an artifact's inventory (SPDX 2.3), or the release view folded from per-artifact documents |
| `stele derive facts` | the OCI image metadata one release asserts on its images |
| `stele derive vex` | this release's coverage document, findings joined to recorded decisions |
| `stele derive claims` | the control claims for one branch, matched by rule content against the forge's live enforcement state |
| `stele derive vex-subjects` | which published releases one VEX decision reaches, and the subjects a claim about it is signed over |
| `stele assert` | evidence against a declaration |
| `stele assert image-facts` | a published image's annotations and labels equal the resolved facts map |
| `stele assert evidence` | every release's declared evidence contract met, every covered subject carrying a store-resident verdict |
| `stele assert blast-radius` | every advisory finding over every published SBOM, joined against the committed VEX decisions |
| `stele assert tags` | every release tag: mint role, signature from the epoch on, a source-chain link on the target |
| `stele assert chains` | a founded, verifying source chain over every protected branch of every repository in the population, or a declared exception |
| `stele assert plans` | pre-publish inventory plans against the same planned obligations the post-publish walk reads, and the judged plan set emitted for the derivation leg |
| `stele assert permissions` | every caller's `permissions:` grant against what the reusable tree it calls requires |
| `stele level` | what a repository's live evidence supports, per track, taking no declaration for a verdict; `--org --out-dir <dir>` with no track publishes the whole board and never over a level already proven |
| `stele level build` | provenance, its authenticity, and the platform's own certificate claims |
| `stele level source` | the source chain measured with no expected identity |
| `stele level dependency` | the DRAFT dependency track, marked draft in every output |
| `stele emit` | the JSON that gets signed |
| `stele emit chain` | source-chain links for the pushed revision and any holes earlier lapses left |
| `stele emit vsa` | the build-track VSA predicate, from a full release verification |
| `stele emit manifest` | the release evidence manifest: the declared contract a stranger reads at the tag |

## Exit codes

A caller distinguishing these depends on them staying put, so changing
a code's meaning is breaking. New codes for new conditions are a minor.
The two that matter most are `1` and `4`: "I found divergence" and "I
could not look" are different answers, and a caller that conflates them
reports a blind run as a clean one.

| Code | Means |
| --- | --- |
| `0` | success — the judgment passed, or the derivation stands |
| `1` | refused — a judgment that found divergence (FAIL), or a derivation that will not stand |
| `2` | usage error — the invocation was wrong |
| `3` | output-stream failure — the work was done and could not be reported, which is never a success |
| `4` | CANNOT_JUDGE — the run could not see enough to judge |

## Machine-readable stdout

Lines a caller is expected to parse rather than read. Changing such a
line's shape is breaking; adding a new one is a minor. Lines meant for
humans go to stderr precisely so they are not part of this promise.

- `key=value` lines from the derive modes — `release=`, `version=`,
  `tag=`, `bump=`, `declared=`, `kind=`, `files=`, `check=` — which the
  canon's release scripts read with `awk -F=`.
- `emit: source revision <sha>`, which the canon's `verify-release.yml`
  reads to state the folded source revision.
- The report document under `--json`, which is a schema of its own
  (below) rather than a line.

## The schemas this tool consumes

Field names, their meanings, and which are required. These files are
the universality boundary — everything org-shaped lives in them and
nothing org-shaped lives in the code — so a repository's committed
policy must keep working across a minor bump. Requiring a new field is
breaking; accepting a new optional one is a minor. Both carry a
`schema` version and refuse a version they do not implement rather
than best-efforting it ([docs/versioning.md](docs/versioning.md)).

| Schema | Spec |
| --- | --- |
| the verify policy | [docs/policy-schema.md](docs/policy-schema.md) |
| the assert policy | [docs/assert-policy-schema.md](docs/assert-policy-schema.md) |
| the inventory plan | [docs/assert-policy-schema.md](docs/assert-policy-schema.md#the-inventory-plan) |
| the build-enrichment predicate | read, never written: the canon's verification control plane signs it |

## The formats this tool emits

The layouts this tool writes and reads back. A verifier that stops
accepting evidence a previous version emitted is breaking, and it
breaks history rather than a build — so this is the surface where a
breaking change costs the most.

| Format | Spec |
| --- | --- |
| the source-chain note (v3) | [docs/chain-format.md](docs/chain-format.md) |
| the VSA predicate | `slsa.dev/verification_summary/v1`, the published spec; its URI is accounted for in [docs/versioning.md](docs/versioning.md) |
| the release evidence manifest | [docs/assert-policy-schema.md](docs/assert-policy-schema.md) |
| the report document (`--json`) | [docs/report-schema.md](docs/report-schema.md) |
| the judged plan set (`assert plans --out`) | [docs/assert-policy-schema.md](docs/assert-policy-schema.md#the-inventory-plan) |
| the release plan (`derive release-plan`) | [docs/release-plan.md](docs/release-plan.md) |
| the shields.io endpoint document (`level --shield`) | [docs/level.md](docs/level.md) |

## Not part of the surface

- **Everything under `internal/`.** It is unimportable by construction;
  that is the point. There is no Go API promise here.
- **Human-facing wording**: diagnostics and log lines on stderr, and
  the prose of the synopsis. Its command, mode and exit-code
  vocabulary is promised above; the sentences describing them are not.
  A caller that greps stderr has taken a dependency this document does
  not grant.
- **Build metadata**: the module version string's exact form, which is
  Go's to decide and is read back from the binary rather than authored.
- **Test fixtures and internal file layout.**

## Release mechanics

Releases run through the org canon: the version and changelog are
derived by this tool from conventional commits, the tag is minted by
the org App on merge of a Release PR, and the binaries are built,
proved reproducible, signed and attested by the canon's `go-binary`
class. Nothing here is released by hand, and no credential lives in
this repository.

Pre-v1, correctness wins every tie: nothing external depends on this
tool yet, so formats and vocabulary change to the correct-by-
construction shape without compatibility shims. 1.0.0 is not a version
number this project drifts into — it is a deliberate statement that
the surface above is stable, set once, by hand, when that is true, and
`derive version --release-as 1.0.0` is how it will be said.
