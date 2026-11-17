# `derive inventories` golden sets (stele#396)

Each directory is one set. `TestDeriveInventoriesGolden` derives the
set again and compares every document with what the release shipped,
byte for byte, with only `creationInfo.created` and the creator tool's
version masked. It also refuses a derived document the release never
shipped.

| path | content |
| --- | --- |
| `inputs.json` | the publish run's facts: `repo`, `version`, `created`, `name`, `classes`, `evidenceClasses`, `machineryVersion`, `pgMajors`, and `run`, the run the plans came from |
| `assert-policy.json` | the canon's `slsa/assert-policy.json` at the release's pinned canon |
| `plans/<leg>/plan.json` | the plan artifacts, as `gh run download <run> -p 'sbom-plan-*'` lays them out |
| `cargo/index.json` | maps each closure selection's cargo flags (`""`, `"--features pg16 --no-default-features"`) to its file |
| `cargo/<file>.json` | `cargo metadata --format-version 1 --locked <flags>` in the released tree, per selection |
| `shipped/*.spdx.json` | the release's shipped inventory assets, downloaded from the release |

## Sets

- `interim-generated-not-a-capture` is NOT a capture. Its plans are
  the producer goldens, its metadata is hand-written, and its
  `shipped/` documents were written by this code. It proves the
  harness runs and nothing more; it does not meet the Done-when row.
- The captured set comes from the batch's proof-pass release-lab
  release. Its plans are downloaded with one `gh run download` inside
  the artifacts' one-day retention, and its run id is recorded in
  `inputs.json`.
