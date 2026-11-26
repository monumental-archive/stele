# `derive inventories` golden sets (stele#396)

Each directory is one set. `TestDeriveInventoriesGolden` derives the
set again and compares every document with what the release shipped,
byte for byte, with only `creationInfo.created` and the creator tool's
version masked. It also refuses a derived document the release never
shipped.

| path | content |
| --- | --- |
| `inputs.json` | the publish run's facts: `repo`, `version`, `created`, `name`, `classes`, `evidenceClasses`, `machineryVersion`, `variants`, and `run`, the run the plans came from |
| `assert-policy.json` | the canon's `slsa/assert-policy.json` at the release's pinned canon, carrying each class's `inventory` declaration |
| `plans/<leg>/plan.json[.golden]` | the plan artifacts, as `gh run download <run> -p 'sbom-plan-*'` lays them out (a capture keeps them byte for byte as `.golden`) |
| `cargo/index.json` | a list of `{flags, file}`: each closure selection's cargo flags (`""`, `"--features pg16 --no-default-features"`) and the file holding its metadata |
| `cargo/<file>` | `cargo metadata --format-version 1 --locked <flags>` in the released tree, per selection (a capture keeps it byte for byte as `.json.golden`; biome would refuse a recording past 1 MiB anyway) |
| `shipped/<asset>.golden` | each shipped inventory asset, downloaded from the release and kept byte for byte (the `.golden` suffix keeps formatters off it) |

## Sets

- `interim-generated-not-a-capture` is NOT a capture. Its plans are
  the producer goldens, its metadata is hand-written, and its
  `shipped/` documents were written by this code. It proves the
  harness runs and nothing more; it does not meet the Done-when row.

- The captured set comes from the batch's proof-pass release-lab
  release, captured with one command inside the plan artifacts'
  one-day retention:

  ```sh
  internal/cli/testdata/inventories/capture.sh <publish run id>
  ```

  It writes `release-lab-<version>-run-<id>/`; run `mise run fix:biome`
  after it, so the one policy file it builds takes the org's layout.
  The run's URL goes into `inputs.json`. The assert policy is the
  canon's at the run's pin, with `canon-inventory.json` adding the
  inventory declarations the canon swap commits.
