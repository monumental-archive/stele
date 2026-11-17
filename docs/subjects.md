# The subject manifest

`stele derive subjects` computes the digests a build's provenance
names, against the legs that build's matrix planned (stele#393). It
replaces the canon's "Compute the subject manifest" blocks and the
pgrx images' "Assemble and refuse a partial set" block, and writes the
same bytes they wrote.

```text
stele derive subjects --class <class> --expected <file> --dir <dir>
    [--subjects-out <file> --leg-subjects-out <file>]
    [--registry-subjects-out <file>]
```

- `--expected` is the planned legs as data: the matrix's JSON list of
  strings, exactly as the build workflow's plan job states it.
  `/dev/stdin` reads it from a pipe. A name pattern is never an
  input.
- `--dir` holds the built assets, or for a registry class the digest
  documents the build legs wrote.
- The flat lines are printed on stdout; each `--*-out` file receives
  its lines as well. Nothing is written for a refused set.

## The class definitions

What one planned leg must leave behind is the release contract's own
definition, in `internal/release`, and nowhere else:

| class | planned entry | assets per leg | leg label |
| --- | --- | --- | --- |
| `go-binary`, `rust-binary` | a target | `*-<target>.tar.gz` | the target |
| `pgrx-extension` | `<major>-<arch>` | `*-pg<major>-linux-<arch>.tar.gz` and `*-pg<major>-linux-<arch>-debug.tar.gz` | the major |
| `pgrx-extension-image` | a major | one digest document (`pg`, `image`, `tag`, `digest`) | the major |

A class absent from this table has no subject definition yet; adding
one is adding a row.

## The lines

- Subjects: `<sha256 hex>  <name>`, one per asset, in name order
  (byte order, which is the runner's C.UTF-8 glob order).
- Leg subjects: `<label> <sha256 hex>  <name>`, in plan order, each
  leg's assets in the table's order.
- Registry subjects: `<label> <sha256 hex>  <image>`, in digest
  document name order.

Every line ends in a newline.

## Refusals

Exit 1, with every problem named in one message:

- a planned asset missing or present twice — `expected exactly one
  <kind> for <leg> (*<suffix>), found N`, with the names found;
- an asset carrying the class's extension that no leg planned —
  `unplanned <kind> <name>: N <kind>s for M planned <unit>s`;
- an empty plan, a leg planned twice, or a leg not shaped for its
  class;
- for a registry class, a major with no digest, a digest naming a
  major the plan does not, two documents for one major, and a
  document missing a field or carrying one it never had — each
  stating the counts as `N image digests for M planned majors`.

Two inputs the shell accepted are refused here: an empty plan (the
shell hashed stdin and signed a subject named `-`) and an image set of
the right size whose majors differ from the plan's (the shell only
counted).
