# The subject manifest

`stele derive subjects` computes the digests a build's provenance
names, against the legs that build's matrix planned (stele#393). It
replaces the canon's "Compute the subject manifest" blocks and the
pgrx images' "Assemble and refuse a partial set" block, and writes the
same bytes they wrote.

```text
stele derive subjects --policy <assert policy> --class <class>
    --expected <file> --dir <dir>
    [--subjects-out <file> --leg-subjects-out <file>]
    [--registry-subjects-out <file>]
```

- `--policy` is the assert policy; `--class` names an entry of its
  `evidence.classes`, and that entry's `subjects` is the shape judged.
  A class the policy does not declare, and a class declared with no
  `subjects`, each refuse by name.
- `--expected` is the planned legs as data: the matrix's JSON list of
  strings, exactly as the build workflow's plan job states it.
  `/dev/stdin` reads it from a pipe. A name pattern is never an
  input.
- `--dir` holds the built assets, or for a registry class the digest
  documents the build legs wrote.
- The flat lines are printed on stdout; each `--*-out` file receives
  its lines as well. Nothing is written for a refused set.

## The class shapes

What one planned leg must leave behind is the class's subject shape,
declared on its assert-policy entry
([assert-policy-schema.md](assert-policy-schema.md), stele#442) and
nowhere else. No class is the engine's: which classes exist and how
their assets are named are one organisation's packaging conventions.
The engine owns the two shape KINDS, because each names a judgment it
computes:

- `files` — a planned entry matching `entry` expands into `assets`,
  each a suffix that exactly one file in `--dir` must end with; the
  leg is labelled by `label`.
- `registry` — each planned leg left one digest file, in the
  class's declared `form`. A `document` names its leg in
  `legField`, beside `image`, `tag` and `digest`, and the leg is
  labelled by that field. A `bare-digest` file holds one digest
  and is named by its leg; it states no image, so it has no subject
  lines and `derive subjects` refuses it. Both forms are read by
  one reader in `internal/release`, shared with any other leg that
  compares what a build pushed.

A class with a naming shape no current kind expresses is new engine
work — a kind — never a flag or a pattern on the command line.

## The lines

- Subjects: `<sha256 hex>  <name>`, one per asset, in name order
  (byte order, which is the runner's C.UTF-8 glob order).
- Leg subjects: `<label> <sha256 hex>  <name>`, in plan order, each
  leg's assets in the shape's `assets` order.
- Registry subjects: `<label> <sha256 hex>  <image>`, in digest
  document name order.

Every line ends in a newline.

## Refusals

Exit 1, with every problem named in one message:

- a planned asset missing or present twice — `expected exactly one
  <noun> for <of> (*<suffix>), found N`, with the names found;
- an asset carrying the class's extension that no leg planned —
  `unplanned <noun> <name>: N <noun>s for M planned <unit>s`, the
  noun being the first asset's;
- an empty plan, a leg planned twice, or a leg the class's pattern
  refuses — `planned <unit> "<entry>" does not match <entry>`, the
  declared pattern itself;
- for a registry class, a leg with no digest, a digest naming a leg
  the plan does not, two documents for one leg, and a document
  missing a field or carrying one it never had — each stating the
  counts as `N image digests for M planned <unit>s`.

Two inputs the shell accepted are refused here: an empty plan (the
shell hashed stdin and signed a subject named `-`) and an image set of
the right size whose majors differ from the plan's (the shell only
counted).
