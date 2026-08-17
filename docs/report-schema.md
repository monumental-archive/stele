# The report document: the shared verdict shape

The JSON document every judging verb emits — `stele verify --json`
today; `assert` and `level` will speak it next, and `assert` will also
consume it. One shape for producer and consumer is the single-binary
argument (.github#392 §7) applied to output: the verb that asserts
"this verifies" reads the same document the verifier wrote.

The model lives in `internal/report`; the sealed constructor is the
spec's enforcement. This file records the wire shape and the three
laws it encodes, so a schema change is a reviewed edit here first.

## The three laws (types, not discipline)

1. **Population**: a run that judged zero subjects cannot report
   `PASS` — it reports `CANNOT_JUDGE`. A population always names how
   the subject set was obtained (`evidence`, `listing`, `declared`),
   because "what a narrowed credential happened to show" and "the
   declared population" are different claims. A `declared` population
   that mismatches its expectation in either direction is
   `CANNOT_JUDGE`: an unseen subject is unchecked, not clean; a
   surplus one means the declaration is stale.
2. **Canary**: a run that declares a known-positive and does not
   reproduce it cannot see, and reports `CANNOT_JUDGE` regardless of
   everything else it found.
3. **Exceptions**: `declared` exceptions come only from a committed
   file a human edited under review; `derived` exceptions come only
   from engine logic and name their evidence. A declared exception
   matching no finding is reported under `staleExceptions` — a
   retirement candidate, never silently carried.

`FAIL` and `CANNOT_JUDGE` are distinct verdicts because "I found
divergence" and "I could not look" must never be conflated by a
caller. Process exit codes are the CLI's business, not the
document's.

## Wire shape

One JSON object, one trailing newline. Optional fields are absent,
never null.

```json
{
  "target": "verify vsa",
  "subject": "acme/widget@v1.2.3",
  "verdict": "PASS | FAIL | CANNOT_JUDGE",
  "population": {
    "size": 3,
    "expected": 4,
    "source": "evidence | listing | declared",
    "detail": "release subjects"
  },
  "canary": { "key": "RUSTSEC-2021-0127", "seen": true },
  "facts": [ { "name": "verifiedLevels", "value": "SLSA_BUILD_LEVEL_3" } ],
  "findings": [
    {
      "subject": "app.tar.gz",
      "assertion": "vsa",
      "expected": "…",
      "actual": "…",
      "detail": "…"
    }
  ],
  "excused": [ { "finding": { "…": "…" }, "exception": { "…": "…" } } ],
  "staleExceptions": [
    { "kind": "declared | derived", "subject": "…", "assertion": "…", "origin": "debt.txt:3" }
  ]
}
```

- `target` — the judging mode that produced the document.
- `subject` — what was judged, as the mode names it.
- `population.expected` — present only for `declared` populations.
- `canary` — present only when a canary was declared.
- `facts` — information beside the verdict (a computed level, a
  source revision, a link count), never part of the judgment.
- `findings` — the unexcused divergences. Under `CANNOT_JUDGE`,
  findings gathered before sight was lost are still carried: partial
  sight is reported, never laundered into either verdict.
- `excused` — every excused finding beside the exception that excused
  it; an excuse is visible, never a deletion.

## What `verify --json` puts in it

| mode | population | facts |
| --- | --- | --- |
| `release` | release subjects (manifest size) | `sourceRevision` |
| `vsa` | release subjects (manifest size) | `verifiedLevels` |
| `chain` | the one branch ref under walk | `links` |
| `level` | the one branch ref under walk | `links`, `sourceLevel` |

A refusal seals as `FAIL` over the declared population with the
engine's message as the finding; a refusal before any population
existed (an empty subject manifest) seals as `CANNOT_JUDGE` by law 1.
With `--json` the progress lines move to stderr so stdout carries
exactly one document; the exit code contract is unchanged.

## Deliberately absent

A decoder. A consumer that trusts a `verdict` field it did not
compute would let a tampered document outrank the evidence; when
`assert` consumes reports it re-seals from parts, so a forged `PASS`
is unrepresentable there too.
