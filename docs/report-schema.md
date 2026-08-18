# The report document: the shared verdict shape

The JSON document every judging verb emits — `stele verify --json`
today, `assert` and `level` too, and `assert` will also
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
  "schema": 4,
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

- `schema` — the document's version identifier, stamped on every
  encode. Refusal boundary: a consumer reading a schema it does not
  implement refuses; it never best-efforts a newer one. When it moves
  is governed by [docs/versioning.md](versioning.md) — added at
  stele#107, before the second consumer arrived, because a format
  acquires the ability to break someone at exactly that moment.
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
| `vsa` | release subjects (manifest size) | `verifiedLevels`, `sourceRevision` |
| `chain` | the one branch ref under walk | `links` |

## What `stele level --json` puts in it

One report per track (`docs/level.md`). The population is the
subjects or branches **with a determinable ladder**, so a track that
lost sight at its boundary is short-covered and seals `CANNOT_JUDGE`
through the coverage law rather than through a second rule.

| track | population | facts |
| --- | --- | --- |
| `build` | latest release's subjects | `level`, `ceiling`, `declared`, `weakest`, `ladder`, `specStatus`, `sealedAt`, `sourceRevision` |
| `source` | the one protected branch | `level`, `ceiling`, `declared`, `weakest`, `ladder`, `specStatus`, `sealedAt` |
| `dependency` | the release's shipped artifacts | `level`, `declared`, `ladder`, `specStatus`, `sealedAt` |

- `level` — the computed scalar, in the spec's `SlsaResult`
  vocabulary.
- `ceiling` — the maximum `slsaRootsOfTrust` permits for the
  attester, absent when no map entry applied.
- `declared` — the policy's target, absent when the policy claims
  nothing on that track.
- `ladder` — each level and its determination, e.g.
  `1:HELD 2:HELD 3:UNDETERMINED 4:UNCLAIMED`. A level with no account
  of how it was reached is a number, not a judgment.
- `specStatus` — `approved` for build and source, `draft` for
  dependency. The dependency track is not part of SLSA v1.2 and every
  output that carries its level says so.
- `sealedAt` — when the judgment was made, RFC 3339. The document
  states an instant; what counts as *stale* is the consumer's
  declaration, and a tool that judged its own output's age would be
  asserting an org convention.

`--shield <path>` writes a shields.io endpoint document beside the
report, from the same seal. There is deliberately no decoder from a
report document back into a report, so a render that parsed one could
be handed a forged verdict; both documents leave one seal instead.

Every mode also carries `trustedRoot` and `trustedRootSha256` — the
origin of the trust material this run held and the sha256 of the
document it resolved to (`docs/trusted-root.md`). They travel on
refusals too: a verification document that does not name its trust
material has not said what it proved, and a verb that resolves a root
over the network on an absent flag must say so out loud. `assert`'s
reports carry the same two whenever the walk had a cryptographic
half.

`vsa`'s `sourceRevision` is present only where the policy declares
`build.enrichment`: the commit the release was built from is a claim
the enrichment carries and a bare verdict does not.

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
