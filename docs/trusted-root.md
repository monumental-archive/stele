# Trust material: where a verification's root comes from

Every `stele` verb that verifies needs one Sigstore trusted-root
document. This file defines where those bytes come from, why the
choice is single-valued, and why this repository commits no root of
its own.

Before stele#85 the document was a required file argument, which
meant every caller produced one out of band — in the first
consumer's org, four copies of

```bash
gh attestation trusted-root > "${root}.all"
head -1 "${root}.all" > "${root}"
```

That dance carried two defects: under `pipefail` a pipeline closing
early kills `gh` with SIGPIPE (the failure that killed the first
production `emit vsa` run, .github#438), and `head -1` *guesses*
which line of `gh`'s output is the root. Both are gone: nothing
shells out, and nothing guesses.

## The rule

The origin is decided once per process, from the invocation alone,
by `trust.PlanRoot` — a pure function, so every refusal below is a
table row rather than a runtime surprise.

| invocation | origin |
| --- | --- |
| `--trusted-root PATH` | that document, no network |
| nothing | TUF, at the Sigstore public-good instance, from the anchor pinned in this binary |
| `--tuf-root PATH --tuf-mirror URL` | TUF, at that instance, from that anchor |

Two refusals, and they are the design:

- **A file beside a TUF instance** — two sources named, one root
  wanted. The caller does not know what it is asking for.
- **Half the TUF pair** — an anchor without its instance verifies
  nothing, an instance without its anchor is fetched blind. The pair
  is declared whole or not at all, the same stance every declared
  obligation takes.

There is no fallback ladder. A verifier that tries sources until one
works has no boundary at all, so a failed TUF resolution is a
refusal — never a quiet drop to a cached or embedded document beyond
TUF's own metadata-expiry semantics.

## One parse, one boundary

Both origins return the trusted-root document's **own bytes**. The
TUF path fetches the `trusted_root.json` target and hands those bytes
back; it never returns an already-parsed type. Exactly one function
(`trust.LoadRoot`) turns bytes into trust material, so the file path
and the TUF path cannot diverge in how the document is interpreted.

The TUF path is a bytes-producer, not a second trust path: below the
CLI edge, nothing knows it exists.

## Why no `root.json` is committed here

stele#85 originally scoped a pinned initial root committed in this
repository. That is reversed, on the reasoning that reversed
vendoring:

- sigstore-go already embeds `repository/root.json` for the
  public-good instance and ships it pinned by `go.sum`;
  `theupdateframework/go-tuf/v2` is already in the graph. A copy here
  would be a **version mirror of a file inside a pinned dependency** —
  derived state that goes stale and needs a staleness lint to prove it
  has not, which is the lint arguing for its own deletion.
- The review it would buy is theatre. The only party who can swap the
  embedded anchor is sigstore-go itself, which is already trusted to
  perform the verification. A dependency that would forge the anchor
  would simply not verify.
- TUF root rotation means a pinned anchor chains forward under
  threshold signatures regardless. The security property is the
  signature chain, not the review of the starting bytes.

Updating the anchor therefore stays a reviewed change: it arrives as
a Renovate bump of sigstore-go, through the gate, with `go.sum` as the
review artifact. An operator who wants their own reviewed anchor —
or runs a private Sigstore instance — passes `--tuf-root` and
`--tuf-mirror`. **stele does not commit an anchor; stele accepts
one.**

## The run says what it trusted

`--json` reports carry two facts beside the verdict, never part of
it:

- `trustedRoot` — the origin, rendered: `file <path>`, or
  `tuf <mirror> (anchor pinned in this binary)`, or
  `tuf <mirror> (anchor <path>)`.
- `trustedRootSha256` — the sha256 of the resolved document.

A verification document that does not name its trust material has not
said what it proved, and a verb that reaches the network on an absent
flag must say so out loud. The facts travel with refusals too.

## What is deliberately absent

- **A cache knob.** sigstore-go's default refreshes TUF metadata each
  run; freshness beats speed for a verifier, and the failure mode of a
  stale root is accepting a revoked key. A knob arrives when a
  measurement asks for one.
- **An `--offline` flag.** `--trusted-root` already is one. Two ways
  to say the same thing is one way too many.

## How the TUF path is proven

`PlanRoot` — the decision — is table-tested whole, including both
refusals. `trust.ResolveRoot`'s file origin is table-tested. The
`fetchTUF` body is the network boundary: exercising it means either
reaching the live instance (a network dependency the gate refuses by
law) or standing up a fake TUF repository, which would prove the fake.
`internal/cli`'s test binary fences the network out structurally —
`TestMain` refuses the TUF origin, so a test that reaches it fails
loudly instead of depending on the instance.

It was proven where a network boundary honestly can be: **in shadow
mode against the live instance before the cutover**, at each of the
four call sites the file argument used to have. The criterion is
deliberately *not* byte equality
with `gh attestation trusted-root | head -1`. If TUF and `gh`
legitimately serve different-but-both-valid roots at a given instant,
byte-matching would be transliterating `gh`'s quirks — the
bash-is-reference law applied to `gh` itself. The criterion is that
**both roots verify the same corpus**.
