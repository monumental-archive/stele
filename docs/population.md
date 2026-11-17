# The population document

`stele derive population` prints the population every `assert`
target enumerates (stele#388). The population is the assert policy's
`population` section, or the default predicate where none is declared
([assert-policy-schema.md](assert-policy-schema.md#population)). The
reconciliation against the forge's listing happens once, in
`internal/population`, and this document is read off the set that
reconciliation returns. A caller that needs the population takes it
from here and keeps no second reading of the roster's rules.

```sh
stele derive population --policy assert-policy.json --org example-org
stele derive population --policy assert-policy.json \
  --repo example-org/widget --tracks "build source"
```

## Shape

```json
{
  "schema": 9,
  "owner": "example-org",
  "declared": true,
  "members": [
    {
      "repo": "widget",
      "tracks": ["build", "source", "dependency"],
      "tracksDeclared": false,
      "exclusion": false,
      "visibility": "public",
      "releaseTags": true
    },
    {
      "repo": "lab",
      "tracks": [],
      "tracksDeclared": true,
      "exclusion": true,
      "visibility": "private",
      "releaseTags": false
    },
    {
      "repo": "signer",
      "tracks": ["source"],
      "tracksDeclared": true,
      "exclusion": false,
      "visibility": "public",
      "releaseTags": false
    }
  ],
  "reconciliation": { "undeclared": [], "unlisted": [], "unexercised": [] }
}
```

- `schema` — the live-read document epoch
  ([versioning.md](versioning.md)). The document is generated fresh by
  the run that prints it.
- `declared` — whether the organisation's declaration placed the
  members (`true`) or the default predicate did (`false`): archived
  repositories and forks out, every other listed repository in, on
  every track.
- `members` — in listing order. `tracks` is resolved, in the spec's
  order: a membership that names no tracks resolves to every track
  this release judges, and an exclusion is the empty list.
  `tracksDeclared` says whether the declaration named the tracks. A
  named list that happens to hold every track and the default read
  alike today, and differ the day a track is added: only the default
  reaches it. `exclusion` marks a member bearing evidence on no
  track. It is still listed, so a walk that asks no track question
  still reads it.
  - `visibility` is the forge listing's own word for the repository,
    printed verbatim and never judged. It is absent where no listing
    was read (the `--repo` form) or the listing did not say. The
    roster's own `visibility` is a declaration about coverage, not
    this fact.
  - `releaseTags` says whether the repository carries a tag the
    policy's `tags.tagPattern` selects. That is the definition
    `assert tags` reads, through the same git reader (every tag,
    commits-only, no tree). It is absent when the policy declares no
    `tags` section, and on the `--repo` form, which fetches nothing.
    It is never `false` for "could not see".
- `reconciliation` — always three lists, possibly empty, so an absent
  key is never read as agreement.
  - `undeclared`: listed repositories the declaration does not
    account for.
  - `unlisted`: declared repositories inside the coverage that the
    listing does not show.
  - `unexercised`: declared members outside the declared enumeration
    coverage, which are never members.

## Exit codes

- `0` — the population reconciled and is printed.
- `1` — the roster and the listing disagree. The document is still
  printed, with no members and both directions by name: a run that
  does not know its population has none to print.
- `1` — with `--repo`, the repository's question is refused (below).
- `4` — the listing could not be read, the forge cannot list the
  organisation, or the default predicate admitted nobody. An empty
  answer is a blind read until shown otherwise (stele#69).
- `4` — a member's tags could not be read. The member is named:
  whether it has released is unknown, not no.
- `2` — usage.

## The one-repository question

`--repo owner/name --tracks <list>` answers what a single repository's
caller asks: is it a member, and do the tracks it states equal the
ones the roster declares for it. The tracks may be separated by
spaces, tabs or commas, and are compared in the spec's order. It
refuses, each by name:

- **a repository the declared population does not name** — the
  organisation has not said it bears evidence. With no declaration at
  all, the default predicate admits it on every track, as every
  `--repo` walk does.
- **no tracks stated.**
- **a stated track this release does not judge, or one named twice.**
- **a mismatch**, where the roster names the member's tracks.

A roster that leaves the tracks to the default declares every track,
present and future, so any stated set agrees with it. The caller
narrows what it runs, never what is owed.

On a pass the document is printed with the one member.

## Deliberately absent

- **Whether a repository carries the right workflow files, and the
  obligation table** (`ci`, `audit`, `scorecard`,
  `dependency-review`). The first is wiring (#157). The second is
  house hygiene, not evidence. Both stay with the caller.
