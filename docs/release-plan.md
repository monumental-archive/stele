# The release plan: the decisions a forge executor runs

`stele derive release-plan` emits one JSON document carrying every
decision a release cycle makes — the version, the notes, the commit's
contents, the branch it lands on, the tag that follows — so the leg
that talks to the forge creates what the plan names and improvises
nothing.

It exists because the org's release scripts were classified as
orchestration for being shaped like shell (stele#155). By the port's
own test they were not: staging a branch is orchestration, but
deciding which files a release commit carries, whether the tree's
state permits a release at all, and what the tag may be called is
engine work — and it was spread across three bash files that each
re-derived what the others knew. The version was read from a `git
describe` in one, a manifest in another, and a commit subject in the
third; three readings that agreed until they did not.

What deliberately does **not** move here: signing, token capability,
the job graph, the OIDC grants. The plan is JSON, not capability
(.github#392's "not signing / not workflows" boundary is untouched).

## Three properties

**It is safe to compute twice.** Assembling reads; nothing in it
writes. `--prepare` writes the tree the plan names — the version
mirrors, and the changelog section when `--changelog` is given — and
that preparation is the plan's own file list applied, never a second
reading of the tree. So the leg that prepares and the leg that commits
cannot disagree about what was prepared, and a later leg (the one that
mints the tag) can recompute the same plan without touching anything.

**The changelog is judged on every run.** The splice `--prepare` would
write is computed on the plain run too — the same read and the same
duplicate guard, without the write — and a splice the prepare leg
would refuse refuses here as well, with the same message and the same
exit 1 (stele#261). A plan is a claim about what the prepare leg will
do, so `release: true` over a splice that leg cannot perform is a
false claim, and a gate running the plain derive would otherwise pass
green on a tree whose release burns after the merge. The judgement
lands before the document is placed, so nothing is ever emitted
describing an edit to a changelog state this refuses — including the
`deletions` entry a plan once carried for a changelog the tree does
not have.

**A refused plan is a document saying why.** A tree state that forbids
the release produces a plan carrying `refusals` and no instructions —
no commit, no branch, no tag — so an executor cannot half-run it. The
process still exits 1: the document is for the reader, the exit code
for the caller.

The two are different questions and get different answers: an input
that makes a plan impossible to STATE (an unreadable tree, a subject
template naming no version) is an error with no document, while a tree
state that forbids the release is a document. "I cannot say" and "the
answer is no" are not the same answer.

## Wire shape

One JSON object, one trailing newline. Absent sections mean absent
decisions.

```json
{
  "schema": 4,
  "release": true,
  "version": "0.16.0",
  "base": "0.15.0",
  "tag": "v0.16.0",
  "bump": { "applied": "minor", "requested": "minor", "declared": false },
  "notes": "## [0.16.0](…) - 2026-08-20\n\n### Added\n\n- …\n",
  "commit": {
    "subject": "chore: release v0.16.0",
    "additions": ["CHANGELOG.md", "CITATION.cff", "Cargo.lock", "Cargo.toml"],
    "deletions": ["sql/ext--0.15.0--next.sql"]
  },
  "branch": { "name": "release/next", "staging": "release-staging/next" }
}
```

- `schema` — the document epoch every stele document carries
  ([versioning.md](versioning.md)).
- `release` — whether this range releases anything. A quiet range is a
  plan with `release: false` and no refusals: the range said so, and
  the executor's one correct action is none.
- `version`, `base`, `tag` — the release being cut, the one it is
  measured from, and the tag name in the namespace `--tag-prefix`
  names. All three from the one shared version decision, so no leg
  re-derives any of them.
- `bump.applied` / `bump.requested` — what moved, and what the range
  voted for. They differ when the 0.x rule absorbed a break into the
  minor, or when a human declared the number.
- `bump.declared` — whether `--release-as` chose this version
  (stele#146). A release nobody derived is a different fact from one
  the range called for, and a reader shown only the number cannot tell
  them apart.
- `notes` — the changelog section, rendered once. The section spliced
  into the changelog and the body a release is published with are this
  one string, so the text a reviewer approves and the text that ships
  cannot be two renderings of the same range made at different
  moments.
- `commit.subject` — the `--subject` template with `{version}`
  substituted. The tag leg compares a candidate commit's subject
  against this rendering, so one template decides both the writing and
  the checking.
- `commit.additions` / `commit.deletions` — the release commit's
  contents, tree-relative and sorted. A path the release names and the
  tree no longer has is the old half of a rename, and it rides as a
  deletion: classifying it at execution time would put the decision
  with whoever happens to be holding the file list. An absolute path,
  or one that climbs out of the tree, is refused — a commit carries
  tree-relative files by definition.
- `branch.name` / `branch.staging` — where the commit lands, and the
  disposable ref it is built on. The staging ref exists because the
  release branch must never momentarily equal the default branch: a
  pull request whose diff is empty is closed by the forge, which
  churns the number and discards the review thread.

The commit's **sign-off is deliberately absent**. It names an identity
only the executing token knows (an App installation's bot user), so
composing it here would be this tool asserting a fact about a
credential it does not hold. The pull request's **body** is absent for
the same reason in reverse: it is org prose, and the canon speaks for
the org.

### A refused plan

```json
{
  "schema": 4,
  "release": false,
  "refusals": [
    { "cause": "mirror-drift", "detail": "the mirrors carry \"0.14.7\" but the last release is 0.15.0 …" }
  ]
}
```

| cause | the state, and what it would burn |
| --- | --- |
| `mirror-drift` | the version mirrors carry neither the last release nor the one being cut. A mirror that moved on its own is evidence of a broken earlier release; surfaced, never overwritten. |
| `tag-taken` | the namespace already carries this version. The base is the highest version *reachable* from the ref, so a maintenance branch can derive a name another line already published — and a tag is an immutable name. |

## Flags

`stele derive release-plan --git-dir <tree>` takes the version flags
every derive mode of this family takes (`--ref --tag-prefix --paths
--minor-types --silent-types --zero-major-bumps-minor --release-as`),
the notes flags (`--groups --group-order --breaking-group
--compare-url --release-url --pull-url --date --changelog`), and its
own:

| flag | what it declares |
| --- | --- |
| `--branch` | the branch the release commit lands on. One branch, never one per version: keying it on the computed version opens a second pull request whenever the bump moves, and abandons the first. |
| `--staging` | the disposable ref the commit is built on. |
| `--subject` | the release commit's subject template, carrying `{version}`. |
| `--also` | further files the release commit carries — the lockfiles an ecosystem's own derivation refreshes beside the mirrors. Declared, never guessed. |
| `--prepare` | write the tree the plan names. Off by default: a plan states, and the caller asks for the writing. |
| `--out` | where the document goes; empty prints it to stdout. |

Every value above is an org convention, which is why every one is a
flag: a branch name or a subject line in this tool's code would be one
organisation's release shape made unclaimable by every other.

## What the executor still does

Everything that is an API call and nothing that is a decision: create
or move the staging ref, build the commit through the forge's own
commit API (so it is signed by the forge rather than unsigned by a
runner), verify that signature, move the release branch in one step
from its old release commit to the new one, open or update the pull
request, and — after the merge — check the candidate commit's subject
against `commit.subject`, mint and push the tag, and create the draft
release with `notes` as its body.

An honest limit, recorded: bash executing a plan can still deviate
from it. This is correct-by-smaller-surface, not correct-by-
construction. The fully correct shape — the engine executing its own
plan — is a separate question (stele#157), and this document is
deliberately compatible with either answer: every decision that is
data here is one a future executor does not re-derive.
