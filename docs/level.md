# The level verb: what the evidence supports

```text
stele level source --repo acme/widget
stele level build --org acme
stele level dependency --repo acme/widget
```

One flag, and it names the subject. No clone, no policy file, no
trusted root, no evidence-layout declaration. Point it at a repository
and it answers, and a stranger pointing at the same repository gets the
same answer.

That is the whole design goal, and everything below follows from it:
**a level is not a number an organization writes down and this tool
repeats back.** It is a set of requirements the specification states,
each one either established from evidence or not.

## The spine: requirements, not declarations

`internal/level/requirements.go` carries every requirement SLSA states,
at the level SLSA places it, in the specification's own words. That
file is the tool's spine, and it is closed:

- no policy adds a requirement, removes one, or moves one to a
  different level
- no policy redefines what a level means
- an organization that wants Source Level 4 does not declare Level 4;
  it enforces two-party review, and the tool finds it

A level holds when every requirement at it and below is established.
The scalar is the highest level whose rungs all hold — the spec's own
cumulative rule, where each level implies those below it.

`Assess` takes a track and evidence. There is no target parameter, no
declared floor, no property list: **there is nowhere to write the
answer down**, which is what makes the measurement worth reading.

### The identifiers are the ecosystem's

The source track's requirement IDs are the control names the SLSA
source proof-of-concept defines — the SCS implementation the
specification itself points at — not names this tool invented:

```text
SLSA_SOURCE_ORG_SCS              SLSA_SOURCE_SCS_REPO_ID
SLSA_SOURCE_ORG_ACCESS_CONTROL   SLSA_SOURCE_SCS_REVISION_ID
SLSA_SOURCE_ORG_SAFE_EXPUNGE     SLSA_SOURCE_SCS_DIFF_DISPLAY
SLSA_SOURCE_ORG_CONTINUITY       SLSA_SOURCE_SCS_VSA
                                 SLSA_SOURCE_SCS_HISTORY
                                 SLSA_SOURCE_SCS_CONTINUITY
                                 SLSA_SOURCE_SCS_IDENTITY
                                 SLSA_SOURCE_SCS_PROVENANCE
                                 SLSA_SOURCE_SCS_PROTECTED_REFS
                                 SLSA_SOURCE_SCS_TWO_PARTY_REVIEW
```

A consumer with its own dialect can only read chains it issued
itself, and that is the opposite of universal. The build and
dependency tracks have no such ecosystem vocabulary yet, so they keep
this tool's identifiers until one exists.

Control names are matched on their meaningful tail, because the
specification requires an SCS to prefix organization-specified
properties and leaves the prefix to the SCS: one control plane writes
`SLSA_SOURCE_ORG_ACCESS_CONTROL` where another writes
`ORG_SOURCE_ACCESS_CONTROL` for the same control.

## Detection, and the three determinations

Each requirement has a detector that computes it from evidence anyone
can fetch — the forge, the attestation store, the released artifacts,
the certificates. A detector returns one of three things:

| | meaning |
| --- | --- |
| `HELD` | the evidence establishes this requirement |
| `REFUTED` | the evidence contradicts it |
| `UNDETERMINED` | the evidence needed was not reachable in this run |

A held requirement is additionally marked **attested** when it rests
on a contemporaneous RECORD rather than on something this tool
recomputed. For the control requirements a contemporaneous record is
the *only* evidence that can exist — which controls were configured
when a revision landed is unrecoverable afterwards, since a rules API
answers about now — and that is exactly why the specification asks the
SCS to record them at the time.

But a chain link is emitted and signed by the repository's **own**
workflow, and a record a subject issues about itself is a claim.
Holding a level on it alone would let any repository mint its own —
self-attestation wearing a signature, the exact defect this verb
exists to refuse. So an attested outcome has exactly one constructor
(`RecordHeld`), and it demands two halves:

- the **record**: the control named in the tip link, contemporaneous
  with the revision;
- the **corroboration**: the forge's own live rules for the branch —
  the platform speaking about its own enforcement, which no tenant can
  forge — showing the control enforced now.

The tip *is* now, so for the revision under judgment the two halves
cover each other's blind spot: the record supplies contemporaneity,
the live answer supplies independence. A record with no readable live
half, or one the live rules do not back, is `UNDETERMINED` — never
held, and not refuted either, because rules legitimately change
between a revision landing and this run looking. A future detector
cannot reintroduce self-attestation without deleting the constructor.

A requirement with **no detector in this build** is `UNDETERMINED`, and
the report names it. That is a statement about the tool's coverage, not
about the world — the alternative is a level that holds because nobody
looked. `requirementCoverage` in every report says how many of a
track's requirements this build can establish.

Refuted outranks undetermined when folding a level: evidence that
contradicts a requirement settles it, while evidence merely missing
does not.

**A level is an at-least claim.** Blindness above an established rung
does not unseat the answer: level 2 with level 3 unreadable IS level 2,
and the report carries a `boundary` fact saying the level is a floor.
Only a ladder that lost sight before any rung held determines nothing —
there the report seals `CANNOT_JUDGE`, because a level-zero answer must
mean "measured, and no level holds", never "nobody could look".

A refuted requirement above the level is **not a finding** — with no
declaration in sight, nothing has diverged. It is the boundary
explanation, recorded in the facts with the specification's own words.
Findings are reserved for a declared level the evidence disagrees
with.

## What the certificate proves

The build track leans on the signing certificate, and it is worth being
explicit about why that is evidence rather than a claim.

A Fulcio certificate carries the OIDC claims the build platform's own
issuer minted for that run. `runner_environment` is the platform
stating which kind of machine it ran the build on. `build_signer_uri`
and `build_signer_digest` name the exact reusable workflow that held
the signing capability, at a commit. These are statements the platform
makes about its own execution and signs; a tenant cannot forge them
without forging the certificate chain, which is what the trust root
exists to stop.

So requirements that read like assessment questions turn out to be
detectable:

- **`build/isolated`** — a hosted runner is provisioned per job and
  destroyed after it. The platform's own claim that the run was hosted
  is the isolation evidence.
- **`build/unforgeable`** — the certificate names the workflow that
  held the signing key. Fetch that workflow at that commit and check it
  executes no caller-controlled step. That is the capability boundary,
  proven from two fetches.

The runner-environment vocabulary is a **table of platform knowledge**
(the same shape as the buildType parameter schemas): known hosted
values hold, known tenant values refute, and a value from a platform
the table has not met is `UNDETERMINED` — refuting it as "the tenant's
machine" would punish every platform this tool's author had not seen.

One honest limitation, stated rather than papered over: the boundary
check reads what the signing workflow's text *expands* (`run:` bodies
and `uses:` resolutions). A workflow that checks out the caller's
repository and executes a script from that tree runs tenant code in a
way no text-level read of the workflow alone can prove or refute; the
check is precise about interpolation and silent about that shape.

`SLSA_SOURCE_ORG_SAFE_EXPUNGE` has the same shape from the other
direction: git has no expunge operation, so content leaves a branch
only by force push. Where the chain proves the branch moved only to
descendants, expunging did not happen and had no path to happen. The
SLSA source proof-of-concept establishes it the same way.

What the platform assessment establishes is trust in the *platform*.
What the certificate establishes is that this artifact was built by it,
in the configuration the assessment covers. Those are different
questions and only the second is this verb's.

## The source chain proves more than it contains

Each chain link records its predecessor and the digest of that
predecessor's stored bytes, and the walk refuses a chain that skips a
revision or fails to reach its genesis.

So a chain that walks clean from tip to genesis is a cryptographic
record that the branch only ever moved to descendants of where it was
— which is `source/history`, the no-force-push requirement, established
from artifacts rather than from a settings read. A branch reset to a
revision that did not descend from its predecessor would orphan the
discarded links and the walk would refuse.

The measurement walk (`verify.MeasureChain`) asserts **no identity**.
It proves each link cryptographically, reads who signed from the
certificate, and reports it. The gating walk (`verify.Chain`) demands a
declared identity, which is right for a release gate and wrong for a
measurement: being handed the answer is how a measurement becomes a
restatement of the claim.

### Two-party review has two legs

Where the tip records the review control and the forge's live rules
corroborate it (a required-approvals rule ≥ 1: the author plus a
distinct approver is two persons), the record settles level four. Where
it does not, the judge reads the forge's **own review history** — a
platform-served record, not a repository's claim about itself — and
counts, per revision, the author plus each distinct approving reviewer.
Every revision agreed by two or more holds; one agreed by fewer
refutes; a revision the forge holds no change record for leaves the
level undetermined. The history walk is bounded (two API reads per
revision), and hitting the bound is logged and leaves the level
undetermined — never silently passed.

## The draft dependency track

SLSA v1.2 approves the Build and Source tracks. The Dependency track
exists only as a draft page.

Judging it anyway is deliberate. Organizations claim dependency levels
today, and a claim nobody computes is a claim nobody has tested — a
moving specification underneath makes that more likely to be wrong, not
less. Every output carrying a dependency level marks it: the report
carries `specStatus: draft` and the shield renders `L2 (draft)`.

The draft's own framing is what makes its levels detectable: it asks
that an inventory EXIST and that findings be TRIAGED, not that a
release be free of vulnerabilities.

Its level 4 — a secure ingestion policy — is judged by the one
consequence a policy cannot avoid leaving: the interval between a
version appearing upstream and this producer shipping it. The
judgment is deliberately asymmetric. A **zero floor refutes** — some
version was consumed the moment it appeared, so no control stood
between publication and use. But a **positive floor establishes
nothing**: a producer who merely releases slowly leaves exactly the
same interval as one running a real quarantine, and the two are
indistinguishable from published artifacts. So a positive floor is
`UNDETERMINED` with the floor stated — the reader gets the
measurement, never a verdict the measurement cannot carry.

Publication times resolve by package URL type, since that is how the
ecosystem already names which registry owns a package. Go modules
resolve through the checksummed proxy a Go build already fetches
through; a type with no resolver answers "unknown", which becomes an
unevaluated requirement rather than a pass.

Every rung of this track is fed from the publish's own artifacts and
nothing else: the inventory names the packages, the scan finds the
advisories, the published triage decisions settle them, the
inventory's download locations say where the build fetched from, and
the registry says when each version appeared. No configuration is
read anywhere in that chain.

### Where a publish is

A release is not the only shape a publish has, and for two releases
this tool behaved as though it were. Every detector above judged a
release, so a repository publishing rolling digests instead — no tag,
no version surface — was permanently `UNEVALUATED` on this track no
matter what its publish path enforced. Each answer was correct about
what it had looked at; what it had looked at was hard-coded.

So a repository's publish surfaces are
[declared, and plural](assert-policy-schema.md#where-a-repository-publishes):
a set that may hold the release surface, a continuous-digest surface,
both, or neither. Absent, the release surface stands alone, which is
what an adopter cutting releases has and what a stranger gets with no
configuration.

Every declared surface is gathered, and there is **no fallback from
one to another**. A repository declaring both is judged on both, and a
release gather that found nothing is never quietly answered by a
continuous one: absence read as compliance costs more than a missing
rung.

The declaration says WHERE to look and nothing else — the same line
`--org` draws. `internal/level` receives evidence and never a policy,
so a surface pointed at the wrong place yields "looked there, found
nothing", which is unevaluated: a statement about this run's sight,
never a level.

**A continuous surface's absences are inconclusive, and the two legs
differ there deliberately.** A release's asset list enumerates
everything that publish emitted, so an inventory missing from it is an
inventory the producer did not publish — that refutes. Reading a
digest's attestations enumerates nothing of the kind: the store is
keyed by subject digest, so evidence a publish emitted about *other*
bytes is invisible from the image however completely it exists. A
continuous surface therefore contributes no artifact unless it found
an inventory, and reports unevaluated with each absence named
separately — no inventory attested over the digest, no decision, and
how many of the artifact digests carry nothing at all. Separately,
because a producer clears them one at a time and the account should
narrow as they do.

### Continuity recovers

A lapse does not diminish a repository forever. The specification
restarts a control's continuity *from a new revision* rather than
voiding it, so a chain that lapsed and has since run clean is
continuous **since the restart** — and that is what the report says,
naming the revision continuity restarted from.

Only a repaired tip refutes, because there the lapse is the current
revision: the controls have not yet run unbroken for a single
revision. The next clean push re-establishes the level, and the report
carries the date from which the claim holds.

## Populations

`--org` measures every repository the forge lists for an organisation
and folds the results: **a rung holds only where it holds for every
member**. An organisation is not at a level because most of it is, and
the report names the weakest member, because a number nobody can trace
to a repository is a number nobody can act on.

By default the population is the forge's listing — what the forge says
exists, archived repositories and forks aside. `--policy` narrows it
to what an organisation declared about itself
([the assert policy's `population` section](assert-policy-schema.md#population)),
per repository AND per track: a repository that will never publish a
release is measured on `source` and is simply not on the board for
`build` and `dependency`.

That is a statement about who is ASKED, and it can never touch what
the answer is. A cell outside the population was never measured — no
number, no grey, no finding — which is a different claim from a cell
that should have been measurable and could not be read this time, and
that second one stays loud. Which members are *permitted to fall
short* is a third question again, asked by a verb that compares
evidence to a declaration, and still not asked here: a repository in
the population is judged on the platform's own facts, and nothing
written down can lift its rung or hide a shortfall it established.

With a track named, `--policy` is meaningful only with `--org`. Over
the one repository `--repo` names, a declared population could do
nothing but veto the question that was asked, so the combination is
refused rather than reinterpreted. The board form below is the
opposite case and accepts both: naming no track, it asks the
declaration *which rows does this repository have*, which the
declaration answers positively.

That is also where a single repository's own declaration reaches its
own judgment. A repository publishing a stream rather than releases
declares its surfaces in its roster row, and the board form over
`--repo` reads them — which is the same run a repository already makes
to publish its own cells with a credential over itself.

### What the enumeration could see

A declared population is reconciled against the listing in both
directions, and an unseen member refuses: **an unseen repository is
unchecked, not clean**, and softening that would let a deleted
repository read as fine.

That rule cannot tell "the listing is complete and something is
missing from it" from "the listing was never going to show this",
which leaves every reconciliation one revoked scope away from refusing
for a reason that is not true. So an organisation may declare what its
enumeration covers
([`population.coverage`](assert-policy-schema.md#population)), and a
declared member outside that coverage is reported **unexercised**:
named on the run's output, counted against the declared population so
the report seals `CANNOT_JUDGE` rather than a clean verdict, and never
measured.

The declaration moves exactly one thing and can never make anything
read as clean:

| the listing | the declaration | outcome |
| --- | --- | --- |
| shows it | does not name it | **refuses** — nobody has said anything about this repository |
| does not show it | names it, inside the coverage | **refuses** — deleted is still deleted |
| does not show it | names it, outside the coverage | **unexercised** — loud, uncounted, unjudged |
| shows it | names it | reconciled, and measured |

An organisation adopting stele on two repositories of forty, holding
private members, or handing a run a deliberately scoped credential is
a normal adopter rather than a degraded one. Absent a `coverage`
declaration, every member is inside the coverage — which is the
behaviour that shipped before this existed.

## The board

`stele level --out-dir <dir>`, with no track named, measures every
cell a population holds and publishes each as its own pair of
documents:

```text
<dir>/<repo>/<track>.report.json
<dir>/<repo>/<track>.shield.json
```

That layout is the whole format. WHICH repositories and tracks appear
is the population's to say and never this tool's, so an organisation
whose repositories are not uniformly evidence-bearing gets a board
with the shape it declared rather than one with grey holes in it.

The board form folds nothing. `--org` with a track answers *what does
this organisation support*, which is a fold to its weakest member;
`--out-dir` answers *what does each cell support*, which is a
different question and keeps every answer separate.

### Two scopes

| scope | population | who can run it |
| --- | --- | --- |
| `--org <org>` | the forge's listing, as the declaration narrows it | a credential that can list the organisation |
| `--repo <owner>/<name>` | that repository's declared rows, and nothing else | a credential over that repository |

The per-repository scope **enumerates nothing and reconciles
nothing**. It reads the declaration only where it names the repository
the caller named — so one committed policy serves every repository's
own run, and a repository publishing its own badge never needs a
credential that can read its organisation. A repository the
declaration places on no track publishes no cell and exits clean: an
exclusion produces nothing, and there is no exit code for a fact.

The two scopes measure identically. Neither learns anything about a
level the other does not, and the org form is unchanged by the
existence of the other.

### What may replace what

One rule, and it belongs to the judge rather than to whatever
schedules it. **A cell that cannot be judged today never publishes
over a level somebody proved yesterday.** What that means depends
entirely on whether the cell was ever judgeable, and the two must not
be confused:

| prior state | this run | what happens |
| --- | --- | --- |
| anything | measured | the measurement publishes |
| absent | could not judge | grey publishes, and **nothing pages** |
| grey | could not judge | grey publishes, and nothing pages |
| a level | could not judge | the level **stands**, and the run exits 4 |
| unreadable | could not judge | the file stands, and the run exits 4 |

A repository that publishes nothing has no build level. That is a fact
about it, not a fault — an alarm there would fire every week forever
over repositories behaving exactly as intended, and a board that is
permanently amber is a board nobody reads. A cell that carried a level
and no longer can is the opposite: evidence went missing, a credential
narrowed, or a forge read degraded, and that is the one state worth
waking somebody for.

A cell whose published shield this release cannot read counts as
holding a level. Its contents are unknown, and overwriting an unknown
with *could not see* is the direction that loses information.

### What leaves the board

A cell the population no longer holds is removed, and each removal is
named on the run's own output. A board is this engine's output whole —
nothing else writes it — so a cell left behind after the population
stopped holding it is not history worth keeping; it is a published
level for a repository and track nobody measured.

**A cell this run could not look at is not such a cell.** A repository
outside the declared coverage, and every repository other than the one
a `--repo` run judged, keeps everything it has: the population still
holds it, and a run that could not see a repository has no standing to
delete what a run that could see it wrote. Removing it would evade the
replacement rule by the back door, since a deleted cell is one no
reader can find.

Only the cell layout is touched. A file the board did not write is not
the board's to delete, and neither is a track this release does not
judge: a board may have been written by a stele that judges more than
this one does, and pruning what it cannot name would narrow somebody
else's board to this release's vocabulary.

## Output

The report carries the computed level, the ladder, and — for every
requirement — what was found and why, quoting the specification's words
where a requirement was not established. A level that does not hold
says which requirement failed.

`--shield <path>` writes a shields.io endpoint document from the same
seal as the report, so no copy of the level exists that could drift
from the other.

The badge is information, not a judgment: **one badge per track,
showing the established level, in green** — it moves up and down as the
evidence does, and a measured L0 is an answer like any other. The
message marks draft tracks (`L2 (draft)`). Grey exists for exactly one
case: the measurement could not establish any level (`unmeasured`),
because a badge that cannot see must not pick a number.

## What this verb does not do

- **It reads no policy.** Not for identities, not for targets, not for
  the evidence layout. Everything it needs, it finds.
- **It makes no settings read.** A configuration is a claim about
  intent; the evidence for a control is its consequence.
- **It mints nothing.** No signature, no attestation, no note.
