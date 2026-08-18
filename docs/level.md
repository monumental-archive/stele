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
on what the SCS or the build platform RECORDED rather than on
something this tool recomputed. Both are evidence. For the control
requirements a contemporaneous attestation is the *only* evidence
that can exist — which controls were configured when a revision
landed is unrecoverable afterwards, since a rules API answers about
now — and that is exactly why the specification asks the SCS to
record them at the time. But attested and recomputed are not the same
strength, so the report says which, and names the identity that
signed.

A requirement with **no detector in this build** is `UNDETERMINED`, and
the report names it. That is a statement about the tool's coverage, not
about the world — the alternative is a level that holds because nobody
looked. `requirementCoverage` in every report says how many of a
track's requirements this build can establish.

Refuted outranks undetermined when folding a level: evidence that
contradicts a requirement settles it, while evidence merely missing
does not. A level that lost sight seals `CANNOT_JUDGE`, never a
confident lower answer.

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

Its level 4 — a secure ingestion policy — is judged by the consequence
a policy leaves behind rather than by the policy itself. A quarantine
window, a malware check, a risk feed consulted before a version is
taken: each shows up as an interval between a version appearing
upstream and this producer taking it. A producer running no quarantine
ingests versions the day they publish; one running any has a floor
below which nothing was taken. So a zero floor refutes and any
positive floor establishes, with the floor stated — because how long a
window is long enough is the organisation's risk determination and not
this tool's.

Publication times resolve by package URL type, since that is how the
ecosystem already names which registry owns a package. Go modules
resolve through the checksummed proxy a Go build already fetches
through; a type with no resolver answers "unknown", which becomes an
unevaluated requirement rather than a pass.

Every rung of this track is fed from the release's own published
artifacts and nothing else: the inventory names the packages, the scan
finds the advisories, the triage decisions published beside it settle
them, the inventory's download locations say where the build fetched
from, and the registry says when each version appeared. No
configuration is read anywhere in that chain.

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

The population is the forge's listing — what the forge says exists —
so no declaration decides who is counted. Which members are
*permitted* to fall short is a different question, asked by a verb
that compares evidence to a declaration, and deliberately not asked
here.

## Output

The report carries the computed level, the ladder, and — for every
requirement — what was found and why, quoting the specification's words
where a requirement was not established. A level that does not hold
says which requirement failed.

`--shield <path>` writes a shields.io endpoint document from the same
seal as the report, so no copy of the level exists that could drift
from the other.

## What this verb does not do

- **It reads no policy.** Not for identities, not for targets, not for
  the evidence layout. Everything it needs, it finds.
- **It makes no settings read.** A configuration is a claim about
  intent; the evidence for a control is its consequence.
- **It mints nothing.** No signature, no attestation, no note.
