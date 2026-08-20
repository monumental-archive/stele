# The VEX join: comparing package identities

A triage decision excuses an advisory finding when the two name the
same thing. This document is the one written statement of when they
do — the rule every implementation of the join must reach the same
answer under, whether it reads an OpenVEX document in Go here or
somewhere else in another language.

What the join MEANS for a report — the exact `(advisory, package,
version)` triple, the empty set deciding nothing, a matched decision
appearing as a declared exception and an unmatched one as stale — is
in [assert-policy-schema.md](assert-policy-schema.md). This document
is narrower, and answers two questions:

1. Given a finding and a decision, when are their package identities
   equal?
2. Given a decision that matches, does it EXCUSE the finding?

They are separate questions and a join has to answer both. Answering
only the first excuses a finding on the strength of a statement that
may be admitting it.

## The rule

The key is the triple `(advisory, package, version)`. Two of its three
parts compare verbatim, byte for byte:

- **advisory** — an identifier in the issuing database's own
  vocabulary (`CVE-2026-0001`, `GO-2026-0001`, `RUSTSEC-2021-0127`).
  Nothing normalises it.
- **version** — compared as a string, never parsed. No purl type
  declares versions case-insensitive, and an ecosystem's version
  vocabulary may be case-significant: Go's `v1.0.0-RC1` and
  `v1.0.0-rc1` are different prereleases of one module.

**The package name compares in its ecosystem's canonical form.** That
form is a per-type fact, stated by the purl spec's definition of the
type, and it is the whole of the rule:

| purl type | name comparison | canonical form |
| --- | --- | --- |
| `golang` | case-insensitive | lowercased |
| every other type | case-sensitive | as written |

The default is case-SENSITIVE. A purl name is compared as it was
written unless that type's spec definition says otherwise, so a type
whose definition nobody has read against this table folds nothing.
That is the safe direction, and the asymmetry is the reason: a fold
that fails to happen leaves a finding undecided, which is loud and
lands in front of a human; a fold that happens wrongly excuses a
vulnerability in some OTHER package, silently. A type joins the first
column when its purl type definition declares its names
case-insensitive — never because a graph happened to need it.

## The two vocabularies

The two sides of the join do not describe an ecosystem the same way,
and each side must fold on what it has:

- A **decision** names a purl `type` — it is reading a package URL,
  which carries the type in its own syntax (`pkg:golang/…`). No caller
  supplies it; the document states it.
- A **finding** names the scanner's ecosystem, in OSV's vocabulary
  (`Go`, `crates.io`, `npm`, `Debian:12`). OSV qualifies distro
  ecosystems with a release, which names no different ecosystem: the
  label is read up to the first `:`.

So `Go` (OSV) and `golang` (purl) name one ecosystem, and both fold.
Ecosystem labels are matched case-insensitively; package names are
not, except by the rule above.

## Why the join folds and the producer does not

The purl golang type declares its namespace and name lowercased. An
SBOM emitter that mints `pkg:golang/github.com/masterminds/semver/v3`
for the module `github.com/Masterminds/semver/v3` is therefore
producing the canonical form, correctly — and a consumer that then
matches it byte-for-byte against the module path a scanner reports is
the defective half. The spec is the bar, so the join is what moved
(stele#201).

The practical consequence is the point: a decision authored the
natural way — product purl copied out of the published SBOM, which is
where the affected inventory is read — joins the finding for the same
module. Before the fold it silently excused nothing for any module
whose path carries an uppercase letter.

A report's finding ID therefore carries the canonical name, so an ID
read out of a report is a name a decision can be written against; the
finding's own detail line carries the module path as the scanner
reported it, which is the spelling a reader will find in a manifest.
Both facts are present and neither is invented.

## Which decisions excuse

A decision that matches a finding has still only answered "somebody
looked at this". Whether it CLEARS the finding is one further
question, asked of its status: **does the status deny that the
advisory applies to the product?** Only a denial excuses.

| status | excuses | why |
| --- | --- | --- |
| `not_affected` | yes | OpenVEX's denial |
| `false_positive` | yes | the same denial in another dialect's spelling |
| `affected` | no | an admission — it states the finding is real |
| `under_investigation` | no | a judgment not yet made |
| `fixed` | no | see below |
| anything else | no | an unrecognised judgment is not one to act on |

`fixed` is the row worth stating explicitly, because it reads like an
exit and is not one. It claims the product was remediated, which is
not a denial that the advisory applies — and the join only meets a
decision where a scan CURRENTLY reports that exact triple, so a
`fixed` statement matching a live finding is a remediation claim the
scanner in hand has just disproved. Excusing on it would let a stale
claim silence the evidence that refutes it.

`false_positive` is not OpenVEX v0.2.0 vocabulary; it is what some
other VEX dialects call the same denial, and reading it as one is a
deliberate choice so a decision written in that spelling does not
silently decide nothing.

**A decision that matches and does not excuse is reported, never
silent.** It belongs on the finding it failed to excuse — a red
finding whose reader cannot tell that somebody already looked at it
and wrote something down is how one advisory gets triaged twice.

## Implementing this join a second time

Anything reading these decisions alongside another scanner must reach
the same answers, or an org acquires two dialects and a decision
excuses a finding in one place and not the other. To agree:

1. Compare `advisory` and `version` verbatim.
2. Lowercase the package name on BOTH sides when the ecosystem is
   golang (purl type `golang`, OSV ecosystem `Go`), by the table
   above. Folding one side only is the original defect wearing a
   patch: the sides still disagree, just about different inputs.
3. Fold nothing else, and treat an unrecognised ecosystem as
   case-sensitive.
4. Excuse only on a denying status, by the table above, and report a
   matching decision that does not excuse.
5. Treat two decisions that fold to one identity as what they are —
   two judgments on one finding, which is a contradiction to surface,
   not a race for file order to settle.
6. Scan one ecosystem, judge one ecosystem: a decision whose purl type
   your scanner cannot report on is not stale and not covered, it is
   out of scope, and it should produce nothing at all.

In this repository the rules are implemented once, in
`internal/vexjoin` (`canonicalName` and `foldsNames` for identity,
`Decision.Excuses` for the status question), and every key on either
side is built through `KeyFromPurl` or `KeyFromFinding` so no caller
can spell the identity rule a second way.

Both `stele assert advisories` and `stele assert blast-radius` join on
that identity. The status rule currently has ONE adopter — `assert
advisories` — because blast-radius excuses on any matching decision
regardless of status, which is a defect recorded at stele#222 rather
than a second reading of this document. Stated here rather than
smoothed over: a doc claiming two conforming implementations where
there is one would be the same kind of unverified confidence this
document exists to correct.
