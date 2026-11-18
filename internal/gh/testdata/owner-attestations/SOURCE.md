# Source of this capture

The owner-level attestation reads, one real response of each form the
client uses, read 2026-11-17 (stele#402). Taken with `gh api`, each
trimmed only as stated:

- `type-monumental-archive.json`, `type-jdx.json`: `GET /users/{login}`
  for an organisation and for a user, trimmed to `login` and `type`,
  the two fields the client reads.
- `orgs-monumental-archive.json`: `GET /orgs/monumental-archive/attestations/sha256:ca2d60b3…76384`
  (`ghcr.io/monumental-archive/lab-pg:0.28.4-pg18-artifact`), kept to
  its SLSA provenance attestation.
- `users-jdx.json`: `GET /users/jdx/attestations/sha256:23ba592f…ca378`
  (`mise-v2026.11.9-linux-x64.tar.gz` from jdx/mise, a user-owned
  repository), kept to its first attestation.

Each attestation keeps `repository_id` and `bundle` and drops
`bundle_url`, a time-limited signed URL that is never committed.

Measured beside these and not relied on: each endpoint also answers
for the other kind of owner — `/orgs/jdx/…` returns the user's
attestations, `/users/monumental-archive/…` the organisation's.
The documented contract is `/orgs` for an organisation and `/users`
for a user, so the client reads the owner's `type` and takes the
documented form.
