# Source of this capture

The attestation store of the `monumental-archive` owner, read
2026-11-17 for two first-party bases that release-lab published, as
`gh.Snapshot` replays an owner-level read
(`<owner>/attestations/<sha256 hex>.json`). Taken with nothing
hand-written:

```bash
gh api "/orgs/monumental-archive/attestations/sha256:<hex>?per_page=100" \
  | jq '[.attestations[].bundle]'
```

- `af094a76…5ab5d.json`: `ghcr.io/monumental-archive/release-lab:latest`,
  the continuous stream. One bundle: SLSA provenance v1 signed by
  `monumental-archive/signer/.github/workflows/sign.yml@b7469566…`,
  source `release-lab` at `refs/heads/main`.
- `ca2d60b3…76384.json`:
  `ghcr.io/monumental-archive/lab-pg:0.28.4-pg18-artifact`, a release
  image whose name is not its repository's. Three bundles: SLSA
  provenance v1 signed by `sign.yml@0d6c6e29…`, source `release-lab`
  at `refs/tags/v0.28.4`; and a build-enrichment and a VSA signed by
  `.github/.github/workflows/verify-release.yml`, which the store
  returns for this digest because one of their subjects names it.

The two provenance bundles were signed at two different signer
commits, neither of them the one the verifying tree pins: the case
`trust.WorkflowIdentity` exists for (stele#402). Both are logged in
the public-good Rekor, so sigstore-go's own public-good trusted root
verifies them; no root is committed here. The tests in
`internal/cli/verify_base_internal_test.go` read this capture. A row
that needs a different answer edits a copy in memory, never these
files.
