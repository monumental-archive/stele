# Source of this capture

Moved byte-for-byte from `monumental-archive/.github`, directory
`.github/rekor-monitor/testdata/`, at commit
`07ff4a5bcc362b30cf9415cc6f781808d1dfef23` (`main`, read
2026-11-17), where the canon's reconciler tests
(`.github/rekor-monitor/test_reconcile.py`, .github#1250) used it.
That test's own header records how it was taken, captured 2026-11-15
with nothing hand-written:

- `ct-443908396.json`: the CT log's get-entries answer
  (`https://ctfe.sigstore.dev/2022`) for the certificate behind canon
  v1.67.0 (release run 43671235061; the chain link is `publish.yml`).
- `ct-335460347.json`: the certificate of the canon's VEX signing on
  2026-08-11 (run 31536050844; `vex-attest.yml`, a top-level canon
  workflow that calls the signer itself).
- `forge-2026-11-15.json`: every forge answer the reconciliation of
  those two read, keyed by REST path, with each file read stored
  under `contents/<commit>/`.

stele#387 moved the reconciliation here; the tests in
`internal/assert/signers_test.go` and `internal/ctlog/claims_test.go`
read this capture. A row that needs a different answer edits a copy
in memory, never these files.
