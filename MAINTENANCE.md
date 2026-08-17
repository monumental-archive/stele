# Maintenance and compatibility surface

Versions of this repository follow semver over the surface consumers
actually depend on. A change is **breaking** when a caller of the
previous version breaks by taking the new one with no change of its own
— where "a caller" means a workflow step, a script, or a person running
the binary, never a Go import.

## The versioned surface

- **The command surface**: verb and mode names (`verify release|vsa|chain|level`,
  `emit …`, `derive version|notes`, `version`, `help`), their flags, and
  which flags are required. Removing or renaming any of these is
  breaking; a new optional flag or a new mode is a minor.
- **Exit codes**: `0` success, `2` usage error, `3` output-stream
  failure. A caller distinguishing "wrong invocation" from "could not
  write" depends on these staying put, so changing a code's meaning is
  breaking. New codes for new conditions are a minor.
- **Machine-readable stdout**: lines a caller is expected to parse
  rather than read. Today that is `emit: source revision <sha>`, which
  the canon's `verify-release.yml` greps to state the folded source
  revision. Changing such a line's shape is breaking; adding a new one
  is a minor. Lines meant for humans go to stderr precisely so they are
  not part of this promise.
- **The policy file schema** (`slsa/verify-policy.json` as consumed):
  field names, their meanings, and which are required. The policy is
  the universality boundary — everything org-shaped lives there and
  nothing org-shaped lives in the code — so a repository's committed
  policy must keep working across a minor bump. Requiring a new field
  is breaking; accepting a new optional one is a minor.
- **Emitted evidence formats**: the chain-link note layout and the
  predicate shapes this tool writes and reads. A verifier that stops
  accepting evidence a previous version emitted is breaking, and it
  breaks history rather than a build — so this is the surface where a
  breaking change costs the most.

## Not part of the surface

- **Everything under `internal/`.** It is unimportable by construction;
  that is the point. There is no Go API promise here.
- **Human-facing wording**: usage text, diagnostics, log lines on
  stderr. A caller that greps stderr has taken a dependency this
  document does not grant.
- **Build metadata**: the module version string's exact form, which is
  Go's to decide and is read back from the binary rather than authored.
- **Test fixtures and internal file layout.**

## Release mechanics

Releases run through the org canon: the version and changelog are
derived by this tool from conventional commits, the tag is minted by
the org App on merge of a Release PR, and the binaries are built,
proved reproducible, signed and attested by the canon's `go-binary`
class. Nothing here is released by hand, and no credential lives in
this repository.

1.0.0 is not a version number this project drifts into. It is a
deliberate statement that the surface above is stable, set once, by
hand, when that is true.
