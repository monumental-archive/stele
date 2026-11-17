# Inventory plan goldens (stele#396)

`crates/plan.golden` and `extension/plan.golden` were written by the
canon's own shell blocks, run verbatim under bash (GNU bash 5, jq
1.8.2, LANG=C.UTF-8) against the fixtures beside them:

- `build-rust-crate.yml`, "Emit the inventory plan (which packages
  these crates ship)", at monumental-archive/.github 9c58951, with
  `UNTRUSTED_VERSION=0.4.2` in a directory whose `target/package` is
  `crates/package`;
- `build-pgrx-extension.yml`, "Emit the inventory plan (what this cell
  built, from its own inputs)", at the same commit, with
  `UNTRUSTED_CRATE_DIR=crate PG=16` in a directory holding a `crate`
  directory whose `Cargo.toml` is `extension/Cargo.toml.fixture`.

The `.crate` files are empty: the block reads their names, never their
bytes. The manifest is committed as `Cargo.toml.fixture`, never as
`Cargo.toml`: a tracked Cargo.toml would make this Go repository's gate
treat it as a Rust crate. The tests lay it out under its real name.
