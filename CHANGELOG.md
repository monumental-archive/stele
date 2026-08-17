# Changelog

All notable changes to this project are recorded here.

<!-- rumdl-disable MD013 -->
<!-- entries are commit subjects, verbatim: a recorded subject's
length is a fact about history, not prose to reflow -->

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
over the surface named in [MAINTENANCE.md](MAINTENANCE.md).

## [0.2.0](https://github.com/monumental-archive/stele/compare/v0.1.0...v0.2.0) - 2026-08-17

### Added

- mint a version DOI for every release ([#48](https://github.com/monumental-archive/stele/pull/48))

## [0.1.0](https://github.com/monumental-archive/stele/releases/tag/v0.1.0) - 2026-08-17

### Added

- stand up the repo — tooling before logic ([#1](https://github.com/monumental-archive/stele/pull/1))
- decode and validate the verify policy ([#11](https://github.com/monumental-archive/stele/pull/11))
- implement the dsse and in-toto statement layer ([#12](https://github.com/monumental-archive/stele/pull/12))
- implement the provenance and vsa predicates ([#13](https://github.com/monumental-archive/stele/pull/13))
- implement the chain-link note format ([#14](https://github.com/monumental-archive/stele/pull/14))
- implement the sigstore trust boundary ([#17](https://github.com/monumental-archive/stele/pull/17))
- implement the verify verb and prove it in shadow mode ([#18](https://github.com/monumental-archive/stele/pull/18))
- prove the legacy verdict epoch against real history ([#20](https://github.com/monumental-archive/stele/pull/20))
- implement the emit verb — chain links and the release vsa ([#23](https://github.com/monumental-archive/stele/pull/23))
- state the folded source revision on the vsa leg ([#26](https://github.com/monumental-archive/stele/pull/26))
- decide versions and render notes from conventional commits ([#31](https://github.com/monumental-archive/stele/pull/31))
- release wiring — stele publishes itself as a go-binary ([#41](https://github.com/monumental-archive/stele/pull/41))

### CI

- pass the codecov token through to the gate ([#2](https://github.com/monumental-archive/stele/pull/2))

### Documentation

- design the verify policy schema, first cut ([#10](https://github.com/monumental-archive/stele/pull/10))
- record the verify cutover — authority, the closed legacy epoch ([#22](https://github.com/monumental-archive/stele/pull/22))
- record emit as authoritative in the port sequence ([#29](https://github.com/monumental-archive/stele/pull/29))
- state the bash as a reference, never a byte-match oracle ([#30](https://github.com/monumental-archive/stele/pull/30))
- declare the versioned surface in MAINTENANCE.md ([#45](https://github.com/monumental-archive/stele/pull/45))

### Fixed

- release.yml triggers on main, not a template placeholder ([#43](https://github.com/monumental-archive/stele/pull/43))

### Miscellaneous

- drop the configs the belt delivers ([#36](https://github.com/monumental-archive/stele/pull/36))
