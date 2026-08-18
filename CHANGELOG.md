# Changelog

All notable changes to this project are recorded here.

<!-- rumdl-disable MD013 -->
<!-- entries are commit subjects, verbatim: a recorded subject's
length is a fact about history, not prose to reflow -->

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
over the surface named in [MAINTENANCE.md](MAINTENANCE.md).

## [0.10.0](https://github.com/monumental-archive/stele/compare/v0.9.0...v0.10.0) - 2026-08-18

### Added

- version-mirror bump and declared notes silence ([#102](https://github.com/monumental-archive/stele/pull/102))

### Fixed

- update module go.yaml.in/yaml/v3 to v3.0.5 ([#104](https://github.com/monumental-archive/stele/pull/104))
- version gate first, schema 2, versioned report ([#110](https://github.com/monumental-archive/stele/pull/110))

### Documentation

- correct three statements the cutover made false ([#100](https://github.com/monumental-archive/stele/pull/100))
- specify the v3 chain format here and test the spec's examples ([#105](https://github.com/monumental-archive/stele/pull/105))

### Testing

- raise coverage to 98.6% and name what cannot be covered ([#106](https://github.com/monumental-archive/stele/pull/106))

## [0.9.0](https://github.com/monumental-archive/stele/compare/v0.8.0...v0.9.0) - 2026-08-18

### Added

- let scoped commit types carry their own notes heading ([#91](https://github.com/monumental-archive/stele/pull/91))

### Fixed

- update github.com/digitorus/pkcs7 digest to ffadbf3 ([#90](https://github.com/monumental-archive/stele/pull/90))

## [0.8.0](https://github.com/monumental-archive/stele/compare/v0.7.0...v0.8.0) - 2026-08-18

### Added

- make every obligation declarable and port the tag audit ([#84](https://github.com/monumental-archive/stele/pull/84))

## [0.7.0](https://github.com/monumental-archive/stele/compare/v0.6.0...v0.7.0) - 2026-08-18

### Added

- re-verify the corpus with --depth full ([#78](https://github.com/monumental-archive/stele/pull/78))
- make the release-decision obligation declarable ([#81](https://github.com/monumental-archive/stele/pull/81))

### Documentation

- record the assert handover in the port sequence ([#76](https://github.com/monumental-archive/stele/pull/76))

### Testing

- stand up fuzz targets over the foreign-byte parsers ([#80](https://github.com/monumental-archive/stele/pull/80))

## [0.6.0](https://github.com/monumental-archive/stele/compare/v0.5.0...v0.6.0) - 2026-08-18

### Added

- refuse an absent workflow identity at preflight ([#74](https://github.com/monumental-archive/stele/pull/74))

## [0.5.0](https://github.com/monumental-archive/stele/compare/v0.4.0...v0.5.0) - 2026-08-18

### Added

- verify continuous digests and base approvals ([#73](https://github.com/monumental-archive/stele/pull/73))

### Fixed

- update module golang.org/x/mod to v0.39.0 ([#71](https://github.com/monumental-archive/stele/pull/71))

## [0.4.0](https://github.com/monumental-archive/stele/compare/v0.3.0...v0.4.0) - 2026-08-17

### Added

- seal verdicts into the shared report model behind --json ([#62](https://github.com/monumental-archive/stele/pull/62))
- stand up the verb with image-facts as its first target ([#63](https://github.com/monumental-archive/stele/pull/63))
- evidence walk, blast radius and the emit preflight ([#66](https://github.com/monumental-archive/stele/pull/66))

### Fixed

- retry transport, split classes, narrow the burn ([#70](https://github.com/monumental-archive/stele/pull/70))

## [0.3.0](https://github.com/monumental-archive/stele/compare/v0.2.2...v0.3.0) - 2026-08-17

### Added

- read the release sbom out of the shipped binaries ([#57](https://github.com/monumental-archive/stele/pull/57))

### Fixed

- accept several commands per platform in the release sbom ([#59](https://github.com/monumental-archive/stele/pull/59))

## [0.2.2](https://github.com/monumental-archive/stele/compare/v0.2.1...v0.2.2) - 2026-08-17

### Documentation

- record the concept DOI minted by v0.2.1 ([#53](https://github.com/monumental-archive/stele/pull/53))

## [0.2.1](https://github.com/monumental-archive/stele/compare/v0.2.0...v0.2.1) - 2026-08-17

### Fixed

- build on Go 1.26.6, clearing four reachable stdlib advisories ([#51](https://github.com/monumental-archive/stele/pull/51))

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
