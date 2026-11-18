# Changelog

All notable changes to this project are recorded here.

<!-- rumdl-disable MD013 -->
<!-- entries are commit subjects, verbatim: a recorded subject's
length is a fact about history, not prose to reflow -->

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
over the surface named in [MAINTENANCE.md](MAINTENANCE.md).

## [0.26.0](https://github.com/monumental-archive/stele/compare/v0.25.0...v0.26.0) - 2026-11-18

### Breaking

- produce the source verdict before the release (#468) ([#469](https://github.com/monumental-archive/stele/pull/469))

## [0.25.0](https://github.com/monumental-archive/stele/compare/v0.24.2...v0.25.0) - 2026-11-18

### Breaking

- change a chain's source signer once (#389) ([#427](https://github.com/monumental-archive/stele/pull/427))
- sign and read a release tag's source verdict (#391) ([#432](https://github.com/monumental-archive/stele/pull/432))
- derive vex from policy and an inventory dir (#397) ([#437](https://github.com/monumental-archive/stele/pull/437))
- plan the signing of several vex decisions (#398) ([#438](https://github.com/monumental-archive/stele/pull/438))
- take the run's raw inputs and place bundles (#400) ([#436](https://github.com/monumental-archive/stele/pull/436))

### Added

- derive the signer digest a tree pins (#392) ([#422](https://github.com/monumental-archive/stele/pull/422))
- derive the subject manifest (#393) ([#429](https://github.com/monumental-archive/stele/pull/429))
- report where a chain changed signer (#389) ([#431](https://github.com/monumental-archive/stele/pull/431))
- port the verify-release shell into stele (#392) ([#435](https://github.com/monumental-archive/stele/pull/435))
- split chain signing from the push (#390) ([#425](https://github.com/monumental-archive/stele/pull/425))
- emit the release decision a commit point signs (#399) ([#434](https://github.com/monumental-archive/stele/pull/434))
- print the population assert walks (#388) ([#445](https://github.com/monumental-archive/stele/pull/445))
- compare the published board with the measured one (#418) ([#452](https://github.com/monumental-archive/stele/pull/452))
- derive a release's pins and subjects when absent (#447) ([#456](https://github.com/monumental-archive/stele/pull/456))
- declare a release's evidence classes by policy (#403) ([#457](https://github.com/monumental-archive/stele/pull/457))
- check one crate's version against a stated one (#455) ([#460](https://github.com/monumental-archive/stele/pull/460))
- add a pre-release form to verify repro (#401) ([#444](https://github.com/monumental-archive/stele/pull/444))
- verify base images with stele's own verifier (#402) ([#459](https://github.com/monumental-archive/stele/pull/459))
- derive a release's inventories in one call (#396) ([#443](https://github.com/monumental-archive/stele/pull/443))

### Fixed

- scrub every repository-local variable from env (#426) ([#428](https://github.com/monumental-archive/stele/pull/428))
- update go.yaml.in/yaml/v3 to v4.0.0 ([#311](https://github.com/monumental-archive/stele/pull/311))
- read every page of the attestation store (#439) ([#449](https://github.com/monumental-archive/stele/pull/449))
- fetch tags shallow only where a tag exists (#446) ([#451](https://github.com/monumental-archive/stele/pull/451))
- declare subject shapes in the assert policy (#442) ([#450](https://github.com/monumental-archive/stele/pull/450))
- declare the runner environments a release may carry (#463) ([#465](https://github.com/monumental-archive/stele/pull/465))
- look provenance-verified bases up by owner (#458) ([#461](https://github.com/monumental-archive/stele/pull/461))
- declare the release workflow in the assert policy (#448) ([#462](https://github.com/monumental-archive/stele/pull/462))

### Testing

- say the golden's inputs are reconstructed (#400) ([#453](https://github.com/monumental-archive/stele/pull/453))

### CI

- adopt the canon's go mutation leg ([#466](https://github.com/monumental-archive/stele/pull/466))

## [0.24.2](https://github.com/monumental-archive/stele/compare/v0.24.1...v0.24.2) - 2026-11-17

### Fixed

- write every test server's state under its lock ([#419](https://github.com/monumental-archive/stele/pull/419))

## [0.24.1](https://github.com/monumental-archive/stele/compare/v0.24.0...v0.24.1) - 2026-11-17

### Fixed

- update github.com/sigstore/rekor to v1.5.6 ([#302](https://github.com/monumental-archive/stele/pull/302))
- judge tags past a link no branch or tag reaches ([#413](https://github.com/monumental-archive/stele/pull/413))
- update github.com/sigstore/rekor to v1.6.0 ([#412](https://github.com/monumental-archive/stele/pull/412))
- found the tag horizon on every tied genesis candidate ([#416](https://github.com/monumental-archive/stele/pull/416))

## [0.24.0](https://github.com/monumental-archive/stele/compare/v0.23.0...v0.24.0) - 2026-11-17

### Breaking

- reconcile signer certificates from the CT log ([#404](https://github.com/monumental-archive/stele/pull/404))

## [0.23.0](https://github.com/monumental-archive/stele/compare/v0.22.3...v0.23.0) - 2026-11-17

### Breaking

- read git objects with one git fetch per repository ([#405](https://github.com/monumental-archive/stele/pull/405))

### Fixed

- update golang.org/x/mod to v0.43.0 ([#381](https://github.com/monumental-archive/stele/pull/381))
- print the evidence that classified a throttle ([#394](https://github.com/monumental-archive/stele/pull/394))
- pass the token to git through its environment, not argv ([#406](https://github.com/monumental-archive/stele/pull/406))

## [0.22.3](https://github.com/monumental-archive/stele/compare/v0.22.2...v0.22.3) - 2026-11-15

### Fixed

- say provenance was retrievable only when it was ([#371](https://github.com/monumental-archive/stele/pull/371))
- read an unreadable release store as unreached ([#372](https://github.com/monumental-archive/stele/pull/372))
- read an unfinished look as unreached, not absent ([#375](https://github.com/monumental-archive/stele/pull/375))

## [0.22.2](https://github.com/monumental-archive/stele/compare/v0.22.1...v0.22.2) - 2026-11-15

### Fixed

- read the licence a manifest-less tree declares ([#357](https://github.com/monumental-archive/stele/pull/357))
- read a continuous publish with no vex document as seen ([#364](https://github.com/monumental-archive/stele/pull/364))
- measure the registry subjects a release names ([#366](https://github.com/monumental-archive/stele/pull/366))
- read the component each published statement decides ([#367](https://github.com/monumental-archive/stele/pull/367))
- gather the build track over every publish surface ([#368](https://github.com/monumental-archive/stele/pull/368))

### Documentation

- answer the best practices questions from this repo ([#359](https://github.com/monumental-archive/stele/pull/359))
- wear the best practices badge ([#360](https://github.com/monumental-archive/stele/pull/360))

### Testing

- prove each tear is what failed, not the fixture ([#349](https://github.com/monumental-archive/stele/pull/349))

### CI

- adopt the scheduled security release ([#351](https://github.com/monumental-archive/stele/pull/351))

## [0.22.1](https://github.com/monumental-archive/stele/compare/v0.22.0...v0.22.1) - 2026-11-15

### Fixed

- follow the link header to the next page ([#341](https://github.com/monumental-archive/stele/pull/341))
- end the walk unseen when a store read cannot complete ([#342](https://github.com/monumental-archive/stele/pull/342))
- end the walk unseen when the credential is refused ([#345](https://github.com/monumental-archive/stele/pull/345))

### Testing

- plant stand-in tools as symlinks, never scripts ([#340](https://github.com/monumental-archive/stele/pull/340))

## [0.22.0](https://github.com/monumental-archive/stele/compare/v0.21.0...v0.22.0) - 2026-11-14

### Added

- state which supported release is still affected ([#336](https://github.com/monumental-archive/stele/pull/336))

## [0.21.0](https://github.com/monumental-archive/stele/compare/v0.20.0...v0.21.0) - 2026-11-14

### Breaking

- name what a release published to a registry ([#331](https://github.com/monumental-archive/stele/pull/331))

### Added

- let the newest release answer for superseded ones ([#333](https://github.com/monumental-archive/stele/pull/333))
- name the toolchain in the go-binary inventory ([#334](https://github.com/monumental-archive/stele/pull/334))

### Fixed

- update go-securesystemslib to v0.11.1 ([#272](https://github.com/monumental-archive/stele/pull/272))
- update github.com/sigstore/rekor to v1.5.4 ([#275](https://github.com/monumental-archive/stele/pull/275))
- update protobuf-specs to v0.5.2 ([#278](https://github.com/monumental-archive/stele/pull/278))
- update go-containerregistry to v0.22.0 ([#279](https://github.com/monumental-archive/stele/pull/279))
- update google.golang.org/grpc to v1.83.1 [security] ([#281](https://github.com/monumental-archive/stele/pull/281))
- update golang.org/x/crypto to v0.56.0 [security] ([#282](https://github.com/monumental-archive/stele/pull/282))
- update golang.org/x/mod to v0.41.0 ([#284](https://github.com/monumental-archive/stele/pull/284))
- update go-containerregistry to v0.22.1 ([#287](https://github.com/monumental-archive/stele/pull/287))
- update google.golang.org/grpc to v1.83.2 [security] ([#286](https://github.com/monumental-archive/stele/pull/286))
- update golang.org/x/net to v0.60.0 [security] ([#292](https://github.com/monumental-archive/stele/pull/292))
- update golang.org/x/mod to v0.42.0 ([#295](https://github.com/monumental-archive/stele/pull/295))
- update github.com/github/go-spdx/v2 to v2.7.1 ([#294](https://github.com/monumental-archive/stele/pull/294))
- update jcs to 32a4819 ([#296](https://github.com/monumental-archive/stele/pull/296))
- update certificate-transparency-go to v1.4.0 ([#300](https://github.com/monumental-archive/stele/pull/300))
- update golang.org/x/net to v0.62.0 [security] ([#301](https://github.com/monumental-archive/stele/pull/301))
- update github.com/github/go-spdx/v2 to v2.8.0 ([#304](https://github.com/monumental-archive/stele/pull/304))
- update github.com/klauspost/compress to v1.20.2 [security] ([#305](https://github.com/monumental-archive/stele/pull/305))
- update go.yaml.in/yaml/v3 to v3.0.6 ([#307](https://github.com/monumental-archive/stele/pull/307))
- update golang.org/x/crypto to v0.59.0 [security] ([#309](https://github.com/monumental-archive/stele/pull/309))
- update go.opentelemetry.io/otel/trace to v1.47.0 [security] ([#314](https://github.com/monumental-archive/stele/pull/314))
- update sigstore-go to v1.4.0 ([#306](https://github.com/monumental-archive/stele/pull/306))
- update pkcs7 to a476de3 ([#276](https://github.com/monumental-archive/stele/pull/276))
- update github.com/sigstore/sigstore to v1.11.3 ([#289](https://github.com/monumental-archive/stele/pull/289))
- build on go 1.27.4, clearing a reachable stdlib advisory ([#332](https://github.com/monumental-archive/stele/pull/332))

### Documentation

- show the reuse badge now the repo is registered ([#321](https://github.com/monumental-archive/stele/pull/321))

### Build

- move the Go language version to 1.27 ([#319](https://github.com/monumental-archive/stele/pull/319))

### CI

- run the gate for the merge queue ([#312](https://github.com/monumental-archive/stele/pull/312))

### Dependencies

- update github/codeql-action to v4.37.8 ([#277](https://github.com/monumental-archive/stele/pull/277))
- update github/codeql-action to v4.37.9 ([#283](https://github.com/monumental-archive/stele/pull/283))
- update github/codeql-action to v4.38.0 ([#288](https://github.com/monumental-archive/stele/pull/288))
- update github/codeql-action to v4.38.1 ([#290](https://github.com/monumental-archive/stele/pull/290))
- update github/codeql-action to v4.38.2 ([#291](https://github.com/monumental-archive/stele/pull/291))
- update github/codeql-action to v4.38.3 ([#293](https://github.com/monumental-archive/stele/pull/293))
- update ossf/scorecard-action to v2.5.0 ([#297](https://github.com/monumental-archive/stele/pull/297))
- update github/codeql-action to v4.39.0 ([#299](https://github.com/monumental-archive/stele/pull/299))
- update github/codeql-action to v4.39.1 ([#303](https://github.com/monumental-archive/stele/pull/303))
- update github/codeql-action to v4.39.2 ([#308](https://github.com/monumental-archive/stele/pull/308))
- update github/codeql-action to v4.39.3 ([#310](https://github.com/monumental-archive/stele/pull/310))
- update go to 1.27.3 ([#273](https://github.com/monumental-archive/stele/pull/273))
- update ubuntu to 26.04 ([#298](https://github.com/monumental-archive/stele/pull/298))

## [0.20.0](https://github.com/monumental-archive/stele/compare/v0.19.1...v0.20.0) - 2026-08-24

### Breaking

- type the base-approval scopes and move the epoch to 7 ([#257](https://github.com/monumental-archive/stele/pull/257))

### Added

- expose the previous release derive version resolves ([#256](https://github.com/monumental-archive/stele/pull/256))
- scope a board to one repository, declare coverage ([#259](https://github.com/monumental-archive/stele/pull/259))
- judge every publish surface a repository declares ([#267](https://github.com/monumental-archive/stele/pull/267))

### Fixed

- attribute a policy-load failure to the verb that ran ([#262](https://github.com/monumental-archive/stele/pull/262))
- judge the release plan's changelog splice on every run ([#263](https://github.com/monumental-archive/stele/pull/263))

### Documentation

- record the cardinality defect class in the stranger test ([#255](https://github.com/monumental-archive/stele/pull/255))
- state the current schema epoch in the three stale examples ([#265](https://github.com/monumental-archive/stele/pull/265))

### Testing

- give every test client its own transport ([#244](https://github.com/monumental-archive/stele/pull/244))

## [0.19.1](https://github.com/monumental-archive/stele/compare/v0.19.0...v0.19.1) - 2026-08-20

### Fixed

- name the flag that supplies a declared input ([#240](https://github.com/monumental-archive/stele/pull/240))

### Documentation

- state the store-resident requirement as trust material ([#239](https://github.com/monumental-archive/stele/pull/239))

## [0.19.0](https://github.com/monumental-archive/stele/compare/v0.18.0...v0.19.0) - 2026-08-20

### Breaking

- judge the rebuild targets the caller declared ([#235](https://github.com/monumental-archive/stele/pull/235))

### Added

- join govulncheck findings against the vex decisions ([#224](https://github.com/monumental-archive/stele/pull/224))
- cross-check checksums against the manifest pins ([#232](https://github.com/monumental-archive/stele/pull/232))

### Fixed

- answer a nil decided set from every accessor ([#226](https://github.com/monumental-archive/stele/pull/226))
- excuse a blast-radius finding on status, not existence ([#228](https://github.com/monumental-archive/stele/pull/228))
- credit every exception that matches a finding ([#229](https://github.com/monumental-archive/stele/pull/229))
- type a refused store apart from an empty one ([#227](https://github.com/monumental-archive/stele/pull/227))
- pause a 429 for the wait the host named ([#231](https://github.com/monumental-archive/stele/pull/231))
- derive the signer pin from the chain that signs ([#234](https://github.com/monumental-archive/stele/pull/234))

### Testing

- raise statement coverage from 92.1% to 94.9% ([#238](https://github.com/monumental-archive/stele/pull/238))

## [0.18.0](https://github.com/monumental-archive/stele/compare/v0.17.1...v0.18.0) - 2026-08-20

### Added

- judge and publish this repository's own levels ([#204](https://github.com/monumental-archive/stele/pull/204))
- load one policy document through the engine's own loader ([#212](https://github.com/monumental-archive/stele/pull/212))

### Fixed

- update module golang.org/x/mod to v0.40.0 ([#203](https://github.com/monumental-archive/stele/pull/203))
- read every throttle marker and honour the host's wait ([#213](https://github.com/monumental-archive/stele/pull/213))
- case-fold golang purl names on both sides of the VEX join ([#211](https://github.com/monumental-archive/stele/pull/211))
- key the enrichment demand per artifact ([#215](https://github.com/monumental-archive/stele/pull/215))
- judge the declared tag population, not the ledger's reach ([#218](https://github.com/monumental-archive/stele/pull/218))

## [0.17.1](https://github.com/monumental-archive/stele/compare/v0.17.0...v0.17.1) - 2026-08-20

### Fixed

- retry the host's throttle, refuse only the subject's 403 ([#198](https://github.com/monumental-archive/stele/pull/198))
- drop openpgp from the link by naming the rekor kind ([#200](https://github.com/monumental-archive/stele/pull/200))

## [0.17.0](https://github.com/monumental-archive/stele/compare/v0.16.0...v0.17.0) - 2026-08-20

### Breaking

- `stele emit manifest` requires `--class-subjects`
covering every build subject, and the live-document epoch moves to 6
for the new policy field. The canon's stele pin bump must land with
the workflow edit that passes the flag, and before the policy edit
that declares the epoch. ([#191](https://github.com/monumental-archive/stele/pull/191))
- declare the tag proof floor and the tag it binds from ([#194](https://github.com/monumental-archive/stele/pull/194))

### Changed

- split the repro class scope into two facts ([#192](https://github.com/monumental-archive/stele/pull/192))

### Fixed

- enumerate the permissions join through the roster ([#187](https://github.com/monumental-archive/stele/pull/187))
- rebuild the rekor body a gitsign offline mint omits ([#188](https://github.com/monumental-archive/stele/pull/188))
- record a chain note as the bytes it is, not as JSON ([#195](https://github.com/monumental-archive/stele/pull/195))

### CI

- scope wrapcheck by the package boundary, not by test files ([#190](https://github.com/monumental-archive/stele/pull/190))

### Dependencies

- update github/codeql-action action to v4.37.7 ([#184](https://github.com/monumental-archive/stele/pull/184))

## [0.16.0](https://github.com/monumental-archive/stele/compare/v0.15.0...v0.16.0) - 2026-08-20

### Breaking

- declare the evidence population per repo and track ([#175](https://github.com/monumental-archive/stele/pull/175))
- one verification stance at countersigned instants ([#178](https://github.com/monumental-archive/stele/pull/178))

### Added

- emit the judged plan set for consumers to iterate ([#160](https://github.com/monumental-archive/stele/pull/160))
- type every manifest entry as build subject or evidence ([#162](https://github.com/monumental-archive/stele/pull/162))
- bear the release decision per planned inventory ([#164](https://github.com/monumental-archive/stele/pull/164))
- accept a declared release version ([#166](https://github.com/monumental-archive/stele/pull/166))
- join caller grants to callee permission requirements ([#165](https://github.com/monumental-archive/stele/pull/165))
- derive a VEX decision's affected releases and subjects ([#169](https://github.com/monumental-archive/stele/pull/169))
- judge every walk's exceptions by what it checked ([#168](https://github.com/monumental-archive/stele/pull/168))
- emit the release decisions as one plan ([#171](https://github.com/monumental-archive/stele/pull/171))
- publish the whole level board and own what replaces what ([#176](https://github.com/monumental-archive/stele/pull/176))

### Fixed

- hold a tag certificate at issuance, not the tagger clock ([#172](https://github.com/monumental-archive/stele/pull/172))
- update module github.com/sigstore/sigstore to v1.10.9 ([#179](https://github.com/monumental-archive/stele/pull/179))
- update module google.golang.org/protobuf to v1.36.12 ([#180](https://github.com/monumental-archive/stele/pull/180))

### Documentation

- execute the schema document's own examples ([#163](https://github.com/monumental-archive/stele/pull/163))
- hold the surface statements to the binary ([#170](https://github.com/monumental-archive/stele/pull/170))
- name the mechanism template in the repo instructions ([#174](https://github.com/monumental-archive/stele/pull/174))

## [0.15.0](https://github.com/monumental-archive/stele/compare/v0.14.0...v0.15.0) - 2026-08-19

### Added

- measure slsa levels from evidence, taking no declaration ([#125](https://github.com/monumental-archive/stele/pull/125))
- walk every population chain, the last evidence-audit bash ([#137](https://github.com/monumental-archive/stele/pull/137))
- judge the reproducibility rebuild with typed verdicts ([#138](https://github.com/monumental-archive/stele/pull/138))
- judge inventory plans against planned obligations ([#142](https://github.com/monumental-archive/stele/pull/142))

### Fixed

- render the level as information, never a judgment ([#135](https://github.com/monumental-archive/stele/pull/135))

### Documentation

- adopter guide with policy floors the test suite executes ([#139](https://github.com/monumental-archive/stele/pull/139))
- bring the repo's front door up to the finished port ([#141](https://github.com/monumental-archive/stele/pull/141))
- say the tool drives releases, not only judges them ([#144](https://github.com/monumental-archive/stele/pull/144))
- restore SLSA to the headline, beside the release engine ([#145](https://github.com/monumental-archive/stele/pull/145))

## [0.14.0](https://github.com/monumental-archive/stele/compare/v0.13.0...v0.14.0) - 2026-08-19

### Added

- variant artifact names, per-entry asset epochs, clone fix ([#127](https://github.com/monumental-archive/stele/pull/127))

## [0.13.0](https://github.com/monumental-archive/stele/compare/v0.12.0...v0.13.0) - 2026-08-19

### Added

- resolve the trusted root through TUF from a pinned anchor ([#108](https://github.com/monumental-archive/stele/pull/108))
- read the enrichment claim as a declared obligation ([#111](https://github.com/monumental-archive/stele/pull/111))
- demand class-keyed enrichment names through one seam ([#123](https://github.com/monumental-archive/stele/pull/123))
- claims, image facts, VEX and per-artifact inventories ([#124](https://github.com/monumental-archive/stele/pull/124))

## [0.12.0](https://github.com/monumental-archive/stele/compare/v0.11.0...v0.12.0) - 2026-08-18

### Added

- bump --check states the release-being-cut as pending ([#116](https://github.com/monumental-archive/stele/pull/116))

## [0.11.0](https://github.com/monumental-archive/stele/compare/v0.10.0...v0.11.0) - 2026-08-18

### Added

- derive manifest obligations from machinery version ([#114](https://github.com/monumental-archive/stele/pull/114))

### Changed

- one schema epoch across live-read documents ([#112](https://github.com/monumental-archive/stele/pull/112))

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
