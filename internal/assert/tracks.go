// Which SLSA track each target measures. One place, because it is the
// same question six times and six answers scattered across six files
// are six chances to answer it differently.
//
// This is mechanism knowledge, not org shape: release provenance and
// the verdicts over it are build-track evidence; a source-chain ledger
// and a signed release tag are statements about the source that was
// tagged; an advisory swept out of a released SBOM is dependency
// evidence. No organisation's configuration moves any of them, which
// is exactly why they are in code and the MEMBERSHIP is not.
//
// The population reads these to decide who a target covers
// (stele#153): a repository declared outside a track is invisible to
// every target that measures it — not measured, not counted, not a
// finding.

package assert

import "github.com/monumental-archive/stele/internal/level"

// The track each target judges.
//
//nolint:gochecknoglobals // a track is a fact of the spec, not state
var (
	// TrackEvidence: the evidence walk judges what a release published
	// — its bundles, its verdicts, its declared contract.
	TrackEvidence = level.TrackBuild
	// TrackChains: the chain-coverage walk judges a source ledger.
	TrackChains = level.TrackSource
	// TrackTags: a release tag's tagger, its gitsign signature and the
	// chain link on its target are statements about the source.
	TrackTags = level.TrackSource
	// TrackBlastRadius: advisories joined to triage decisions over
	// released SBOMs are dependency evidence.
	TrackBlastRadius = level.TrackDependency
	// TrackPermissions: what a workflow may do to a build is the build
	// track's question, asked before the build rather than after it.
	TrackPermissions = level.TrackBuild
)
