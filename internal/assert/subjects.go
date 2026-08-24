// Which subjects each target enumerates, and therefore which door of
// the population it opens. One place, because it is the same question
// six times and six answers scattered across six files are six
// chances to answer it differently.
//
// A WALK ENUMERATES BY THE QUESTION IT ASKS (stele#181). A target
// measuring evidence — what a release published, what a ledger
// recorded, what an advisory reached — asks a TRACK question, and a
// repository declared outside that track is invisible to it: not
// measured, not counted, not a finding. A target measuring something
// every repository has whatever it publishes asks no track question
// at all, and reads the roster whole.
//
// This is mechanism knowledge, not org shape: release provenance and
// the verdicts over it are build-track evidence; a source-chain ledger
// and a signed release tag are statements about the source that was
// tagged; an advisory swept out of a released SBOM is dependency
// evidence; and what a workflow may do to a build is none of the
// three, because it is equally true of a repository that publishes
// nothing. No organisation's configuration moves any of them, which
// is exactly why they are in code and the MEMBERSHIP is not.

package assert

import (
	"fmt"
	"strings"

	"github.com/monumental-archive/stele/internal/level"
	"github.com/monumental-archive/stele/internal/population"
)

// Subjects is one target's enumeration: the question it asks the
// population, held in the shape that answers it.
//
// Which door a target opens is decided HERE and nowhere else: a
// caller that could ask a target for its door could branch on the
// answer, and a door decided twice is a door that can be decided
// differently — the defect this type exists to close.
type Subjects struct {
	// track is the SLSA track this target's evidence sits on, and means
	// nothing unless evidence is set. Unexported, so a coverage claim
	// over an evidence target's subjects (chains) takes the same track
	// the walk enumerated by rather than naming one a second time; a
	// second literal is a second fact waiting to disagree.
	track level.Track
	// evidence is whether this target measures evidence at all: the bit
	// the door turns on, and the one nothing reads outside Enumerate.
	evidence bool
}

// onTrack: this target measures evidence, and that evidence sits on
// one SLSA track. Its subjects are the track's bearers.
func onTrack(t level.Track) Subjects { return Subjects{track: t, evidence: true} }

// everyRepository: this target measures something every repository
// has whatever it publishes, so no track scopes it. Its subjects are
// the roster.
func everyRepository() Subjects { return Subjects{} }

// The subjects each target enumerates.
//
//nolint:gochecknoglobals // the question a target asks is a fact of the mechanism, not state
var (
	// EvidenceSubjects: the evidence walk judges what a release
	// published — its bundles, its verdicts, its declared contract.
	EvidenceSubjects = onTrack(level.TrackBuild)
	// ChainsSubjects: the chain-coverage walk judges a source ledger.
	ChainsSubjects = onTrack(level.TrackSource)
	// TagsSubjects: a release tag's tagger, its gitsign signature and
	// the chain link on its target are statements about the source.
	TagsSubjects = onTrack(level.TrackSource)
	// BlastRadiusSubjects: advisories joined to triage decisions over
	// released SBOMs are dependency evidence.
	BlastRadiusSubjects = onTrack(level.TrackDependency)
	// PermissionsSubjects: the caller/callee join reads workflow files,
	// computes a requirement and compares it against a grant. It makes
	// no claim about any release and consumes no attestation, so no
	// track scopes it — and the org that says a repository bears no
	// build evidence must still be able to have its workflow grants
	// audited, which mapping this to a track made unspellable
	// (stele#181, measured at .github#580: the signing repository is
	// source-track only and carries three caller stubs, and forecasting
	// which callers die at the next pin bump is the whole point of
	// asking).
	PermissionsSubjects = everyRepository()
)

// Enumerate opens the population at this target's door.
//
// A population carrying members this run could not look at is refused
// here rather than measured (stele#252). The reclassification a
// declared enumeration coverage performs is real, but it hands the
// caller a shorter list plus a statement about the difference, and
// these targets seal a population sized by what they measured — so
// the statement would go nowhere and the shorter list would read as
// the whole. Refusing is what today's reconciliation already does for
// the same population; naming the repositories is the part that is
// new. A target that grows a vocabulary for an unexercised subject
// stops needing this.
func (s Subjects) Enumerate(pop *population.Set) ([]string, error) {
	if unlooked := s.unexercised(pop); len(unlooked) > 0 {
		return nil, fmt.Errorf(
			"population: %s is outside this run's declared enumeration coverage, and this target has no"+
				" way to report a subject it could not look at — enumerate with a credential that covers it,"+
				" or declare the coverage this run actually has",
			strings.Join(unlooked, " "))
	}

	if !s.evidence {
		return pop.Roster(), nil
	}

	return pop.Members(s.track)
}

// unexercised opens the SAME door for the members this run could not
// look at. Sharing the door decision with Enumerate is the whole
// point: a target that asked the roster and then checked the track's
// unexercised members would be answering two different questions
// about one population.
func (s Subjects) unexercised(pop *population.Set) []string {
	if !s.evidence {
		return pop.UnexercisedRoster()
	}

	return pop.UnexercisedMembers(s.track)
}
