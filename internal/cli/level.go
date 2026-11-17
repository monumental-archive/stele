// The level verb: point it at a repository and it answers.
//
// One required flag, and it names the subject: --repo owner/name. No
// clone, no policy, no trusted root, no evidence-layout declaration.
// Every one of those was a thing this tool can find out for itself,
// and requiring them made a universal judge into something you
// configure before it will speak.
//
// --org takes one optional declaration and it is worth stating what
// it can and cannot do. A population declaration decides WHO IS
// ASKED; it can never touch what the answer is (stele#153). Being
// outside the population means a track was never measured for that
// repository — no cell, no number, no finding — which is a different
// claim from a measured shortfall, and the declaration has no
// vocabulary for the second. There is still no route from anything an
// organisation writes down to a rung: internal/level imports no
// policy, this file filters the SUBJECT LIST before any evidence is
// gathered, and a repository that is asked is judged on what the
// platform says about it and nothing else.
//
// What is left here is fetching. Nothing in this file judges: it
// gathers what the forge and the attestation store will give up, hands
// it to internal/level, and prints what came back. If a fetch fails,
// the corresponding evidence is simply absent, and the judge reports
// the requirement as unevaluated rather than as met.

package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	yaml "go.yaml.in/yaml/v4"

	"github.com/monumental-archive/stele/internal/evidence"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/gitfetch"
	"github.com/monumental-archive/stele/internal/gitrepo"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/level"
	"github.com/monumental-archive/stele/internal/pkgtime"
	"github.com/monumental-archive/stele/internal/population"
	"github.com/monumental-archive/stele/internal/verify"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

// The three tracks.
const (
	trackBuild      = "build"
	trackSource     = "source"
	trackDependency = "dependency"
)

// Defaults that make the verb answer with no configuration. Each is
// the ecosystem's own convention, not one organization's: git's notes
// ref, git's usual primary branch.
const (
	defaultNotesRef = "refs/notes/commits"
	defaultBranch   = "refs/heads/main"
)

// maxManifestProbes bounds the search for a release's checksum
// manifest. The manifest is found by CONTENT — an asset whose lines
// parse as sha256sum records — because a name is a convention and
// this tool must not require one. The bound keeps that search from
// downloading a whole release.
const maxManifestProbes = 12

// sha256HexRE is what a sha256sum record's first field looks like.
var sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// The seams, swapped only by test setup.
//
//nolint:gochecknoglobals // test seams, written only by test setup
var (
	clock = time.Now

	newPkgTime = func() pkgtime.Resolver { return pkgtime.New() }
)

// levelArgs is everything the three tracks read.
type levelArgs struct {
	track       string
	repo        string
	org         string
	ref         string
	notesRef    string
	tag         string
	shieldPath  string
	policyPath  string
	jsonOut     bool
	root        rootFlags
	owner, name string
	// surfaces is where this repository publishes, as its population
	// row declared it — nil where nothing was declared, which is not
	// the same as a declared empty set and resolves to the opposite of
	// it (surfaceSet). It says WHERE to look and reaches no verdict.
	surfaces []population.Surface
	// git reads the source track's history, fetched once per
	// repository for the run; nil for the tracks that read none.
	git *gitfetch.Session
}

// levelCmd dispatches `stele level <track>`.
func levelCmd(args []string, stdout, stderr io.Writer) int {
	// A leading flag is the BOARD form: every track at once, published
	// as files under --out-dir. A track argument is the single cell.
	if len(args) > 0 && strings.HasPrefix(args[0], "-") {
		return levelBoard(args, stdout, stderr)
	}

	if len(args) == 0 {
		if _, err := fmt.Fprintln(stderr,
			"stele level: a track is required: build, source or dependency\n"+
				"stele level: or --org with --out-dir <dir> to publish every track as its own document"); err != nil {
			return exitIO
		}

		return exitUsage
	}

	track := args[0]
	switch track {
	case trackBuild, trackSource, trackDependency:
	default:
		if _, err := fmt.Fprintf(stderr, "stele level: unknown track %q (build, source, dependency)\n", track); err != nil {
			return exitIO
		}

		return exitUsage
	}

	la, code := parseLevelArgs(track, args[1:], stderr)
	if code != exitOK {
		return code
	}

	out := &latch{w: stdout}
	if la.jsonOut {
		out = &latch{w: stderr}
	}

	if la.track == trackSource {
		la.git = newGitSession(la.sourceWant(), out.logf)
		if err := la.git.Check(); err != nil {
			if _, werr := fmt.Fprintf(stderr, "stele level %s: %v\n", la.track, err); werr != nil {
				return exitIO
			}

			return exitUsage
		}
		defer closeSession(la.git, stderr)
	}

	assessment := la.assess(out)

	subject := la.repo
	if subject == "" {
		subject = la.org
	}

	out.logf("level: %s %s: %s %s [%s]",
		la.track, subject, assessment.Track().Name(), assessment.Level(), assessment.Ladder())

	if out.err != nil {
		return exitIO
	}

	if la.shieldPath != "" {
		// Rendered beside the report from the same seal, so no copy of
		// the level can drift from another.
		if code := writeDoc(la.shieldPath, assessment.Shield().Encode); code != exitOK {
			return code
		}
	}

	return emitReport(assessment.Report(), la.jsonOut, stdout, stderr)
}

// parseLevelArgs parses flags. Only --repo is required, and it names
// what to look at rather than what to expect.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseLevelArgs(track string, args []string, stderr io.Writer) (*levelArgs, int) {
	la := &levelArgs{track: track}

	fs := flag.NewFlagSet("stele level "+track, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&la.repo, "repo", "", "owner/repo to measure (this or --org)")
	fs.StringVar(&la.org, "org", "", "organisation whose repositories to measure (this or --repo)")
	fs.BoolVar(&la.jsonOut, "json", false, "emit the judgment as one JSON report document on stdout")
	fs.StringVar(&la.shieldPath, "shield", "", "write a shields.io endpoint document for this judgment here")
	fs.StringVar(&la.ref, "ref", defaultBranch, "fully qualified branch ref to measure")
	fs.StringVar(&la.notesRef, "notes-ref", defaultNotesRef, "fully qualified notes ref carrying the source chain")
	fs.StringVar(&la.tag, "tag", "", "release to measure (default: the repository's highest released version)")
	fs.StringVar(&la.policyPath, "policy", "",
		"assert policy whose declared population scopes --org (membership only: no declaration reaches a verdict)")
	la.root.register(fs)

	if err := fs.Parse(args); err != nil {
		return nil, exitUsage
	}

	fail := func(msg string) (*levelArgs, int) {
		if _, werr := fmt.Fprintf(stderr, "stele level %s: %s\n", track, msg); werr != nil {
			return nil, exitIO
		}

		return nil, exitUsage
	}

	switch {
	case la.repo != "" && la.org != "":
		// Two populations is two questions; answering one and labelling
		// it the other is how a measurement stops meaning anything.
		return fail("--repo and --org name two different populations — choose one")
	case la.repo != "" && la.policyPath != "":
		// A declared population is a statement about an organisation's
		// listing. Over the one repository a caller named, it can only
		// veto the question that was asked — so it is refused rather
		// than reinterpreted (the stele#79 shape).
		return fail("--policy declares a population and --repo already is one — the declaration cannot apply")
	case la.org != "":
		la.owner = la.org

		return la, exitOK
	case la.repo == "":
		return fail("--repo or --org is required")
	}

	owner, name, ok := strings.Cut(la.repo, "/")
	if !ok || owner == "" || name == "" {
		return fail("--repo must be owner/repo")
	}

	la.owner, la.name = owner, name

	return la, exitOK
}

// assessOrg measures every repository in the organisation's
// population for this track and folds the results.
//
// The population is the listing, narrowed by whatever the
// organisation declared about it (stele#153) — a repository that
// bears no evidence on this track is not measured here, because a
// cell that can never be filled reads as a gap forever and an
// organisation learns to stop reading a board that is permanently
// amber. What it is NOT is an excuse: a repository that is asked is
// measured on the platform's own facts, and no declaration can lift
// its rung or hide a shortfall it did establish.
func (la *levelArgs) assessOrg(out *latch) *level.Assessment {
	forge := newForge()

	pop, err := la.members(forge)
	if err != nil {
		out.logf("level: the organisation's population could not be enumerated: %v", err)

		// Sealed rather than measured: a run that does not know who it
		// was asking about has measured nobody, and the report says so
		// with the cause in it rather than only on this log.
		return level.Unenumerated(la.trackValue(), la.org, err, clock())
	}

	members := make([]*level.Evidence, 0, len(pop.members))

	for _, name := range pop.members {
		member := *la
		member.name = name
		member.repo = la.org + "/" + name
		member.surfaces = pop.set.Surfaces(name)

		members = append(members, member.gather(forge, out))
	}

	out.logf("level: measured %d of %s's repositories", len(members), la.org)

	for _, name := range pop.unlooked {
		out.logf("level: %s: not looked at — outside the declared enumeration coverage", name)
	}

	return level.AssessPopulation(la.trackValue(), members, pop.unlooked, clock())
}

// enumerated is one run's population: the members to measure, the
// ones it could not look at, and the set both came out of.
//
// The set travels with them because a second question is asked of it
// per member — where that repository publishes (surfaceSet) — and
// re-resolving a population to ask it would be a second enumeration,
// which is the one thing this tool has exactly one of (stele#153).
type enumerated struct {
	set      *population.Set
	members  []string
	unlooked []string
}

// members enumerates the organisation's population for this track,
// through the one component allowed to enumerate one: the repositories
// to measure, then the ones this run could not look at.
//
// A failure here is not survivable by measuring what happened to
// arrive: a partial listing, or a listing that does not reconcile
// with the declaration, is a run that does not know its own
// population — and AssessPopulation folds an empty population into a
// blind ladder, which is the honest answer to a question nobody could
// ask.
//
// A member outside the declared enumeration coverage is the one thing
// that is neither: the run knows it is there and knows it did not see
// it. It is carried out of here BESIDE the members rather than among
// them, because it is judged on nothing and must lower nobody's rung
// — what it does is keep the fold from being published as though it
// covered the whole population.
func (la *levelArgs) members(forge gh.Forge) (*enumerated, error) {
	var declared *population.Declaration

	if la.policyPath != "" {
		pol, err := loadAssertPolicy(la.policyPath)
		if err != nil {
			// Named here, because this cause travels IN the sealed
			// report and the document carries no other verb.
			return nil, fmt.Errorf("level: %w", err)
		}

		declared = pol.Population
	}

	pop, err := resolvePopulation(population.Scope{Org: la.org}, forge, declared)
	if err != nil {
		return nil, err
	}

	members, err := pop.Members(la.trackValue())
	if err != nil {
		return nil, err
	}

	unlooked := pop.UnexercisedMembers(la.trackValue())
	for i, name := range unlooked {
		// Spelled as the members are, because they end up in one
		// document: a subject named two ways in one report is two
		// subjects to anything reading it.
		unlooked[i] = la.org + "/" + name
	}

	return &enumerated{set: pop, members: members, unlooked: unlooked}, nil
}

// assess gathers what it can and hands it to the judge.
//
// Fetch failures are not returned: they are absences in the evidence,
// and the judge turns an absence into an unevaluated requirement. A
// tool that refused to answer because one read failed would be less
// useful than one that answers with the gap named.
func (la *levelArgs) assess(out *latch) *level.Assessment {
	if la.org != "" {
		return la.assessOrg(out)
	}

	return level.Assess(la.trackValue(), la.gather(newForge(), out))
}

// gather fetches one repository's evidence for the selected track.
func (la *levelArgs) gather(forge gh.Forge, out *latch) *level.Evidence {
	ev := &level.Evidence{
		Owner: la.owner, Repo: la.name, Ref: la.ref, Now: clock(),
	}

	switch la.track {
	case trackSource:
		la.gatherSource(ev, forge, out)
	case trackBuild:
		la.gatherBuild(ev, forge, out)
	case trackDependency:
		la.gatherDependency(ev, forge, out)
	}

	return ev
}

func (la *levelArgs) trackValue() level.Track {
	switch la.track {
	case trackBuild:
		return level.TrackBuild
	case trackDependency:
		return level.TrackDependency
	default:
		return level.TrackSource
	}
}

// gatherSource reads the branch and its chain from the history it
// fetches itself (stele#384) — no checkout, no source, and no
// declaration of who ought to have signed.
//
// A history that could not be fetched is an absence, not a refusal:
// the requirements that need no chain are still measured, and the
// ones that do stay unevaluated with the fetch's own words logged.
func (la *levelArgs) gatherSource(ev *level.Evidence, forge gh.Forge, out *latch) {
	if la.git == nil {
		out.logf("level: no git reader was bound, so the source history cannot be read")

		return
	}

	hist, herr := la.git.Repo(la.owner, la.name)
	if herr != nil {
		out.logf("level: %s: history unreadable: %v", la.ref, herr)
	} else {
		ev.HistoryFetch = &level.HistoryFetch{FilterIgnored: la.git.IgnoredFilter(la.owner, la.name)}
		la.gatherRevisions(ev, hist, out)
	}

	ev.Live = la.liveRules(forge, out)

	measurer, code := la.measurer(out)
	if code != exitOK {
		return
	}

	if herr != nil {
		out.logf("level: the source chain could not be measured: %v", herr)
	} else {
		la.measureChain(ev, hist, measurer, out)
	}

	la.gatherApprovals(ev, forge, out)
}

// gatherRevisions reads the measured branch's whole first-parent line.
func (la *levelArgs) gatherRevisions(ev *level.Evidence, hist *gitrepo.Repo, out *latch) {
	revs, err := hist.Revisions(la.ref, time.Time{})
	if err != nil {
		out.logf("level: %s: history unreadable: %v", la.ref, err)
	}

	for _, r := range revs {
		ev.Revisions = append(ev.Revisions,
			level.Revision{ID: r.ID, Subject: r.Subject, Parents: r.Parents, Time: r.Time})
	}
}

// measureChain measures the branch's source chain from its tip.
func (la *levelArgs) measureChain(ev *level.Evidence, hist *gitrepo.Repo, measurer verify.Measurer, out *latch) {
	measured, err := verify.MeasureChain(
		verify.Coords{Owner: la.owner, Repo: la.name}, la.ref, hist, measurer, out.logf,
	)

	switch {
	case errors.Is(err, verify.ErrNoChain):
		ev.NoChain = true
	case err != nil:
		out.logf("level: the source chain could not be measured: %v", err)
	default:
		ev.Measured = measured
		out.logf("level: measured %d link(s), signed by %v", measured.Links(), measured.Signers())
	}
}

// sourceWant is what the source track fetches: the measured branch
// commits-only and the ledger whole.
func (la *levelArgs) sourceWant() gitfetch.Want {
	return gitfetch.Want{Branches: []string{la.ref}, NotesRef: la.notesRef}
}

// maxApprovalReads bounds the review-history walk. Two API reads per
// revision over an unbounded history is a walk that never ends on an
// old repository; hitting the bound is logged and leaves the map nil,
// which the judge reports as unevaluated — never as a pass.
const maxApprovalReads = 200

// gatherApprovals reads, for each revision, how many distinct trusted
// persons the forge's own review history says agreed to it — the
// source track's level-four evidence.
//
// Skipped when the recorded control plus the forge's live rules
// already settle the judgment: that pair is stronger evidence (a
// contemporaneous record, corroborated), and reading a whole review
// history to re-answer a settled question is cost without sight.
func (la *levelArgs) gatherApprovals(ev *level.Evidence, forge gh.Forge, out *latch) {
	if recordSettlesReview(tipProperties(ev), ev.Live) {
		return
	}

	reader, ok := forge.(gh.ApprovalsReader)
	if !ok {
		out.logf("level: this forge cannot serve review history")

		return
	}

	if len(ev.Revisions) == 0 {
		return
	}

	if len(ev.Revisions) > maxApprovalReads {
		out.logf("level: %d revisions exceed the %d-read bound for review history, so two-party review"+
			" stays unevaluated", len(ev.Revisions), maxApprovalReads)

		return
	}

	approvals := make(map[string]int, len(ev.Revisions))

	for _, r := range ev.Revisions {
		parties, found, err := reader.Approvals(la.owner, la.name, r.ID)
		if err != nil {
			out.logf("level: review history for %.12s unreadable: %v", r.ID, err)

			continue // absent from the map, which the judge reads as unevaluated
		}

		if found {
			approvals[r.ID] = parties
		}
	}

	ev.Approvals = approvals
	out.logf("level: review history read for %d of %d revision(s)", len(approvals), len(ev.Revisions))
}

// tipProperties lists the controls the measured tip records, empty
// when no tip was reached.
func tipProperties(ev *level.Evidence) []string {
	if ev.Measured == nil {
		return nil
	}

	tip, ok := ev.Measured.Tip()
	if !ok {
		return nil
	}

	return tip.Properties()
}

// recordSettlesReview reports whether the tip's recorded two-party
// control, corroborated by the forge's live rules, already answers the
// review question.
func recordSettlesReview(props []string, live *level.LiveRules) bool {
	if live == nil || live.RequiredApprovals < 1 {
		return false
	}

	for _, got := range props {
		if level.SameControl(got, "SLSA_SOURCE_SCS_TWO_PARTY_REVIEW") {
			return true
		}
	}

	return false
}

// liveRules reads the forge's own effective rules for the measured
// branch — the platform's independent statement of what is enforced
// NOW. A chain link's recorded controls are written by the
// repository's own workflow, so the judge holds a control rung only
// where this answer corroborates the record; nil (an unreadable read)
// leaves those rungs unevaluated rather than letting a repository's
// record about itself stand alone.
func (la *levelArgs) liveRules(forge gh.Forge, out *latch) *level.LiveRules {
	reader, ok := forge.(gh.RulesReader)
	if !ok {
		out.logf("level: this forge cannot serve branch rules, so recorded controls have no corroboration")

		return nil
	}

	branch := strings.TrimPrefix(la.ref, "refs/heads/")

	live, err := gh.EnforcedControls(reader, la.owner, la.name, branch)
	if err != nil {
		out.logf("level: %s: effective rules unreadable, so recorded controls have no corroboration: %v",
			branch, err)

		return nil
	}

	out.logf("level: %s: forge rules: restrictive=%t force-push-blocked=%t required-approvals=%d",
		branch, live.Restrictive, live.ForcePushBlocked, live.RequiredApprovals)

	return live
}

// gatherBuild gathers the build track over every surface this
// repository publishes on, as gatherDependency does: one
// level.PublishSurface per declared surface, each saying what was
// missing on it, and NO fallback from one surface to another. A
// release that answered never stands in for a stream that could not
// be read; the detectors ask the coverage question before they count
// a single artifact.
func (la *levelArgs) gatherBuild(ev *level.Evidence, forge gh.Forge, out *latch) {
	for _, s := range la.surfaceSet() {
		surface := level.PublishSurface{Name: s.Name()}

		switch *s.Kind {
		case population.SurfaceRelease:
			la.buildOnRelease(ev, &surface, forge, out)
		case population.SurfaceContinuousDigest:
			la.buildOnContinuous(ev, &surface, s, forge, out)
		}

		ev.PublishSurfaces = append(ev.PublishSurfaces, surface)
	}

	// The capability boundary is a question about the certificate's
	// signing workflow, whichever surface the artifact came from.
	ev.SignerRunsTenantCode = la.capabilityBoundary(forge)
}

// buildOnRelease gathers the release surface: the newest release's
// artifacts and the platform claims behind each one's provenance.
func (la *levelArgs) buildOnRelease(
	ev *level.Evidence, surface *level.PublishSurface, forge gh.Forge, out *latch,
) {
	tag, subjects, missing := la.releaseSubjects(forge, out)
	if tag == "" {
		surface.Missing = append(surface.Missing, missing)

		return
	}

	measurer, code := la.measurer(out)
	if code != exitOK {
		surface.Missing = append(surface.Missing, noTrustMaterial)

		return
	}

	files, registry := 0, 0
	measured := make([]level.Subject, 0, len(subjects))

	for _, sub := range subjects {
		s := level.Subject{Name: sub.name}

		bundles, err := forge.Attestations(la.owner, la.name, sub.digest)
		if err != nil {
			// A read error is never evidence about the artifact: the
			// store was not seen, so the surface is unreached. The
			// remaining subjects are still read, so the account names
			// every digest that failed.
			out.logf("level: attestations of %s unreadable: %v", shortDigest(sub.digest), err)
			surface.Missing = append(surface.Missing, fmt.Sprintf(
				"the attestation store could not be read for %s (%s): %v", sub.name, sub.digest, err,
			))

			continue
		}

		// The release surface declares no signer: whose provenance a
		// release carries is the certificate's to say, and the
		// detectors read it from there.
		la.measureProvenance(measurer, &s, bundles, sub.digest, nil)

		if !s.Verified && sub.listed {
			// No BUILD PROVENANCE for this digest. Before calling that a
			// breach, ask what the asset IS: a release ships evidence
			// documents beside its artifacts, and a bundle cannot carry
			// provenance about itself. The fetch is paid only for these
			// anomalies, and the answer comes from the bytes rather than
			// from a naming convention. A registry subject skips it:
			// the release's own manifest typed it an artifact, and
			// there is no asset to fetch; so does a file the release
			// does not list, for the same reason.
			evidenceDoc, err := la.evidenceDocument(forge, tag, sub.name)
			if err != nil {
				// Unverified artifact or evidence about the release:
				// this run cannot say which, and only the first would
				// refute.
				surface.Missing = append(surface.Missing, unreadAsset(tag, sub.name, err))

				continue
			}

			if evidenceDoc {
				out.logf("level: %s is an evidence document, not a build subject", sub.name)

				continue
			}
		}

		if sub.registry {
			registry++
		} else {
			files++
		}

		measured = append(measured, s)
	}

	if len(surface.Missing) > 0 {
		// A partial population is not judged: the coverage guard
		// exists so a rung is never sealed across artifacts this run
		// knowingly did not see (stele#252).
		out.logf("level: release %s: %d read(s) did not finish, so no artifact is judged",
			tag, len(surface.Missing))

		return
	}

	ev.Subjects = append(ev.Subjects, measured...)

	out.logf("level: release %s: %d artifact(s) measured (%d file, %d registry)",
		tag, files+registry, files, registry)
}

// noTrustMaterial is the absence a surface reports when no trust root
// could be resolved: nothing the store holds could be proven, which is
// a statement about this run's sight and never about the publish.
const noTrustMaterial = "no trust material could be resolved, so nothing the store holds could be proven"

// measureProvenance finds the artifact's BUILD PROVENANCE among the
// bundles the store holds for its digest. A non-nil signer keeps only
// bundles whose certificate identity it matches — the declared
// identity of a surface that names one; it decides WHOSE bundles are
// read, never what they prove.
//
// Selecting by predicate type matters: a digest carries several
// attestations — provenance, the verdict summarising it, the build
// enrichment — and taking whichever verified first read the build
// track's facts off whatever the store happened to return, which is
// how a verifier's identity ended up standing in for a builder's.
func (la *levelArgs) measureProvenance(
	m verify.Measurer, s *level.Subject, bundles []jsonx.Raw, digest string, signer *regexp.Regexp,
) {
	for _, raw := range bundles {
		verified, err := m.MeasureAttestation(raw, digest)
		if err != nil {
			continue
		}

		if signer != nil && !signer.MatchString(verified.SAN) {
			continue // somebody else's signature over these bytes: not this surface's evidence
		}

		buildType, unrecognised, isProvenance := provenanceShape(verified.Payload)
		if !isProvenance {
			continue
		}

		s.Verified = true
		s.Cert = verified.Extensions
		s.BuildType, s.UnrecognisedParameters = buildType, unrecognised

		return
	}
}

// evidenceDocument reports whether a release asset is evidence ABOUT
// the release rather than an artifact OF it — an attestation bundle,
// an inventory, a triage decision, a digest manifest. Judged from the
// bytes: every one of these formats names itself. A read error is
// returned, never answered: "could not read it" and "it is an
// artifact" are different facts, and only the second can refute.
func (la *levelArgs) evidenceDocument(forge gh.Forge, tag, name string) (bool, error) {
	raw, err := forge.Asset(la.owner, la.name, tag, name)
	if err != nil {
		return false, err
	}

	if len(parseDigestManifest(string(raw))) > 0 {
		return true, nil
	}

	// Each format names itself. A release's evidence is JSON that
	// declares what it is; its artifacts are the bytes a build
	// produced. Recognising a format is not a naming convention — the
	// marker is inside the document, so a producer may call the file
	// anything.
	for _, marker := range [][]byte{
		[]byte(`"dsseEnvelope"`), []byte(`"payloadType"`), // an attestation bundle
		[]byte(`"spdxVersion"`), []byte(`"bomFormat"`), // an inventory
		[]byte("openvex.dev/ns"),                  // a triage decision
		[]byte(`"classes"`), []byte(`"storeVsa"`), // an evidence manifest
	} {
		if bytes.Contains(raw, marker) {
			return true, nil
		}
	}

	return false, nil
}

// unreadAsset is the account a release surface owes for an asset it
// had to read to tell an artifact from evidence about the release, and
// could not.
func unreadAsset(tag, name string, err error) string {
	return fmt.Sprintf("release %s: asset %s could not be read, so whether it is an artifact or evidence"+
		" about the release is unknown: %v", tag, name, err)
}

// provenanceShape reads what the build declared about itself: the
// buildType, and any externalParameter the buildType's published
// schema does not describe. A parameter outside the schema is one a
// consumer cannot form an expectation about, which is what the
// completeness requirement is for.
//
//nolint:gocritic // unnamedResult: buildType, unrecognised keys, whether this is provenance at all
func provenanceShape(statement []byte) (string, []string, bool) {
	stmt, err := jsonx.DecodeForeign[provenanceStatement](statement)
	if err != nil || stmt.PredicateType == nil || !strings.HasPrefix(*stmt.PredicateType, provenancePredicate) {
		return "", nil, false
	}

	if stmt.Predicate == nil || stmt.Predicate.BuildDefinition == nil {
		return "", nil, true
	}

	def := stmt.Predicate.BuildDefinition
	if def.BuildType == nil {
		return "", nil, true
	}

	known := buildTypeSchemas[*def.BuildType]
	if known == nil {
		// A buildType this tool has no schema for: its parameters
		// cannot be judged, so none are reported unrecognised. The
		// detector turns an unknown buildType into UNDETERMINED.
		return "", nil, true
	}

	var unrecognised []string

	for key := range def.ExternalParameters {
		if !slices.Contains(known, key) {
			unrecognised = append(unrecognised, key)
		}
	}

	sort.Strings(unrecognised)

	return *def.BuildType, unrecognised, true
}

// provenancePredicate is the SLSA build provenance predicate type, the
// spec's own identifier for "this document describes how an artifact
// was built".
const provenancePredicate = "https://slsa.dev/provenance/v"

// provenanceStatement is the minimal read of a build provenance
// statement the build track needs.
type provenanceStatement struct {
	PredicateType *string `json:"predicateType"`
	Predicate     *struct {
		BuildDefinition *struct {
			BuildType          *string              `json:"buildType"`
			ExternalParameters map[string]jsonx.Raw `json:"externalParameters"`
		} `json:"buildDefinition"`
	} `json:"predicate"`
}

// buildTypeSchemas is the published parameter schema of each buildType
// this tool can judge — the buildType's own specification, not an
// organisation's expectation. A buildType absent here is unjudged
// rather than assumed complete.
//
//nolint:gochecknoglobals // the schemas are constants; Go has no const map
var buildTypeSchemas = map[string][]string{
	// https://actions.github.io/buildtypes/workflow/v1
	"https://actions.github.io/buildtypes/workflow/v1": {"workflow", "inputs", "vars"},
}

// capabilityBoundary answers whether the workflow that held the
// signing capability executes any caller-controlled step.
//
// This is Build L3's unforgeability requirement, checked rather than
// assumed: the certificate names the workflow and the commit, so the
// workflow's own text at that commit says whether tenant code could
// reach the signing material.
func (la *levelArgs) capabilityBoundary(forge gh.Forge) func(uri, digest string) (bool, error) {
	return func(uri, digest string) (bool, error) {
		owner, repo, path, ok := splitWorkflowURI(uri)
		if !ok {
			return false, fmt.Errorf("the signing identity %q does not name a workflow", uri)
		}

		content, found, err := forge.FileAt(owner, repo, path, digest)
		if err != nil {
			return false, err
		}

		if !found {
			return false, fmt.Errorf("%s carries no %s at %.12s", owner+"/"+repo, path, digest)
		}

		return runsTenantCode(content), nil
	}
}

// splitWorkflowURI breaks a signing identity into the repository and
// path its workflow lives at.
//
//nolint:gocritic // unnamedResult: owner, repo, path, ok
func splitWorkflowURI(uri string) (string, string, string, bool) {
	rest := uri
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}

	rest, _, _ = strings.Cut(rest, "@") // the ref the certificate names
	if i := strings.Index(rest, "/"); i >= 0 {
		rest = rest[i+1:] // drop the host
	}

	const ownerRepoPath = 3

	parts := strings.SplitN(rest, "/", ownerRepoPath)
	if len(parts) < ownerRepoPath || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}

	return parts[0], parts[1], parts[2], true
}

// callerValueRE finds an expansion of a value the caller supplies.
var callerValueRE = regexp.MustCompile(`\$\{\{[^}]*\b(?:inputs|github\.event)\.`)

// workflowSteps is the part of a workflow this check reads: what each
// step runs, and what it resolves an action from.
type workflowSteps struct {
	Jobs map[string]struct {
		Steps []struct {
			Run  string `yaml:"run"`
			Uses string `yaml:"uses"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// runsTenantCode reports whether a workflow executes anything the
// caller decides.
//
// The distinction this makes is the whole point, and getting it wrong
// in either direction is expensive. A caller value expanded INTO a
// run body becomes shell text the caller wrote, in a job holding the
// signing capability. The same value passed through `env:` does not:
// the script reads a variable, and no caller string is ever parsed as
// code. That is the recommended hardening, so a check that flagged it
// would refuse exactly the workflows that got it right — as a first
// regex here did, against a signer whose own comment reads "nothing
// the caller controls is ever expanded into run:".
//
// Hence a parse rather than a pattern: only the `run` and `uses`
// fields are read, which is precisely where caller-controlled code
// would have to appear.
func runsTenantCode(workflow []byte) bool {
	var doc workflowSteps
	if err := yaml.Unmarshal(workflow, &doc); err != nil {
		// Unreadable is not safe: a workflow this check cannot parse is
		// one it cannot clear.
		return true
	}

	for _, job := range doc.Jobs {
		for _, step := range job.Steps {
			if callerValueRE.MatchString(step.Run) || strings.Contains(step.Uses, "${{") {
				return true
			}
		}
	}

	return false
}

// gatherDependency reads which published artifacts carry a published
// inventory beside them — on every surface this repository publishes
// on, and on nothing else.
//
// The surface set is where the defect was. Every detector on this
// track judged a RELEASE, so a repository that publishes rolling
// digests instead of releases was permanently unevaluated no matter
// what its publish path enforced: each answer was correct about what
// it had looked at, and what it had looked at was the release
// surface, hard-coded as the only surface a publish can have
// (stele#249). Which surfaces a repository publishes on is a fact
// about that repository, so it is declared and it is plural.
//
// Every surface is gathered. There is deliberately NO fallback from
// one to another — a repository declaring both is judged on both, and
// a release gather that found nothing may not be quietly answered by
// a continuous one, because absence read as compliance is the failure
// mode that costs more than the missing rung.
func (la *levelArgs) gatherDependency(ev *level.Evidence, forge gh.Forge, out *latch) {
	for _, s := range la.surfaceSet() {
		surface := level.PublishSurface{Name: s.Name()}

		switch *s.Kind {
		case population.SurfaceRelease:
			la.dependencyOnRelease(ev, &surface, forge, out)
		case population.SurfaceContinuousDigest:
			la.dependencyOnContinuous(ev, &surface, s, forge, out)
		}

		ev.PublishSurfaces = append(ev.PublishSurfaces, surface)
	}
}

// surfaceSet is where this repository publishes: what it declared, or
// the default expression where it declared nothing.
//
// The declaration decides WHERE TO LOOK and can reach no further —
// the same line --org already draws (stele#153). internal/level is
// handed evidence and never a policy, so there is no route from
// anything an organisation writes down to a rung; the worst a wrong
// surface can do is send this run to a place with nothing in it,
// which reports as unevaluated with the place named.
func (la *levelArgs) surfaceSet() []population.Surface {
	if la.surfaces == nil {
		return population.DefaultSurfaces()
	}

	return la.surfaces
}

// dependencyOnRelease gathers the release surface: the newest
// release's artifacts, the inventories published beside them, and the
// triage decisions published beside those.
//
// An absence HERE is conclusive, which is why this leg refutes where
// the continuous one cannot. A release's asset list is the complete
// enumeration of what that publish emitted, so an inventory missing
// from it is an inventory the publish did not emit.
func (la *levelArgs) dependencyOnRelease(
	ev *level.Evidence, surface *level.PublishSurface, forge gh.Forge, out *latch,
) {
	tag, subjects, missing := la.releaseSubjects(forge, out)
	if tag == "" {
		surface.Missing = append(surface.Missing, missing)

		return
	}

	assets, err := forge.ReleaseAssets(la.owner, la.name, tag)
	if err != nil {
		out.logf("level: release %s: assets unreadable: %v", tag, err)
		surface.Missing = append(surface.Missing,
			fmt.Sprintf("release %s was found and its assets could not be listed: %v", tag, err))

		return
	}

	invs, unread, stoppedAfter := la.inventories(forge, tag, assets, out)

	// The draft asks that a producer inventory the dependencies of
	// every version they RELEASE. A union document covering the whole
	// release covers each of its artifacts; requiring one document per
	// artifact was this tool inventing a publishing convention, and it
	// refused a release that ships exactly one complete inventory.
	covered := inventoryCovers(invs)

	if !covered {
		// With no covering inventory found, an asset this run could not
		// read might have been it. A read error is never evidence that
		// the release is uninventoried, so the surface is unreached.
		for _, name := range slices.Sorted(maps.Keys(unread)) {
			surface.Missing = append(surface.Missing, fmt.Sprintf(
				"release %s: asset %s could not be read, so whether it is an inventory is unknown: %v",
				tag, name, unread[name],
			))
		}

		// A search the bound stopped is a look not finished: the
		// inventory may be among the assets nobody read. The bound
		// stays — it keeps the search from downloading a release of
		// binaries — and the account tells a producer exactly why the
		// release was not measured.
		if stoppedAfter > 0 {
			surface.Missing = append(surface.Missing, fmt.Sprintf(
				"release %s: stopped looking for an inventory after %d of %d asset(s), so whether the"+
					" release carries one is unknown", tag, stoppedAfter, len(assets),
			))
		}
	}

	var inventoried, uninventoried []string

	for _, sub := range subjects {
		// A registry subject is an artifact by the release's own
		// typing; only a file can be evidence ABOUT the release, and
		// only one the release lists can be read to ask.
		if sub.listed {
			evidenceDoc, err := la.evidenceDocument(forge, tag, sub.name)
			if err != nil && !covered {
				// Uninventoried or evidence about the release: this run
				// cannot say which, and only the first would refute.
				surface.Missing = append(surface.Missing, unreadAsset(tag, sub.name, err))

				continue
			}

			if evidenceDoc {
				continue // evidence about the release, not an artifact of it
			}
		}

		if covered {
			inventoried = append(inventoried, sub.name)

			continue
		}

		uninventoried = append(uninventoried, sub.name)
	}

	if len(surface.Missing) > 0 {
		// A partial population is not judged (stele#252).
		out.logf("level: release %s: %d asset read(s) failed, so no artifact is judged", tag, len(surface.Missing))

		return
	}

	ev.Inventoried = append(ev.Inventoried, inventoried...)
	ev.Uninventoried = append(ev.Uninventoried, uninventoried...)

	out.logf("level: release %s: %d inventoried, %d not", tag, len(ev.Inventoried), len(ev.Uninventoried))

	la.gatherIngestion(ev, forge, tag, invs, out)
	la.gatherTriage(ev, forge, tag, assets, invs, out)
	la.gatherSources(ev, invs)
}

// gatherIngestion resolves, for each dependency the release's
// inventories name, how long its version had been published before the
// release took it. That interval is the observable consequence of an
// ingestion policy, and it is a fact about published artifacts rather
// than a claim about configuration.
func (la *levelArgs) gatherIngestion(
	ev *level.Evidence, forge gh.Forge, tag string, invs map[string][]byte, out *latch,
) {
	released, err := forge.ReleaseDate(la.owner, la.name, tag)
	if err != nil {
		out.logf("level: release %s: publication date unreadable, so ingestion intervals are unknown: %v", tag, err)

		return
	}

	purls := inventoryPurls(invs)
	if len(purls) == 0 {
		return
	}

	intervals := make(map[string]time.Duration, len(purls))
	unresolved := 0
	own := strings.ToLower(la.owner + "/" + la.name)

	for _, purl := range purls {
		// The inventory names the artifact's own module alongside what
		// it depends on. A producer does not ingest its own code, and
		// its publication time is the release's own, so counting it
		// would put every quarantine floor at zero.
		if mentionsModule(purl, own) {
			continue
		}

		when, ok, perr := newPkgTime().Published(purl)
		if perr != nil || !ok {
			unresolved++

			continue
		}

		intervals[purl] = released.Sub(when)
	}

	ev.IngestionIntervals = intervals

	out.logf("level: release %s: %d dependency publication time(s) resolved, %d not",
		tag, len(intervals), unresolved)
}

// gatherTriage scans the release's inventories for known
// vulnerabilities and joins every finding against the triage decisions
// the release publishes beside them. The draft asks that findings be
// TRIAGED, not that a release be free of them, so a decided finding is
// the requirement met.
func (la *levelArgs) gatherTriage(
	ev *level.Evidence, forge gh.Forge, tag string, assets []string, invs map[string][]byte, out *latch,
) {
	decisions := publishedDecisions(la, forge, tag, assets, out)

	scanAndJoin(ev, invs, decisions, "release "+tag, out)
}

// scanAndJoin scans one surface's inventories and joins their findings
// against that surface's published decisions.
//
// Shared by both surfaces on purpose. A release publishes its
// inventory as an asset and a stream publishes it as an attestation
// over the digest, but what "scanned" and "triaged" MEAN cannot differ
// between them — two copies of this join would be two definitions of a
// decided finding, and the rung would quietly mean something different
// depending on where a repository publishes.
func scanAndJoin(
	ev *level.Evidence, invs map[string][]byte, decisions *vexjoin.Decisions, where string, out *latch,
) {
	scanner := newScanner()
	scanned := false

	for name, raw := range invs {
		report, err := scanner.Scan(raw)
		if err != nil {
			out.logf("level: inventory %s could not be scanned: %v", name, err)

			return
		}

		ev.Scanned, scanned = true, true

		found, decided := joinFindings(report, decisions)
		ev.Findings += found
		ev.Triaged += decided
	}

	if scanned {
		out.logf("level: %s: %d advisory finding(s), %d carrying a published decision",
			where, ev.Findings, ev.Triaged)
	}
}

// scanReport is the scanner's output, read for the triple a decision
// matches on.
type scanReport struct {
	Results []struct {
		Packages []struct {
			Package struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				// Read for the join, not for classification: the
				// ecosystem decides whether the name compares
				// case-insensitively (docs/vex-join.md), so a report
				// decoded without it would join a mixed-case package
				// differently from the evidence walk.
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID string `json:"id"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

// joinFindings counts findings and how many carry a decision, on the
// exact (advisory, package, version) triple — the same join the
// evidence walk performs, because a looser match would decide a
// vulnerability nobody looked at.
//
//nolint:gocritic // unnamedResult: found then decided, named in the doc
func joinFindings(report []byte, decisions *vexjoin.Decisions) (int, int) {
	decoded, err := jsonx.DecodeForeign[scanReport](report)
	if err != nil {
		return 0, 0
	}

	var found, decided int

	for _, res := range decoded.Results {
		for _, pkg := range res.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				found++

				if decisions.Has(vexjoin.KeyFromFinding(
					vuln.ID, pkg.Package.Ecosystem, pkg.Package.Name, pkg.Package.Version,
				)) {
					decided++
				}
			}
		}
	}

	return found, decided
}

// publishedDecisions reads the triage decisions a release publishes.
// Found by CONTENT — an OpenVEX document names its own context — so no
// asset naming convention is required of a producer.
//
// Read as PUBLISHED documents (vexjoin.ParsePublished), never as source
// decisions: a release's statement names the shipped artifact and
// decides the dependency inside it, and repeats one decision once per
// artifact it ships. The join is at the grain of the release — a
// finding is triaged when any of these documents decides its triple,
// whichever product the statement names. A statement that cannot join
// is logged by name and the read carries on: a stranger's document may
// speak about things this join does not scan.
func publishedDecisions(la *levelArgs, forge gh.Forge, tag string, assets []string, out *latch) *vexjoin.Decisions {
	decisions := &vexjoin.Decisions{}

	for _, name := range assets {
		raw, err := forge.Asset(la.owner, la.name, tag, name)
		if err != nil || !bytes.Contains(raw, []byte("openvex.dev/ns")) {
			continue
		}

		unjoinable, perr := vexjoin.ParsePublished(decisions, raw, name)
		if perr != nil {
			out.logf("level: triage document %s unreadable: %v", name, perr)

			continue
		}

		logUnjoinable(unjoinable, out)
	}

	return decisions
}

// logUnjoinable names each published statement the join could not
// read, one line apiece — shared by both surfaces so a stream and a
// release report an unusable statement in the same words.
func logUnjoinable(unjoinable []vexjoin.Unjoinable, out *latch) {
	for _, u := range unjoinable {
		out.logf("level: triage document %s", u)
	}
}

// gatherSources reads where the release's dependencies were fetched
// from. An inventory records each package's download location, and a
// location the producer serves is one the producer controls.
func (la *levelArgs) gatherSources(ev *level.Evidence, invs map[string][]byte) {
	sources := map[string]bool{}
	unrecognised := map[string]bool{}
	own := strings.ToLower(la.owner + "/" + la.name)

	for _, raw := range invs {
		doc, derr := jsonx.DecodeForeign[inventoryPackages](raw)
		if derr != nil {
			continue
		}

		for _, pkg := range doc.Packages {
			// A package URL answers this on its own. The purl
			// specification says an absent repository_url qualifier
			// means the ecosystem's DEFAULT public registry — so a bare
			// pkg:golang/… or pkg:cargo/… records a dependency taken
			// straight from upstream, and one carrying repository_url
			// records where the producer actually took it from.
			//
			// That is why this reads purls rather than SPDX download
			// locations: the spec asks where the build fetched from, not
			// that an inventory carry a particular field, and most
			// inventories carry no download location at all.
			where := pkg.source()
			if where == "" {
				continue
			}

			// The inventory names the artifact's own package beside what
			// it depends on. A producer does not fetch its own source
			// from anywhere, so counting it would answer this
			// requirement from a self-reference — which is how one
			// repository read as fully producer-controlled on the
			// strength of a single entry describing itself.
			if pkg.namesModule(own) {
				continue
			}

			switch owns := producerControls(where, la.owner); owns {
			case ownedByProducer:
				sources[where] = true
			case upstreamDefault:
				sources[where] = false
			case unknownHost:
				unrecognised[where] = true
			}
		}
	}

	for where := range unrecognised {
		if !slices.Contains(ev.UnrecognisedSources, where) {
			ev.UnrecognisedSources = append(ev.UnrecognisedSources, where)
		}
	}

	sort.Strings(ev.UnrecognisedSources)

	if len(sources) == 0 && len(unrecognised) == 0 {
		return
	}

	// Merged, never replaced. A repository publishing on two surfaces
	// fetched its dependencies from wherever both of them record, and a
	// second surface that overwrote the first would answer this
	// requirement from whichever gather happened to run last.
	if ev.DependencySources == nil {
		ev.DependencySources = map[string]bool{}
	}

	for where, producerOwned := range sources {
		// A location either surface records as upstream is upstream:
		// this map's true means "the producer controls it", and one
		// publish taking a dependency from upstream is not undone by
		// another taking it from a mirror.
		if was, seen := ev.DependencySources[where]; seen && !was {
			continue
		}

		ev.DependencySources[where] = producerOwned
	}
}

// inventoryPackages is the part of an inventory this check reads: each
// package's identity and where it was fetched from. Read as a
// STRUCTURE rather than scanned for values, because the association
// between a package and its location is the whole question — a
// location lifted out of its package cannot be told apart from the
// artifact's own.
type inventoryPackages struct {
	Packages []inventoryPackage `json:"packages"`
}

// inventoryPackage is one package an inventory records.
type inventoryPackage struct {
	Name             string `json:"name"`
	DownloadLocation string `json:"downloadLocation"`
	ExternalRefs     []struct {
		ReferenceLocator string `json:"referenceLocator"`
	} `json:"externalRefs"`
}

// source names where this package was fetched from, or empty when the
// inventory records nothing that says.
func (p inventoryPackage) source() string {
	for _, ref := range p.ExternalRefs {
		purl := ref.ReferenceLocator
		if !strings.HasPrefix(purl, "pkg:") {
			continue
		}

		if _, qualifiers, found := strings.Cut(purl, "?"); found {
			for q := range strings.SplitSeq(qualifiers, "&") {
				if repo, ok := strings.CutPrefix(q, "repository_url="); ok && repo != "" {
					return repo
				}
			}
		}

		// No qualifier: the ecosystem's default public registry, named
		// by the purl's type so a report says which one.
		if ecosystem, _, ok := strings.Cut(strings.TrimPrefix(purl, "pkg:"), "/"); ok && ecosystem != "" {
			return "the default " + ecosystem + " registry"
		}
	}

	if loc := p.DownloadLocation; loc != "" && loc != "NOASSERTION" && loc != "NONE" && loc != "git+." {
		return loc
	}

	return ""
}

// namesModule reports whether this package IS the artifact rather than
// one of its dependencies.
func (p inventoryPackage) namesModule(own string) bool {
	if mentionsModule(p.Name, own) {
		return true
	}

	for _, ref := range p.ExternalRefs {
		if mentionsModule(ref.ReferenceLocator, own) {
			return true
		}
	}

	return false
}

// mentionsModule reports whether s names the owner/repo module as a
// whole path element — bounded on both sides, so that a dependency
// whose name merely EXTENDS the module's ("acme/widget-utils") is
// never mistaken for the module itself, while its own subpaths and
// versions ("acme/widget/v2", "acme/widget@v1") still match.
func mentionsModule(s, own string) bool {
	lower := strings.ToLower(s)

	for i := 0; ; {
		j := strings.Index(lower[i:], own)
		if j < 0 {
			return false
		}

		j += i

		before := j == 0 || lower[j-1] == '/' || lower[j-1] == ':'
		end := j + len(own)
		after := end == len(lower) || strings.ContainsRune("@/?#", rune(lower[end]))

		if before && after {
			return true
		}

		i = j + 1
	}
}

// forgeHost is the one host this adapter can place namespaces on. On
// it, a namespace either is the producer's or belongs to someone else
// — both answerable. On any other host, ownership cannot be derived
// from a coordinate at all.
const forgeHost = "github.com"

// producerControls reports whether a download location is one the
// producer serves.
//
// The decidable ground is deliberately small. The ecosystem's default
// registry is upstream by definition. On the subject's own forge, the
// namespace segment answers exactly: the producer's namespace is
// theirs, and any other namespace is a location the producer does not
// control. Everywhere else is UNDETERMINED — a producer's private
// mirror and a stranger's server are indistinguishable from a
// coordinate, and a substring match here once handed ownership to any
// URL that happened to carry the producer's name in a path.
func producerControls(location, owner string) ownership {
	lower := strings.ToLower(location)

	// An ecosystem's default registry is upstream by definition: that
	// is what "default" means in the package URL specification.
	if strings.HasPrefix(lower, "the default ") {
		return upstreamDefault
	}

	host, path := splitLocation(lower)
	if host != forgeHost {
		return unknownHost
	}

	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) > 0 && strings.EqualFold(segs[0], owner) {
		return ownedByProducer
	}

	return upstreamDefault
}

// splitLocation breaks a download location into host and path,
// tolerating an absent scheme and a VCS prefix like git+https.
//
//nolint:gocritic // unnamedResult: host then path, named in the doc
func splitLocation(location string) (string, string) {
	if i := strings.Index(location, "://"); i >= 0 {
		location = location[i+3:]
	}

	host, path, _ := strings.Cut(location, "/")
	host, _, _ = strings.Cut(host, ":") // drop a port

	return host, path
}

// ownership is what a run could establish about a dependency source.
type ownership int

const (
	unknownHost ownership = iota
	ownedByProducer
	upstreamDefault
)

// inventories finds the release's dependency inventories BY CONTENT:
// SPDX and CycloneDX documents name themselves inside their bytes, so
// a producer may call the file anything — the same rule the digest
// manifest and the triage documents already follow, because a filename
// is a convention and a universal tool cannot require one.
//
// Name-hinted assets are probed first (they are almost always the
// answer and always small); the rest are probed under a bound so this
// search cannot download a whole release of binaries, and hitting the
// bound is logged rather than silently read as absence.
//
// The second result is every probed asset that could not be read, with
// the error the forge gave: such an asset might have been the
// inventory, and only the caller knows whether that matters. The
// third is how many assets were probed when the bound stopped the
// search having found none, zero when it finished: the assets past the
// bound were not looked at, which is not the same as holding nothing.
//
//nolint:gocritic // unnamedResult: inventories found, assets unread, then where the bound stopped the search
func (la *levelArgs) inventories(
	forge gh.Forge, tag string, assets []string, out *latch,
) (map[string][]byte, map[string]error, int) {
	hinted, rest := splitByInventoryHint(assets)
	found := map[string][]byte{}
	unread := map[string]error{}
	probes := 0

	for _, name := range append(hinted, rest...) {
		if probes >= maxManifestProbes && len(found) == 0 {
			out.logf("level: release %s: stopped looking for an inventory after %d asset(s)", tag, probes)

			return found, unread, probes
		}

		probes++

		raw, err := forge.Asset(la.owner, la.name, tag, name)
		if err != nil {
			unread[name] = err

			continue
		}

		if bytes.Contains(raw, []byte(`"spdxVersion"`)) || bytes.Contains(raw, []byte(`"bomFormat"`)) {
			found[name] = raw
		}
	}

	return found, unread, 0
}

// splitByInventoryHint orders the probe: assets whose names suggest an
// inventory first. The hint decides ORDER, never membership — an
// inventory named anything else is still found by its bytes.
//
//nolint:gocritic // unnamedResult: hinted then rest, named in the doc
func splitByInventoryHint(assets []string) ([]string, []string) {
	var hinted, rest []string

	for _, a := range assets {
		lower := strings.ToLower(a)
		if strings.Contains(lower, "spdx") || strings.Contains(lower, "cyclonedx") ||
			strings.Contains(lower, "sbom") {
			hinted = append(hinted, a)

			continue
		}

		rest = append(rest, a)
	}

	return hinted, rest
}

// inventoryPurls reads the package URLs the release's inventories name.
func inventoryPurls(invs map[string][]byte) []string {
	seen := map[string]bool{}

	var purls []string

	for _, raw := range invs {
		for _, purl := range purlRE.FindAllString(string(raw), -1) {
			if !seen[purl] {
				seen[purl] = true
				purls = append(purls, purl)
			}
		}
	}

	sort.Strings(purls)

	return purls
}

// purlRE finds package URLs in an inventory, whatever document format
// carries them: purl is the one identifier SPDX and CycloneDX share.
var purlRE = regexp.MustCompile(`pkg:[a-zA-Z0-9.+-]+/[^"\s,\]}]+`)

// inventoryCovers reports whether the release publishes an inventory
// that names dependencies. Judged from the document's contents: an
// inventory listing no package inventories nothing.
func inventoryCovers(invs map[string][]byte) bool {
	for _, raw := range invs {
		if purlRE.Match(raw) {
			return true
		}
	}

	return false
}

// releaseSubject is one artifact a release says it published: a file
// its digest manifest pins, or a registry subject its evidence
// manifest names. The two are measured alike; only a file can turn out
// to be an evidence document, because only a file has bytes beside the
// release to read.
type releaseSubject struct {
	// name is the asset's name, or for a registry subject the name its
	// provenance attests joined to its digest — one image name may
	// carry several digests, and each is its own artifact.
	name string
	// digest is bare sha256 hex, the shape the store's door takes.
	digest   string
	registry bool
	// listed is whether the release's asset listing holds this file.
	// Only a listed asset can be read to ask whether it is evidence
	// about the release; a file the digest manifest names and the
	// release does not carry has nothing to read, so no read of it can
	// fail.
	listed bool
}

// releaseSubjects finds the release to measure and the artifacts it
// published: the ONE place the level walk learns what a release
// shipped, so the Build and Dependency legs cannot disagree about it.
// The answer is the union of the files the digest manifest pins and
// the registry subjects the release's own evidence manifest names —
// the release's claim, read, never reconstructed from whatever
// provenance happens to exist.
//
// The third result is the absence to report when there is no release
// to measure. It is returned rather than only logged because a
// dependency judgment now says which surfaces it looked at and what
// was missing on each, and "no release" is one of four different
// facts here — never published, unreadable, assets unreadable, or
// published with nothing naming its artifacts.
//
//nolint:gocritic // unnamedResult: tag, subjects, then the absence to report
func (la *levelArgs) releaseSubjects(forge gh.Forge, out *latch) (string, []releaseSubject, string) {
	tag := la.tag

	if tag == "" {
		tags, err := forge.ReleaseTags(la.owner, la.name)
		if err != nil {
			out.logf("level: releases unreadable: %v", err)

			return "", nil, fmt.Sprintf("this repository's releases could not be listed: %v", err)
		}

		tag = newestRelease(tags)
	}

	if tag == "" {
		out.logf("level: this repository has published no release this tool can order")

		return "", nil, "this repository has published no release this tool can order"
	}

	assets, err := forge.ReleaseAssets(la.owner, la.name, tag)
	if err != nil {
		out.logf("level: release %s: assets unreadable: %v", tag, err)

		return "", nil, fmt.Sprintf("release %s was found and its assets could not be listed: %v", tag, err)
	}

	files := la.findManifest(forge, tag, assets, out)
	subjects := make([]releaseSubject, 0, len(files))

	for _, name := range slices.Sorted(maps.Keys(files)) {
		subjects = append(subjects, releaseSubject{
			name: name, digest: files[name], listed: slices.Contains(assets, name),
		})
	}

	subjects = append(subjects, la.registrySubjects(forge, tag, assets, out)...)

	if len(subjects) == 0 {
		out.logf("level: release %s: no asset lists artifact digests, so its artifacts cannot be located", tag)

		return "", nil, fmt.Sprintf(
			"release %s publishes no asset listing artifact digests, so its artifacts cannot be located", tag,
		)
	}

	return tag, subjects, ""
}

// registrySubjects reads what the release published somewhere other
// than its assets, from the release's own evidence manifest — found BY
// CONTENT, as the digest manifest is, and read through
// evidence.Manifest.RegistrySubjects, the reader the assert walk uses.
//
// A release with no evidence manifest, or one whose schema predates
// registry entries, contributes none, and the walk says so by name.
// It does not read them back out of the bundles: the level judges the
// newest release only, and an old format there is a release to
// re-cut, not a history to excuse.
//
// A search that stopped at its bound without finding a manifest is not
// "no manifest", and it is not a blind surface either: the evidence
// manifest is one publisher family's format, a stranger's release
// never carries one, and so on any release longer than the bound the
// search always ends there. Its files are judged as before; the walk
// says plainly that registry subjects, if any, are not counted
// (stele#373).
func (la *levelArgs) registrySubjects(
	forge gh.Forge, tag string, assets []string, out *latch,
) []releaseSubject {
	doc, stoppedAfter := la.findEvidenceManifest(forge, tag, assets)
	if stoppedAfter > 0 {
		out.logf("level: release %s: stopped looking for an evidence manifest after %d of %d asset(s);"+
			" registry subjects, if the release names any, are not counted", tag, stoppedAfter, len(assets))

		return nil
	}

	var listed []evidence.Asset

	ok := false
	if doc != nil {
		listed, ok = doc.RegistrySubjects()
	}

	if !ok {
		out.logf("level: release %s names no registry subjects (no manifest, or one that predates them)", tag)

		return nil
	}

	subjects := make([]releaseSubject, 0, len(listed))
	for _, a := range listed {
		subjects = append(subjects, releaseSubject{
			name: a.Name + "@sha256:" + a.SHA256, digest: a.SHA256, registry: true,
		})
	}

	return subjects
}

// findEvidenceManifest locates the release's evidence manifest BY
// CONTENT: an asset that parses as one. Assets whose names suggest a
// manifest are probed first — the hint decides ORDER, never
// membership — and the probe is bounded so this search cannot
// download a whole release of binaries. The second result is how many
// assets were probed when the bound stopped the search, zero when it
// finished.
//
//nolint:gocritic // unnamedResult: the manifest, then where the bound stopped the search
func (la *levelArgs) findEvidenceManifest(
	forge gh.Forge, tag string, assets []string,
) (*evidence.Manifest, int) {
	var hinted, rest []string

	for _, a := range assets {
		if strings.Contains(strings.ToLower(a), "manifest") {
			hinted = append(hinted, a)

			continue
		}

		rest = append(rest, a)
	}

	probes := 0

	for _, a := range append(hinted, rest...) {
		if probes >= maxManifestProbes {
			return nil, probes // the caller says what that means
		}

		probes++

		raw, err := forge.Asset(la.owner, la.name, tag, a)
		if err != nil {
			continue
		}

		if doc, err := evidence.Parse(raw); err == nil {
			return doc, 0
		}
	}

	return nil, 0
}

// findManifest locates the release's digest manifest BY CONTENT: an
// asset whose lines parse as sha256sum records. Names are conventions
// and a universal tool cannot require one.
func (la *levelArgs) findManifest(
	forge gh.Forge, tag string, assets []string, out *latch,
) map[string]string {
	probes := 0

	for _, a := range assets {
		if probes >= maxManifestProbes {
			out.logf("level: release %s: stopped looking for a digest manifest after %d asset(s)", tag, probes)

			break
		}

		probes++

		raw, err := forge.Asset(la.owner, la.name, tag, a)
		if err != nil {
			continue
		}

		if got := parseDigestManifest(string(raw)); len(got) > 0 {
			return got
		}
	}

	return nil
}

// parseDigestManifest reads sha256sum records, returning name→digest.
// A document with any non-conforming line is not a manifest: partial
// parsing would invent a subject set.
func parseDigestManifest(text string) map[string]string {
	out := map[string]string{}

	for raw := range strings.Lines(text) {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 2 || !sha256HexRE.MatchString(fields[0]) {
			return nil
		}

		out[strings.TrimPrefix(fields[1], "*")] = fields[0]
	}

	return out
}

// newestRelease picks the highest released version by semver, never
// whichever the listing happened to return first.
func newestRelease(tags []string) string {
	var (
		best   *semver.Version
		newest string
	)

	for _, t := range tags {
		v, err := semver.NewVersion(strings.TrimPrefix(t, "v"))
		if err != nil {
			continue
		}

		if best == nil || v.GreaterThan(best) {
			best, newest = v, t
		}
	}

	return newest
}

// measurer builds the cryptographic boundary. No flag is required: a
// root resolves through TUF from the anchor pinned in this binary.
//
// verifier could name a gating one
//
//nolint:ireturn // the boundary IS an interface — a caller able to name a concrete
func (la *levelArgs) measurer(out *latch) (m verify.Measurer, code int) { //nolint:nonamedreturns // named for the doc
	rootJSON, err := la.root.resolve()
	if err != nil {
		out.logf("level: no trust material could be resolved: %v", err)

		return nil, exitIO
	}

	bv, err := newBundleVerifier(rootJSON)
	if err != nil {
		out.logf("level: the verifier could not be built: %v", err)

		return nil, exitIO
	}

	m, ok := bv.(verify.Measurer)
	if !ok {
		out.logf("level: this verifier cannot measure without an identity")

		return nil, exitIO
	}

	return m, exitOK
}
