// The blast-radius walk: which published releases ship an affected
// package? Every release's SBOM is scanned and every finding joined
// against the committed VEX decisions by the exact (advisory,
// package, version) triple. The report model carries the bash's
// whole taxonomy as types: a VEX decision is a DECLARED exception
// (its origin is the reviewed statement file), the unfixed
// base-layer background is a DERIVED exception (its remediation is
// the rebuild cadence, not a per-CVE judgment — but an OS finding
// WITH a shipped fix gates like everything else), and a decision
// matching no current finding surfaces as a stale exception: a
// retirement candidate, never an archaeology project.
//
// A decision excuses on its STATUS, never its existence (#222): only
// one that denies the advisory applies is an exit, and that question
// is asked of `vexjoin.Decision.Excuses()` alone. A decision that is
// not an exit is reported as seen — a judgment a human made, stated
// and not silent — over a finding that stays red.
//
// A decision is registered SUBJECT-AGNOSTICALLY (#147): it judges a
// package version, not the release that happens to carry it, so it
// excuses its triple wherever the scan meets it. That is also what
// makes staleness honest here — this walk DISCOVERS rather than
// enumerating obligations, so each scanned subject is recorded as
// swept, and a decision that met nothing across a swept corpus is
// stale by evidence rather than by a fabricated subject.
//
// Which releases an org still answers for is POLICY (`supported`),
// and what follows from the answer is code: where only the newest
// release is supported, a finding on an older one is remediated by
// the upgrade — but only when the upgrade is real. The newest release
// must have been read whole and must not itself carry that advisory
// against that package unexcused; then the older finding is a DERIVED
// exception naming the release that answers it. Anything less and the
// finding gates as it always did. The walk therefore judges after it
// has read everything, never release by release: what an old finding
// amounts to depends on a release the listing may hand over later.

package assert

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/population"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/sbomwalk"
	"github.com/monumental-archive/stele/internal/triage"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

// BlastRadiusPolicy parameterises the scan walk — the triage classes
// are org policy, never code.
type BlastRadiusPolicy struct {
	// OSEcosystems are the ecosystem substrings classed as OS base
	// layers (matched lowercase). Unfixed findings there are the
	// rebuild cadence's input; fixable ones gate.
	OSEcosystems []string `json:"osEcosystems"`
	// Canary is the known-positive the scan must reproduce, or it
	// cannot see. Optional, but an org with any history should pin one.
	Canary *CanaryPolicy `json:"canary,omitempty"`
	// Supported declares which releases the org still answers for.
	// Absent, every published release does and every finding gates —
	// the walk's original reading. SupportedLatestRelease is the
	// roll-forward policy: only each repository's newest stable
	// release receives fixes, so a finding on an older one is answered
	// by the upgrade wherever the newest release proves the upgrade
	// remedies it.
	Supported *string `json:"supported,omitempty"`
}

// SupportedLatestRelease is the one support window this walk knows:
// the newest stable release of each repository, and nothing behind it.
// The vocabulary is open — a second window is a second constant and a
// second derivation, never a reinterpretation of this one.
const SupportedLatestRelease = "latest-release"

// CanaryPolicy names the pinned release and the advisory it must
// yield.
type CanaryPolicy struct {
	Repo     *string `json:"repo"`
	Tag      *string `json:"tag"`
	Advisory *string `json:"advisory"`
}

func (b *BlastRadiusPolicy) validate() error {
	if len(b.OSEcosystems) == 0 {
		return errors.New("blastRadius.osEcosystems is empty — every finding would gate, including the base-layer background")
	}

	if b.Canary != nil {
		for name, f := range map[string]*string{
			"repo": b.Canary.Repo, "tag": b.Canary.Tag, "advisory": b.Canary.Advisory,
		} {
			if f == nil || *f == "" {
				return fmt.Errorf("blastRadius.canary.%s is absent or empty", name)
			}
		}
	}

	if b.Supported != nil && *b.Supported != SupportedLatestRelease {
		return fmt.Errorf(
			"blastRadius.supported is %q — the only support window this walk knows is %q; "+
				"an unrecognised one would be read as either everything or nothing",
			*b.Supported, SupportedLatestRelease,
		)
	}

	return nil
}

// BlastRadius walks one org's SBOMs and seals the triage verdict.
func BlastRadius(
	pol *Policy, pop *population.Set, forge gh.Forge, scanner osv.Scanner, decisions *vexjoin.Decisions,
	j *report.Journal, log Logf,
) (*report.Report, error) {
	if pol.BlastRadius == nil {
		return nil, errors.New("assert: the policy declares no blastRadius section")
	}

	org := pop.Owner()

	repos, err := BlastRadiusSubjects.Enumerate(pop)
	if err != nil {
		return nil, err
	}

	w := &blastWalk{pol: pol.BlastRadius, org: org, decisions: decisions, j: j, log: log}

	// Every recorded decision enters the judgment once, before the
	// scan, and SUBJECT-AGNOSTICALLY: a decision judges a package
	// version, not the release that happens to carry it, so it excuses
	// its triple wherever the scan meets it. One that meets nothing is
	// answered by what the walk swept.
	//
	// Whether it excuses is the DECISION's property, answered by
	// vexjoin's one door (#222): excusing on a decision's existence
	// would let a statement whose status ADMITS the advisory clear the
	// finding it admits. A non-excusing decision is still a judgment a
	// human made and recorded, so it is stated rather than dropped —
	// the finding stays red and the report names the decision seen.
	// The status set is not re-derived here; this asks Excuses().
	var notExcusing []string

	all := decisions.All()

	for i := range all {
		if !all[i].Excuses() {
			notExcusing = append(notExcusing, all[i].Key.String()+"="+all[i].Status)

			continue
		}

		// The assertion an exception must meet is DERIVED from the key,
		// never spelled by hand beside the producer of the finding it
		// excuses (docs/vex-join.md).
		j.Except(report.Declared("", all[i].Key.String(), all[i].Origin))
	}

	walk := &sbomwalk.Walk{
		Org: org, SBOMSuffix: *pol.Evidence.SBOMSuffix, Forge: forge, Scanner: scanner,
	}

	if err := walk.Releases(repos, w.inventory); err != nil {
		return nil, err
	}

	window := w.settle()

	covered := report.PopulationFromListing(w.scanned, "SBOMs scanned")

	facts := []report.Fact{}
	if len(notExcusing) > 0 {
		facts = append(facts, report.Fact{
			Name: "decisionsSeenNotExcusing", Value: strings.Join(notExcusing, " "),
		})
	}

	if len(w.missing) > 0 {
		facts = append(facts, report.Fact{Name: "releasesWithoutSBOM", Value: strings.Join(w.missing, " ")})
	}

	if len(window.withheld) > 0 {
		facts = append(facts, report.Fact{Name: "supersessionWithheld", Value: strings.Join(window.withheld, " ")})
	}

	// What the support window came to, stated rather than left for a
	// reader to re-derive from the findings: which release answers for
	// each repository, and which of those is itself carrying an advisory
	// nothing excuses. The second is the one fact a release decision
	// needs — "would a new release remedy anything?" — and a consumer
	// that worked it out from finding subjects would be choosing the
	// newest release a second way.
	if supported := window.supported(); len(supported) > 0 {
		facts = append(facts, report.Fact{Name: "supportedReleases", Value: strings.Join(supported, " ")})
	}

	if affected := window.affected(); len(affected) > 0 {
		facts = append(facts, report.Fact{Name: "supportedReleasesAffected", Value: strings.Join(affected, " ")})
	}

	return report.Seal("assert blast-radius", pop.Subject(), covered, j,
		w.canary(), report.NoJudgedSet(), facts...), nil
}

type blastWalk struct {
	pol        *BlastRadiusPolicy
	org        string
	decisions  *vexjoin.Decisions
	j          *report.Journal
	log        Logf
	scanned    int
	missing    []string
	canarySeen bool
	// read is every inventory scanned, in walk order, held until the
	// whole corpus is in: a finding's standing can depend on a release
	// read after it.
	read []scannedInventory
	// tags is every release the walk reached per repository, defective
	// or not — the set the newest release is chosen from.
	tags map[string][]string
	// defective marks a release (repo@tag) the walk could not read
	// whole. Such a release proves nothing about what it ships, so it
	// can supersede nothing.
	defective map[string]bool
}

// scannedInventory is one SBOM's classified findings, awaiting the
// judgment that needs the whole corpus.
type scannedInventory struct {
	repo     string
	tag      string
	findings []triage.Finding
}

func (s *scannedInventory) subject() string { return s.repo + "@" + s.tag }

// inventory answers for one thing the shared walk found — the
// blast-radius reading of it. A release with no inventory is recorded
// rather than failed: pre-standup releases predate the obligation,
// and the evidence walk owns the completeness question. A defect the
// walk DID reach is a finding: bytes nothing attests, or a scan that
// read nothing, must never pass for a clean release.
func (w *blastWalk) inventory(inv *sbomwalk.Inventory) error {
	w.reached(inv.Repo, inv.Tag)

	switch inv.Defect {
	case sbomwalk.DefectNoInventory:
		w.missing = append(w.missing, inv.Subject())
		w.defective[inv.Subject()] = true

		return nil
	case sbomwalk.DefectUnattested:
		w.defective[inv.Subject()] = true
		w.j.Check(inv.Subject(), inv.Asset+":unattested").
			Diverged("no attestation in the store covers the downloaded SBOM bytes")

		return nil
	case sbomwalk.DefectZeroPackages:
		w.defective[inv.Subject()] = true
		w.j.Check(inv.Subject(), inv.Asset+":empty-scan").
			Diverged("the SBOM parsed to zero packages — a scan that reads nothing must not report clean")

		return nil
	case sbomwalk.DefectNone:
	}

	w.scanned++
	w.log("assert: blast-radius: %s scanned", inv.Subject())

	// Classified through the SHARED derivation: this walk and the VEX
	// leg must agree on what a finding IS, and two implementations of
	// that drift into disagreeing about whether a release was ever
	// covered (internal/triage).
	pol := &triage.Policy{BaseEcosystems: w.pol.OSEcosystems}

	findings, err := pol.Findings(inv.Report)
	if err != nil {
		return fmt.Errorf("assert: %s: %w", inv.Subject(), err)
	}

	w.read = append(w.read, scannedInventory{repo: inv.Repo, tag: inv.Tag, findings: findings})

	// The inventory was read whole: every advisory on this subject was
	// observed, so one a decision names and the scan did not meet was
	// observed to be ABSENT — which is what makes that decision stale
	// by evidence rather than by a fabricated subject.
	w.j.Swept(inv.Subject())

	w.noteCanary(inv.Repo, inv.Tag, findings)

	return nil
}

// reached records one release the walk visited, once.
func (w *blastWalk) reached(repo, tag string) {
	if w.tags == nil {
		w.tags = map[string][]string{}
		w.defective = map[string]bool{}
	}

	if slices.Contains(w.tags[repo], tag) {
		return
	}

	w.tags[repo] = append(w.tags[repo], tag)
}

// settle judges everything the walk read, now that all of it is in,
// and returns the repositories whose newest release could not answer
// for the older ones.
func (w *blastWalk) settle() supportWindow {
	window := w.supportWindow()

	for i := range w.read {
		w.judge(&w.read[i], window.answers[w.read[i].repo])
	}

	return window
}

// supportWindow is what the declared support policy comes to over the
// corpus the walk read: per repository, the release that answers for
// the older ones — or, by name, why none does.
type supportWindow struct {
	answers  map[string]supportedRelease
	withheld []string
}

// supportedRelease is what a repository's newest release proved: the
// tag, and the (advisory, package) pairs it still carries unexcused.
type supportedRelease struct {
	tag  string
	live map[string]bool
}

// supported renders every release that answers for its repository, as
// repo@tag, sorted.
func (s supportWindow) supported() []string {
	out := make([]string, 0, len(s.answers))
	for repo, a := range s.answers {
		out = append(out, repo+"@"+a.tag)
	}

	sort.Strings(out)

	return out
}

// affected renders the supported releases that carry an advisory
// nothing excuses — the ones only a new release, or a decision, can
// answer.
func (s supportWindow) affected() []string {
	var out []string

	for repo, a := range s.answers {
		if len(a.live) > 0 {
			out = append(out, repo+"@"+a.tag)
		}
	}

	sort.Strings(out)

	return out
}

// supportWindow derives, per repository, the release that answers for
// the older ones — or withholds the answer by name. It is withheld
// wherever the newest release proves nothing: no tag orders as a
// stable version, or the newest one was not read whole. A release the
// walk could not see into is not evidence that an upgrade remedies
// anything.
func (w *blastWalk) supportWindow() supportWindow {
	window := supportWindow{answers: map[string]supportedRelease{}}

	if w.pol.Supported == nil {
		return window
	}

	for repo, tags := range w.tags {
		newest := newestStable(tags)

		switch {
		case newest == "":
			window.withheld = append(window.withheld, repo+"(no release tag orders as a stable version)")
		case w.defective[repo+"@"+newest]:
			window.withheld = append(window.withheld, repo+"@"+newest+"(not read whole)")
		default:
			window.answers[repo] = supportedRelease{tag: newest, live: w.liveOn(repo, newest)}
		}
	}

	sort.Strings(window.withheld)

	return window
}

// liveOn is the set of (advisory, package) pairs one release carries
// that nothing excuses — a decision or the rebuild cadence. The
// version is deliberately not part of the pair: an older release
// shipping the advisory at another version of the package is remedied
// by the upgrade exactly when the newest release is not itself red on
// that advisory in that package.
func (w *blastWalk) liveOn(repo, tag string) map[string]bool {
	live := map[string]bool{}

	for i := range w.read {
		if w.read[i].repo != repo || w.read[i].tag != tag {
			continue
		}

		for _, f := range triage.Join(w.read[i].findings, w.decisions).Undecided {
			live[advisoryPackage(&f)] = true
		}
	}

	return live
}

// advisoryPackage is the pair supersession compares: the advisory and
// the package in its ecosystem's canonical form, both read off the
// key so the identity rule is never spelled here (docs/vex-join.md).
func advisoryPackage(f *triage.Finding) string {
	return f.Key.Advisory() + "\x00" + f.Key.Package()
}

// newestStable picks the greatest stable semantic version among the
// tags, by version order and never by listing order — a forge lists
// by creation time, and a release cut out of order must not become
// the supported one by arriving last. A prerelease is not a release
// an org supports, and a tag that is no version orders nowhere.
func newestStable(tags []string) string {
	var (
		best   *semver.Version
		newest string
	)

	for _, t := range tags {
		v, err := semver.NewVersion(strings.TrimPrefix(t, "v"))
		if err != nil || v.Prerelease() != "" {
			continue
		}

		if best == nil || v.GreaterThan(best) {
			best, newest = v, t
		}
	}

	return newest
}

// judge joins one inventory's findings against the decisions and
// records them. The join is the shared one (internal/triage); what
// this walk adds is the two derived exits — the base-layer background
// and the superseded release.
func (w *blastWalk) judge(inv *scannedInventory, answer supportedRelease) {
	subject := inv.subject()
	split := triage.Join(inv.findings, w.decisions)

	for i := range inv.findings {
		w.record(subject, &inv.findings[i])
	}

	for i := range split.Rebuild {
		// The perpetual base-layer background: no shipped fix anywhere,
		// so remediation is the next build on a refreshed base digest
		// and a per-advisory decision would decide nothing. DERIVED, so
		// a human cannot widen it.
		w.j.Except(report.Derived(subject, split.Rebuild[i].String(),
			"unfixed OS base-layer package: remediation is the next release on a refreshed base digest"))
	}

	// answer is the zero value where the policy declares no support
	// window or the repository's newest release proved nothing. The
	// newest release needs no case of its own: every finding it carries
	// undecided is in its own live set, so it can never supersede
	// itself.
	if answer.tag == "" {
		return
	}

	for i := range split.Undecided {
		f := &split.Undecided[i]
		if answer.live[advisoryPackage(f)] {
			continue
		}

		// DERIVED, like the rebuild exit: nobody writes this down, so
		// nobody can widen it, and it stops holding the moment the
		// newest release carries the advisory itself.
		w.j.Except(report.Derived(subject, f.String(), fmt.Sprintf(
			"superseded release: %s@%s is the supported release and does not carry %s in %s unexcused — "+
				"remediation is the upgrade",
			inv.repo, answer.tag, f.Key.Advisory(), f.Package,
		)))
	}
}

// record adds one finding as a fact carrying no verdict of its own;
// Seal decides what the set of facts amounts to.
func (w *blastWalk) record(subject string, f *triage.Finding) {
	// The finding's ID is the canonical triple — the spelling a
	// decision must use to join it. The detail names the package as
	// the scanner reported it, which is the spelling a reader will
	// find in the manifest; for all but a case-folded ecosystem the
	// two are one string (docs/vex-join.md).
	w.j.Check(subject, f.String()).Diverged(
		fmt.Sprintf("%s affects %s@%s (%s)", f.Key.Advisory(), f.Package, f.Key.Version(), f.Ecosystem),
	)
}

// noteCanary records whether this scan reproduced the declared
// known-positive. A walk that declares one and misses it cannot see,
// which is CANNOT_JUDGE rather than a pass.
func (w *blastWalk) noteCanary(repo, tag string, findings []triage.Finding) {
	if w.pol.Canary == nil || repo != *w.pol.Canary.Repo || tag != *w.pol.Canary.Tag {
		return
	}

	for i := range findings {
		if findings[i].Key.Advisory() == *w.pol.Canary.Advisory {
			w.canarySeen = true

			return
		}
	}
}

func (w *blastWalk) canary() report.Canary {
	if w.pol.Canary == nil {
		return report.NoCanary()
	}

	key := *w.pol.Canary.Advisory + " in " + *w.pol.Canary.Repo + "@" + *w.pol.Canary.Tag
	if w.canarySeen {
		return report.CanarySeen(key)
	}

	return report.CanaryMissed(key)
}
