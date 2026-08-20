// Package population is the one place a repository population is
// enumerated, and the only place a rule about membership is applied.
//
// The org's shape is the org's to state. Which repositories bear
// evidence, and on which SLSA tracks, is a POLICY fact — a signing
// workflow repository that will never publish a release owes nothing
// on the build track, and an engine that decided otherwise from its
// own listing would be asserting a fact about the world from one
// organisation's configuration (stele#153).
//
// Two vocabularies meet here and must never merge. An EXCLUSION says
// a repository owes nothing: it produces no member, no finding, no
// count and no cell — silence, because there is nothing to say. An
// exception (declared elsewhere, in the assert policy and the debt
// file) says a repository owes something it has not got: dated,
// removal-conditioned, and loud until resolved. The schema here
// cannot express the second, which is what keeps "outside the scope"
// from decaying into "behind on the work".
//
// The reconciliation is the other half. A credential that cannot see
// a repository makes a walk run short and PASS — a clean check
// indistinguishable from no check — so a declared population is
// checked against the listing in both directions, by NAME. A count
// cannot say which repository went missing; this does.
package population

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/level"
	"github.com/monumental-archive/stele/internal/report"
)

// Declaration is the committed population object: the organisation's
// own statement of which repositories bear evidence, and where.
//
// Absent, the DEFAULT PREDICATE stands alone — archived repositories
// and forks are out, everything the listing shows is in, on every
// track. That default is what a uniform organisation needs and what a
// stranger gets with no configuration at all; declaring this object
// replaces it with a roster, and a roster is closed.
type Declaration struct {
	// Repositories is the roster. Every repository the listing shows
	// that the default predicate would admit must appear here, and
	// every entry here must appear in the listing — the reconciliation
	// runs both ways.
	Repositories []Entry `json:"repositories"`
}

// Entry is one repository's declared membership.
//
// Tracks is stated POSITIVELY and validated against the track
// vocabulary, so the dangerous direction is closed: a mistyped track
// name is refused at load rather than quietly narrowing a population,
// and a repository can only leave a walk's sight by a statement that
// parsed.
type Entry struct {
	// Repo is the bare repository name within the population's owner.
	Repo *string `json:"repo"`
	// Tracks are the tracks this repository bears evidence on. Absent
	// means every track, present and future — the ordinary case, and
	// the one that needs no words. An empty list means none of them.
	Tracks *[]string `json:"tracks,omitempty"`
	// Reason is why the membership is narrower than everything. It is
	// required whenever Tracks is present, because a narrowing nobody
	// wrote a reason for is indistinguishable from a mistake, and this
	// is the one field that tells a later reader which it was.
	Reason *string `json:"reason,omitempty"`
}

// Validate refuses a declaration that cannot mean what it says.
func (d *Declaration) Validate() error {
	if d == nil {
		return nil
	}

	if len(d.Repositories) == 0 {
		return errors.New(
			"population.repositories is empty — a declared population of nothing cannot be reconciled" +
				" against any listing; omit the section to take the default predicate")
	}

	seen := map[string]bool{}

	for i, e := range d.Repositories {
		if err := e.validate(i); err != nil {
			return err
		}

		if seen[*e.Repo] {
			return fmt.Errorf(
				"population.repositories[%d] names %s twice — one repository, one membership", i, *e.Repo)
		}

		seen[*e.Repo] = true
	}

	return nil
}

func (e Entry) validate(i int) error {
	if e.Repo == nil || *e.Repo == "" {
		return fmt.Errorf("population.repositories[%d].repo is absent or empty", i)
	}

	if strings.Contains(*e.Repo, "/") {
		return fmt.Errorf(
			"population.repositories[%d].repo is %q — name the repository alone;"+
				" the owner is the population's, declared once", i, *e.Repo)
	}

	if e.Tracks == nil {
		return nil
	}

	for _, name := range *e.Tracks {
		if _, ok := level.TrackByName(name); !ok {
			return fmt.Errorf(
				"population.repositories[%d].tracks names %q, which is no track this release judges (%s)"+
					" — a track that does not parse would silently narrow the population",
				i, name, strings.Join(trackKeys(), ", "))
		}
	}

	if e.Reason == nil || *e.Reason == "" {
		return fmt.Errorf(
			"population.repositories[%d].reason is absent or empty — %s bears evidence on fewer tracks"+
				" than the default, and a narrowing nobody wrote a reason for reads as a mistake",
			i, *e.Repo)
	}

	return nil
}

// trackKeys is the vocabulary, spelled for a diagnostic.
func trackKeys() []string {
	tracks := level.Tracks()
	out := make([]string, 0, len(tracks))

	for _, t := range tracks {
		out = append(out, t.Key())
	}

	return out
}

// Scope is what a caller pointed a walk at: an organisation, or
// exactly one repository. Exactly one field is set — the CLI enforces
// the exclusivity, Resolve refuses the impossible combinations it can
// still see.
type Scope struct {
	// Org is the organisation whose listing is the population.
	Org string
	// Repo is a single owner/name population — the single-repository
	// consumer (stele#79): the same walk, the enumeration replaced by
	// the one repository named.
	Repo string
}

// Subject is the report subject a walk over this scope runs under.
func (s Scope) Subject() string {
	if s.Repo != "" {
		return s.Repo
	}

	return s.Org
}

// member is one resolved repository and the tracks it bears evidence
// on. all records "every track, present and future" as its own state
// rather than as a snapshot of today's three: a track added later must
// reach a repository that declared nothing, and must NOT reach one
// that named its tracks — an org that listed them said which it meant.
type member struct {
	name string
	all  bool
	in   map[string]bool
}

func (m member) bears(t level.Track) bool { return m.all || m.in[t.Key()] }

// Set is a resolved population: who is in, per track, and how the set
// was obtained. It is the ONLY thing a walk receives — a walk holds a
// set, never the means to enumerate one, so a second population is
// unrepresentable rather than merely discouraged.
type Set struct {
	owner    string
	subject  string
	declared bool
	members  []member
}

// Owner is the account every member sits under.
func (s *Set) Owner() string { return s.owner }

// Subject is what the sealed report is about.
func (s *Set) Subject() string { return s.subject }

// Members are the repositories that bear evidence on one track, in
// listing order.
//
// An empty result means two opposite things, and the difference is
// which of them the caller declared:
//
//   - DECLARED empty — every member of this scope is outside this
//     track — is a contradiction, returned as an error. The operator
//     pointed a walk at a track their own policy says nobody owes
//     evidence on, and the fix is theirs: stop running that target
//     here. Answering it silently would seal CANNOT_JUDGE with no
//     cause, which reads like a credential that could not look.
//   - UNDECLARED empty — a listing that came back with nobody in it
//     — is exactly the degraded forge stele#69 met on its first day,
//     and it must stay CANNOT_JUDGE with the population at zero.
//     Refusing it would turn an outage into a usage error and lose
//     the population rule that caught it.
func (s *Set) Members(t level.Track) ([]string, error) {
	out := s.bearers(t)

	if s.declared && len(out) == 0 {
		return nil, fmt.Errorf(
			"population: the policy declares %s outside the %s track, and this walk judges %s"+
				" — what owes nothing there has nothing to judge",
			s.subject, t.Key(), t.Key())
	}

	return out, nil
}

// Membership is one repository's place on one track — the unit a
// board of cells is built from.
type Membership struct {
	Repo  string
	Track level.Track
}

// Grid is every (repository, track) pair this population holds, in
// listing order, tracks in the spec's own order.
//
// Its own door, beside Members, because it answers a different
// question. Members is asked BY a walk that named one track, so a
// track nobody is in is a contradiction it must report. Grid is asked
// by a consumer that named no track at all — an empty column is then
// the declaration working, not a contradiction — and having the two
// separately named is what keeps a walk from reaching for the quiet
// one by accident.
func (s *Set) Grid() []Membership {
	var out []Membership

	for _, m := range s.members {
		for _, t := range level.Tracks() {
			if m.bears(t) {
				out = append(out, Membership{Repo: m.name, Track: t})
			}
		}
	}

	return out
}

// Population is the coverage claim a walk over one track seals with.
// A declared population says so — provenance travels with the count,
// because "what a credential happened to show" and "the population
// the organisation declared" are different claims about the same
// number (docs/report-schema.md).
func (s *Set) Population(t level.Track) report.Population {
	n := len(s.bearers(t))
	detail := "repositories in the " + t.Key() + " population"

	if !s.declared {
		return report.PopulationFromListing(n, detail)
	}

	return report.PopulationAgainstDeclared(n, n, detail)
}

// bearers is the membership filter both public readers share, so the
// count a report carries and the list a walk covers can never be two
// different answers to one question.
func (s *Set) bearers(t level.Track) []string {
	out := make([]string, 0, len(s.members))

	for _, m := range s.members {
		if m.bears(t) {
			out = append(out, m.name)
		}
	}

	return out
}

// defaultIn is the default predicate: the membership rule that stands
// where the organisation declares none. Archived repositories and
// forks are out; everything else is in, on every track.
//
// It lives here, not in the forge seam, and a roster entry OVERRIDES
// it — an organisation that keeps auditing a repository it archived
// says so by naming it, and needs no change to this tool to do it.
func defaultIn(r gh.Repo) bool { return !r.Archived && !r.Fork }

// Resolve enumerates the scope into a set, reconciling the listing
// against the declaration when one is declared.
//
// This is the only enumeration in the tool. Everything downstream
// receives the Set.
func (s Scope) Resolve(lister gh.RepoLister, d *Declaration) (*Set, error) {
	// Validated HERE as well as at policy load, so this package is
	// total over its own inputs: every read below dereferences a
	// declaration's pointer fields, and a package that panics on a
	// hand-built value is one a test cannot exercise honestly.
	if err := d.Validate(); err != nil {
		return nil, err
	}

	if s.Repo != "" {
		return s.single(d)
	}

	if s.Org == "" {
		return nil, errors.New("population: neither an organisation nor a repository was named")
	}

	// A forge with no listing seam cannot answer "who is in this
	// organisation", and the honest report of that is its name — not
	// a walk over nobody, which seals CANNOT_JUDGE with no cause and
	// reads like an organisation that owns nothing.
	if lister == nil {
		return nil, fmt.Errorf("population: this forge cannot list %s", s.Org)
	}

	listed, err := lister.ListRepos(s.Org)
	if err != nil {
		return nil, fmt.Errorf("population: listing %s: %w", s.Org, err)
	}

	set := &Set{owner: s.Org, subject: s.Org, declared: d != nil}

	if d == nil {
		for _, r := range listed {
			if defaultIn(r) {
				set.members = append(set.members, member{name: r.Name, all: true})
			}
		}

		return set, nil
	}

	return s.roster(set, listed, d)
}

// single resolves the one-repository scope. The declaration is
// consulted only where it names that repository: the roster is closed
// over an ORGANISATION's listing, and a caller who named a target
// explicitly has not asked this policy whether the target exists —
// which is what lets an adopter point the same walk at a repository
// the canon's roster never heard of.
func (s Scope) single(d *Declaration) (*Set, error) {
	owner, name, ok := strings.Cut(s.Repo, "/")
	if !ok || owner == "" || name == "" {
		return nil, fmt.Errorf("population: %q is not owner/name", s.Repo)
	}

	set := &Set{owner: owner, subject: s.Repo}

	if e, found := entryFor(d, name); found {
		set.declared = true
		set.members = []member{membership(e)}

		return set, nil
	}

	set.members = []member{{name: name, all: true}}

	return set, nil
}

func entryFor(d *Declaration, name string) (Entry, bool) {
	if d == nil {
		return Entry{}, false
	}

	for _, e := range d.Repositories {
		if *e.Repo == name {
			return e, true
		}
	}

	return Entry{}, false
}

// membership turns one entry into the resolved member it declares.
func membership(e Entry) member {
	if e.Tracks == nil {
		return member{name: *e.Repo, all: true}
	}

	in := make(map[string]bool, len(*e.Tracks))
	for _, name := range *e.Tracks {
		in[name] = true
	}

	return member{name: *e.Repo, in: in}
}

// roster resolves an organisation against a declared roster, refusing
// unless the two account for each other exactly.
//
// Both directions are defects and neither is recoverable here. A
// listed repository nobody declared is a repository nobody has said
// anything about — the onboarding signal, working. A declared
// repository the listing does not show is either a credential that
// cannot see it or a roster nobody updated when it was archived or
// deleted; both mean this run does not know its own population, and a
// run that does not know its population cannot judge one.
func (s Scope) roster(set *Set, listed []gh.Repo, d *Declaration) (*Set, error) {
	var undeclared []string

	matched := map[string]bool{}

	for _, r := range listed {
		e, found := entryFor(d, r.Name)
		if !found {
			if defaultIn(r) {
				undeclared = append(undeclared, r.Name)
			}

			continue
		}

		matched[r.Name] = true

		set.members = append(set.members, membership(e))
	}

	var unlisted []string

	for _, e := range d.Repositories {
		if !matched[*e.Repo] {
			unlisted = append(unlisted, *e.Repo)
		}
	}

	if len(undeclared) == 0 && len(unlisted) == 0 {
		return set, nil
	}

	return nil, reconcileError(s.Org, undeclared, unlisted)
}

// reconcileError names every repository the two sides disagree about.
// Names, never a count: a count cannot say which repository went
// missing, and the repository that went missing is the whole finding.
func reconcileError(org string, undeclared, unlisted []string) error {
	sort.Strings(undeclared)
	sort.Strings(unlisted)

	var parts []string

	if len(undeclared) > 0 {
		parts = append(parts, fmt.Sprintf(
			"the listing shows %s, which the declared population does not account for"+
				" (declare each, with its tracks, or with an empty track list and a reason)",
			strings.Join(undeclared, " ")))
	}

	if len(unlisted) > 0 {
		parts = append(parts, fmt.Sprintf(
			"the declared population names %s, which the listing does not show"+
				" (an unseen repository is unchecked, not clean)",
			strings.Join(unlisted, " ")))
	}

	return fmt.Errorf("population: %s does not reconcile with its declaration: %s",
		org, strings.Join(parts, "; "))
}
