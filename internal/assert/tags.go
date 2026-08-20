// The tag audit (stele#83): for every release tag in the population,
// the tagger is the minting role, the tag carries a signature that
// verifies against the policy identity, and the tag's target carries
// a source chain link. The forge's own verification verdict is never
// consulted — it cannot judge gitsign's x509-in-the-PGP-slot and
// reports every signed tag unsigned (measured).
//
// THE DECLARED EPOCH IS THE POPULATION, and the only selector
// (stele#208). A tag before its repository's epoch is an EXCLUSION:
// the organisation has said it owes nothing there, so it produces
// nothing — no check, no finding, no count. Every tag from the epoch
// onward is a member, and a member is judged or is loudly
// unjudgeable; it is never silently absent. `pending` — declared
// unsigned — puts every release tag in the population and asks none
// of them for a signature.
//
// The ledger's founded genesis bounds ONE obligation, never the
// population (the stele#208 defect: a derived bound doing a
// declaration's job, and moving under the walk when the ledger was
// re-emitted). The chain link is the only thing a ledger can witness,
// and it witnesses from its genesis onward — the oldest link-noted
// revision whose first parent carries no link. For a target the
// genesis does not reach, the missing link is UNKNOWABLE rather than
// defective: the finding is recorded and carries a derived exception
// naming the horizon, so the tag stays visible, stays counted and
// never reddens. Whether a repository founds a chain at all is
// `assert chains`' question, judged there and not a second time here.
//
// Each obligation is its own assertion (`tag:tagger`, `tag:signature`,
// `tag:link`…) rather than one blanket `tags` (#147): an assertion
// names the check that saw the divergence, so a written-down defect
// excuses THAT check on THAT tag and nothing else. An excluded tag
// records no check at all, which is what keeps an excuse for it from
// being called stale by a run that never looked.

package assert

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/population"
	"github.com/monumental-archive/stele/internal/report"
)

// TagVerifier proves one tag signature — the trust boundary behind a
// seam so every guard here stays table-tested; the CLI binds the real
// gitsign verification.
type TagVerifier interface {
	// Verify proves the signature over the payload to at least the
	// given floor and returns the proof it reached.
	//
	// The floor is per TAG, not per run (stele#186): a mint gains the
	// capability to prove more partway through a repository's history,
	// and the tags before that point are not defective. A run-wide
	// floor could only be the lowest any tag can meet, which is a
	// floor nothing rises above.
	Verify(payload, signature []byte, floor string) (TagProof, error)
}

// TagProof is one verified tag signature's verdict: who signed, the
// depth of proof reached, and the countersigned instants it was held
// against (stele#173: the verdict states the depth it reached; the
// policy states the floor it requires).
type TagProof struct {
	// SAN is the certificate identity the signature verified under.
	SAN string
	// Depth is the proof depth reached — at least the declared floor.
	Depth string
	// Observed names every countersigned instant and the log that
	// carries it, human-readable.
	Observed string
}

// The tag audit's assertions: one per obligation, so an exception can
// name the single check it excuses.
const (
	assertTagEpoch     = "tag:epoch"
	assertTagAnnotated = "tag:annotated"
	assertTagTagger    = "tag:tagger"
	assertTagSignature = "tag:signature"
	assertTagLink      = "tag:link"
)

// linkNote is the shape test distinguishing a chain link from
// scaffolding notes: version and a provenance bundle, both present.
type linkNote struct {
	Version    *int `json:"version"`
	Provenance *struct {
		Bundle jsonx.Raw `json:"bundle"`
	} `json:"provenance"`
}

// Tags walks the population's release tags and seals the verdict.
// runFacts are the caller's facts about the run itself — the trust
// material it held, which the walk cannot know.
func Tags(
	pol *Policy, pop *population.Set, tags gh.TagReader, tv TagVerifier, j *report.Journal, log Logf,
	runFacts ...report.Fact,
) (*report.Report, error) {
	tp := pol.Tags
	if tp == nil {
		return nil, errors.New("assert: the policy declares no tags section")
	}

	repos, err := TagsSubjects.Enumerate(pop)
	if err != nil {
		return nil, err
	}

	w := &tagsWalk{
		pol: tp, org: pop.Owner(), tags: tags, tv: tv, j: j, log: log,
		tagRE: regexp.MustCompile(*tp.TagPattern), floors: map[string]int{},
	}

	for _, repo := range repos {
		if err := w.repo(repo); err != nil {
			return nil, err
		}
	}

	facts := append(append([]report.Fact{}, runFacts...), w.reconciliation()...)

	// A raised floor is only proven by a run that PROVED tags on both
	// sides of it, so the run reports how many it proved at each —
	// sorted, so the fact does not depend on map order. Refused tags
	// are absent by construction: the counter moves after a verdict,
	// and a tag that did not verify proves no regime.
	if tp.ProofFloor.Raised() {
		names := make([]string, 0, len(w.floors))
		for floor := range w.floors {
			names = append(names, floor)
		}

		sort.Strings(names)

		for _, floor := range names {
			facts = append(facts, report.Fact{
				Name: "tagsProvenAt:" + floor, Value: strconv.Itoa(w.floors[floor]),
			})
		}
	}

	// The population is what the DECLARATION holds, never what the walk
	// managed to judge: a member the ledger could not answer for is
	// covered by this run and says so, and counting only the judged
	// would hide exactly the narrowing stele#208 found. Excluded tags
	// are absent from it by construction — an exclusion produces no
	// count.
	pop2 := report.PopulationFromListing(w.total().members(), "release tags from the declared signing epochs")

	return report.Seal("assert tags", pop.Subject(), pop2, j,
		report.NoCanary(), report.NoJudgedSet(), facts...), nil
}

// tagCount is one repository's reconciliation of the forge listing
// against the declaration: what was listed, what the epoch excluded,
// and what the walk was able to say about the rest. Every member
// lands in exactly one of judged and unjudgeable, so the four numbers
// close — `listed = excluded + judged + unjudgeable` — and a run that
// silently dropped members could not balance.
type tagCount struct {
	repo        string
	epoch       string
	listed      int
	excluded    int
	judged      int
	unjudgeable int
}

// members is the population this repository contributed. Derived from
// the two dispositions rather than stored beside them, so a member
// that reached neither could not be counted as covered.
func (c tagCount) members() int { return c.judged + c.unjudgeable }

// factsPerRepo is how many numbers one repository's reconciliation
// reports — the four fields of tagCount that a reader adds up.
const factsPerRepo = 4

type tagsWalk struct {
	pol   *TagsPolicy
	org   string
	tags  gh.TagReader
	tv    TagVerifier
	j     *report.Journal
	log   Logf
	tagRE *regexp.Regexp
	// counts holds one reconciliation per repository whose epoch the
	// policy declares, in walk order. A repository with no declared
	// epoch has no population to reconcile — its finding is the whole
	// account of it.
	counts []tagCount
	// floors counts the tags PROVEN at each declared floor — the fact
	// that says which regimes a run actually covered, rather than
	// which the policy declared.
	floors map[string]int
}

// total sums the per-repository reconciliations, from the same slice
// the per-repository facts are built from — one derivation, so the
// summary and its parts cannot disagree.
func (w *tagsWalk) total() tagCount {
	var t tagCount

	for _, c := range w.counts {
		t.listed += c.listed
		t.excluded += c.excluded
		t.judged += c.judged
		t.unjudgeable += c.unjudgeable
	}

	return t
}

// reconciliation states what the run covered — per repository and in
// total — as facts beside the verdict and as a line in the run's own
// output. A green names its own scope (stele#208): a PASS over 21 of
// 158 tags is otherwise indistinguishable from a PASS over all of
// them, and the counts are the only thing that tells them apart.
func (w *tagsWalk) reconciliation() []report.Fact {
	facts := make([]report.Fact, 0, len(w.counts)*factsPerRepo)

	for _, c := range w.counts {
		facts = append(facts,
			report.Fact{Name: "tagsListed:" + c.repo, Value: strconv.Itoa(c.listed)},
			report.Fact{Name: "tagsExcluded:" + c.repo, Value: strconv.Itoa(c.excluded)},
			report.Fact{Name: "tagsJudged:" + c.repo, Value: strconv.Itoa(c.judged)},
			report.Fact{Name: "tagsUnjudgeable:" + c.repo, Value: strconv.Itoa(c.unjudgeable)})
	}

	t := w.total()
	w.log("assert: tags: %d tag(s) listed, %d excluded before a declared epoch, "+
		"%d in population: %d judged, %d unjudgeable",
		t.listed, t.excluded, t.members(), t.judged, t.unjudgeable)

	return facts
}

func (w *tagsWalk) repo(repo string) error {
	refs, err := w.tags.TagRefs(w.org, repo)
	if err != nil {
		return fmt.Errorf("assert: tags of %s/%s: %w", w.org, repo, err)
	}

	var listed []gh.TagRef

	for _, r := range refs {
		if w.tagRE.MatchString(r.Name) {
			listed = append(listed, r)
		}
	}

	if len(listed) == 0 {
		return nil
	}

	epoch, declared := w.pol.Epochs[repo]
	if c := w.j.Check(w.org+"/"+repo, assertTagEpoch); !declared {
		c.Diverged("the repository releases tags but the policy declares no signing epoch for it")
		w.log("assert: tags: %s: %d tag(s) listed, no declared signing epoch: "+
			"none of them can be placed in a population", repo, len(listed))

		return nil
	}

	count, err := w.split(repo, epoch, listed)
	if err != nil {
		return err
	}

	w.counts = append(w.counts, count)
	w.log("assert: tags: %s: %d tag(s) listed, %d excluded %s, %d in population: %d judged, %d unjudgeable",
		count.repo, count.listed, count.excluded, epochClause(count.epoch),
		count.members(), count.judged, count.unjudgeable)

	return nil
}

// split divides one repository's listing at its declared epoch and
// judges the population half. The ledger is read only when there is a
// member to judge — a repository whose whole listing predates its
// epoch owes nothing and is asked nothing.
func (w *tagsWalk) split(repo, epoch string, listed []gh.TagRef) (tagCount, error) {
	count := tagCount{repo: repo, epoch: epoch, listed: len(listed)}

	admitted := make([]gh.TagRef, 0, len(listed))

	for _, ref := range listed {
		if inPopulation(ref.Name, epoch) {
			admitted = append(admitted, ref)

			continue
		}

		count.excluded++
	}

	if len(admitted) == 0 {
		return count, nil
	}

	horizon, err := w.horizon(repo)
	if err != nil {
		return count, err
	}

	for _, ref := range admitted {
		judged, terr := w.tag(repo, ref, epoch, horizon)
		if terr != nil {
			return count, terr
		}

		if judged {
			count.judged++
		} else {
			count.unjudgeable++
		}
	}

	return count, nil
}

// chainHorizon is what one repository's ledger can bear witness to:
// the revisions it links, and the founded genesis before which it
// says nothing at all.
type chainHorizon struct {
	noted   map[string]bool
	genesis string
}

// unwitnessed names why the ledger cannot answer for one target — the
// origin the derived exception carries AND the line the run prints,
// from one definition, so the excuse in the document and the sentence
// in the log can never say different things.
func (h chainHorizon) unwitnessed(target string) string {
	if h.genesis == "" {
		return "the ledger founds no chain, so no link on target " + target + " can be witnessed here"
	}

	return "the ledger's founded genesis " + h.genesis + " does not reach target " + target
}

// horizon derives the linked-revision set and the chain genesis — the
// oldest link whose first parent carries no link.
func (w *tagsWalk) horizon(repo string) (chainHorizon, error) {
	notes, err := w.tags.ChainNotes(w.org, repo, *w.pol.NotesRef)
	if err != nil {
		return chainHorizon{}, fmt.Errorf("assert: chain notes of %s/%s: %w", w.org, repo, err)
	}

	h := chainHorizon{noted: map[string]bool{}}

	for _, n := range notes {
		link, derr := jsonx.DecodeForeign[linkNote](n.Note)
		if derr != nil || link.Version == nil || link.Provenance == nil {
			continue // scaffolding, not a link
		}

		h.noted[n.Rev] = true
	}

	gtime := int64(0)

	for rev := range h.noted {
		meta, merr := w.tags.CommitMeta(w.org, repo, rev)
		if merr != nil {
			return chainHorizon{}, fmt.Errorf("assert: commit %s of %s/%s: %w", rev, w.org, repo, merr)
		}

		if len(meta.Parents) > 0 && h.noted[meta.Parents[0]] {
			continue // its first parent is linked: not a genesis candidate
		}

		if h.genesis == "" || meta.CommitEpoch < gtime {
			h.genesis, gtime = rev, meta.CommitEpoch
		}
	}

	return h, nil
}

// witnesses reports whether the ledger is in a position to answer for
// one target at all: the founded genesis reaches it. A ledger that
// founds no chain witnesses nothing — that absence is `assert chains`'
// finding (#266), and judging it again here would redden every tag of
// a repository for one missing ledger.
func (w *tagsWalk) witnesses(repo, subject, target string, h chainHorizon) (bool, error) {
	if h.genesis == "" {
		return false, nil
	}

	within, err := w.tags.IsAncestor(w.org, repo, h.genesis, target)
	if err != nil {
		return false, fmt.Errorf("assert: ancestry of %s: %w", subject, err)
	}

	return within, nil
}

// tag judges one member of the population and reports whether every
// obligation it owes reached a verdict. False is the loud case, never
// the quiet one: the tag is named, counted and excused, never dropped.
func (w *tagsWalk) tag(repo string, ref gh.TagRef, epoch string, h chainHorizon) (bool, error) {
	subject := repo + "@" + ref.Name

	target, obj, err := w.resolveTarget(repo, ref)
	if err != nil {
		return false, err
	}

	if c := w.j.Check(subject, assertTagAnnotated); obj == nil {
		// A lightweight tag has no tagger, no signature and no object to
		// read one from: the one divergence answers for the whole tag,
		// and it is a verdict rather than an absence of sight.
		c.Diverged("lightweight tag — the mint always annotates")

		return true, nil
	}

	if c := w.j.Check(subject, assertTagTagger); obj.Tagger != *w.pol.TaggerName {
		c.Diverged(fmt.Sprintf("tagger %q is not the minting identity %q", obj.Tagger, *w.pol.TaggerName))
	}

	// Membership and the signing obligation come from ONE reading of
	// the epoch: every member owes a signature unless its repository
	// declared it has not begun signing, so "inside the population" and
	// "owes a signature" cannot drift apart (they did, and the drift is
	// stele#208).
	if epoch != EpochPending {
		w.signature(subject, obj, w.pol.ProofFloor.floorFor(repo, ref.Name))
	}

	judged, err := w.link(repo, subject, target, h)
	if err != nil {
		return false, err
	}

	w.log("assert: tags: %s", subject)

	return judged, nil
}

// link judges the chain-link obligation, or states that the ledger
// cannot answer for it.
//
// Absence INSIDE the horizon is a defect: the ledger covers that span
// and holds no link. Absence before the founded genesis is unknowable
// — the ledger's first link postdates the tag — so the finding is
// recorded and carries a DERIVED exception naming the horizon it came
// from. That is the assert-chains shape: what excuses a finding is
// recorded beside it, never a decision to drop it. The tag stays
// visible, stays counted, and never reddens.
func (w *tagsWalk) link(repo, subject, target string, h chainHorizon) (bool, error) {
	c := w.j.Check(subject, assertTagLink)
	if h.noted[target] {
		return true, nil
	}

	c.Diverged(fmt.Sprintf("target %s carries no source chain link", target))

	within, err := w.witnesses(repo, subject, target, h)
	if err != nil {
		return false, err
	}

	if within {
		return true, nil
	}

	why := h.unwitnessed(target)
	w.j.Except(report.Derived(subject, assertTagLink, why))
	w.log("assert: tags: %s: %s unjudgeable — %s", subject, assertTagLink, why)

	return false, nil
}

// resolveTarget dereferences the ref: an annotated tag through its
// object, a lightweight tag directly (obj nil marks lightweight).
func (w *tagsWalk) resolveTarget(repo string, ref gh.TagRef) (string, *gh.TagObject, error) {
	if !ref.Annotated {
		return ref.ObjectSHA, nil, nil
	}

	obj, err := w.tags.TagObject(w.org, repo, ref.ObjectSHA)
	if err != nil {
		return "", nil, fmt.Errorf("assert: tag object of %s/%s@%s: %w", w.org, repo, ref.Name, err)
	}

	return obj.Target, obj, nil
}

// signature judges the signing obligation on one annotated tag,
// against the floor that tag owes.
func (w *tagsWalk) signature(subject string, obj *gh.TagObject, floor string) {
	c := w.j.Check(subject, assertTagSignature)

	if len(obj.Signature) == 0 {
		c.Diverged("unsigned tag inside the declared signing epoch")

		return
	}

	// The detail names the obligation, never the cause: the verifier
	// refuses over the signature, the countersignatures, the declared
	// signing time and the identity, and a prefix that picks one of
	// them misreports the others (stele#167, where a clock
	// disagreement surfaced as an untrusted chain).
	proof, err := w.tv.Verify(obj.Payload, obj.Signature, floor)
	if err != nil {
		c.Diverged("signature refused: " + err.Error())

		return
	}

	w.floors[floor]++

	// The floor is logged beside the depth because they are different
	// facts: what was owed, and what was proven. A run that reports
	// only the depth cannot be read as evidence that the raised floor
	// bound anything.
	w.log("assert: tags: %s signature %s (floor %s) observed %s", subject, proof.Depth, floor, proof.Observed)
}

// inPopulation reports whether one tag is a member of the population
// the organisation declared: from its repository's signing epoch
// onward, or every release tag of a repository that has declared it
// has not begun signing at all.
//
// `pending` admits the whole listing on purpose. It says a repository
// signs no tags YET, which is a statement about one obligation — the
// tagger role and the chain link are owed whatever the mint has begun
// doing, and reading `pending` as an empty population would make a
// declaration of scope silently remove a repository from sight.
func inPopulation(tag, epoch string) bool {
	return epoch == EpochPending || tagAtOrAfter(tag, epoch)
}

// epochClause names the declaration an exclusion count came from. The
// reconciliation is unreadable without it: zero excluded means "the
// epoch is the first tag" and "no epoch bounds this listing at all",
// and those are different claims about the same number.
func epochClause(epoch string) string {
	if epoch == EpochPending {
		return "before an epoch (none declared: pending)"
	}

	return "before epoch " + epoch
}

// tagAtOrAfter reports whether the tag sits at or after the epoch
// tag in version order. An unparsable version fails toward the
// stricter obligation — it owes a signature.
func tagAtOrAfter(tag, epoch string) bool {
	tv, terr := semver.NewVersion(strings.TrimPrefix(tag, "v"))
	ev, eerr := semver.NewVersion(strings.TrimPrefix(epoch, "v"))

	if terr != nil || eerr != nil {
		return true
	}

	return !tv.LessThan(ev)
}
