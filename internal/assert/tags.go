// The tag audit (stele#83): for every release tag in the population,
// the tagger is the minting role, the tag from the repository's
// signing epoch onward carries a signature that verifies against the
// policy identity, and the tag's target carries a source chain link.
// The forge's own verification verdict is never consulted — it cannot
// judge gitsign's x509-in-the-PGP-slot and reports every signed tag
// unsigned (measured).
//
// The legacy bound is DERIVED from the chain, never declared: a tag
// whose target predates the chain genesis was minted before the
// machinery existed — legacy by construction, reported by name,
// never red. Genesis is the oldest link-noted revision whose first
// parent carries no link.
//
// Each obligation is its own assertion (`tag:tagger`, `tag:signature`,
// `tag:link`…) rather than one blanket `tags` (#147): an assertion
// names the check that saw the divergence, so a written-down defect
// excuses THAT check on THAT tag and nothing else. A tag the epoch
// exempts records no signature check at all, which is what keeps an
// excuse for it from being called stale by a run that never looked.

package assert

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/report"
)

// TagVerifier proves one tag signature — the trust boundary behind a
// seam so every guard here stays table-tested; the CLI binds the
// real gitsign verification.
type TagVerifier interface {
	// Verify proves the signature over the payload and returns the
	// certificate identity it verified under.
	Verify(payload, signature []byte) (string, error)
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
	pol *Policy, pop Population, forge gh.Forge, tags gh.TagReader, tv TagVerifier, j *report.Journal, log Logf,
	runFacts ...report.Fact,
) (*report.Report, error) {
	tp := pol.Tags
	if tp == nil {
		return nil, errors.New("assert: the policy declares no tags section")
	}

	org, repos, err := pop.Resolve(forge)
	if err != nil {
		return nil, err
	}

	w := &tagsWalk{
		pol: tp, org: org, tags: tags, tv: tv, j: j, log: log,
		tagRE: regexp.MustCompile(*tp.TagPattern),
	}

	for _, repo := range repos {
		if err := w.repo(repo); err != nil {
			return nil, err
		}
	}

	facts := append(append([]report.Fact{}, runFacts...),
		report.Fact{Name: "tagsChecked", Value: strconv.Itoa(w.checked)})
	if len(w.legacy) > 0 {
		facts = append(facts, report.Fact{Name: "legacyTags", Value: strings.Join(w.legacy, " ")})
	}

	pop2 := report.PopulationFromListing(w.checked, "release tags")

	return report.Seal("assert tags", pop.Subject(), pop2, j,
		report.NoCanary(), report.NoJudgedSet(), facts...), nil
}

type tagsWalk struct {
	pol     *TagsPolicy
	org     string
	tags    gh.TagReader
	tv      TagVerifier
	j       *report.Journal
	log     Logf
	tagRE   *regexp.Regexp
	checked int
	legacy  []string
}

func (w *tagsWalk) repo(repo string) error {
	refs, err := w.tags.TagRefs(w.org, repo)
	if err != nil {
		return fmt.Errorf("assert: tags of %s/%s: %w", w.org, repo, err)
	}

	var release []gh.TagRef

	for _, r := range refs {
		if w.tagRE.MatchString(r.Name) {
			release = append(release, r)
		}
	}

	if len(release) == 0 {
		return nil
	}

	epoch, declared := w.pol.Epochs[repo]
	if c := w.j.Check(w.org+"/"+repo, assertTagEpoch); !declared {
		c.Diverged("the repository releases tags but the policy declares no signing epoch for it")

		return nil
	}

	noted, genesis, err := w.chainBound(repo)
	if err != nil {
		return err
	}

	for _, ref := range release {
		if err := w.tag(repo, ref, epoch, noted, genesis); err != nil {
			return err
		}
	}

	return nil
}

// chainBound derives the linked-revision set and the chain genesis —
// the oldest link whose first parent carries no link.
//
//nolint:gocritic // unnamedResult: the noted set, then the genesis revision
func (w *tagsWalk) chainBound(repo string) (map[string]bool, string, error) {
	notes, err := w.tags.ChainNotes(w.org, repo, *w.pol.NotesRef)
	if err != nil {
		return nil, "", fmt.Errorf("assert: chain notes of %s/%s: %w", w.org, repo, err)
	}

	noted := map[string]bool{}

	for _, n := range notes {
		link, derr := jsonx.DecodeForeign[linkNote](n.Note)
		if derr != nil || link.Version == nil || link.Provenance == nil {
			continue // scaffolding, not a link
		}

		noted[n.Rev] = true
	}

	genesis, gtime := "", int64(0)

	for rev := range noted {
		meta, merr := w.tags.CommitMeta(w.org, repo, rev)
		if merr != nil {
			return nil, "", fmt.Errorf("assert: commit %s of %s/%s: %w", rev, w.org, repo, merr)
		}

		if len(meta.Parents) > 0 && noted[meta.Parents[0]] {
			continue // its first parent is linked: not a genesis candidate
		}

		if genesis == "" || meta.CommitEpoch < gtime {
			genesis, gtime = rev, meta.CommitEpoch
		}
	}

	return noted, genesis, nil
}

func (w *tagsWalk) tag(repo string, ref gh.TagRef, epoch string, noted map[string]bool, genesis string) error {
	subject := repo + "@" + ref.Name
	w.checked++

	target, obj, err := w.resolveTarget(repo, ref)
	if err != nil {
		return err
	}

	if genesis != "" {
		ancestor, aerr := w.tags.IsAncestor(w.org, repo, genesis, target)
		if aerr != nil {
			return fmt.Errorf("assert: ancestry of %s: %w", subject, aerr)
		}

		if !ancestor {
			// The target predates the chain genesis: minted before the
			// machinery existed, legacy by construction.
			w.legacy = append(w.legacy, subject)

			return nil
		}
	}

	if c := w.j.Check(subject, assertTagAnnotated); obj == nil {
		c.Diverged("lightweight tag — the mint always annotates")

		return nil
	}

	if c := w.j.Check(subject, assertTagTagger); obj.Tagger != *w.pol.TaggerName {
		c.Diverged(fmt.Sprintf("tagger %q is not the minting identity %q", obj.Tagger, *w.pol.TaggerName))
	}

	// Outside the declared epoch the signature check is not performed
	// at all — not performed and passed, which is the distinction an
	// excuse for such a tag rests on.
	if epoch != EpochPending && tagAtOrAfter(ref.Name, epoch) {
		w.signature(subject, obj)
	}

	if c := w.j.Check(subject, assertTagLink); !noted[target] {
		c.Diverged(fmt.Sprintf("target %s carries no source chain link", target))
	}

	w.log("assert: tags: %s", subject)

	return nil
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

// signature judges the signing obligation on one annotated tag.
func (w *tagsWalk) signature(subject string, obj *gh.TagObject) {
	c := w.j.Check(subject, assertTagSignature)

	if len(obj.Signature) == 0 {
		c.Diverged("unsigned tag inside the declared signing epoch")

		return
	}

	if _, err := w.tv.Verify(obj.Payload, obj.Signature); err != nil {
		c.Diverged("signature does not verify against the declared identity: " + err.Error())
	}
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
