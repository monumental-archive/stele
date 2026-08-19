// The chain-coverage audit (stele#94): for every repository in the
// population, either a founded source chain verifies end to end over
// every protected branch, or the repository is a DECLARED exception.
// An unactivated repository with no declared exception is a finding
// (the #266 rule): the population is enumerated, never the enrolled
// set, because an unactivated repo is silent by construction — the
// same defect as a release shipping without its SBOM with every
// board green.
//
// Absence is judged HERE, before the engine: a repository with no
// link-shaped notes is unactivated, and handing it to the chain walk
// would refuse it as an evidence failure — the wrong verdict for
// absence. A FOUNDED chain that fails to verify is never excusable:
// the declared exceptions carry the unactivated assertion alone, so
// an opt-out can only ever excuse absence, structurally.
//
// The walk is cloneless — the notes ref, the branch tips and every
// blob come from the forge's own API (gh.History), the same surface
// verify.Chain already walks. The verification itself sits behind
// ChainVerifier so every guard branch here is table-tested; the CLI
// binds the real engine.

package assert

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/report"
)

// ChainVerifier proves one repository's chain over one branch ref —
// the trust boundary behind a seam. The CLI binds verify.Chain over
// the forge-backed history; tests script it.
type ChainVerifier interface {
	// Verify walks and cryptographically verifies the chain, returning
	// the number of links it proved.
	Verify(owner, repo, ref string) (int, error)
}

// assertionUnactivated is the one assertion a declared chains
// exception may excuse. Chain-defect findings carry a different
// assertion, so a founded-but-broken chain can never be opted out.
const assertionUnactivated = "unactivated"

// Chains walks the population and seals the coverage verdict.
// notesRef and refs come from the verify policy's source section —
// the ONE declaration of where the ledger lives and which branches
// it covers; restating them here would be a second source of truth.
// runFacts are the caller's facts about the run itself — the trust
// material it held, which the walk cannot know.
func Chains(
	pol *Policy, pop Population, forge gh.Forge, tags gh.TagReader, cv ChainVerifier,
	notesRef string, refs []string, log Logf, runFacts ...report.Fact,
) (*report.Report, error) {
	cp := pol.Chains
	if cp == nil {
		return nil, errors.New("assert: the policy declares no chains section")
	}

	if notesRef == "" || len(refs) == 0 {
		return nil, errors.New("assert: chains needs the source notes ref and at least one protected branch")
	}

	org, repos, err := pop.resolve(forge)
	if err != nil {
		return nil, err
	}

	w := &chainsWalk{org: org, tags: tags, cv: cv, notesRef: notesRef, refs: refs, log: log}

	for _, repo := range repos {
		if err := w.repo(repo); err != nil {
			return nil, err
		}
	}

	exceptions := make([]report.Exception, 0, len(cp.Exceptions))
	for _, e := range cp.Exceptions {
		exceptions = append(exceptions,
			report.Declared(org+"/"+*e.Repo, assertionUnactivated, "assert policy chains.exceptions: "+*e.Reason))
	}

	facts := append(append([]report.Fact{}, runFacts...),
		report.Fact{Name: "chainsVerified", Value: strconv.Itoa(w.verified)},
		report.Fact{Name: "links", Value: strconv.Itoa(w.links)})

	pop2 := report.PopulationFromListing(len(repos), "repositories in the population")

	return report.Seal("assert chains", pop.Subject(), pop2, w.findings, exceptions, report.NoCanary(), facts...), nil
}

type chainsWalk struct {
	org      string
	tags     gh.TagReader
	cv       ChainVerifier
	notesRef string
	refs     []string
	log      Logf
	verified int
	links    int
	findings []report.Finding
}

func (w *chainsWalk) repo(repo string) error {
	subject := w.org + "/" + repo

	founded, err := w.founded(repo)
	if err != nil {
		return fmt.Errorf("assert: chain notes of %s: %w", subject, err)
	}

	if !founded {
		w.findings = append(w.findings, report.Finding{
			Subject: subject, Assertion: assertionUnactivated,
			Detail: "no chain founded — an unactivated repository is silent by construction, not clean (#266)",
		})

		return nil
	}

	for _, ref := range w.refs {
		links, verr := w.cv.Verify(w.org, repo, ref)
		if verr != nil {
			w.findings = append(w.findings, report.Finding{
				Subject: subject, Assertion: "chains", Detail: ref + ": " + verr.Error(),
			})

			continue
		}

		w.verified++
		w.links += links
		w.log("assert: chains: %s %s: %d link(s) verified", subject, ref, links)
	}

	return nil
}

// founded reports whether the repository carries at least one
// link-shaped note — the same shape test the tag audit applies, so
// scaffolding notes never count as a founded chain.
func (w *chainsWalk) founded(repo string) (bool, error) {
	notes, err := w.tags.ChainNotes(w.org, repo, w.notesRef)
	if err != nil {
		return false, err
	}

	for _, n := range notes {
		link, derr := jsonx.DecodeForeign[linkNote](n.Note)
		if derr != nil || link.Version == nil || link.Provenance == nil {
			continue // scaffolding, not a link
		}

		return true, nil
	}

	return false, nil
}
