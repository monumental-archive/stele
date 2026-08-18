// The evidence walk: nothing ships unattested. For every non-draft
// release of every repository in the population, the classes the
// release DECLARED (its contract) resolve through the policy into
// required assets, and — where the contract says verdicts are
// store-resident — every subject the attached bundles cover must
// carry a VSA in the attestation store: a verdict over exactly what
// the evidence covers, with no second derivation of the subject set.
//
// The three report-not-fail categories are typed, not interchangeable
// (the report package's exception law): legacy releases (no contract
// at the tag) owe nothing and are recorded as a fact; debt is a
// human-declared exception parsed from a committed file; burned is
// DERIVED here from run history and only ever excuses vsa findings —
// a verdict missing from a release that published cleanly stays red.

package assert

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/monumental-archive/stele/internal/dsse"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/vsa"
)

var hex64OnlyRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Population names what the evidence walk covers: an organisation's
// listing, or exactly one repository. Exactly one field is set — the
// CLI enforces the exclusivity, the walk refuses the impossible
// combinations it can still see.
type Population struct {
	// Org is the organisation whose listing is the population.
	Org string
	// Repo is a single owner/name population — the single-repo
	// consumer (#79): the same walk, the population enumeration
	// replaced by the one repository named.
	Repo string
}

// Subject is the report subject the population walks under.
func (p Population) Subject() string {
	if p.Repo != "" {
		return p.Repo
	}

	return p.Org
}

// resolve turns the population into the owner and its repositories —
// a listing for an org, the one named repository otherwise.
//
//nolint:gocritic // unnamedResult: the doc line names the results
func (p Population) resolve(forge gh.Forge) (string, []string, error) {
	if p.Repo == "" {
		repos, err := forge.Repos(p.Org)
		if err != nil {
			return "", nil, fmt.Errorf("assert: listing %s: %w", p.Org, err)
		}

		return p.Org, repos, nil
	}

	owner, name, ok := strings.Cut(p.Repo, "/")
	if !ok || owner == "" || name == "" {
		return "", nil, fmt.Errorf("assert: population %q is not owner/name", p.Repo)
	}

	return owner, []string{name}, nil
}

// Evidence walks the population's releases and seals the
// completeness verdict. debt carries the committed file's declared
// exceptions; burned exceptions are derived inside the walk.
func Evidence(
	pol *Policy, pop Population, forge gh.Forge, src ContractSource, att Attestor,
	debt []report.Exception, pinFile []byte, full *FullDepth, log Logf,
) (*report.Report, error) {
	e := pol.Evidence

	// A declared org population is meaningless over a single
	// repository, and silently ignoring it would let one policy mean
	// two things (#79): refused, never reinterpreted.
	if pop.Repo != "" && e.ExpectedRepos != nil {
		return nil, errors.New(
			"assert: expectedRepos is declared but the population is one repository — the declaration cannot apply")
	}

	org, repos, err := pop.resolve(forge)
	if err != nil {
		return nil, err
	}

	// The declared-population guard, before anything else: a token
	// that sees a partial org makes the walk run short and pass —
	// a clean check indistinguishable from no check.
	if e.ExpectedRepos != nil && len(repos) != *e.ExpectedRepos {
		return nil, fmt.Errorf(
			"assert: the listing sees %d repos, the declared population is %d — an unseen repo is unchecked, not clean",
			len(repos), *e.ExpectedRepos)
	}

	w := &evidenceWalk{
		pol: e, org: org, subject: pop.Subject(),
		forge: forge, src: src, attestor: att, full: full, log: log,
	}

	for _, repo := range repos {
		if err := w.repo(repo); err != nil {
			return nil, err
		}

		if err := w.continuous(repo); err != nil {
			return nil, err
		}
	}

	w.baseImages(pinFile)

	exceptions := make([]report.Exception, 0, len(debt)+len(w.burned))
	exceptions = append(exceptions, debt...)
	exceptions = append(exceptions, w.burned...)

	facts := []report.Fact{{Name: "releasesChecked", Value: strconv.Itoa(w.checked)}}
	if len(w.legacy) > 0 {
		facts = append(facts, report.Fact{Name: "legacyReleases", Value: strings.Join(w.legacy, " ")})
	}

	covered := report.PopulationFromListing(w.checked, "subjects with a declared evidence contract")

	return report.Seal("assert evidence", w.subject, covered, w.findings, exceptions, report.NoCanary(), facts...), nil
}

type evidenceWalk struct {
	pol      *EvidencePolicy
	org      string
	subject  string
	forge    gh.Forge
	src      ContractSource
	attestor Attestor
	full     *FullDepth
	log      Logf
	checked  int
	legacy   []string
	findings []report.Finding
	burned   []report.Exception
}

func (w *evidenceWalk) repo(repo string) error {
	tags, err := w.forge.ReleaseTags(w.org, repo)
	if err != nil {
		return fmt.Errorf("assert: releases of %s/%s: %w", w.org, repo, err)
	}

	for _, tag := range tags {
		if err := w.release(repo, tag); err != nil {
			return err
		}
	}

	return nil
}

func (w *evidenceWalk) release(repo, tag string) error {
	subject := repo + "@" + tag

	contract, ok, err := w.src.Contract(w.org, repo, tag)
	if err != nil {
		return err
	}

	if !ok {
		// No source speaks for this release: it predates the
		// machinery, and the obligation starts when the machinery
		// does. Recorded, never failed — and never excusable by hand:
		// this category is derived from the tag's own tree.
		w.legacy = append(w.legacy, subject)

		return nil
	}

	assets, err := w.forge.ReleaseAssets(w.org, repo, tag)
	if err != nil {
		return fmt.Errorf("assert: assets of %s/%s@%s: %w", w.org, repo, tag, err)
	}

	w.checked++
	w.log("assert: evidence: %s (%s)", subject, contract.Origin)

	have := map[string]bool{}
	for _, a := range assets {
		have[a] = true
	}

	bundles := w.requiredAssets(subject, contract, assets, have)

	if contract.StoreVSA {
		if err := w.storeVerdicts(repo, tag, bundles); err != nil {
			return err
		}
	}

	if w.full != nil {
		return w.fullDepth(repo, tag, contract)
	}

	return nil
}

// requiredAssets judges the asset obligations and returns the bundle
// assets that are PRESENT — the subject-set derivation reads exactly
// the evidence the release ships.
func (w *evidenceWalk) requiredAssets(
	subject string, contract *Contract, assets []string, have map[string]bool,
) []string {
	if !anySuffix(assets, *w.pol.SBOMSuffix) {
		w.finding(subject, "sbom", "no asset carries the SBOM suffix "+*w.pol.SBOMSuffix)
	}

	if !have[*w.pol.Checksums] {
		w.finding(subject, *w.pol.Checksums, "the checksum manifest is absent")
	}

	var required []string

	for _, class := range contract.Classes {
		cp, ok := w.pol.Classes[class]
		if !ok {
			w.finding(subject, "class:"+class, "the contract names a class the policy does not define")

			continue
		}

		required = append(required, cp.Bundles...)

		if !contract.StoreVSA {
			required = append(required, cp.LegacyVSABundles...)
		}

		for _, prefix := range cp.AssetPrefixes {
			if !anyPrefix(assets, prefix) {
				w.finding(subject, prefix, "no asset carries the required prefix")
			}
		}
	}

	// One bundle covering the whole release truthfully takes the
	// umbrella name — the single-bundle case.
	umbrella := len(required) == 1 && have[*w.pol.UmbrellaBundle]

	var present []string

	for _, b := range required {
		switch {
		case have[b]:
			present = append(present, b)
		case umbrella:
			present = append(present, *w.pol.UmbrellaBundle)
		default:
			w.finding(subject, b, "the class bundle is absent")
		}
	}

	return present
}

// bundleLine is one line of a bundle asset — a Sigstore bundle whose
// DSSE envelope carries the statement (foreign envelope, judged
// leniently; the statement inside is judged downstream).
type bundleLine struct {
	DSSEEnvelope *struct {
		Payload *string `json:"payload"`
	} `json:"dsseEnvelope"`
}

// stmtSubjects is the minimal statement read the subject derivation
// needs.
type stmtSubjects struct {
	Subject []struct {
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	PredicateType *string `json:"predicateType"`
}

// storeVerdicts asserts a store-resident VSA over every subject the
// present bundles cover.
func (w *evidenceWalk) storeVerdicts(repo, tag string, bundles []string) error {
	subject := repo + "@" + tag
	seen := map[string]bool{}

	for _, asset := range bundles {
		raw, err := w.forge.Asset(w.org, repo, tag, asset)
		if err != nil {
			w.finding(subject, asset+":unreadable", err.Error())

			continue
		}

		digests, err := subjectDigests(raw)
		if err != nil {
			w.finding(subject, asset+":unreadable", err.Error())

			continue
		}

		for _, d := range digests {
			if seen[d] {
				continue
			}

			seen[d] = true

			ok, err := w.storeHasVSA(repo, d)
			if err != nil {
				return err
			}

			if !ok {
				w.finding(subject, "vsa:"+d[:12], "no verification summary in the attestation store for sha256:"+d)
			}
		}
	}

	if len(w.vsaFindings(subject)) == 0 {
		return nil
	}

	// The burned derivation (#378): only where the tag's own run
	// history shows a PUBLISHING failure, and only for vsa findings —
	// narrow and derived, never assertable by hand. Which workflows
	// publish is policy data: without it any failed run would excuse,
	// so one flaky unrelated workflow on a tag would mute a genuinely
	// missing verdict.
	failed, err := w.forge.FailedRuns(w.org, repo, tag)
	if err != nil {
		return fmt.Errorf("assert: run history of %s/%s@%s: %w", w.org, repo, tag, err)
	}

	culprit, ok := w.burnedBy(failed)
	if !ok {
		return nil
	}

	for _, f := range w.vsaFindings(subject) {
		w.burned = append(w.burned, report.Derived(subject, f,
			fmt.Sprintf("burned release: the %s run failed on %s (#378)", culprit, tag)))
	}

	return nil
}

// burnedBy reports which failed run burns the release, if any. With
// publishWorkflows declared only those names burn; without it any
// failure does, which is the bash's broader stance and is why the
// policy field exists.
func (w *evidenceWalk) burnedBy(failed []string) (string, bool) {
	for _, name := range failed {
		if len(w.pol.PublishWorkflows) == 0 {
			return name, true
		}

		if slices.Contains(w.pol.PublishWorkflows, name) {
			return name, true
		}
	}

	return "", false
}

func (w *evidenceWalk) vsaFindings(subject string) []string {
	var out []string

	for _, f := range w.findings {
		if f.Subject == subject && strings.HasPrefix(f.Assertion, "vsa:") {
			out = append(out, f.Assertion)
		}
	}

	return out
}

// storeHasVSA peeks the stored bundles for one digest for a VSA
// predicate type. Presence depth: the cryptographic judgment is the
// full-depth leg (#4), which reuses the verify engine.
func (w *evidenceWalk) storeHasVSA(repo, digest string) (bool, error) {
	stored, err := w.forge.Attestations(w.org, repo, digest)
	if err != nil {
		return false, fmt.Errorf("assert: store for sha256:%s: %w", digest, err)
	}

	for _, raw := range stored {
		line, err := jsonx.DecodeForeign[bundleLine](raw)
		if err != nil || line.DSSEEnvelope == nil || line.DSSEEnvelope.Payload == nil {
			continue
		}

		stmt, err := decodeStatement(*line.DSSEEnvelope.Payload)
		if err != nil {
			continue
		}

		if stmt.PredicateType != nil && *stmt.PredicateType == vsa.PredicateType {
			return true, nil
		}
	}

	return false, nil
}

// subjectDigests reads every sha256 subject digest out of one bundle
// asset (JSONL: one Sigstore bundle per line).
func subjectDigests(raw []byte) ([]string, error) {
	var out []string

	lines := 0

	for line := range strings.SplitSeq(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}

		lines++

		decoded, err := jsonx.DecodeForeign[bundleLine]([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("bundle line %d: %w", lines, err)
		}

		if decoded.DSSEEnvelope == nil || decoded.DSSEEnvelope.Payload == nil {
			return nil, fmt.Errorf("bundle line %d carries no DSSE payload", lines)
		}

		stmt, err := decodeStatement(*decoded.DSSEEnvelope.Payload)
		if err != nil {
			return nil, fmt.Errorf("bundle line %d: %w", lines, err)
		}

		for _, s := range stmt.Subject {
			if d, ok := s.Digest["sha256"]; ok && hex64OnlyRE.MatchString(d) {
				out = append(out, d)
			}
		}
	}

	if lines == 0 {
		return nil, errors.New("the bundle asset is empty")
	}

	return out, nil
}

func decodeStatement(payloadB64 string) (*stmtSubjects, error) {
	stmtBytes, err := dsse.DecodeBase64(payloadB64)
	if err != nil {
		return nil, err
	}

	stmt, err := jsonx.DecodeForeign[stmtSubjects](stmtBytes)
	if err != nil {
		return nil, err
	}

	return stmt, nil
}

func (w *evidenceWalk) finding(subject, assertion, detail string) {
	w.findings = append(w.findings, report.Finding{Subject: subject, Assertion: assertion, Detail: detail})
}

func anySuffix(items []string, suffix string) bool {
	for _, s := range items {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}

	return false
}

func anyPrefix(items []string, prefix string) bool {
	for _, s := range items {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}

	return false
}
