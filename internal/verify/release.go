// Release verification: every attestation against the pinned signer
// identity, all four of verifying-artifacts' comparisons, subject
// coverage equality, the source-revision fold, and the release
// decision — the checks whose outputs are the only legal inputs to a
// build-track verdict. Re-derived from SLSA v1.2 verifying-artifacts
// with the canon's verify-release.yml as oracle, never transliterated.

package verify

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/provenance"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/vsa"
)

// Ref names one piece of evidence a verdict rests on: where it was
// fetched and the sha256 of its bytes — the inputAttestations shape.
type Ref struct {
	URI    string
	SHA256 string
}

// ReleaseVerdict is the proof that release verification ran and
// passed. Its fields are unexported and its only constructor is
// Release — the #208 rule as a compile-time fact: nothing can hold
// one of these without every check having returned it.
type ReleaseVerdict struct {
	sourceRevision string
	opened         []Ref
	subjects       int
}

// SourceRevision is the one revision every verified provenance
// attested — the fold's single survivor-free answer.
func (v *ReleaseVerdict) SourceRevision() string { return v.sourceRevision }

// InputAttestations lists every bundle the verification opened, by
// address and digest — appended inside the same iteration that
// verified each one, so the list cannot name what was not read.
func (v *ReleaseVerdict) InputAttestations() []Ref {
	out := make([]Ref, len(v.opened))
	copy(out, v.opened)

	return out
}

// VSAPredicate renders the build-track verification summary this
// verdict earned — the emit verb's output, a method on the verdict
// deliberately: the only way to hold a ReleaseVerdict is for Release
// to have returned one, so a PASSED predicate cannot exist unearned
// (#208). The verifier.id rendered here is exactly the identity the
// consumer read (VSA) requires the signing certificate to carry, and
// the policy is pinned by uri and commit digest as the spec asks.
func (v *ReleaseVerdict) VSAPredicate(
	p *policy.Policy, c Coords, policyURI, machineryDigest, timeVerified string,
) ([]byte, error) {
	if p.Trust.Verdict == nil {
		return nil, errors.New("verify: the policy declares no trust.verdict — a VSA cannot name its verifier")
	}

	pred, err := vsa.New(
		serverURL+"/"+expandWorkflow(*p.Trust.Verdict.VerifierWorkflow, c),
		timeVerified,
		expand(*p.Build.ResourceURI, c),
		policyURI, machineryDigest,
		vsa.ResultPassed,
		[]string{*p.Build.TargetLevel},
	)
	if err != nil {
		return nil, fmt.Errorf("verify: verdict predicate: %w", err)
	}

	atts := make([]intoto.ResourceDescriptor, 0, len(v.opened))

	for i := range v.opened {
		atts = append(atts, intoto.ResourceDescriptor{
			URI:    &v.opened[i].URI,
			Digest: map[string]string{intoto.AlgSHA256: v.opened[i].SHA256},
		})
	}

	pred.InputAttestations = atts

	out, err := jsonx.Marshal(pred)
	if err != nil {
		return nil, fmt.Errorf("verify: verdict predicate: %w", err)
	}

	return out, nil
}

// externalWorkflow is the GitHub Actions buildType's workflow
// object inside externalParameters — the spec's exact three fields,
// decoded strictly.
type externalWorkflow struct {
	Repository *string `json:"repository"`
	Ref        *string `json:"ref"`
	Path       *string `json:"path"`
}

// decisionPredicate is the org's release-decision claim, typed to
// its documented field set. Only tag and conclusion are judged; the
// rest travel raw.
type decisionPredicate struct {
	Tag        *string   `json:"tag"`
	Classes    jsonx.Raw `json:"classes"`
	Conclusion *string   `json:"conclusion"`
	DecidedAt  jsonx.Raw `json:"decidedAt"`
	Proofs     jsonx.Raw `json:"proofs"`
}

// SBOMs is the release's SBOM evidence as the decision judgment sees
// it: every SBOM asset the release carries, and among them the
// planned inventories the release's own plan named.
//
// The two lists answer two different questions. Assets is what a
// decision may LEGALLY cover; Planned is the denominator the
// obligation is measured against — one decision per planned
// inventory, which is what a release shipping per-artifact
// inventories owes (stele#158). Planned is a caller DECLARATION
// derived from the plan (.github#544/stele#142), never inferred here
// from an asset's spelling: which documents a release planned is a
// per-release fact, and a naming rule in this engine would be one
// org's file convention asserted as a fact about every adopter's
// world.
//
// Planned empty declares a release with no plan, and the
// whole-release invariant applies: exactly one SBOM asset carries the
// decision. That is every release published before per-artifact
// inventories existed — grandfathered history proving what it CAN
// prove, with the epoch that decides which releases plan their
// inventories being policy data, exactly as the decision obligation
// itself is.
type SBOMs struct {
	// Assets is every SBOM asset on the release — the decision
	// candidates, a separate list from the build subjects because a
	// class manifest need not contain the release's SBOMs.
	Assets []Subject
	// Planned is the release's inventory plan as digests: a subset of
	// Assets, each of which owes its own decision.
	Planned []Subject
}

// Release verifies one published release like a stranger: subjects
// are the manifest the release claims, sboms carries the release's
// SBOM assets and its inventory plan, and everything else is fetched
// through store and proven through bv. It fails closed at the first
// refusal; the returned verdict exists only on a fully clean pass.
func Release(
	p *policy.Policy, c Coords, subjects []Subject, sboms SBOMs, pins Pins,
	store Store, bv BundleVerifier, log Logf,
) (*ReleaseVerdict, error) {
	if p.Build == nil {
		return nil, errors.New("verify: the policy declares no build section — release verification needs one")
	}

	// No declared decision obligation: the release proves what the
	// policy asks of it — the provenance half whole, nothing invented
	// beyond it. Deterministic on the policy, never a try-each.
	if p.Trust.Decision == nil {
		return ReleaseProvenance(p, c, subjects, pins, store, bv, log)
	}

	if err := validateSBOMs(sboms); err != nil {
		return nil, err
	}

	verdict, prov, err := releaseProvenance(p, c, subjects, pins, store, bv, log)
	if err != nil {
		return nil, err
	}

	decisionRefs, err := verifyDecision(p, c, sboms, pins, store, bv, log)
	if err != nil {
		return nil, err
	}

	prov.opened = append(prov.opened, decisionRefs...)
	verdict.opened = prov.opened

	log("verify: release %s@%s: %d attestation(s) opened over %d subject(s), source revision %s",
		c.Slug(), c.Tag, len(verdict.opened), verdict.subjects, verdict.sourceRevision)

	return verdict, nil
}

// ReleaseProvenance is the provenance half of Release alone: every
// subject covered by verified provenance under the pinned identities,
// with no release decision demanded. It exists for corpus
// re-verification over releases that predate the decision mechanism
// (stele#4) — grandfathered history verifies what it CAN prove, and
// the epoch that decides which releases owe a decision is policy
// data, never a try-each.
func ReleaseProvenance(
	p *policy.Policy, c Coords, subjects []Subject, pins Pins,
	store Store, bv BundleVerifier, log Logf,
) (*ReleaseVerdict, error) {
	if p.Build == nil {
		return nil, errors.New("verify: the policy declares no build section — release verification needs one")
	}

	verdict, prov, err := releaseProvenance(p, c, subjects, pins, store, bv, log)
	if err != nil {
		return nil, err
	}

	verdict.opened = prov.opened

	log("verify: release %s@%s: %d provenance attestation(s) opened over %d subject(s), source revision %s",
		c.Slug(), c.Tag, len(verdict.opened), verdict.subjects, verdict.sourceRevision)

	return verdict, nil
}

// releaseProvenance runs the shared provenance pass: input
// validation, every subject proven against the store, and the
// coverage close. Both entry points build on exactly this — one
// implementation, two obligations.
func releaseProvenance(
	p *policy.Policy, c Coords, subjects []Subject, pins Pins,
	store Store, bv BundleVerifier, log Logf,
) (*ReleaseVerdict, *provenancePass, error) {
	if err := validateInputs(c, subjects, pins); err != nil {
		return nil, nil, err
	}

	prov := newProvenancePass(p, c, pins)

	// The whole manifest is known before any bundle is opened — a
	// statement may cover subjects the loop has not reached yet, and
	// judging it against a partial manifest would refuse the truth.
	for _, s := range subjects {
		prov.manifest[s.SHA256+"  "+s.Name] = true
	}

	for _, s := range subjects {
		bundles, err := store.Bundles(c.Slug(), s.SHA256)
		if err != nil {
			return nil, nil, fmt.Errorf("verify: %s: no attestation retrievable: %w", s.Name, err)
		}

		if err := prov.subject(s, bundles, bv, log); err != nil {
			return nil, nil, err
		}
	}

	if err := prov.close(subjects); err != nil {
		return nil, nil, err
	}

	return &ReleaseVerdict{
		sourceRevision: prov.oneRevision(),
		subjects:       len(subjects),
	}, prov, nil
}

func validateInputs(c Coords, subjects []Subject, pins Pins) error {
	if err := validateCoords(c, true); err != nil {
		return err
	}

	if err := validateSubjects(subjects); err != nil {
		return err
	}

	if !hex40RE.MatchString(pins.Signer) || !hex40RE.MatchString(pins.Machinery) {
		return errors.New("verify: pins must be full 40-hex commit digests — an unpinned identity matches too much")
	}

	return nil
}

// provenancePass accumulates the provenance loop's facts as sets, so
// the cross-bundle claims are folds by construction, never loop
// survivors (#349 finding 7).
type provenancePass struct {
	p         *policy.Policy
	c         Coords
	pins      Pins
	signerID  trust.Identity
	srcRepo   string
	manifest  map[string]bool
	covered   map[string]bool
	seen      map[string]bool
	revisions map[string]bool
	opened    []Ref
}

func newProvenancePass(p *policy.Policy, c Coords, pins Pins) *provenancePass {
	return &provenancePass{
		p:    p,
		c:    c,
		pins: pins,
		signerID: trust.Identity{
			SAN: workflowSAN(expandWorkflow(*p.Trust.Provenance.SignerWorkflow, c),
				identityRef(expandWorkflow(*p.Trust.Provenance.SignerWorkflow, c), c, pins.Signer)),
			Issuer: *p.Issuer,
		},
		srcRepo:   expand(*p.Build.SourceRepository, c),
		manifest:  map[string]bool{},
		covered:   map[string]bool{},
		seen:      map[string]bool{},
		revisions: map[string]bool{},
	}
}

// subject verifies every provenance bundle the store holds for one
// subject. Bundles already verified under another subject are
// skipped by content digest, exactly once each.
func (pp *provenancePass) subject(s Subject, bundles []StoredBundle, bv BundleVerifier, log Logf) error {
	for _, sb := range bundles {
		stmtPeek, err := bv.Peek(sb.Bundle)
		if err != nil {
			return fmt.Errorf("verify: %s: unreadable bundle in the store: %w", s.Name, err)
		}

		peek, err := jsonx.DecodeBytes[intoto.Statement](stmtPeek)
		if err != nil {
			return fmt.Errorf("verify: %s: bundle payload is not a statement: %w", s.Name, err)
		}

		// Selection only: other predicate types over the same subject
		// (the VSA itself, VEX) are claims, not the evidence this
		// verification opens. Nothing peeked informs a verdict — the
		// judged bytes below come from the verified payload.
		if peek.PredicateType == nil || *peek.PredicateType != provenance.PredicateType {
			continue
		}

		bsha := sha256Hex(sb.Bundle)
		if pp.seen[bsha] {
			continue
		}

		if err := pp.verifyBundle(s, sb, bsha, bv, log); err != nil {
			return err
		}
	}

	return nil
}

func (pp *provenancePass) verifyBundle(s Subject, sb StoredBundle, bsha string, bv BundleVerifier, log Logf) error {
	verified, err := bv.Attestation(sb.Bundle, pp.signerID, s.SHA256)
	if err != nil {
		return fmt.Errorf("verify: %s: provenance bundle refused: %w", s.Name, err)
	}

	if cerr := pp.checkCertificate(s, verified); cerr != nil {
		return cerr
	}

	stmt, err := jsonx.DecodeBytes[intoto.Statement](verified.Payload)
	if err != nil {
		return fmt.Errorf("verify: %s: verified payload is not a statement: %w", s.Name, err)
	}

	if verr := stmt.Validate(); verr != nil {
		return fmt.Errorf("verify: %s: %w", s.Name, verr)
	}

	// Re-asserted on the verified bytes: the peek selected, this judges.
	if *stmt.PredicateType != provenance.PredicateType {
		return fmt.Errorf("verify: %s: verified payload is not provenance", s.Name)
	}

	pred, perr := jsonx.DecodeBytes[provenance.Predicate](stmt.Predicate)
	if perr != nil {
		return fmt.Errorf("verify: %s: provenance predicate: %w", s.Name, perr)
	}

	if cerr := pp.checkPredicate(s, pred, verified); cerr != nil {
		return cerr
	}

	// The statement may cover no subject this release did not claim…
	for _, sub := range stmt.Subject {
		line, lerr := subjectLine(sub)
		if lerr != nil {
			return fmt.Errorf("verify: %s: %w", s.Name, lerr)
		}

		if !pp.manifest[line] {
			return errors.New("verify: provenance covers a subject this release does not claim")
		}

		pp.covered[line] = true
	}

	rev, rerr := pred.SourceRevision(pp.srcRepo)
	if rerr != nil {
		return fmt.Errorf("verify: %s: %w", s.Name, rerr)
	}

	pp.revisions[rev] = true

	pp.seen[bsha] = true
	pp.opened = append(pp.opened, Ref{URI: sb.URI, SHA256: bsha})
	log("verify: provenance %s verified (via %s)", bsha[:12], s.Name)

	return nil
}

// checkCertificate holds the certificate facts against the policy:
// the signer pin to the commit, the runner stance, and the canonical
// source repository — the comparison guarding against an unofficial
// fork building under the right identity.
func (pp *provenancePass) checkCertificate(s Subject, verified *trust.Verified) error {
	ext := verified.Extensions
	if ext.BuildSignerDigest != pp.pins.Signer {
		return fmt.Errorf("verify: %s: provenance signed at %q, pin is %q", s.Name, ext.BuildSignerDigest, pp.pins.Signer)
	}

	if *pp.p.Build.DenySelfHostedRunners && ext.RunnerEnvironment != "github-hosted" {
		return fmt.Errorf("verify: %s: runner environment %q is not github-hosted", s.Name, ext.RunnerEnvironment)
	}

	if ext.SourceRepositoryURI != pp.srcRepo {
		return fmt.Errorf("verify: %s: certificate source repository %q is not the canonical %q",
			s.Name, ext.SourceRepositoryURI, pp.srcRepo)
	}

	return nil
}

// checkPredicate holds the provenance content against the policy:
// builder identity, buildType, and externalParameters — with every
// expectation derived from the release coordinates and the
// certificate the same verification returned, because a stranger has
// no run identity to inherit (docs/policy-schema.md, disagreement 2).
func (pp *provenancePass) checkPredicate(s Subject, pred *provenance.Predicate, verified *trust.Verified) error {
	if err := pred.Validate(); err != nil {
		return fmt.Errorf("verify: %s: %w", s.Name, err)
	}

	builderPrefix := serverURL + "/" + expandWorkflow(*pp.p.Trust.Provenance.SignerWorkflow, pp.c) + "@"
	if !strings.HasPrefix(*pred.RunDetails.Builder.ID, builderPrefix) {
		return fmt.Errorf("verify: %s: builder.id does not name the trusted signer", s.Name)
	}

	bt, ok := pp.p.Build.BuildTypes[*pred.BuildDefinition.BuildType]
	if !ok {
		return fmt.Errorf("verify: %s: buildType %q is not one the policy accepts", s.Name, *pred.BuildDefinition.BuildType)
	}

	params, err := jsonx.DecodeBytes[map[string]jsonx.Raw](pred.BuildDefinition.ExternalParameters)
	if err != nil {
		return fmt.Errorf("verify: %s: externalParameters: %w", s.Name, err)
	}

	// The spec's SHOULD enforced as MUST (the org stance): an
	// unrecognised field is where unofficial behaviour hides.
	allowed := map[string]bool{}
	for _, k := range bt.ExternalParameterKeys {
		allowed[k] = true
	}

	for key := range *params {
		if !allowed[key] {
			// Field names only; the values are attacker-controlled.
			return fmt.Errorf("verify: %s: externalParameters carries an unrecognised field", s.Name)
		}
	}

	return pp.checkWorkflowParam(s, *params, verified)
}

// checkWorkflowParam asserts the workflow identity inside
// externalParameters: repository and ref from the release
// coordinates, path against the certificate's own build config —
// binding the provenance content to the certificate that vouched
// for it.
func (pp *provenancePass) checkWorkflowParam(s Subject, params map[string]jsonx.Raw, verified *trust.Verified) error {
	raw, ok := params["workflow"]
	if !ok {
		return fmt.Errorf("verify: %s: externalParameters carries no workflow object", s.Name)
	}

	wf, err := jsonx.DecodeBytes[externalWorkflow](raw)
	if err != nil {
		return fmt.Errorf("verify: %s: externalParameters.workflow: %w", s.Name, err)
	}

	wantRef := "refs/tags/" + pp.c.Tag

	cfg, err := splitConfigURI(verified.Extensions.BuildConfigURI, pp.c.Slug())
	if err != nil {
		return fmt.Errorf("verify: %s: %w", s.Name, err)
	}

	var fail []string

	if wf.Repository == nil || *wf.Repository != pp.srcRepo {
		fail = append(fail, "repository")
	}

	if wf.Ref == nil || *wf.Ref != wantRef {
		fail = append(fail, "ref")
	}

	if wf.Path == nil || *wf.Path != cfg.path {
		fail = append(fail, "path")
	}

	if cfg.ref != wantRef {
		fail = append(fail, "configRef")
	}

	if len(fail) > 0 {
		// Field names only; the values are attacker-controlled.
		return fmt.Errorf("verify: %s: externalParameters.workflow does not match the release coordinates: %s",
			s.Name, strings.Join(fail, " "))
	}

	return nil
}

// close runs the after-the-loop assertions: coverage equality and
// the source-revision fold.
func (pp *provenancePass) close(subjects []Subject) error {
	for _, s := range subjects {
		if !pp.covered[s.SHA256+"  "+s.Name] {
			return fmt.Errorf("verify: %s: no verified provenance covers this subject", s.Name)
		}
	}

	if len(pp.opened) == 0 {
		return errors.New("verify: no provenance opened — a verdict over nothing is not a verdict")
	}

	if len(pp.revisions) != 1 {
		revs := make([]string, 0, len(pp.revisions))
		for r := range pp.revisions {
			revs = append(revs, r)
		}

		sort.Strings(revs)

		return fmt.Errorf(
			"verify: verified provenance disagrees on the source revision: %s — one release, one revision, or no claim",
			strings.Join(revs, " "))
	}

	if rev := pp.oneRevision(); !hex40RE.MatchString(rev) {
		return fmt.Errorf("verify: attested source revision %q is not a full commit digest", rev)
	}

	return nil
}

// oneRevision reads the fold's single member. Only meaningful after
// close proved the set a singleton.
func (pp *provenancePass) oneRevision() string {
	for r := range pp.revisions {
		return r
	}

	return ""
}

// subjectLine renders a statement subject in manifest form. A
// subject without a sha256 cannot match any manifest line and is
// refused by name rather than silently uncovered.
func subjectLine(sub intoto.ResourceDescriptor) (string, error) {
	digest, ok := sub.Digest[intoto.AlgSHA256]
	if !ok {
		return "", errors.New("statement subject carries no sha256 digest")
	}

	name := ""
	if sub.Name != nil {
		name = *sub.Name
	}

	return digest + "  " + name, nil
}

// buildConfig is a parsed certificate build-config URI:
// "<server>/<slug>/<path>@<ref>".
type buildConfig struct {
	path string
	ref  string
}

// splitConfigURI parses the certificate's build config URI and
// refuses one naming a foreign repository: the entry workflow that
// built a release lives in the repository that released.
func splitConfigURI(uri, slug string) (*buildConfig, error) {
	rest, ok := strings.CutPrefix(uri, serverURL+"/"+slug+"/")
	if !ok {
		return nil, fmt.Errorf("certificate build config %q is not in the release repository", uri)
	}

	path, ref, ok := strings.Cut(rest, "@")
	if !ok || path == "" || ref == "" {
		return nil, fmt.Errorf("certificate build config %q carries no path@ref", uri)
	}

	return &buildConfig{path: path, ref: ref}, nil
}

// validateSBOMs refuses a decision judgment that could not be one:
// no candidates at all, or a plan naming a document the release does
// not carry. The plan is the DENOMINATOR — a denominator naming
// bytes nobody published measures the obligation against a document
// no consumer can hold, which is a caller defect, not a verdict.
func validateSBOMs(s SBOMs) error {
	if err := validateSubjects(s.Assets); err != nil {
		return fmt.Errorf("%w — the decision has no subject to verify against", err)
	}

	if len(s.Planned) == 0 {
		return nil
	}

	if err := validateSubjects(s.Planned); err != nil {
		return fmt.Errorf("%w — the plan is the decision's denominator", err)
	}

	carried := map[string]bool{}
	for _, a := range s.Assets {
		carried[subjectKey(a)] = true
	}

	for _, inv := range s.Planned {
		if !carried[subjectKey(inv)] {
			return fmt.Errorf(
				"verify: the plan names inventory %s, which is not among the release's SBOM assets — "+
					"a planned document that did not ship decides nothing", inv.Name)
		}
	}

	return nil
}

// subjectKey renders a subject as one comparable line — digest and
// name together, the manifest form, so a plan entry matches an asset
// only when BOTH agree.
func subjectKey(s Subject) string { return s.SHA256 + "  " + s.Name }

// verifyDecision proves the release decision against the plan. Two
// obligations, one for each direction the plan can be defeated
// (stele#158):
//
//   - every planned inventory carries a decision attestation that
//     verifies under the decision identity over its own bytes and
//     names the required conclusion for this tag;
//   - no decision names anything the plan does not — a decision over
//     the union view (a view is aggregated from the per-artifact
//     documents, .github#492, and decides nothing of its own) or over
//     a document no plan produced is machinery deciding something the
//     release never planned.
//
// The second direction is read from the decisions' own signed
// subject lists, never by asking the store about assets the plan does
// not name: absence is not a question the attestation API answers —
// it retries a just-published digest and then errors — so a probe
// there would read "this view has no decision, correctly" and "the
// forge is degraded" as the same byte. It is the same rule the
// provenance pass holds against the release manifest, pointed at the
// plan.
//
// Selection is by verification throughout, never by filename (#354):
// a decision counts by being signed over a candidate's own bytes
// under the pinned identity. Nothing is SELECTED at all in the
// planned world — every decision found is judged, so "which one is
// the decision" cannot be asked, which is what makes the ambiguity
// this replaces (one decision, N candidates) unrepresentable rather
// than merely refused.
//
// A release with no plan falls to the whole-release invariant it was
// published under.
func verifyDecision(
	p *policy.Policy, c Coords, sboms SBOMs, pins Pins,
	store Store, bv BundleVerifier, log Logf,
) ([]Ref, error) {
	dp := &decisionPass{
		p: p,
		c: c,
		id: trust.Identity{
			SAN: workflowSAN(expandWorkflow(*p.Trust.Decision.SignerWorkflow, c),
				identityRef(expandWorkflow(*p.Trust.Decision.SignerWorkflow, c), c, pins.Machinery)),
			Issuer: *p.Issuer,
		},
		pin:    pins.Machinery,
		store:  store,
		bv:     bv,
		opened: map[string]bool{},
	}

	if len(sboms.Planned) == 0 {
		return dp.wholeRelease(sboms.Assets, log)
	}

	return dp.perInventory(sboms, log)
}

// decisionPass carries the decision judgment's shared state: the
// identity every candidate is proven against, and the bundles
// already opened, so one attestation covering several subjects is
// listed once however many times it is met.
type decisionPass struct {
	p      *policy.Policy
	c      Coords
	id     trust.Identity
	pin    string
	store  Store
	bv     BundleVerifier
	opened map[string]bool
	refs   []Ref
}

// perInventory runs the plan-shaped obligation: one decision per
// planned inventory, and nothing decided that the plan never named.
func (dp *decisionPass) perInventory(sboms SBOMs, log Logf) ([]Ref, error) {
	planned := map[string]bool{}
	for _, inv := range sboms.Planned {
		planned[subjectKey(inv)] = true
	}

	for _, inv := range sboms.Planned {
		found, err := dp.decisions(inv)
		if err != nil {
			return nil, err
		}

		if len(found) == 0 {
			return nil, fmt.Errorf(
				"verify: %s: the release plans this inventory but no verified decision covers it — "+
					"refusing the verdict", inv.Name)
		}

		for _, d := range found {
			if aerr := dp.accept(inv, d, planned); aerr != nil {
				return nil, aerr
			}
		}
	}

	log("verify: release decision verified: %s for %s over %d planned inventory document(s)",
		*dp.p.Trust.Decision.RequiredConclusion, dp.c.Tag, len(sboms.Planned))

	return dp.refs, nil
}

// wholeRelease runs the invariant every release without a plan was
// published under: among the SBOM assets, EXACTLY one carries a
// decision. Two bearers are ambiguous — here a decision must still be
// selected, because the release declared no denominator to judge them
// against, and picking arbitrarily would be the verifier inventing
// the answer it was asked for.
func (dp *decisionPass) wholeRelease(assets []Subject, log Logf) ([]Ref, error) {
	var winner *Subject

	for i, a := range assets {
		found, err := dp.decisions(a)
		if err != nil {
			return nil, err
		}

		if len(found) == 0 {
			continue
		}

		if winner != nil {
			return nil, errors.New(
				"verify: more than one SBOM asset carries a release decision — ambiguous, refusing the verdict")
		}

		winner = &assets[i]

		for _, d := range found {
			if aerr := dp.accept(a, d, nil); aerr != nil {
				return nil, aerr
			}
		}
	}

	if winner == nil {
		return nil, errors.New("verify: no SBOM asset carries a verifiable release decision — refusing the verdict")
	}

	log("verify: release decision verified: %s for %s", *dp.p.Trust.Decision.RequiredConclusion, dp.c.Tag)

	return dp.refs, nil
}

// accept holds one verified decision against the policy and the plan,
// then records it as evidence this verdict rests on. Every decision
// opened is asked the same questions — a second decision agreeing
// with the first is not an ambiguity, and a second one disagreeing
// must never be the one nobody read — but only once per attestation:
// one bundle covering several inventories is judged where it is first
// met and listed once.
//
// planned nil is the release that declared no plan: there is no
// denominator to hold coverage against, and inventing one from the
// asset list would be this engine deciding what the release planned.
func (dp *decisionPass) accept(s Subject, d decision, planned map[string]bool) error {
	if dp.opened[d.ref.SHA256] {
		return nil
	}

	want := *dp.p.Trust.Decision.RequiredConclusion
	if d.pred.Conclusion == nil || *d.pred.Conclusion != want {
		return fmt.Errorf("verify: %s: the release decision does not name conclusion %s — refusing the verdict",
			s.Name, want)
	}

	if d.pred.Tag == nil || *d.pred.Tag != dp.c.Tag {
		return fmt.Errorf("verify: %s: the release decision does not name tag %s — refusing the verdict",
			s.Name, dp.c.Tag)
	}

	if planned != nil {
		if cerr := coversPlanOnly(d, planned); cerr != nil {
			return cerr
		}
	}

	dp.opened[d.ref.SHA256] = true
	dp.refs = append(dp.refs, d.ref)

	return nil
}

// coversPlanOnly holds one decision's own subject list against the
// plan: a decision may name planned inventories and nothing else.
// The release view, the evidence manifest, a VEX document — each is
// a document ABOUT the release that no plan produced, and a decision
// reaching them is one decision standing in for the per-artifact
// decisions the plan owes.
func coversPlanOnly(d decision, planned map[string]bool) error {
	for _, sub := range d.subjects {
		line, err := subjectLine(sub)
		if err != nil {
			return fmt.Errorf("verify: release decision: %w", err)
		}

		if !planned[line] {
			name := "an unnamed subject"
			if sub.Name != nil {
				name = *sub.Name
			}

			return fmt.Errorf(
				"verify: a release decision names %s, which the release's plan does not — refusing the verdict", name)
		}
	}

	return nil
}

// decision is one release decision proven over a candidate's bytes:
// the bundle it was read from, the claim it carries, and everything
// it names — the subject list read from the VERIFIED statement, so
// what a decision covers is evidence rather than a second fetch.
type decision struct {
	ref      Ref
	pred     *decisionPredicate
	subjects []intoto.ResourceDescriptor
}

// decisions examines one SBOM candidate and returns every decision
// the store holds over its bytes. A candidate carrying none is simply
// not decided; a decision-typed bundle that FAILS verification is a
// refusal, never a pass-over — a forged decision must never read as
// an absent one.
func (dp *decisionPass) decisions(s Subject) ([]decision, error) {
	bundles, err := dp.store.Bundles(dp.c.Slug(), s.SHA256)
	if err != nil {
		return nil, fmt.Errorf("verify: %s: no attestation retrievable: %w", s.Name, err)
	}

	var found []decision

	seen := map[string]bool{}

	for _, sb := range bundles {
		stmtPeek, perr := dp.bv.Peek(sb.Bundle)
		if perr != nil {
			return nil, fmt.Errorf("verify: %s: unreadable bundle in the store: %w", s.Name, perr)
		}

		peek, derr := jsonx.DecodeBytes[intoto.Statement](stmtPeek)
		if derr != nil {
			return nil, fmt.Errorf("verify: %s: bundle payload is not a statement: %w", s.Name, derr)
		}

		if peek.PredicateType == nil || *peek.PredicateType != *dp.p.Trust.Decision.PredicateType {
			continue
		}

		bsha := sha256Hex(sb.Bundle)
		if seen[bsha] {
			continue
		}

		seen[bsha] = true

		d, verr := dp.verified(s, sb, bsha)
		if verr != nil {
			return nil, verr
		}

		found = append(found, *d)
	}

	return found, nil
}

// verified proves one decision-typed bundle over the candidate's own
// digest and decodes the claim from the VERIFIED bytes — the peek
// above selected, this judges.
func (dp *decisionPass) verified(s Subject, sb StoredBundle, bsha string) (*decision, error) {
	v, err := dp.bv.Attestation(sb.Bundle, dp.id, s.SHA256)
	if err != nil {
		return nil, fmt.Errorf("verify: %s: decision bundle refused: %w", s.Name, err)
	}

	// The commit-level binding, independent of the SAN's ref form.
	if got := v.Extensions.BuildSignerDigest; got != dp.pin {
		return nil, fmt.Errorf("verify: %s: decision signed at %q, pin is %q", s.Name, got, dp.pin)
	}

	stmt, serr := jsonx.DecodeBytes[intoto.Statement](v.Payload)
	if serr != nil {
		return nil, fmt.Errorf("verify: %s: verified payload is not a statement: %w", s.Name, serr)
	}

	if verr := stmt.Validate(); verr != nil {
		return nil, fmt.Errorf("verify: %s: %w", s.Name, verr)
	}

	if *stmt.PredicateType != *dp.p.Trust.Decision.PredicateType {
		return nil, fmt.Errorf("verify: %s: verified payload is not a release decision", s.Name)
	}

	pred, perr := jsonx.DecodeBytes[decisionPredicate](stmt.Predicate)
	if perr != nil {
		return nil, fmt.Errorf("verify: %s: decision predicate: %w", s.Name, perr)
	}

	return &decision{ref: Ref{URI: sb.URI, SHA256: bsha}, pred: pred, subjects: stmt.Subject}, nil
}
