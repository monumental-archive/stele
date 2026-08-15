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
	p *policy.Policy, c Coords, policyURI, canonDigest, timeVerified string,
) ([]byte, error) {
	pred, err := vsa.New(
		serverURL+"/"+*p.Trust.Verdict.VerifierWorkflow,
		timeVerified,
		expand(*p.Build.ResourceURI, c),
		policyURI, canonDigest,
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

// Release verifies one published release like a stranger: subjects
// are the manifest the release claims, sboms are the release's SBOM
// assets (the decision candidates — a separate list because a class
// manifest need not contain the release SBOM), and everything else
// is fetched through store and proven through bv. It fails closed at
// the first refusal; the returned verdict exists only on a fully
// clean pass.
func Release(
	p *policy.Policy, c Coords, subjects, sboms []Subject, pins Pins,
	store Store, bv BundleVerifier, log Logf,
) (*ReleaseVerdict, error) {
	if err := validateInputs(c, subjects, pins); err != nil {
		return nil, err
	}

	if err := validateSubjects(sboms); err != nil {
		return nil, fmt.Errorf("%w — the decision has no subject to verify against", err)
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
			return nil, fmt.Errorf("verify: %s: no attestation retrievable: %w", s.Name, err)
		}

		if err := prov.subject(s, bundles, bv, log); err != nil {
			return nil, err
		}
	}

	if err := prov.close(subjects); err != nil {
		return nil, err
	}

	decisionRef, err := verifyDecision(p, c, sboms, pins, store, bv, log)
	if err != nil {
		return nil, err
	}

	verdict := &ReleaseVerdict{
		sourceRevision: prov.oneRevision(),
		opened:         append(prov.opened, *decisionRef),
		subjects:       len(subjects),
	}

	log("verify: release %s@%s: %d attestation(s) opened over %d subject(s), source revision %s",
		c.Slug(), c.Tag, len(verdict.opened), verdict.subjects, verdict.sourceRevision)

	return verdict, nil
}

func validateInputs(c Coords, subjects []Subject, pins Pins) error {
	if err := validateCoords(c, true); err != nil {
		return err
	}

	if err := validateSubjects(subjects); err != nil {
		return err
	}

	if !hex40RE.MatchString(pins.Signer) || !hex40RE.MatchString(pins.Canon) {
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
			SAN: workflowSAN(*p.Trust.Provenance.SignerWorkflow,
				identityRef(*p.Trust.Provenance.SignerWorkflow, c, pins.Signer)),
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

	builderPrefix := serverURL + "/" + *pp.p.Trust.Provenance.SignerWorkflow + "@"
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

// verifyDecision finds and proves the release decision: among the
// release's SBOM assets, exactly one must carry a decision
// attestation verifying under the decision identity, and that
// decision must name the required conclusion for this tag. Selection
// is by verification, never by filename — a candidate only wins by
// carrying a decision signed over its own bytes (#354).
func verifyDecision(
	p *policy.Policy, c Coords, sboms []Subject, pins Pins,
	store Store, bv BundleVerifier, log Logf,
) (*Ref, error) {
	id := trust.Identity{
		SAN:    workflowSAN(*p.Trust.Decision.SignerWorkflow, identityRef(*p.Trust.Decision.SignerWorkflow, c, pins.Canon)),
		Issuer: *p.Issuer,
	}

	var (
		winner  *Ref
		verdict *decisionPredicate
	)

	for _, s := range sboms {
		ref, pred, err := decisionFor(p, c.Slug(), s, id, pins.Canon, store, bv)
		if err != nil {
			return nil, err
		}

		if pred == nil {
			continue
		}

		if winner != nil {
			return nil, errors.New(
				"verify: more than one SBOM asset carries a release decision — ambiguous, refusing the verdict")
		}

		winner, verdict = ref, pred
	}

	if winner == nil {
		return nil, errors.New("verify: no SBOM asset carries a verifiable release decision — refusing the verdict")
	}

	want := *p.Trust.Decision.RequiredConclusion
	if verdict.Conclusion == nil || *verdict.Conclusion != want {
		return nil, fmt.Errorf("verify: the release decision does not name conclusion %s — refusing the verdict", want)
	}

	if verdict.Tag == nil || *verdict.Tag != c.Tag {
		return nil, fmt.Errorf("verify: the release decision does not name tag %s — refusing the verdict", c.Tag)
	}

	log("verify: release decision verified: %s for %s", want, c.Tag)

	return winner, nil
}

// decisionFor examines one SBOM candidate: a decision-typed bundle
// that verifies under the decision identity over the candidate's own
// digest makes it a winner; a candidate carrying none is simply not
// the decided SBOM. A decision-typed bundle that FAILS verification
// is a refusal, not a pass-over — a forged decision must never read
// as an absent one.
func decisionFor(
	p *policy.Policy, slug string, s Subject, id trust.Identity, pin string, store Store, bv BundleVerifier,
) (*Ref, *decisionPredicate, error) {
	bundles, err := store.Bundles(slug, s.SHA256)
	if err != nil {
		return nil, nil, fmt.Errorf("verify: %s: no attestation retrievable: %w", s.Name, err)
	}

	for _, sb := range bundles {
		stmtPeek, perr := bv.Peek(sb.Bundle)
		if perr != nil {
			return nil, nil, fmt.Errorf("verify: %s: unreadable bundle in the store: %w", s.Name, perr)
		}

		peek, derr := jsonx.DecodeBytes[intoto.Statement](stmtPeek)
		if derr != nil {
			return nil, nil, fmt.Errorf("verify: %s: bundle payload is not a statement: %w", s.Name, derr)
		}

		if peek.PredicateType == nil || *peek.PredicateType != *p.Trust.Decision.PredicateType {
			continue
		}

		verified, err := bv.Attestation(sb.Bundle, id, s.SHA256)
		if err != nil {
			return nil, nil, fmt.Errorf("verify: %s: decision bundle refused: %w", s.Name, err)
		}

		// The commit-level binding, independent of the SAN's ref form.
		if got := verified.Extensions.BuildSignerDigest; got != pin {
			return nil, nil, fmt.Errorf("verify: %s: decision signed at %q, pin is %q", s.Name, got, pin)
		}

		stmt, serr := jsonx.DecodeBytes[intoto.Statement](verified.Payload)
		if serr != nil {
			return nil, nil, fmt.Errorf("verify: %s: verified payload is not a statement: %w", s.Name, serr)
		}

		if verr := stmt.Validate(); verr != nil {
			return nil, nil, fmt.Errorf("verify: %s: %w", s.Name, verr)
		}

		if *stmt.PredicateType != *p.Trust.Decision.PredicateType {
			return nil, nil, fmt.Errorf("verify: %s: verified payload is not a release decision", s.Name)
		}

		pred, err := jsonx.DecodeBytes[decisionPredicate](stmt.Predicate)
		if err != nil {
			return nil, nil, fmt.Errorf("verify: %s: decision predicate: %w", s.Name, err)
		}

		return &Ref{URI: sb.URI, SHA256: sha256Hex(sb.Bundle)}, pred, nil
	}

	return nil, nil, nil
}
