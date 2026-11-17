// The source verdict for a release tag (stele#391): a second verdict
// beside the release verdict, binding the tag's name to the commit it
// points at and to the source level that commit's chain link already
// holds. It adds no claim the chain does not support — the level is
// copied from the verified link, never computed afresh — and it is
// signed by the verdict identity, which is not the repository's own.
//
// The verdict is a whole in-toto statement, not a bare predicate: its
// subject is a gitCommit digest carrying a `sourceRefs` annotation,
// which no subject-from-file attestation step can express. It travels
// in the chain format's own envelope (payload type, base64 statement,
// the bundle signing PAE over both), because a bundle signed over PAE
// bytes does not carry the statement it covers.

package verify

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/dsse"
	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/vsa"
)

// SourceVerdict is the proof that a release tag's two source checks
// passed: the tag's signature verified under the tags policy, and the
// commit it points at carries a verified chain link. Fields are
// unexported and NewSourceVerdict is the only constructor — the #208
// rule again: a statement for a tag nobody verified is unrepresentable.
type SourceVerdict struct {
	tag    string
	commit string
	levels []string
	halves []Ref
}

// NewSourceVerdict joins the two proofs the verdict rests on. tag is
// the tag's verified signature; target is the commit the tag object
// names; release is the one source revision the release verification
// folded its provenance to; link is the verified chain link on that
// commit, from a walk of a protected branch. A nil proof refuses by
// name — the caller found none — and so does a tag pointing anywhere
// but the commit the release was built from.
func NewSourceVerdict(c Coords, release, target string, tag *trust.TagVerdict, link *TipFacts) (*SourceVerdict, error) {
	if err := validateCoords(c, true); err != nil {
		return nil, err
	}

	if !hex40RE.MatchString(release) {
		return nil, fmt.Errorf("verify: source verdict for %s: release revision %q is not a commit digest", c.Tag, release)
	}

	switch {
	case tag == nil:
		return nil, fmt.Errorf("verify: source verdict for %s: the tag carries no verified signature", c.Tag)
	case target != release:
		return nil, fmt.Errorf(
			"verify: source verdict for %s: the tag points at %s, not %s — the commit the release was built from",
			c.Tag, target, release,
		)
	case link == nil:
		return nil, fmt.Errorf(
			"verify: source verdict for %s: commit %s carries no verified chain link on a declared protected branch",
			c.Tag, target,
		)
	case link.Revision() != target:
		return nil, fmt.Errorf("verify: source verdict for %s: the link verified at %s, the tag's commit is %s",
			c.Tag, link.Revision(), target)
	case len(link.vsaLevels) == 0:
		return nil, fmt.Errorf("verify: source verdict for %s: the link at %s claims no level to copy", c.Tag, target)
	}

	return &SourceVerdict{
		tag:    c.Tag,
		commit: target,
		levels: slices.Clone(link.vsaLevels),
		halves: link.Halves(),
	}, nil
}

// Commit is the tag's target, the verdict's subject.
func (v *SourceVerdict) Commit() string { return v.commit }

// Levels are the levels copied from the commit's verified link.
func (v *SourceVerdict) Levels() []string { return slices.Clone(v.levels) }

// Statement renders the verdict's in-toto statement: the commit as
// subject with the tag in `sourceRefs`, and a VSA predicate naming the
// verdict identity as verifier, the source resource, the policy pinned
// by uri and commit, the copied levels, and the link's two halves as
// inputAttestations. Validated through the same types the read below
// decodes with.
func (v *SourceVerdict) Statement(
	p *policy.Policy, c Coords, policyURI, machineryDigest, timeVerified string,
) ([]byte, error) {
	if p.Trust == nil || p.Trust.Verdict == nil {
		return nil, errors.New("verify: the policy declares no trust.verdict — a source verdict cannot name its verifier")
	}

	if p.Source == nil {
		return nil, errors.New("verify: the policy declares no source section — a source verdict names its resource")
	}

	pred, err := vsa.New(
		serverURL+"/"+expandWorkflow(*p.Trust.Verdict.VerifierWorkflow, c),
		timeVerified,
		expand(*p.Source.ResourceURI, c),
		policyURI, machineryDigest,
		vsa.ResultPassed,
		v.levels,
	)
	if err != nil {
		return nil, fmt.Errorf("verify: source verdict predicate: %w", err)
	}

	for i := range v.halves {
		pred.InputAttestations = append(pred.InputAttestations, intoto.ResourceDescriptor{
			URI:    &v.halves[i].URI,
			Digest: map[string]string{intoto.AlgSHA256: v.halves[i].SHA256},
		})
	}

	predRaw, err := jsonx.Marshal(pred)
	if err != nil {
		return nil, fmt.Errorf("verify: source verdict predicate: %w", err)
	}

	annotations, err := jsonx.Marshal(map[string][]string{sourceRefsKey: {tagRef(v.tag)}})
	if err != nil {
		return nil, fmt.Errorf("verify: source verdict annotations: %w", err)
	}

	uri := serverURL + "/" + c.Slug() + "/commit/" + v.commit
	stype, ptype := intoto.StatementType, vsa.PredicateType
	stmt := intoto.Statement{
		Type: &stype,
		Subject: []intoto.ResourceDescriptor{{
			URI:         &uri,
			Digest:      map[string]string{intoto.AlgGitCommit: v.commit},
			Annotations: annotations,
		}},
		PredicateType: &ptype,
		Predicate:     predRaw,
	}

	if err := stmt.Validate(); err != nil {
		return nil, fmt.Errorf("verify: source verdict statement: %w", err)
	}

	return jsonx.Marshal(stmt)
}

// SourceVerdictPAE is the exact byte string a source verdict's
// signature covers: DSSE's pre-authentication encoding of the
// statement under the chain format's payload type.
func SourceVerdictPAE(stmt []byte) []byte { return dsse.PAE(chain.StatementType, stmt) }

// SourceVerdictEnvelope packs a signed statement into the envelope the
// read below takes: the chain format's half shape, one definition.
func SourceVerdictEnvelope(stmt, bundle []byte) ([]byte, error) {
	ptype := chain.StatementType
	encoded := base64.StdEncoding.EncodeToString(stmt)

	return jsonx.Marshal(chain.Envelope{PayloadType: &ptype, Statement: &encoded, Bundle: bundle})
}

// sourceRefsKey is the subject annotation naming the refs a source
// verdict speaks for — the key the chain's own links carry.
const sourceRefsKey = "sourceRefs"

// tagRef is the fully qualified ref of one tag.
func tagRef(tag string) string { return "refs/tags/" + tag }

// SourceVSAVerdict is the proof a published source verdict verified
// for one tag. Constructor: SourceVSA, alone.
type SourceVSAVerdict struct {
	commit string
	levels []string
}

// Commit is the tag's commit the verdict was held against.
func (v *SourceVSAVerdict) Commit() string { return v.commit }

// Levels are the levels the verdict claimed, each within what the
// commit's link shows.
func (v *SourceVSAVerdict) Levels() []string { return slices.Clone(v.levels) }

// SourceVSA reads one source verdict for a tag: the signature under
// the verdict identity at the machinery pin, over PAE of the exact
// statement; a single subject whose gitCommit digest is the tag's
// commit; `sourceRefs` naming exactly that tag; the predicate's
// verifier, resource and result; and levels no higher than the
// commit's link shows now (link: the walk's verified facts for that
// commit, nil when none). Epoch-free: whether a release OWES one is
// the corpus walk's question.
func SourceVSA(
	p *policy.Policy, c Coords, pins Pins, commit string, link *TipFacts, envelope []byte, bv BundleVerifier,
) (*SourceVSAVerdict, error) {
	if err := validateCoords(c, true); err != nil {
		return nil, err
	}

	if p.Trust == nil || p.Trust.Verdict == nil || p.Source == nil {
		return nil, errors.New("verify: a source verdict is read under trust.verdict and source — the policy lacks one")
	}

	if !hex40RE.MatchString(pins.Machinery) {
		return nil, errors.New("verify: machinery digest is not a 40-hex commit")
	}

	if link == nil {
		return nil, fmt.Errorf("verify: source verdict for %s: commit %s carries no verified chain link today — "+
			"there is no level the verdict could be held within", c.Tag, commit)
	}

	stmt, err := openSourceVerdict(c, sourceVerdictRoot(p, c, pins), envelope, bv)
	if err != nil {
		return nil, err
	}

	if serr := sourceSubject(c, stmt, commit); serr != nil {
		return nil, serr
	}

	pred, err := jsonx.DecodeBytes[vsa.Predicate](stmt.Predicate)
	if err != nil {
		return nil, fmt.Errorf("verify: source verdict for %s: predicate: %w", c.Tag, err)
	}

	if jerr := judgeSourcePredicate(p, c, pins, pred); jerr != nil {
		return nil, jerr
	}

	if lerr := levelsWithin(pred.VerifiedLevels, link.vsaLevels); lerr != nil {
		return nil, fmt.Errorf("verify: source verdict for %s: %w", c.Tag, lerr)
	}

	return &SourceVSAVerdict{commit: commit, levels: slices.Clone(pred.VerifiedLevels)}, nil
}

// sourceVerdictRoot is the identity a source verdict verifies under:
// the CURRENT verifier at the machinery pin. Never the legacy lookup —
// grandfathered verdicts predate this mechanism, so none of them is a
// source verdict, and a source verdict signed by a legacy root is not
// one this tool ever emitted.
func sourceVerdictRoot(p *policy.Policy, c Coords, pins Pins) verdictRoot {
	workflow := expandWorkflow(*p.Trust.Verdict.VerifierWorkflow, c)

	return verdictRoot{
		id:  trust.Identity{SAN: workflowSAN(workflow, identityRef(workflow, c, pins.Machinery)), Issuer: *p.Issuer},
		pin: pins.Machinery,
		uri: serverURL + "/" + workflow,
	}
}

// openSourceVerdict decodes the envelope, proves its bundle over PAE
// of the exact statement bytes under the root, and returns the
// validated VSA statement.
func openSourceVerdict(c Coords, root verdictRoot, envelope []byte, bv BundleVerifier) (*intoto.Statement, error) {
	env, err := jsonx.DecodeBytes[chain.Envelope](envelope)
	if err != nil {
		return nil, fmt.Errorf("verify: source verdict for %s: envelope: %w", c.Tag, err)
	}

	switch {
	case env.PayloadType == nil || *env.PayloadType != chain.StatementType:
		return nil, fmt.Errorf("verify: source verdict for %s: payloadType is not %s", c.Tag, chain.StatementType)
	case env.Statement == nil || *env.Statement == "":
		return nil, fmt.Errorf("verify: source verdict for %s: statement is absent or empty", c.Tag)
	case len(env.Bundle) == 0:
		return nil, fmt.Errorf("verify: source verdict for %s: bundle is absent", c.Tag)
	}

	stmtBytes, err := dsse.DecodeBase64(*env.Statement)
	if err != nil {
		return nil, fmt.Errorf("verify: source verdict for %s: statement: %w", c.Tag, err)
	}

	verified, err := bv.Blob(env.Bundle, root.id, sha256Hex(SourceVerdictPAE(stmtBytes)))
	if err != nil {
		return nil, fmt.Errorf("verify: source verdict for %s: signature refused under %s: %w", c.Tag, root.id.SAN, err)
	}

	if got := verified.Extensions.BuildSignerDigest; got != root.pin {
		return nil, fmt.Errorf("verify: source verdict for %s: signed at %q, pin is %q", c.Tag, got, root.pin)
	}

	stmt, err := jsonx.DecodeBytes[intoto.Statement](stmtBytes)
	if err != nil {
		return nil, fmt.Errorf("verify: source verdict for %s: statement: %w", c.Tag, err)
	}

	if err := stmt.Validate(); err != nil {
		return nil, fmt.Errorf("verify: source verdict for %s: %w", c.Tag, err)
	}

	if *stmt.PredicateType != vsa.PredicateType {
		return nil, fmt.Errorf("verify: source verdict for %s: predicate type %q is not the VSA type",
			c.Tag, *stmt.PredicateType)
	}

	return stmt, nil
}

// sourceSubject requires exactly one subject: the tag's commit, by
// gitCommit digest, annotated with exactly this tag's ref.
func sourceSubject(c Coords, stmt *intoto.Statement, commit string) error {
	if len(stmt.Subject) != 1 {
		return fmt.Errorf("verify: source verdict for %s: %d subjects — the verdict speaks for one commit",
			c.Tag, len(stmt.Subject))
	}

	sub := stmt.Subject[0]
	if got := sub.Digest[intoto.AlgGitCommit]; got != commit {
		return fmt.Errorf("verify: source verdict for %s: subject attests commit %q, the tag's commit is %s",
			c.Tag, got, commit)
	}

	if len(sub.Annotations) == 0 {
		return fmt.Errorf("verify: source verdict for %s: the subject carries no sourceRefs", c.Tag)
	}

	annotations, err := jsonx.DecodeBytes[map[string]jsonx.Raw](sub.Annotations)
	if err != nil {
		return fmt.Errorf("verify: source verdict for %s: annotations: %w", c.Tag, err)
	}

	raw, ok := (*annotations)[sourceRefsKey]
	if !ok {
		return fmt.Errorf("verify: source verdict for %s: the subject carries no sourceRefs", c.Tag)
	}

	refs, err := jsonx.DecodeBytes[[]string](raw)
	if err != nil {
		return fmt.Errorf("verify: source verdict for %s: sourceRefs: %w", c.Tag, err)
	}

	if want := tagRef(c.Tag); len(*refs) != 1 || (*refs)[0] != want {
		return fmt.Errorf("verify: source verdict for %s: sourceRefs names %s, not exactly %s",
			c.Tag, strconv.Quote(fmt.Sprint(*refs)), want)
	}

	return nil
}

// judgeSourcePredicate runs the VSA's own steps: format, verifier as a
// tautology with the signing identity, resource, result.
func judgeSourcePredicate(p *policy.Policy, c Coords, pins Pins, pred *vsa.Predicate) error {
	if err := pred.Validate(); err != nil {
		return fmt.Errorf("verify: source verdict for %s: %w", c.Tag, err)
	}

	root := sourceVerdictRoot(p, c, pins)
	if *pred.Verifier.ID != root.uri {
		return fmt.Errorf("verify: source verdict for %s: verifier.id %q is not the signing identity %q",
			c.Tag, *pred.Verifier.ID, root.uri)
	}

	if want := expand(*p.Source.ResourceURI, c); *pred.ResourceURI != want {
		return fmt.Errorf("verify: source verdict for %s: names resource %q, expected %q", c.Tag, *pred.ResourceURI, want)
	}

	if *pred.VerificationResult != vsa.ResultPassed {
		return fmt.Errorf("verify: source verdict for %s: verificationResult is %q, not %s",
			c.Tag, *pred.VerificationResult, vsa.ResultPassed)
	}

	return nil
}

// levelsWithin holds a verdict's claimed levels against what the
// link shows: an SLSA track level may not exceed the link's level on
// the same track, and any other value (an org property) must be one
// the link still carries. A claim the link no longer supports is an
// overclaim, whatever the verdict said when it was signed.
func levelsWithin(claimed, held []string) error {
	pred := &vsa.Predicate{VerifiedLevels: held}

	for _, l := range claimed {
		m := slsaTrackLevel(l)
		if m == nil {
			if !slices.Contains(held, l) {
				return fmt.Errorf("claims %q, which the commit's link no longer carries", l)
			}

			continue
		}

		have, ok := pred.Level(m.track)
		if !ok {
			return fmt.Errorf("claims %s, the commit's link shows no %s level", l, m.track)
		}

		h := slsaTrackLevel(have)
		if h == nil || h.level < m.level {
			return fmt.Errorf("claims %s, higher than the commit's link shows (%s)", l, have)
		}
	}

	return nil
}

// slsaLevelRE is a numbered SLSA level. The vsa package owns the
// format rule; this reads the number out of a value it already
// validated.
var slsaLevelRE = regexp.MustCompile(`^SLSA_([A-Z]+)_LEVEL_(\d+)$`)

// trackLevel is one parsed SLSA_<TRACK>_LEVEL_<N>.
type trackLevel struct {
	track string
	level int
}

// slsaTrackLevel parses a numbered SLSA level, or nil for anything
// else (a custom value, or UNEVALUATED — which claims no rung).
func slsaTrackLevel(l string) *trackLevel {
	m := slsaLevelRE.FindStringSubmatch(l)
	if m == nil {
		return nil
	}

	n, err := strconv.Atoi(m[2])
	if err != nil {
		return nil
	}

	return &trackLevel{track: m[1], level: n}
}
