// The tag audit's table (stele#83): every obligation class — epoch
// declaration, annotation, tagger role, signing epoch, chain link —
// and the derived legacy bound, each broken one fact at a time.

package assert_test

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/report"
)

const tagsPolicyJSON = `{
  "schema": 6,
  "issuer": "https://token.example.com",
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "storeVsaFromVersion": "1.13.0",
    "classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}
  },
  "tags": {
    "tagPattern": "^v[0-9]",
    "taggerName": "release-mint[bot]",
    "identityPattern": "^https://github\\.com/acme/",
    "proofFloor": {"floor": "certificate-transparency"},
    "notesRef": "refs/notes/commits",
    "epochs": {"widget": "v1.1.0", "gadget": "pending"}
  }
}`

func loadTagsPolicy(t *testing.T) *assert.Policy {
	t.Helper()

	p, err := assert.LoadPolicy(strings.NewReader(tagsPolicyJSON))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	return p
}

// Revisions in the scripted history: genesis → linked → tip, with
// preGenesis dangling before the chain began.
const (
	preGenesisRev = "0000000000000000000000000000000000000001"
	genesisRev    = "0000000000000000000000000000000000000002"
	linkedRev     = "0000000000000000000000000000000000000003"
	unlinkedRev   = "0000000000000000000000000000000000000004"
	tagObjSHA     = "00000000000000000000000000000000000000aa"
	tagObjSHA2    = "00000000000000000000000000000000000000bb"
	tagObjSHA3    = "00000000000000000000000000000000000000cc"
)

// signedTagObject is one conformant annotated tag object over a
// target: the minting tagger, a payload and a signature. One
// definition, so a fixture that differs from another differs in the
// fact under test and nowhere else.
func signedTagObject(target string) *gh.TagObject {
	return &gh.TagObject{
		Tagger: "release-mint[bot]", Target: target,
		Payload:   []byte("object x\ntagger release-mint[bot] <m@e> 1755000000 +0000\n"),
		Signature: []byte("-----BEGIN SIGNED MESSAGE-----\nx\n-----END SIGNED MESSAGE-----\n"),
	}
}

const link = `{"version": 2, "provenance": {"bundle": {}}}`

// fakeTags scripts the TagReader.
type fakeTags struct {
	refs     map[string][]gh.TagRef
	objects  map[string]*gh.TagObject
	notes    map[string][]gh.ChainNote
	meta     map[string]*gh.CommitMeta
	ancestry map[string]bool // "base...head"
	refsErr  error
	// torn fails one named read — the tag audit's own version of a
	// forge that tears mid-walk.
	torn map[string]error
}

func (f *fakeTags) TagRefs(_, repo string) ([]gh.TagRef, error) {
	if f.refsErr != nil {
		return nil, f.refsErr
	}

	return f.refs[repo], nil
}

func (f *fakeTags) TagObject(_, _, sha string) (*gh.TagObject, error) {
	obj, ok := f.objects[sha]
	if !ok {
		return nil, errors.New("no such tag object scripted")
	}

	return obj, nil
}

func (f *fakeTags) ChainNotes(_, repo, _ string) ([]gh.ChainNote, error) {
	return f.notes[repo], f.tear("ChainNotes")
}

func (f *fakeTags) CommitMeta(_, _, rev string) (*gh.CommitMeta, error) {
	m, ok := f.meta[rev]
	if !ok {
		return nil, errors.New("no commit meta scripted for " + rev)
	}

	return m, nil
}

func (f *fakeTags) IsAncestor(_, _, base, head string) (bool, error) {
	return f.ancestry[base+"..."+head], f.tear("IsAncestor")
}

// tear reports the scripted failure for one named read, if any.
func (f *fakeTags) tear(read string) error { return f.torn[read] }

// fakeTagVerifier scripts the trust seam, recording the floor each
// tag was judged against — the fact stele#186's boundary is proven
// by, since a floor that binds nowhere looks exactly like one that
// binds everywhere.
type fakeTagVerifier struct {
	err    error
	called int
	floors []string
	// refuseFloor refuses exactly one floor — the shape a mint that
	// stopped embedding its receipts takes: every signature still
	// verifies, and only the raised obligation is unmet.
	refuseFloor string
}

func (v *fakeTagVerifier) Verify(_, _ []byte, floor string) (assert.TagProof, error) {
	v.called++
	v.floors = append(v.floors, floor)

	err := v.err
	if v.refuseFloor != "" && floor == v.refuseFloor {
		err = errors.New("the tag signature carries no transparency-log entry and no signed timestamp")
	}

	return assert.TagProof{
		SAN:      "https://github.com/acme/widget/x",
		Depth:    floor,
		Observed: "2026-08-19T13:49:19Z (certificate-transparency test-log)",
	}, err
}

// conformantTags scripts one repo, widget, with a signed post-epoch
// tag on a linked revision.
func conformantTags() *fakeTags {
	return &fakeTags{
		refs: map[string][]gh.TagRef{
			"widget": {{Name: "v1.1.0", ObjectSHA: tagObjSHA, Annotated: true}},
		},
		objects: map[string]*gh.TagObject{tagObjSHA: signedTagObject(linkedRev)},
		notes: map[string][]gh.ChainNote{
			"widget": {
				{Rev: genesisRev, Note: []byte(link)},
				{Rev: linkedRev, Note: []byte(link)},
				{Rev: preGenesisRev, Note: []byte(`{"seed": true}`)},
			},
		},
		meta: map[string]*gh.CommitMeta{
			genesisRev: {Parents: []string{preGenesisRev}, CommitEpoch: 100},
			linkedRev:  {Parents: []string{genesisRev}, CommitEpoch: 200},
		},
		ancestry: map[string]bool{
			genesisRev + "..." + linkedRev:   true,
			genesisRev + "..." + genesisRev:  true,
			genesisRev + "..." + unlinkedRev: true,
		},
	}
}

// The raised-floor policy (stele#186): widget's mint gained the
// capability at v1.3.0, so from there the floor is the observer
// stance and before it certificate transparency. gadget is declared
// unsigned and never appears in `from`.
const raisedFloorPolicyJSON = `{
  "schema": 6,
  "issuer": "https://token.example.com",
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "storeVsaFromVersion": "1.13.0",
    "classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}
  },
  "tags": {
    "tagPattern": "^v[0-9]",
    "taggerName": "release-mint[bot]",
    "identityPattern": "^https://github\\.com/acme/",
    "proofFloor": {
      "floor": "observer-timestamp",
      "from": {"widget": "v1.3.0"},
      "before": "certificate-transparency"
    },
    "notesRef": "refs/notes/commits",
    "epochs": {"widget": "v1.1.0", "gadget": "pending"}
  }
}`

// spanningTags scripts widget across the raise: two tags below the
// boundary, the boundary tag itself, and one above it. All four are
// signed, annotated and linked — the ONLY thing that differs across
// them is what they owe.
func spanningTags() *fakeTags {
	refs := []gh.TagRef{}
	objects := map[string]*gh.TagObject{}

	for i, name := range []string{"v1.1.0", "v1.2.0", "v1.3.0", "v1.4.0"} {
		sha := fmt.Sprintf("00000000000000000000000000000000000000d%d", i)
		refs = append(refs, gh.TagRef{Name: name, ObjectSHA: sha, Annotated: true})
		objects[sha] = signedTagObject(linkedRev)
	}

	f := conformantTags()
	f.refs = map[string][]gh.TagRef{"widget": refs}
	f.objects = objects

	return f
}

// preGenesisTags scripts widget's one member on a target the ledger's
// founded genesis does not reach: conformant in every other way, so
// what the walk says about it is about the horizon alone.
func preGenesisTags() *fakeTags {
	f := conformantTags()
	f.objects[tagObjSHA].Target = preGenesisRev
	f.ancestry[genesisRev+"..."+preGenesisRev] = false

	return f
}

// mixedTags scripts one tag in each disposition the reconciliation
// counts: below the epoch (excluded), on a linked revision (judged),
// and on a target the genesis does not reach (unjudgeable).
func mixedTags() *fakeTags {
	f := preGenesisTags()
	f.refs["widget"] = []gh.TagRef{
		{Name: "v1.0.0", ObjectSHA: tagObjSHA2, Annotated: true},
		{Name: "v1.1.0", ObjectSHA: tagObjSHA3, Annotated: true},
		{Name: "v1.2.0", ObjectSHA: tagObjSHA, Annotated: true},
	}
	f.objects[tagObjSHA2] = signedTagObject(preGenesisRev)
	f.objects[tagObjSHA3] = signedTagObject(linkedRev)

	return f
}

// unfoundedTags scripts a ledger of scaffolding alone: no link-shaped
// note, so no founded genesis and nothing the chain can witness.
func unfoundedTags() *fakeTags {
	f := conformantTags()
	f.notes["widget"] = []gh.ChainNote{{Rev: preGenesisRev, Note: []byte(`{"seed": true}`)}}

	return f
}

func runTagsPolicy(t *testing.T, policyJSON string, f *fakeTags, tv assert.TagVerifier) *report.Report {
	t.Helper()

	pol, err := assert.LoadPolicy(strings.NewReader(policyJSON))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	rep, rerr := assert.Tags(pol, repoPop(t, "acme/widget"), f, tv, report.NewJournal(), func(string, ...any) {})
	if rerr != nil {
		t.Fatalf("Tags: %v", rerr)
	}

	return rep
}

// TestTagsRaisedFloorBoundary: the floor rises at a named tag and
// nowhere else. Every tag below the boundary owes what the mint could
// prove then; the boundary tag and everything above owe the raised
// obligation. This is the whole of stele#186 in one assertion — a
// floor raised globally instead would redden the tags below it, which
// are not defective.
func TestTagsRaisedFloorBoundary(t *testing.T) {
	t.Parallel()

	tv := &fakeTagVerifier{}

	rep := runTagsPolicy(t, raisedFloorPolicyJSON, spanningTags(), tv)
	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
	}

	want := []string{
		"certificate-transparency", // v1.1.0 — the signing epoch, before the raise
		"certificate-transparency", // v1.2.0 — the last tag below the boundary
		"observer-timestamp",       // v1.3.0 — the boundary tag itself owes the raise
		"observer-timestamp",       // v1.4.0 — and everything after it
	}

	if !slices.Equal(tv.floors, want) {
		t.Fatalf("floors = %v, want %v", tv.floors, want)
	}
}

// TestTagsRaisedFloorRefusesAMintThatReverted: the obligation the
// declaration creates. A tag at or after the boundary whose mint
// dropped its receipts refuses — which is what makes a silent revert
// of the mint visible, and is the reason the floor is declared at all
// rather than left implied by what the tags happen to carry.
func TestTagsRaisedFloorRefusesAMintThatReverted(t *testing.T) {
	t.Parallel()

	tv := &fakeTagVerifier{refuseFloor: "observer-timestamp"}

	rep := runTagsPolicy(t, raisedFloorPolicyJSON, spanningTags(), tv)
	if rep.Verdict() == report.VerdictPass {
		t.Fatal("a post-boundary tag with no receipt passed")
	}

	subjects := map[string]bool{}

	for _, f := range rep.Findings() {
		subjects[f.Subject] = true
	}

	for _, tag := range []string{"widget@v1.3.0", "widget@v1.4.0"} {
		if !subjects[tag] {
			t.Errorf("no finding for %s — the raised floor bound nothing there", tag)
		}
	}

	for _, tag := range []string{"widget@v1.1.0", "widget@v1.2.0"} {
		if subjects[tag] {
			t.Errorf("finding for %s — a tag below the boundary owes the raise it predates", tag)
		}
	}
}

// TestTagsRaisedFloorReportsBothRegimes: a run that judged only one
// side of a boundary has not proven the boundary, so the report
// carries the count at each floor. Without it a policy whose `from`
// names a tag nobody minted reads exactly like one that binds.
func TestTagsRaisedFloorReportsBothRegimes(t *testing.T) {
	t.Parallel()

	facts := tagFacts(t, runTagsPolicy(t, raisedFloorPolicyJSON, spanningTags(), &fakeTagVerifier{}))

	if facts["tagsProvenAt:certificate-transparency"] != "2" || facts["tagsProvenAt:observer-timestamp"] != "2" {
		t.Fatalf("floor facts = %+v, want two tags judged at each floor", facts)
	}
}

// tagFacts reads a sealed report's facts the way a consumer does —
// through the encoded document, never a test-only accessor.
func tagFacts(t *testing.T, rep *report.Report) map[string]string {
	t.Helper()

	var buf bytes.Buffer
	if err := rep.Encode(&buf); err != nil {
		t.Fatalf("Encode = %v", err)
	}

	doc, err := jsonx.DecodeForeign[struct {
		Facts []report.Fact `json:"facts"`
	}](buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	facts := map[string]string{}
	for _, f := range doc.Facts {
		facts[f.Name] = f.Value
	}

	return facts
}

// TestTagsUnraisedFloorReportsNoRegimes: an org whose floor never
// rose declares no boundary, so the run states no split — a fact
// naming a regime that does not exist is noise that reads as
// evidence.
func TestTagsUnraisedFloorReportsNoRegimes(t *testing.T) {
	t.Parallel()

	for name := range tagFacts(t, runTags(t, conformantTags(), &fakeTagVerifier{})) {
		if strings.HasPrefix(name, "tagsProvenAt:") {
			t.Fatalf("fact %s on a policy that declares no boundary", name)
		}
	}
}

// TestTagsUnraisedRepositoryStaysBelow: a repository absent from a
// declared `from` has not raised its floor, and every one of its tags
// owes what came before — the correct reading for a rollout partway
// through a population, and the one that keeps a partial switch from
// reddening the repositories that have not switched.
func TestTagsUnraisedRepositoryStaysBelow(t *testing.T) {
	t.Parallel()

	policy := strings.Replace(raisedFloorPolicyJSON,
		`"from": {"widget": "v1.3.0"}`, `"from": {"gadget": "v2.0.0"}`, 1)
	policy = strings.Replace(policy,
		`"epochs": {"widget": "v1.1.0", "gadget": "pending"}`,
		`"epochs": {"widget": "v1.1.0", "gadget": "v2.0.0"}`, 1)

	tv := &fakeTagVerifier{}

	rep := runTagsPolicy(t, policy, spanningTags(), tv)
	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
	}

	for i, floor := range tv.floors {
		if floor != "certificate-transparency" {
			t.Fatalf("tag %d judged at %q — widget declares no raise", i, floor)
		}
	}
}

func runTags(t *testing.T, f *fakeTags, tv assert.TagVerifier) *report.Report {
	t.Helper()

	rep, _ := runTagsLogged(t, f, tv)

	return rep
}

// runTagsLogged runs the walk and keeps what it said. The lines are
// evidence: stele#208's defect was invisible precisely because the
// run's own output named neither the bound nor the tags it dropped.
//
//nolint:gocritic // unnamedResult: the sealed report, then the lines the run printed
func runTagsLogged(t *testing.T, f *fakeTags, tv assert.TagVerifier) (*report.Report, []string) {
	t.Helper()

	var lines []string

	rep, err := assert.Tags(loadTagsPolicy(t), repoPop(t, "acme/widget"), f, tv, report.NewJournal(),
		func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) })
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}

	return rep, lines
}

// TestTagsReconciliation is stele#208's subject: the run states the
// population it judged AGAINST THE DECLARATION, and every member of
// that population is judged or is loudly unjudgeable. The counts have
// to close — a set that does not balance is a member that went
// missing, which is exactly what a silent narrowing looks like.
func TestTagsReconciliation(t *testing.T) {
	t.Parallel()

	rep, lines := runTagsLogged(t, mixedTags(), &fakeTagVerifier{})

	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
	}

	facts := tagFacts(t, rep)
	for name, want := range map[string]string{
		"tagsListed:widget":      "3",
		"tagsExcluded:widget":    "1",
		"tagsJudged:widget":      "1",
		"tagsUnjudgeable:widget": "1",
	} {
		if facts[name] != want {
			t.Errorf("%s = %q, want %q — facts: %+v", name, facts[name], want, facts)
		}
	}

	for _, want := range []string{
		"widget: 3 tag(s) listed, 1 excluded before epoch v1.1.0, 2 in population: 1 judged, 1 unjudgeable",
		"widget@v1.2.0: tag:link unjudgeable — the ledger's founded genesis " + genesisRev,
		"3 tag(s) listed, 1 excluded before a declared epoch, 2 in population: 1 judged, 1 unjudgeable",
	} {
		if !slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, want) }) {
			t.Errorf("no line carries %q — the run said:\n%s", want, strings.Join(lines, "\n"))
		}
	}

	// The other half of the law: an exclusion produces NOTHING. Not a
	// finding, not a count, and not a line — the excluded tag is absent
	// from the run's output entirely.
	for _, line := range lines {
		if strings.Contains(line, "v1.0.0") {
			t.Errorf("the excluded tag reached the output: %q", line)
		}
	}
}

// TestTagsUnjudgeableCarriesItsHorizon: the unjudgeable member's
// finding is RECORDED and excused by a derived exception naming the
// horizon it came from — the assert-chains shape. A walk that instead
// decided not to look leaves nothing a reader could audit.
func TestTagsUnjudgeableCarriesItsHorizon(t *testing.T) {
	t.Parallel()

	doc := encodeReport(t, runTags(t, preGenesisTags(), &fakeTagVerifier{}))

	if len(doc.Excused) != 1 {
		t.Fatalf("excused = %+v, want the one link finding the horizon excuses", doc.Excused)
	}

	e := doc.Excused[0].Exception
	if e.Kind != "derived" || e.Subject != "widget@v1.1.0" || e.Assertion != "tag:link" {
		t.Fatalf("exception = %+v, want a derived exception over that tag's link alone", e)
	}

	if !strings.Contains(e.Origin, genesisRev) || !strings.Contains(e.Origin, preGenesisRev) {
		t.Fatalf("origin = %q, want the founded genesis and the target it does not reach", e.Origin)
	}
}

// TestTagsDebtLineBesideItsDerivation is stele#220's measured case,
// run through the walk that produced it: a debt line and the ledger
// horizon answer one coordinate. Both are credited, neither is called
// stale, and the pairing — a declared line shown beside a derivation
// over the same coordinate — is the signal that the machinery has
// outgrown the line. Before the fix the walk credited the debt line
// and told a human to go and delete the derivation.
func TestTagsDebtLineBesideItsDerivation(t *testing.T) {
	t.Parallel()

	debt, err := report.ParseDebt([]byte("widget@v1.1.0(tag:link)\n"), "debt.txt")
	if err != nil {
		t.Fatalf("debt: %v", err)
	}

	rep, err := assert.Tags(loadTagsPolicy(t), repoPop(t, "acme/widget"),
		preGenesisTags(), &fakeTagVerifier{}, report.NewJournal(debt...), func(string, ...any) {})
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}

	doc := encodeReport(t, rep)

	if len(doc.Excused) != 2 {
		t.Fatalf("excused = %+v, want the finding named beside BOTH excuses", doc.Excused)
	}

	if k, o := doc.Excused[0].Exception.Kind, doc.Excused[0].Exception.Origin; k != "declared" || o != "debt.txt:1" {
		t.Errorf("first excuse = %s %q, want the declared debt line", k, o)
	}

	if k := doc.Excused[1].Exception.Kind; k != "derived" {
		t.Errorf("second excuse kind = %q, want the derived horizon", k)
	}

	if len(doc.Stale) != 0 || len(doc.Unexercised) != 0 {
		t.Errorf("stale = %+v, unexercised = %+v — nothing here was checked clean",
			doc.Stale, doc.Unexercised)
	}
}

// TestTagsUnfoundedLedgerWitnessesNothing: a repository whose ledger
// founds no chain cannot answer the link question for ANY tag.
// Answering it anyway reddens a whole listing for one missing ledger,
// and whether a repository founds a chain at all is `assert chains`'
// finding to make — once, where it is judged.
func TestTagsUnfoundedLedgerWitnessesNothing(t *testing.T) {
	t.Parallel()

	rep := runTags(t, unfoundedTags(), &fakeTagVerifier{})
	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
	}

	if facts := tagFacts(t, rep); facts["tagsUnjudgeable:widget"] != "1" {
		t.Fatalf("facts = %+v, want the member counted unjudgeable", facts)
	}

	if origin := encodeReport(t, rep).Excused[0].Exception.Origin; !strings.Contains(origin, "founds no chain") {
		t.Fatalf("origin = %q, want the unfounded ledger named", origin)
	}
}

func TestTagsConformantPasses(t *testing.T) {
	t.Parallel()

	tv := &fakeTagVerifier{}

	rep := runTags(t, conformantTags(), tv)
	if rep.Verdict() != report.VerdictPass {
		t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
	}

	if tv.called != 1 {
		t.Fatalf("verifier calls = %d, want 1 — the post-epoch tag owes exactly one verification", tv.called)
	}

	// A policy declaring no `from` at all binds its floor everywhere —
	// the third of the three readings of that key, beside a repository
	// the map names and one it does not.
	if !slices.Equal(tv.floors, []string{"certificate-transparency"}) {
		t.Fatalf("floors = %v, want the declared floor binding with no boundary declared", tv.floors)
	}
}

func TestTagsDefects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*fakeTags, *fakeTagVerifier)
		want   string
	}{
		{
			"a lightweight tag reddens",
			func(f *fakeTags, _ *fakeTagVerifier) {
				f.refs["widget"] = []gh.TagRef{{Name: "v1.1.0", ObjectSHA: linkedRev, Annotated: false}}
			},
			"lightweight",
		},
		{
			"a foreign tagger reddens",
			func(f *fakeTags, _ *fakeTagVerifier) { f.objects[tagObjSHA].Tagger = "mallory" },
			"not the minting identity",
		},
		{
			"an unsigned post-epoch tag reddens",
			func(f *fakeTags, _ *fakeTagVerifier) { f.objects[tagObjSHA].Signature = nil },
			"unsigned tag",
		},
		{
			"a refusing signature reddens",
			func(_ *fakeTags, tv *fakeTagVerifier) { tv.err = errors.New("chains to no trusted authority") },
			"signature refused: chains to no trusted authority",
		},
		{
			"an unlinked target reddens",
			func(f *fakeTags, _ *fakeTagVerifier) { f.objects[tagObjSHA].Target = unlinkedRev },
			"no source chain link",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f, tv := conformantTags(), &fakeTagVerifier{}
			tt.mutate(f, tv)

			rep, err := assert.Tags(loadTagsPolicy(t), repoPop(t, "acme/widget"),
				f, tv, report.NewJournal(), func(string, ...any) {})
			if err != nil {
				t.Fatalf("Tags: %v", err)
			}

			if rep.Verdict() != report.VerdictFail {
				t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
			}

			found := false
			for _, fd := range rep.Findings() {
				if strings.Contains(fd.Detail, tt.want) {
					found = true
				}
			}

			if !found {
				t.Fatalf("findings %+v carry no %q", rep.Findings(), tt.want)
			}
		})
	}
}

// TestTagsPopulationBounds walks the two bounds and the difference
// between them (stele#208). The DECLARED epoch bounds the population:
// below it a tag produces nothing at all. The ledger's horizon bounds
// one obligation: beyond it the link cannot be judged, and everything
// else the tag owes still is.
func TestTagsPopulationBounds(t *testing.T) {
	t.Parallel()

	t.Run("a pre-genesis target's link is unjudgeable, not absent", func(t *testing.T) {
		t.Parallel()

		f := preGenesisTags()

		rep := runTags(t, f, &fakeTagVerifier{})
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v — a link the ledger cannot witness is not a defect",
				rep.Verdict(), rep.Findings())
		}

		facts := tagFacts(t, rep)
		if facts["tagsUnjudgeable:widget"] != "1" || facts["tagsJudged:widget"] != "0" {
			t.Fatalf("facts = %+v, want the member counted unjudgeable rather than dropped", facts)
		}
	})

	t.Run("a pre-genesis member still owes its signature", func(t *testing.T) {
		t.Parallel()

		f := preGenesisTags()
		f.objects[tagObjSHA].Signature = nil

		rep := runTags(t, f, &fakeTagVerifier{})
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — the epoch declares this tag signed, and the ledger's reach"+
				" says nothing about that obligation", rep.Verdict())
		}
	})

	t.Run("a pre-epoch tag is excluded: no check, no count, no line", func(t *testing.T) {
		t.Parallel()

		f := conformantTags()
		f.refs["widget"] = []gh.TagRef{{Name: "v1.0.0", ObjectSHA: tagObjSHA, Annotated: true}}
		f.objects[tagObjSHA].Signature = nil

		tv := &fakeTagVerifier{}

		// A population of nothing cannot pass: the declaration excludes
		// every tag this repository has, so the run judged no subject.
		rep := runTags(t, f, tv)
		if rep.Verdict() != report.VerdictCannotJudge {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		if tv.called != 0 || len(rep.Findings()) != 0 {
			t.Fatalf("verifier calls = %d, findings = %+v — an exclusion produces nothing",
				tv.called, rep.Findings())
		}

		facts := tagFacts(t, rep)
		if facts["tagsListed:widget"] != "1" || facts["tagsExcluded:widget"] != "1" ||
			facts["tagsJudged:widget"] != "0" || facts["tagsUnjudgeable:widget"] != "0" {
			t.Fatalf("facts = %+v, want the tag listed and excluded, judged by nothing", facts)
		}
	})
}

func TestTagsBounds(t *testing.T) {
	t.Parallel()

	t.Run("a pending epoch owes no signatures at all", func(t *testing.T) {
		t.Parallel()

		f := conformantTags()
		f.refs["gadget"] = []gh.TagRef{{Name: "v9.9.9", ObjectSHA: tagObjSHA2, Annotated: true}}
		f.objects[tagObjSHA2] = &gh.TagObject{Tagger: "release-mint[bot]", Target: linkedRev}
		f.notes["gadget"] = f.notes["widget"]
		f.meta[genesisRev] = &gh.CommitMeta{Parents: []string{preGenesisRev}, CommitEpoch: 100}

		tv := &fakeTagVerifier{}

		rep, err := assert.Tags(loadTagsPolicy(t), repoPop(t, "acme/gadget"),
			f, tv, report.NewJournal(), func(string, ...any) {})
		if err != nil {
			t.Fatalf("Tags: %v", err)
		}

		if rep.Verdict() != report.VerdictPass || tv.called != 0 {
			t.Fatalf("verdict = %s, verifier calls = %d — pending means declared-unsigned",
				rep.Verdict(), tv.called)
		}

		// And `pending` excludes nothing: a repository that has not begun
		// signing is still wholly in the population, so its tagger and
		// chain obligations stay in sight.
		facts := tagFacts(t, rep)
		if facts["tagsExcluded:gadget"] != "0" || facts["tagsJudged:gadget"] != "1" {
			t.Fatalf("facts = %+v, want the whole listing judged and nothing excluded", facts)
		}
	})

	t.Run("a releasing repo without an epoch line cannot be judged", func(t *testing.T) {
		t.Parallel()

		f := conformantTags()
		f.refs["mystery"] = f.refs["widget"]

		rep, err := assert.Tags(loadTagsPolicy(t), repoPop(t, "acme/mystery"),
			f, &fakeTagVerifier{}, report.NewJournal(), func(string, ...any) {})
		if err != nil {
			t.Fatalf("Tags: %v", err)
		}

		// Zero tags were judged and the absence is a finding: the seal
		// speaks CANNOT_JUDGE — an undeclared population member is
		// unchecked, never clean and never a confident FAIL.
		if rep.Verdict() != report.VerdictCannotJudge {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}
	})

	t.Run("a torn listing dies loudly", func(t *testing.T) {
		t.Parallel()

		f := conformantTags()
		f.refsErr = errors.New("listing torn")

		if _, err := assert.Tags(loadTagsPolicy(t), repoPop(t, "acme/widget"),
			f, &fakeTagVerifier{}, report.NewJournal(), func(string, ...any) {}); err == nil ||
			!strings.Contains(err.Error(), "listing torn") {
			t.Fatalf("error = %v, want the torn listing", err)
		}
	})

	t.Run("a policy without a tags section refuses", func(t *testing.T) {
		t.Parallel()

		if _, err := assert.Tags(loadTestPolicy(t), repoPop(t, "acme/widget"),
			conformantTags(), &fakeTagVerifier{}, report.NewJournal(), func(string, ...any) {}); err == nil ||
			!strings.Contains(err.Error(), "no tags section") {
			t.Fatalf("error = %v, want the section refusal", err)
		}
	})
}

// TestTagsWalkEdges covers the remaining guard branches: an
// unreadable tag object, a broken chain read, an unparsable tag
// version (strict toward the obligation), and an epochless repo with
// no matching tags at all.
func TestTagsWalkEdges(t *testing.T) {
	t.Parallel()

	t.Run("an unreadable tag object dies loudly", func(t *testing.T) {
		t.Parallel()

		f := conformantTags()
		delete(f.objects, tagObjSHA)

		if _, err := assert.Tags(loadTagsPolicy(t), repoPop(t, "acme/widget"),
			f, &fakeTagVerifier{}, report.NewJournal(), func(string, ...any) {}); err == nil ||
			!strings.Contains(err.Error(), "tag object") {
			t.Fatalf("error = %v, want the object read failure", err)
		}
	})

	t.Run("a broken genesis derivation dies loudly", func(t *testing.T) {
		t.Parallel()

		f := conformantTags()
		delete(f.meta, genesisRev)

		if _, err := assert.Tags(loadTagsPolicy(t), repoPop(t, "acme/widget"),
			f, &fakeTagVerifier{}, report.NewJournal(), func(string, ...any) {}); err == nil ||
			!strings.Contains(err.Error(), "commit") {
			t.Fatalf("error = %v, want the commit read failure", err)
		}
	})

	t.Run("an unparsable tag version owes a signature", func(t *testing.T) {
		t.Parallel()

		f := conformantTags()
		f.refs["widget"] = []gh.TagRef{{Name: "v1.weird", ObjectSHA: tagObjSHA, Annotated: true}}
		f.objects[tagObjSHA].Signature = nil

		rep := runTags(t, f, &fakeTagVerifier{})
		if rep.Verdict() != report.VerdictFail {
			t.Fatalf("verdict = %s — an unparsable version fails toward the obligation", rep.Verdict())
		}
	})

	t.Run("a repo with no matching tags owes nothing", func(t *testing.T) {
		t.Parallel()

		f := conformantTags()
		f.refs["widget"] = []gh.TagRef{{Name: "nightly", ObjectSHA: tagObjSHA, Annotated: false}}
		f.refs["gadget"] = nil

		rep := runTags(t, f, &fakeTagVerifier{})
		if rep.Verdict() != report.VerdictCannotJudge {
			t.Fatalf("verdict = %s — zero release tags is an empty population", rep.Verdict())
		}
	})
}

// TestTagsDebtExcusesOneCheck is #147's subject: a defect on an
// immutable tag inside the signed epoch is writable-down. The line
// excuses THAT check on THAT tag — the tag stays defective forever,
// recorded rather than healed — and nothing else it might have.
func TestTagsDebtExcusesOneCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		line   string
		mutate func(*fakeTags)
		want   report.Verdict
	}{
		{
			"a signature line excuses the signature defect it names",
			"widget@v1.1.0(tag:signature)",
			func(f *fakeTags) { f.objects[tagObjSHA].Signature = nil },
			report.VerdictPass,
		},
		{
			"the same line excuses nothing else on that tag",
			"widget@v1.1.0(tag:signature)",
			func(f *fakeTags) { f.objects[tagObjSHA].Tagger = "mallory" },
			report.VerdictFail,
		},
		{
			"a line for another tag excuses nothing",
			"widget@v9.9.9(tag:signature)",
			func(f *fakeTags) { f.objects[tagObjSHA].Signature = nil },
			report.VerdictFail,
		},
		{
			"a tagger line excuses the tagger defect",
			"widget@v1.1.0(tag:tagger)",
			func(f *fakeTags) { f.objects[tagObjSHA].Tagger = "mallory" },
			report.VerdictPass,
		},
		{
			"a link line excuses the missing chain link",
			"widget@v1.1.0(tag:link)",
			func(f *fakeTags) { f.objects[tagObjSHA].Target = unlinkedRev },
			report.VerdictPass,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			debt, err := report.ParseDebt([]byte(tt.line+"\n"), "debt.txt")
			if err != nil {
				t.Fatalf("debt: %v", err)
			}

			f := conformantTags()
			tt.mutate(f)

			rep, err := assert.Tags(loadTagsPolicy(t), repoPop(t, "acme/widget"),
				f, &fakeTagVerifier{}, report.NewJournal(debt...), func(string, ...any) {})
			if err != nil {
				t.Fatalf("Tags: %v", err)
			}

			if rep.Verdict() != tt.want {
				t.Fatalf("verdict = %s, want %s — findings: %+v", rep.Verdict(), tt.want, rep.Findings())
			}
		})
	}
}

// A line whose check the walk PERFORMED and found clean is stale — a
// retirement candidate. A line whose check the walk never performed
// (the epoch exempts a pre-epoch tag from signing) is unexercised:
// this run looked at that tag and never asked the question, so it has
// nothing to say about the excuse. Calling that one stale would
// retire an excuse on evidence nobody gathered.
func TestTagsDebtStalenessFollowsWhatWasChecked(t *testing.T) {
	t.Parallel()

	debt, err := report.ParseDebt(
		[]byte("widget@v1.1.0(tag:signature)\nwidget@v1.0.0(tag:signature)\n"), "debt.txt")
	if err != nil {
		t.Fatalf("debt: %v", err)
	}

	f := conformantTags()
	f.refs["widget"] = []gh.TagRef{
		{Name: "v1.1.0", ObjectSHA: tagObjSHA, Annotated: true},
		{Name: "v1.0.0", ObjectSHA: tagObjSHA2, Annotated: true},
	}
	f.objects[tagObjSHA2] = &gh.TagObject{Tagger: "release-mint[bot]", Target: linkedRev}

	rep, err := assert.Tags(loadTagsPolicy(t), repoPop(t, "acme/widget"),
		f, &fakeTagVerifier{}, report.NewJournal(debt...), func(string, ...any) {})
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}

	doc := encodeReport(t, rep)

	if len(doc.Stale) != 1 || doc.Stale[0].Origin != "debt.txt:1" {
		t.Fatalf("staleExceptions = %+v, want the post-epoch line whose check ran clean", doc.Stale)
	}

	if len(doc.Unexercised) != 1 || doc.Unexercised[0].Origin != "debt.txt:2" {
		t.Fatalf("unexercisedExceptions = %+v, want the pre-epoch line nobody could answer", doc.Unexercised)
	}
}

// reportDoc is the wire shape this package's tests read back — the
// report package exports no decoder by design, so a consumer that
// needs one owns it.
type reportDoc struct {
	Verdict     *string        `json:"verdict"`
	Excused     []excusedDoc   `json:"excused"`
	Stale       []exceptionDoc `json:"staleExceptions"`
	Unexercised []exceptionDoc `json:"unexercisedExceptions"`
}

type excusedDoc struct {
	Finding   report.Finding `json:"finding"`
	Exception exceptionDoc   `json:"exception"`
}

type exceptionDoc struct {
	Kind      string `json:"kind"`
	Subject   string `json:"subject"`
	Assertion string `json:"assertion"`
	Origin    string `json:"origin"`
}

func encodeReport(t *testing.T, rep *report.Report) *reportDoc {
	t.Helper()

	var buf bytes.Buffer
	if err := rep.Encode(&buf); err != nil {
		t.Fatalf("encode: %v", err)
	}

	doc, err := jsonx.DecodeForeign[reportDoc](buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	return doc
}
