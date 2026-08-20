// The tag audit's table (stele#83): every obligation class — epoch
// declaration, annotation, tagger role, signing epoch, chain link —
// and the derived legacy bound, each broken one fact at a time.

package assert_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/report"
)

const tagsPolicyJSON = `{
  "schema": 5,
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
)

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

// fakeTagVerifier scripts the trust seam.
type fakeTagVerifier struct {
	err    error
	called int
}

func (v *fakeTagVerifier) Verify(_, _ []byte) (string, error) {
	v.called++

	return "https://github.com/acme/widget/x", v.err
}

// conformantTags scripts one repo, widget, with a signed post-epoch
// tag on a linked revision.
func conformantTags() *fakeTags {
	return &fakeTags{
		refs: map[string][]gh.TagRef{
			"widget": {{Name: "v1.1.0", ObjectSHA: tagObjSHA, Annotated: true}},
		},
		objects: map[string]*gh.TagObject{
			tagObjSHA: {
				Tagger: "release-mint[bot]", Target: linkedRev,
				Payload:   []byte("object x\ntagger release-mint[bot] <m@e> 1755000000 +0000\n"),
				Signature: []byte("-----BEGIN SIGNED MESSAGE-----\nx\n-----END SIGNED MESSAGE-----\n"),
			},
		},
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

func runTags(t *testing.T, f *fakeTags, tv assert.TagVerifier) *report.Report {
	t.Helper()

	rep, err := assert.Tags(loadTagsPolicy(t), assert.Population{Repo: "acme/widget"},
		&fakeForge{}, f, tv, report.NewJournal(), func(string, ...any) {})
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}

	return rep
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

			rep, err := assert.Tags(loadTagsPolicy(t), assert.Population{Repo: "acme/widget"},
				&fakeForge{}, f, tv, report.NewJournal(), func(string, ...any) {})
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

func TestTagsBounds(t *testing.T) {
	t.Parallel()

	t.Run("a pre-genesis target is legacy, exempt by construction", func(t *testing.T) {
		t.Parallel()

		f := conformantTags()
		f.objects[tagObjSHA].Target = preGenesisRev
		f.objects[tagObjSHA].Signature = nil // owes nothing: legacy
		f.ancestry[genesisRev+"..."+preGenesisRev] = false

		rep := runTags(t, f, &fakeTagVerifier{})
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v — legacy tags owe nothing", rep.Verdict(), rep.Findings())
		}
	})

	t.Run("a pre-epoch tag owes no signature", func(t *testing.T) {
		t.Parallel()

		f := conformantTags()
		f.refs["widget"] = []gh.TagRef{{Name: "v1.0.0", ObjectSHA: tagObjSHA, Annotated: true}}
		f.objects[tagObjSHA].Signature = nil

		tv := &fakeTagVerifier{}

		rep := runTags(t, f, tv)
		if rep.Verdict() != report.VerdictPass {
			t.Fatalf("verdict = %s, findings: %+v", rep.Verdict(), rep.Findings())
		}

		if tv.called != 0 {
			t.Fatal("a pre-epoch tag was asked for a signature")
		}
	})

	t.Run("a pending epoch owes no signatures at all", func(t *testing.T) {
		t.Parallel()

		f := conformantTags()
		f.refs["gadget"] = []gh.TagRef{{Name: "v9.9.9", ObjectSHA: tagObjSHA2, Annotated: true}}
		f.objects[tagObjSHA2] = &gh.TagObject{Tagger: "release-mint[bot]", Target: linkedRev}
		f.notes["gadget"] = f.notes["widget"]
		f.meta[genesisRev] = &gh.CommitMeta{Parents: []string{preGenesisRev}, CommitEpoch: 100}

		tv := &fakeTagVerifier{}

		rep, err := assert.Tags(loadTagsPolicy(t), assert.Population{Repo: "acme/gadget"},
			&fakeForge{}, f, tv, report.NewJournal(), func(string, ...any) {})
		if err != nil {
			t.Fatalf("Tags: %v", err)
		}

		if rep.Verdict() != report.VerdictPass || tv.called != 0 {
			t.Fatalf("verdict = %s, verifier calls = %d — pending means declared-unsigned",
				rep.Verdict(), tv.called)
		}
	})

	t.Run("a releasing repo without an epoch line cannot be judged", func(t *testing.T) {
		t.Parallel()

		f := conformantTags()
		f.refs["mystery"] = f.refs["widget"]

		rep, err := assert.Tags(loadTagsPolicy(t), assert.Population{Repo: "acme/mystery"},
			&fakeForge{}, f, &fakeTagVerifier{}, report.NewJournal(), func(string, ...any) {})
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

		if _, err := assert.Tags(loadTagsPolicy(t), assert.Population{Repo: "acme/widget"},
			&fakeForge{}, f, &fakeTagVerifier{}, report.NewJournal(), func(string, ...any) {}); err == nil ||
			!strings.Contains(err.Error(), "listing torn") {
			t.Fatalf("error = %v, want the torn listing", err)
		}
	})

	t.Run("a policy without a tags section refuses", func(t *testing.T) {
		t.Parallel()

		if _, err := assert.Tags(loadTestPolicy(t), assert.Population{Repo: "acme/widget"},
			&fakeForge{}, conformantTags(), &fakeTagVerifier{}, report.NewJournal(), func(string, ...any) {}); err == nil ||
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

		if _, err := assert.Tags(loadTagsPolicy(t), assert.Population{Repo: "acme/widget"},
			&fakeForge{}, f, &fakeTagVerifier{}, report.NewJournal(), func(string, ...any) {}); err == nil ||
			!strings.Contains(err.Error(), "tag object") {
			t.Fatalf("error = %v, want the object read failure", err)
		}
	})

	t.Run("a broken genesis derivation dies loudly", func(t *testing.T) {
		t.Parallel()

		f := conformantTags()
		delete(f.meta, genesisRev)

		if _, err := assert.Tags(loadTagsPolicy(t), assert.Population{Repo: "acme/widget"},
			&fakeForge{}, f, &fakeTagVerifier{}, report.NewJournal(), func(string, ...any) {}); err == nil ||
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

	t.Run("a broken population refuses before any walk", func(t *testing.T) {
		t.Parallel()

		if _, err := assert.Tags(loadTagsPolicy(t), assert.Population{Repo: "solo"},
			&fakeForge{}, conformantTags(), &fakeTagVerifier{}, report.NewJournal(), func(string, ...any) {}); err == nil ||
			!strings.Contains(err.Error(), "owner/name") {
			t.Fatalf("error = %v, want the population refusal", err)
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

			rep, err := assert.Tags(loadTagsPolicy(t), assert.Population{Repo: "acme/widget"},
				&fakeForge{}, f, &fakeTagVerifier{}, report.NewJournal(debt...), func(string, ...any) {})
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

	rep, err := assert.Tags(loadTagsPolicy(t), assert.Population{Repo: "acme/widget"},
		&fakeForge{}, f, &fakeTagVerifier{}, report.NewJournal(debt...), func(string, ...any) {})
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
	Stale       []exceptionDoc `json:"staleExceptions"`
	Unexercised []exceptionDoc `json:"unexercisedExceptions"`
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
