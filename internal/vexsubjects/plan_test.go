package vexsubjects_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/vexjoin"
	"github.com/monumental-archive/stele/internal/vexsubjects"
)

// The recorded world these tests replay, all read on 2026-11-17:
//
//   - RUSTSEC-2021-0127.openvex.json: the canon's decision at
//     monumental-archive/.github dabadd7 (security/vex/), version 3;
//   - affected.document.json.gz: the subjects that decision's signed
//     attestation binds, in the order the signed statement lists them
//     (484, signed by vex-attest in .github run 32395822585);
//   - store-holds.attestations.json.gz: the attestation store's own
//     response for one of those subjects — the bundle that holds the
//     decision;
//   - *.golden: what the canon's shell planner rendered from those two
//     inputs, by its own expressions, under jq 1.8.2:
//     `jq -c . <decision>` for the predicate, and
//     `jq -r '.subjects[] | "\(.sha256)  \(.name)"'` for the subject
//     lines (each without the trailing newline `$(…)` strips).
const planData = "testdata/plan"

func readPlanFile(t *testing.T, name string) []byte {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(planData, name)) //nolint:gosec // G304: a fixed fixture path
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasSuffix(name, ".gz") {
		return raw
	}

	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}

	return out
}

// recordedDocument is the derivation's answer for the real decision.
func recordedDocument(t *testing.T) *vexsubjects.Document {
	t.Helper()

	doc, err := jsonx.DecodeBytes[vexsubjects.Document](readPlanFile(t, "affected.document.json.gz"))
	if err != nil {
		t.Fatal(err)
	}

	return doc
}

// recordedHeld is the store's recorded answer holding the decision.
func recordedHeld(t *testing.T) []jsonx.Raw {
	t.Helper()

	type response struct {
		Attestations []struct {
			Bundle jsonx.Raw `json:"bundle"`
		} `json:"attestations"`
	}

	r, err := jsonx.DecodeForeign[response](readPlanFile(t, "store-holds.attestations.json.gz"))
	if err != nil {
		t.Fatal(err)
	}

	out := make([]jsonx.Raw, 0, len(r.Attestations))
	for _, a := range r.Attestations {
		out = append(out, a.Bundle)
	}

	return out
}

// bundleOf wraps a statement as a stored bundle's DSSE payload.
func bundleOf(t *testing.T, predicateType, predicate string) jsonx.Raw {
	t.Helper()

	stmt := `{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"` + predicateType +
		`","predicate":` + predicate + `}`

	return jsonx.Raw(`{"dsseEnvelope":{"payload":"` + base64.StdEncoding.EncodeToString([]byte(stmt)) + `"}}`)
}

// fakeStore answers per digest: bundles, an error, or the 404 (nil).
type fakeStore struct {
	answers    map[string][]jsonx.Raw
	errs       map[string]error
	control    error
	notFound   bool
	probed     []string
	controlled int
}

func (s *fakeStore) Attestations(owner, repo, digest string) ([]jsonx.Raw, error) {
	s.probed = append(s.probed, owner+"/"+repo+"@"+digest)

	if err := s.errs[digest]; err != nil {
		return nil, err
	}

	return s.answers[digest], nil
}

//nolint:gocritic // unnamedResult: the forge's own DefaultBranch shape
func (s *fakeStore) DefaultBranch(string, string) (string, bool, error) {
	s.controlled++

	if s.control != nil {
		return "", false, s.control
	}

	return "main", !s.notFound, nil
}

// planner plans the real decision's derivation (or a scripted refusal)
// against a store.
func planner(t *testing.T, store *fakeStore, doc *vexsubjects.Document) *vexsubjects.Planner {
	t.Helper()

	return &vexsubjects.Planner{
		Derive: func(*vexjoin.Decisions, string) (*vexsubjects.Document, error) {
			return doc, nil
		},
		UnsignedOnly: store != nil,
		Store:        store,
		StoreOwner:   "acme",
		StoreRepo:    "canon",
	}
}

func decisionFile(t *testing.T) vexsubjects.DecisionFile {
	t.Helper()

	return vexsubjects.DecisionFile{
		Path: "security/vex/RUSTSEC-2021-0127.openvex.json",
		Raw:  readPlanFile(t, "RUSTSEC-2021-0127.openvex.json"),
	}
}

func golden(t *testing.T, name string) string {
	t.Helper()

	return strings.TrimSuffix(string(readPlanFile(t, name)), "\n")
}

// TestPlanCellMatchesTheShell: for the recorded real decision, the
// cell's subject lines and predicate are byte for byte what the canon's
// shell handed the signer.
func TestPlanCellMatchesTheShell(t *testing.T) {
	t.Parallel()

	plan, err := planner(t, nil, recordedDocument(t)).Plan([]vexsubjects.DecisionFile{decisionFile(t)})
	if err != nil {
		t.Fatalf("Plan = %v", err)
	}

	if len(plan.Cells) != 1 {
		t.Fatalf("plan = %+v, want one cell", plan)
	}

	cell := plan.Cells[0]

	if want := golden(t, "RUSTSEC-2021-0127.subjects.golden"); cell.Subjects != want {
		t.Errorf("subject lines differ from the shell's (%d vs %d bytes)", len(cell.Subjects), len(want))
	}

	if want := golden(t, "RUSTSEC-2021-0127.predicate.golden"); cell.Predicate != want {
		t.Errorf("predicate:\n got %s\nwant %s", cell.Predicate, want)
	}

	if cell.Slug != "RUSTSEC-2021-0127" || cell.Decision != "security/vex/RUSTSEC-2021-0127.openvex.json" {
		t.Errorf("cell names %q / %q", cell.Decision, cell.Slug)
	}
}

// TestPlanSlugAndLog: a decision name outside the file-safe set slugs
// as the shell's `${slug//[^[:alnum:]._-]/-}` did, and the planner
// says what it planned.
func TestPlanSlugAndLog(t *testing.T) {
	t.Parallel()

	var lines []string

	doc := recordedDocument(t)
	doc.Releases = []vexsubjects.Release{{Repo: "widget", Tag: "v1.0.0", Advisories: []string{"RUSTSEC-2021-0127"}}}

	pl := planner(t, nil, doc)
	pl.Log = func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }

	f := decisionFile(t)
	f.Path = "security/vex/odd name+v2.openvex.json"

	plan, err := pl.Plan([]vexsubjects.DecisionFile{f})
	if err != nil {
		t.Fatal(err)
	}

	if got := plan.Cells[0].Slug; got != "odd-name-v2" {
		t.Errorf("slug = %q, want odd-name-v2", got)
	}

	named := func(l string) bool { return strings.Contains(l, "affected releases: widget@v1.0.0") }
	if !slices.ContainsFunc(lines, named) {
		t.Errorf("the planner did not name the affected releases: %q", lines)
	}
}

// TestPlanAgainstTheStore: the recorded store responses, one row each.
// Every probed digest is named, so a row also pins WHICH subjects were
// asked: the derived set's first and last, and no others.
func TestPlanAgainstTheStore(t *testing.T) {
	t.Parallel()

	doc := recordedDocument(t)
	first, last := doc.Subjects[0].SHA256, doc.Subjects[len(doc.Subjects)-1].SHA256
	decision := string(readPlanFile(t, "RUSTSEC-2021-0127.openvex.json"))

	// The decision's version 2 under the identifier version 3 still
	// carries: the store holds earlier versions of a decision by the
	// same @id, which is why @id is never the key.
	earlier := strings.Replace(decision, `"version": 3`, `"version": 2`, 1)

	for _, tt := range []struct {
		name   string
		store  *fakeStore
		held   bool
		blind  string
		probes []string
	}{
		{
			name:   "the store holds the decision under the first subject: omitted",
			store:  &fakeStore{answers: map[string][]jsonx.Raw{first: recordedHeld(t)}},
			held:   true,
			probes: []string{first},
		},
		{
			// A newly published release lands at the head of the derived
			// set; probing the tail keeps an already-public decision
			// from being signed again as the population grows.
			name:   "the store holds it only under the last subject: omitted",
			store:  &fakeStore{answers: map[string][]jsonx.Raw{last: recordedHeld(t)}},
			held:   true,
			probes: []string{first, last},
		},
		{
			name:   "a 404 on both probes: a cell",
			store:  &fakeStore{},
			probes: []string{first, last},
		},
		{
			name: "the store holds only an earlier version under the same @id: a cell",
			store: &fakeStore{answers: map[string][]jsonx.Raw{
				first: {bundleOf(t, "https://openvex.dev/ns/v0.2.0", earlier)},
			}},
			probes: []string{first, last},
		},
		{
			name: "the store holds the decision under another predicate type: a cell",
			store: &fakeStore{answers: map[string][]jsonx.Raw{
				first: {bundleOf(t, "https://slsa.dev/provenance/v1", decision)},
			}},
			probes: []string{first, last},
		},
		{
			name: "a stored bundle whose payload cannot be read is not the decision",
			store: &fakeStore{answers: map[string][]jsonx.Raw{
				first: {
					jsonx.Raw(`{"dsseEnvelope":{"payload":"%%%"}}`), jsonx.Raw(`{}`), jsonx.Raw(`[]`),
					jsonx.Raw(`{"dsseEnvelope":{"payload":"` + base64.StdEncoding.EncodeToString([]byte("not json")) + `"}}`),
					jsonx.Raw(`{"dsseEnvelope":{"payload":"` + base64.StdEncoding.EncodeToString([]byte("[1]")) + `"}}`),
				},
			}},
			probes: []string{first, last},
		},
		{
			name:   "a 403 on a probe: unjudged, never unsigned",
			store:  &fakeStore{errs: map[string]error{first: errors.New("gh: HTTP 403")}},
			blind:  "the attestation store could not be read — refusing to read that as unsigned: gh: HTTP 403",
			probes: []string{first},
		},
		{
			name:   "a 5xx on the second probe: unjudged",
			store:  &fakeStore{errs: map[string]error{last: errors.New("gh: HTTP 502")}},
			blind:  "refusing to read that as unsigned: gh: HTTP 502",
			probes: []string{first, last},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan, err := planner(t, tt.store, doc).Plan([]vexsubjects.DecisionFile{decisionFile(t)})
			if err != nil {
				t.Fatalf("Plan = %v", err)
			}

			var want []string
			for _, p := range tt.probes {
				want = append(want, "acme/canon@"+p)
			}

			if !slices.Equal(tt.store.probed, want) {
				t.Errorf("probed %v, want %v", tt.store.probed, want)
			}

			switch {
			case tt.blind != "":
				if len(plan.Refused) != 1 || !plan.Blind() || !strings.Contains(plan.Refused[0].Reason, tt.blind) {
					t.Fatalf("plan = %+v, want the decision unjudged: %q", plan, tt.blind)
				}
			case tt.held:
				if len(plan.Held) != 1 || len(plan.Cells) != 0 || len(plan.Refused) != 0 {
					t.Fatalf("plan = %+v, want the decision held and omitted", plan)
				}
			default:
				if len(plan.Cells) != 1 || len(plan.Held) != 0 || len(plan.Refused) != 0 {
					t.Fatalf("plan = %+v, want a cell", plan)
				}
			}
		})
	}
}

// TestPlanControlRead: the store's repository is read once before any
// probe, and a repository the store cannot show refuses the whole plan
// — the attestations endpoint answers a missing repository with the
// same 404 as an empty store, and reading that as "nothing held" would
// re-sign every decision.
func TestPlanControlRead(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		store *fakeStore
		want  string
	}{
		{"the repository answers 404", &fakeStore{notFound: true}, "acme/canon answered 404"},
		{"the repository read fails", &fakeStore{control: errors.New("gh: HTTP 503")}, "gh: HTTP 503"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := planner(t, tt.store, recordedDocument(t)).Plan([]vexsubjects.DecisionFile{decisionFile(t)})
			if !errors.Is(err, vexsubjects.ErrStoreUnreadable) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Plan = %v, want the unreadable-store refusal naming %q", err, tt.want)
			}

			if len(tt.store.probed) != 0 {
				t.Errorf("probed %v before the control read passed", tt.store.probed)
			}
		})
	}

	t.Run("no store named", func(t *testing.T) {
		t.Parallel()

		pl := planner(t, &fakeStore{}, recordedDocument(t))
		pl.Store = nil

		if _, err := pl.Plan(nil); err == nil || !strings.Contains(err.Error(), "none was named") {
			t.Fatalf("Plan = %v, want the unnamed-store refusal", err)
		}
	})

	t.Run("read once for several decisions", func(t *testing.T) {
		t.Parallel()

		store := &fakeStore{}
		f := decisionFile(t)
		g := f
		g.Path = "security/vex/other.openvex.json"

		if _, err := planner(t, store, recordedDocument(t)).Plan([]vexsubjects.DecisionFile{f, g}); err != nil {
			t.Fatal(err)
		}

		if store.controlled != 1 {
			t.Errorf("control reads = %d, want 1", store.controlled)
		}
	})
}

// errNoSubjects scripts a derivation that answers with no subjects.
var errNoSubjects = errors.New("scripted: no subjects")

// TestPlanRefusals: a decision the run will not sign is a named entry,
// never a crash, and the decisions beside it are still planned.
func TestPlanRefusals(t *testing.T) {
	t.Parallel()

	good := decisionFile(t)

	for _, tt := range []struct {
		name      string
		file      vexsubjects.DecisionFile
		deriveErr error
		want      string
	}{
		{
			name: "a file that is not an OpenVEX document",
			file: vexsubjects.DecisionFile{Path: "security/vex/x.openvex.json", Raw: []byte(`{"statements": []}`)},
			want: "security/vex/x.openvex.json is not an OpenVEX document",
		},
		{
			name: "a file that is not JSON",
			file: vexsubjects.DecisionFile{Path: "security/vex/x.openvex.json", Raw: []byte(`not json`)},
			want: "is not an OpenVEX document",
		},
		{
			name: "an @context that is null",
			file: vexsubjects.DecisionFile{
				Path: "security/vex/x.openvex.json", Raw: []byte(`{"@context": null, "statements": [1]}`),
			},
			want: "is not an OpenVEX document",
		},
		{
			name: "statements that are false",
			file: vexsubjects.DecisionFile{
				Path: "security/vex/x.openvex.json", Raw: []byte(`{"@context": "c", "statements": false}`),
			},
			want: "is not an OpenVEX document",
		},
		{
			name: "a file that cannot be read",
			file: vexsubjects.DecisionFile{Path: "security/vex/x.openvex.json", Err: errors.New("permission denied")},
			want: "security/vex/x.openvex.json: unreadable: permission denied",
		},
		{
			name: "an OpenVEX document that decides nothing joinable",
			file: vexsubjects.DecisionFile{
				Path: "security/vex/x.openvex.json",
				Raw:  []byte(`{"@context": "c", "statements": [{"vulnerability": {"name": "X"}}]}`),
			},
			want: "the affected-release derivation refused: vexjoin:",
		},
		{
			name:      "a derivation that binds no subject",
			file:      good,
			deriveErr: errNoSubjects,
			want:      "the derivation bound it to no subject — a claim bound to nothing is not signed",
		},
		{
			name:      "a derivation that refuses",
			file:      good,
			deriveErr: errors.New("vexsubjects: no published release ships a package"),
			want:      "the affected-release derivation refused: vexsubjects: no published release ships a package",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// The refused decision first, the good one after it: the
			// refusal must not stop the plan.
			pl := planner(t, nil, recordedDocument(t))
			derive := pl.Derive
			pl.Derive = func(d *vexjoin.Decisions, origin string) (*vexsubjects.Document, error) {
				if origin == tt.file.Path && errors.Is(tt.deriveErr, errNoSubjects) {
					return &vexsubjects.Document{Decision: origin}, nil
				}

				if origin == tt.file.Path && tt.deriveErr != nil {
					return nil, tt.deriveErr
				}

				return derive(d, origin)
			}

			other := good
			other.Path = "security/vex/after.openvex.json"

			plan, err := pl.Plan([]vexsubjects.DecisionFile{tt.file, other})
			if err != nil {
				t.Fatalf("Plan = %v", err)
			}

			if len(plan.Refused) != 1 || !strings.Contains(plan.Refused[0].Reason, tt.want) || plan.Blind() {
				t.Fatalf("refused = %+v, want one refusal naming %q", plan.Refused, tt.want)
			}

			if len(plan.Cells) != 1 || plan.Cells[0].Decision != other.Path {
				t.Fatalf("cells = %+v, want the other decision still planned", plan.Cells)
			}
		})
	}
}

// TestPlanStoreComparison: the store comparison is JSON equality — key
// order and number spelling do not make a different decision.
func TestPlanStoreComparison(t *testing.T) {
	t.Parallel()

	doc := recordedDocument(t)
	first := doc.Subjects[0].SHA256

	for _, tt := range []struct {
		name     string
		decision string
		stored   string
		held     bool
	}{
		{
			"keys in another order", `{"@context":"c","statements":[{"vulnerability":{"name":"X"},"status":"not_affected",` +
				`"timestamp":"2026-01-01T00:00:00Z","products":[{"@id":"pkg:cargo/a@1"}]}]}`,
			`{"statements":[{"products":[{"@id":"pkg:cargo/a@1"}],"timestamp":"2026-01-01T00:00:00Z",` +
				`"status":"not_affected","vulnerability":{"name":"X"}}],"@context":"c"}`, true,
		},
		{
			"a number spelled differently", `{"@context":"c","statements":[],"version":1}`,
			`{"@context":"c","statements":[],"version":1.0}`, true,
		},
		{
			"a different number", `{"@context":"c","statements":[],"version":1}`,
			`{"@context":"c","statements":[],"version":2}`, false,
		},
		{"an extra key", `{"@context":"c","statements":[]}`, `{"@context":"c","statements":[],"x":0}`, false},
		{
			"another key, same count", `{"@context":"c","statements":[],"x":0}`,
			`{"@context":"c","statements":[],"y":0}`, false,
		},
		{
			"an array of another length", `{"@context":"c","statements":[],"x":[1]}`,
			`{"@context":"c","statements":[],"x":[1,1]}`, false,
		},
		{
			"an array in another order", `{"@context":"c","statements":[],"x":[1,2]}`,
			`{"@context":"c","statements":[],"x":[2,1]}`, false,
		},
		{
			"an object where an array was", `{"@context":"c","statements":[],"x":[]}`,
			`{"@context":"c","statements":[],"x":{}}`, false,
		},
		{
			"an array where an object was", `{"@context":"c","statements":[],"x":{}}`,
			`{"@context":"c","statements":[],"x":[]}`, false,
		},
		{
			"a number where a string was", `{"@context":"c","statements":[],"version":"1"}`,
			`{"@context":"c","statements":[],"version":1}`, false,
		},
		{
			"a string where a number was", `{"@context":"c","statements":[],"version":1}`,
			`{"@context":"c","statements":[],"version":"1"}`, false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &fakeStore{answers: map[string][]jsonx.Raw{
				first: {bundleOf(t, "https://openvex.dev/ns/v0.2.0", tt.stored)},
			}}

			f := vexsubjects.DecisionFile{Path: "security/vex/x.openvex.json", Raw: []byte(tt.decision)}

			pl := planner(t, store, doc)
			pl.Derive = func(*vexjoin.Decisions, string) (*vexsubjects.Document, error) { return doc, nil }

			// The comparison is under test, not the join: a document
			// with nothing joinable still reaches the probe through a
			// scripted derivation.
			plan, err := pl.Plan([]vexsubjects.DecisionFile{f})
			if err != nil {
				t.Fatal(err)
			}

			if len(plan.Refused) != 0 {
				t.Fatalf("refused %+v — the comparison never ran", plan.Refused)
			}

			if got := len(plan.Held) == 1; got != tt.held {
				t.Fatalf("held = %v, want %v (plan %+v)", got, tt.held, plan)
			}
		})
	}
}
