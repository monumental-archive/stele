package assert_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// The capture: two real signer certificates and every forge answer
// their reconciliation read, moved from the canon's rekor-monitor
// testdata; signer-certificates/SOURCE.md records where and when.
const captureDir = "testdata/signer-certificates"

// The two real signings, as the canon's tests named them.
const (
	captureOwner   = "monumental-archive"
	captureCanon   = "monumental-archive/.github"
	captureSigner  = "monumental-archive/signer"
	captureSignYML = "monumental-archive/signer/.github/workflows/sign.yml"

	releaseIndex  = 443908396
	releaseRun    = "43671235061"
	releaseSigner = "cffec9441210d46f237099d8785098aacf5b8273"
	releaseSHA    = "ebce3d46ea3130824b827cbbe383e16dfc64b17c"

	vexIndex  = 335460347
	vexRun    = "31536050844"
	vexSigner = "e50552beb52c8220c470e15702310561d7a3cfb1"
	vexSHA    = "cabe764282864c0724672b58dd899b423a120368"

	otherSHA = "0123456789abcdef0123456789abcdef01234567"
)

// capturedLeaf is the Merkle tree leaf of one captured get-entries
// answer: the bytes the log committed to.
func capturedLeaf(t *testing.T, index int) []byte {
	t.Helper()

	b, err := os.ReadFile(filepath.Join(captureDir, fmt.Sprintf("ct-%d.json", index)))
	if err != nil {
		t.Fatal(err)
	}

	doc, err := jsonx.DecodeBytes[struct {
		Entries []entryDoc `json:"entries"`
	}](b)
	if err != nil {
		t.Fatal(err)
	}

	if len(doc.Entries) != 1 {
		t.Fatalf("ct-%d.json holds %d entries, want 1", index, len(doc.Entries))
	}

	leaf, err := base64.StdEncoding.DecodeString(doc.Entries[0].LeafInput)
	if err != nil {
		t.Fatal(err)
	}

	return leaf
}

// capturedRun is a run as the forge answered it.
type capturedRun struct {
	Event      string `json:"event"`
	HeadSHA    string `json:"head_sha"`
	HTMLURL    string `json:"html_url"`
	ID         int64  `json:"id"`
	Path       string `json:"path"`
	Referenced []struct {
		Path string `json:"path"`
		Ref  string `json:"ref,omitempty"`
		SHA  string `json:"sha"`
	} `json:"referenced_workflows"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

// captureForge answers the reconciliation's reads from the capture,
// keyed by the REST path each answer was captured under. Each row
// edits its own copy. A read the capture does not hold fails the test
// by name, the way the canon's fake raised UnexpectedReadError — except
// a run (absent is the forge's 404) and a compare (absent is the
// canon's "diverged").
type captureForge struct {
	t *testing.T

	mu       sync.Mutex
	runs     map[string]*capturedRun
	files    map[string]string
	branches map[string]string
	compare  map[string]string
	// absent are the file reads the forge answers 404 for.
	absent map[string]bool
	// fail, when set, refuses every read whose key it matches.
	fail  func(key string) error
	reads []string
}

func newCaptureForge(t *testing.T) *captureForge {
	t.Helper()

	b, err := os.ReadFile(filepath.Join(captureDir, "forge-2026-11-15.json"))
	if err != nil {
		t.Fatal(err)
	}

	raw, err := jsonx.DecodeBytes[map[string][2]jsonx.Raw](b)
	if err != nil {
		t.Fatal(err)
	}

	f := &captureForge{
		t: t, runs: map[string]*capturedRun{}, files: map[string]string{},
		branches: map[string]string{}, compare: map[string]string{}, absent: map[string]bool{},
	}

	for key, answer := range *raw {
		f.load(key, answer[1])
	}

	return f
}

func (f *captureForge) WorkflowRun(owner, repo string, id uint64) (*gh.WorkflowRun, bool, error) {
	key := runKey(owner+"/"+repo, strconv.FormatUint(id, 10))
	if err := f.read(key); err != nil {
		return nil, false, err
	}

	run, ok := f.runs[key]
	if !ok {
		return nil, false, nil
	}

	out := &gh.WorkflowRun{
		Repository: run.Repository.FullName,
		Path:       run.Path,
		HeadSHA:    run.HeadSHA,
		HTMLURL:    run.HTMLURL,
		Event:      run.Event,
	}

	for _, r := range run.Referenced {
		out.Referenced = append(out.Referenced, gh.ReferencedWorkflow{Path: r.Path, SHA: r.SHA})
	}

	return out, true, nil
}

//nolint:gocritic // unnamedResult: assert.SignerForge's shape, which a fake implements as declared
func (f *captureForge) FileAt(owner, repo, path, ref string) ([]byte, bool, error) {
	key := fileKey(owner+"/"+repo, path, ref)
	if err := f.read(key); err != nil {
		return nil, false, err
	}

	if f.absent[key] {
		return nil, false, nil
	}

	text, ok := f.files[key]
	if !ok {
		f.t.Errorf("the reconciliation read %s, which the capture does not hold", key)

		return nil, false, fmt.Errorf("unexpected read %s", key)
	}

	return []byte(text), true, nil
}

func (f *captureForge) OnDefaultBranch(owner, repo, sha string) (bool, error) {
	full := owner + "/" + repo
	if err := f.read("/repos/" + full + "@" + sha); err != nil {
		return false, err
	}

	branch, ok := f.branches["/repos/"+full]
	if !ok {
		f.t.Errorf("the reconciliation asked for %s's default branch, which the capture does not hold", full)

		return false, fmt.Errorf("unexpected read /repos/%s", full)
	}

	status := f.compare[compareKey(full, branch, sha)]

	return status == "identical" || status == "behind", nil
}

func (f *captureForge) load(key string, body jsonx.Raw) {
	f.t.Helper()

	switch {
	case strings.Contains(key, "/actions/runs/"):
		run, err := jsonx.DecodeBytes[capturedRun](body)
		if err != nil {
			f.t.Fatal(err)
		}

		f.runs[key] = run
	case strings.Contains(key, "/contents/"):
		doc, err := jsonx.DecodeForeign[struct {
			File string `json:"file"`
		}](body)
		if err != nil {
			f.t.Fatal(err)
		}

		text, err := os.ReadFile(filepath.Join(captureDir, doc.File))
		if err != nil {
			f.t.Fatal(err)
		}

		f.files[key] = string(text)
	case strings.Contains(key, "/compare/"):
		doc, err := jsonx.DecodeBytes[struct {
			Status string `json:"status"`
		}](body)
		if err != nil {
			f.t.Fatal(err)
		}

		f.compare[key] = doc.Status
	default:
		doc, err := jsonx.DecodeBytes[struct {
			DefaultBranch string `json:"default_branch"`
		}](body)
		if err != nil {
			f.t.Fatal(err)
		}

		f.branches[key] = doc.DefaultBranch
	}
}

func runKey(repo, id string) string { return "/repos/" + repo + "/actions/runs/" + id }

func fileKey(repo, path, sha string) string {
	return "/repos/" + repo + "/contents/" + path + "?ref=" + sha
}

func compareKey(repo, branch, sha string) string {
	return "/repos/" + repo + "/compare/" + branch + "..." + sha
}

// editRelease opens the captured release run for editing.
func (f *captureForge) editRelease() *capturedRun {
	f.t.Helper()

	run, ok := f.runs[runKey(captureCanon, releaseRun)]
	if !ok {
		f.t.Fatalf("the capture holds no run %s in %s", releaseRun, captureCanon)
	}

	return run
}

// putFile answers a contents read with this text.
func (f *captureForge) putFile(repo, path, sha, text string) {
	f.files[fileKey(repo, path, sha)] = text
}

// file is a captured file's text.
func (f *captureForge) file(repo, path, sha string) string {
	f.t.Helper()

	text, ok := f.files[fileKey(repo, path, sha)]
	if !ok {
		f.t.Fatalf("the capture holds no %s", fileKey(repo, path, sha))
	}

	return text
}

func (f *captureForge) read(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.reads = append(f.reads, key)

	if f.fail != nil {
		return f.fail(key)
	}

	return nil
}

// throttledRead is the shape a forge read that could not complete
// returns: the host's pace, never a fact about the run.
func throttledRead(key string) error {
	t := gh.ThrottleEvidence(http.Header{"X-Ratelimit-Remaining": {"0"}}, gh.MarkerRemainingZero)

	return gh.ThrottleRefusal("GET "+key+": HTTP 403", &t)
}
