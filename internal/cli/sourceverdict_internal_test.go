// The source verdict leg of `emit vsa` (stele#391), end to end through
// the verb over a real repository: a release world whose provenance
// folds to a commit carrying a verified chain link, a signed release
// tag on that commit, and a signer that registers what it signs with
// the truthful verifier — so the emitter's own read-back judges the
// exact bytes it is about to write.

package cli

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/dsse"
	"github.com/monumental-archive/stele/internal/emit"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/gitrepo"
	"github.com/monumental-archive/stele/internal/gittest"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

const (
	srcLinkSAN    = "https://github.com/acme/widget/.github/workflows/source-attest.yml@refs/heads/main"
	srcVerdictSAN = "https://github.com/acme/canon/.github/workflows/verify-release.yml@" +
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	srcMinter = "release-mint[bot]"
)

// sourceWorld is the release world plus the repository its source
// verdict reads.
type sourceWorld struct {
	*releaseWorld

	repo   *gittest.Repo
	commit string
	// tagged is the commit the release tag points at.
	tagged string
	// lastFloor and lastIdentity record what the tag check asked of the
	// signature verifier.
	lastFloor    trust.TagFloor
	lastIdentity trust.TagIdentity
}

// linkNote renders a version-3 chain link on rev whose two halves the
// truthful verifier accepts under the source identity.
func (w *sourceWorld) linkNote(t *testing.T, rev string, levels []string) []byte {
	t.Helper()

	prov := mustMarshal(t, map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"digest": map[string]any{"gitCommit": rev}}},
		"predicateType": "https://acme.example/attestations/source-provenance/v1",
		"predicate": map[string]any{
			"repository": "acme/widget", "ref": "refs/heads/main", "commitTime": "2026-08-01T00:00:00Z",
			"controls":   []any{map[string]any{"property": "ORG_SOURCE_GATED", "evidence": map[string]any{}}},
			"ledgerPrev": nil,
		},
	})

	summary := mustMarshal(t, map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"digest": map[string]any{"gitCommit": rev}}},
		"predicateType": "https://slsa.dev/verification_summary/v1",
		"predicate": map[string]any{
			"verifier":           map[string]any{"id": srcLinkSAN},
			"resourceUri":        "git+https://github.com/acme/widget",
			"policy":             map[string]any{"uri": "https://github.com/acme/canon/tree/v1.0.0"},
			"verificationResult": "PASSED",
			"verifiedLevels":     levels,
		},
	})

	half := func(name string, stmt []byte) map[string]any {
		raw := []byte(`{"prepared":"link-` + name + `-` + rev[:8] + `"}`)
		w.bv.byRaw[string(raw)] = &prepared{
			raw: raw, san: srcLinkSAN,
			digests: map[string]bool{chain.SHA256Hex(dsse.PAE(chain.StatementType, stmt)): true},
		}

		bundle, err := jsonx.DecodeBytes[map[string]any](raw)
		if err != nil {
			t.Fatal(err)
		}

		return map[string]any{
			"payloadType": chain.StatementType,
			"statement":   b64Std(stmt),
			"bundle":      *bundle,
		}
	}

	return mustMarshal(t, map[string]any{
		"version":    3,
		"provenance": half("prov", prov),
		"vsa":        half("vsa", summary),
	})
}

// newSourceWorld builds the clean world: one linked genesis commit on
// main, a signed annotated release tag on it by the minting tagger,
// and the release's provenance folded to that commit.
func newSourceWorld(t *testing.T) *sourceWorld {
	t.Helper()

	w := &sourceWorld{releaseWorld: newReleaseWorld(t), repo: gittest.New(t)}
	w.commit = w.repo.Commit("feat: the release")
	w.tagged = w.commit

	// The provenance names this repository's real commit.
	prov := w.bv.byRaw[`{"prepared": "provenance"}`]
	prov.stmt = bytes.ReplaceAll(prov.stmt, []byte(relSrcRev), []byte(w.commit))

	return w
}

// build lays the notes and the tag, and swaps every seam the leg
// reaches: the release seams, a signer that registers its bundles with
// the truthful verifier, and a tag verifier that records what it was
// asked.
func (w *sourceWorld) build(t *testing.T, tagger string, signed bool, tagErr error) {
	t.Helper()

	w.repo.Note("refs/notes/commits", w.commit, w.linkNote(t, w.commit, []string{"SLSA_SOURCE_LEVEL_3"}))

	if tagger != "" {
		w.repo.Annotated(relTag, w.tagged, tagger, signed)
	}

	swap(t, w.bv, w.store)
	swapSourceSeams(t, w, registeringSigner{bv: w.bv}, tagErr)
}

func swapSourceSeams(t *testing.T, w *sourceWorld, s emit.Signer, tagErr error) {
	t.Helper()

	origSigner, origTag, origNow := newSigner, verifyTagSignature, emitNow

	newSigner = func(string) emit.Signer { return s }
	verifyTagSignature = func(_, _, _ []byte, id trust.TagIdentity, floor trust.TagFloor) (*trust.TagVerdict, error) {
		w.lastFloor, w.lastIdentity = floor, id
		if tagErr != nil {
			return nil, tagErr
		}

		return &trust.TagVerdict{SAN: "https://github.com/acme/mint", Depth: floor}, nil
	}
	emitNow = swapNow

	t.Cleanup(func() { newSigner, verifyTagSignature, emitNow = origSigner, origTag, origNow })
}

// registeringSigner plays the verdict identity: what it signs, the
// truthful verifier will verify under that identity and pin.
type registeringSigner struct {
	bv       truthfulBV
	checkErr error
	signErr  error
	// unregistered signs without telling the verifier — a bundle that
	// will not prove as published.
	unregistered bool
}

func (s registeringSigner) Check() error { return s.checkErr }

func (s registeringSigner) Sign(payload []byte) ([]byte, error) {
	if s.signErr != nil {
		return nil, s.signErr
	}

	raw := []byte(`{"prepared":"source-verdict"}`)
	if !s.unregistered {
		s.bv.byRaw[string(raw)] = &prepared{
			raw: raw, san: srcVerdictSAN,
			digests: map[string]bool{chain.SHA256Hex(payload): true},
			ext:     certificate.Extensions{BuildSignerDigest: strings.Repeat("b", 40)},
		}
	}

	return raw, nil
}

// sourceAssertPolicy writes an assert policy declaring the tag
// obligation, the source-verdict epoch when owed, and the epoch line.
func sourceAssertPolicy(t *testing.T, owed bool, epochs string) string {
	t.Helper()

	// The floor rises for widget from v1.0.0 — the tag under test owes
	// the heavier one — wherever widget signs at all; a raise for a
	// repository the epochs leave unsigned is a policy the loader
	// refuses, so those worlds declare the plain floor.
	floor := `"proofFloor": {"floor": "certificate-transparency"}, `
	if epochs == signingEpochs {
		floor = `"proofFloor": {"floor": "observer-timestamp", "from": {"widget": "v1.0.0"}, ` +
			`"before": "certificate-transparency"}, `
	}

	epoch := ""
	if owed {
		epoch = `"sourceVerdictFromVersion": "1.70.0", "sourceVerdictBundle": "source-verdict.json", `
	}

	doc := `{"schema": 9, "issuer": "https://token.example.com", ` +
		`"evidence": {"sbomSuffix": ".spdx.json", "checksums": "checksums.txt", ` + epoch +
		`"umbrellaBundle": "attestations.intoto.jsonl", "manifestAsset": "evidence-manifest.json", ` +
		`"classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}}, ` +
		`"tags": {"tagPattern": "^v[0-9]", "taggerName": "` + srcMinter + `", ` +
		`"identityPattern": "^https://github\\.com/acme/", ` + floor +
		`"notesRef": "refs/notes/commits", "epochs": ` + epochs + `}}`

	path := filepath.Join(t.TempDir(), "assert-policy.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

const signingEpochs = `{"widget": "v0.1.0"}`

// sourceRun is one `emit vsa` invocation with its outputs.
type sourceRun struct {
	code           int
	stdout, stderr string
	predicate      string
	source         string
}

func (w *sourceWorld) emit(t *testing.T, assertPolicy string, extra ...string) sourceRun {
	t.Helper()

	px := files(t)
	subjects, sboms := w.manifests(t)
	dir := t.TempDir()
	run := sourceRun{predicate: filepath.Join(dir, "vsa.json"), source: filepath.Join(dir, "source.json")}

	args := []string{
		"emit", "vsa",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", relTag,
		"--subjects", subjects, "--sboms", sboms,
		"--signer-digest", strings.Repeat("a", 40), "--machinery-digest", strings.Repeat("b", 40),
		"--policy-uri", "https://github.com/acme/canon/blob/x/slsa/verify-policy.json",
		"--out", run.predicate,
	}
	if assertPolicy != "" {
		args = append(args, "--assert-policy", assertPolicy, "--git-dir", w.repo.Dir, "--source-out", run.source)
	}

	var stdout, stderr bytes.Buffer

	run.code = Run(append(args, extra...), &stdout, &stderr)
	run.stdout, run.stderr = stdout.String(), stderr.String()

	return run
}

func written(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}

// TestEmitVSAEmitsTheSourceVerdict: both verdicts written, the source
// one an envelope the consumer's read accepts against the commit's
// link, naming exactly the tag, and the tag judged at the floor the
// policy owes THIS tag under the declared identity.
func TestEmitVSAEmitsTheSourceVerdict(t *testing.T) {
	w := newSourceWorld(t)
	w.build(t, srcMinter, true, nil)

	run := w.emit(t, sourceAssertPolicy(t, true, signingEpochs))
	if run.code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", run.code, run.stdout, run.stderr)
	}

	if !written(run.predicate) {
		t.Error("the release predicate was not written")
	}

	env, err := os.ReadFile(run.source)
	if err != nil {
		t.Fatalf("the source verdict was not written: %v", err)
	}

	if w.lastFloor != trust.TagFloorObserverTimestamp || w.lastIdentity.Issuer != "https://token.example.com" ||
		!w.lastIdentity.SANPattern.MatchString("https://github.com/acme/mint") {
		t.Errorf("tag judged at floor %q under %+v — want the raised floor and the declared identity",
			w.lastFloor, w.lastIdentity)
	}

	// The consumer's read, independently: walk the clone again and hold
	// the written envelope against the commit's link.
	vp := loadTestPolicy(t)

	h, err := gitrepo.Open(w.repo.Dir, "refs/notes/commits")
	if err != nil {
		t.Fatal(err)
	}

	c := verify.Coords{Owner: "acme", Repo: "widget", Tag: relTag}

	walk, err := verify.Chain(vp, c, "refs/heads/main", h, w.bv, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}

	link, _ := walk.Link(w.commit)
	pins := verify.Pins{Signer: strings.Repeat("a", 40), Machinery: strings.Repeat("b", 40)}

	got, err := verify.SourceVSA(vp, c, pins, w.commit, link, bytes.TrimSpace(env), w.bv)
	if err != nil {
		t.Fatalf("the written source verdict does not read back: %v", err)
	}

	if strings.Join(got.Levels(), " ") != "SLSA_SOURCE_LEVEL_3" {
		t.Errorf("levels = %v, want the link's", got.Levels())
	}

	if !strings.Contains(run.stdout, "source verdict for acme/widget@"+relTag) {
		t.Errorf("stdout = %q, want the source verdict line", run.stdout)
	}
}

// TestEmitVSAOwesNoSourceVerdict: without the assert policy, or with
// one that declares no source-verdict epoch, the verb is what it was —
// no source flags demanded, nothing extra written, the tag never read.
func TestEmitVSAOwesNoSourceVerdict(t *testing.T) {
	for _, tt := range []struct {
		name   string
		policy func(t *testing.T) string
	}{
		{"no assert policy", func(*testing.T) string { return "" }},
		{"no source-verdict epoch", func(t *testing.T) string {
			t.Helper()

			return sourceAssertPolicy(t, false, signingEpochs)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := newSourceWorld(t)
			w.build(t, "", false, errors.New("the tag must not be read"))

			run := w.emit(t, tt.policy(t))
			if run.code != exitOK {
				t.Fatalf("Run = %d\nstderr: %s", run.code, run.stderr)
			}

			if written(run.source) || !written(run.predicate) {
				t.Errorf("source written %v, predicate written %v — want the release verdict alone",
					written(run.source), written(run.predicate))
			}
		})
	}
}

// TestEmitVSASourceVerdictUsage: the inputs an owed verdict needs are
// refused by name before anything verifies.
func TestEmitVSASourceVerdictUsage(t *testing.T) {
	w := newSourceWorld(t)
	w.build(t, srcMinter, true, nil)

	owed := sourceAssertPolicy(t, true, signingEpochs)
	notAPolicy := filepath.Join(t.TempDir(), "x.json")

	if err := os.WriteFile(notAPolicy, []byte(`{"schema": 9}`), 0o600); err != nil {
		t.Fatal(err)
	}

	sourceless := filepath.Join(t.TempDir(), "verify-policy.json")

	doc, err := jsonx.Value([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}

	m, ok := doc.(map[string]any)
	if !ok {
		t.Fatal("the test policy is not an object")
	}

	delete(m, "source")

	if err := os.WriteFile(sourceless, mustMarshal(t, m), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"assert policy unreadable", []string{"--assert-policy", "/nonexistent"}, "nonexistent"},
		{"assert policy invalid", []string{"--assert-policy", notAPolicy}, "assert policy:"},
		{"owed without a clone", []string{"--assert-policy", owed, "--source-out", "x"}, "--git-dir is required"},
		{"owed without an output", []string{"--assert-policy", owed, "--git-dir", "x"}, "--source-out is required"},
		{
			"owed under a verify policy with no source section",
			[]string{"--assert-policy", owed, "--git-dir", "x", "--source-out", "y", "--policy", sourceless},
			"declares no source section",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := w.emit(t, "", tt.args...)
			if run.code != exitUsage || !strings.Contains(run.stderr, tt.want) {
				t.Fatalf("Run = %d, stderr %q — want %q", run.code, run.stderr, tt.want)
			}
		})
	}
}

// TestEmitVSASourceVerdictRefusals: every check the leg makes refuses
// by name and writes NEITHER verdict.
func TestEmitVSASourceVerdictRefusals(t *testing.T) {
	tests := []struct {
		name string
		// setup shapes the world; the default is the clean one.
		setup  func(t *testing.T, w *sourceWorld)
		epochs string
		tagger string
		// unsigned lays the tag without a signature block.
		unsigned bool
		tagErr   error
		signer   *registeringSigner
		gitDir   string
		want     string
	}{
		{
			name: "the tag's signature fails", tagErr: errors.New("chain untrusted"),
			want: "tag " + relTag + " signature refused (floor observer-timestamp): chain untrusted",
		},
		{name: "the commit has no verifying link", setup: func(t *testing.T, w *sourceWorld) {
			t.Helper()
			w.commit = w.repo.Commit("feat: past the ledger")
			w.tagged = w.commit
			prov := w.bv.byRaw[`{"prepared": "provenance"}`]
			prov.stmt = bytes.ReplaceAll(prov.stmt, []byte(w.repo.Git("rev-parse", "HEAD~1")), []byte(w.commit))
			w.repo.Note("refs/notes/commits", w.repo.Git("rev-parse", "HEAD~1"),
				w.linkNote(t, w.repo.Git("rev-parse", "HEAD~1"), []string{"SLSA_SOURCE_LEVEL_3"}))
		}, want: "carries no verified chain link on a declared protected branch"},
		{name: "the tag points elsewhere", setup: func(t *testing.T, w *sourceWorld) {
			t.Helper()
			w.tagged = w.repo.Commit("feat: after the release")
		}, want: "the tag points at"},
		{name: "the tag is not fetched", tagger: "-", want: "tag " + relTag + " is not in the clone"},
		{name: "a lightweight tag", setup: func(t *testing.T, w *sourceWorld) {
			t.Helper()
			w.repo.Lightweight(relTag, w.commit)
		}, tagger: "-", want: "is lightweight"},
		{name: "another tagger", tagger: "someone", want: `made by tagger "someone", not the minting identity`},
		{
			name: "no signing epoch for the repository", epochs: `{"gadget": "v0.1.0"}`,
			want: "declares no signing epoch for widget",
		},
		{name: "a repository declared unsigned", epochs: `{"widget": "pending"}`, want: "unsigned (pending)"},
		{name: "an unsigned tag", unsigned: true, want: "tag " + relTag + " is unsigned"},
		{
			name: "a tag before its repository's signing epoch", epochs: `{"widget": "v2.0.0"}`,
			want: "tag " + relTag + " predates widget's signing epoch v2.0.0",
		},
		{name: "the clone cannot be opened", gitDir: "/nonexistent", want: "emit: source verdict:"},
		{
			name: "the signer is unusable", signer: &registeringSigner{checkErr: errors.New("no cosign")},
			want: "no cosign",
		},
		{
			name: "signing fails", signer: &registeringSigner{signErr: errors.New("no token")},
			want: "signing: no token",
		},
		{
			name: "the signed verdict does not verify", signer: &registeringSigner{unregistered: true},
			want: "the source verdict just signed does not verify as published",
		},
		{name: "a protected branch's walk refuses", setup: func(t *testing.T, w *sourceWorld) {
			t.Helper()
			w.repo.Note("refs/notes/commits", w.commit, w.linkNote(t, strings.Repeat("e", 40), nil))
		}, want: "walks refused: refs/heads/main"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newSourceWorld(t)

			tagger := tt.tagger
			if tagger == "" {
				tagger = srcMinter
			}

			w.repo.Note("refs/notes/commits", w.commit, w.linkNote(t, w.commit, []string{"SLSA_SOURCE_LEVEL_3"}))

			if tt.setup != nil {
				tt.setup(t, w)
			}

			if tagger != "-" {
				w.repo.Annotated(relTag, w.tagged, tagger, !tt.unsigned)
			}

			signer := registeringSigner{bv: w.bv}
			if tt.signer != nil {
				signer = *tt.signer
				signer.bv = w.bv
			}

			swap(t, w.bv, w.store)
			swapSourceSeams(t, w, signer, tt.tagErr)

			epochs := tt.epochs
			if epochs == "" {
				epochs = signingEpochs
			}

			var extra []string
			if tt.gitDir != "" {
				extra = []string{"--git-dir", tt.gitDir}
			}

			run := w.emit(t, sourceAssertPolicy(t, true, epochs), extra...)
			if run.code != exitRefused || !strings.Contains(run.stderr, tt.want) {
				t.Fatalf("Run = %d, stderr %q — want %q", run.code, run.stderr, tt.want)
			}

			if written(run.source) || written(run.predicate) {
				t.Errorf("source written %v, predicate written %v — a refusal writes neither",
					written(run.source), written(run.predicate))
			}
		})
	}
}

// TestEmitVSAPredicateWriteFailureTakesTheSourceVerdictWithIt: the
// source verdict is written first, and removed again when the release
// predicate cannot be — neither verdict is left without the other.
func TestEmitVSAPredicateWriteFailureTakesTheSourceVerdictWithIt(t *testing.T) {
	w := newSourceWorld(t)
	w.build(t, srcMinter, true, nil)

	unwritable := filepath.Join(t.TempDir(), "missing-dir", "vsa.json")

	run := w.emit(t, sourceAssertPolicy(t, true, signingEpochs), "--out", unwritable)
	if run.code != exitRefused || !strings.Contains(run.stderr, "writing the predicate") {
		t.Fatalf("Run = %d, stderr %q — want the predicate write refusal", run.code, run.stderr)
	}

	if written(run.source) {
		t.Error("the source verdict outlived the release predicate's failed write")
	}
}

// TestEmitVSASourceVerdictWriteFailure: an unwritable source path
// refuses before the predicate is written.
func TestEmitVSASourceVerdictWriteFailure(t *testing.T) {
	w := newSourceWorld(t)
	w.build(t, srcMinter, true, nil)

	unwritable := filepath.Join(t.TempDir(), "missing-dir", "source.json")

	run := w.emit(t, sourceAssertPolicy(t, true, signingEpochs), "--source-out", unwritable)
	if run.code != exitRefused || !strings.Contains(run.stderr, "writing the source verdict") {
		t.Fatalf("Run = %d, stderr %q — want the source write refusal", run.code, run.stderr)
	}

	if written(run.predicate) {
		t.Error("the release predicate was written after the source verdict's write failed")
	}
}

// mustMarshal renders a test document through jsonx.
func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()

	out, err := jsonx.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	return out
}

func b64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// swapNow is the fixed clock both verdicts are stamped with.
func swapNow() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) }

func loadTestPolicy(t *testing.T) *policy.Policy {
	t.Helper()

	p, err := policy.Load(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}

	return p
}

// assetForge serves release assets from a map and nothing else — the
// only read `verify source-vsa` makes of the forge.
type assetForge struct {
	gh.Forge

	assets map[string][]byte // repo@tag/name
}

func (f assetForge) Asset(_, repo, tag, name string) ([]byte, error) {
	b, ok := f.assets[repo+"@"+tag+"/"+name]
	if !ok {
		return nil, errors.New("no such asset")
	}

	return b, nil
}

// publishedVerdict emits the world's source verdict and serves it as
// the release asset the assert policy names, for every tag given.
func (w *sourceWorld) publishedVerdict(t *testing.T, tags ...string) string {
	t.Helper()

	policyPath := sourceAssertPolicy(t, true, signingEpochs)

	run := w.emit(t, policyPath)
	if run.code != exitOK {
		t.Fatalf("emitting the verdict = %d: %s", run.code, run.stderr)
	}

	env, err := os.ReadFile(run.source)
	if err != nil {
		t.Fatal(err)
	}

	f := assetForge{assets: map[string][]byte{}}
	for _, tag := range tags {
		f.assets["widget@"+tag+"/source-verdict.json"] = env
	}

	orig := newForge
	newForge = func() gh.Forge { return f }

	t.Cleanup(func() { newForge = orig })

	return policyPath
}

func (w *sourceWorld) verifySource(t *testing.T, tag string, extra ...string) sourceRun {
	t.Helper()

	px := files(t)

	args := append([]string{
		"verify", "source-vsa",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", tag,
		"--git-dir", w.repo.Dir,
		"--machinery-digest", strings.Repeat("b", 40),
	}, extra...)

	var stdout, stderr bytes.Buffer

	code := Run(args, &stdout, &stderr)

	return sourceRun{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// TestVerifySourceVSA: the published verdict, fetched as the release
// asset the assert policy names, reads back against the tag's commit
// and that commit's link — and the report carries both.
func TestVerifySourceVSA(t *testing.T) {
	w := newSourceWorld(t)
	w.build(t, srcMinter, true, nil)

	ap := w.publishedVerdict(t, relTag)

	run := w.verifySource(t, relTag, "--assert-policy", ap, "--json")
	if run.code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", run.code, run.stdout, run.stderr)
	}

	doc := decodeReport(t, bytes.NewBufferString(run.stdout))
	if doc.Verdict == nil || *doc.Verdict != "PASS" {
		t.Fatalf("verdict = %v, want PASS", doc.Verdict)
	}

	if got := factOf(doc, "sourceRevision"); got != w.commit {
		t.Errorf("sourceRevision = %q, want %q", got, w.commit)
	}

	if got := factOf(doc, "verifiedLevels"); got != "SLSA_SOURCE_LEVEL_3" {
		t.Errorf("verifiedLevels = %q, want the link's level", got)
	}
}

// TestVerifySourceVSARefusals: each guard of the read refuses by name.
func TestVerifySourceVSARefusals(t *testing.T) {
	w := newSourceWorld(t)
	w.build(t, srcMinter, true, nil)

	ap := w.publishedVerdict(t, relTag, "v1.2.4", "v9.9.9")

	// Another tag on the same commit, served the same verdict: the
	// subject matches, the tag it names does not.
	w.repo.Annotated("v1.2.4", w.commit, srcMinter, true)

	bare := filepath.Join(t.TempDir(), "bare-assert-policy.json")
	if err := os.WriteFile(bare, []byte(strings.Replace(
		mustRead(t, sourceAssertPolicy(t, false, signingEpochs)), `"sourceVerdictFromVersion": "1.70.0", `, "", 1,
	)), 0o600); err != nil {
		t.Fatal(err)
	}

	notAPolicy := filepath.Join(t.TempDir(), "x.json")
	if err := os.WriteFile(notAPolicy, []byte(`{"schema": 9}`), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		tag   string
		extra []string
		code  int
		want  string
	}{
		{
			"a verdict naming another tag fails by name", "v1.2.4",
			[]string{"--assert-policy", ap},
			exitRefused,
			`sourceRefs names "[refs/tags/v1.2.3]", not exactly refs/tags/v1.2.4`,
		},
		{
			"the asset is not published", "v1.2.5",
			[]string{"--assert-policy", ap},
			exitRefused,
			"source verdict asset source-verdict.json of acme/widget@v1.2.5: no such asset",
		},
		{
			"the tag is not in the clone", "v9.9.9",
			[]string{"--assert-policy", ap},
			exitRefused,
			"tag v9.9.9 is not in the clone",
		},
		{
			"the clone cannot be opened", relTag,
			[]string{"--assert-policy", ap, "--git-dir", "/nonexistent"},
			exitRefused, "verify: ",
		},
		{"no --tag", "", []string{"--assert-policy", ap}, exitUsage, "--tag is required"},
		{"no --git-dir", relTag, []string{"--assert-policy", ap, "--git-dir", ""}, exitUsage, "--git-dir is required"},
		{"no --assert-policy", relTag, nil, exitUsage, "--assert-policy is required"},
		{"an unreadable assert policy", relTag, []string{"--assert-policy", "/nonexistent"}, exitUsage, "nonexistent"},
		{"an invalid assert policy", relTag, []string{"--assert-policy", notAPolicy}, exitUsage, "assert policy:"},
		{
			"an assert policy naming no asset", relTag,
			[]string{"--assert-policy", bare},
			exitUsage,
			"declares no evidence.sourceVerdictBundle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := w.verifySource(t, tt.tag, tt.extra...)
			if run.code != tt.code || !strings.Contains(run.stderr, tt.want) {
				t.Fatalf("Run = %d, stderr %q — want %d and %q", run.code, run.stderr, tt.code, tt.want)
			}
		})
	}
}

// TestVerifySourceVSAWithoutASourceSection: a verify policy that
// declares no source section names no resource for the verdict.
func TestVerifySourceVSAWithoutASourceSection(t *testing.T) {
	w := newSourceWorld(t)
	w.build(t, srcMinter, true, nil)

	ap := w.publishedVerdict(t, relTag)

	doc, err := jsonx.Value([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}

	m, ok := doc.(map[string]any)
	if !ok {
		t.Fatal("the test policy is not an object")
	}

	delete(m, "source")

	sourceless := filepath.Join(t.TempDir(), "verify-policy.json")
	if err := os.WriteFile(sourceless, mustMarshal(t, m), 0o600); err != nil {
		t.Fatal(err)
	}

	run := w.verifySource(t, relTag, "--assert-policy", ap, "--policy", sourceless)
	if run.code != exitRefused || !strings.Contains(run.stderr, "the verify policy declares no source section") {
		t.Fatalf("Run = %d, stderr %q", run.code, run.stderr)
	}
}

// fixedHistories serves one clone for every repository, or one error.
type fixedHistories struct {
	repo *gitrepo.Repo
	err  error
}

func (h fixedHistories) Repo(string, string) (*gitrepo.Repo, error) { return h.repo, h.err }

// TestEngineVerifierSourceVSA: the full-depth seam runs the same read
// over the history session, and says so when no history was fetched.
func TestEngineVerifierSourceVSA(t *testing.T) {
	w := newSourceWorld(t)
	w.build(t, srcMinter, true, nil)

	w.publishedVerdict(t, relTag)

	env, err := newForge().Asset("acme", "widget", relTag, "source-verdict.json")
	if err != nil {
		t.Fatal(err)
	}

	clone, err := gitrepo.Open(w.repo.Dir, "refs/notes/commits")
	if err != nil {
		t.Fatal(err)
	}

	c := verify.Coords{Owner: "acme", Repo: "widget", Tag: relTag}
	pins := verify.Pins{Signer: strings.Repeat("a", 40), Machinery: strings.Repeat("b", 40)}

	tests := []struct {
		name    string
		history sourceHistories
		want    string
	}{
		{"the read passes over the fetched clone", fixedHistories{repo: clone}, ""},
		{"no history was fetched", nil, "no history was fetched for source verdicts"},
		{"the fetch failed", fixedHistories{err: errors.New("fetch torn")}, "fetch torn"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &engineVerifier{vp: loadTestPolicy(t), bv: w.bv, history: tt.history}

			err := ev.SourceVSA(c, env, pins)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("SourceVSA = %v", err)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("SourceVSA = %v, want %q", err, tt.want)
			}
		})
	}
}

// TestLoadFullDepthSourceHistory: a walk owing source verdicts gets a
// history session over the declared protected branches and the
// ledger; one whose verify policy declares no source section refuses.
func TestLoadFullDepthSourceHistory(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})

	px := files(t)

	_, history, err := loadFullDepth(px.policy, []byte(`{"any": "bytes"}`), &storeForge{}, noPins{}, true, nil)
	if err != nil {
		t.Fatalf("loadFullDepth = %v", err)
	}

	if history == nil || len(history.Want.Branches) != 1 || history.Want.Branches[0] != "refs/heads/main" ||
		history.Want.NotesRef != "refs/notes/commits" || !history.Want.Tags || history.Want.Shallow {
		t.Fatalf("history session = %+v, want the protected branches, the ledger and the tags, unshallow", history)
	}

	_, history, err = loadFullDepth(px.policy, []byte(`{"any": "bytes"}`), &storeForge{}, noPins{}, false, nil)
	if err != nil || history != nil {
		t.Fatalf("loadFullDepth owing nothing = %v, %v — want no history session", history, err)
	}

	doc, err := jsonx.Value([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}

	m, ok := doc.(map[string]any)
	if !ok {
		t.Fatal("the test policy is not an object")
	}

	delete(m, "source")

	sourceless := filepath.Join(t.TempDir(), "verify-policy.json")
	if err := os.WriteFile(sourceless, mustMarshal(t, m), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := loadFullDepth(sourceless, nil, &storeForge{}, noPins{}, true, nil); err == nil ||
		!strings.Contains(err.Error(), "owes source verdicts but the verify policy declares no source section") {
		t.Fatalf("loadFullDepth = %v, want the undeclared history refused by name", err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()

	b, err := os.ReadFile(path) //nolint:gosec // a path this test wrote
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}
