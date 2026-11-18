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
func (w *sourceWorld) build(t *testing.T) {
	t.Helper()

	w.repo.Note("refs/notes/commits", w.commit, w.linkNote(t, w.commit, []string{"SLSA_SOURCE_LEVEL_3"}))
	w.repo.Annotated(relTag, w.tagged, srcMinter, true)

	swap(t, w.bv, w.store)
	swapSourceSeams(t, w, registeringSigner{bv: w.bv}, nil)
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

// srcMachinery is the release machinery the world's release runs: at
// the policy's source-verdict epoch (1.70.0), so the verdict is owed.
const srcMachinery = "1.70.0"

// sourceRun is one emit invocation with its outputs.
type sourceRun struct {
	code           int
	stdout, stderr string
	predicate      string
	source         string
}

func runCLI(args []string, run sourceRun) sourceRun {
	var stdout, stderr bytes.Buffer

	run.code = Run(args, &stdout, &stderr)
	run.stdout, run.stderr = stdout.String(), stderr.String()

	return run
}

// emitSource runs `emit source-vsa` for the release tag over the
// world's clone; extra flags are appended last, so they win.
func (w *sourceWorld) emitSource(t *testing.T, assertPolicy string, extra ...string) sourceRun {
	t.Helper()

	px := files(t)
	run := sourceRun{source: filepath.Join(t.TempDir(), "source.json")}

	args := []string{
		"emit", "source-vsa",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", relTag,
		"--machinery-digest", strings.Repeat("b", 40),
		"--policy-uri", "https://github.com/acme/canon/blob/x/slsa/verify-policy.json",
		"--assert-policy", assertPolicy, "--git-dir", w.repo.Dir, "--out", run.source,
		"--machinery-version", srcMachinery,
	}

	return runCLI(append(args, extra...), run)
}

// emitVSA runs `emit vsa` for the release, with the assert policy and
// the published source verdict when given.
func (w *sourceWorld) emitVSA(t *testing.T, assertPolicy, sourceVerdict string, extra ...string) sourceRun {
	t.Helper()

	px := files(t)
	subjects, sboms := w.manifests(t)
	run := sourceRun{predicate: filepath.Join(t.TempDir(), "vsa.json")}

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
		args = append(args, "--assert-policy", assertPolicy, "--git-dir", w.repo.Dir,
			"--machinery-version", srcMachinery)
	}

	if sourceVerdict != "" {
		args = append(args, "--source-verdict", sourceVerdict)
	}

	return runCLI(append(args, extra...), run)
}

func written(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}

// tagless is an assert policy that owes source verdicts but declares no
// tag obligation — refused at load, so it is written raw.
func taglessAssertPolicy(t *testing.T) string {
	t.Helper()

	doc := `{"schema": 9, "issuer": "https://token.example.com", ` +
		`"evidence": {"sbomSuffix": ".spdx.json", "checksums": "checksums.txt", ` +
		`"umbrellaBundle": "attestations.intoto.jsonl", "manifestAsset": "evidence-manifest.json", ` +
		`"classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}}}`

	path := filepath.Join(t.TempDir(), "assert-policy.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// TestEmitSourceVSAWritesTheEnvelopeWithoutARelease (stele#468): the
// mode writes the envelope from a clone with a signed tag and a chain
// link, against a store that refuses every read — it reads no release,
// no store and no registry. The envelope is the one a consumer's read
// accepts, and the tag was judged at the floor the policy owes it.
func TestEmitSourceVSAWritesTheEnvelopeWithoutARelease(t *testing.T) {
	w := newSourceWorld(t)
	w.build(t)
	swap(t, w.bv, scriptedStore{err: errors.New("the store was read — this mode reads none")})

	run := w.emitSource(t, sourceAssertPolicy(t, true, signingEpochs))
	if run.code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", run.code, run.stdout, run.stderr)
	}

	env, err := os.ReadFile(run.source)
	if err != nil {
		t.Fatalf("the envelope was not written: %v", err)
	}

	if w.lastFloor != trust.TagFloorObserverTimestamp || w.lastIdentity.Issuer != "https://token.example.com" {
		t.Errorf("tag judged at floor %q under %+v — want the raised floor and the declared identity",
			w.lastFloor, w.lastIdentity)
	}

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
		t.Fatalf("the written envelope does not read back: %v", err)
	}

	if strings.Join(got.Levels(), " ") != "SLSA_SOURCE_LEVEL_3" {
		t.Errorf("levels = %v, want the link's", got.Levels())
	}
}

// TestEmitSourceVSARefusals: every check the producer makes refuses by
// name and writes nothing.
func TestEmitSourceVSARefusals(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(t *testing.T, w *sourceWorld)
		policy func(t *testing.T) string
		epochs string
		tagger string
		// unsigned lays the tag without a signature block.
		unsigned bool
		tagErr   error
		signer   *registeringSigner
		extra    []string
		code     int
		want     string
	}{
		{
			name: "no tags section", policy: taglessAssertPolicy, code: exitUsage,
			want: "the assert policy declares no tags section — a source verdict binds a signed tag",
		},
		{name: "no epoch", policy: func(t *testing.T) string {
			t.Helper()

			return sourceAssertPolicy(t, false, signingEpochs)
		}, code: exitUsage, want: "declares no evidence.sourceVerdictFromVersion — nobody owes a source verdict"},
		{name: "a lightweight tag", setup: func(t *testing.T, w *sourceWorld) {
			t.Helper()
			w.repo.Lightweight(relTag, w.commit)
		}, tagger: "-", code: exitRefused, want: "is lightweight"},
		{
			name: "a tag by another tagger", tagger: "someone", code: exitRefused,
			want: `made by tagger "someone", not the minting identity`,
		},
		{name: "no chain link at the target", setup: func(t *testing.T, w *sourceWorld) {
			t.Helper()
			w.tagged = w.repo.Commit("feat: past the ledger")
		}, code: exitRefused, want: "carries no verified chain link on a declared protected branch"},
		{
			name: "the tag's signature fails", tagErr: errors.New("chain untrusted"), code: exitRefused,
			want: "tag " + relTag + " signature refused (floor observer-timestamp): chain untrusted",
		},
		{name: "the tag is not fetched", tagger: "-", code: exitRefused, want: "tag " + relTag + " is not in the clone"},
		{
			name: "no signing epoch for the repository", epochs: `{"gadget": "v0.1.0"}`, code: exitUsage,
			want: "acme/widget@" + relTag + " owes no source verdict: the tags section owes no signature on widget@" +
				relTag,
		},
		{
			name: "a repository declared unsigned", epochs: `{"widget": "pending"}`, code: exitUsage,
			want: "owes no source verdict: the tags section owes no signature on widget@" + relTag,
		},
		{
			name: "a tag before its repository's signing epoch", epochs: `{"widget": "v2.0.0"}`, code: exitUsage,
			want: "owes no source verdict: the tags section owes no signature on widget@" + relTag,
		},
		{
			name: "machinery before the source-verdict epoch", extra: []string{"--machinery-version", "1.69.9"},
			code: exitUsage,
			want: "owes no source verdict: machinery 1.69.9 predates evidence.sourceVerdictFromVersion 1.70.0",
		},
		{
			name: "no machinery version", extra: []string{"--machinery-version", ""}, code: exitUsage,
			want: "--machinery-version is required: the assert policy declares evidence.sourceVerdictFromVersion",
		},
		{name: "an unsigned tag", unsigned: true, code: exitRefused, want: "tag " + relTag + " is unsigned"},
		{
			name: "the clone cannot be opened", extra: []string{"--git-dir", "/nonexistent"}, code: exitRefused,
			want: "emit: source verdict:",
		},
		{
			name: "the signer is unusable", signer: &registeringSigner{checkErr: errors.New("no cosign")},
			code: exitRefused, want: "no cosign",
		},
		{
			name: "signing fails", signer: &registeringSigner{signErr: errors.New("no token")}, code: exitRefused,
			want: "signing: no token",
		},
		{
			name: "the signed verdict does not verify", signer: &registeringSigner{unregistered: true},
			code: exitRefused, want: "the source verdict just signed does not verify as published",
		},
		{name: "a protected branch's walk refuses", setup: func(t *testing.T, w *sourceWorld) {
			t.Helper()
			w.repo.Note("refs/notes/commits", w.commit, w.linkNote(t, strings.Repeat("e", 40), nil))
		}, code: exitRefused, want: "walks refused: refs/heads/main"},
		{
			name: "an unwritable output", extra: []string{"--out", "/nonexistent/dir/source.json"}, code: exitRefused,
			want: "emit: writing the source verdict",
		},
		{name: "no tag", extra: []string{"--tag", ""}, code: exitUsage, want: "--tag is required"},
		{
			name: "no assert policy", extra: []string{"--assert-policy", ""}, code: exitUsage,
			want: "--assert-policy is required",
		},
		{name: "no clone", extra: []string{"--git-dir", ""}, code: exitUsage, want: "--git-dir is required"},
		{name: "no output", extra: []string{"--out", ""}, code: exitUsage, want: "--out is required"},
		{
			name: "an unreadable assert policy", extra: []string{"--assert-policy", "/nonexistent"}, code: exitUsage,
			want: "assert policy:",
		},
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

			assertPol := sourceAssertPolicy(t, true, epochs)
			if tt.policy != nil {
				assertPol = tt.policy(t)
			}

			run := w.emitSource(t, assertPol, tt.extra...)
			if run.code != tt.code || !strings.Contains(run.stderr, tt.want) {
				t.Fatalf("Run = %d, stderr %q — want %d and %q", run.code, run.stderr, tt.code, tt.want)
			}

			if written(run.source) {
				t.Error("a refusal wrote an envelope")
			}
		})
	}
}

// TestEmitSourceVSANoSourceSection: a verify policy with no source
// section names no resource for the verdict.
func TestEmitSourceVSANoSourceSection(t *testing.T) {
	w := newSourceWorld(t)
	w.build(t)

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

	run := w.emitSource(t, sourceAssertPolicy(t, true, signingEpochs), "--policy", sourceless)
	if run.code != exitUsage || !strings.Contains(run.stderr, "the verify policy declares no source section") {
		t.Fatalf("Run = %d, stderr %q", run.code, run.stderr)
	}
}

// publishSource produces the world's envelope with `emit source-vsa`
// and returns its path — what a publisher attaches before it seals.
func (w *sourceWorld) publishSource(t *testing.T) string {
	t.Helper()

	run := w.emitSource(t, sourceAssertPolicy(t, true, signingEpochs))
	if run.code != exitOK {
		t.Fatalf("emit source-vsa = %d: %s", run.code, run.stderr)
	}

	return run.source
}

// goldenPredicate is the release predicate `emit vsa` renders for the
// source world when no source verdict is owed.
var goldenPredicate = filepath.Join("testdata", "emit-vsa-predicate.golden")

// TestEmitVSARequiresThePublishedSourceVerdict (stele#468): `emit vsa`
// no longer writes a source verdict. Where one is owed it requires the
// published envelope and refuses unless it binds the release's own
// commit; where none is owed it is byte-for-byte what it was.
func TestEmitVSARequiresThePublishedSourceVerdict(t *testing.T) {
	t.Run("owed and absent is refused by name", func(t *testing.T) {
		w := newSourceWorld(t)
		w.build(t)

		run := w.emitVSA(t, sourceAssertPolicy(t, true, signingEpochs), "")
		if run.code != exitUsage || !strings.Contains(run.stderr, "--source-verdict is required") {
			t.Fatalf("Run = %d, stderr %q", run.code, run.stderr)
		}

		if written(run.predicate) {
			t.Error("the release predicate was written without the source verdict it owes")
		}
	})

	t.Run("present and matching passes", func(t *testing.T) {
		w := newSourceWorld(t)
		w.build(t)

		run := w.emitVSA(t, sourceAssertPolicy(t, true, signingEpochs), w.publishSource(t))
		if run.code != exitOK || !written(run.predicate) {
			t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", run.code, run.stdout, run.stderr)
		}

		if !strings.Contains(run.stdout, "published source verdict for acme/widget@"+relTag+" holds") {
			t.Errorf("stdout = %q, want the published verdict's check", run.stdout)
		}
	})

	t.Run("present with another commit is refused by name", func(t *testing.T) {
		w := newSourceWorld(t)
		w.build(t)

		env := w.publishSource(t)

		// The release's own provenance names another commit than the
		// one the published verdict binds.
		other := strings.Repeat("f", 40)
		prov := w.bv.byRaw[`{"prepared": "provenance"}`]
		prov.stmt = bytes.ReplaceAll(prov.stmt, []byte(w.commit), []byte(other))

		run := w.emitVSA(t, sourceAssertPolicy(t, true, signingEpochs), env)
		want := "the published source verdict binds " + relTag + " to commit " + w.commit +
			", but the release was built from " + other
		if run.code != exitRefused || !strings.Contains(run.stderr, want) {
			t.Fatalf("Run = %d, stderr %q — want %q", run.code, run.stderr, want)
		}

		if written(run.predicate) {
			t.Error("the release predicate was written beside a source verdict for another commit")
		}
	})

	t.Run("not owed and absent writes the same bytes as before", notOwedIsUnchanged)
}

// notOwedIsUnchanged: with no assert policy, and with one that owes
// no source verdict, the release predicate is the golden bytes.
func notOwedIsUnchanged(t *testing.T) {
	w := newSourceWorld(t)
	w.build(t)

	want, err := os.ReadFile(goldenPredicate) //nolint:gosec // G304: a fixed path under testdata
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		assertPol string
		extra     []string
	}{
		{assertPol: ""},
		{assertPol: sourceAssertPolicy(t, false, signingEpochs)},
		// Declared, but this release's machinery predates the epoch.
		{assertPol: sourceAssertPolicy(t, true, signingEpochs), extra: []string{"--machinery-version", "1.0.0"}},
	}

	for _, c := range cases {
		assertPol := c.assertPol

		run := w.emitVSA(t, assertPol, "", c.extra...)
		if run.code != exitOK {
			t.Fatalf("Run = %d, stderr %q", run.code, run.stderr)
		}

		got, rerr := os.ReadFile(run.predicate)
		if rerr != nil {
			t.Fatal(rerr)
		}

		if !bytes.Equal(got, want) {
			t.Fatalf("predicate (assert policy %q) drifted from %s:\n%s", assertPol, goldenPredicate, got)
		}
	}
}

// TestEmitVSASourceVerdictRefusals: the guards around the published
// envelope, each by name.
func TestEmitVSASourceVerdictRefusals(t *testing.T) {
	notOwed := func(t *testing.T) string {
		t.Helper()

		return sourceAssertPolicy(t, false, signingEpochs)
	}
	owed := func(t *testing.T) string {
		t.Helper()

		return sourceAssertPolicy(t, true, signingEpochs)
	}

	garbage := filepath.Join(t.TempDir(), "garbage.json")
	if err := os.WriteFile(garbage, []byte(`{"not": "an envelope"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		policy        func(t *testing.T) string
		sourceVerdict string
		extra         []string
		code          int
		want          string
	}{
		{
			"an envelope nobody owes", notOwed, garbage, nil, exitUsage,
			"--source-verdict was given, but this release owes no source verdict: the assert policy declares no " +
				"evidence.sourceVerdictFromVersion",
		},
		{
			"an envelope for machinery before the epoch", owed, garbage,
			[]string{"--machinery-version", "1.0.0"},
			exitUsage, "this release owes no source verdict: machinery 1.0.0 predates",
		},
		{
			"owed without a machinery version", owed, garbage,
			[]string{"--machinery-version", ""},
			exitUsage,
			"--machinery-version is required",
		},
		{
			"an envelope with no assert policy", nil, garbage, nil, exitUsage,
			"--source-verdict needs --assert-policy",
		},
		{"an unreadable envelope", owed, "/nonexistent/source.json", nil, exitUsage, "--source-verdict:"},
		{
			"an envelope that does not verify", owed, garbage, nil, exitRefused,
			"the published source verdict does not verify",
		},
		{"owed without a clone", owed, garbage, []string{"--git-dir", ""}, exitUsage, "--git-dir is required"},
		{
			"an unreadable assert policy", nil, "",
			[]string{"--assert-policy", "/nonexistent"},
			exitUsage,
			"assert policy:",
		},
		{
			"the clone cannot be opened", owed, garbage,
			[]string{"--git-dir", "/nonexistent"},
			exitRefused,
			"emit: published source verdict:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newSourceWorld(t)
			w.build(t)

			assertPol := ""
			if tt.policy != nil {
				assertPol = tt.policy(t)
			}

			run := w.emitVSA(t, assertPol, tt.sourceVerdict, tt.extra...)
			if run.code != tt.code || !strings.Contains(run.stderr, tt.want) {
				t.Fatalf("Run = %d, stderr %q — want %d and %q", run.code, run.stderr, tt.code, tt.want)
			}
		})
	}
}

// TestEmitVSAOwedUnderASourcelessVerifyPolicy: owed, but the verify
// policy names no source resource to read the verdict against.
func TestEmitVSAOwedUnderASourcelessVerifyPolicy(t *testing.T) {
	w := newSourceWorld(t)
	w.build(t)

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

	run := w.emitVSA(t, sourceAssertPolicy(t, true, signingEpochs), "x", "--policy", sourceless)
	if run.code != exitUsage || !strings.Contains(run.stderr, "declares no source section") {
		t.Fatalf("Run = %d, stderr %q", run.code, run.stderr)
	}
}

// TestEmitVSASourceOutIsGone (stele#468): `emit vsa` writes no source
// verdict, so its old output flag is refused as unknown and its help
// no longer lists it.
func TestEmitVSASourceOutIsGone(t *testing.T) {
	w := newSourceWorld(t)
	w.build(t)

	run := w.emitVSA(t, "", "", "--source-out", "x")
	if run.code != exitUsage || !strings.Contains(run.stderr, "flag provided but not defined: -source-out") {
		t.Fatalf("Run = %d, stderr %q", run.code, run.stderr)
	}

	help := runCLI([]string{"emit", "vsa", "-h"}, sourceRun{})
	if help.code != exitUsage || strings.Contains(help.stderr, "source-out") ||
		!strings.Contains(help.stderr, "-source-verdict") {
		t.Fatalf("emit vsa -h = %d:\n%s", help.code, help.stderr)
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

	env, err := os.ReadFile(w.publishSource(t))
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
	w.build(t)

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
	w.build(t)

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
	w.build(t)

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
	w.build(t)

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

// emitSourcePinned runs `emit source-vsa` with the policy pin given by
// the caller — pin replaces the explicit --machinery-digest and
// --policy-uri the other helper passes — over a policy file whose own
// directory is the policy tree.
func (w *sourceWorld) emitSourcePinned(t *testing.T, pin func(tree string) []string, extra ...string) sourceRun {
	t.Helper()

	px := files(t)
	run := sourceRun{source: filepath.Join(t.TempDir(), "source.json")}

	args := append([]string{
		"emit", "source-vsa",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", relTag,
		"--assert-policy", sourceAssertPolicy(t, true, signingEpochs), "--git-dir", w.repo.Dir,
		"--out", run.source, "--machinery-version", srcMachinery,
	}, pin(filepath.Dir(px.policy))...)

	return runCLI(append(args, extra...), run)
}

// TestEmitSourceVSAResolvesThePolicyRef (stele#472): --policy-ref,
// resolved through the same code `emit vsa` runs, yields byte for byte
// the envelope the explicit --machinery-digest and --policy-uri for
// that commit yield.
func TestEmitSourceVSAResolvesThePolicyRef(t *testing.T) {
	w := newSourceWorld(t)
	w.build(t)

	sha := strings.Repeat("b", 40)
	swapResolveCommit(t, sha, true, nil)

	byRef := w.emitSourcePinned(t, func(tree string) []string {
		return []string{"--policy-ref", "v1.69.4", "--policy-repo", "acme/canon", "--policy-tree", tree}
	})
	if byRef.code != exitOK {
		t.Fatalf("by ref: Run = %d, stderr %q", byRef.code, byRef.stderr)
	}

	explicit := w.emitSourcePinned(t, func(string) []string {
		return []string{
			"--machinery-digest", sha,
			"--policy-uri", "https://github.com/acme/canon/blob/" + sha + "/policy.json",
		}
	})
	if explicit.code != exitOK {
		t.Fatalf("explicit: Run = %d, stderr %q", explicit.code, explicit.stderr)
	}

	got, err := os.ReadFile(byRef.source)
	if err != nil {
		t.Fatal(err)
	}

	want, err := os.ReadFile(explicit.source)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("the envelope by ref differs from the explicit one:\n by ref: %s\nexplicit: %s", got, want)
	}

	if !strings.Contains(byRef.stdout, "emit: policy ref v1.69.4 is commit "+sha) {
		t.Errorf("stdout = %q, want the resolution stated", byRef.stdout)
	}
}

// TestEmitSourceVSAPolicyRefRefusals: the pin's guards, each by name,
// the same as on `emit vsa`.
func TestEmitSourceVSAPolicyRefRefusals(t *testing.T) {
	sha := strings.Repeat("b", 40)

	tests := []struct {
		name    string
		pin     func(tree string) []string
		resolve func(t *testing.T)
		code    int
		want    string
	}{
		{
			"a ref beside an explicit digest", func(tree string) []string {
				return []string{
					"--policy-ref", "v1.69.4", "--policy-repo", "acme/canon", "--policy-tree", tree,
					"--machinery-digest", sha,
				}
			}, nil, exitUsage,
			"--policy-ref resolves the machinery digest and the policy URI — --machinery-digest and --policy-uri",
		},
		{"a ref with no repository", func(tree string) []string {
			return []string{"--policy-ref", "v1.69.4", "--policy-tree", tree}
		}, nil, exitUsage, "--policy-ref needs --policy-repo owner/repo"},
		{"a ref with no tree", func(string) []string {
			return []string{"--policy-ref", "v1.69.4", "--policy-repo", "acme/canon"}
		}, nil, exitUsage, "--policy-tree is required"},
		{"a ref the forge does not resolve", func(tree string) []string {
			return []string{"--policy-ref", "v9.9.9", "--policy-repo", "acme/canon", "--policy-tree", tree}
		}, func(t *testing.T) {
			t.Helper()
			swapResolveCommit(t, "", false, nil)
		}, exitRefused, "emit: could not resolve the policy ref v9.9.9 to a commit: acme/canon has no such ref"},
		{"a forge that fails", func(tree string) []string {
			return []string{"--policy-ref", "v1.69.4", "--policy-repo", "acme/canon", "--policy-tree", tree}
		}, func(t *testing.T) {
			t.Helper()
			swapResolveCommit(t, "", false, errors.New("forge down"))
		}, exitRefused, "could not resolve the policy ref v1.69.4 to a commit: forge down"},
		{
			"no pin at all", func(string) []string { return nil }, nil, exitUsage,
			`--machinery-digest "" is not a commit, and no --policy-ref names one`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newSourceWorld(t)
			w.build(t)

			if tt.resolve != nil {
				tt.resolve(t)
			}

			run := w.emitSourcePinned(t, tt.pin)
			if run.code != tt.code || !strings.Contains(run.stderr, tt.want) {
				t.Fatalf("Run = %d, stderr %q — want %d and %q", run.code, run.stderr, tt.code, tt.want)
			}

			if written(run.source) {
				t.Error("a refusal wrote an envelope")
			}
		})
	}
}
