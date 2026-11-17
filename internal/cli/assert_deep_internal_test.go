// The full-depth wiring's own guards: the store adapter's slug shape,
// the trust-authority loader's refusals, and the engine delegation's
// fail-closed validation (the engine itself is proven in
// internal/verify).

package cli

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/verify"
)

func TestForgeStore(t *testing.T) {
	t.Parallel()

	t.Run("a slug that is not owner/repo refuses", func(t *testing.T) {
		t.Parallel()

		if _, err := (forgeStore{forge: &storeForge{}}).Bundles("solo", strings.Repeat("a", 64)); err == nil {
			t.Fatal("Bundles accepted a slug with no owner")
		}
	})

	t.Run("bundles arrive addressed", func(t *testing.T) {
		t.Parallel()

		f := &storeForge{bundles: []jsonx.Raw{jsonx.Raw(`{"a":1}`), jsonx.Raw(`{"b":2}`)}}

		out, err := (forgeStore{forge: f}).Bundles("acme/widget", strings.Repeat("a", 64))
		if err != nil || len(out) != 2 {
			t.Fatalf("Bundles = %d, %v", len(out), err)
		}

		if !strings.HasPrefix(out[0].URI, "store://acme/widget/sha256:") {
			t.Fatalf("URI = %q — the verdict must be able to name its evidence by address", out[0].URI)
		}
	})
}

// noPins is the tag resolver of a test whose walk resolves no pin:
// reaching it is a test defect, said as one.
type noPins struct{}

func (noPins) TagCommit(_, _, _ string) (string, error) {
	return "", errors.New("this test resolves no release pin")
}

func TestLoadFullDepth(t *testing.T) {
	t.Parallel()

	t.Run("an unreadable verify policy refuses", func(t *testing.T) {
		t.Parallel()

		if _, _, err := loadFullDepth("/no/such/verify-policy.json", nil, &storeForge{}, noPins{}, false, nil); err == nil {
			t.Fatal("loadFullDepth accepted a missing verify policy")
		}
	})

	t.Run("a malformed verify policy refuses", func(t *testing.T) {
		t.Parallel()

		p := filepath.Join(t.TempDir(), "vp.json")
		if err := os.WriteFile(p, []byte(`{"schema": 9}`), 0o600); err != nil {
			t.Fatal(err)
		}

		if _, _, err := loadFullDepth(p, nil, &storeForge{}, noPins{}, false, nil); err == nil {
			t.Fatal("loadFullDepth accepted a policy with no trust section")
		}
	})
}

// TestLoadFullDepthHappyPath proves the wiring assembles when the
// trust authority is readable — the crypto seam is swapped, the
// policy is real.
func TestLoadFullDepthHappyPath(t *testing.T) {
	dir := t.TempDir()

	vp := filepath.Join(dir, "vp.json")
	if err := os.WriteFile(vp, []byte(testPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	orig := newBundleVerifier
	newBundleVerifier = func([]byte) (verify.BundleVerifier, error) { return attestorBV{}, nil }

	t.Cleanup(func() { newBundleVerifier = orig })

	full, _, err := loadFullDepth(vp, []byte(`{"any": "bytes"}`), &storeForge{}, noPins{}, false, nil)
	if err != nil {
		t.Fatalf("loadFullDepth = %v", err)
	}

	if _, ok := full.Tags.(noPins); !ok {
		t.Fatalf("Tags = %T, want the resolver the run handed in — pins are read through git", full.Tags)
	}

	if full.MachineryOwner != "acme" || full.MachineryRepo != "canon" {
		t.Fatalf("roots = %s/%s, want the verifier workflow's own repository", full.MachineryOwner, full.MachineryRepo)
	}
}

// passDeep accepts everything — the walk's own branch is under test.
type passDeep struct{}

func (passDeep) Release(verify.Coords, []verify.Subject, verify.SBOMs, verify.Pins, bool) error {
	return nil
}

func (passDeep) VSA(verify.Coords, []verify.Subject, verify.Pins, *verify.EnrichmentDemand) error {
	return nil
}

func (passDeep) SourceVSA(verify.Coords, []byte, verify.Pins) error { return nil }

// deepSnapshot stages the whole --depth full world and returns the
// argument list one Run needs.
func deepSnapshot(t *testing.T, rewrite func(files map[string]string)) []string {
	t.Helper()

	args, _ := deepWorld(t, rewrite)

	return args
}

// deepWorld stages the whole --depth full world: the evidence snapshot
// plus what the deep branch reads — the checksum manifest and the two
// pin trees — with the engine seam scripted to pass. The forge reads
// replay through the forge seam, never --snapshot, which full depth
// refuses: its pins are git objects (stele#384). It returns the
// argument list one Run needs and the snapshot directory. rewrite,
// when set, shapes the fixture files before they are written.
//
//nolint:gocritic // unnamedResult: the arguments, then the snapshot directory
func deepWorld(t *testing.T, rewrite func(files map[string]string)) ([]string, string) {
	t.Helper()

	snap, policyPath := evidenceSnapshotWith(t, rewrite)
	dir := filepath.Dir(snap)

	// Snapshot FileAt stores the path as one escaped segment.
	digest := strings.Repeat("5", 64)
	wfSeg := url.PathEscape(".github/workflows/publish.yml")
	files := map[string]string{
		"acme/widget/releases/v1.0.0/assets/checksums.txt": digest + "  app.tar.gz\n",
		"acme/widget/files/v1.0.0/" + wfSeg: "jobs:\n  publish:\n    uses: acme/canon/.github/workflows/publish.yml@" +
			strings.Repeat("a", 40) + "\n",
		"acme/canon/files/" + strings.Repeat("a", 40) + "/" + wfSeg: "jobs:\n  sign:\n" +
			"    uses: acme/signer/.github/workflows/sign.yml@" + strings.Repeat("b", 40) + "\n",
	}
	for p, c := range files {
		full := filepath.Join(snap, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(full, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	vp := filepath.Join(dir, "vp.json")
	if err := os.WriteFile(vp, []byte(testPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(dir, "root.json")
	if err := os.WriteFile(root, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	origBV, origDeep := newBundleVerifier, newDeepVerifier
	newBundleVerifier = func([]byte) (verify.BundleVerifier, error) { return attestorBV{}, nil }
	newDeepVerifier = func(
		vp *policy.Policy, _ gh.Forge, tags assert.TagResolver, _ verify.BundleVerifier, _ sourceHistories,
	) (*assert.FullDepth, error) {
		return assert.NewFullDepth(passDeep{}, tags, *vp.Trust.Verdict.VerifierWorkflow,
			*vp.Trust.Provenance.SignerWorkflow)
	}

	t.Cleanup(func() { newBundleVerifier, newDeepVerifier = origBV, origDeep })

	swapForgeSnapshot(t, snap)

	return []string{
		"assert", "evidence", "--org", "acme", "--policy", policyPath,
		"--trusted-root", root, "--verify-policy", vp, "--depth", "full",
	}, snap
}

// narrowDeepSnapshot is deepSnapshot with the release's manifest rolled
// back to the pre-class-split schema and the policy giving its class an
// enrichment name — the shape whose class-specific obligation the walk
// must excuse, loudly (stele#206). The schema epoch moves past the
// fixture's machinery version so the old manifest reads as the history
// it is instead of refusing.
func narrowDeepSnapshot(t *testing.T) []string {
	t.Helper()

	classless := `{"schema": 2, "classes": ["oci-image"], "storeVsa": true, "machineryVersion": "9.9.9",` +
		` "entries": [{"name": "app.tar.gz", "sha256": "` + strings.Repeat("5", 64) +
		`", "type": "build-subject"}]}`

	return deepSnapshot(t, func(files map[string]string) {
		files["snap/acme/widget/releases/v1.0.0/assets/evidence-manifest.json"] = classless

		narrowed := strings.Replace(files["policy.json"],
			`"classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}`,
			`"manifestSchemaFromVersion": "10.0.0", `+
				`"classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"], `+
				`"enrichment": ["base-images"]}}`, 1)
		if narrowed == files["policy.json"] {
			t.Fatal("the fixture policy changed shape — the narrowing rewrite matched nothing")
		}

		files["policy.json"] = narrowed
	})
}

// TestAssertEvidenceFullDepth drives the whole CLI at --depth full
// over a replayed forge, with the engine seam scripted to pass — the flag
// path, the trust-authority load and the walk's deep branch in one
// stroke.
func TestAssertEvidenceFullDepth(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := Run(deepSnapshot(t, nil), &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	if !strings.Contains(stderr.String()+stdout.String(), "full depth") {
		t.Fatalf("output names no deep leg:\n%s%s", stdout.String(), stderr.String())
	}
}

// TestAssertEvidenceExcusalIsWritten holds the excusal to the output
// contract every other line of this walk keeps (stele#206): it is
// STATED, and it is stated through the stream whose failure the verb
// reports. A narrowing written down a side channel would survive a
// failing writer, which is exactly how a silent excusal gets built by
// accident.
func TestAssertEvidenceExcusalIsWritten(t *testing.T) {
	t.Run("the narrowing is stated, naming the artifact and what it excused", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		code := Run(narrowDeepSnapshot(t), &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}

		want := "app.tar.gz: class unknowable under schema 2 — excused: base-images"
		if got := stdout.String() + stderr.String(); !strings.Contains(got, want) {
			t.Fatalf("output does not state the narrowing:\n%s\nwant substring %q", got, want)
		}
	})

	t.Run("a writer that fails while stating it fails the run", func(t *testing.T) {
		var stderr bytes.Buffer

		if code := Run(narrowDeepSnapshot(t), failWriterI{}, &stderr); code != exitIO {
			t.Fatalf("Run = %d, want %d — the excusal must ride the reported stream", code, exitIO)
		}
	})
}

// TestEngineVerifierFailsClosed pins the delegation: the engine's own
// input validation refuses before any network or crypto, so an empty
// subject list can never verify.
func TestEngineVerifierFailsClosed(t *testing.T) {
	t.Parallel()

	vp, err := policy.Load(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}

	ev := &engineVerifier{vp: vp, store: forgeStore{forge: &storeForge{}}, bv: attestorBV{}}
	c := verify.Coords{Owner: "acme", Repo: "widget", Tag: "v1.0.0"}
	pins := verify.Pins{Machinery: strings.Repeat("a", 40), Signer: strings.Repeat("b", 40)}

	if rerr := ev.Release(c, nil, verify.SBOMs{}, pins, true); rerr == nil {
		t.Fatal("Release verified an empty subject list")
	}

	if verr := ev.VSA(c, nil, pins, &verify.EnrichmentDemand{}); verr == nil {
		t.Fatal("VSA verified an empty subject list")
	}

	if verr := ev.VSA(c, nil, pins, nil); verr == nil {
		t.Fatal("verdict-only VSA verified an empty subject list")
	}

	if perr := ev.Release(c, nil, verify.SBOMs{}, pins, false); perr == nil {
		t.Fatal("provenance-only Release verified an empty subject list")
	}
}

// storeThrottle is the deep world's forge with ONE store read routed to
// a live client: the read for digest goes over HTTP to a server that
// refuses it the way GitHub does, and every other read replays the
// snapshot. The live client is internal/gh's own, so the throttle is
// classified exactly as it is in a real run (stele#339).
//
// The snapshot is embedded by its concrete type, so the population
// still enumerates through the snapshot's own lister.
type storeThrottle struct {
	gh.Snapshot

	store  *gh.Client
	digest string
}

func (f storeThrottle) Attestations(owner, repo, sha256Hex string) ([]jsonx.Raw, error) {
	if sha256Hex == f.digest {
		return f.store.Attestations(owner, repo, sha256Hex)
	}

	return f.Snapshot.Attestations(owner, repo, sha256Hex)
}

// primaryLimitResponse is the primary-limit refusal in the shape
// GitHub's REST rate-limit page documents
// (https://docs.github.com/rest/using-the-rest-api/rate-limits-for-the-rest-api,
// read 2026-11-15): a 403 with the five x-ratelimit-* headers, remaining
// at 0. The page shows no body; this one is the message GitHub's
// earlier REST overview printed, and it carries no marker.
func primaryLimitResponse(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Ratelimit-Limit", "60")
	h.Set("X-Ratelimit-Remaining", "0")
	h.Set("X-Ratelimit-Used", "60")
	h.Set("X-Ratelimit-Reset", "1377013266")
	h.Set("X-Ratelimit-Resource", "core")
	w.WriteHeader(http.StatusForbidden)
	//nolint:errcheck,gosec // test server write
	w.Write([]byte(`{"message":"API rate limit exceeded for xxx.xxx.xxx.xxx. (But here's the good news:` +
		` Authenticated requests get a higher rate limit. Check out the documentation for more details.)",` +
		`"documentation_url":"https://docs.github.com/rest/overview/rate-limits-for-the-rest-api"}`))
}

// TestAssertEvidenceThrottledBaseApproval is stele#339's measurement
// at the command surface: `assert evidence --depth full` over a world
// whose store throttles on the base-approval read — or whose transient
// ladder runs out on it — seals CANNOT_JUDGE,
// and no finding is recorded against the pinned base — the walk did
// not see it. The one line the refusal carries is the run's own
// sentence about itself, against the population scope, the shape
// every walk-incomplete run of this verb already has.
func TestAssertEvidenceThrottledBaseApproval(t *testing.T) {
	for _, tc := range []struct {
		name    string
		respond http.HandlerFunc
		says    string
	}{
		{name: "the primary rate limit", respond: primaryLimitResponse, says: "throttled this walk"},
		{name: "a 503 past the ladder", respond: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}, says: "HTTP 503"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blindBaseApproval(t, tc.respond, tc.says)
		})
	}
}

// blindBaseApproval runs the deep world with the base-approval store
// read answered by respond, and holds the run to CANNOT_JUDGE with no
// finding against the base and a refusal that says what happened.
func blindBaseApproval(t *testing.T, respond http.HandlerFunc, says string) {
	t.Helper()

	baseHex := strings.Repeat("8", 64)
	ref := "docker.io/library/debian:trixie@sha256:" + baseHex

	args, snap := deepWorld(t, func(files map[string]string) {
		scoped := strings.Replace(files["policy.json"],
			`"classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}}}`,
			`"classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}, `+
				`"baseImages": {"scopes": [{"name": "pgrx-bases", "mechanism": "pin-file", `+
				`"pinFile": "docker/base-images.toml", "attestorRepo": ".github", `+
				`"attestorIdentity": "https://github.com/acme/.github/.github/workflows/base-attest.yml@refs/heads/main", `+
				`"predicateType": "https://acme.example/attestations/base-image-approval/v1"}]}}}`, 1)
		scoped = strings.Replace(scoped, `{"schema": 9, `,
			`{"schema": 9, "issuer": "https://token.actions.githubusercontent.com", `, 1)

		if scoped == files["policy.json"] {
			t.Fatal("the fixture policy changed shape — the base-scope rewrite matched nothing")
		}

		files["policy.json"] = scoped
	})

	// The forge replays through the seam, so the one store read can be
	// routed live.
	pins := filepath.Join(t.TempDir(), "base-images.toml")
	if err := os.WriteFile(pins, []byte("images = [\n  \""+ref+"\",\n]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	args = append(args, "--base-pins", "pgrx-bases="+pins, "--json")

	var reads atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/repos/acme/.github/attestations/sha256:"+baseHex) {
			t.Errorf("the live store was asked for %s, want only the base-approval read", r.URL.Path)
		}

		reads.Add(1)
		respond(w, r)
	}))
	t.Cleanup(srv.Close)

	live := gh.New("")
	live.HTTP = srv.Client()
	live.Base = srv.URL
	live.Sleep = func(time.Duration) {}

	orig := newForge
	newForge = func() gh.Forge {
		return storeThrottle{Dir: snap, store: live, digest: baseHex}
	}

	t.Cleanup(func() { newForge = orig })

	var stdout, stderr bytes.Buffer

	code := Run(args, &stdout, &stderr)
	if code != exitBlind {
		t.Fatalf("Run = %d, want %d (CANNOT_JUDGE)\nstdout: %s\nstderr: %s",
			code, exitBlind, stdout.String(), stderr.String())
	}

	if reads.Load() == 0 {
		t.Fatalf("the base-approval read never reached the store — the row proves nothing\nstdout: %s\nstderr: %s",
			stdout.String(), stderr.String())
	}

	doc := stdout.String()
	if !strings.Contains(doc, `"CANNOT_JUDGE"`) {
		t.Fatalf("report is not CANNOT_JUDGE:\n%s", doc)
	}

	// No finding names the base the run never saw.
	if strings.Contains(doc, `"subject": "`+ref) || strings.Contains(doc, `"subject":"`+ref) {
		t.Fatalf("the report records a finding against %s, which the run never saw:\n%s", ref, doc)
	}

	if !strings.Contains(stderr.String()+doc, says) {
		t.Fatalf("the refusal does not say %q:\nstdout: %s\nstderr: %s", says, doc, stderr.String())
	}
}
