// The enrichment table: every way a declared obligation can go
// unmet. The world is one published release carrying a verdict and a
// valid enrichment claim beside it; each row breaks exactly one fact
// and asserts the refusal names it.

package verify_test

import (
	"maps"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/verify"
)

const (
	enrichType = "https://acme.example/attestations/build-enrichment/v1"
	builtFrom  = "1111111111111111111111111111111111111111"
)

// enrichPolicy is the base policy with the obligation declared —
// spliced into the one policy const rather than copied beside it, so
// the two cannot drift apart.
func enrichPolicy(t *testing.T) *policy.Policy {
	t.Helper()

	const declared = `"denySelfHostedRunners": true,
    "enrichment": {
      "predicateType": "` + enrichType + `",
      "required": ["toolbelt-lock"],
      "permitted": ["Cargo.lock", "base-images"]
    }`

	spliced := strings.Replace(policyJSON, `"denySelfHostedRunners": true`, declared, 1)

	p, err := policy.Load(strings.NewReader(spliced))
	if err != nil {
		t.Fatalf("policy.Load = %v", err)
	}

	return p
}

// enrichWorld is one mutable, fully valid release: a verdict and the
// enrichment claim beside it, over one subject.
type enrichWorld struct {
	appSHA   string
	subjects []verify.Subject
	vsaStmt  map[string]any
	claim    map[string]any
	// claimPeek, when set, is what selection sees INSTEAD of claim —
	// the divergence a hostile store could stage between the bytes
	// that get chosen and the bytes that get signed.
	claimPeek map[string]any
	// otherRevision, when set, is the commit the SECOND subject's
	// claim names — the fold's disagreement case.
	otherRevision string
	// broken stages a bundle the store holds but nothing can open.
	broken bool
	// claimSAN, when set, is the identity the enrichment claim is
	// signed under instead of the verdict identity.
	claimSAN string
	pin      string
	copies   int
	policy   *policy.Policy
}

func newEnrichWorld(t *testing.T) *enrichWorld {
	t.Helper()

	appSHA := digestHex([]byte("app bytes"))
	w := &enrichWorld{
		appSHA:   appSHA,
		subjects: []verify.Subject{{Name: "app.tar.gz", SHA256: appSHA}},
		pin:      machineryPin,
		copies:   1,
		policy:   enrichPolicy(t),
	}

	w.vsaStmt = newVSAWorld().stmt
	w.claim = enrichStatement(appSHA, builtFrom)

	return w
}

// enrichStatement is one valid enrichment statement over a subject.
func enrichStatement(appSHA, revision string) map[string]any {
	return map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []any{
			map[string]any{"name": "app.tar.gz", "digest": map[string]any{"sha256": appSHA}},
		},
		"predicateType": enrichType,
		"predicate": map[string]any{
			"resourceUri": "pkg:github/acme/widget@v1.2.3",
			"sourceRevision": map[string]any{
				"uri":    "https://github.com/acme/widget",
				"digest": map[string]any{"gitCommit": revision},
			},
			"policy": map[string]any{
				"uri":    "https://github.com/acme/canon/blob/abc/slsa/verify-policy.json",
				"digest": map[string]any{"sha256": digestHex([]byte("the policy tree"))},
			},
			"resolvedDependencies": []any{
				map[string]any{
					"name":   "toolbelt-lock",
					"uri":    "https://github.com/acme/canon/blob/abc/mise/mise.lock",
					"digest": map[string]any{"sha256": digestHex([]byte("the lock"))},
				},
			},
		},
	}
}

// pred reaches the claim's predicate object for surgery.
func (w *enrichWorld) pred() map[string]any { return asMap(w.claim["predicate"]) }

// deps reaches the claim's resolved dependency list.
func (w *enrichWorld) deps() []any { return asList(w.pred()["resolvedDependencies"]) }

func (w *enrichWorld) run(t *testing.T) (*verify.VSAVerdict, error) {
	t.Helper()

	return verify.VSA(w.policy, coords, w.subjects, pins, w.store(t), fakeBV{}, discardLog)
}

// runVerdictOnly is the corpus entry point: the same world judged by
// the verdict half alone.
func (w *enrichWorld) runVerdictOnly(t *testing.T) (*verify.VSAVerdict, error) {
	t.Helper()

	return verify.VSAVerdictOnly(w.policy, coords, w.subjects, pins, w.store(t), fakeBV{}, discardLog)
}

func (w *enrichWorld) store(t *testing.T) fakeStore {
	t.Helper()

	san := "https://github.com/" + verifierWF + "@" + machineryPin

	held := map[string][]verify.StoredBundle{}
	for _, s := range w.subjects {
		held[s.SHA256] = w.bundlesFor(t, s.SHA256, san)
	}

	return fakeStore{bundles: held}
}

// bundlesFor stages one subject's store: the verdict, then however
// many copies of the enrichment claim the row asked for.
func (w *enrichWorld) bundlesFor(t *testing.T, sha, san string) []verify.StoredBundle {
	t.Helper()

	vsaStmt, claim, peek := w.vsaStmt, w.claim, w.claimPeek

	// Subjects beyond the first carry their own digest through both
	// statements, so a multi-subject row stages a coherent release —
	// or, when otherRevision is set, a release whose claims disagree.
	if sha != w.appSHA {
		vsaStmt = retarget(vsaStmt, sha)

		revision := builtFrom
		if w.otherRevision != "" {
			revision = w.otherRevision
		}

		claim = retarget(enrichStatement(w.appSHA, revision), sha)
		peek = nil
	}

	var peekJSON []byte
	if peek != nil {
		peekJSON = mustJSON(t, peek)
	}

	out := []verify.StoredBundle{{
		URI: "https://store.example/vsa",
		Bundle: (&fakeBundle{
			Stmt: mustJSON(t, vsaStmt), SAN: san, Issuer: issuer,
			Digests: []string{sha}, Ext: certificate.Extensions{BuildSignerDigest: machineryPin},
		}).bytes(t),
	}}

	claimSAN := san
	if w.claimSAN != "" {
		claimSAN = w.claimSAN
	}

	enrichBundle := (&fakeBundle{
		Stmt: mustJSON(t, claim), PeekStmt: peekJSON, SAN: claimSAN, Issuer: issuer,
		Digests: []string{sha}, Ext: certificate.Extensions{BuildSignerDigest: w.pin},
		Broken: w.broken,
	}).bytes(t)

	for range w.copies {
		out = append(out, verify.StoredBundle{URI: "https://store.example/enrichment", Bundle: enrichBundle})
	}

	return out
}

// retarget rewrites a statement's single subject digest.
func retarget(stmt map[string]any, sha string) map[string]any {
	out := maps.Clone(stmt)

	out["subject"] = []any{
		map[string]any{"name": "other.tar.gz", "digest": map[string]any{"sha256": sha}},
	}

	return out
}

// TestEnrichmentVerifies is the clean pass: the obligation is met and
// the verdict gains a source revision a bare VSA never carries.
func TestEnrichmentVerifies(t *testing.T) {
	t.Parallel()

	verdict, err := newEnrichWorld(t).run(t)
	if err != nil {
		t.Fatalf("VSA = %v", err)
	}

	if got := verdict.SourceRevision(); got != builtFrom {
		t.Errorf("SourceRevision = %q, want the commit the enrichment claims (%s)", got, builtFrom)
	}
}

// TestEnrichmentUndeclared pins the declared-obligation half: with no
// section the leg does not run, no claim is demanded, and the verdict
// honestly reports no revision.
func TestEnrichmentUndeclared(t *testing.T) {
	t.Parallel()

	w := newEnrichWorld(t)
	w.policy = loadPolicy(t)
	w.copies = 0

	verdict, err := w.run(t)
	if err != nil {
		t.Fatalf("VSA = %v — an undeclared obligation must demand nothing", err)
	}

	if got := verdict.SourceRevision(); got != "" {
		t.Errorf("SourceRevision = %q, want empty: a verdict alone does not carry it", got)
	}
}

func TestEnrichmentRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		spoil func(w *enrichWorld)
		want  string
	}{
		{
			name:  "no claim at all leaves the obligation unmet",
			spoil: func(w *enrichWorld) { w.copies = 0 },
			want:  "no enrichment claim covers this subject",
		},
		{
			name:  "two claims are two answers",
			spoil: func(w *enrichWorld) { w.copies = 2 },
			want:  "two claims are two answers",
		},
		{
			name:  "a claim signed from an unpinned tree",
			spoil: func(w *enrichWorld) { w.pin = strings.Repeat("f", 40) },
			want:  "enrichment signed at",
		},
		{
			name:  "a claim about another resource",
			spoil: func(w *enrichWorld) { w.pred()["resourceUri"] = "pkg:github/acme/other@v9" },
			want:  "names resource",
		},
		{
			name: "a claim bound to another repository",
			spoil: func(w *enrichWorld) {
				asMap(w.pred()["sourceRevision"])["uri"] = "https://github.com/acme/fork"
			},
			want: "binds to source repository",
		},
		{
			name:  "a claim resolving nothing",
			spoil: func(w *enrichWorld) { w.pred()["resolvedDependencies"] = []any{} },
			want:  "resolving nothing claims nothing",
		},
		{
			name:  "a claim unbound to any commit",
			spoil: func(w *enrichWorld) { delete(w.pred(), "sourceRevision") },
			want:  "facts unbound to a commit",
		},
		{
			name:  "a claim naming no policy tree",
			spoil: func(w *enrichWorld) { delete(w.pred(), "policy") },
			want:  "unauditable",
		},
		{
			name: "a dependency outside the closed set",
			spoil: func(w *enrichWorld) {
				asMap(w.deps()[0])["name"] = "something-nobody-declared"
			},
			want: "neither requires nor permits",
		},
		{
			name: "a permitted name is not a required one",
			spoil: func(w *enrichWorld) {
				asMap(w.deps()[0])["name"] = "Cargo.lock"
			},
			want: `claims no "toolbelt-lock"`,
		},
		{
			name: "a dependency nobody can fetch",
			spoil: func(w *enrichWorld) {
				delete(asMap(w.deps()[0]), "uri")
			},
			want: "not evidence",
		},
		{
			name: "a dependency digest that is not a digest",
			spoil: func(w *enrichWorld) {
				asMap(asMap(w.deps()[0])["digest"])["sha256"] = "nothex"
			},
			want: "not 64 lowercase hex",
		},
		{
			name:  "a bundle the store holds but nothing can open",
			spoil: func(w *enrichWorld) { w.broken = true },
			want:  "unreadable bundle in the store",
		},
		{
			name: "a claim signed by somebody other than the verifier",
			spoil: func(w *enrichWorld) {
				w.claimSAN = "https://github.com/acme/impostor/.github/workflows/sign.yml@" + machineryPin
			},
			want: "enrichment bundle refused",
		},
		{
			name:  "a claim that is not an in-toto statement",
			spoil: func(w *enrichWorld) { delete(w.claim, "_type") },
			want:  "_type is absent",
		},
		{
			name:  "a claim whose predicate is not an enrichment predicate",
			spoil: func(w *enrichWorld) { w.claim["predicate"] = "a bare string" },
			want:  "enrichment predicate",
		},
		{
			name: "the verified payload is not the claim the peek promised",
			spoil: func(w *enrichWorld) {
				w.claimPeek = enrichStatement(w.appSHA, builtFrom)
				w.claim["predicateType"] = "https://acme.example/attestations/something-else/v1"
			},
			want: "not an enrichment claim",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newEnrichWorld(t)
			tc.spoil(w)

			verdict, err := w.run(t)
			if err == nil {
				t.Fatalf("VSA = %+v, want refusal", verdict)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("VSA error = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestEnrichmentRevisionFold pins the fold: one release was built
// from one commit, so subjects whose claims agree collapse to it and
// subjects whose claims disagree refuse — never whichever subject the
// loop happened to end on.
func TestEnrichmentRevisionFold(t *testing.T) {
	t.Parallel()

	other := digestHex([]byte("other bytes"))
	second := verify.Subject{Name: "other.tar.gz", SHA256: other}

	t.Run("agreement collapses to the one commit", func(t *testing.T) {
		t.Parallel()

		w := newEnrichWorld(t)
		w.subjects = append(w.subjects, second)

		verdict, err := w.run(t)
		if err != nil {
			t.Fatalf("VSA = %v — two subjects claiming one commit must pass", err)
		}

		if verdict.SourceRevision() != builtFrom {
			t.Fatalf("SourceRevision = %q, want %s", verdict.SourceRevision(), builtFrom)
		}
	})

	t.Run("disagreement refuses", func(t *testing.T) {
		t.Parallel()

		w := newEnrichWorld(t)
		w.subjects = append(w.subjects, second)
		w.otherRevision = strings.Repeat("2", 40)

		verdict, err := w.run(t)
		if err == nil {
			t.Fatalf("VSA = %+v, want refusal", verdict)
		}

		if !strings.Contains(err.Error(), "one release was built from one commit") {
			t.Fatalf("VSA error = %v", err)
		}
	})
}

// TestVSAVerdictOnly is the epoch's engine half: a release predating
// the enrichment mechanism is judged on its verdict alone, even
// though the policy declares the obligation in full. Which releases
// those are is the walk's question, answered from the machinery
// version it already derives — never guessed here, and never a
// try-each over whether a claim happens to be present.
func TestVSAVerdictOnly(t *testing.T) {
	t.Parallel()

	t.Run("a declared obligation is left unasked", func(t *testing.T) {
		t.Parallel()

		w := newEnrichWorld(t)
		w.copies = 0 // nothing to find, and nothing looked for

		verdict, err := w.runVerdictOnly(t)
		if err != nil {
			t.Fatalf("VSAVerdictOnly = %v — the corpus half must not demand a claim", err)
		}

		if got := verdict.SourceRevision(); got != "" {
			t.Errorf("SourceRevision = %q, want empty: no enrichment was read", got)
		}

		// The same world through the whole entry point refuses, which
		// is what makes the two entry points different obligations
		// rather than two spellings of one.
		if _, werr := w.run(t); werr == nil {
			t.Fatal("VSA accepted a release with no enrichment claim while the policy declares one")
		}
	})

	t.Run("a claim present but broken is still not judged", func(t *testing.T) {
		t.Parallel()

		// Withholding the obligation withholds it whole: a corpus
		// release carrying a malformed claim is not quietly held to
		// a standard the walk decided it does not owe.
		w := newEnrichWorld(t)
		w.pred()["resolvedDependencies"] = []any{}

		if _, err := w.runVerdictOnly(t); err != nil {
			t.Fatalf("VSAVerdictOnly = %v — the claim was not this release's obligation", err)
		}

		if _, err := w.run(t); err == nil {
			t.Fatal("VSA accepted an enrichment resolving nothing")
		}
	})
}
