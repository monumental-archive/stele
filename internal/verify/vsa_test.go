package verify_test

import (
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/monumental-archive/stele/internal/verify"
)

// vsaWorld is one mutable, fully valid published verdict.
type vsaWorld struct {
	appSHA   string
	subjects []verify.Subject
	stmt     map[string]any
	san      string
	pin      string
	peek     []byte
	store    fakeStore
}

func newVSAWorld() *vsaWorld {
	appSHA := digestHex([]byte("app bytes"))

	w := &vsaWorld{
		appSHA:   appSHA,
		subjects: []verify.Subject{{Name: "app.tar.gz", SHA256: appSHA}},
		san:      "https://github.com/" + verifierWF + "@" + canonPin,
		pin:      canonPin,
	}

	w.stmt = map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []any{
			map[string]any{"name": "app.tar.gz", "digest": map[string]any{"sha256": appSHA}},
		},
		"predicateType": "https://slsa.dev/verification_summary/v1",
		"predicate": map[string]any{
			"verifier":           map[string]any{"id": "https://github.com/" + verifierWF},
			"timeVerified":       "2026-08-01T00:00:00Z",
			"resourceUri":        "pkg:github/acme/widget@v1.2.3",
			"policy":             map[string]any{"uri": "https://github.com/acme/canon/tree/v1.0.0"},
			"verificationResult": "PASSED",
			"verifiedLevels":     []any{"SLSA_BUILD_LEVEL_3"},
			"slsaVersion":        "1.2",
		},
	}

	return w
}

func (w *vsaWorld) run(t *testing.T) (*verify.VSAVerdict, error) {
	t.Helper()

	bundle := (&fakeBundle{
		Stmt: mustJSON(t, w.stmt), PeekStmt: w.peek,
		SAN: w.san, Issuer: issuer, Digests: []string{w.appSHA},
		Ext: certificate.Extensions{BuildSignerDigest: w.pin},
	}).bytes(t)
	w.store = fakeStore{bundles: map[string][]verify.StoredBundle{
		w.appSHA: {{URI: "https://store.example/vsa", Bundle: bundle}},
	}}

	return verify.VSA(loadPolicy(t), coords, w.subjects, pins, w.store, fakeBV{}, discardLog)
}

func TestVSA(t *testing.T) {
	t.Parallel()

	w := newVSAWorld()

	verdict, err := w.run(t)
	if err != nil {
		t.Fatalf("VSA = %v", err)
	}

	if got := verdict.Levels(); len(got) != 1 || got[0] != "SLSA_BUILD_LEVEL_3" {
		t.Errorf("Levels = %v, want [SLSA_BUILD_LEVEL_3]", got)
	}
}

// TestVSALegacyRoot pins the enumerated exception path: a release
// the policy grandfathers verifies under its NAMED legacy signer,
// and only under it — the current root refuses that bundle.
func TestVSALegacyRoot(t *testing.T) {
	t.Parallel()

	legacy := verify.Coords{Owner: "acme", Repo: "relic", Tag: "v0.1.0"}

	w := newVSAWorld()
	// Signed by the legacy signer, but claiming the org verifier as
	// verifier.id — the real shape of the grandfathered epoch (the
	// signer signed on the verifier's behalf and the predicate named
	// the verifier throughout; proven on .github v1.13.0 and
	// release-lab v0.20.1 in shadow).
	w.san = "https://github.com/" + signerWF + "@" + signerPin
	dig(w.stmt, "predicate")["resourceUri"] = "pkg:github/acme/relic@v0.1.0"

	bundle := (&fakeBundle{
		Stmt: mustJSON(t, w.stmt), SAN: w.san, Issuer: issuer, Digests: []string{w.appSHA},
		Ext: certificate.Extensions{BuildSignerDigest: signerPin},
	}).bytes(t)
	store := fakeStore{bundles: map[string][]verify.StoredBundle{
		w.appSHA: {{URI: "u", Bundle: bundle}},
	}}

	if _, err := verify.VSA(loadPolicy(t), legacy, w.subjects, pins, store, fakeBV{}, discardLog); err != nil {
		t.Errorf("VSA under the enumerated legacy root = %v, want acceptance", err)
	}

	// The same bundle for a NON-enumerated release must refuse: a
	// try-each fallback would have accepted it.
	other := verify.Coords{Owner: "acme", Repo: "relic", Tag: "v0.2.0"}
	dig(w.stmt, "predicate")["resourceUri"] = "pkg:github/acme/relic@v0.2.0"
	bundle = (&fakeBundle{
		Stmt: mustJSON(t, w.stmt), SAN: w.san, Issuer: issuer, Digests: []string{w.appSHA},
		Ext: certificate.Extensions{BuildSignerDigest: signerPin},
	}).bytes(t)
	store.bundles[w.appSHA] = []verify.StoredBundle{{URI: "u", Bundle: bundle}}

	if _, err := verify.VSA(loadPolicy(t), other, w.subjects, pins, store, fakeBV{}, discardLog); err == nil {
		t.Error("VSA accepted a legacy-signed verdict for a release the policy does not enumerate")
	}
}

func TestVSARefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(w *vsaWorld)
		want   string
	}{
		{
			"verdict signed under another identity",
			func(w *vsaWorld) { w.san = "https://github.com/mallory/canon/v.yml@" + canonPin },
			"verdict bundle refused",
		},
		{
			"verifier.id is not the signing identity",
			func(w *vsaWorld) { dig(w.stmt, "predicate", "verifier")["id"] = "https://github.com/mallory/v" },
			"not the signing identity",
		},
		{
			"verdict names another resource",
			func(w *vsaWorld) { dig(w.stmt, "predicate")["resourceUri"] = "pkg:github/acme/other@v1.2.3" },
			"naming another resource is rejected",
		},
		{
			"verificationResult FAILED",
			func(w *vsaWorld) { dig(w.stmt, "predicate")["verificationResult"] = "FAILED" },
			"not PASSED",
		},
		{
			"target level not claimed",
			func(w *vsaWorld) { dig(w.stmt, "predicate")["verifiedLevels"] = []any{"SLSA_BUILD_LEVEL_2"} },
			"does not claim SLSA_BUILD_LEVEL_3",
		},
		{
			"predicate breaking the spec's format rules",
			func(w *vsaWorld) { dig(w.stmt, "predicate")["verificationResult"] = "MAYBE" },
			"neither PASSED nor FAILED",
		},
		{
			"predicate that does not decode",
			func(w *vsaWorld) { w.stmt["predicate"] = []any{} },
			"vsa predicate",
		},
		{
			"statement that does not validate",
			func(w *vsaWorld) { w.stmt["subject"] = []any{} },
			"statement about nothing",
		},
		{
			"no verdict in the store",
			func(w *vsaWorld) { w.stmt["predicateType"] = "https://example.com/other/v1" },
			"no verdict found",
		},
		{
			"peek and verified payload diverge",
			func(w *vsaWorld) {
				w.peek = mustJSON(t, map[string]any{
					"_type":         "https://in-toto.io/Statement/v1",
					"subject":       []any{map[string]any{"digest": map[string]any{"sha256": w.appSHA}}},
					"predicateType": "https://slsa.dev/verification_summary/v1",
					"predicate":     map[string]any{},
				})
				w.stmt["predicateType"] = "https://example.com/other/v1"
			},
			"verified payload is not a verification summary",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newVSAWorld()
			tt.mutate(w)

			if _, err := w.run(t); err == nil {
				t.Fatal("VSA accepted what it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("VSA error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestReleaseDivergentPeek pins the release-side divergence guards:
// a store whose peek advertises one predicate type while the signed
// payload carries another.
func TestReleaseDivergentPeek(t *testing.T) {
	t.Parallel()

	t.Run("provenance peek over a foreign payload", func(t *testing.T) {
		t.Parallel()

		w := newReleaseWorld()
		w.build(t)

		foreign := map[string]any{
			"_type":         "https://in-toto.io/Statement/v1",
			"subject":       []any{map[string]any{"digest": map[string]any{"sha256": w.appSHA}}},
			"predicateType": "https://example.com/other/v1",
			"predicate":     map[string]any{},
		}
		bundle := (&fakeBundle{
			Stmt:     mustJSON(t, foreign),
			PeekStmt: mustJSON(t, w.provStmt),
			SAN:      w.provSAN, Issuer: issuer,
			Digests: []string{w.appSHA}, Ext: w.provExt,
		}).bytes(t)
		w.store.bundles[w.appSHA] = []verify.StoredBundle{{URI: "u", Bundle: bundle}}

		_, err := verify.Release(loadPolicy(t), coords, w.subjects, w.sboms, pins, w.store, fakeBV{}, discardLog)
		if err == nil || !strings.Contains(err.Error(), "verified payload is not provenance") {
			t.Errorf("Release error = %v, want the divergence refusal", err)
		}
	})

	t.Run("decision peek over a foreign payload", func(t *testing.T) {
		t.Parallel()

		w := newReleaseWorld()
		w.build(t)

		foreign := map[string]any{
			"_type":         "https://in-toto.io/Statement/v1",
			"subject":       []any{map[string]any{"digest": map[string]any{"sha256": w.sbomSHA}}},
			"predicateType": "https://example.com/other/v1",
			"predicate":     map[string]any{},
		}
		bundle := (&fakeBundle{
			Stmt:     mustJSON(t, foreign),
			PeekStmt: mustJSON(t, w.decStmt),
			SAN:      w.decSAN, Issuer: issuer, Digests: []string{w.sbomSHA},
			Ext: certificate.Extensions{BuildSignerDigest: canonPin},
		}).bytes(t)
		w.store.bundles[w.sbomSHA] = []verify.StoredBundle{w.store.bundles[w.sbomSHA][0], {URI: "u", Bundle: bundle}}

		_, err := verify.Release(loadPolicy(t), coords, w.subjects, w.sboms, pins, w.store, fakeBV{}, discardLog)
		if err == nil || !strings.Contains(err.Error(), "not a release decision") {
			t.Errorf("Release error = %v, want the divergence refusal", err)
		}
	})
}
