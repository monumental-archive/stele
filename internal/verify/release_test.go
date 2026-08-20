package verify_test

import (
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/verify"
	"github.com/monumental-archive/stele/internal/vsa"
)

// releaseWorld is one mutable, fully valid release: tests mutate a
// single fact and assert the guard that fires — the mutation-built
// table row pattern.
type releaseWorld struct {
	appSHA, sbomSHA string
	subjects        []verify.Subject
	sboms           []verify.Subject
	planned         []verify.Subject
	provStmt        map[string]any
	provExt         certificate.Extensions
	provSAN         string
	decStmt         map[string]any
	decSAN          string
	// assembled by build():
	store fakeStore
}

func newReleaseWorld() *releaseWorld {
	appSHA := digestHex([]byte("app bytes"))
	sbomSHA := digestHex([]byte("sbom bytes"))

	w := &releaseWorld{
		appSHA:  appSHA,
		sbomSHA: sbomSHA,
		subjects: []verify.Subject{
			{Name: "app.tar.gz", SHA256: appSHA},
			{Name: "widget-1.2.3.spdx.json", SHA256: sbomSHA},
		},
		sboms: []verify.Subject{
			{Name: "widget-1.2.3.spdx.json", SHA256: sbomSHA},
		},
		provSAN: "https://github.com/" + signerWF + "@" + signerPin,
		decSAN:  "https://github.com/" + publishWF + "@" + machineryPin,
		provExt: certificate.Extensions{
			BuildSignerDigest:   signerPin,
			RunnerEnvironment:   "github-hosted",
			SourceRepositoryURI: "https://github.com/acme/widget",
			BuildConfigURI:      "https://github.com/acme/widget/.github/workflows/publish.yml@refs/tags/v1.2.3",
		},
	}

	w.provStmt = map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []any{
			map[string]any{"name": "app.tar.gz", "digest": map[string]any{"sha256": appSHA}},
			map[string]any{"name": "widget-1.2.3.spdx.json", "digest": map[string]any{"sha256": sbomSHA}},
		},
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"buildType": buildType,
				"externalParameters": map[string]any{
					"workflow": map[string]any{
						"repository": "https://github.com/acme/widget",
						"ref":        "refs/tags/v1.2.3",
						"path":       ".github/workflows/publish.yml",
					},
					"inputs": map[string]any{},
				},
				// The decoy sits FIRST so a positional read can never
				// agree with the content-based one by accident — the
				// provenance package's own fixture rule, carried here.
				"resolvedDependencies": []any{
					map[string]any{"uri": "pkg:decoy/first"},
					map[string]any{
						"uri":    "git+https://github.com/acme/widget@refs/tags/v1.2.3",
						"digest": map[string]any{"gitCommit": srcRev},
					},
				},
			},
			"runDetails": map[string]any{
				"builder": map[string]any{"id": "https://github.com/" + signerWF + "@" + signerPin},
			},
		},
	}

	w.decStmt = map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []any{
			map[string]any{"name": "widget-1.2.3.spdx.json", "digest": map[string]any{"sha256": sbomSHA}},
		},
		"predicateType": decisionType,
		"predicate": map[string]any{
			"tag":        "v1.2.3",
			"classes":    []any{"crates"},
			"conclusion": "OPEN",
			"decidedAt":  "2026-08-01T00:00:00Z",
			"proofs":     map[string]any{},
		},
	}

	return w
}

// build assembles the store from the current (possibly mutated)
// statements. The same provenance bundle serves both subjects, so
// the dedup-by-content path runs on every happy pass.
func (w *releaseWorld) build(t *testing.T) {
	t.Helper()

	prov := (&fakeBundle{
		Stmt:    mustJSON(t, w.provStmt),
		SAN:     w.provSAN,
		Issuer:  issuer,
		Digests: []string{w.appSHA, w.sbomSHA},
		Ext:     w.provExt,
	}).bytes(t)

	dec := (&fakeBundle{
		Stmt:    mustJSON(t, w.decStmt),
		SAN:     w.decSAN,
		Issuer:  issuer,
		Digests: []string{w.sbomSHA},
		Ext:     certificate.Extensions{BuildSignerDigest: machineryPin},
	}).bytes(t)

	w.store = fakeStore{bundles: map[string][]verify.StoredBundle{
		w.appSHA:  {{URI: "https://store.example/app", Bundle: prov}},
		w.sbomSHA: {{URI: "https://store.example/sbom", Bundle: prov}, {URI: "https://store.example/dec", Bundle: dec}},
	}}
}

// plan renders the world's SBOM evidence as the engine takes it:
// every asset, and the planned inventories among them. Default
// worlds plan nothing — the whole-release invariant every release
// before per-artifact inventories was published under — and the plan
// rows below set w.planned to enter the other world.
func (w *releaseWorld) plan() verify.SBOMs {
	return verify.SBOMs{Assets: w.sboms, Planned: w.planned}
}

func (w *releaseWorld) run(t *testing.T) (*verify.ReleaseVerdict, error) {
	t.Helper()
	w.build(t)

	return verify.Release(loadPolicy(t), coords, w.subjects, w.plan(), pins, w.store, fakeBV{}, discardLog)
}

// mutate reaches into the provenance statement by path — the rows
// below each flip exactly one fact.
func dig(m map[string]any, path ...string) map[string]any {
	for _, p := range path {
		m = asMap(m[p])
	}

	return m
}

func TestRelease(t *testing.T) {
	t.Parallel()

	w := newReleaseWorld()

	verdict, err := w.run(t)
	if err != nil {
		t.Fatalf("Release = %v", err)
	}

	if got := verdict.SourceRevision(); got != srcRev {
		t.Errorf("SourceRevision = %q, want %q", got, srcRev)
	}

	// One provenance bundle (deduped across two subjects) plus the
	// decision: the evidence list names exactly what was opened.
	if got := verdict.InputAttestations(); len(got) != 2 {
		t.Errorf("InputAttestations = %d entries, want 2", len(got))
	}
}

// TestReleaseWithoutDecisionPolicy pins the optional obligation: a
// policy declaring no trust.decision gets the provenance half whole
// from Release itself — nothing invented beyond what the policy asks.
func TestReleaseWithoutDecisionPolicy(t *testing.T) {
	t.Parallel()

	w := newReleaseWorld()
	w.build(t)

	p := loadPolicy(t)
	p.Trust.Decision = nil

	verdict, err := verify.Release(p, coords, w.subjects, verify.SBOMs{}, pins, w.store, fakeBV{}, discardLog)
	if err != nil {
		t.Fatalf("Release without a decision policy = %v", err)
	}

	if got := verdict.InputAttestations(); len(got) != 1 {
		t.Errorf("InputAttestations = %d entries, want the provenance bundle alone", len(got))
	}
}

// TestReleaseProvenance pins the provenance-only entry (stele#4's
// pre-decision-epoch path): the same pass, the same evidence list,
// no decision demanded — and no decision opened.
func TestReleaseProvenance(t *testing.T) {
	t.Parallel()

	w := newReleaseWorld()
	w.build(t)

	verdict, err := verify.ReleaseProvenance(loadPolicy(t), coords, w.subjects, pins, w.store, fakeBV{}, discardLog)
	if err != nil {
		t.Fatalf("ReleaseProvenance = %v", err)
	}

	if got := verdict.SourceRevision(); got != srcRev {
		t.Errorf("SourceRevision = %q, want %q", got, srcRev)
	}

	// The provenance bundle alone: no decision ref may appear on an
	// entry point that never judged one.
	if got := verdict.InputAttestations(); len(got) != 1 {
		t.Errorf("InputAttestations = %d entries, want the provenance bundle alone", len(got))
	}

	if _, perr := verify.ReleaseProvenance(
		loadPolicy(t), coords, nil, pins, w.store, fakeBV{}, discardLog); perr == nil {
		t.Error("ReleaseProvenance verified an empty subject manifest")
	}
}

func TestReleaseRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(w *releaseWorld)
		want   string
	}{
		{
			"provenance signed under another identity",
			func(w *releaseWorld) { w.provSAN = "https://github.com/mallory/signer/sign.yml@" + signerPin },
			"provenance bundle refused",
		},
		{
			"certificate pinned at a different signer commit",
			func(w *releaseWorld) { w.provExt.BuildSignerDigest = machineryPin },
			"provenance signed at",
		},
		{
			"self-hosted runner against the deny stance",
			func(w *releaseWorld) { w.provExt.RunnerEnvironment = "self-hosted" },
			"not github-hosted",
		},
		{
			"certificate names a fork as source",
			func(w *releaseWorld) { w.provExt.SourceRepositoryURI = "https://github.com/mallory/widget" },
			"certificate source repository",
		},
		{
			"build config in a foreign repository",
			func(w *releaseWorld) {
				w.provExt.BuildConfigURI = "https://github.com/mallory/widget/x.yml@refs/tags/v1.2.3"
			},
			"not in the release repository",
		},
		{
			"build config without path@ref",
			func(w *releaseWorld) { w.provExt.BuildConfigURI = "https://github.com/acme/widget/publish.yml" },
			"no path@ref",
		},
		{
			"builder.id names a foreign builder",
			func(w *releaseWorld) {
				dig(w.provStmt, "predicate", "runDetails", "builder")["id"] = "https://github.com/mallory/b@x"
			},
			"builder.id does not name the trusted signer",
		},
		{
			"buildType outside the policy",
			func(w *releaseWorld) {
				dig(w.provStmt, "predicate", "buildDefinition")["buildType"] = "https://mallory.example/buildtypes/v1"
			},
			"not one the policy accepts",
		},
		{
			"unrecognised externalParameters field",
			func(w *releaseWorld) {
				dig(w.provStmt, "predicate", "buildDefinition", "externalParameters")["novel"] = map[string]any{}
			},
			"unrecognised field",
		},
		{
			"externalParameters without a workflow object",
			func(w *releaseWorld) {
				delete(dig(w.provStmt, "predicate", "buildDefinition", "externalParameters"), "workflow")
			},
			"no workflow object",
		},
		{
			"workflow ref is not the release tag",
			func(w *releaseWorld) {
				dig(w.provStmt, "predicate", "buildDefinition", "externalParameters", "workflow")["ref"] = "refs/heads/main"
			},
			"does not match the release coordinates",
		},
		{
			"workflow repository is a fork",
			func(w *releaseWorld) {
				wf := dig(w.provStmt, "predicate", "buildDefinition", "externalParameters", "workflow")
				wf["repository"] = "https://github.com/mallory/widget"
			},
			"does not match the release coordinates",
		},
		{
			"workflow path disagrees with the certificate",
			func(w *releaseWorld) {
				dig(w.provStmt, "predicate", "buildDefinition", "externalParameters", "workflow")["path"] = "other.yml"
			},
			"does not match the release coordinates",
		},
		{
			"certificate build config ref is not the release tag",
			func(w *releaseWorld) {
				w.provExt.BuildConfigURI = "https://github.com/acme/widget/.github/workflows/publish.yml@refs/heads/main"
			},
			"does not match the release coordinates",
		},
		{
			"provenance covers an unclaimed subject",
			func(w *releaseWorld) {
				w.provStmt["subject"] = append(asList(w.provStmt["subject"]),
					map[string]any{"name": "smuggled", "digest": map[string]any{"sha256": digestHex([]byte("x"))}})
			},
			"does not claim",
		},
		{
			"statement subject without sha256",
			func(w *releaseWorld) {
				w.provStmt["subject"] = append(asList(w.provStmt["subject"]),
					map[string]any{"name": "odd", "digest": map[string]any{"gitCommit": srcRev}})
			},
			"no sha256 digest",
		},
		{
			"a subject no provenance covers",
			func(w *releaseWorld) { w.provStmt["subject"] = asList(w.provStmt["subject"])[:1] },
			"no verified provenance covers",
		},
		{
			"statement without subjects",
			func(w *releaseWorld) { w.provStmt["subject"] = []any{} },
			"statement about nothing",
		},
		{
			"predicate that does not decode",
			func(w *releaseWorld) { w.provStmt["predicate"] = []any{} },
			"provenance predicate",
		},
		{
			"no resolvedDependencies entry names the source",
			func(w *releaseWorld) {
				dig(w.provStmt, "predicate", "buildDefinition")["resolvedDependencies"] = []any{
					map[string]any{"uri": "pkg:decoy/first"},
				}
			},
			"names the source repository",
		},
		{
			"source revision is not a commit digest",
			func(w *releaseWorld) {
				deps := asList(dig(w.provStmt, "predicate", "buildDefinition")["resolvedDependencies"])
				dig(asMap(deps[1]), "digest")["gitCommit"] = "not-a-revision"
			},
			"not a full commit digest",
		},
		{
			"decision conclusion is not the required one",
			func(w *releaseWorld) { dig(w.decStmt, "predicate")["conclusion"] = "CLOSED" },
			"does not name conclusion OPEN",
		},
		{
			"decision names another tag",
			func(w *releaseWorld) { dig(w.decStmt, "predicate")["tag"] = "v9.9.9" },
			"does not name tag",
		},
		{
			"decision signed under another identity",
			func(w *releaseWorld) { w.decSAN = "https://github.com/mallory/canon/publish.yml@" + machineryPin },
			"decision bundle refused",
		},
		{
			"decision predicate that does not decode",
			func(w *releaseWorld) { dig(w.decStmt)["predicate"] = []any{} },
			"decision predicate",
		},
		{
			"no SBOM assets declared",
			func(w *releaseWorld) { w.sboms = nil },
			"decision has no subject to verify against",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newReleaseWorld()
			tt.mutate(w)

			if _, err := w.run(t); err == nil {
				t.Fatal("Release accepted what it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Release error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

func TestReleaseInputRefusals(t *testing.T) {
	t.Parallel()

	w := newReleaseWorld()
	w.build(t)

	valid := w.subjects

	tests := []struct {
		name     string
		coords   verify.Coords
		subjects []verify.Subject
		pins     verify.Pins
		want     string
	}{
		{
			"implausible tag",
			verify.Coords{Owner: "acme", Repo: "widget", Tag: "1.2.3"},
			valid, pins, "not a plausible release tag",
		},
		{
			"implausible repo",
			verify.Coords{Owner: "acme", Repo: "wi dget", Tag: "v1.2.3"},
			valid, pins, "not a plausible repository",
		},
		{"no subjects", coords, nil, pins, "an empty proof is not a proof"},
		{
			"malformed subject digest", coords,
			[]verify.Subject{{Name: "a", SHA256: "zz"}},
			pins, "not 64 lowercase hex",
		},
		{
			"subject name with whitespace", coords,
			[]verify.Subject{{Name: "a b", SHA256: digestHex([]byte("x"))}},
			pins, "carries whitespace",
		},
		{"short pin", coords, valid, verify.Pins{Signer: "abc", Machinery: machineryPin}, "40-hex"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := verify.Release(loadPolicy(t), tt.coords, tt.subjects, w.plan(), tt.pins, w.store, fakeBV{}, discardLog)
			if err == nil {
				t.Fatal("Release accepted what it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Release error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestReleaseStoreAndBundleFailures pins the fetch-side guards:
// a digest the store cannot serve, an unreadable bundle, a payload
// that is not a statement, and disagreeing revisions across bundles.
func TestReleaseStoreAndBundleFailures(t *testing.T) {
	t.Parallel()

	t.Run("store cannot serve a digest", func(t *testing.T) {
		t.Parallel()

		w := newReleaseWorld()
		w.build(t)
		delete(w.store.bundles, w.appSHA)

		_, err := verify.Release(loadPolicy(t), coords, w.subjects, w.plan(), pins, w.store, fakeBV{}, discardLog)
		if err == nil || !strings.Contains(err.Error(), "no attestation retrievable") {
			t.Errorf("Release error = %v, want the fetch refusal", err)
		}
	})

	t.Run("unreadable bundle in the store", func(t *testing.T) {
		t.Parallel()

		w := newReleaseWorld()
		w.build(t)
		w.store.bundles[w.appSHA] = []verify.StoredBundle{{URI: "u", Bundle: []byte("not a bundle")}}

		_, err := verify.Release(loadPolicy(t), coords, w.subjects, w.plan(), pins, w.store, fakeBV{}, discardLog)
		if err == nil || !strings.Contains(err.Error(), "unreadable bundle") {
			t.Errorf("Release error = %v, want the unreadable-bundle refusal", err)
		}
	})

	t.Run("bundle payload is not a statement", func(t *testing.T) {
		t.Parallel()

		w := newReleaseWorld()
		w.build(t)
		bad := (&fakeBundle{Stmt: []byte(`[]`), SAN: w.provSAN, Issuer: issuer}).bytes(t)
		w.store.bundles[w.appSHA] = []verify.StoredBundle{{URI: "u", Bundle: bad}}

		_, err := verify.Release(loadPolicy(t), coords, w.subjects, w.plan(), pins, w.store, fakeBV{}, discardLog)
		if err == nil || !strings.Contains(err.Error(), "not a statement") {
			t.Errorf("Release error = %v, want the not-a-statement refusal", err)
		}
	})

	t.Run("bundles disagree on the source revision", func(t *testing.T) {
		t.Parallel()

		// Two provenance bundles, each covering one subject, attesting
		// different revisions: subject coverage holds, the fold refuses.
		w := newReleaseWorld()
		w.provStmt["subject"] = asList(w.provStmt["subject"])[:1]
		w.build(t)
		first := w.store.bundles[w.appSHA]

		w2 := newReleaseWorld()
		w2.provStmt["subject"] = asList(w2.provStmt["subject"])[1:]
		deps := asList(dig(w2.provStmt, "predicate", "buildDefinition")["resolvedDependencies"])
		dig(asMap(deps[1]), "digest")["gitCommit"] = leafRev
		w2.build(t)

		store := fakeStore{bundles: map[string][]verify.StoredBundle{
			w.appSHA:  first,
			w.sbomSHA: w2.store.bundles[w.sbomSHA],
		}}

		_, err := verify.Release(loadPolicy(t), coords, w.subjects, w.plan(), pins, store, fakeBV{}, discardLog)
		if err == nil || !strings.Contains(err.Error(), "disagrees on the source revision") {
			t.Errorf("Release error = %v, want the revision-fold refusal", err)
		}
	})

	t.Run("two SBOM subjects both carry decisions", func(t *testing.T) {
		t.Parallel()

		w := newReleaseWorld()
		w.subjects[0].Name = "widget-image.spdx.json"
		w.sboms = append(w.sboms, verify.Subject{Name: "widget-image.spdx.json", SHA256: w.appSHA})
		asMap(asList(w.provStmt["subject"])[0])["name"] = "widget-image.spdx.json"
		asMap(asList(w.decStmt["subject"])[0])["name"] = "widget-image.spdx.json"
		w.build(t)

		// A second decision over the image SBOM's digest.
		dec2 := (&fakeBundle{
			Ext: certificate.Extensions{BuildSignerDigest: machineryPin},
			Stmt: mustJSON(t, map[string]any{
				"_type": "https://in-toto.io/Statement/v1",
				"subject": []any{
					map[string]any{"name": "widget-image.spdx.json", "digest": map[string]any{"sha256": w.appSHA}},
				},
				"predicateType": decisionType,
				"predicate": map[string]any{
					"tag": "v1.2.3", "classes": []any{}, "conclusion": "OPEN",
					"decidedAt": "2026-08-01T00:00:00Z", "proofs": map[string]any{},
				},
			}),
			SAN: w.decSAN, Issuer: issuer, Digests: []string{w.appSHA},
		}).bytes(t)
		w.store.bundles[w.appSHA] = append(w.store.bundles[w.appSHA], verify.StoredBundle{URI: "d2", Bundle: dec2})

		_, err := verify.Release(loadPolicy(t), coords, w.subjects, w.plan(), pins, w.store, fakeBV{}, discardLog)
		if err == nil || !strings.Contains(err.Error(), "more than one SBOM asset carries a release decision") {
			t.Errorf("Release error = %v, want the ambiguity refusal", err)
		}
	})

	t.Run("no SBOM subject carries a decision", func(t *testing.T) {
		t.Parallel()

		w := newReleaseWorld()
		w.build(t)
		w.store.bundles[w.sbomSHA] = w.store.bundles[w.sbomSHA][:1] // drop the decision bundle

		_, err := verify.Release(loadPolicy(t), coords, w.subjects, w.plan(), pins, w.store, fakeBV{}, discardLog)
		if err == nil || !strings.Contains(err.Error(), "no SBOM asset carries a verifiable release decision") {
			t.Errorf("Release error = %v, want the missing-decision refusal", err)
		}
	})
}

// TestReleaseVSAPredicate proves the verdict's render: only a verdict
// Release returned can produce a predicate, and what it produces is
// exactly what the consumer read (verify.VSA) demands — the verifier
// identity, the expanded resource, the pinned policy, the target
// level, and the opened evidence.
func TestReleaseVSAPredicate(t *testing.T) {
	t.Parallel()

	w := newReleaseWorld()

	verdict, err := w.run(t)
	if err != nil {
		t.Fatalf("Release = %v", err)
	}

	const policyURI = "https://github.com/acme/canon/blob/" + machineryPin + "/slsa/verify-policy.json"

	pred, err := verdict.VSAPredicate(loadPolicy(t), coords, policyURI, machineryPin, "2026-08-15T12:00:00Z")
	if err != nil {
		t.Fatalf("VSAPredicate = %v", err)
	}

	got, err := jsonx.DecodeBytes[vsa.Predicate](pred)
	if err != nil {
		t.Fatalf("the rendered predicate does not decode: %v", err)
	}

	if err := got.Validate(); err != nil {
		t.Fatalf("Validate(rendered) = %v", err)
	}

	if *got.Verifier.ID != "https://github.com/"+verifierWF {
		t.Errorf("verifier.id = %q, want the policy's verifier workflow", *got.Verifier.ID)
	}

	if *got.ResourceURI != "pkg:github/acme/widget@v1.2.3" {
		t.Errorf("resourceUri = %q", *got.ResourceURI)
	}

	if *got.VerificationResult != vsa.ResultPassed {
		t.Errorf("verificationResult = %q", *got.VerificationResult)
	}

	if len(got.VerifiedLevels) != 1 || got.VerifiedLevels[0] != "SLSA_BUILD_LEVEL_3" {
		t.Errorf("verifiedLevels = %v, want exactly the target", got.VerifiedLevels)
	}

	if got.Policy.Digest["gitCommit"] != machineryPin {
		t.Errorf("policy.digest = %v, want the canon pin", got.Policy.Digest)
	}

	if len(got.InputAttestations) != 2 {
		t.Errorf("inputAttestations = %d entries, want the 2 the verdict opened", len(got.InputAttestations))
	}

	if got.SlsaVersion == nil || *got.SlsaVersion != vsa.SpecVersion {
		t.Errorf("slsaVersion = %v, want the assembler's pin", got.SlsaVersion)
	}
}

func TestReleaseVSAPredicateRefusals(t *testing.T) {
	t.Parallel()

	w := newReleaseWorld()

	verdict, err := w.run(t)
	if err != nil {
		t.Fatalf("Release = %v", err)
	}

	const when = "2026-08-15T12:00:00Z"

	if _, err := verdict.VSAPredicate(loadPolicy(t), coords, "https://p.example", "not-a-pin", when); err == nil {
		t.Error("VSAPredicate accepted a policy digest that is not a commit")
	}

	if _, err := verdict.VSAPredicate(loadPolicy(t), coords, "", machineryPin, "2026-08-15T12:00:00Z"); err == nil {
		t.Error("VSAPredicate accepted an empty policy URI — a verdict naming no policy must never recur")
	}
}
