// The release derivation the verb shares with the deep walk
// (stele#447): every guard of DeriveRelease and NewPinRoots, and the
// two callers reading one recorded release to the same answer.

package assert_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/provenance"
	"github.com/monumental-archive/stele/internal/verify"
)

// scriptedContract is a contract source answering one fixed contract,
// so a row can reach the derivation's later guards with the contract
// it needs.
type scriptedContract struct {
	c   *assert.Contract
	err error
}

func (s scriptedContract) Contract(string, string, string) (*assert.Contract, bool, error) {
	return s.c, s.c != nil, s.err
}

// manifestContract is the walk's own contract source over a forge.
func manifestContract(f *fakeForge, pol *assert.Policy) assert.Sources {
	return assert.Sources{assert.ManifestSource{Forge: f, Policy: pol.Evidence, Asset: "evidence-manifest.json"}}
}

// deriveOne runs the derivation over deepForge's release, collecting
// what it logged.
func deriveOne(
	t *testing.T, f *fakeForge, src assert.ContractSource,
) (*assert.ReleaseInputs, []string, error) {
	t.Helper()

	var logs []string

	in, err := loadTestPolicy(t).Evidence.DeriveRelease(f, src, testOrg, "widget", "v1.0.0",
		func(format string, _ ...any) { logs = append(logs, format) })

	return in, logs, err
}

func names(subjects []verify.Subject) []string {
	out := make([]string, 0, len(subjects))
	for _, s := range subjects {
		out = append(out, s.Name)
	}

	return out
}

// TestDeriveReleaseIsTheWalksReading holds the derivation to the deep
// walk over one recorded release: the subjects, the SBOM candidates
// and the pins the walk hands the engine are exactly what the verb's
// derivation reads.
func TestDeriveReleaseIsTheWalksReading(t *testing.T) {
	t.Parallel()

	f := deepForge()
	deep := &fakeDeep{}
	runDeepWalk(t, f, deep)

	if len(deep.releasePins) != 1 || len(deep.sboms) != 1 {
		t.Fatalf("the walk re-verified %d releases, want 1", len(deep.releasePins))
	}

	in, _, err := deriveOne(t, deepForge(), manifestContract(deepForge(), loadTestPolicy(t)))
	if err != nil {
		t.Fatalf("DeriveRelease = %v", err)
	}

	if got := names(in.Subjects); !slices.Equal(got, deep.names) {
		t.Errorf("subjects = %v, the walk verified %v", got, deep.names)
	}

	if !slices.Equal(in.SBOMs.Assets, deep.sboms[0].Assets) || !slices.Equal(in.SBOMs.Planned, deep.sboms[0].Planned) {
		t.Errorf("sboms = %+v, the walk verified %+v", in.SBOMs, deep.sboms[0])
	}

	roots, err := assert.NewPinRoots(deepForge(),
		"acme/canon/.github/workflows/verify-release.yml", "acme/signer/.github/workflows/sign.yml")
	if err != nil {
		t.Fatal(err)
	}

	roots.Publish = loadTestPolicy(t).Evidence.Publish

	pins, err := roots.Resolve(deepForge(), testOrg, "widget", "v1.0.0")
	if err != nil || pins != deep.releasePins[0] {
		t.Errorf("pins = %+v, %v; the walk verified %+v", pins, err, deep.releasePins[0])
	}
}

func TestDeriveRelease(t *testing.T) {
	t.Parallel()

	t.Run("a healthy release states its artifacts and SBOMs, documents excluded", func(t *testing.T) {
		t.Parallel()

		f := deepForge()

		in, logs, err := deriveOne(t, f, manifestContract(f, loadTestPolicy(t)))
		if err != nil {
			t.Fatalf("DeriveRelease = %v", err)
		}

		if got := names(in.Subjects); !slices.Equal(got, []string{"widget-v1.0.0.tar.gz"}) {
			t.Errorf("subjects = %v", got)
		}

		if got := names(in.SBOMs.Assets); !slices.Equal(got, []string{"app.spdx.json"}) {
			t.Errorf("sboms = %v", got)
		}

		if len(logs) != 0 {
			t.Errorf("logged %v on a complete release", logs)
		}
	})

	t.Run("an absent owed bundle is said, and the derivation reads what is present", func(t *testing.T) {
		t.Parallel()

		f := deepForge()
		f.assets["widget@v1.0.0"] = slices.DeleteFunc(slices.Clone(f.assets["widget@v1.0.0"]),
			func(a string) bool { return a == "attestations-image.intoto.jsonl" })

		in, logs, err := deriveOne(t, f, manifestContract(f, loadTestPolicy(t)))
		if err != nil || len(in.Subjects) != 1 {
			t.Fatalf("DeriveRelease = %v, %v", in, err)
		}

		if len(logs) != 1 || !strings.Contains(logs[0], "is absent") {
			t.Errorf("logs = %v, want the absent bundle said", logs)
		}
	})

	t.Run("an unregistered contract reads registry subjects from provenance", func(t *testing.T) {
		t.Parallel()

		f := deepForge()
		f.assetBytes["widget@v1.0.0"]["attestations-image.intoto.jsonl"] = bundleJSONL(provenance.PredicateType)

		in, _, err := deriveOne(t, f, scriptedContract{c: &assert.Contract{Classes: []string{"oci-image"}}})
		if err != nil {
			t.Fatalf("DeriveRelease = %v", err)
		}

		if got := names(in.Subjects); !slices.Equal(got, []string{"widget-v1.0.0.tar.gz", "app"}) {
			t.Errorf("subjects = %v, want the checksummed artifact then the attested one", got)
		}
	})

	for _, tc := range []struct {
		name  string
		shape func(f *fakeForge) assert.ContractSource
		want  string
	}{
		{
			name: "the contract source cannot be read",
			shape: func(*fakeForge) assert.ContractSource {
				return scriptedContract{err: errors.New("contract torn")}
			},
			want: "contract torn",
		},
		{
			name: "no contract speaks for the release",
			shape: func(f *fakeForge) assert.ContractSource {
				f.assets["widget@v1.0.0"] = []string{"checksums.txt"}

				return manifestContract(f, loadTestPolicy(t))
			},
			want: "no evidence contract speaks for acme/widget@v1.0.0",
		},
		{
			name: "the asset listing cannot be read",
			shape: func(f *fakeForge) assert.ContractSource {
				f.torn = map[string]error{"ReleaseAssets": errors.New("listing torn")}

				return scriptedContract{c: &assert.Contract{Classes: []string{"oci-image"}}}
			},
			want: "the assets of acme/widget@v1.0.0 are unreadable: listing torn",
		},
		{
			name: "the checksum manifest cannot be read",
			shape: func(f *fakeForge) assert.ContractSource {
				f.assetErr = map[string]error{"widget@v1.0.0/checksums.txt": errors.New("checksums torn")}

				return manifestContract(f, loadTestPolicy(t))
			},
			want: "the checksum manifest is unreadable",
		},
		{
			name: "the two pinning documents disagree",
			shape: func(f *fakeForge) assert.ContractSource {
				f.assetBytes["widget@v1.0.0"]["checksums.txt"] = strings.Repeat("9", 64) + "  widget-v1.0.0.tar.gz\n"

				return manifestContract(f, loadTestPolicy(t))
			},
			want: "the evidence manifest pins " + subjectDigest,
		},
		{
			name: "a class bundle cannot be read",
			shape: func(f *fakeForge) assert.ContractSource {
				f.lateAssetErr = map[string]error{
					"widget@v1.0.0/attestations-image.intoto.jsonl": errors.New("bundle torn"),
				}
				// The contract read is the first read; the bundle is the
				// derivation's own.
				f.assetReads = map[string]int{"widget@v1.0.0/attestations-image.intoto.jsonl": 1}

				return manifestContract(f, loadTestPolicy(t))
			},
			want: "attestations-image.intoto.jsonl is unreadable: bundle torn",
		},
		{
			name: "provenance attests a subject the claim does not name",
			shape: func(f *fakeForge) assert.ContractSource {
				f.assetBytes["widget@v1.0.0"]["attestations-image.intoto.jsonl"] = bundleJSONL(provenance.PredicateType)

				return manifestContract(f, loadTestPolicy(t))
			},
			want: "provenance attests subject(s) neither checksums.txt nor the evidence manifest names: app",
		},
		{
			name: "the release names no artifact",
			shape: func(f *fakeForge) assert.ContractSource {
				f.assetBytes["widget@v1.0.0"]["checksums.txt"] = strings.Repeat("d", 64) + "  app.spdx.json\n"

				return manifestContract(f, loadTestPolicy(t))
			},
			want: "the release names no artifact subjects",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := deepForge()
			src := tc.shape(f)

			in, _, err := deriveOne(t, f, src)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("DeriveRelease = %+v, %v; want a refusal naming %q", in, err, tc.want)
			}

			if in != nil {
				t.Errorf("a refused derivation returned inputs %+v — a short list is a narrower verdict", in)
			}
		})
	}
}

func TestNewPinRoots(t *testing.T) {
	t.Parallel()

	t.Run("no tag resolver refuses", func(t *testing.T) {
		t.Parallel()

		if _, err := assert.NewPinRoots(nil, "", "acme/signer/x.yml"); err == nil ||
			!strings.Contains(err.Error(), "needs a tag resolver") {
			t.Fatalf("NewPinRoots(nil) = %v", err)
		}
	})

	t.Run("a verifier workflow naming no repository refuses", func(t *testing.T) {
		t.Parallel()

		if _, err := assert.NewPinRoots(deepForge(), "canon", "acme/signer/x.yml"); err == nil ||
			!strings.Contains(err.Error(), "does not name owner/repo/path") {
			t.Fatalf("NewPinRoots = %v", err)
		}
	})

	t.Run("no verdict obligation leaves the machinery unknown, and the stub still names it", func(t *testing.T) {
		t.Parallel()

		roots, err := assert.NewPinRoots(deepForge(), "", "acme/signer/.github/workflows/sign.yml")
		if err != nil || roots.MachineryOwner != "" || roots.SelfSigned {
			t.Fatalf("roots = %+v, %v", roots, err)
		}

		roots.Publish = loadTestPolicy(t).Evidence.Publish

		pins, rerr := roots.Resolve(deepForge(), testOrg, "widget", "v1.0.0")
		if rerr != nil || pins != (verify.Pins{Machinery: machineryPin40, Signer: signerPin40}) {
			t.Fatalf("Resolve = %+v, %v; want the pins the declared stub names", pins, rerr)
		}
	})

	t.Run("a templated signer is the self-attesting topology", func(t *testing.T) {
		t.Parallel()

		f := deepForge()
		f.tagCommits = map[string]string{"v1.0.0": tagSHA40}

		roots, err := assert.NewPinRoots(f, "", "{owner}/{repo}/.github/workflows/release.yml")
		if err != nil || !roots.SelfSigned {
			t.Fatalf("roots = %+v, %v", roots, err)
		}

		pins, err := roots.Resolve(f, testOrg, "widget", "v1.0.0")
		if err != nil || pins != (verify.Pins{Signer: tagSHA40, Machinery: tagSHA40}) {
			t.Fatalf("Resolve = %+v, %v; want both pins at the tag's commit", pins, err)
		}
	})
}
