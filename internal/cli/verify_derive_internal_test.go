// `verify release` and `verify vsa` over a published release with
// the inputs a consumer cannot know left out (stele#447): derived by
// the deep walk's own derivation, printed, and never preferred over a
// flag that was given.

package cli

import (
	"bytes"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/gitfetch"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

// The deep world's two-hop pins: the caller's publish workflow at the
// tag pins the canon at machineryA, whose publish workflow pins the
// signer at signerB.
var (
	machineryA = strings.Repeat("a", 40)
	signerB    = strings.Repeat("b", 40)
	tagC       = strings.Repeat("c", 40)
	appSHA     = strings.Repeat("5", 64)
)

// derivedVSA is the verdict the deep world's release carries.
var derivedVSA = strings.NewReplacer(subjectSHA, appSHA, "v1.2.3", "v1.0.0").Replace(vsaStatement)

// pinBV serves the verdict only to an identity pinned at want — the
// one property of the trust boundary these tests turn on: which pin
// the run verified against.
type pinBV struct {
	scriptedBV

	want string
}

func (b pinBV) Attestation(raw []byte, id trust.Identity, sha string) (*trust.Verified, error) {
	if !strings.HasSuffix(id.SAN, "@"+b.want) {
		return nil, errors.New("identity " + id.SAN + " is not pinned at " + b.want)
	}

	v, err := b.scriptedBV.Attestation(raw, id, sha)
	if err != nil {
		return nil, err
	}

	// The certificate names the pin it was signed at — the pin, since
	// the identity matched it.
	v.Extensions.BuildSignerDigest = b.want

	return v, nil
}

// derivedWorld stages the deep world and the verify inputs over it,
// with the pin tags scripted. It returns the verify policy, the
// trusted root, the publisher's assert policy and the snapshot.
type derivedWorld struct {
	vp, root, ap, snap string
}

func stageDerived(t *testing.T, tags assert.TagResolver, closeErr error) derivedWorld {
	t.Helper()

	args, snap := deepWorld(t, nil)

	w := derivedWorld{
		vp: argValue(t, args, "--verify-policy"), root: argValue(t, args, "--trusted-root"),
		ap: argValue(t, args, "--policy"), snap: snap,
	}

	orig := newPinTags
	newPinTags = func(func(string, ...any)) (assert.TagResolver, func() error) {
		return tags, func() error { return closeErr }
	}

	t.Cleanup(func() { newPinTags = orig })

	return w
}

// newPinBV is the verifier pinned at want, serving the deep world's
// verdict.
func newPinBV(want string) pinBV {
	return pinBV{payload: []byte(derivedVSA), want: want}
}

// snapPath names a file of acme/widget in the replayed forge.
func snapPath(snap string, parts ...string) string {
	return filepath.Join(append([]string{snap, "acme", "widget"}, parts...)...)
}

func argValue(t *testing.T, args []string, flag string) string {
	t.Helper()

	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		t.Fatalf("the fixture's arguments carry no %s", flag)
	}

	return args[i+1]
}

func stageFile(t *testing.T, path, content string) string {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func (w derivedWorld) vsa(extra ...string) []string {
	return append([]string{
		"verify", "vsa", "--policy", w.vp, "--trusted-root", w.root, "--repo", "acme/widget", "--tag", "v1.0.0",
	}, extra...)
}

// TestVerifyDerivesItsPins runs `verify vsa` over a recorded release
// with no digest flags: the pins come from the trees at the tag, are
// printed, and are the ones the verdict's identity is held to. A digest
// that IS given is used as given, and a wrong one refuses as it always
// has.
func TestVerifyDerivesItsPins(t *testing.T) {
	t.Run("no digest flags: both pins derived and verified against", func(t *testing.T) {
		w := stageDerived(t, noPins{}, nil)
		swap(t, newPinBV(machineryA), scriptedStore{})

		subjects := stageFile(t, filepath.Join(t.TempDir(), "subjects"), appSHA+"  app.tar.gz\n")

		var stdout, stderr bytes.Buffer
		if code := Run(w.vsa("--subjects", subjects), &stdout, &stderr); code != exitOK {
			t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}

		for _, want := range []string{"derived --machinery-digest " + machineryA, "derived --signer-digest " + signerB} {
			if !strings.Contains(stdout.String(), want) {
				t.Errorf("stdout does not state %q:\n%s", want, stdout.String())
			}
		}
	})

	t.Run("no digest flags and no subjects: everything read from the release", func(t *testing.T) {
		w := stageDerived(t, noPins{}, nil)
		swap(t, newPinBV(machineryA), scriptedStore{})

		var stdout, stderr bytes.Buffer
		if code := Run(w.vsa("--assert-policy", w.ap), &stdout, &stderr); code != exitOK {
			t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}

		if want := "derived subject " + appSHA + "  app.tar.gz"; !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout does not state %q:\n%s", want, stdout.String())
		}
	})

	t.Run("a wrong explicit digest still refuses, and is not replaced", func(t *testing.T) {
		w := stageDerived(t, noPins{}, nil)
		swap(t, newPinBV(machineryA), scriptedStore{})

		subjects := stageFile(t, filepath.Join(t.TempDir(), "subjects"), appSHA+"  app.tar.gz\n")

		var stdout, stderr bytes.Buffer

		code := Run(w.vsa("--subjects", subjects, "--machinery-digest", tagC), &stdout, &stderr)
		if code != exitRefused {
			t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitRefused, stderr.String())
		}

		if strings.Contains(stdout.String(), "derived --machinery-digest") {
			t.Errorf("a given digest was derived over:\n%s", stdout.String())
		}

		if !strings.Contains(stderr.String(), "not pinned at "+machineryA) {
			t.Errorf("stderr = %q, want the identity refusal", stderr.String())
		}
	})
}

// recordingDeep records what the deep walk hands the engine.
type recordingDeep struct {
	passDeep

	subjects []verify.Subject
	sboms    verify.SBOMs
	pins     verify.Pins
	calls    int
}

func (r *recordingDeep) Release(_ verify.Coords, s []verify.Subject, sb verify.SBOMs, p verify.Pins, _ bool) error {
	r.subjects, r.sboms, r.pins = s, sb, p
	r.calls++

	return nil
}

// TestVerifyAndTheDeepWalkDeriveTheSame reads one recorded release
// through both callers: the corpus walk at full depth, and the verb's
// derivation. The pins, the subjects, the SBOM candidates and the plan
// are equal — one derivation, two callers.
func TestVerifyAndTheDeepWalkDeriveTheSame(t *testing.T) {
	w := stageDerived(t, noPins{}, nil)

	// An SBOM beside the artifact, so the candidates are not trivially
	// empty on both sides.
	stageFile(t, snapPath(w.snap, "releases", "v1.0.0", "assets", "checksums.txt"),
		appSHA+"  app.tar.gz\n"+strings.Repeat("6", 64)+"  app.spdx.json\n")

	deep := &recordingDeep{}
	orig := newDeepVerifier
	newDeepVerifier = func(
		vp *policy.Policy, _ gh.Forge, tags assert.TagResolver, _ verify.BundleVerifier, _ sourceHistories,
	) (*assert.FullDepth, error) {
		return assert.NewFullDepth(deep, tags, *vp.Trust.Verdict.VerifierWorkflow, *vp.Trust.Provenance.SignerWorkflow)
	}

	t.Cleanup(func() { newDeepVerifier = orig })

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"assert", "evidence", "--org", "acme", "--policy", w.ap,
		"--trusted-root", w.root, "--verify-policy", w.vp, "--depth", "full",
	}, &stdout, &stderr)
	if code != exitOK || deep.calls != 1 {
		t.Fatalf("walk Run = %d, %d release(s) re-verified\nstdout: %s\nstderr: %s",
			code, deep.calls, stdout.String(), stderr.String())
	}

	va, pcode := parseVerifyArgs(modeRelease, []string{
		"--policy", w.vp, "--trusted-root", w.root, "--repo", "acme/widget", "--tag", "v1.0.0",
		"--assert-policy", w.ap,
	}, &stderr)
	if pcode != exitOK {
		t.Fatalf("parseVerifyArgs = %d: %s", pcode, stderr.String())
	}

	if err := va.derive(&latch{w: &stdout}); err != nil {
		t.Fatalf("derive = %v", err)
	}

	if got := (verify.Pins{Signer: va.signerPin, Machinery: va.machineryPin}); got != deep.pins {
		t.Errorf("verb pins %+v, walk pins %+v", got, deep.pins)
	}

	if !slices.Equal(va.subjectList, deep.subjects) {
		t.Errorf("verb subjects %v, walk subjects %v", va.subjectList, deep.subjects)
	}

	if !slices.Equal(va.sbomList, deep.sboms.Assets) || !slices.Equal(va.inventoryList, deep.sboms.Planned) {
		t.Errorf("verb sboms %v / plan %v, walk %+v", va.sbomList, va.inventoryList, deep.sboms)
	}

	if len(va.sbomList) != 1 {
		t.Errorf("sboms = %v — the fixture's SBOM was not read", va.sbomList)
	}
}

// fixedTags answers every tag with one commit, or one error.
type fixedTags struct {
	sha string
	err error
}

func (f fixedTags) TagCommit(string, string, string) (string, error) { return f.sha, f.err }

// selfAttestingPolicy is the deep world's verify policy with the signer
// identity templated — every repository signs for itself.
func selfAttestingPolicy(t *testing.T) string {
	t.Helper()

	return stageFile(t, filepath.Join(t.TempDir(), "vp.json"), strings.Replace(testPolicy,
		`"acme/signer/.github/workflows/sign.yml"`, `"{owner}/{repo}/.github/workflows/release.yml"`, 1))
}

// TestVerifyDerivationUsageRefusals holds the inputs a derivation
// needs to the usage vocabulary: refused before anything is read, by
// name.
func TestVerifyDerivationUsageRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		args func(w derivedWorld) []string
		want string
	}{
		{
			name: "neither --subjects nor --assert-policy",
			args: func(w derivedWorld) []string { return w.vsa() },
			want: "--subjects is required unless --assert-policy",
		},
		{
			name: "release mode: neither --sboms nor --assert-policy",
			args: func(w derivedWorld) []string {
				subjects := stageFile(t, filepath.Join(t.TempDir(), "subjects"), appSHA+"  app.tar.gz\n")

				return []string{
					"verify", "release", "--policy", w.vp, "--trusted-root", w.root, "--repo", "acme/widget",
					"--tag", "v1.0.0", "--subjects", subjects,
				}
			},
			want: "--sboms is required unless --assert-policy",
		},
		{
			name: "an unreadable assert policy",
			args: func(w derivedWorld) []string { return w.vsa("--assert-policy", "/no/such/assert-policy.json") },
			want: "/no/such/assert-policy.json",
		},
		{
			name: "an assert policy with no evidence section",
			args: func(w derivedWorld) []string {
				return w.vsa("--assert-policy", stageFile(t, filepath.Join(t.TempDir(), "ap.json"), `{"schema": 9}`))
			},
			want: "assert policy: assert: policy: evidence is absent",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := stageDerived(t, noPins{}, nil)

			var stdout, stderr bytes.Buffer
			if code := Run(tc.args(w), &stdout, &stderr); code != exitUsage {
				t.Fatalf("Run = %d, want %d (stderr %s)", code, exitUsage, stderr.String())
			}

			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr = %q, want %q", stderr.String(), tc.want)
			}
		})
	}
}

// TestVerifyDerivationRefusals holds every derivation that cannot
// complete to a refusal naming the release and the cause — never a
// verdict over inputs nobody derived.
func TestVerifyDerivationRefusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tags  assert.TagResolver
		shape func(t *testing.T, w derivedWorld) []string
		want  []string
	}{
		{
			name: "a publish workflow with no full-commit pin",
			tags: noPins{},
			shape: func(t *testing.T, w derivedWorld) []string {
				t.Helper()
				stageFile(t, snapPath(w.snap, "files", "v1.0.0", url.PathEscape(".github/workflows/publish.yml")),
					"uses: acme/canon/.github/workflows/publish.yml@v1\n")

				return w.vsa("--assert-policy", w.ap)
			},
			want: []string{
				"the signing pins of acme/widget@v1.0.0: no full-commit machinery pin on the publish workflow at v1.0.0",
			},
		},
		{
			name: "a tag the resolver cannot read",
			tags: fixedTags{err: errors.New("no such tag v1.0.0")},
			shape: func(t *testing.T, w derivedWorld) []string {
				t.Helper()

				return []string{
					"verify", "vsa", "--policy", selfAttestingPolicy(t), "--trusted-root", w.root,
					"--repo", "acme/widget", "--tag", "v1.0.0", "--assert-policy", w.ap,
				}
			},
			want: []string{"the signing pins of acme/widget@v1.0.0", "no such tag v1.0.0"},
		},
		{
			name: "what the release shipped cannot be read",
			tags: noPins{},
			shape: func(t *testing.T, w derivedWorld) []string {
				t.Helper()

				if err := os.Remove(snapPath(w.snap, "releases", "v1.0.0", "assets", "checksums.txt")); err != nil {
					t.Fatal(err)
				}

				return w.vsa("--assert-policy", w.ap)
			},
			want: []string{"what acme/widget@v1.0.0 shipped: the checksum manifest is unreadable"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := stageDerived(t, tc.tags, nil)
			swap(t, newPinBV(machineryA), scriptedStore{})

			var stdout, stderr bytes.Buffer
			if code := Run(tc.shape(t, w), &stdout, &stderr); code != exitRefused {
				t.Fatalf("Run = %d, want %d (stderr %s)", code, exitRefused, stderr.String())
			}

			for _, want := range tc.want {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr = %q, want %q", stderr.String(), want)
				}
			}
		})
	}
}

// TestVerifyDerivesSelfAttestingPins is the templated-signer topology:
// both identities are pinned at the tag's own commit, read through
// the tag resolver.
func TestVerifyDerivesSelfAttestingPins(t *testing.T) {
	w := stageDerived(t, fixedTags{sha: tagC}, nil)
	swap(t, newPinBV(tagC), scriptedStore{})

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "vsa", "--policy", selfAttestingPolicy(t), "--trusted-root", w.root, "--repo", "acme/widget",
		"--tag", "v1.0.0", "--assert-policy", w.ap,
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	for _, want := range []string{"derived --machinery-digest " + tagC, "derived --signer-digest " + tagC} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout does not state %q:\n%s", want, stdout.String())
		}
	}
}

// TestVerifyDerivationCloseFailure: a tag session that will not close
// is said, and the verdict it did not affect stands.
func TestVerifyDerivationCloseFailure(t *testing.T) {
	w := stageDerived(t, noPins{}, errors.New("fetched directory stuck"))
	swap(t, newPinBV(machineryA), scriptedStore{})

	var stdout, stderr bytes.Buffer
	if code := Run(w.vsa("--assert-policy", w.ap), &stdout, &stderr); code != exitOK {
		t.Fatalf("Run = %d, stderr %s", code, stderr.String())
	}

	if !strings.Contains(stdout.String(), "verify: fetched directory stuck") {
		t.Errorf("stdout = %q, want the close failure said", stdout.String())
	}
}

// TestVerifyDerivationKeepsExplicitPlan: with the SBOMs derived, a
// plan given on the command line is used as given.
func TestVerifyDerivationKeepsExplicitPlan(t *testing.T) {
	w := stageDerived(t, noPins{}, nil)
	plan := stageFile(t, filepath.Join(t.TempDir(), "plan"), strings.Repeat("7", 64)+"  planned.spdx.json\n")

	var stderr bytes.Buffer

	va, code := parseVerifyArgs(modeRelease, []string{
		"--policy", w.vp, "--trusted-root", w.root, "--repo", "acme/widget", "--tag", "v1.0.0",
		"--assert-policy", w.ap, "--inventories", plan,
		"--signer-digest", signerB, "--machinery-digest", machineryA,
	}, &stderr)
	if code != exitOK {
		t.Fatalf("parseVerifyArgs = %d: %s", code, stderr.String())
	}

	var out bytes.Buffer
	if err := va.derive(&latch{w: &out}); err != nil {
		t.Fatalf("derive = %v", err)
	}

	if len(va.inventoryList) != 1 || va.inventoryList[0].Name != "planned.spdx.json" {
		t.Errorf("plan = %v, want the explicit one", va.inventoryList)
	}

	if strings.Contains(out.String(), "derived planned inventory") || strings.Contains(out.String(), "derived --") {
		t.Errorf("a given input was derived over:\n%s", out.String())
	}
}

// checkedTags is the real resolver's guard: an unusable git refuses at
// the first tag read, never at construction.
func TestCheckedTagsRefusesAnUnusableGit(t *testing.T) {
	ct := &checkedTags{s: &gitfetch.Session{Fetcher: &gitfetch.Fetcher{Git: filepath.Join(t.TempDir(), "no-git")}}}

	if _, err := ct.TagCommit("acme", "widget", "v1.0.0"); err == nil {
		t.Fatal("TagCommit read through a git that does not exist")
	}

	if ct.checked {
		t.Error("a refused check was remembered as passed")
	}
}
