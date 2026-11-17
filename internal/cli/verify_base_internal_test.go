// `stele verify base` over the recorded store of two bases release-lab
// published (testdata/base-images/SOURCE.md): every row runs the real
// attestor, the real trust boundary and sigstore-go's own public-good
// root, and changes one thing about the reference or the policy.
// Beside them, the rows for a build with nothing to judge, every usage
// guard, and the upstream half over a scripted registry.

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/oci"
	"github.com/monumental-archive/stele/internal/verify"
)

const (
	latestDigest = "sha256:af094a76642c8a52b04952baa2796d3d8f65eb9cf5ac97def1bd1a7edaa5ab5d"
	labPgDigest  = "sha256:ca2d60b355aeaf2837e96cdb5b7595cf09398260c864e08bcf39c91f79f76384"

	// The continuous stream, and a release image whose name is not its
	// repository's: both built by release-lab, signed at two different
	// signer commits.
	latestRef = "ghcr.io/monumental-archive/release-lab:latest@" + latestDigest
	labPgRef  = "ghcr.io/monumental-archive/lab-pg:0.28.4-pg18-artifact@" + labPgDigest

	debianRef = "docker.io/library/debian:trixie@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	pgBaseRef = "postgres:14-bookworm@sha256:a54c8b1e143b22f16b0fd3e249e9297a6f08828a143ee7108b1b5ca51f352765"

	orgSigner = "monumental-archive/signer/.github/workflows/sign.yml"
)

// basePolicy is an assert policy declaring the org's first-party scope,
// signed by signer, and the official postgres image upstream.
func basePolicy(signer string) string {
	return `{"schema": 9, "issuer": "https://token.actions.githubusercontent.com",
	  "evidence": {"sbomSuffix": ".spdx.json", "checksums": "checksums.txt",
	    "umbrellaBundle": "attestations.intoto.jsonl", "manifestAsset": "evidence-manifest.json",
	    "classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}},
	    "baseImages": {
	      "scopes": [{"name": "org-bases", "mechanism": "provenance-verified", "fromFile": "Dockerfile",
	        "registryPrefix": "ghcr.io/monumental-archive/", "signerWorkflow": "` + signer + `",
	        "refs": [{"tag": "^latest$", "ref": "refs/heads/main"},
	          {"tag": "^(?P<version>[0-9]+\\.[0-9]+\\.[0-9]+)(-.*)?$", "ref": "refs/tags/v${version}"}],
	        "predicateType": "https://slsa.dev/provenance/v1"}],
	      "upstream": [{"image": "docker.io/library/postgres",
	        "tagPattern": "^(?P<major>[0-9]+)-(?P<suite>[a-z]+)$",
	        "source": "https://github.com/docker-library/postgres.git", "path": "${major}/${suite}"}]}}}`
}

// writeFile writes content to a fresh temp file and returns its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// publicGood writes sigstore-go's own public-good trusted root, the
// one the recorded bundles were logged under.
func publicGood(t *testing.T) string {
	t.Helper()

	return writeFile(t, "root.json", string(upstreamRoot(t, "public-good.json")))
}

// swapBaseForge serves the attestation store from forge.
func swapBaseForge(t *testing.T, forge gh.Forge) {
	t.Helper()

	orig := newForge
	newForge = func() gh.Forge { return forge }

	t.Cleanup(func() { newForge = orig })
}

// swapStatements serves the registry's provenance read from reader.
func swapStatements(t *testing.T, reader oci.StatementReader) {
	t.Helper()

	orig := newStatementReader
	newStatementReader = func() oci.StatementReader { return reader }

	t.Cleanup(func() { newStatementReader = orig })
}

// runBase runs `stele verify base` with the policy and the arguments.
//
//nolint:gocritic // unnamedResult: code, stdout, stderr — the order Run's own signature implies
func runBase(t *testing.T, policyDoc string, args ...string) (int, string, string) {
	t.Helper()

	var stdout, stderr bytes.Buffer

	argv := append([]string{"verify", "base", "--assert-policy", writeFile(t, "assert-policy.json", policyDoc)},
		args...)
	code := Run(argv, &stdout, &stderr)

	return code, stdout.String(), stderr.String()
}

// refArgs renders each reference as its own --ref.
func refArgs(refs ...string) []string {
	out := make([]string, 0, 2*len(refs))
	for _, r := range refs {
		out = append(out, "--ref", r)
	}

	return out
}

// TestVerifyBaseRecorded is the issue's done-when, on the recorded
// store. Not parallel: it swaps the forge seam.
func TestVerifyBaseRecorded(t *testing.T) {
	swapBaseForge(t, gh.Snapshot{Dir: "testdata/base-images"})

	root := publicGood(t)

	tests := []struct {
		name   string
		signer string
		refs   []string
		code   int
		want   []string
	}{
		{
			name: "verified at latest", refs: []string{latestRef}, code: exitOK,
			want: []string{
				"verify base: approved first-party base: " + latestRef + " (produced at refs/heads/main)",
				"verify: PASS",
			},
		},
		{
			// The image is not named after its repository: the owner's
			// store is read, never one derived from the image's name.
			name: "verified at a decorated version tag", refs: []string{labPgRef}, code: exitOK,
			want: []string{
				"verify base: approved first-party base: " + labPgRef + " (produced at refs/tags/v0.28.4)",
				"verify: PASS",
			},
		},
		{
			// Signed at b7469566 and at 0d6c6e29, and the policy pins
			// neither: a base is signed at whatever signer its own
			// release pinned (the canon's measured e4a285f8 vs e90a971e).
			name: "two bases signed at two signer commits, in one build", refs: []string{latestRef, labPgRef},
			code: exitOK, want: []string{"(produced at refs/heads/main)", "(produced at refs/tags/v0.28.4)", "verify: PASS"},
		},
		{
			name: "no digest", refs: []string{"ghcr.io/monumental-archive/lab-pg:0.28.4-pg18-artifact"},
			code: exitRefused,
			want: []string{
				"ghcr.io/monumental-archive/lab-pg:0.28.4-pg18-artifact is a first-party base with no digest" +
					" — there is nothing to verify; pin as image:tag@sha256:…",
				"verify: FAIL",
			},
		},
		{
			name: "no tag", refs: []string{"ghcr.io/monumental-archive/lab-pg@" + labPgDigest}, code: exitRefused,
			want: []string{
				"ghcr.io/monumental-archive/lab-pg@" + labPgDigest + " carries a digest but no tag, so the ref that" +
					" produced it cannot be derived — pin as image:tag@sha256:… (Renovate rolls both together)",
			},
		},
		{
			name: "an undecodable tag", refs: []string{"ghcr.io/monumental-archive/lab-pg:nightly@" + labPgDigest},
			code: exitRefused,
			want: []string{"cannot derive the ref that produced it from tag 'nightly' — the declared tags are ^latest$"},
		},
		{
			name: "signed by another workflow", signer: "monumental-archive/signer/.github/workflows/sign-other.yml",
			refs: []string{labPgRef}, code: exitRefused,
			want: []string{
				"no https://slsa.dev/provenance/v1 attestation verifies for these bytes at refs/tags/v0.28.4 — a" +
					" first-party base is verified before it is instantiated (.github#715)",
				"trust: verify",
			},
		},
		{
			// The tag claims 0.28.3; the bytes were built at v0.28.4.
			name: "built at another ref", refs: []string{"ghcr.io/monumental-archive/lab-pg:0.28.3-pg18-artifact@" +
				labPgDigest},
			code: exitRefused,
			want: []string{
				"at refs/tags/v0.28.3 — a first-party base is verified before it is instantiated",
				`trust: certificate source ref "refs/tags/v0.28.4" is not "refs/tags/v0.28.3"`,
			},
		},
		{
			// .github#715: bytes nobody attested are refused before they
			// are used, not merely pinned.
			name: "bytes nobody attested", refs: []string{"ghcr.io/monumental-archive/release-lab:latest@sha256:" +
				strings.Repeat("1", 64)},
			code: exitRefused,
			want: []string{"before it is instantiated (.github#715): the store holds no attestation for this subject"},
		},
		{
			name: "outside the prefix, not judged", refs: []string{debianRef}, code: exitOK,
			want: []string{
				"verify base: not judged: " + debianRef + " — no declared scope's prefix or upstream entry claims it",
				"verify base: no base to judge — none of the 1 reference(s) is under a declared scope or upstream entry",
			},
		},
		{
			name: "outside the prefix, beside a judged base", refs: []string{debianRef, latestRef}, code: exitOK,
			want: []string{"verify base: not judged: " + debianRef, "verify: PASS"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := orgSigner
			if tt.signer != "" {
				signer = tt.signer
			}

			code, stdout, stderr := runBase(t, basePolicy(signer), append(refArgs(tt.refs...), "--trusted-root",
				root)...)
			if code != tt.code {
				t.Fatalf("code = %d, want %d\nstdout: %s\nstderr: %s", code, tt.code, stdout, stderr)
			}

			for _, w := range tt.want {
				if !strings.Contains(stdout, w) {
					t.Errorf("stdout lacks %q\nstdout: %s", w, stdout)
				}
			}
		})
	}
}

// baseReport is the part of the report document these rows read.
type baseReport struct {
	Verdict    *string `json:"verdict"`
	Population *struct {
		Size     *int `json:"size"`
		Expected *int `json:"expected"`
	} `json:"population"`
	Facts []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"facts"`
}

// TestVerifyBaseJSON: with --json the one document is the sealed
// report, over the claimed references alone — the base nothing claims
// is named on the progress stream and counted nowhere.
func TestVerifyBaseJSON(t *testing.T) {
	swapBaseForge(t, gh.Snapshot{Dir: "testdata/base-images"})

	code, stdout, stderr := runBase(t, basePolicy(orgSigner),
		append(refArgs(debianRef, labPgRef, labPgRef), "--trusted-root", publicGood(t), "--json")...)
	if code != exitOK {
		t.Fatalf("code = %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	doc, err := jsonx.DecodeForeign[baseReport]([]byte(stdout))
	if err != nil {
		t.Fatalf("stdout is not one report document: %v\n%s", err, stdout)
	}

	// One base named twice is instantiated once, and judged once.
	if *doc.Verdict != "PASS" || *doc.Population.Size != 1 || *doc.Population.Expected != 1 {
		t.Fatalf("report = %s", stdout)
	}

	if len(doc.Facts) != 1 || doc.Facts[0].Name != "produced:"+labPgRef || doc.Facts[0].Value != "refs/tags/v0.28.4" {
		t.Fatalf("facts = %+v", doc.Facts)
	}

	if !strings.Contains(stderr, "verify base: not judged: "+debianRef) {
		t.Fatalf("stderr = %s, want the unclaimed base named", stderr)
	}
}

// TestVerifyBaseNothingToJudge: a build with no claimed reference
// exits 0 and says why, and seals no verdict — with --json, no
// document at all, because PASS over no subject is a pass nothing
// earned, and CANNOT_JUDGE would contradict the exit.
func TestVerifyBaseNothingToJudge(t *testing.T) {
	t.Parallel()

	const (
		scratch = "verify base: no base to judge — the build names no base reference (scratch, or stages only)\n"
		outside = "verify base: not judged: " + debianRef + " — no declared scope's prefix or upstream entry claims it\n"
		noneOf  = "verify base: no base to judge — none of the 1 reference(s) is under a declared scope or" +
			" upstream entry\n"
	)

	tests := []struct {
		name                   string
		args                   []string
		wantStdout, wantStderr string
	}{
		{"FROM scratch", nil, scratch, ""},
		{"FROM scratch, as JSON", []string{"--json"}, "", scratch},
		{"every reference outside", refArgs(debianRef), outside + noneOf, ""},
		{"one outside reference named twice", refArgs(debianRef, debianRef), outside + noneOf, ""},
		{"every reference outside, as JSON", append(refArgs(debianRef), "--json"), "", outside + noneOf},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := runBase(t, basePolicy(orgSigner), tt.args...)
			if code != exitOK || stdout != tt.wantStdout || stderr != tt.wantStderr {
				t.Fatalf("code = %d\nstdout: %q, want %q\nstderr: %q, want %q",
					code, stdout, tt.wantStdout, stderr, tt.wantStderr)
			}
		})
	}
}

// TestVerifyBaseUsage holds every refusal the mode makes before it
// judges anything, each by its message.
func TestVerifyBaseUsage(t *testing.T) {
	t.Parallel()

	const noSection = `{"schema": 9, "evidence": {"sbomSuffix": ".spdx.json", "checksums": "checksums.txt",
	  "umbrellaBundle": "attestations.intoto.jsonl", "manifestAsset": "evidence-manifest.json",
	  "classes": {"oci-image": {"bundles": ["attestations-image.intoto.jsonl"]}}}}`

	tests := []struct {
		name   string
		policy string
		args   []string
		want   string
	}{
		{"an unexpected argument", "", []string{"x"}, `unexpected argument "x" — every reference is passed as --ref`},
		{"an empty reference", "", []string{"--ref", " "}, "an empty --ref is refused rather than dropped"},
		{"a binding with no value", "", []string{"--bind", "major"}, `--bind "major" is not <group>=<value>`},
		{"a binding with no group", "", []string{"--bind", "=14"}, `--bind "=14" is not <group>=<value>`},
		{
			"one group bound twice", "",
			[]string{"--bind", "major=14", "--bind", "major=15"},
			`--bind names group "major" twice — one group, one value`,
		},
		{"an unknown flag", "", []string{"--refs", pgBaseRef}, "flag provided but not defined: -refs"},
		{"a policy that does not load", `{"schema": 9}`, nil, "assert: policy:"},
		{"a policy with no base section", noSection, nil, "declares no evidence.baseImages section — there is" +
			" nothing to judge a base against"},
		{
			"facts asked of no upstream reference", "", append(refArgs(latestRef), "--facts-out", "f.json"),
			"--bind and --facts-out describe one upstream image, and 0 of the references are under an upstream entry",
		},
		{
			"a binding over two upstream references", "",
			append(refArgs(pgBaseRef, strings.Replace(pgBaseRef, "14-", "15-", 1)), "--bind", "major=14"),
			"and 2 of the references are under an upstream entry",
		},
		{
			"a binding naming a group the pattern does not capture", "",
			append(refArgs(pgBaseRef), "--bind", "variant=x"),
			pgBaseRef + `: --bind names "variant", which docker.io/library/postgres's tag pattern`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := tt.policy
			if doc == "" {
				doc = basePolicy(orgSigner)
			}

			code, stdout, stderr := runBase(t, doc, tt.args...)
			if code != exitUsage || stdout != "" || !strings.Contains(stderr, tt.want) {
				t.Fatalf("code = %d, stdout %q\nstderr: %s\nwant the refusal %q", code, stdout, stderr, tt.want)
			}
		})
	}

	var stderr bytes.Buffer

	if code := Run([]string{"verify", "base"}, &bytes.Buffer{}, &stderr); code != exitUsage ||
		stderr.String() != "stele verify base: --assert-policy is required\n" {
		t.Fatalf("no policy: code %d, stderr %q", code, stderr.String())
	}

	stderr.Reset()

	if code := Run([]string{"verify", "base", "--assert-policy", filepath.Join(t.TempDir(), "absent.json")},
		&bytes.Buffer{}, &stderr); code != exitUsage || !strings.Contains(stderr.String(), "absent.json") {
		t.Fatalf("an absent policy: code %d, stderr %q", code, stderr.String())
	}
}

// TestVerifyBaseTrustGuards: a first-party reference owes trust
// material, and a root that cannot be read, or that builds no
// verifier, refuses before anything is judged. Not parallel: the
// second row swaps nothing, but the first resolves a root from disk
// beside tests that swap the verifier seam.
func TestVerifyBaseTrustGuards(t *testing.T) {
	code, _, stderr := runBase(t, basePolicy(orgSigner),
		append(refArgs(latestRef), "--trusted-root", "/no/such/root.json")...)
	if code != exitUsage || !strings.Contains(stderr, "/no/such/root.json") {
		t.Fatalf("an unreadable root: code %d, stderr %q", code, stderr)
	}

	code, _, stderr = runBase(t, basePolicy(orgSigner),
		append(refArgs(latestRef), "--trusted-root", writeFile(t, "root.json", "not a root"))...)
	if code != exitUsage || !strings.Contains(stderr, "stele verify base: trusted root:") {
		t.Fatalf("a root that builds no verifier: code %d, stderr %q", code, stderr)
	}

	// An upstream reference alone owes none: its provenance is
	// unsigned, so no root is read and a bad one is never noticed.
	swapStatements(t, statementsFor(upstreamPlatforms(pgUpstreamURI)))

	if code, stdout, stderr := runBase(t, basePolicy(orgSigner),
		append(refArgs(pgBaseRef), "--trusted-root", "/no/such/root.json")...); code != exitOK {
		t.Fatalf("an upstream reference read a root: code %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
}

// TestVerifyBaseBlind: a store or registry the run could not read is
// CANNOT_JUDGE, never a finding about the base. Not parallel: it swaps
// the forge and the registry seams.
func TestVerifyBaseBlind(t *testing.T) {
	swapBaseForge(t, &storeForge{err: gh.ErrForbidden})

	orig := newBundleVerifier
	newBundleVerifier = func([]byte) (verify.BundleVerifier, error) { return attestorBV{}, nil }

	t.Cleanup(func() { newBundleVerifier = orig })

	root := writeFile(t, "root.json", `{"any": "bytes — the seam swallows them"}`)

	code, stdout, stderr := runBase(t, basePolicy(orgSigner), append(refArgs(latestRef), "--trusted-root", root)...)
	if code != exitBlind || !strings.Contains(stdout, "the credential cannot read "+latestRef) ||
		!strings.Contains(stdout, "verify: CANNOT_JUDGE") ||
		!strings.Contains(stderr, "the run could not see enough to judge") {
		t.Fatalf("an unreadable store: code %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	swapStatements(t, statementsFor(nil, errors.New("connection refused")))

	code, stdout, _ = runBase(t, basePolicy(orgSigner), refArgs(pgBaseRef)...)
	if code != exitBlind || !strings.Contains(stdout, "verify: reading "+pgBaseRef+"'s provenance: connection refused") {
		t.Fatalf("an unreadable registry: code %d\nstdout: %s", code, stdout)
	}
}

const pgUpstreamURI = "https://github.com/docker-library/postgres.git#9becbc9d:14/bookworm"

// scriptedStatements scripts the registry's provenance read.
type scriptedStatements struct {
	platforms []oci.PlatformStatements
	err       error
}

func (s scriptedStatements) Statements(_, _, _ string) ([]oci.PlatformStatements, error) {
	return s.platforms, s.err
}

func statementsFor(platforms []oci.PlatformStatements, err ...error) scriptedStatements {
	s := scriptedStatements{platforms: platforms}
	if len(err) > 0 {
		s.err = err[0]
	}

	return s
}

// upstreamPlatforms is two platforms whose provenance names uri.
func upstreamPlatforms(uri string) []oci.PlatformStatements {
	st := []byte(`{"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://slsa.dev/provenance/v0.2",` +
		` "predicate": {"invocation": {"configSource": {"uri": "` + uri + `"}}}}`)

	return []oci.PlatformStatements{
		{Platform: "linux/amd64", Statements: [][]byte{st}},
		{Platform: "linux/arm64/v8", Statements: [][]byte{st}},
	}
}

// TestVerifyBaseUpstream drives the upstream half the base-approval
// run calls: the caller's binding held, every platform judged (#212),
// and the facts written only for a verified image. Not parallel: it
// swaps the registry seam.
func TestVerifyBaseUpstream(t *testing.T) {
	t.Run("verified, the facts written", func(t *testing.T) {
		swapStatements(t, statementsFor(upstreamPlatforms(pgUpstreamURI)))

		facts := filepath.Join(t.TempDir(), "upstream.json")

		code, stdout, stderr := runBase(t, basePolicy(orgSigner),
			append(refArgs(pgBaseRef), "--bind", "major=14", "--facts-out", facts)...)
		if code != exitOK || !strings.Contains(stdout,
			"verify base: "+pgBaseRef+": upstream provenance verified across 2 platform(s)") {
			t.Fatalf("code %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}

		got, err := os.ReadFile(facts) //nolint:gosec // the test's own temp file
		if err != nil {
			t.Fatal(err)
		}

		want := `{"sources":["` + pgUpstreamURI + `"],"platforms":["linux/amd64","linux/arm64/v8"],` +
			`"provenanceType":"https://slsa.dev/provenance/v0.2"}`
		if strings.Join(strings.Fields(string(got)), "") != want {
			t.Fatalf("facts = %s, want %s", got, want)
		}
	})

	t.Run("one platform naming another directory (#212)", func(t *testing.T) {
		platforms := upstreamPlatforms(pgUpstreamURI)
		platforms[1].Statements = upstreamPlatforms(strings.Replace(pgUpstreamURI, "bookworm", "bullseye", 1))[1].
			Statements
		swapStatements(t, statementsFor(platforms))

		facts := filepath.Join(t.TempDir(), "upstream.json")

		code, stdout, _ := runBase(t, basePolicy(orgSigner), append(refArgs(pgBaseRef), "--facts-out", facts)...)
		if code != exitRefused || !strings.Contains(stdout, "linux/arm64/v8's provenance names") {
			t.Fatalf("code %d\nstdout: %s", code, stdout)
		}

		if _, err := os.Stat(facts); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("facts were written for an image that failed: %v", err)
		}
	})

	t.Run("a binding the tag disagrees with", func(t *testing.T) {
		swapStatements(t, statementsFor(upstreamPlatforms(pgUpstreamURI)))

		code, stdout, _ := runBase(t, basePolicy(orgSigner), append(refArgs(pgBaseRef), "--bind", "major=15")...)
		if code != exitRefused || !strings.Contains(stdout, `the tag's major is "14", the caller bound "15"`) {
			t.Fatalf("code %d\nstdout: %s", code, stdout)
		}
	})

	t.Run("facts that cannot be written", func(t *testing.T) {
		swapStatements(t, statementsFor(upstreamPlatforms(pgUpstreamURI)))

		code, _, stderr := runBase(t, basePolicy(orgSigner),
			append(refArgs(pgBaseRef), "--facts-out", t.TempDir())...)
		if code != exitIO || !strings.Contains(stderr, "stele verify base: --facts-out:") {
			t.Fatalf("code %d\nstderr: %s", code, stderr)
		}
	})
}

// TestVerifyBaseWriteFailures sweeps every write each path makes: the
// gate must not exit 0 after failing to say what it judged.
func TestVerifyBaseWriteFailures(t *testing.T) {
	swapBaseForge(t, gh.Snapshot{Dir: "testdata/base-images"})
	swapStatements(t, statementsFor(upstreamPlatforms(pgUpstreamURI)))

	policy := writeFile(t, "assert-policy.json", basePolicy(orgSigner))
	root := publicGood(t)

	for _, args := range [][]string{
		nil,
		refArgs(debianRef),
		refArgs(debianRef, latestRef),
		append(refArgs(latestRef), "--json"),
		refArgs("ghcr.io/monumental-archive/lab-pg:nightly@" + labPgDigest),
		append(refArgs(pgBaseRef), "--facts-out", filepath.Join(t.TempDir(), "facts.json")),
		append(refArgs(latestRef), "--facts-out", "facts.json"),
	} {
		sweepWriteFailures(t, append([]string{"verify", "base", "--assert-policy", policy, "--trusted-root", root},
			args...))
	}
}
