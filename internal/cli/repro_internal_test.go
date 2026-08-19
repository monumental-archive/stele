// Wiring tests for `stele verify repro` (stele#96): the tri-state
// exit contract, the usage refusals, and the population rule — an
// empty subject population is CANNOT_JUDGE, never PASS.
//
// The released manifest arrives WHOLE (stele#156). Two shapes reach
// this verb — a typed evidence manifest, whose entries say which
// assets are build subjects, and a legacy or foreign sha256sum
// manifest, classified through the org's declared vocabulary — and
// both must land on the same population, because the engine, not the
// caller, is what knows the difference.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const digestA = "1111111111111111111111111111111111111111111111111111111111111111"

const digestB = "2222222222222222222222222222222222222222222222222222222222222222"

// reproManifests writes a released and a rebuilt manifest and returns
// their paths.
func reproManifests(t *testing.T, released, rebuilt string) (string, string) { //nolint:gocritic // two paths
	t.Helper()

	dir := t.TempDir()
	sub := filepath.Join(dir, "released.txt")
	reb := filepath.Join(dir, "rebuilt.txt")

	if err := os.WriteFile(sub, []byte(released), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(reb, []byte(rebuilt), 0o600); err != nil {
		t.Fatal(err)
	}

	return sub, reb
}

// reproPolicy writes the evidence vocabulary an untyped manifest is
// classified through.
func reproPolicy(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "assert-policy.json")
	if err := os.WriteFile(path, []byte(manifestPolicyJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// typedManifest renders a released manifest that types its own
// entries — what `emit manifest` writes.
func typedManifest(entries string) string {
	return `{"schema": 2, "classes": ["go-binary"], "storeVsa": true, ` +
		`"machineryVersion": "1.40.0", "entries": [` + entries + `]}`
}

func typedEntry(name, digest, entryType string) string {
	return `{"name": "` + name + `", "sha256": "` + digest + `", "type": "` + entryType + `"}`
}

func TestVerifyReproPass(t *testing.T) {
	sub, reb := reproManifests(t,
		digestA+"  stele.tar.gz\n", digestA+"  stele.tar.gz\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "repro", "--repo", "acme/widget", "--tag", "v1.0.0",
		"--released", sub, "--rebuilt", reb, "--assert-policy", reproPolicy(t), "--json",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	doc := decodeReport(t, &stdout)
	if doc.Verdict == nil || *doc.Verdict != "PASS" {
		t.Fatalf("verdict = %v, want PASS", doc.Verdict)
	}
}

// The shape that exposed the defect: a release whose one artifact
// rebuilt bit-for-bit, published beside documents that CANNOT rebuild
// — a Sigstore bundle embeds a fresh timestamp on every signing.
// Handed the manifest whole, the walk judges the artifact alone.
func TestVerifyReproTakesTheReleasedManifestWhole(t *testing.T) {
	released := digestA + "  github-1.44.1.tar.gz\n" +
		digestB + "  attestations.intoto.jsonl\n" +
		digestB + "  evidence-manifest.json\n" +
		digestB + "  github-1.44.1.spdx.json\n" +
		digestB + "  checksums.txt\n"

	sub, reb := reproManifests(t, released, digestA+"  github-1.44.1.tar.gz\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "repro", "--repo", "acme/widget", "--tag", "v1.44.1",
		"--released", sub, "--rebuilt", reb, "--assert-policy", reproPolicy(t), "--json",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d — the evidence documents were judged as artifacts\nstdout: %s\nstderr: %s",
			code, stdout.String(), stderr.String())
	}

	doc := decodeReport(t, &stdout)
	if doc.Verdict == nil || *doc.Verdict != "PASS" || len(doc.Findings) != 0 {
		t.Fatalf("verdict = %v with %d finding(s), want PASS and none", doc.Verdict, len(doc.Findings))
	}

	if doc.Population == nil || doc.Population.Size == nil || *doc.Population.Size != 1 {
		t.Fatalf("population = %+v, want the one build subject", doc.Population)
	}
}

// A typed manifest is READ, never re-classified: the entry's type
// decides the population even where no naming convention would, and
// no --policy is needed or consulted.
func TestVerifyReproReadsTheManifestTyping(t *testing.T) {
	released := typedManifest(
		typedEntry("odd-name-no-convention-would-match", digestA, "build-subject") + ", " +
			// Named exactly like an artifact, typed as a document.
			typedEntry("widget-linux-amd64.tar.gz", digestB, "evidence"))

	sub, reb := reproManifests(t, released, digestA+"  odd-name-no-convention-would-match\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "repro", "--repo", "acme/widget", "--tag", "v1.0.0",
		"--released", sub, "--rebuilt", reb, "--json",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	doc := decodeReport(t, &stdout)
	if doc.Verdict == nil || *doc.Verdict != "PASS" {
		t.Fatalf("verdict = %v, want PASS", doc.Verdict)
	}
}

// A typed manifest this build refuses REFUSES the walk — it never
// falls through to the text parser, which would launder a version
// skew into a differently-worded failure.
func TestVerifyReproRefusesAManifestItCannotRead(t *testing.T) {
	sub, reb := reproManifests(t,
		`{"schema": 1, "classes": ["go-binary"], "storeVsa": true, "machineryVersion": "1.0.0"}`,
		digestA+"  a.tar.gz\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "repro", "--repo", "acme/widget", "--tag", "v1.0.0",
		"--released", sub, "--rebuilt", reb, "--assert-policy", reproPolicy(t),
	}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitUsage, stderr.String())
	}

	if !strings.Contains(stderr.String(), "schema 1 is not 2") {
		t.Fatalf("stderr = %q, want the format's own refusal", stderr.String())
	}
}

func TestVerifyReproDivergenceFails(t *testing.T) {
	sub, reb := reproManifests(t,
		digestA+"  stele.tar.gz\n", digestB+"  stele.tar.gz\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "repro", "--repo", "acme/widget", "--tag", "v1.0.0",
		"--released", sub, "--rebuilt", reb, "--assert-policy", reproPolicy(t),
	}, &stdout, &stderr)
	if code != exitRefused {
		t.Fatalf("Run = %d, want %d\nstdout: %s", code, exitRefused, stdout.String())
	}

	if !strings.Contains(stdout.String(), "repro/diverged") {
		t.Errorf("stdout = %q, want the typed divergence", stdout.String())
	}
}

// A repro claim over nothing is not a proof — whichever way the
// population emptied: an empty manifest, or one whose every entry is
// a document.
func TestVerifyReproEmptySubjectPopulationCannotJudge(t *testing.T) {
	for name, released := range map[string]string{
		"an empty manifest":           "",
		"documents alone, untyped":    digestB + "  attestations.intoto.jsonl\n",
		"documents alone, self-typed": typedManifest(typedEntry("attestations.intoto.jsonl", digestB, "evidence")),
	} {
		t.Run(name, func(t *testing.T) {
			sub, reb := reproManifests(t, released, digestA+"  stele.tar.gz\n")

			var stdout, stderr bytes.Buffer

			code := Run([]string{
				"verify", "repro", "--repo", "acme/widget", "--tag", "v1.0.0",
				"--released", sub, "--rebuilt", reb, "--assert-policy", reproPolicy(t),
			}, &stdout, &stderr)
			if code != exitBlind {
				t.Fatalf("Run = %d, want %d — comparing nothing proves nothing\nstdout: %s",
					code, exitBlind, stdout.String())
			}
		})
	}
}

func TestVerifyReproUsageRefusals(t *testing.T) {
	sub, reb := reproManifests(t, digestA+"  a\n", digestA+"  a\n")
	pol := reproPolicy(t)

	junk := filepath.Join(t.TempDir(), "junk.txt")
	if err := os.WriteFile(junk, []byte("not a manifest line\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rows := [][]string{
		{"verify", "repro", "--tag", "v1", "--released", sub, "--rebuilt", reb, "--assert-policy", pol},
		{
			"verify", "repro", "--repo", "solo", "--tag", "v1",
			"--released", sub, "--rebuilt", reb, "--assert-policy", pol,
		},
		{"verify", "repro", "--repo", "a/b", "--released", sub, "--rebuilt", reb, "--assert-policy", pol},
		{"verify", "repro", "--repo", "a/b", "--tag", "v1", "--rebuilt", reb, "--assert-policy", pol},
		{"verify", "repro", "--repo", "a/b", "--tag", "v1", "--released", sub, "--assert-policy", pol},
		// An untyped manifest with no vocabulary to classify it: the
		// population would have to be guessed, and guessing it is the
		// defect this verb was rebuilt to remove.
		{"verify", "repro", "--repo", "a/b", "--tag", "v1", "--released", sub, "--rebuilt", reb},
		{
			"verify", "repro", "--repo", "a/b", "--tag", "v1",
			"--released", "/no/such", "--rebuilt", reb, "--assert-policy", pol,
		},
		{
			"verify", "repro", "--repo", "a/b", "--tag", "v1",
			"--released", sub, "--rebuilt", "/no/such", "--assert-policy", pol,
		},
		{
			"verify", "repro", "--repo", "a/b", "--tag", "v1",
			"--released", junk, "--rebuilt", reb, "--assert-policy", pol,
		},
		{
			"verify", "repro", "--repo", "a/b", "--tag", "v1",
			"--released", sub, "--rebuilt", reb, "--assert-policy", "/no/such",
		},
		{
			"verify", "repro", "--repo", "a/b", "--tag", "v1",
			"--released", sub, "--rebuilt", reb, "--assert-policy", junk,
		},
		{"verify", "repro", "--conjure"},
	}

	for _, args := range rows {
		t.Run(strings.Join(args[2:], " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := Run(args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("Run = %d, want %d; stderr: %s", code, exitUsage, stderr.String())
			}
		})
	}
}
