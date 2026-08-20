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
//
// A rebuild covering ONE class narrows that population with --class
// (stele#185), and the narrowing is honoured only where the released
// manifest can answer it. Every combination of "was a class asked
// for" and "can this manifest say" gets a row, because the two ways
// of getting it wrong are opposite and both silent: a whole-release
// verdict read as a per-class one blames a class for artifacts
// nobody rebuilt, and a per-class verdict read as a whole-release one
// claims coverage it never had.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// muslX86 is the canary target the weekly rebuild covers — the one
// value release-lab v0.26.0's rust-binary matrix declares by default.
const muslX86 = "x86_64-unknown-linux-musl"

const digestA = "1111111111111111111111111111111111111111111111111111111111111111"

const digestB = "2222222222222222222222222222222222222222222222222222222222222222"

const digestC = "4444444444444444444444444444444444444444444444444444444444444444"

const digestD = "5555555555555555555555555555555555555555555555555555555555555555"

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
	return classedManifest([]string{"go-binary"}, entries)
}

// classedManifest is typedManifest for a release shipping more than
// one class — the shape a per-class rebuild scopes into.
func classedManifest(classes []string, entries string) string {
	return `{"schema": 4, "classes": ["` + strings.Join(classes, `", "`) + `"], "storeVsa": true, ` +
		`"machineryVersion": "1.49.0", "entries": [` + entries + `]}`
}

// preTargetManifest is a manifest from before entries named the
// target that produced them — a real published asset, immutable, that
// says which class built each artifact and cannot say which target
// (stele#223).
func preTargetManifest(entries string) string {
	return `{"schema": 3, "classes": ["rust-binary"], "storeVsa": true, ` +
		`"machineryVersion": "1.40.0", "entries": [` + entries + `]}`
}

// typedEntry renders one entry; class and target are empty for a
// document about the release, which belongs to no one build leg, and
// for a fixture at a schema that never carried them.
func typedEntry(name, digest, entryType, class, target string) string {
	entry := `{"name": "` + name + `", "sha256": "` + digest + `", "type": "` + entryType + `"`
	if class != "" {
		entry += `, "class": "` + class + `"`
	}

	if target != "" {
		entry += `, "target": "` + target + `"`
	}

	return entry + `}`
}

// legacyTypedManifest is a manifest from before entries named their
// class — a real published asset, immutable, that this build still
// reads for what it says (stele#185).
func legacyTypedManifest(entries string) string {
	return `{"schema": 2, "classes": ["go-binary", "oci-image"], "storeVsa": true, ` +
		`"machineryVersion": "1.40.0", "entries": [` + entries + `]}`
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
		typedEntry("odd-name-no-convention-would-match", digestA, "build-subject", "go-binary", "linux-amd64") + ", " +
			// Named exactly like an artifact, typed as a document.
			typedEntry("widget-linux-amd64.tar.gz", digestB, "evidence", "", ""))

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
		`{"schema": 99, "classes": ["go-binary"], "storeVsa": true, "machineryVersion": "1.0.0"}`,
		digestA+"  a.tar.gz\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "repro", "--repo", "acme/widget", "--tag", "v1.0.0",
		"--released", sub, "--rebuilt", reb, "--assert-policy", reproPolicy(t),
	}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitUsage, stderr.String())
	}

	if !strings.Contains(stderr.String(), "not a manifest schema this build reads") {
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
		"an empty manifest":        "",
		"documents alone, untyped": digestB + "  attestations.intoto.jsonl\n",
		"documents alone, self-typed": typedManifest(
			typedEntry("attestations.intoto.jsonl", digestB, "evidence", "", "")),
		// A manifest from before entries existed lists nothing, so it
		// is a population of zero — an honest CANNOT_JUDGE, and the
		// reason the canon hands those releases their checksum
		// manifest instead (stele#185).
		"a manifest from before entries existed": `{"schema": 1, "classes": ["go-binary"], ` +
			`"storeVsa": true, "machineryVersion": "1.0.0"}`,
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

// factValue reads one fact off a sealed report, so a row can assert
// what the verdict SAYS it covered rather than infer it from a count.
func factValue(t *testing.T, doc *jsonReportDoc, name string) string {
	t.Helper()

	got, ok := optionalFact(doc, name)
	if !ok {
		t.Fatalf("no %s fact on the verdict: %+v", name, doc.Facts)
	}

	return got
}

// optionalFact reads a fact that may legitimately be absent — the
// absence IS an answer for classScopeUnmet, so a row must be able to
// assert it rather than only its value.
func optionalFact(doc *jsonReportDoc, name string) (string, bool) {
	for _, f := range doc.Facts {
		if f.Name == name {
			return f.Value, true
		}
	}

	return "", false
}

// The defect, measured: release-lab v0.25.3 rebuilt ONE class and the
// walk judged all fourteen artifacts, reporting the other thirteen as
// absent from a rebuild that never covered them — two supply-chain
// issues filed against a release that was fine (stele#185). Scoped by
// class, the population is that class's artifacts and the verdict
// says nothing about the rest.
func TestVerifyReproScopesToTheClassUnderRebuild(t *testing.T) {
	released := classedManifest([]string{"rust-binary", "pgrx-extension"},
		typedEntry("lab-x86_64-linux.tar.gz", digestA, "build-subject", "rust-binary", muslX86)+", "+
			typedEntry("lab-aarch64-darwin.tar.gz", digestB, "build-subject", "rust-binary", "aarch64-apple-darwin")+", "+
			typedEntry("lab_pg-pg17-linux-amd64.tar.gz", digestC, "build-subject", "pgrx-extension", "pg17-amd64")+", "+
			typedEntry("attestations-extensions.intoto.jsonl", digestD, "evidence", "", ""))

	// The pgrx leg alone rebuilt: the rust binaries are absent from
	// this rebuild by design, not by defect.
	sub, reb := reproManifests(t, released, digestC+"  lab_pg-pg17-linux-amd64.tar.gz\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "repro", "--repo", "acme/lab", "--tag", "v0.25.3",
		"--released", sub, "--rebuilt", reb, "--class", "pgrx-extension", "--json",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d — a class nobody rebuilt was judged\nstdout: %s\nstderr: %s",
			code, stdout.String(), stderr.String())
	}

	doc := decodeReport(t, &stdout)
	if doc.Verdict == nil || *doc.Verdict != "PASS" || len(doc.Findings) != 0 {
		t.Fatalf("verdict = %v with %d finding(s), want PASS and none", doc.Verdict, len(doc.Findings))
	}

	if doc.Population == nil || doc.Population.Size == nil || *doc.Population.Size != 1 {
		t.Fatalf("population = %+v, want the one artifact that class built", doc.Population)
	}

	if doc.Population.Detail == nil || !strings.Contains(*doc.Population.Detail, "pgrx-extension") {
		t.Errorf("population detail = %v, want the scope named", doc.Population.Detail)
	}

	if got := factValue(t, doc, "classScope"); got != "pgrx-extension" {
		t.Errorf("classScope = %q, want the class the rebuild covered", got)
	}
}

// Scoping narrows the population; it does not mute it. An artifact of
// the class under rebuild that the rebuild failed to produce is still
// a finding — the v0.25.3 darwin case stays true.
func TestVerifyReproScopeStaysLoudInsideItsClass(t *testing.T) {
	released := classedManifest([]string{"rust-binary", "pgrx-extension"},
		typedEntry("lab-x86_64-linux.tar.gz", digestA, "build-subject", "rust-binary", muslX86)+", "+
			typedEntry("lab-aarch64-darwin.tar.gz", digestB, "build-subject", "rust-binary", "aarch64-apple-darwin")+", "+
			typedEntry("lab_pg-pg17-linux-amd64.tar.gz", digestC, "build-subject", "pgrx-extension", "pg17-amd64"))

	sub, reb := reproManifests(t, released, digestA+"  lab-x86_64-linux.tar.gz\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "repro", "--repo", "acme/lab", "--tag", "v0.25.3",
		"--released", sub, "--rebuilt", reb, "--class", "rust-binary", "--json",
	}, &stdout, &stderr)
	if code != exitRefused {
		t.Fatalf("Run = %d, want %d\nstdout: %s", code, exitRefused, stdout.String())
	}

	doc := decodeReport(t, &stdout)
	if len(doc.Findings) != 1 || !strings.Contains(doc.Findings[0].Assertion, "absent-from-rebuild") {
		t.Fatalf("findings = %+v, want the darwin artifact named", doc.Findings)
	}

	if doc.Findings[0].Subject != "lab-aarch64-darwin.tar.gz" {
		t.Errorf("finding subject = %q, want the artifact of the class under rebuild", doc.Findings[0].Subject)
	}
}

// What the verdict COVERS is stated, never inferred — and stated as
// TWO facts, because what the population covers and why that is not
// what was asked are two different things. A single value a reader
// has to split at a separator is two facts wearing one name, which is
// the shape this org refuses everywhere else.
//
// So `classScope` is always the population's own scope, and
// `classScopeUnmet` appears ONLY when a request went unhonoured: its
// absence is the answer in the two clean cases, and every row asserts
// that absence rather than leaving it untested.
func TestVerifyReproStatesWhatItCovered(t *testing.T) {
	oneSubject := digestA + "  widget-linux-amd64.tar.gz\n"

	tests := []struct {
		name      string
		released  string
		class     string
		wantScope string
		wantUnmet string
	}{
		{
			"no class asked: the whole release",
			typedManifest(typedEntry("widget-linux-amd64.tar.gz", digestA, "build-subject", "go-binary", "linux-amd64")),
			"", "whole-release", "",
		},
		{
			"a class asked and answered",
			typedManifest(typedEntry("widget-linux-amd64.tar.gz", digestA, "build-subject", "go-binary", "linux-amd64")),
			"go-binary", "go-binary", "",
		},
		{
			// A published manifest from before entries named their
			// class. Immutable, attested by digest at its tag, and
			// still perfectly able to say which assets are artifacts —
			// just not which class built one.
			"a class asked of a manifest that predates the answer",
			legacyTypedManifest(
				`{"name": "widget-linux-amd64.tar.gz", "sha256": "` + digestA + `", "type": "build-subject"}`),
			"go-binary", "whole-release", "no-class-answer",
		},
		{
			// A sha256sum manifest names assets and nothing else.
			"a class asked of a manifest with no typing at all",
			oneSubject, "go-binary", "whole-release", "no-class-answer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, reb := reproManifests(t, tt.released, oneSubject)

			args := []string{
				"verify", "repro", "--repo", "acme/widget", "--tag", "v1.0.0",
				"--released", sub, "--rebuilt", reb, "--assert-policy", reproPolicy(t), "--json",
			}
			if tt.class != "" {
				args = append(args, "--class", tt.class)
			}

			var stdout, stderr bytes.Buffer

			if code := Run(args, &stdout, &stderr); code != exitOK {
				t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
			}

			doc := decodeReport(t, &stdout)
			if got := factValue(t, doc, "classScope"); got != tt.wantScope {
				t.Fatalf("classScope = %q, want %q", got, tt.wantScope)
			}

			// The absence of the unmet fact is itself the answer, so
			// the clean rows assert it is not there at all.
			unmet, present := optionalFact(doc, "classScopeUnmet")
			if want := tt.wantUnmet != ""; present != want {
				t.Fatalf("classScopeUnmet present = %v, want %v: %+v", present, want, doc.Facts)
			}

			if present && unmet != tt.wantUnmet {
				t.Fatalf("classScopeUnmet = %q, want %q", unmet, tt.wantUnmet)
			}

			if doc.Population == nil || doc.Population.Size == nil || *doc.Population.Size != 1 {
				t.Fatalf("population = %+v, want the one build subject either way", doc.Population)
			}

			// Loud on stderr too: a caller that asked for one class and
			// got the whole release reads it, never deduces it.
			said := strings.Contains(stderr.String(), "carries no class answer")
			if want := tt.wantUnmet != ""; said != want {
				t.Errorf("stderr said-it-could-not-scope = %v, want %v: %s", said, want, stderr.String())
			}
		})
	}
}

// A class the release never shipped refuses rather than sealing over
// the population of zero it would otherwise draw: zero is an honest
// CANNOT_JUDGE for a class that built nothing, and a misspelling that
// seals the same way is a verdict nobody asked for.
func TestVerifyReproRefusesAClassTheReleaseNeverShipped(t *testing.T) {
	sub, reb := reproManifests(t,
		typedManifest(typedEntry("widget-linux-amd64.tar.gz", digestA, "build-subject", "go-binary", "linux-amd64")),
		digestA+"  widget-linux-amd64.tar.gz\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "repro", "--repo", "acme/widget", "--tag", "v1.0.0",
		"--released", sub, "--rebuilt", reb, "--class", "go-binaries",
	}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitUsage, stderr.String())
	}

	if !strings.Contains(stderr.String(), "declared no class") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

// A class that shipped but published nowhere on the release — an
// image pushed to a registry — is an empty population, which seals
// CANNOT_JUDGE. That is the answer, not the absence of one.
func TestVerifyReproScopedToAClassThatShipsNoAssets(t *testing.T) {
	released := classedManifest([]string{"go-binary", "oci-image"},
		typedEntry("widget-linux-amd64.tar.gz", digestA, "build-subject", "go-binary", "linux-amd64"))

	sub, reb := reproManifests(t, released, digestA+"  widget-linux-amd64.tar.gz\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "repro", "--repo", "acme/widget", "--tag", "v1.0.0",
		"--released", sub, "--rebuilt", reb, "--class", "oci-image", "--json",
	}, &stdout, &stderr)
	if code != exitBlind {
		t.Fatalf("Run = %d, want %d\nstdout: %s", code, exitBlind, stdout.String())
	}

	doc := decodeReport(t, &stdout)
	if got := factValue(t, doc, "classScope"); got != "oci-image" {
		t.Errorf("classScope = %q — an empty population is still a class answer", got)
	}
}

// The defect this scoping exists for, measured: release-lab v0.26.0
// published four rust-binary artifacts and the weekly rebuild covers
// ONE target. Scoped by class alone the walk judged all four and
// reported the three nobody asked it to rebuild as absent — FAIL over
// a release that was fine, filed weekly (stele#223).
//
// Both directions in one test, because the fix is the declaration and
// not a mute: undeclared, the same healthy rebuild still fails over
// artifacts nobody rebuilt; declared, the population is the target
// under test and the verdict is clean.
func TestVerifyReproScopesToTheDeclaredTargets(t *testing.T) {
	released := classedManifest([]string{"rust-binary"},
		typedEntry("lab-x86_64-linux.tar.gz", digestA, "build-subject", "rust-binary", muslX86)+", "+
			typedEntry("lab-aarch64-linux.tar.gz", digestB, "build-subject", "rust-binary",
				"aarch64-unknown-linux-musl")+", "+
			typedEntry("lab-x86_64-darwin.tar.gz", digestC, "build-subject", "rust-binary",
				"x86_64-apple-darwin")+", "+
			typedEntry("lab-aarch64-darwin.tar.gz", digestD, "build-subject", "rust-binary",
				"aarch64-apple-darwin"))

	// The canary rebuild, healthy: the one target it covered, at the
	// digest the release published.
	sub, reb := reproManifests(t, released, digestA+"  lab-x86_64-linux.tar.gz\n")

	base := []string{
		"verify", "repro", "--repo", "acme/lab", "--tag", "v0.26.0",
		"--released", sub, "--rebuilt", reb, "--class", "rust-binary", "--json",
	}

	t.Run("declaring no target judges the whole class, as it did", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		if code := Run(base, &stdout, &stderr); code != exitRefused {
			t.Fatalf("Run = %d, want %d\nstdout: %s", code, exitRefused, stdout.String())
		}

		if doc := decodeReport(t, &stdout); len(doc.Findings) != 3 {
			t.Fatalf("findings = %+v, want the three artifacts nobody rebuilt", doc.Findings)
		}
	})

	t.Run("declaring the target under test judges that target", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		if code := Run(append(base, "--targets", muslX86), &stdout, &stderr); code != exitOK {
			t.Fatalf("Run = %d — artifacts nobody rebuilt were judged\nstdout: %s\nstderr: %s",
				code, stdout.String(), stderr.String())
		}

		doc := decodeReport(t, &stdout)
		if doc.Verdict == nil || *doc.Verdict != "PASS" || len(doc.Findings) != 0 {
			t.Fatalf("verdict = %v with %d finding(s), want PASS and none", doc.Verdict, len(doc.Findings))
		}

		// The population is the DECLARATION, not the artifact count: it
		// is what the caller said was under test, and a target it could
		// not place would short-cover it.
		pop := doc.Population
		if pop == nil || pop.Size == nil || *pop.Size != 1 || pop.Expected == nil || *pop.Expected != 1 {
			t.Fatalf("population = %+v, want the one declared target answered", pop)
		}

		if pop.Source == nil || *pop.Source != "declared" {
			t.Errorf("population source = %v, want the declaration named as the source", pop.Source)
		}

		if got := factValue(t, doc, "targetScope"); got != muslX86 {
			t.Errorf("targetScope = %q, want the declared target", got)
		}

		// The artifact count still rides, because the seal now counts
		// targets and a reader must not have to infer how many artifacts
		// that came to.
		if got := factValue(t, doc, "judgedArtifacts"); got != "1" {
			t.Errorf("judgedArtifacts = %q, want the one artifact that target built", got)
		}

		if got := factValue(t, doc, "classScope"); got != "rust-binary" {
			t.Errorf("classScope = %q — the class narrowing still stands beside the target one", got)
		}
	})
}

// Narrowing to a target does not mute it. The partial-rebuild
// inversion stele#96 exists to catch cannot regress here, because the
// declaration precedes the rebuild: a declared target that produced
// nothing, and one that produced the wrong bytes, are both loud.
func TestVerifyReproDeclaredTargetStaysLoud(t *testing.T) {
	released := classedManifest([]string{"rust-binary"},
		typedEntry("lab-x86_64-linux.tar.gz", digestA, "build-subject", "rust-binary", muslX86)+", "+
			typedEntry("lab-x86_64-musl-debug.tar.gz", digestB, "build-subject", "rust-binary", muslX86)+", "+
			typedEntry("lab-aarch64-darwin.tar.gz", digestC, "build-subject", "rust-binary",
				"aarch64-apple-darwin"))

	tests := []struct {
		name          string
		rebuilt       string
		wantAssertion string
		wantSubject   string
	}{
		{
			// One of the declared target's two artifacts is missing from
			// a rebuild that claimed to cover it.
			"an artifact the declared target did not produce",
			digestA + "  lab-x86_64-linux.tar.gz\n",
			"repro/absent-from-rebuild", "lab-x86_64-musl-debug.tar.gz",
		},
		{
			"an artifact the declared target rebuilt to other bytes",
			digestA + "  lab-x86_64-linux.tar.gz\n" + digestD + "  lab-x86_64-musl-debug.tar.gz\n",
			"repro/diverged", "lab-x86_64-musl-debug.tar.gz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, reb := reproManifests(t, released, tt.rebuilt)

			var stdout, stderr bytes.Buffer

			code := Run([]string{
				"verify", "repro", "--repo", "acme/lab", "--tag", "v0.26.0",
				"--released", sub, "--rebuilt", reb, "--class", "rust-binary", "--targets", muslX86, "--json",
			}, &stdout, &stderr)
			if code != exitRefused {
				t.Fatalf("Run = %d, want %d\nstdout: %s", code, exitRefused, stdout.String())
			}

			doc := decodeReport(t, &stdout)
			if len(doc.Findings) != 1 || doc.Findings[0].Assertion != tt.wantAssertion {
				t.Fatalf("findings = %+v, want one %s", doc.Findings, tt.wantAssertion)
			}

			if doc.Findings[0].Subject != tt.wantSubject {
				t.Errorf("finding subject = %q, want %q", doc.Findings[0].Subject, tt.wantSubject)
			}
		})
	}
}

// A declared target the release cannot place is CANNOT_JUDGE, named
// — never silence, and never a pass over the targets that did answer.
// The three ways a release fails to place one are opposite in cause
// and identical in shape, so each gets a row and each carries the
// cause a reader would act on.
func TestVerifyReproDeclaredTargetTheReleaseCannotPlace(t *testing.T) {
	tests := []struct {
		name      string
		released  string
		targets   string
		wantCause string
	}{
		{
			// A release published before targets were typed. The fix is
			// the publisher's.
			"a manifest that predates the target answer",
			preTargetManifest(
				typedEntry("lab-x86_64-linux.tar.gz", digestA, "build-subject", "rust-binary", "")),
			muslX86, "types no targets",
		},
		{
			// A sha256sum manifest names assets and nothing else.
			"a manifest with no typing at all",
			digestA + "  lab-x86_64-linux.tar.gz\n",
			muslX86, "types no targets",
		},
		{
			// The manifest types targets and carries no artifact of this
			// one: a matrix value nobody built. The fix is the caller's.
			"a target this release never built",
			classedManifest([]string{"rust-binary"},
				typedEntry("lab-x86_64-linux.tar.gz", digestA, "build-subject", "rust-binary", muslX86)),
			"riscv64gc-unknown-linux-gnu", "was built for this target",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, reb := reproManifests(t, tt.released, digestA+"  lab-x86_64-linux.tar.gz\n")

			var stdout, stderr bytes.Buffer

			code := Run([]string{
				"verify", "repro", "--repo", "acme/lab", "--tag", "v0.26.0",
				"--released", sub, "--rebuilt", reb, "--assert-policy", reproPolicy(t),
				"--targets", tt.targets, "--json",
			}, &stdout, &stderr)
			if code != exitBlind {
				t.Fatalf("Run = %d, want %d — an unplaceable target is not a judgment\nstdout: %s",
					code, exitBlind, stdout.String())
			}

			doc := decodeReport(t, &stdout)
			if doc.Verdict == nil || *doc.Verdict != "CANNOT_JUDGE" {
				t.Fatalf("verdict = %v, want CANNOT_JUDGE", doc.Verdict)
			}

			// By NAME: a count cannot say which target went unjudged.
			if len(doc.Findings) != 1 || doc.Findings[0].Assertion != "repro/target-not-typed" {
				t.Fatalf("findings = %+v, want the target named", doc.Findings)
			}

			if doc.Findings[0].Subject != tt.targets {
				t.Errorf("finding subject = %q, want the declared target", doc.Findings[0].Subject)
			}

			if !strings.Contains(doc.Findings[0].Detail, tt.wantCause) {
				t.Errorf("finding detail = %q, want it to carry %q", doc.Findings[0].Detail, tt.wantCause)
			}
		})
	}
}

// The other direction of the same guard: a declaration one target of
// which the release cannot place does not pass over the one it can.
// Partial sight is reported, never laundered into either verdict.
func TestVerifyReproPartlyPlaceableDeclarationCannotJudge(t *testing.T) {
	released := classedManifest([]string{"rust-binary"},
		typedEntry("lab-x86_64-linux.tar.gz", digestA, "build-subject", "rust-binary", muslX86))

	sub, reb := reproManifests(t, released, digestA+"  lab-x86_64-linux.tar.gz\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "repro", "--repo", "acme/lab", "--tag", "v0.26.0", "--released", sub, "--rebuilt", reb,
		"--targets", muslX86 + ",riscv64gc-unknown-linux-gnu", "--json",
	}, &stdout, &stderr)
	if code != exitBlind {
		t.Fatalf("Run = %d, want %d\nstdout: %s", code, exitBlind, stdout.String())
	}

	doc := decodeReport(t, &stdout)

	pop := doc.Population
	if pop == nil || pop.Size == nil || *pop.Size != 1 || pop.Expected == nil || *pop.Expected != 2 {
		t.Fatalf("population = %+v, want one of two declared targets answered", pop)
	}

	if got := factValue(t, doc, "targetScope"); got != muslX86+",riscv64gc-unknown-linux-gnu" {
		t.Errorf("targetScope = %q, want the whole declaration whatever answered", got)
	}
}

// An undeclared target produces NOTHING — no finding, no count, no
// cell. The artifact the rebuild did not produce is one nobody
// claimed to have rebuilt, so there is nothing to say about it, and
// saying something quieter instead is how the false-finding class was
// born.
func TestVerifyReproUndeclaredTargetProducesNothing(t *testing.T) {
	released := classedManifest([]string{"rust-binary"},
		typedEntry("lab-x86_64-linux.tar.gz", digestA, "build-subject", "rust-binary", muslX86)+", "+
			typedEntry("lab-aarch64-darwin.tar.gz", digestB, "build-subject", "rust-binary",
				"aarch64-apple-darwin"))

	sub, reb := reproManifests(t, released, digestA+"  lab-x86_64-linux.tar.gz\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "repro", "--repo", "acme/lab", "--tag", "v0.26.0",
		"--released", sub, "--rebuilt", reb, "--targets", muslX86, "--json",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	out := stdout.String()
	if strings.Contains(out, "lab-aarch64-darwin.tar.gz") {
		t.Errorf("the undeclared target's artifact reached the verdict: %s", out)
	}

	if got := factValue(t, decodeReport(t, &stdout), "judgedArtifacts"); got != "1" {
		t.Errorf("judgedArtifacts = %q, want the undeclared target counted nowhere", got)
	}
}

// A declaration with a hole in it is not one: an empty element is
// refused rather than dropped, because a split that swallowed it
// would narrow the judged population by exactly the value nobody
// noticed was missing.
func TestVerifyReproRefusesADeclarationWithAHole(t *testing.T) {
	released := classedManifest([]string{"rust-binary"},
		typedEntry("lab-x86_64-linux.tar.gz", digestA, "build-subject", "rust-binary", muslX86))

	sub, reb := reproManifests(t, released, digestA+"  lab-x86_64-linux.tar.gz\n")

	for _, targets := range []string{muslX86 + ",", ",", muslX86 + "," + muslX86} {
		t.Run(targets, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := Run([]string{
				"verify", "repro", "--repo", "acme/lab", "--tag", "v0.26.0",
				"--released", sub, "--rebuilt", reb, "--targets", targets,
			}, &stdout, &stderr)
			if code != exitUsage {
				t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitUsage, stderr.String())
			}
		})
	}
}

// A manifest that cannot say which class built an artifact cannot say
// which target did either, so a caller that asked for both reads what
// the population became: a declaration it can place nothing in, never
// a silent widening to every build subject the release published.
func TestVerifyReproUnmetClassSaysWhatTheTargetsBecame(t *testing.T) {
	released := legacyTypedManifest(
		`{"name": "lab-x86_64-linux.tar.gz", "sha256": "` + digestA + `", "type": "build-subject"}`)

	sub, reb := reproManifests(t, released, digestA+"  lab-x86_64-linux.tar.gz\n")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "repro", "--repo", "acme/lab", "--tag", "v0.26.0", "--released", sub, "--rebuilt", reb,
		"--class", "go-binary", "--targets", muslX86, "--json",
	}, &stdout, &stderr)
	if code != exitBlind {
		t.Fatalf("Run = %d, want %d\nstdout: %s", code, exitBlind, stdout.String())
	}

	if !strings.Contains(stderr.String(), "can place no declared target either") {
		t.Errorf("stderr = %q, want the population it became stated", stderr.String())
	}

	doc := decodeReport(t, &stdout)
	if got := factValue(t, doc, "classScopeUnmet"); got != "no-class-answer" {
		t.Errorf("classScopeUnmet = %q, want the class request named unhonoured beside it", got)
	}

	if len(doc.Findings) != 1 || doc.Findings[0].Assertion != "repro/target-not-typed" {
		t.Fatalf("findings = %+v, want the unplaceable target named", doc.Findings)
	}
}
