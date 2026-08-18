// The file-backed inputs, read and refused before anything verifies,
// signs or writes. Every row breaks one input and names the refusal:
// an input read wrong is the failure that produces a confident verdict
// over the wrong bytes.

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/verify"
)

// TestVerifyInputRefusals walks every file input of the release modes.
// The trusted-root row runs with the REAL constructor in place, because
// that guard is the only one a swapped seam hides.
func TestVerifyInputRefusals(t *testing.T) {
	px := files(t)

	blank := filepath.Join(t.TempDir(), "blank.sha256")
	if err := os.WriteFile(blank, []byte("\n"+subjectSHA+"  app.tar.gz\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	notAManifest := filepath.Join(t.TempDir(), "bad.sha256")
	if err := os.WriteFile(notAManifest, []byte("no two spaces here\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	base := []string{
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", "v1.2.3",
		"--signer-digest", strings.Repeat("a", 40), "--machinery-digest", strings.Repeat("b", 40),
	}

	cases := []struct {
		name    string
		args    []string
		want    string
		theReal bool // run without the swapped trust seam
	}{
		{
			name: "a trusted root that is not one",
			args: append([]string{"verify", "vsa", "--subjects", px.subjects}, base...),
			want: "trusted root", theReal: true,
		},
		{
			name: "an unreadable subject manifest",
			args: append([]string{"verify", "vsa", "--subjects", "/no/such/subjects.sha256"}, base...),
			want: "subjects.sha256",
		},
		{
			name: "a subject manifest that is not one",
			args: append([]string{"verify", "vsa", "--subjects", notAManifest}, base...),
			want: "not a sha256sum record",
		},
		{
			name: "release mode without an sbom manifest",
			args: append([]string{"verify", "release", "--subjects", px.subjects}, base...),
			want: "--sboms is required",
		},
		{
			name: "an unreadable sbom manifest",
			args: append([]string{
				"verify", "release", "--subjects", px.subjects, "--sboms", "/no/such/sboms.sha256",
			}, base...),
			want: "sboms.sha256",
		},
		{
			name: "an sbom manifest that is not one",
			args: append([]string{"verify", "release", "--subjects", px.subjects, "--sboms", notAManifest}, base...),
			want: "not a sha256sum record",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.theReal {
				swap(t, scriptedBV{}, scriptedStore{})
			}

			var stdout, stderr bytes.Buffer

			if code := Run(tc.args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitUsage, stderr.String())
			}

			if !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("stderr = %q, want it to name %q", stderr.String(), tc.want)
			}
		})
	}

	// Blank lines are the manifest format's own noise — sha256sum
	// output ends in one — so they are skipped, not refused.
	t.Run("blank lines in a manifest are skipped", func(t *testing.T) {
		swap(t, scriptedBV{payload: []byte(vsaStatement)}, scriptedStore{})

		var stdout, stderr bytes.Buffer

		code := Run(append([]string{"verify", "vsa", "--subjects", blank}, base...), &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("Run = %d, stderr: %s", code, stderr.String())
		}
	})
}

// TestVerifyWalkRefusalSealsTheBranchPopulation: a refused walk still
// reports what it HAD under test — one branch ref — because a
// population of zero would seal CANNOT_JUDGE and hide the refusal.
func TestVerifyWalkRefusalSealsTheBranchPopulation(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})

	px := files(t)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "chain", "--json",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--git-dir", t.TempDir(),
	}, &stdout, &stderr)
	if code != exitRefused {
		t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitRefused, stderr.String())
	}

	doc := decodeReport(t, &stdout)
	if doc.Verdict == nil || *doc.Verdict != "FAIL" {
		t.Fatalf("verdict = %v, want FAIL", doc.Verdict)
	}

	if doc.Population == nil || doc.Population.Size == nil || *doc.Population.Size != 1 {
		t.Fatalf("population = %+v, want the one branch ref under walk", doc.Population)
	}
}

// TestEmitInputRefusals walks the emit verb's file inputs the same
// way, including the trusted-root guard with the real constructor.
func TestEmitInputRefusals(t *testing.T) {
	px := files(t)

	notAPolicy := filepath.Join(t.TempDir(), "not-a-policy.json")
	if err := os.WriteFile(notAPolicy, []byte(`{"schema": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		args    []string
		want    string
		theReal bool
	}{
		{
			name: "an unreadable policy",
			args: []string{
				"emit", "vsa", "--repo", "acme/widget",
				"--policy", "/no/such/policy.json", "--trusted-root", px.root,
			},
			want: "policy.json",
		},
		{
			name: "a policy that is not one",
			args: []string{"emit", "vsa", "--repo", "acme/widget", "--policy", notAPolicy, "--trusted-root", px.root},
			want: "policy",
		},
		{
			name: "an unreadable trusted root",
			args: []string{
				"emit", "vsa", "--repo", "acme/widget", "--policy", px.policy,
				"--trusted-root", "/no/such/root.json",
			},
			want: "root.json",
		},
		{
			name: "a trusted root that is not one",
			args: []string{
				"emit", "vsa", "--repo", "acme/widget", "--policy", px.policy, "--trusted-root", px.root,
			},
			want: "trusted root", theReal: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.theReal {
				swap(t, scriptedBV{}, scriptedStore{})
			}

			var stdout, stderr bytes.Buffer

			if code := Run(tc.args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitUsage, stderr.String())
			}

			if !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("stderr = %q, want it to name %q", stderr.String(), tc.want)
			}
		})
	}
}

// TestEmitChainUnwritableStaging: cosign reads and writes through a
// staging directory, so a run that cannot make one must refuse before
// anything is signed — never sign into a path that does not exist.
func TestEmitChainUnwritableStaging(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})
	swapEmit(t, &fakeEmitGit{notes: map[string][]byte{}}, nil)

	px, claims := emitFiles(t)

	// TMPDIR is where MkdirTemp looks; a path that is not there makes
	// the staging directory impossible.
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))

	var stdout, stderr bytes.Buffer

	code := Run(chainArgs(px, claims), &stdout, &stderr)
	if code != exitRefused || !strings.Contains(stderr.String(), "staging directory") {
		t.Fatalf("Run = %d, stderr %q — want the staging refusal", code, stderr.String())
	}
}

// TestEmitStreamGuards sweeps the emit verb's writes: a passing chain
// emission, a refused one, and the usage refusals.
func TestEmitStreamGuards(t *testing.T) {
	t.Run("a passing chain emission", func(t *testing.T) {
		swap(t, scriptedBV{}, scriptedStore{})

		g := &fakeEmitGit{notes: map[string][]byte{}}
		swapEmit(t, g, nil)

		px, claims := emitFiles(t)

		// A genesis emission appends a note, and a second genesis over
		// the same history is refused by design — so each attempt gets
		// a fresh history.
		sweepWriteFailuresReseeding(t, chainArgs(px, claims), func() {
			g.notes = map[string][]byte{}
		})
	})

	t.Run("a refused chain emission", func(t *testing.T) {
		swap(t, scriptedBV{}, scriptedStore{})
		swapEmit(t, nil, errors.New("not a repository"))

		px, claims := emitFiles(t)
		sweepWriteFailures(t, chainArgs(px, claims))
	})

	t.Run("a usage refusal", func(t *testing.T) {
		swap(t, scriptedBV{}, scriptedStore{})
		sweepWriteFailures(t, []string{"emit", "vsa", "--repo", "solo"})
	})
}

// TestDeriveVersionPrereleaseBase: a namespace whose latest release is
// a prerelease has no base to measure a bump from — the refusal names
// it rather than inventing one.
func TestDeriveVersionPrereleaseBase(t *testing.T) {
	hist := releaseHistory()
	hist.tags = []string{"v1.0.0-rc.1"}
	withHistory(t, hist, nil)

	var stdout, stderr bytes.Buffer

	code := deriveCmd([]string{"version", "--git-dir", "."}, &stdout, &stderr)
	if code != exitRefused || !strings.Contains(stderr.String(), "prerelease") {
		t.Fatalf("deriveCmd = %d, stderr %q — want the prerelease refusal", code, stderr.String())
	}
}

// TestDeriveStreamGuardsOverAFailingHistory sweeps the two derive
// modes' refusal writes, which only exist once the derivation itself
// has failed.
func TestDeriveStreamGuardsOverAFailingHistory(t *testing.T) {
	t.Run("version", func(t *testing.T) {
		hist := releaseHistory()
		hist.tagsErr = errors.New("git said no")
		withHistory(t, hist, nil)
		sweepWriteFailures(t, []string{"derive", "version", "--git-dir", "."})
	})

	t.Run("notes", func(t *testing.T) {
		hist := releaseHistory()
		hist.tagsErr = errors.New("git said no")
		withHistory(t, hist, nil)
		sweepWriteFailures(t, []string{"derive", "notes", "--git-dir", "."})
	})

	t.Run("a passing notes render", func(t *testing.T) {
		withHistory(t, releaseHistory(), nil)
		sweepWriteFailures(t, []string{"derive", "notes", "--git-dir", "."})
	})

	t.Run("a passing version derivation", func(t *testing.T) {
		withHistory(t, releaseHistory(), nil)
		sweepWriteFailures(t, []string{"derive", "version", "--git-dir", "."})
	})
}

// TestNotesRenderRefusals walks the notes mode's own guards: an ordering the
// groups contradict, a release date the history cannot supply, and a
// changelog path that cannot be written.
func TestNotesRenderRefusals(t *testing.T) {
	t.Run("an ordering that names a heading twice", func(t *testing.T) {
		got := runNotes(t, releaseHistory(), "--group-order", "Added,Added")
		if got.code != exitRefused || !strings.Contains(got.stderr, "ordered twice") {
			t.Fatalf("code = %d, stderr %q — want the ordering refusal", got.code, got.stderr)
		}
	})

	t.Run("a history that cannot date the release", func(t *testing.T) {
		hist := releaseHistory()
		hist.timeErr = errors.New("no committer date")

		got := runNotes(t, hist)
		if got.code != exitRefused || !strings.Contains(got.stderr, "no committer date") {
			t.Fatalf("code = %d, stderr %q — want the date refusal", got.code, got.stderr)
		}
	})

	t.Run("a changelog path that cannot be written", func(t *testing.T) {
		absent := filepath.Join(t.TempDir(), "absent", "CHANGELOG.md")

		got := runNotes(t, releaseHistory(), "--changelog", absent)
		if got.code != exitRefused || !strings.Contains(got.stderr, "CHANGELOG.md") {
			t.Fatalf("code = %d, stderr %q — want the write refusal", got.code, got.stderr)
		}
	})
}

// swapHistory points the chain walk at a scripted history for one
// test, leaving the other seams as swap() installed them.
func swapHistory(t *testing.T, h verify.History) {
	t.Helper()

	orig := openHistory
	openHistory = func(string, string) (verify.History, error) { return h, nil }

	t.Cleanup(func() { openHistory = orig })
}

// TestChainWalkAcceptsWhatTheEmitterWrote is the cross-leg law in one
// test: the note this binary's emit verb appends is the note its
// verify verb walks. The world is the emitter's own — no
// hand-assembled link — so a format change that broke one leg and not
// the other would fail here rather than in a ledger.
func TestChainWalkAcceptsWhatTheEmitterWrote(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})

	g := &fakeEmitGit{notes: map[string][]byte{}}
	swapEmit(t, g, nil)

	px, claims := emitFiles(t)

	var emitOut, emitErr bytes.Buffer

	if code := Run(chainArgs(px, claims), &emitOut, &emitErr); code != exitOK {
		t.Fatalf("emitting the genesis link = %d, stderr: %s", code, emitErr.String())
	}

	// The emitter's own history is the walker's: Tip, Parent, Note and
	// Noted are the four reads both legs share.
	swapHistory(t, g)

	t.Run("chain reports the link count", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"verify", "chain", "--json",
			"--policy", px.policy, "--trusted-root", px.root,
			"--repo", "acme/widget", "--git-dir", "ignored-by-the-seam",
		}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}

		doc := decodeReport(t, &stdout)
		if doc.Verdict == nil || *doc.Verdict != "PASS" {
			t.Fatalf("verdict = %v, want PASS", doc.Verdict)
		}

		if factOf(doc, "links") != "1" {
			t.Fatalf("links = %q, want the one emitted link", factOf(doc, "links"))
		}
	})

	t.Run("level adds the computed source level", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"verify", "level", "--json",
			"--policy", px.policy, "--trusted-root", px.root,
			"--repo", "acme/widget", "--git-dir", "ignored-by-the-seam",
		}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("Run = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
		}

		doc := decodeReport(t, &stdout)

		level := factOf(doc, "sourceLevel")
		if !strings.HasPrefix(level, "SLSA_SOURCE_LEVEL_") {
			t.Fatalf("sourceLevel = %q, want a computed source level", level)
		}

		if !strings.Contains(stderr.String(), "SOURCE "+level) {
			t.Errorf("stderr = %q, want the level line naming %s", stderr.String(), level)
		}
	})

	t.Run("chain mode reports no level", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		code := Run([]string{
			"verify", "chain", "--json",
			"--policy", px.policy, "--trusted-root", px.root,
			"--repo", "acme/widget", "--git-dir", "ignored-by-the-seam",
		}, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("Run = %d, stderr: %s", code, stderr.String())
		}

		if got := factOf(decodeReport(t, &stdout), "sourceLevel"); got != "" {
			t.Fatalf("chain mode reported sourceLevel %q — only level mode computes one", got)
		}
	})
}

// factOf reads one named fact from a report document, "" when absent.
func factOf(doc *jsonReportDoc, name string) string {
	for _, f := range doc.Facts {
		if f.Name == name {
			return f.Value
		}
	}

	return ""
}

// failingTip is a history whose ref cannot be resolved: the clone
// opened, the walk cannot start.
type failingTip struct{ verify.History }

func (failingTip) Tip(string) (string, error) { return "", errNoSuchRef }

func (failingTip) Parent(string) (string, error) { return "", nil }
func (failingTip) Note(string) ([]byte, error)   { return nil, nil }
func (failingTip) Noted() ([]string, error)      { return nil, nil }

var errNoSuchRef = errors.New("no such ref in this clone")

// TestVerifyWalkRefusesAfterOpening separates the two ways a walk
// fails: the clone that cannot be opened (covered elsewhere) and the
// clone that opens and then refuses. Both must exit as refusals, and
// the second is the one a swapped-open seam hides.
func TestVerifyWalkRefusesAfterOpening(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})
	swapHistory(t, failingTip{})

	px := files(t)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "chain",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--git-dir", "ignored-by-the-seam",
	}, &stdout, &stderr)
	if code != exitRefused || !strings.Contains(stderr.String(), "no such ref") {
		t.Fatalf("Run = %d, stderr %q — want the walk refusal", code, stderr.String())
	}
}

// TestVerifyLevelRefusesAnUndeclaredBranch: the policy names which
// branches carry a level, and level mode over any other ref has
// nothing to compute against — the refusal is the honest answer, never
// a default level.
func TestVerifyLevelRefusesAnUndeclaredBranch(t *testing.T) {
	swap(t, scriptedBV{}, scriptedStore{})

	g := &fakeEmitGit{notes: map[string][]byte{}}
	swapEmit(t, g, nil)

	px, claims := emitFiles(t)

	var emitOut, emitErr bytes.Buffer

	if code := Run(chainArgs(px, claims), &emitOut, &emitErr); code != exitOK {
		t.Fatalf("emitting the genesis link = %d, stderr: %s", code, emitErr.String())
	}

	swapHistory(t, g)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"verify", "level",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--git-dir", "ignored-by-the-seam",
		"--ref", "refs/heads/other",
	}, &stdout, &stderr)
	if code != exitRefused {
		t.Fatalf("Run = %d, want %d\nstderr: %s", code, exitRefused, stderr.String())
	}
}

// TestEmitVSARefusesAnUnnameablePolicy: the VSA must name where a
// stranger reads the policy it was judged against, so a run that
// cannot say refuses rather than emitting a verdict nobody can check.
func TestEmitVSARefusesAnUnnameablePolicy(t *testing.T) {
	w := newReleaseWorld(t)
	swap(t, w.bv, w.store)

	px := files(t)
	subjects, sboms := w.manifests(t)

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"emit", "vsa",
		"--policy", px.policy, "--trusted-root", px.root,
		"--repo", "acme/widget", "--tag", relTag,
		"--subjects", subjects, "--sboms", sboms,
		"--signer-digest", strings.Repeat("a", 40), "--machinery-digest", strings.Repeat("b", 40),
	}, &stdout, &stderr)
	if code != exitRefused || !strings.Contains(stderr.String(), "predicate") {
		t.Fatalf("Run = %d, stderr %q — want the predicate refusal", code, stderr.String())
	}
}

// TestLoaderStreamGuards sweeps the three input loaders' own refusal
// writes: each reports a malformed committed file, and each has its own
// stream guard.
func TestLoaderStreamGuards(t *testing.T) {
	t.Run("a malformed debt file", func(t *testing.T) {
		_, policy := evidenceSnapshot(t)

		debt := filepath.Join(t.TempDir(), "debt.txt")
		if err := os.WriteFile(debt, []byte("no parentheses here\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		sweepWriteFailures(t, []string{
			"assert", "evidence", "--org", "acme", "--policy", policy, "--debt", debt,
		})
	})

	t.Run("a vex path that is not a directory", func(t *testing.T) {
		_, policy, _ := blastSnapshot(t)

		notADir := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}

		sweepWriteFailures(t, []string{
			"assert", "blast-radius", "--org", "acme", "--policy", policy, "--vex", notADir,
		})
	})

	t.Run("signing epochs with no trusted root", func(t *testing.T) {
		_, policy := tagsSnapshot(t)

		sweepWriteFailures(t, []string{"assert", "tags", "--repo", "acme/widget", "--policy", policy})
	})
}

// TestDeriveSBOMStreamGuards sweeps the sbom mode's refusal write,
// which exists only once the derivation itself has failed.
func TestDeriveSBOMStreamGuards(t *testing.T) {
	notABinary := filepath.Join(t.TempDir(), "not-a-binary")
	if err := os.WriteFile(notABinary, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sweepWriteFailures(t, []string{"derive", "sbom", notABinary})
}
