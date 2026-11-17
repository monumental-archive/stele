package assert_test

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/report"
)

// Where the two real certificates sit in the reconciliation's small
// log. The finding subject is the index in the log that was read, so
// these are what the findings name.
const (
	releaseAt = 7
	vexAt     = 19
	smallLog  = 30
)

// reconcileHarness is a small log holding one real certificate.
func reconcileHarness(t *testing.T, which int) *harness {
	t.Helper()

	at := releaseAt
	if which == vexIndex {
		at = vexAt
	}

	return newHarness(t, withLeaf(fillerLeaves(smallLog), at, capturedLeaf(t, which)))
}

// claimsOf is the claims a finding about a real certificate carries.
func claimsOf(which int) string {
	if which == vexIndex {
		return "build_config_uri=https://github.com/monumental-archive/.github/.github/workflows/vex-attest.yml" +
			"@refs/heads/main, build_signer_digest=" + vexSigner
	}

	return "build_config_uri=https://github.com/monumental-archive/.github/.github/workflows/self-publish.yml" +
		"@refs/tags/v1.67.0, build_signer_digest=" + releaseSigner
}

// assertOneFinding: the run is FAIL with exactly one finding, on the
// named condition, saying the message and carrying the claims read.
func assertOneFinding(t *testing.T, rep *report.Report, at, which int, condition, message string) {
	t.Helper()

	if rep.Verdict() != report.VerdictFail {
		t.Fatalf("verdict = %s, want FAIL; findings %+v", rep.Verdict(), rep.Findings())
	}

	findings := rep.Findings()
	if len(findings) != 1 {
		t.Fatalf("%d findings, want exactly one on %s: %+v", len(findings), condition, findings)
	}

	f := findings[0]

	if f.Subject != fmt.Sprintf("CT index %d", at) || f.Assertion != condition {
		t.Fatalf("finding is %s(%s), want CT index %d(%s)", f.Subject, f.Assertion, at, condition)
	}

	for _, want := range []string{message, "claims read: " + claimsOf(which), fmt.Sprintf("CT index %d of ", at)} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("finding detail %q\nwant it to say %q", f.Detail, want)
		}
	}
}

// Both real signings reconcile, each through its own chain link, and
// the run's log says how.
func TestSignerReconcilesBothRealSignings(t *testing.T) {
	t.Parallel()

	cases := []struct {
		which int
		line  string
	}{
		{
			which: releaseIndex,
			line: fmt.Sprintf("reconciled CT index %d: run https://github.com/%s/actions/runs/%s "+
				"(.github/workflows/self-publish.yml, push); chain %s/.github/workflows/publish.yml@%s calls "+
				"%s@%s; signer %s on default branch",
				releaseAt, captureCanon, releaseRun, captureCanon, releaseSHA[:12], captureSignYML,
				releaseSigner[:12], releaseSigner[:12]),
		},
		{
			which: vexIndex,
			line: fmt.Sprintf("reconciled CT index %d: run https://github.com/%s/actions/runs/%s "+
				"(.github/workflows/vex-attest.yml, push); chain %s/.github/workflows/vex-attest.yml@%s calls "+
				"%s@%s; signer %s on default branch",
				vexAt, captureCanon, vexRun, captureCanon, vexSHA[:12], captureSignYML, vexSigner[:12], vexSigner[:12]),
		},
	}

	for _, tc := range cases {
		t.Run(strconv.Itoa(tc.which), func(t *testing.T) {
			t.Parallel()

			h := reconcileHarness(t, tc.which)

			rep, err := h.run(0)
			if err != nil {
				t.Fatal(err)
			}

			if rep.Verdict() != report.VerdictPass {
				t.Fatalf("verdict = %s, findings %+v", rep.Verdict(), rep.Findings())
			}

			if !slices.Contains(h.progress, "assert: signer-certificates: "+tc.line) {
				t.Fatalf("the run's log does not say %q:\n%s", tc.line, strings.Join(h.progress, "\n"))
			}
		})
	}
}

// One claim or forge answer changed per row; each names its condition,
// by name and by message (the canon's test_reconcile.py rows, ported).
func TestSignerConditions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		which     int
		edit      func(h *harness)
		condition string
		message   string
	}{
		{
			name:      "a run the forge answers 404 for",
			which:     releaseIndex,
			edit:      func(h *harness) { delete(h.forge.runs, runKey(captureCanon, releaseRun)) },
			condition: "run",
			message: fmt.Sprintf("run %s does not exist in %s (never existed, or deleted)",
				releaseRun, captureCanon),
		},
		{
			name:  "a run in a repository outside the population",
			which: releaseIndex,
			edit: func(h *harness) {
				h.pol = signersPolicy(h.t, h.log.url(), githubIssuer, oneSigner, []string{"signer", "stele"})
			},
			condition: "run",
			message:   captureCanon + " is not a repository of the population",
		},
		{
			name:  "a reusable workflow from outside the callers",
			which: releaseIndex,
			edit: func(h *harness) {
				run := h.forge.editRelease()
				run.Referenced = append(run.Referenced, run.Referenced[0])
				run.Referenced[len(run.Referenced)-1].Path = "someone-else/tools/.github/workflows/x.yml@" + otherSHA
			},
			condition: "foreign",
			message: "the run called someone-else/tools/.github/workflows/x.yml@" + otherSHA +
				", which is neither a callers repository's workflow nor the signer's",
		},
		{
			name:  "the signer called at another digest",
			which: releaseIndex,
			edit: func(h *harness) {
				run := h.forge.editRelease()
				for i := range run.Referenced {
					if strings.HasPrefix(run.Referenced[i].Path, captureSigner+"/") {
						run.Referenced[i].Path = strings.ReplaceAll(run.Referenced[i].Path, releaseSigner, otherSHA)
						run.Referenced[i].SHA = otherSHA
					}
				}
			},
			condition: "signer-in-run",
			message: fmt.Sprintf("the run called %s at %s, the certificate says %s",
				captureSignYML, otherSHA, releaseSigner),
		},
		{
			name:  "the callers' workflows off the default branch",
			which: releaseIndex,
			edit: func(h *harness) {
				h.forge.compare[compareKey(captureCanon, "main", releaseSHA)] = "diverged"
			},
			condition: "caller-branch",
			message: fmt.Sprintf("%s/.github/workflows/publish.yml at %s is not on %s's default branch",
				captureCanon, releaseSHA, captureCanon),
		},
		{
			name:  "no candidate pins the certificate's digest",
			which: releaseIndex,
			edit: func(h *harness) {
				path := ".github/workflows/publish.yml"
				text := h.forge.file(captureCanon, path, releaseSHA)
				h.forge.putFile(captureCanon, path, releaseSHA, strings.ReplaceAll(text, releaseSigner, otherSHA))
			},
			condition: "chain",
			message:   fmt.Sprintf("no callers workflow the run used calls %s@%s", captureSignYML, releaseSigner),
		},
		{
			name:  "a repository outside the callers calls the signer itself",
			which: releaseIndex,
			edit: func(h *harness) {
				run := h.forge.editRelease()
				run.Repository.FullName = "monumental-archive/stele"
				run.Path = ".github/workflows/release.yml"
				h.forge.putFile("monumental-archive/stele", run.Path, run.HeadSHA,
					"on: push\njobs:\n  sign:\n    uses: "+captureSignYML+"@"+releaseSigner+"\n")
			},
			condition: "direct",
			message: "monumental-archive/stele's .github/workflows/release.yml at " + releaseSHA +
				" calls the signer itself",
		},
		{
			name:  "a callers top-level run off the default branch",
			which: vexIndex,
			edit: func(h *harness) {
				h.forge.compare[compareKey(captureCanon, "main", vexSHA)] = "diverged"
			},
			condition: "caller-branch",
			message: fmt.Sprintf("%s/.github/workflows/vex-attest.yml at %s is not on %s's default branch",
				captureCanon, vexSHA, captureCanon),
		},
		{
			name:  "the signer commit off the signer's default branch",
			which: releaseIndex,
			edit: func(h *harness) {
				h.forge.compare[compareKey(captureSigner, "main", releaseSigner)] = "diverged"
			},
			condition: "signer-branch",
			message:   fmt.Sprintf("signer commit %s is not on %s's default branch", releaseSigner, captureSigner),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := reconcileHarness(t, tc.which)
			tc.edit(h)

			rep, err := h.run(0)
			if err != nil {
				t.Fatal(err)
			}

			at := releaseAt
			if tc.which == vexIndex {
				at = vexAt
			}

			assertOneFinding(t, rep, at, tc.which, tc.condition, tc.message)

			// A finding is a judgment: the checkpoint still advances.
			if h.lastSaved() != smallLog {
				t.Fatalf("the checkpoint is at %d, want %d — a finding does not hold it back", h.lastSaved(), smallLog)
			}
		})
	}
}

// Two signers: each certificate is matched to the entry its subject
// names and judged against THAT entry's callers — never the other's.
func TestSignerTwoSignersEachJudgedByItsOwnCallers(t *testing.T) {
	t.Parallel()

	const sourceSigner = "monumental-archive/signer/.github/workflows/sign-source.yml"

	cases := []struct {
		name    string
		signers string
		pass    bool
	}{
		{
			name: "sign.yml called through the canon, sign-source.yml through stele",
			signers: fmt.Sprintf(`[{"workflow": %q, "callers": [%q]}, {"workflow": %q, "callers": [%q]}]`,
				captureSignYML, captureCanon, sourceSigner, "monumental-archive/stele"),
			pass: true,
		},
		{
			name: "the callers swapped: the canon's runs are no longer sign.yml's callers",
			signers: fmt.Sprintf(`[{"workflow": %q, "callers": [%q]}, {"workflow": %q, "callers": [%q]}]`,
				captureSignYML, "monumental-archive/stele", sourceSigner, captureCanon),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			leaves := fillerLeaves(smallLog)
			leaves[releaseAt] = capturedLeaf(t, releaseIndex)
			leaves[vexAt] = capturedLeaf(t, vexIndex)

			h := newHarness(t, leaves)
			h.pol = signersPolicy(t, h.log.url(), githubIssuer, tc.signers, captureRoster)

			rep, err := h.run(0)
			if err != nil {
				t.Fatal(err)
			}

			if fact(t, rep, "matches") != "2" {
				t.Fatalf("matches = %s, want both certificates", fact(t, rep, "matches"))
			}

			if tc.pass {
				if rep.Verdict() != report.VerdictPass {
					t.Fatalf("verdict = %s, findings %+v", rep.Verdict(), rep.Findings())
				}

				return
			}

			// Judged against sign.yml's own callers, the canon's runs are
			// outside them: their reusable workflows are foreign, nothing
			// in the callers carries the chain, and the canon's top-level
			// workflow is a run calling the signer directly.
			got := map[string][]string{}
			for _, f := range rep.Findings() {
				got[f.Subject] = append(got[f.Subject], f.Assertion)
			}

			want := map[string][]string{
				fmt.Sprintf("CT index %d", releaseAt): {"foreign", "chain"},
				fmt.Sprintf("CT index %d", vexAt):     {"direct", "chain"},
			}

			for subject, conditions := range want {
				slices.Sort(conditions)
				slices.Sort(got[subject])

				if !slices.Equal(got[subject], conditions) {
					t.Errorf("%s failed %v, want %v", subject, got[subject], conditions)
				}
			}
		})
	}
}

// A read that cannot be completed is not a finding: the chunk is not
// done, the checkpoint does not pass it, and the run cannot judge —
// whichever of the reconciliation's reads it was.
func TestSignerIncompleteForgeRead(t *testing.T) {
	t.Parallel()

	const stele = "monumental-archive/stele"

	cases := []struct {
		name  string
		edit  func(h *harness)
		fails func(key string) bool
		want  string
	}{
		{
			name:  "the run",
			fails: func(key string) bool { return strings.Contains(key, "/actions/runs/") },
			want:  "reading run " + releaseRun + " in " + captureCanon,
		},
		{
			name: "the top-level workflow outside the callers",
			edit: func(h *harness) {
				run := h.forge.editRelease()
				run.Repository.FullName = stele
				run.Path = ".github/workflows/release.yml"
			},
			fails: func(key string) bool { return strings.HasPrefix(key, "/repos/"+stele+"/contents/") },
			want:  "reading " + stele + "/.github/workflows/release.yml@" + releaseSHA,
		},
		{
			name:  "a caller file's branch",
			fails: func(key string) bool { return key == "/repos/"+captureCanon+"@"+releaseSHA },
			want:  "asking whether " + captureCanon + "@" + releaseSHA + " is on its default branch",
		},
		{
			name:  "a caller file",
			fails: func(key string) bool { return strings.HasPrefix(key, "/repos/"+captureCanon+"/contents/") },
			want:  "reading " + captureCanon + "/.github/workflows/assemble-oci-index.yml@" + releaseSHA,
		},
		{
			name:  "the signer's branch",
			fails: func(key string) bool { return key == "/repos/"+captureSigner+"@"+releaseSigner },
			want:  "asking whether " + captureSigner + "@" + releaseSigner + " is on its default branch",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := reconcileHarness(t, releaseIndex)
			h.chunk = 10

			if tc.edit != nil {
				tc.edit(h)
			}

			h.forge.fail = func(key string) error {
				if tc.fails(key) {
					return throttledRead(key)
				}

				return nil
			}

			rep, err := h.run(0)
			if err != nil {
				t.Fatal(err)
			}

			if rep.Verdict() != report.VerdictCannotJudge || len(rep.Findings()) != 0 {
				t.Fatalf("verdict = %s with findings %+v, want CANNOT_JUDGE and none", rep.Verdict(), rep.Findings())
			}

			// The certificate sits at 7, in the first chunk (0..9):
			// nothing moved past the founding.
			if h.lastSaved() != 0 {
				t.Fatalf("the checkpoint is at %d, want 0 — not past the unreconciled certificate", h.lastSaved())
			}

			stopped := fact(t, rep, "stopped")
			for _, want := range []string{
				"throttled: reconciling CT index 7: " + tc.want,
				"the host throttled this walk, which says nothing about the subject",
			} {
				if !strings.Contains(stopped, want) {
					t.Errorf("stopped = %q, want it to say %q", stopped, want)
				}
			}
		})
	}
}

// A release mints one certificate per signing, and each is reconciled
// against the same run, files and commits: the forge is asked once.
func TestSignerReadsTheForgeOncePerFact(t *testing.T) {
	t.Parallel()

	leaf := capturedLeaf(t, releaseIndex)
	leaves := fillerLeaves(smallLog)
	leaves[3], leaves[12], leaves[25] = leaf, leaf, leaf

	h := newHarness(t, leaves)

	rep, err := h.run(0)
	if err != nil {
		t.Fatal(err)
	}

	if rep.Verdict() != report.VerdictPass || fact(t, rep, "reconciled") != "3" {
		t.Fatalf("verdict %s, %s reconciled", rep.Verdict(), fact(t, rep, "reconciled"))
	}

	seen := map[string]int{}
	for _, key := range h.forge.reads {
		seen[key]++
	}

	for key, n := range seen {
		if n != 1 {
			t.Errorf("%s was read %d times", key, n)
		}
	}
}

// The identity is the subject AND the issuer: a certificate for the
// signer's subject from another issuer is not the declared identity.
func TestSignerIdentityIsSubjectAndIssuer(t *testing.T) {
	t.Parallel()

	h := reconcileHarness(t, releaseIndex)
	h.pol = signersPolicy(t, h.log.url(), "https://issuer.example", oneSigner, captureRoster)

	rep, err := h.run(0)
	if err != nil {
		t.Fatal(err)
	}

	if rep.Verdict() != report.VerdictPass || fact(t, rep, "matches") != "0" {
		t.Fatalf("verdict %s with %s matches, want PASS over none", rep.Verdict(), fact(t, rep, "matches"))
	}
}

// What a failing file read and an unreadable file mean to `chain` and
// `direct`: neither is a skip.
func TestSignerFileShapes(t *testing.T) {
	t.Parallel()

	const stele = "monumental-archive/stele"

	// moveToStele makes the release run a run of stele, outside the
	// callers, so `direct` reads its top-level workflow.
	moveToStele := func(h *harness) *capturedRun {
		run := h.forge.editRelease()
		run.Repository.FullName = stele
		run.Path = ".github/workflows/release.yml"

		return run
	}

	cases := []struct {
		name      string
		edit      func(h *harness)
		condition string
		message   string
	}{
		{
			name: "the top-level workflow is absent at the run's commit",
			edit: func(h *harness) {
				run := moveToStele(h)
				h.forge.absent[fileKey(stele, run.Path, run.HeadSHA)] = true
			},
			condition: "direct",
			message:   stele + "'s .github/workflows/release.yml at " + releaseSHA + " is absent",
		},
		{
			name: "the top-level workflow does not parse",
			edit: func(h *harness) {
				run := moveToStele(h)
				h.forge.putFile(stele, run.Path, run.HeadSHA, "jobs: [not, a, mapping")
			},
			condition: "direct",
			message:   "does not parse, so it cannot be shown not to call the signer",
		},
		{
			name: "the only pinning candidate is absent",
			edit: func(h *harness) {
				h.forge.absent[fileKey(captureCanon, ".github/workflows/publish.yml", releaseSHA)] = true
			},
			condition: "chain",
			message: fmt.Sprintf("(%s/.github/workflows/publish.yml@%s is absent)",
				captureCanon, releaseSHA),
		},
		{
			name: "the only pinning candidate does not parse",
			edit: func(h *harness) {
				h.forge.putFile(captureCanon, ".github/workflows/publish.yml", releaseSHA, "jobs: [")
			},
			condition: "chain",
			message:   fmt.Sprintf("%s/.github/workflows/publish.yml@%s does not parse", captureCanon, releaseSHA),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := reconcileHarness(t, releaseIndex)
			tc.edit(h)

			rep, err := h.run(0)
			if err != nil {
				t.Fatal(err)
			}

			assertOneFinding(t, rep, releaseAt, releaseIndex, tc.condition, tc.message)
		})
	}
}

// A certificate carrying a signer's subject whose leaf will not parse
// is still a match, judged on what could be read — never skipped.
func TestSignerUnreadableLeafIsAMatch(t *testing.T) {
	t.Parallel()

	leaf := capturedLeaf(t, releaseIndex)
	broken := slices.Clone(leaf)
	broken[11] = 2 // an entry type RFC 6962 does not define

	h := newHarness(t, withLeaf(fillerLeaves(smallLog), releaseAt, broken))

	rep, err := h.run(0)
	if err != nil {
		t.Fatal(err)
	}

	findings := rep.Findings()
	if rep.Verdict() != report.VerdictFail || len(findings) != 1 || findings[0].Assertion != "signer-in-run" ||
		!strings.Contains(findings[0].Detail, "signer claim unreadable: ctlog: the leaf is not an RFC 6962") {
		t.Fatalf("verdict %s, findings %+v — want one signer-in-run finding naming the unreadable leaf",
			rep.Verdict(), findings)
	}
}
