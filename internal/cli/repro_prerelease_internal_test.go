// `verify repro`'s pre-release form (stele#401): the first build
// against the rebuild, one typed finding per artifact, through the
// same engine as the post-release form. Each row stands for a state a
// publish run reaches, and each refusal asserts its message beside the
// shell's:
//
//	"${class}: a build produced no subjects — an empty proof is not a proof"
//	"the gate compared nothing — an empty proof is not a proof"
//	"oci-image: rebuild produced no ${arch} digest"            → finding repro/absent-from-rebuild
//	"oci-image: ${arch} digest differs — …"                    → finding repro/diverged
//	"pgrx images: ${major} index differs (${da} vs ${db})"      → finding repro/diverged, both digests
//	"${class}: the rebuild does not reproduce the first build bit for bit" + raw diff
//	                                                          → one finding per artifact

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	preDigestA = "1111111111111111111111111111111111111111111111111111111111111111"
	preDigestB = "2222222222222222222222222222222222222222222222222222222222222222"
)

// builds is one pre-release run's two builds on disk.
type builds struct {
	dir  string
	args []string
}

// preReleasePolicy declares the fixture classes' subject shapes: a
// files class, a bare-digest registry class (one file per
// architecture) and a document registry class (one JSON document per
// major) — the classes are the policy's, never the code's (stele#442).
// "docs-only" is declared with no subjects at all.
const preReleasePolicy = `{
  "schema": 9,
  "evidence": {
    "sbomSuffix": ".spdx.json",
    "checksums": "checksums.txt",
    "umbrellaBundle": "attestations.intoto.jsonl",
    "manifestAsset": "evidence-manifest.json",
    "classes": {
      "go-binary": {"bundles": ["b.jsonl"], "subjects": {
        "kind": "files", "entry": "^(?P<t>[a-z0-9-]+)$", "unit": "target", "extension": ".tar.gz",
        "label": "${t}", "assets": [{"noun": "archive", "suffix": "-${t}.tar.gz"}]}},
      "rust-binary": {"bundles": ["r.jsonl"], "subjects": {
        "kind": "files", "entry": "^(?P<t>[a-z0-9-]+)$", "unit": "target", "extension": ".tar.gz",
        "label": "${t}", "assets": [{"noun": "archive", "suffix": "-${t}.tar.gz"}]}},
      "oci-image": {"bundles": ["i.jsonl"], "subjects": {
        "kind": "registry", "form": "bare-digest", "entry": "^[a-z0-9]+$", "unit": "arch"}},
      "pgrx-extension-image": {"bundles": ["e.jsonl"], "subjects": {
        "kind": "registry", "form": "document", "entry": "^\\d+$", "unit": "major",
        "extension": ".json", "legField": "pg"}},
      "docs-only": {"bundles": ["d.jsonl"]}
    }
  }
}`

// newBuilds starts a run requesting classes.
func newBuilds(t *testing.T, classes string) *builds {
	t.Helper()

	dir := t.TempDir()

	policy := filepath.Join(dir, "assert-policy.json")
	if err := os.WriteFile(policy, []byte(preReleasePolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	return &builds{dir: dir, args: []string{
		"verify", "repro", "--repo", "acme/widget", "--tag", "v1.0.0", "--classes", classes,
		"--assert-policy", policy,
	}}
}

// manifests gives one class's sha256sum manifest from each build.
func (b *builds) manifests(t *testing.T, class, first, rebuilt string) *builds {
	t.Helper()

	for side, body := range map[string]string{"first": first, "rebuild": rebuilt} {
		path := filepath.Join(b.dir, side+"-"+class+".sha256")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}

		b.args = append(b.args, "--"+side, class+"="+path)
	}

	return b
}

// digests gives one registry class's digest directory from each build.
func (b *builds) digests(t *testing.T, class string, first, rebuilt map[string]string) *builds {
	t.Helper()

	for side, files := range map[string]map[string]string{"first": first, "rebuild": rebuilt} {
		dir := filepath.Join(b.dir, side+"-"+class)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}

		for name, body := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}

		b.args = append(b.args, "--"+side, class+"="+dir)
	}

	return b
}

// pgIndex is one pgrx index digest document as the image leg writes it.
func pgIndex(pg, digest string) string {
	return `{"pg":"` + pg + `","image":"ghcr.io/acme/ext","tag":"1.0.0-pg` + pg + `-artifact","digest":"sha256:` +
		digest + `"}`
}

// run runs the form with --json and returns the verdict.
func (b *builds) run(t *testing.T, code int, extra ...string) *jsonReportDoc {
	t.Helper()

	var stdout, stderr bytes.Buffer
	if got := Run(append(append(b.args, extra...), "--json"), &stdout, &stderr); got != code {
		t.Fatalf("Run = %d, want %d\nstderr: %s", got, code, stderr.String())
	}

	return decodeReport(t, &stdout)
}

// refused runs the form and returns stderr, asserting the code.
func (b *builds) refused(t *testing.T, code int, extra ...string) string {
	t.Helper()

	var stdout, stderr bytes.Buffer
	if got := Run(append(b.args, extra...), &stdout, &stderr); got != code {
		t.Fatalf("Run = %d, want %d\nstderr: %s", got, code, stderr.String())
	}

	if stdout.Len() != 0 {
		t.Errorf("a refusal wrote a verdict: %s", stdout.String())
	}

	return stderr.String()
}

func TestPreReleaseReproIdenticalBuilds(t *testing.T) {
	t.Parallel()

	doc := newBuilds(t, "go-binary,oci-image,pgrx-extension-image").
		manifests(t, "go-binary", preDigestA+"  w-linux.tar.gz\n", preDigestA+"  w-linux.tar.gz\n").
		digests(t, "oci-image",
			map[string]string{"amd64": "sha256:" + preDigestA, "arm64": "sha256:" + preDigestB},
			map[string]string{"amd64": "sha256:" + preDigestA, "arm64": "sha256:" + preDigestB}).
		digests(t, "pgrx-extension-image",
			map[string]string{"pg16.json": pgIndex("16", preDigestA)},
			map[string]string{"pg16.json": pgIndex("16", preDigestA)}).
		run(t, exitOK)

	if *doc.Verdict != "PASS" || len(doc.Findings) != 0 {
		t.Fatalf("verdict = %s with %d finding(s), want PASS and none", *doc.Verdict, len(doc.Findings))
	}

	if got := factValue(t, doc, "classesCompared"); got != "go-binary,oci-image,pgrx-extension-image" {
		t.Errorf("classesCompared = %s", got)
	}

	if got := factValue(t, doc, "judgedArtifacts"); got != "4" {
		t.Errorf("judgedArtifacts = %s, want 4 (one file, two architectures, one major)", got)
	}

	if got := factValue(t, doc, "form"); got != "pre-release" {
		t.Errorf("form = %s", got)
	}
}

// One finding per artifact, typed — never one class-wide "differs"
// with a diff hunk.
func TestPreReleaseReproFindings(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name            string
		build           func(t *testing.T) *builds
		subject, assert string
	}{
		{
			"one differing artifact",
			func(t *testing.T) *builds {
				t.Helper()

				return newBuilds(t, "go-binary").manifests(t, "go-binary",
					preDigestA+"  w-darwin.tar.gz\n"+preDigestA+"  w-linux.tar.gz\n",
					preDigestA+"  w-darwin.tar.gz\n"+preDigestB+"  w-linux.tar.gz\n")
			},
			"w-linux.tar.gz", "repro/diverged",
		},
		{
			"one absent from the rebuild",
			func(t *testing.T) *builds {
				t.Helper()

				return newBuilds(t, "go-binary").manifests(t, "go-binary",
					preDigestA+"  w-darwin.tar.gz\n"+preDigestA+"  w-linux.tar.gz\n",
					preDigestA+"  w-darwin.tar.gz\n")
			},
			"w-linux.tar.gz", "repro/absent-from-rebuild",
		},
		{
			// The shell's string comparison caught this only as "differs";
			// it is its own answer: the rebuild produced an artifact the
			// first build never did.
			"one absent from the first build",
			func(t *testing.T) *builds {
				t.Helper()

				return newBuilds(t, "go-binary").manifests(t, "go-binary",
					preDigestA+"  w-linux.tar.gz\n",
					preDigestA+"  w-linux.tar.gz\n"+preDigestA+"  w-riscv.tar.gz\n")
			},
			"w-riscv.tar.gz", "repro/extra-in-rebuild",
		},
		{
			"a missing per-architecture digest",
			func(t *testing.T) *builds {
				t.Helper()

				return newBuilds(t, "oci-image").digests(t, "oci-image",
					map[string]string{"amd64": "sha256:" + preDigestA, "arm64": "sha256:" + preDigestB},
					map[string]string{"amd64": "sha256:" + preDigestA})
			},
			"oci-image/arm64", "repro/absent-from-rebuild",
		},
		{
			// The shell walked only the first build's files, so a digest
			// the rebuild alone produced was never looked at.
			"a per-architecture digest only the rebuild produced",
			func(t *testing.T) *builds {
				t.Helper()

				return newBuilds(t, "oci-image").digests(t, "oci-image",
					map[string]string{"amd64": "sha256:" + preDigestA},
					map[string]string{"amd64": "sha256:" + preDigestA, "s390x": "sha256:" + preDigestB})
			},
			"oci-image/s390x", "repro/extra-in-rebuild",
		},
		{
			"a differing pgrx index",
			func(t *testing.T) *builds {
				t.Helper()

				return newBuilds(t, "pgrx-extension-image").digests(t, "pgrx-extension-image",
					map[string]string{"pg16.json": pgIndex("16", preDigestA), "pg17.json": pgIndex("17", preDigestA)},
					map[string]string{"pg16.json": pgIndex("16", preDigestB), "pg17.json": pgIndex("17", preDigestA)})
			},
			"pgrx-extension-image/16", "repro/diverged",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc := tc.build(t).run(t, exitRefused)

			if *doc.Verdict != "FAIL" || len(doc.Findings) != 1 {
				t.Fatalf("verdict = %s with findings %+v, want FAIL and one", *doc.Verdict, doc.Findings)
			}

			f := doc.Findings[0]
			if f.Subject != tc.subject || f.Assertion != tc.assert {
				t.Errorf("finding = %s %s, want %s %s", f.Subject, f.Assertion, tc.subject, tc.assert)
			}

			if !strings.Contains(f.Detail, "the rebuild did not reproduce the first build") {
				t.Errorf("finding detail = %q", f.Detail)
			}
		})
	}
}

// The rehearsal pushed no image: its registry classes are reported as
// not compared, by name, and the file classes are still judged — the
// shell's dry-run branch, made a stated fact instead of a skipped step.
func TestPreReleaseReproRehearsal(t *testing.T) {
	t.Parallel()

	doc := newBuilds(t, "go-binary,oci-image,pgrx-extension-image").
		manifests(t, "go-binary", preDigestA+"  w-linux.tar.gz\n", preDigestA+"  w-linux.tar.gz\n").
		run(t, exitOK, "--rehearsal")

	if *doc.Verdict != "PASS" {
		t.Fatalf("verdict = %s, want PASS", *doc.Verdict)
	}

	if got := factValue(t, doc, "rehearsalNotCompared"); got != "oci-image,pgrx-extension-image" {
		t.Errorf("rehearsalNotCompared = %s", got)
	}

	if got := factValue(t, doc, "classesCompared"); got != "go-binary" {
		t.Errorf("classesCompared = %s", got)
	}

	// Outside a rehearsal the same run is missing two classes' subjects.
	stderr := newBuilds(t, "go-binary,oci-image").
		manifests(t, "go-binary", preDigestA+"  w-linux.tar.gz\n", preDigestA+"  w-linux.tar.gz\n").
		refused(t, exitRefused)
	if want := "oci-image: a build produced no subjects — an empty proof is not a proof"; !strings.Contains(stderr, want) {
		t.Errorf("stderr %q\nlacks %q", stderr, want)
	}
}

func TestPreReleaseReproRefusals(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		build func(t *testing.T) (*builds, []string)
		code  int
		want  string
	}{
		{
			"an empty class",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return newBuilds(t, "go-binary").manifests(t, "go-binary", preDigestA+"  w.tar.gz\n", ""), nil
			},
			exitRefused, "stele verify repro: go-binary: a build produced no subjects — an empty proof is not a proof",
		},
		{
			"a requested class neither build was given",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return newBuilds(t, "go-binary,rust-binary").manifests(t, "go-binary",
					preDigestA+"  w.tar.gz\n", preDigestA+"  w.tar.gz\n"), nil
			},
			exitRefused, "rust-binary: a build produced no subjects — an empty proof is not a proof",
		},
		{
			"an empty digest directory",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return newBuilds(t, "oci-image").digests(t, "oci-image",
					map[string]string{"amd64": "sha256:" + preDigestA}, map[string]string{}), nil
			},
			exitRefused, "oci-image: a build produced no subjects — an empty proof is not a proof",
		},
		{
			"nothing compared: a rehearsal of registry classes alone",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return newBuilds(t, "oci-image"), []string{"--rehearsal"}
			},
			exitRefused, "stele verify repro: the gate compared nothing — an empty proof is not a proof",
		},
		{
			"nothing compared: no class requested",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return newBuilds(t, " , "), nil
			},
			exitRefused, "the gate compared nothing — an empty proof is not a proof",
		},
		{
			"digests given to a rehearsal",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return newBuilds(t, "oci-image").digests(t, "oci-image",
					map[string]string{"amd64": "sha256:" + preDigestA},
					map[string]string{"amd64": "sha256:" + preDigestA}), []string{"--rehearsal"}
			},
			exitUsage, "oci-image: a rehearsal pushes no image, so there are no digests to give",
		},
		{
			"a rebuild's digests given to a rehearsal",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				b := newBuilds(t, "oci-image")
				b.args = append(b.args, "--rebuild", "oci-image="+t.TempDir())

				return b, []string{"--rehearsal"}
			},
			exitUsage, "oci-image: a rehearsal pushes no image",
		},
		{
			"an output for a class not requested",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return newBuilds(t, "go-binary").manifests(t, "rust-binary", "", ""), nil
			},
			exitUsage, "names rust-binary, which --classes does not request",
		},
		{
			"a class requested twice",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return newBuilds(t, "go-binary,go-binary"), nil
			},
			exitUsage, "--classes names go-binary twice",
		},
		{
			"one class's output named twice",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return newBuilds(t, "go-binary"), []string{"--first", "go-binary=a", "--first", "go-binary=b"}
			},
			exitUsage, "go-binary is named twice — one build has one output per class",
		},
		{
			"an output that is not <class>=<path>",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return newBuilds(t, "go-binary"), []string{"--first", "go-binary"}
			},
			exitUsage, `"go-binary" is not <class>=<path>`,
		},
		{
			"a manifest that cannot be read",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return newBuilds(t, "go-binary"), []string{"--first", "go-binary=/no/such", "--rebuild", "go-binary=/no/such"}
			},
			exitUsage, "--first go-binary: open /no/such",
		},
		{
			"a rebuild manifest that is not one",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return newBuilds(t, "go-binary").manifests(t, "go-binary", preDigestA+"  w.tar.gz\n", "junk\n"), nil
			},
			exitUsage, "--rebuild go-binary: manifest: subject line 1 is not a sha256sum record",
		},
		{
			"a digest directory that cannot be read",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return newBuilds(t, "oci-image"), []string{"--first", "oci-image=/no/such", "--rebuild", "oci-image=/no/such"}
			},
			exitUsage, "--first oci-image: release: reading the asset directory: open /no/such",
		},
		{
			"a class the policy does not declare",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return newBuilds(t, "wasm-npm"), nil
			},
			exitUsage, `class "wasm-npm" is not declared in`,
		},
		{
			"a class declared with no subjects",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return newBuilds(t, "docs-only"), nil
			},
			exitUsage, "evidence.classes.docs-only in",
		},
		{
			"no assert policy",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return &builds{args: []string{
					"verify", "repro", "--repo", "a/b", "--tag", "v1", "--classes", "go-binary",
				}}, nil
			},
			exitUsage, "--assert-policy is required with --classes: each class's subject shape is declared there",
		},
		{
			"a post-release flag in the pre-release form",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return newBuilds(t, "go-binary"), []string{"--targets", "linux-amd64"}
			},
			exitUsage, "--targets belongs to the post-release form; --classes is the pre-release form",
		},
		{
			"no repository",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return &builds{args: []string{"verify", "repro", "--tag", "v1", "--classes", "go-binary"}}, nil
			},
			exitUsage, "--repo must be owner/repo",
		},
		{
			"no tag",
			func(t *testing.T) (*builds, []string) {
				t.Helper()

				return &builds{args: []string{"verify", "repro", "--repo", "a/b", "--classes", "go-binary"}}, nil
			},
			exitUsage, "--tag is required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b, extra := tc.build(t)

			stderr := b.refused(t, tc.code, extra...)
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr %q\nlacks %q", stderr, tc.want)
			}
		})
	}
}

// The pre-release form's flags without --classes are read by nobody:
// refused, never ignored.
func TestPostReleaseReproRefusesThePreReleaseFlags(t *testing.T) {
	t.Parallel()

	sub, reb := reproManifests(t, digestA+"  a\n", digestA+"  a\n")

	for _, flagArgs := range [][]string{
		{"--first", "go-binary=" + sub},
		{"--rebuild", "go-binary=" + reb},
		{"--rehearsal"},
	} {
		t.Run(flagArgs[0], func(t *testing.T) {
			t.Parallel()

			args := append([]string{
				"verify", "repro", "--repo", "a/b", "--tag", "v1", "--released", sub, "--rebuilt", reb,
			}, flagArgs...)

			var stdout, stderr bytes.Buffer
			if code := Run(args, &stdout, &stderr); code != exitUsage {
				t.Fatalf("Run = %d, want %d", code, exitUsage)
			}

			if want := flagArgs[0] + " belongs to the pre-release form, which --classes names"; !strings.Contains(
				stderr.String(), want,
			) {
				t.Errorf("stderr %q\nlacks %q", stderr.String(), want)
			}
		})
	}
}

// A stream that breaks is exitIO, never a verdict or a refusal: on the
// progress stream mid-comparison, and on stderr while refusing.
func TestPreReleaseReproBrokenStreams(t *testing.T) {
	t.Parallel()

	t.Run("progress", func(t *testing.T) {
		t.Parallel()

		b := newBuilds(t, "go-binary").manifests(t, "go-binary", preDigestA+"  w.tar.gz\n", preDigestA+"  w.tar.gz\n")

		var stderr bytes.Buffer
		if code := Run(b.args, failWriterI{}, &stderr); code != exitIO {
			t.Errorf("Run = %d, want %d", code, exitIO)
		}
	})

	t.Run("refusal", func(t *testing.T) {
		t.Parallel()

		b := newBuilds(t, "go-binary")

		var stdout bytes.Buffer
		if code := Run(b.args, &stdout, failWriterI{}); code != exitIO {
			t.Errorf("Run = %d, want %d", code, exitIO)
		}
	})
}
