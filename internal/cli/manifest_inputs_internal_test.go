// `emit manifest`'s raw inputs (stele#400): a class's lines split into
// legs, the asset directory hashed in place, the bundles placed under
// the names the policy declares, and the machinery read from its tree.
//
// The golden is a recorded release: release-lab v0.28.4's published
// evidence-manifest.json, reproduced byte for byte from that release's
// own inputs — its checksums.txt less the manifest itself (the digests
// `sha256sum ./*` produced over the same directory; the asset bytes
// are tens of megabytes, so the golden enters after the hash and
// hashing has rows of its own), the canon tree it was published with
// (v1.68.4: its CITATION.cff, and its assert policy with only the
// epoch moved to today's), and each class's lines in the
// `<target> <sha256>  <name>` shape its build legs emit, in the order
// the canon's step passed them.
//
// Those lines are RECONSTRUCTED from the published manifest's (class,
// target) entries, because the raw job outputs were not kept: the
// golden proves the split, join and encoding reproduce the release,
// not that its build legs emitted these exact lines. The real proof
// of the swap is the lab release monumental-archive/.github#1375
// names.

package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const labRelease = "testdata/release-lab-0.28.4"

func TestEmitManifestReproducesARecordedRelease(t *testing.T) {
	t.Parallel()

	pol, err := loadEvidencePolicy(filepath.Join(labRelease, "assert-policy.json"))
	if err != nil {
		t.Fatal(err)
	}

	listed, err := digestManifest(filepath.Join(labRelease, "assets.sha256"))
	if err != nil {
		t.Fatal(err)
	}

	version, err := machineryOfTree(filepath.Join(labRelease, "machinery"))
	if err != nil {
		t.Fatal(err)
	}

	var legs, registry classLines

	// The canon step's order: the leg classes, then the image, npm and
	// extension-image registry classes.
	for _, l := range []struct {
		into        *classLines
		kind, class string
	}{
		{&legs, "leg", "rust-binary"},
		{&legs, "leg", "pgrx-extension"},
		{&registry, "registry", "oci-image-crate"},
		{&registry, "registry", "wasm-npm"},
		{&registry, "registry", "pgrx-extension-image"},
	} {
		path := filepath.Join(labRelease, "lines", l.kind+"-lines-"+l.class+".txt")
		if err = l.into.Set(l.class + "=" + path); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := manifestEntries(listed, pol, legs, registry)
	if err != nil {
		t.Fatal(err)
	}

	ma := &manifestArgs{
		classes:          []string{"rust-binary", "oci-image-crate", "wasm-npm", "pgrx-extension", "pgrx-extension-image"},
		storeVSA:         true,
		machineryVersion: version,
		entries:          entries,
	}

	var doc bytes.Buffer
	if err = runEmitManifest(ma, &doc, &latch{w: io.Discard}); err != nil {
		t.Fatal(err)
	}

	want, err := os.ReadFile(filepath.Join(labRelease, "evidence-manifest.json.golden"))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(doc.Bytes(), want) {
		t.Errorf("the manifest is not release-lab v0.28.4's:\n got: %s\nwant: %s", doc.Bytes(), want)
	}
}

func TestEmitManifestSplitsClassLines(t *testing.T) {
	t.Parallel()

	want := `{"name":"` + widget + `","sha256":"` + sumOf(widgetBody) +
		`","type":"build-subject","class":"go-binary","target":"linux-amd64"}`

	for _, tc := range []struct {
		name  string
		flags func(t *testing.T) []string
	}{
		{"one leg", func(t *testing.T) []string {
			t.Helper()

			return []string{"--leg-lines", goBinaryLines(t)}
		}},
		{"blank lines are not lines", func(t *testing.T) []string {
			t.Helper()

			return []string{"--leg-lines", writeClassLines(t, "go-binary",
				"\n  \n"+legLine("linux-amd64", widget, widgetBody)+"\n")}
		}},
		{"an empty class beside no lines contributes nothing", func(t *testing.T) []string {
			t.Helper()

			// The orchestrator passes a derived class name that is empty
			// exactly when that class built nothing: no refusal.
			return []string{
				"--leg-lines", goBinaryLines(t),
				"--leg-lines", writeClassLines(t, "", ""),
				"--registry-lines", writeClassLines(t, "", "\n \n"),
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out, _ := emitWants(t, theRelease(t).args("go-binary", tc.flags(t)...), exitOK)
			if !strings.Contains(out, want) {
				t.Errorf("manifest lacks %s:\n%s", want, out)
			}
		})
	}
}

// Every refusal of the line split, each beside the shell message it
// keeps the meaning of:
//
//	"${flag}: subjects arrived with no class to attribute them to"
//	"${class}: subject line names no target — an untargeted artifact no scoped rebuild judges"
//	"${class}: target ${target} is not a plain name — it becomes a file this step writes"
//
// The untargeted row is the .github#637 fix: without the refusal, the
// line's digest would become its target and the artifact would go
// unclaimed — refused for the wrong reason, which this row's message
// tells apart.
func TestEmitManifestClassLineRefusals(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		flags func(t *testing.T) []string
		want  string
	}{
		{
			"lines with no class",
			func(t *testing.T) []string {
				t.Helper()

				return []string{"--leg-lines", writeClassLines(t, "", legLine("linux-amd64", widget, widgetBody))}
			},
			"stele emit manifest: --leg-lines: subjects arrived with no class to attribute them to",
		},
		{
			"registry lines with no class",
			func(t *testing.T) []string {
				t.Helper()

				return []string{
					"--leg-lines", goBinaryLines(t),
					"--registry-lines", writeClassLines(t, "", legLine("image", "ghcr.io/x/y", "i")),
				}
			},
			"--registry-lines: subjects arrived with no class to attribute them to",
		},
		{
			"an untargeted line",
			func(t *testing.T) []string {
				t.Helper()

				return []string{"--leg-lines", writeClassLines(t, "go-binary", sumOf(widgetBody)+"\n")}
			},
			"--leg-lines go-binary line 1: subject line names no target — an untargeted artifact no scoped" +
				" rebuild judges",
		},
		{
			"a line that opens with its separator",
			func(t *testing.T) []string {
				t.Helper()

				return []string{"--leg-lines", writeClassLines(t, "go-binary", " "+sumOf(widgetBody)+"  "+widget+"\n")}
			},
			"--leg-lines go-binary line 1: subject line names no target",
		},
		{
			"a target with a path character",
			func(t *testing.T) []string {
				t.Helper()

				return []string{"--leg-lines", writeClassLines(t, "go-binary", "\n"+legLine("../linux-amd64", widget, widgetBody))}
			},
			`--leg-lines go-binary line 2: target "../linux-amd64" is not a plain name`,
		},
		{
			"a record that is not sha256sum's",
			func(t *testing.T) []string {
				t.Helper()

				return []string{"--leg-lines", writeClassLines(t, "go-binary", "linux-amd64 nonsense\n")}
			},
			"--leg-lines go-binary line 1: manifest: subject line 1 is not a sha256sum record",
		},
		{
			"one class's lines twice",
			func(t *testing.T) []string {
				t.Helper()

				return []string{"--leg-lines", goBinaryLines(t), "--leg-lines", goBinaryLines(t)}
			},
			"--leg-lines names go-binary twice — one class's legs arrive as one set of lines",
		},
		{
			"lines that cannot be read",
			func(*testing.T) []string { return []string{"--leg-lines", "go-binary=/no/such/lines"} },
			"/no/such/lines",
		},
		{
			"a flag value with no file",
			func(*testing.T) []string { return []string{"--leg-lines", "go-binary"} },
			`invalid value "go-binary" for flag -leg-lines: "go-binary" is not <class>=<file>`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, stderr := emitWants(t, theRelease(t).args("go-binary,oci-image", tc.flags(t)...), exitUsage)
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr %q\nlacks %q", stderr, tc.want)
			}
		})
	}
}

// lockDir makes a directory unreadable for one row and restores it,
// so the test's own cleanup can remove it.
func lockDir(t *testing.T, dir string) {
	t.Helper()

	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory's mode
			t.Error(err)
		}
	})
}

// writeFile writes one file a row needs.
func writeFile(t *testing.T, path, body string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEmitManifestAssetsDirectoryRefusals(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, r releaseFixture) []string
		want  string
	}{
		{
			"a dotfile",
			func(t *testing.T, r releaseFixture) []string {
				t.Helper()

				writeFile(t, filepath.Join(r.assets, ".github-1.0.0.spdx.json"), "x")

				return nil
			},
			"--assets-dir: .github-1.0.0.spdx.json is a dotfile — it would ship unpinned",
		},
		{
			"a subdirectory",
			func(t *testing.T, r releaseFixture) []string {
				t.Helper()

				if err := os.Mkdir(filepath.Join(r.assets, "nested"), 0o700); err != nil {
					t.Fatal(err)
				}

				return nil
			},
			"--assets-dir: nested is not a regular file",
		},
		{
			"a name a record cannot carry",
			func(t *testing.T, r releaseFixture) []string {
				t.Helper()

				// A backslash is a name character here, not a separator.
				odd := `odd\name.tar.gz`
				writeFile(t, filepath.Join(r.assets, odd), "x")

				return nil
			},
			`--assets-dir: "odd\\name.tar.gz" carries a character a sha256sum record cannot`,
		},
		{
			"a dangling link",
			func(t *testing.T, r releaseFixture) []string {
				t.Helper()

				if err := os.Symlink("nowhere", filepath.Join(r.assets, "gone.tar.gz")); err != nil {
					t.Fatal(err)
				}

				return nil
			},
			"--assets-dir: stat",
		},
		{
			"an unreadable asset",
			func(t *testing.T, r releaseFixture) []string {
				t.Helper()

				if err := os.Chmod(filepath.Join(r.assets, widget), 0o000); err != nil {
					t.Fatal(err)
				}

				return nil
			},
			"--assets-dir: release: hashing " + widget,
		},
		{
			"an empty directory in a rehearsal",
			func(t *testing.T, _ releaseFixture) []string {
				t.Helper()

				return newRelease(t, nil, nil).args("go-binary", "--rehearsal")
			},
			"--assets-dir: the directory is empty",
		},
		{
			"no directory",
			func(t *testing.T, r releaseFixture) []string {
				t.Helper()

				return setFlag(r.args("go-binary"), "--assets-dir", filepath.Join(t.TempDir(), "absent"))
			},
			"--assets-dir: stat",
		},
		{
			"a file where the directory should be",
			func(t *testing.T, r releaseFixture) []string {
				t.Helper()

				return setFlag(r.args("go-binary"), "--assets-dir", filepath.Join(r.assets, widget))
			},
			widget + " is not a directory",
		},
		{
			"an unreadable directory, bundles waiting",
			func(t *testing.T, r releaseFixture) []string {
				t.Helper()

				lockDir(t, r.assets)

				return nil
			},
			"--assets-dir: lstat",
		},
		{
			"an unreadable directory in a rehearsal",
			func(t *testing.T, _ releaseFixture) []string {
				t.Helper()

				bare := newRelease(t, map[string]string{widget: widgetBody}, nil)
				lockDir(t, bare.assets)

				return bare.args("go-binary", "--rehearsal")
			},
			"--assets-dir: open",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := theRelease(t)

			args := tc.setup(t, r)
			if args == nil {
				args = r.args("go-binary", "--leg-lines", goBinaryLines(t))
			}

			_, stderr := emitWants(t, args, exitUsage)
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr %q\nlacks %q", stderr, tc.want)
			}
		})
	}
}

// A tree that states no version refuses the way the shell's awk read
// did: "the pinned canon tree's CITATION.cff names no version — the
// manifest cannot state its machinery".
func TestEmitManifestMachineryTreeRefusals(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		citation string
		want     string
	}{
		{"a tree with no version mirror", "", ": manifest: no version mirrors in this tree — the manifest cannot" +
			" state its machinery"},
		{
			"a citation naming no version", "cff-version: 1.2.0\ndate-released: 2026-11-17\n",
			": manifest: CITATION.cff carries no version",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := theRelease(t)

			path := filepath.Join(r.tree, "CITATION.cff")
			if tc.citation == "" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				writeFile(t, path, tc.citation)
			}

			_, stderr := emitWants(t, r.args("go-binary", "--leg-lines", goBinaryLines(t)), exitUsage)
			if want := "--machinery-tree " + r.tree + tc.want; !strings.Contains(stderr, want) {
				t.Errorf("stderr %q\nlacks %q", stderr, want)
			}
		})
	}
}

// bundleDirs lays out one directory per bundle.
func bundleDirs(t *testing.T, dir string, bundles map[string]string) {
	t.Helper()

	for name, body := range bundles {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}

		writeFile(t, filepath.Join(dir, name, "bundle.jsonl"), body)
	}
}

// Bundle placement (stele#400, the orchestrator's ruling C): each
// directory under --bundles-dir holds one bundle and is the name it is
// placed as; a single flat file is the policy's umbrella bundle; every
// placed name must be one the evidence vocabulary declares.
func TestEmitManifestPlacesBundles(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		bundles func(t *testing.T, dir string)
		extra   []string
		placed  []string
		note    string
	}{
		{
			name: "several class bundles",
			bundles: func(t *testing.T, dir string) {
				t.Helper()

				bundleDirs(t, dir, map[string]string{goBundle: "go\n", "attestations-image.intoto.jsonl": "img\n"})
			},
			placed: []string{goBundle, "attestations-image.intoto.jsonl"},
			note:   "2 attestation bundle(s) placed",
		},
		{
			// download-artifact delivers exactly one artifact FLAT, with
			// no name to recover a class from — and one bundle covering
			// the whole release truthfully takes the umbrella name.
			name: "one flat bundle",
			bundles: func(t *testing.T, dir string) {
				t.Helper()

				writeFile(t, filepath.Join(dir, "bundle.jsonl"), "all\n")
			},
			placed: []string{"attestations.intoto.jsonl"},
			note:   "1 attestation bundle(s) placed",
		},
		{
			name:    "no bundle in a declared rehearsal",
			bundles: func(*testing.T, string) {},
			extra:   []string{"--rehearsal"},
			note:    "rehearsal: no Sigstore bundle to attach",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRelease(t, map[string]string{widget: widgetBody}, nil)
			tc.bundles(t, r.bundles)

			args := append(r.args("go-binary", "--leg-lines", goBinaryLines(t),
				"--out", filepath.Join(t.TempDir(), "m.json")), tc.extra...)

			stdout, _ := emitWants(t, args, exitOK)

			for _, name := range tc.placed {
				if _, err := os.Stat(filepath.Join(r.assets, name)); err != nil {
					t.Errorf("%s was not placed: %v", name, err)
				}
			}

			if !strings.Contains(stdout, tc.note) {
				t.Errorf("progress %q lacks %q", stdout, tc.note)
			}
		})
	}
}

// Every bundle refusal, each beside the shell message it keeps the
// meaning of where the shell had one ("empty bundle for ${class}";
// "no Sigstore bundle — a release without evidence does not
// publish"). The two-files row is the other half of .github#682: the
// shell's `find -print -quit` stopped at whichever file it met first,
// so a directory holding two bundles shipped one of them silently.
func TestEmitManifestBundleRefusals(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		bundles func(t *testing.T, r releaseFixture)
		want    string
	}{
		{
			"a directory with two files",
			func(t *testing.T, r releaseFixture) {
				t.Helper()

				bundleDirs(t, r.bundles, map[string]string{goBundle: "a\n"})
				writeFile(t, filepath.Join(r.bundles, goBundle, "second.jsonl"), "b\n")
			},
			"--bundles-dir: " + goBundle + " holds 2 files (bundle.jsonl, second.jsonl) — one bundle is one file",
		},
		{
			"a directory with none",
			func(t *testing.T, r releaseFixture) {
				t.Helper()

				if err := os.Mkdir(filepath.Join(r.bundles, goBundle), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			"--bundles-dir: empty bundle for " + goBundle,
		},
		{
			"a name the policy does not declare",
			func(t *testing.T, r releaseFixture) {
				t.Helper()

				bundleDirs(t, r.bundles, map[string]string{"attestation-bundle-go-binaries": "a\n"})
			},
			"--bundles-dir: attestation-bundle-go-binaries is not a name the assert policy's evidence vocabulary" +
				" declares",
		},
		{
			"both a flat file and directories",
			func(t *testing.T, r releaseFixture) {
				t.Helper()

				bundleDirs(t, r.bundles, map[string]string{goBundle: "a\n"})
				writeFile(t, filepath.Join(r.bundles, "flat.jsonl"), "b\n")
			},
			"--bundles-dir holds both a flat bundle (flat.jsonl) and bundle directories (" + goBundle + ")",
		},
		{
			"two flat files",
			func(t *testing.T, r releaseFixture) {
				t.Helper()

				writeFile(t, filepath.Join(r.bundles, "a.jsonl"), "a\n")
				writeFile(t, filepath.Join(r.bundles, "b.jsonl"), "b\n")
			},
			"--bundles-dir holds 2 flat files (a.jsonl, b.jsonl)",
		},
		{
			"no bundle",
			func(*testing.T, releaseFixture) {},
			"--bundles-dir: no Sigstore bundle — a release without evidence does not publish",
		},
		{
			"no bundle directory at all",
			func(t *testing.T, r releaseFixture) {
				t.Helper()

				if err := os.Remove(r.bundles); err != nil {
					t.Fatal(err)
				}
			},
			"--bundles-dir: no Sigstore bundle — a release without evidence does not publish",
		},
		{
			"a bundle path that is a file",
			func(t *testing.T, r releaseFixture) {
				t.Helper()

				if err := os.Remove(r.bundles); err != nil {
					t.Fatal(err)
				}

				writeFile(t, r.bundles, "not a directory\n")
			},
			"--bundles-dir: open",
		},
		{
			"a dotfile",
			func(t *testing.T, r releaseFixture) {
				t.Helper()

				writeFile(t, filepath.Join(r.bundles, ".hidden.jsonl"), "a\n")
			},
			"--bundles-dir: .hidden.jsonl is a dotfile",
		},
		{
			"a bundle directory holding a directory",
			func(t *testing.T, r releaseFixture) {
				t.Helper()

				if err := os.MkdirAll(filepath.Join(r.bundles, goBundle, "nested"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			"--bundles-dir: " + goBundle + " holds nested, which is not a file",
		},
		{
			"an unreadable bundle directory",
			func(t *testing.T, r releaseFixture) {
				t.Helper()

				bundleDirs(t, r.bundles, map[string]string{goBundle: "a\n"})
				lockDir(t, filepath.Join(r.bundles, goBundle))
			},
			"--bundles-dir: open",
		},
		{
			"an asset directory that cannot be written",
			func(t *testing.T, r releaseFixture) {
				t.Helper()

				bundleDirs(t, r.bundles, map[string]string{goBundle: "a\n"})

				if err := os.Chmod(r.assets, 0o500); err != nil { //nolint:gosec // G302: a directory's mode
					t.Fatal(err)
				}

				t.Cleanup(func() {
					if err := os.Chmod(r.assets, 0o700); err != nil { //nolint:gosec // G302: a directory's mode
						t.Error(err)
					}
				})
			},
			"--bundles-dir: placing " + goBundle,
		},
		{
			"a bundle name that already ships",
			func(t *testing.T, r releaseFixture) {
				t.Helper()

				bundleDirs(t, r.bundles, map[string]string{goBundle: "a\n"})
				writeFile(t, filepath.Join(r.assets, goBundle), "stale\n")
			},
			"--bundles-dir: " + goBundle + " already ships in --assets-dir — one name, one file",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRelease(t, map[string]string{widget: widgetBody}, nil)
			tc.bundles(t, r)

			_, stderr := emitWants(t, r.args("go-binary", "--leg-lines", goBinaryLines(t)), exitUsage)
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr %q\nlacks %q", stderr, tc.want)
			}

			// Checked before anything moves: a refused layout leaves the
			// asset directory holding only what shipped.
			entries, err := os.ReadDir(r.assets)
			if err != nil {
				t.Fatal(err)
			}

			for _, e := range entries {
				if e.Name() != widget && e.Name() != goBundle {
					t.Errorf("a refused layout placed %s", e.Name())
				}
			}
		})
	}
}
