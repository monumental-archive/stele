// `assert published` end to end through Run: every refusal of the
// input before a store is asked (usage, exit 2, the message asserted),
// the judgment's three exits, the manifest written only on PASS, the
// rehearsal, and the broken streams. The stores are seams; the waiting
// rule itself is internal/published's table.

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/published"
)

const (
	pubA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pubB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// pubStores scripts what each URL serves; an unscripted URL is a store
// that would not answer. Every ask is recorded.
type pubStores struct {
	served map[string]string
	asked  []string
}

func (s *pubStores) Fetch(name, url string) (string, error) {
	s.asked = append(s.asked, url)

	if d, ok := s.served[url]; ok {
		return d, nil
	}

	return "", fmt.Errorf("%s: not served after 10 minutes", name)
}

func swapPublished(t *testing.T, s *pubStores) {
	t.Helper()

	orig := newPublishedFetcher
	newPublishedFetcher = func() assert.BytesFetcher { return s }

	t.Cleanup(func() { newPublishedFetcher = orig })
}

// pubFixture writes a policy, a subjects manifest and an images file.
type pubFixture struct {
	dir, policy, bare, subjects, images string
}

func newPubFixture(t *testing.T) *pubFixture {
	t.Helper()

	dir := t.TempDir()
	evidence := `"evidence": {"sbomSuffix": ".spdx.json", "checksums": "c.txt",
	  "umbrellaBundle": "u.jsonl", "manifestAsset": "m.json", "classes": {"a": {"bundles": ["b"]}}}`
	schema := fmt.Sprintf(`"schema": %d`, assert.PolicySchema)

	f := &pubFixture{
		dir:      dir,
		policy:   filepath.Join(dir, "policy.json"),
		bare:     filepath.Join(dir, "bare.json"),
		subjects: filepath.Join(dir, "subjects.sha256"),
		images:   filepath.Join(dir, "images.json"),
	}

	writeTree(t, dir, map[string]string{
		"policy.json": `{` + schema + `, ` + evidence + `, "published": {"registries": [
		  {"extension": ".crate", "coordinate": "file",
		   "url": "https://crates.example/crates/{name}/{name}-{version}.crate"},
		  {"extension": ".tgz", "coordinate": "declared",
		   "url": "https://npm.example/{name}/-/{basename}-{version}.tgz"}]}}`,
		"bare.json":       `{` + schema + `, ` + evidence + `}`,
		"subjects.sha256": pubA + "  widget-1.0.0.crate\n" + pubB + "  acme-widget-1.0.0.tgz\n",
		"images.json":     `[{"image": "ghcr.io/acme/widget", "tag": "1.0.0", "digest": "sha256:` + pubA + `"}]`,
		"empty.sha256":    "",
		"junk.sha256":     "not a record\n",
		"asset.sha256":    pubA + "  widget-linux.tar.gz\n",
		"bad-images.json": `{"image": "x"}`,
		"debt.txt":        "this is not a debt line\n",
	})

	return f
}

func (f *pubFixture) path(name string) string { return filepath.Join(f.dir, name) }

// liveStores serves the fixture's two files as built.
func liveStores() *pubStores {
	return &pubStores{served: map[string]string{
		"https://crates.example/crates/widget/widget-1.0.0.crate": pubA,
		"https://npm.example/@acme/widget/-/widget-1.0.0.tgz":     pubB,
	}}
}

//nolint:gocritic // unnamedResult: the exit code, stdout, stderr
func runPublished(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer

	code := Run(append([]string{"assert", "published"}, args...), &stdout, &stderr)

	return code, stdout.String(), stderr.String()
}

func TestAssertPublishedInputRefusals(t *testing.T) {
	f := newPubFixture(t)
	stores := liveStores()
	swapPublished(t, stores)

	base := []string{"--policy", f.policy, "--repo", "acme/widget"}
	with := func(extra ...string) []string { return append(append([]string{}, base...), extra...) }

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no policy", []string{"--repo", "acme/widget", "--subjects", f.subjects}, "--policy is required"},
		{"no repo", []string{"--policy", f.policy, "--subjects", f.subjects}, "--repo must be owner/name"},
		{"a mode that is neither", with("--mode", "both", "--subjects", f.subjects), "--mode must be bytes or verdict"},
		{
			"a rehearsal asked for a verdict",
			with("--mode", "verdict", "--rehearsal", "--subjects", f.subjects),
			"a rehearsal must never assemble a PASSED verdict",
		},
		{
			"a rehearsal asked for a report",
			with("--rehearsal", "--json", "--subjects", f.subjects),
			"--json has no report to carry in a rehearsal — nothing is judged",
		},
		{
			"an implausible release tag",
			with("--release-tag", "1.0.0; rm -rf", "--subjects", f.subjects),
			"--release-tag is not a plausible release tag",
		},
		{
			"a package that is not name@version",
			with("--package", ".tgz=widget", "--subjects", f.subjects),
			`--package must be <extension>=<name>@<version>, got ".tgz=widget"`,
		},
		{
			"a package with no extension",
			with("--package", "@acme/widget@1.0.0", "--subjects", f.subjects),
			`--package must be <extension>=<name>@<version>`,
		},
		{
			"a package declared twice for one extension",
			with("--package", ".tgz=a@1.0.0", "--package", ".tgz=b@1.0.0", "--subjects", f.subjects),
			"--package names .tgz twice — one extension, one package",
		},
		{"an unreadable policy", []string{"--policy", f.path("absent.json"), "--repo", "a/b"}, "absent.json"},
		{
			"a policy the loader refuses",
			[]string{"--policy", f.subjects, "--repo", "a/b", "--subjects", f.subjects},
			"assert: policy:",
		},
		{
			"a policy with no published section",
			[]string{"--policy", f.bare, "--repo", "a/b", "--subjects", f.subjects},
			"the policy declares no published section — which registry serves which file is the policy's to say",
		},
		{"an unreadable subjects manifest", with("--subjects", f.path("absent.sha256")), "absent.sha256"},
		{"a malformed record", with("--subjects", f.path("junk.sha256")), "subject line 1 is not a sha256sum record"},
		{"an unreadable images file", with("--images", f.path("absent.json")), "absent.json"},
		{
			"images that are no array",
			with("--images", f.path("bad-images.json")),
			"images is not a JSON array of {image, tag, digest}",
		},
		{
			"nothing to prove",
			with("--subjects", f.path("empty.sha256")),
			"nothing to verify — an empty proof is not a proof",
		},
		{
			"a file no registry claims and no release declared",
			with("--subjects", f.path("asset.sha256")),
			"widget-linux.tar.gz: no registry claims this subject type and no release-tag was declared",
		},
		{
			"a declared-coordinate file with no package",
			with("--subjects", f.subjects),
			"acme-widget-1.0.0.tgz is a .tgz subject but no package was declared for .tgz",
		},
		{
			"a debt file that parses as nothing",
			with("--subjects", f.subjects, "--package", ".tgz=@acme/widget@1.0.0", "--debt", f.path("debt.txt")),
			"debt.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stores.asked = nil

			code, stdout, stderr := runPublished(tt.args...)
			if code != exitUsage {
				t.Fatalf("exit %d, want %d (usage)\nstdout: %s\nstderr: %s", code, exitUsage, stdout, stderr)
			}

			if !strings.Contains(stderr, tt.want) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr, tt.want)
			}

			if len(stores.asked) != 0 {
				t.Fatalf("a refused input still asked the stores: %q", stores.asked)
			}
		})
	}

	if code, _, _ := runPublished("--bogus"); code != exitUsage {
		t.Fatalf("an unknown flag exited %d, want %d", code, exitUsage)
	}
}

func TestAssertPublishedVerdicts(t *testing.T) {
	f := newPubFixture(t)
	swapOCI(t, scriptedOCI{resolved: "sha256:" + pubA})

	pkg := []string{"--package", ".tgz=@acme/widget@1.0.0"}

	tests := []struct {
		name    string
		stores  *pubStores
		args    []string
		code    int
		stdout  []string
		stderr  string
		written string // "" when --out must not be written
	}{
		{
			name:   "every subject proved: PASS, the manifest written as the report judged it",
			stores: liveStores(),
			args:   append([]string{"--subjects", f.subjects, "--images", f.images}, pkg...),
			code:   exitOK,
			stdout: []string{"assert: published: verified widget-1.0.0.crate", "assert: PASS"},
			written: pubA + "  widget-1.0.0.crate\n" + pubB + "  acme-widget-1.0.0.tgz\n" +
				pubA + "  ghcr.io/acme/widget\n",
		},
		{
			name: "a release asset is fetched from the forge's public address",
			stores: &pubStores{served: map[string]string{
				"https://github.com/acme/widget/releases/download/v1.0.0/widget-linux.tar.gz": pubA,
			}},
			args:    []string{"--subjects", f.path("asset.sha256"), "--release-tag", "v1.0.0"},
			code:    exitOK,
			stdout:  []string{"assert: PASS"},
			written: pubA + "  widget-linux.tar.gz\n",
		},
		{
			name: "a store serving other bytes: FAIL, named, nothing written",
			stores: &pubStores{served: map[string]string{
				"https://crates.example/crates/widget/widget-1.0.0.crate": pubB,
				"https://npm.example/@acme/widget/-/widget-1.0.0.tgz":     pubB,
			}},
			args: append([]string{"--subjects", f.subjects}, pkg...),
			code: exitRefused,
			stdout: []string{
				"assert: widget-1.0.0.crate: published-bytes: the store served other bytes than were built" +
					` (expected "` + pubA + `", actual "` + pubB + `")`,
				"assert: FAIL",
			},
		},
		{
			name:   "a store that would not answer: CANNOT_JUDGE, named, nothing written",
			stores: &pubStores{},
			args:   append([]string{"--subjects", f.subjects}, pkg...),
			code:   exitBlind,
			stdout: []string{
				"assert: widget-1.0.0.crate: published-read: widget-1.0.0.crate: not served after 10 minutes",
				"assert: CANNOT_JUDGE",
			},
			stderr: "stele assert: the run could not see enough to judge",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swapPublished(t, tt.stores)

			out := filepath.Join(t.TempDir(), "verified.sha256")
			args := append([]string{"--policy", f.policy, "--repo", "acme/widget", "--out", out}, tt.args...)

			code, stdout, stderr := runPublished(args...)
			if code != tt.code {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, tt.code, stdout, stderr)
			}

			for _, want := range tt.stdout {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout lacks %q:\n%s", want, stdout)
				}
			}

			if !strings.Contains(stderr, tt.stderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.stderr)
			}

			written, err := os.ReadFile(out) //nolint:gosec // the test's own temp file
			switch {
			case tt.written == "" && err == nil:
				t.Fatalf("a %d exit wrote the manifest:\n%s", code, written)
			case tt.written != "" && string(written) != tt.written:
				t.Fatalf("manifest =\n%s\nwant\n%s", written, tt.written)
			}
		})
	}
}

func TestAssertPublishedJSON(t *testing.T) {
	f := newPubFixture(t)
	swapPublished(t, liveStores())

	code, stdout, stderr := runPublished("--policy", f.policy, "--repo", "acme/widget", "--json",
		"--subjects", f.subjects, "--package", ".tgz=@acme/widget@1.0.0")
	if code != exitOK {
		t.Fatalf("exit %d\nstderr: %s", code, stderr)
	}

	for _, want := range []string{`"target":"assert published"`, `"subject":"acme/widget"`, `"verdict":"PASS"`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the report lacks %s:\n%s", want, stdout)
		}
	}

	if !strings.Contains(stderr, "assert: published: verified widget-1.0.0.crate") {
		t.Errorf("progress did not move to stderr: %q", stderr)
	}
}

func TestAssertPublishedRehearsal(t *testing.T) {
	f := newPubFixture(t)
	stores := &pubStores{}
	swapPublished(t, stores)

	out := filepath.Join(t.TempDir(), "verified.sha256")

	// No --package and no release: a rehearsal locates nothing and asks
	// nothing — it passes the manifest through, as the dry run always has.
	code, stdout, stderr := runPublished("--policy", f.policy, "--repo", "acme/widget", "--rehearsal",
		"--subjects", f.subjects, "--images", f.images, "--out", out)
	if code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	for _, want := range []string{
		"assert: published: rehearsal: widget-1.0.0.crate was NOT proved against a registry",
		"assert: published: rehearsal: ghcr.io/acme/widget:1.0.0 was NOT resolved against the registry",
		"assert: published: rehearsal — 3 subject(s) passed through, none proved",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}

	if len(stores.asked) != 0 {
		t.Fatalf("a rehearsal asked the stores: %q", stores.asked)
	}

	written, err := os.ReadFile(out) //nolint:gosec // the test's own temp file
	if err != nil {
		t.Fatal(err)
	}

	want := pubA + "  widget-1.0.0.crate\n" + pubB + "  acme-widget-1.0.0.tgz\n" + pubA + "  ghcr.io/acme/widget\n"
	if string(written) != want {
		t.Fatalf("manifest =\n%s\nwant\n%s", written, want)
	}
}

// TestAssertPublishedBrokenOutputs holds the output guards: a manifest
// that could not be written, or a stream that broke, is never success.
func TestAssertPublishedBrokenOutputs(t *testing.T) {
	f := newPubFixture(t)
	swapPublished(t, liveStores())

	unwritable := filepath.Join(f.dir, "no-such-dir", "verified.sha256")
	args := []string{
		"--policy", f.policy, "--repo", "acme/widget", "--subjects", f.subjects,
		"--package", ".tgz=@acme/widget@1.0.0",
	}

	if code, _, _ := runPublished(append(args, "--out", unwritable)...); code != exitIO {
		t.Fatalf("an unwritable manifest exited %d, want %d", code, exitIO)
	}

	if code, _, _ := runPublished(append(args, "--rehearsal", "--out", unwritable)...); code != exitIO {
		t.Fatalf("an unwritable rehearsal manifest exited %d, want %d", code, exitIO)
	}

	if code := Run(append([]string{"assert", "published"}, args...), failWriterI{}, &bytes.Buffer{}); code != exitIO {
		t.Fatalf("a broken progress stream exited %d, want %d", code, exitIO)
	}

	rehearsal := append([]string{"assert", "published", "--rehearsal"}, args...)
	if code := Run(rehearsal, failWriterI{}, &bytes.Buffer{}); code != exitIO {
		t.Fatalf("a broken rehearsal stream exited %d, want %d", code, exitIO)
	}

	failUsage := []string{"assert", "published", "--repo", "acme/widget"}
	if code := Run(failUsage, &bytes.Buffer{}, failWriterI{}); code != exitIO {
		t.Fatalf("a usage refusal on a broken stderr exited %d, want %d", code, exitIO)
	}
}

// TestPublishedFetcherIsTheLadder: the store seam's default is the
// waiting rule's own fetcher, naming the tool to the host.
func TestPublishedFetcherIsTheLadder(t *testing.T) {
	f, ok := newPublishedFetcher().(*published.Fetcher)
	if !ok {
		t.Fatalf("newPublishedFetcher = %T, want the published ladder", newPublishedFetcher())
	}

	if f.UserAgent != "stele assert published" {
		t.Fatalf("UserAgent = %q", f.UserAgent)
	}
}
