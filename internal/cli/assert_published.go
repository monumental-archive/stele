// `assert published`: the published-bytes proof (stele#392) — the
// canon verify-release.yml's "Prove each declared subject against the
// registry" step, as one call. Every refusal of the INPUT (a record
// that is not one, a subject no store claims, a package nobody
// declared, a rehearsal asked for a verdict) is a usage refusal before
// any store is asked; the judgment itself seals the report's
// tri-state, so a store that would not answer exits 4, never 1.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/published"
	"github.com/monumental-archive/stele/internal/verify"
)

const targetPublished = "published"

// The two modes the proof runs in. They differ in one rule alone: a
// rehearsal may pass a bytes leg's manifest through, unproved and
// saying so, but never feed a verdict.
const (
	publishedBytes   = "bytes"
	publishedVerdict = "verdict"
)

// newPublishedFetcher is the store seam, swapped only by tests.
//
//nolint:gochecknoglobals // test seam, written only by test setup
var newPublishedFetcher = func() assert.BytesFetcher { return published.New("stele assert published") }

// packageFlags is the repeatable --package EXT=NAME@VERSION: one
// declared coordinate per extension.
type packageFlags map[string]assert.Package

// String implements flag.Value.
func (p *packageFlags) String() string { return strings.Join(slices.Sorted(maps.Keys(*p)), ",") }

// Set implements flag.Value. The version splits off the LAST `@`, so a
// scoped name (@scope/pkg) survives.
func (p *packageFlags) Set(v string) error {
	ext, coord, ok := strings.Cut(v, "=")
	at := strings.LastIndex(coord, "@")

	if !ok || ext == "" || at <= 0 || at == len(coord)-1 {
		return fmt.Errorf("--package must be <extension>=<name>@<version>, got %q", v)
	}

	if *p == nil {
		*p = packageFlags{}
	}

	if _, dup := (*p)[ext]; dup {
		return fmt.Errorf("--package names %s twice — one extension, one package", ext)
	}

	(*p)[ext] = assert.Package{Name: coord[:at], Version: coord[at+1:]}

	return nil
}

// publishedArgs is everything the target reads.
type publishedArgs struct {
	policyPath, repo, releaseTag string
	subjectsPath, imagesPath     string
	mode, out, debtPath          string
	rehearsal, jsonOut           bool
	packages                     packageFlags
}

// assertPublished runs the published-bytes proof.
func assertPublished(args []string, stdout, stderr io.Writer) int {
	pa := &publishedArgs{}

	flags := flag.NewFlagSet("stele assert published", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&pa.policyPath, "policy", "",
		"path to the committed assert policy; its published section says which registry serves which file (required)")
	flags.StringVar(&pa.repo, "repo", "", "owner/name whose release this is, named in the report (required)")
	flags.StringVar(&pa.releaseTag, "release-tag", "",
		"declares that a file no registry claims is an asset of this published release; without it, such a "+
			"file is refused")
	flags.StringVar(&pa.subjectsPath, "subjects", "", "sha256sum manifest of the file subjects")
	flags.StringVar(&pa.imagesPath, "images", "",
		"JSON array of image subjects, {image, tag, digest}; extra keys are ignored")
	flags.Var(&pa.packages, "package",
		"<extension>=<name>@<version>: the package a declared-coordinate registry's files belong to, repeatable")
	flags.StringVar(&pa.mode, "mode", publishedBytes,
		"bytes (default) or verdict: what the proven manifest feeds — a rehearsal may feed only bytes")
	flags.BoolVar(&pa.rehearsal, "rehearsal", false,
		"nothing was published: pass the manifest through unproved, saying so per subject (bytes mode only)")
	flags.StringVar(&pa.out, "out", "",
		"write the proven manifest here — on PASS, or in a rehearsal the manifest passed through")
	debtFlag(flags, &pa.debtPath)
	flags.BoolVar(&pa.jsonOut, "json", false,
		"emit the verdict as one JSON report document on stdout (progress moves to stderr)")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	usageFail := func(err error) int {
		if _, werr := fmt.Fprintf(stderr, "stele assert published: %v\n", err); werr != nil {
			return exitIO
		}

		return exitUsage
	}

	if err := pa.check(); err != nil {
		return usageFail(err)
	}

	pol, files, images, err := pa.load()
	if err != nil {
		return usageFail(err)
	}

	out := &latch{w: stdout}
	if pa.jsonOut {
		out = &latch{w: stderr}
	}

	if pa.rehearsal {
		return pa.rehearse(files, images, out)
	}

	located, err := pa.locate(pol, files)
	if err != nil {
		return usageFail(err)
	}

	j, code := openJournal(debtPathFor(pol, pa.debtPath), targetPublished, stderr)
	if code != exitOK {
		return code
	}

	rep := assert.Published(pa.repo+pa.atTag(), located, images, newPublishedFetcher(), newOCIReader(), j, out.logf)

	if pa.out != "" && rep.Passed() {
		if code := writeDoc(pa.out, func(w io.Writer) error { return writeJudgedLines(w, rep.Judged()) }); code != exitOK {
			return code
		}
	}

	if out.err != nil {
		return exitIO
	}

	return emitReport(rep, pa.jsonOut, stdout, stderr)
}

// check holds the flag surface together before anything is read.
func (pa *publishedArgs) check() error {
	switch {
	case pa.policyPath == "":
		return errors.New("--policy is required")
	case !strings.Contains(pa.repo, "/"):
		return errors.New("--repo must be owner/name")
	case pa.mode != publishedBytes && pa.mode != publishedVerdict:
		return errors.New("--mode must be bytes or verdict")
	case pa.rehearsal && pa.mode == publishedVerdict:
		return errors.New("a rehearsal must never assemble a PASSED verdict")
	case pa.rehearsal && pa.jsonOut:
		return errors.New("--json has no report to carry in a rehearsal — nothing is judged")
	case pa.releaseTag != "" && !verify.PlausibleTag(pa.releaseTag):
		return errors.New("--release-tag is not a plausible release tag")
	}

	return nil
}

// load reads the policy and the two subject inputs; an empty proof
// refuses here, before any store is asked.
func (pa *publishedArgs) load() (*assert.Policy, []published.File, []published.Image, error) {
	pf, err := os.Open(pa.policyPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading the policy: %w", err)
	}
	defer pf.Close() //nolint:errcheck // read-only close

	pol, err := assert.LoadPolicy(pf)
	if err != nil {
		return nil, nil, nil, err
	}

	if pol.Published == nil {
		return nil, nil, nil, errors.New("the policy declares no published section — which registry serves" +
			" which file is the policy's to say")
	}

	var (
		files  []published.File
		images []published.Image
	)

	if pa.subjectsPath != "" {
		text, rerr := os.ReadFile(pa.subjectsPath)
		if rerr != nil {
			return nil, nil, nil, fmt.Errorf("reading the subjects: %w", rerr)
		}

		if files, err = published.ParseFiles(string(text)); err != nil {
			return nil, nil, nil, err
		}
	}

	if pa.imagesPath != "" {
		text, rerr := os.ReadFile(pa.imagesPath)
		if rerr != nil {
			return nil, nil, nil, fmt.Errorf("reading the images: %w", rerr)
		}

		if images, err = published.ParseImages(string(text)); err != nil {
			return nil, nil, nil, err
		}
	}

	if len(files)+len(images) == 0 {
		return nil, nil, nil, published.ErrEmpty
	}

	return pol, files, images, nil
}

// locate resolves every file subject's address before any store is
// asked: a subject that cannot be located is a refusal of the input.
func (pa *publishedArgs) locate(pol *assert.Policy, files []published.File) ([]assert.PublishedFile, error) {
	loc := &assert.Locator{Registries: pol.Published.Registries, Packages: pa.packages}

	if pa.releaseTag != "" {
		owner, repo, _ := strings.Cut(pa.repo, "/")
		forge := gh.New("")
		loc.Asset = func(name string) string { return forge.AssetURL(owner, repo, pa.releaseTag, name) }
	}

	located := make([]assert.PublishedFile, 0, len(files))

	for _, f := range files {
		u, err := loc.Locate(f.Name)
		if err != nil {
			return nil, err
		}

		located = append(located, assert.PublishedFile{Name: f.Name, SHA256: f.SHA256, URL: u})
	}

	return located, nil
}

// rehearse is the dry run: nothing was published, so nothing is
// proved, the manifest passes through as built, and every subject says
// so by name. No report is sealed — a rehearsal judges nothing.
func (pa *publishedArgs) rehearse(files []published.File, images []published.Image, out *latch) int {
	lines := published.Rehearse(files, images, func(format string, args ...any) {
		out.logf("assert: published: "+format, args...)
	})

	if pa.out != "" {
		text := make([]string, 0, len(lines))
		for _, l := range lines {
			text = append(text, l.String())
		}

		if code := writeDoc(pa.out, func(w io.Writer) error { return writeLines(w, text) }); code != exitOK {
			return code
		}
	}

	out.logf("assert: published: rehearsal — %d subject(s) passed through, none proved", len(lines))

	if out.err != nil {
		return exitIO
	}

	return exitOK
}

// atTag renders the release in the report's subject, when one was
// declared.
func (pa *publishedArgs) atTag() string {
	if pa.releaseTag == "" {
		return ""
	}

	return "@" + pa.releaseTag
}

// writeJudgedLines writes the judged set — the proven sha256sum lines,
// as the report carries them — back out as a manifest: the same lines,
// never a second rendering of the inputs.
func writeJudgedLines(w io.Writer, judged jsonx.Raw) error {
	lines, err := jsonx.DecodeBytes[[]string](judged)
	if err != nil {
		return err
	}

	return writeLines(w, *lines)
}

// writeLines writes one manifest, a line per subject.
func writeLines(w io.Writer, lines []string) error {
	if _, err := io.WriteString(w, strings.Join(lines, "\n")+"\n"); err != nil {
		return fmt.Errorf("writing the manifest: %w", err)
	}

	return nil
}
