// The raw inputs `emit manifest` takes from a publish run (stele#400):
// each class's subject lines as its build legs wrote them, the
// directory of what ships, and the machinery tree whose version the
// manifest states. Before this, a 54-line shell step hashed the
// directory, read the version out of CITATION.cff with awk, and split
// every class's lines into one file per (class, target) to build the
// per-leg flags — so what a subject line MEANS was decided in a
// workflow, untested, beside the reader that later judged it.

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/evidence"
	"github.com/monumental-archive/stele/internal/manifest"
	"github.com/monumental-archive/stele/internal/release"
	"github.com/monumental-archive/stele/internal/verify"
)

// The two flags that take a class's raw lines.
const (
	flagLegLines      = "--leg-lines"
	flagRegistryLines = "--registry-lines"
)

// classLines is the repeatable `<class>=<file>` flag: one class's
// subject lines, `<target> <sha256>  <name>`, exactly as the class's
// build legs emitted them. The class may arrive empty — a publish
// orchestrator passes a derived class name beside subjects that may
// not exist — and is refused only when lines arrive with it.
type classLines []classLineFile

type classLineFile struct {
	class string
	path  string
}

// String implements flag.Value.
func (c *classLines) String() string {
	names := make([]string, 0, len(*c))
	for _, f := range *c {
		names = append(names, f.class)
	}

	return strings.Join(names, ",")
}

// Set implements flag.Value. The path is cut off at the FIRST `=`, so
// a class can never carry one and a path may.
func (c *classLines) Set(v string) error {
	class, path, ok := strings.Cut(v, "=")
	if !ok || strings.TrimSpace(path) == "" {
		return fmt.Errorf("%q is not <class>=<file>", v)
	}

	*c = append(*c, classLineFile{class: strings.TrimSpace(class), path: strings.TrimSpace(path)})

	return nil
}

// plainTarget is a target the manifest can carry as a grain name: the
// alphabet the shell enforced, because a target with a path character
// in it names a place, not a leg.
var plainTarget = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// splitClassLines reads each class's lines and splits them into one
// leg per (class, target), in the order the targets first appear. The
// target column is READ, never invented: the leg that built the
// artifact wrote it, and a line without one is refused rather than
// defaulted, because a subject with no target goes unjudged by every
// scoped rebuild — silently (.github#637).
func splitClassLines(flagName string, files classLines) ([]legSubjectSet, error) {
	var (
		legs  []legSubjectSet
		named = map[string]bool{}
	)

	for _, f := range files {
		raw, err := os.ReadFile(f.path)
		if err != nil {
			return nil, err //nolint:wrapcheck // the path is in the message; a prefix would say it twice
		}

		split, err := splitOneClass(flagName, f.class, string(raw))
		if err != nil {
			return nil, err
		}

		if len(split) == 0 {
			continue
		}

		if named[f.class] {
			return nil, fmt.Errorf("%s names %s twice — one class's legs arrive as one set of lines", flagName, f.class)
		}

		named[f.class] = true
		legs = append(legs, split...)
	}

	return legs, nil
}

// splitOneClass splits one class's lines. Blank lines are not lines;
// input that is all blank contributes nothing, whatever the class.
func splitOneClass(flagName, class, text string) ([]legSubjectSet, error) {
	var (
		legs  []legSubjectSet
		index = map[string]int{}
		n     = 0
	)

	for raw := range strings.Lines(text) {
		n++

		line := strings.TrimRight(raw, "\r\n")
		if strings.TrimSpace(line) == "" {
			continue
		}

		if class == "" {
			return nil, fmt.Errorf("%s: subjects arrived with no class to attribute them to", flagName)
		}

		target, record, ok := strings.Cut(line, " ")
		if !ok || target == "" {
			return nil, fmt.Errorf("%s %s line %d: subject line names no target — an untargeted artifact no"+
				" scoped rebuild judges", flagName, class, n)
		}

		if !plainTarget.MatchString(target) {
			return nil, fmt.Errorf("%s %s line %d: target %q is not a plain name — a target names a build leg,"+
				" and a path character in one names a place", flagName, class, n, target)
		}

		subjects, err := parseManifest(record + "\n")
		if err != nil {
			return nil, fmt.Errorf("%s %s line %d: %w", flagName, class, n, err)
		}

		i, seen := index[target]
		if !seen {
			i = len(legs)
			index[target] = i
			legs = append(legs, legSubjectSet{class: class, target: target, flag: flagName})
		}

		legs[i].subjects = append(legs[i].subjects, subjects...)
	}

	return legs, nil
}

// assetsDirectory refuses an asset directory that is not one, before
// anything is placed into it.
func assetsDirectory(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("--assets-dir: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("--assets-dir: %s is not a directory", dir)
	}

	return nil
}

// hashAssetsDir is `sha256sum ./*` over the directory of what ships,
// in byte order — the order the runner's C.UTF-8 glob listed it. The
// glob skipped dotfiles, so the shell's manifest could silently omit
// one; here a dotfile is refused instead, because an asset this
// manifest does not pin still ships. A subdirectory is refused too:
// a release's assets are files.
func hashAssetsDir(dir string) ([]verify.Subject, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("--assets-dir: %w", err)
	}

	subjects := make([]verify.Subject, 0, len(entries))

	for _, e := range entries {
		name := e.Name()

		switch {
		case strings.HasPrefix(name, "."):
			return nil, fmt.Errorf("--assets-dir: %s is a dotfile — it would ship unpinned, as the shell's glob"+
				" skipped it", name)
		case strings.ContainsAny(name, "\\\n"):
			return nil, fmt.Errorf("--assets-dir: %q carries a character a sha256sum record cannot", name)
		}

		info, serr := os.Stat(filepath.Join(dir, name))
		if serr != nil {
			return nil, fmt.Errorf("--assets-dir: %w", serr)
		}

		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("--assets-dir: %s is not a regular file — a release's assets are files", name)
		}

		digest, derr := release.FileDigest(filepath.Join(dir, name))
		if derr != nil {
			return nil, fmt.Errorf("--assets-dir: %w", derr)
		}

		subjects = append(subjects, verify.Subject{Name: name, SHA256: digest})
	}

	if len(subjects) == 0 {
		return nil, errors.New("--assets-dir: the directory is empty — a manifest that lists nothing says" +
			" nothing about what the release published")
	}

	return subjects, nil
}

// bundlePlacement is one bundle file and the name it ships under.
type bundlePlacement struct {
	src, name string
}

// placeBundles moves each attestation bundle into the asset directory
// under the name it ships as (stele#400). The layout is the artifact
// download's: one directory per bundle, whose NAME is the name the
// bundle is placed under, or — when exactly one artifact was
// downloaded — one flat file, which is the release's umbrella bundle as
// the policy names it. Every placed name must be one the policy's
// evidence vocabulary declares: a provenance placed under a name it
// does not know would be typed as a build subject and judged as one.
//
// Every bundle is checked before any is moved, so a refusal leaves the
// directories as they were.
func placeBundles(bundlesDir, assetsDir string, pol *assert.EvidencePolicy, rehearsal bool) ([]string, error) {
	plan, err := planBundles(bundlesDir, pol)
	if err != nil {
		return nil, err
	}

	if len(plan) == 0 {
		if !rehearsal {
			return nil, errors.New("--bundles-dir: no Sigstore bundle — a release without evidence does not" +
				" publish")
		}

		return []string{"rehearsal: no Sigstore bundle to attach"}, nil
	}

	for _, p := range plan {
		_, serr := os.Lstat(filepath.Join(assetsDir, p.name))

		switch {
		case serr == nil:
			return nil, fmt.Errorf("--bundles-dir: %s already ships in --assets-dir — one name, one file", p.name)
		case !errors.Is(serr, os.ErrNotExist):
			return nil, fmt.Errorf("--assets-dir: %w", serr)
		}
	}

	for _, p := range plan {
		if err := os.Rename(p.src, filepath.Join(assetsDir, p.name)); err != nil {
			return nil, fmt.Errorf("--bundles-dir: placing %s: %w", p.name, err)
		}
	}

	return []string{fmt.Sprintf("%d attestation bundle(s) placed", len(plan))}, nil
}

// planBundles reads the bundle layout and names each bundle. A
// directory that does not exist holds no bundle, which is the state the
// rehearsal rule judges.
func planBundles(bundlesDir string, pol *assert.EvidencePolicy) ([]bundlePlacement, error) {
	entries, err := os.ReadDir(bundlesDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("--bundles-dir: %w", err)
	}

	var dirs, flat []string

	for _, e := range entries {
		switch {
		case strings.HasPrefix(e.Name(), "."):
			return nil, fmt.Errorf("--bundles-dir: %s is a dotfile — a bundle is placed by its name, and a"+
				" hidden name ships hidden", e.Name())
		case e.IsDir():
			dirs = append(dirs, e.Name())
		default:
			flat = append(flat, e.Name())
		}
	}

	switch {
	case len(dirs) > 0 && len(flat) > 0:
		return nil, fmt.Errorf("--bundles-dir holds both a flat bundle (%s) and bundle directories (%s) — one"+
			" layout, or one release's provenance has two names", strings.Join(flat, ", "), strings.Join(dirs, ", "))
	case len(flat) > 1:
		return nil, fmt.Errorf("--bundles-dir holds %d flat files (%s) — a flat bundle is the release's one"+
			" umbrella bundle, and choosing one would ship whichever was listed first",
			len(flat), strings.Join(flat, ", "))
	case len(flat) == 1:
		return []bundlePlacement{{src: filepath.Join(bundlesDir, flat[0]), name: *pol.UmbrellaBundle}}, nil
	}

	plan := make([]bundlePlacement, 0, len(dirs))

	for _, dir := range dirs {
		src, err := oneBundle(filepath.Join(bundlesDir, dir), dir)
		if err != nil {
			return nil, err
		}

		if pol.Classify(dir) != evidence.TypeEvidence {
			return nil, fmt.Errorf("--bundles-dir: %s is not a name the assert policy's evidence vocabulary"+
				" declares — a provenance placed under it would be typed and judged as a build subject", dir)
		}

		plan = append(plan, bundlePlacement{src: src, name: dir})
	}

	return plan, nil
}

// oneBundle returns the one file a bundle directory holds.
func oneBundle(dir, name string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("--bundles-dir: %w", err)
	}

	var files []string

	for _, e := range entries {
		if !e.Type().IsRegular() {
			return "", fmt.Errorf("--bundles-dir: %s holds %s, which is not a file — a bundle is one file",
				name, e.Name())
		}

		files = append(files, e.Name())
	}

	switch len(files) {
	case 0:
		return "", fmt.Errorf("--bundles-dir: empty bundle for %s", name)
	case 1:
		return filepath.Join(dir, files[0]), nil
	default:
		return "", fmt.Errorf("--bundles-dir: %s holds %d files (%s) — one bundle is one file, and choosing"+
			" one would ship whichever was listed first", name, len(files), strings.Join(files, ", "))
	}
}

// machineryOfTree reads the machinery version from the tree the
// publish machinery was resolved to, through the one reader of
// version mirrors — the version is a fact about the TREE, not about
// how a caller spelled the ref it pinned.
func machineryOfTree(root string) (string, error) {
	set, err := manifest.Detect(root)
	if err != nil {
		return "", fmt.Errorf("--machinery-tree %s: %w", root, err)
	}

	version, err := set.Version()
	if err != nil {
		return "", fmt.Errorf("--machinery-tree %s: %w — the manifest cannot state its machinery", root, err)
	}

	return version, nil
}
