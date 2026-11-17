// `emit enrichment`: the build-enrichment predicate (stele#392), the
// canon verify-release.yml's "Compute the enrichment facts" step as
// one call. Which names a claim must and may carry is the verify
// policy's build.enrichment; where each name's bytes come from is this
// command's typed input — a tree, a path, and for the one rows kind
// its tables, prefix and keys — because the contents are the write
// side's concern (stele#86). The org's name-to-file mapping lives in
// the caller's workflow, never here.

package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/emit"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/verify"
)

// emitEnrichment is the mode name.
const emitEnrichment = "enrichment"

var (
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	rowKeyRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// sourceFlags is the ordered list of declared sources: --file and
// --rows append to the same list, so the claim lists its dependencies
// in the order the caller declared them.
type sourceFlags struct {
	list *[]emit.Source
	rows bool
}

func (s sourceFlags) String() string { return "" }

// Set reads NAME=TREE:PATH.
func (s sourceFlags) Set(v string) error {
	flagName := "--file"
	if s.rows {
		flagName = "--rows"
	}

	name, spec, ok := strings.Cut(v, "=")
	tree, p, ok2 := strings.Cut(spec, ":")

	switch {
	case !ok || !ok2 || name == "" || p == "":
		return fmt.Errorf("%s %q is not <name>=<tree>:<path>", flagName, v)
	case tree != emit.TreePolicy && tree != emit.TreeSource:
		return fmt.Errorf("%s %q: the tree is %s or %s", flagName, v, emit.TreePolicy, emit.TreeSource)
	case path.IsAbs(p) || path.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../"):
		return fmt.Errorf("%s %q: the path must be clean and stay inside its tree", flagName, v)
	}

	src := emit.Source{Name: name, Tree: tree, Path: p}
	if s.rows {
		src.Rows = &emit.Rows{}
	}

	*s.list = append(*s.list, src)

	return nil
}

// keyedFlags is a repeatable NAME=VALUE, one value per name.
type keyedFlags struct {
	flag   string
	values map[string]string
}

func (k *keyedFlags) String() string { return "" }

func (k *keyedFlags) Set(v string) error {
	name, value, ok := strings.Cut(v, "=")
	if !ok || name == "" {
		return fmt.Errorf("%s %q is not <name>=<value>", k.flag, v)
	}

	if _, dup := k.values[name]; dup {
		return fmt.Errorf("%s names %s twice", k.flag, name)
	}

	k.values[name] = value

	return nil
}

// enrichmentArgs is everything the mode reads.
type enrichmentArgs struct {
	policyPath, policyTree, policyRepo, machinery string
	repo, tag, source, out                        string

	sources                       []emit.Source
	tables, prefixes, files, keys keyedFlags
}

// emitEnrichmentCmd runs `stele emit enrichment`.
func emitEnrichmentCmd(args []string, stdout, stderr io.Writer) int {
	ea := &enrichmentArgs{
		tables:   keyedFlags{flag: "--rows-tables", values: map[string]string{}},
		prefixes: keyedFlags{flag: "--rows-prefix", values: map[string]string{}},
		files:    keyedFlags{flag: "--rows-file", values: map[string]string{}},
		keys:     keyedFlags{flag: "--rows-keys", values: map[string]string{}},
	}

	flags := flag.NewFlagSet("stele emit "+emitEnrichment, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&ea.policyPath, "policy", "",
		"the verify policy: build.enrichment says which names a claim must and may carry (required)")
	flags.StringVar(&ea.policyTree, "policy-tree", "", "the checkout the policy is read from (required)")
	flags.StringVar(&ea.policyRepo, "policy-repo", "", "owner/repo the policy tree is (required)")
	flags.StringVar(&ea.machinery, "machinery-digest", "",
		"the commit the policy tree is pinned at — the claim's policy pin (required)")
	flags.StringVar(&ea.repo, "repo", "", "owner/repo whose release this is (required)")
	flags.StringVar(&ea.tag, "tag", "", "the release tag (required)")
	flags.StringVar(&ea.source, "source-revision", "",
		"the attested source revision — the commit the release was built from (required)")
	flags.Var(sourceFlags{list: &ea.sources}, "file",
		"<name>=<tree>:<path>: claim one file, from the policy or the source tree, repeatable")
	flags.Var(sourceFlags{list: &ea.sources, rows: true}, "rows",
		"<name>=<tree>:<path>: claim rows of one TOML table file, repeatable")
	flags.Var(&ea.tables, "rows-tables", "<name>=<table>,...: the tables a --rows source reads")
	flags.Var(&ea.prefixes, "rows-prefix", "<name>=<prefix>: what each row's value is claimed under")
	flags.Var(&ea.files, "rows-file", "<name>=<claimed name>: claim the rows' file itself beside them")
	flags.Var(&ea.keys, "rows-keys",
		"<name>=<key>,...: the rows the build consumed; empty claims none, and not the file either")
	flags.StringVar(&ea.out, "out", "", "write the predicate here instead of stdout")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	in, p, err := ea.load()
	if err != nil {
		if _, werr := fmt.Fprintf(stderr, "stele emit %s: %v\n", emitEnrichment, err); werr != nil {
			return exitIO
		}

		return exitUsage
	}

	owner, repo, _ := strings.Cut(ea.repo, "/")
	trees := enrichTrees{args: ea, owner: owner, repo: repo, forge: newForge(), urls: gh.New("")}

	return runDeriveMode(ea.out, stdout, stderr, func(doc io.Writer, log *latch) error {
		pred, err := emit.Enrichment(p.Build.Enrichment, in, trees, log.logf)
		if err != nil {
			return err
		}

		return writeJSONDoc(ea.out, pred, doc, log)
	})
}

// load validates every input before a byte is read, and binds the
// claim: the policy's templates expanded for this release, the policy
// document cited at its pin.
//
//nolint:gocritic // unnamedResult: the bound inputs, the policy they came from, any error
func (ea *enrichmentArgs) load() (*emit.EnrichmentInputs, *policy.Policy, error) {
	owner, repo, ok := strings.Cut(ea.repo, "/")
	powner, prepo, pok := strings.Cut(ea.policyRepo, "/")

	switch {
	case ea.policyPath == "":
		return nil, nil, errors.New("--policy is required")
	case !ok || owner == "" || repo == "":
		return nil, nil, errors.New("--repo must be owner/repo")
	case !verify.PlausibleTag(ea.tag):
		return nil, nil, fmt.Errorf("--tag %q is not a plausible release tag", ea.tag)
	case !commitRE.MatchString(ea.source):
		return nil, nil, fmt.Errorf("--source-revision %q is not a commit — enrichment unbound to a revision "+
			"would claim nothing", ea.source)
	case !commitRE.MatchString(ea.machinery):
		return nil, nil, fmt.Errorf("--machinery-digest %q is not a commit — enrichment cannot name its policy",
			ea.machinery)
	case !pok || powner == "" || prepo == "":
		return nil, nil, errors.New("--policy-repo must be owner/repo")
	}

	rel, err := policyPathInTree(ea.policyTree, ea.policyPath)
	if err != nil {
		return nil, nil, err
	}

	raw, err := os.ReadFile(ea.policyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the policy: %w", err)
	}

	p, err := policy.Load(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}

	if p.Build == nil {
		return nil, nil, errors.New("the policy declares no build section — an enrichment binds to the " +
			"resource and repository it names")
	}

	if err := ea.bindRows(); err != nil {
		return nil, nil, err
	}

	c := verify.Coords{Owner: owner, Repo: repo, Tag: ea.tag}

	return &emit.EnrichmentInputs{
		ResourceURI:      verify.Expand(*p.Build.ResourceURI, c),
		SourceRepository: verify.Expand(*p.Build.SourceRepository, c),
		SourceRevision:   ea.source,
		PolicyURI:        gh.New("").BlobURL(powner, prepo, ea.machinery, rel),
		PolicySHA256:     chain.SHA256Hex(raw),
		PolicyCommit:     ea.machinery,
		Sources:          ea.sources,
	}, p, nil
}

// policyPathInTree is the policy document's path within its tree — the
// address it is cited at. A policy outside the tree it claims to be
// read from has no such address.
func policyPathInTree(tree, policyPath string) (string, error) {
	if tree == "" {
		return "", errors.New("--policy-tree is required")
	}

	rel, err := filepath.Rel(tree, policyPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("--policy %s is not inside --policy-tree %s — the policy's address is its path"+
			" in that tree", policyPath, tree)
	}

	return filepath.ToSlash(rel), nil
}

// bindRows attaches each --rows source's parameters, refusing a
// parameter that names no rows source and a rows source missing one.
func (ea *enrichmentArgs) bindRows() error {
	rows := map[string]*emit.Rows{}

	for i := range ea.sources {
		if r := ea.sources[i].Rows; r != nil {
			rows[ea.sources[i].Name] = r
		}
	}

	for _, k := range []*keyedFlags{&ea.tables, &ea.prefixes, &ea.files, &ea.keys} {
		for name := range k.values {
			if rows[name] == nil {
				return fmt.Errorf("%s names %s, which no --rows declares", k.flag, name)
			}
		}
	}

	for i := range ea.sources {
		r := ea.sources[i].Rows
		if r == nil {
			continue
		}

		name := ea.sources[i].Name
		tables, prefix := ea.tables.values[name], ea.prefixes.values[name]

		switch {
		case tables == "":
			return fmt.Errorf("--rows %s declares no --rows-tables", name)
		case prefix == "":
			return fmt.Errorf("--rows %s declares no --rows-prefix", name)
		}

		r.Tables = strings.Split(tables, ",")
		r.Prefix = prefix
		r.File = ea.files.values[name]

		keys := strings.ReplaceAll(ea.keys.values[name], " ", "")
		if keys == "" {
			continue
		}

		for key := range strings.SplitSeq(keys, ",") {
			if !rowKeyRE.MatchString(key) {
				return fmt.Errorf("--rows-keys %s must be comma-separated keys, got: %q", name, ea.keys.values[name])
			}

			r.Keys = append(r.Keys, key)
		}
	}

	return nil
}

// enrichTrees reads the policy tree from the checkout and the released
// source through the forge, at the attested revision.
type enrichTrees struct {
	args        *enrichmentArgs
	owner, repo string
	forge       gh.Forge
	urls        *gh.Client
}

//nolint:gocritic // unnamedResult: the emit.Trees interface documents the results
func (t enrichTrees) Read(tree, p string) ([]byte, bool, error) {
	if tree == emit.TreeSource {
		content, ok, err := t.forge.FileAt(t.owner, t.repo, p, t.args.source)
		if err != nil {
			return nil, false, fmt.Errorf("the forge: %w", err)
		}

		return content, ok, nil
	}

	content, err := os.ReadFile(filepath.Join(t.args.policyTree, filepath.FromSlash(p)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}

	if err != nil {
		return nil, false, fmt.Errorf("the policy tree: %w", err)
	}

	return content, true, nil
}

func (t enrichTrees) URI(tree, p string) string {
	if tree == emit.TreeSource {
		return t.urls.RawURL(t.owner, t.repo, t.args.source, p)
	}

	powner, prepo, _ := strings.Cut(t.args.policyRepo, "/")

	return t.urls.BlobURL(powner, prepo, t.args.machinery, p)
}
