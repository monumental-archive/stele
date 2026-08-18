// `derive facts`: the OCI image metadata a release asserts on its
// images, resolved once before anything is built (#40).
//
// The output contract is `derive version`'s — key=value lines a
// workflow reads directly — because that is what the caller already
// consumes and what the bash wrote into GITHUB_OUTPUT.
//
// The instant is read from a NAMED checkout. The bash reads `git log
// -1` from the current directory, and its own comment records the bug
// that cost: build-pgrx-images once stamped every extension image
// with a canon commit's timestamp, because the script ran in the
// wrong tree. A flag cannot be in the wrong tree by accident.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/gitrepo"
	"github.com/monumental-archive/stele/internal/imagefacts"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/manifest"
)

// deriveFacts is the mode name.
const deriveFacts = "facts"

// The two archetypes, the caller's vocabulary.
const (
	archetypeVersioned  = "versioned"
	archetypeContinuous = "continuous"
)

// defaultServerURL is the forge every identity and repository URI
// lives under when the caller names no other.
const defaultServerURL = "https://github.com"

// The metadata-reading seam, swapped only by tests.
//
//nolint:gochecknoglobals // test seam, written only by test setup
var newMetaClient = func() *gh.Client {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}

	return gh.New(token)
}

// factsHistory is the released checkout, read for exactly two facts:
// which commit is being released, and when it was made. Narrow like
// every other history seam here — this verb never writes and never
// walks a range.
type factsHistory interface {
	Tip(ref string) (string, error)
	CommitTime(rev string) (string, error)
}

// The released-checkout seam, swapped only by tests.
//
//nolint:gochecknoglobals // test seam, written only by test setup
var openFactsGit = func(dir string) (factsHistory, error) {
	return gitrepo.Open(dir, notesRefUnused)
}

// factsArgs is everything `derive facts` reads.
type factsArgs struct {
	archetype   string
	version     string
	repo        string
	serverURL   string
	gitDir      string
	rev         string
	tree        string
	title       string
	description string
}

// parseFactsArgs reads the flag surface.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseFactsArgs(args []string, stderr io.Writer) (*factsArgs, int) {
	fa := &factsArgs{}

	flags := flag.NewFlagSet("stele derive facts", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&fa.archetype, "archetype", "",
		"versioned or continuous; a continuous release has no version surface (required)")
	flags.StringVar(&fa.version, "version", "",
		"the version being released; required for versioned, refused for continuous")
	flags.StringVar(&fa.repo, "repo", "", "owner/name being released (required)")
	flags.StringVar(&fa.serverURL, "server-url", defaultServerURL, "the forge these facts name")
	flags.StringVar(&fa.gitDir, "git-dir", "",
		"the RELEASED checkout, whose commit dates the release (required)")
	flags.StringVar(&fa.rev, "rev", "HEAD", "the revision being released")
	flags.StringVar(&fa.tree, "tree", "",
		"tree whose manifest declares the licence and repository; defaults to --git-dir")
	flags.StringVar(&fa.title, "title", "", "editorial title; defaults to the repository's own name")
	flags.StringVar(&fa.description, "description", "",
		"editorial description; defaults to the forge's, omitted when there is none")

	if err := flags.Parse(args); err != nil {
		return fa, exitUsage
	}

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele derive facts: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch {
	case fa.archetype != archetypeVersioned && fa.archetype != archetypeContinuous:
		return fa, usageFail("--archetype must be versioned or continuous")
	case fa.archetype == archetypeVersioned && fa.version == "":
		return fa, usageFail("--version is required for a versioned release")
	case fa.archetype == archetypeContinuous && fa.version != "":
		return fa, usageFail("a continuous release has no version surface; --version must not be given")
	case fa.repo == "":
		return fa, usageFail("--repo is required")
	case !strings.Contains(fa.repo, "/"):
		return fa, usageFail("--repo must be owner/name")
	case fa.gitDir == "":
		return fa, usageFail("--git-dir is required — the released commit dates the release")
	}

	if fa.tree == "" {
		fa.tree = fa.gitDir
	}

	return fa, exitOK
}

// runDeriveFacts resolves the fact set and reports it.
func runDeriveFacts(fa *factsArgs, out *latch) error {
	owner, repo, _ := strings.Cut(fa.repo, "/")

	// One open, both reads: the revision and its instant are two facts
	// about ONE commit, and reading them through separate handles is
	// how they come to describe different ones.
	history, err := openFactsGit(fa.gitDir)
	if err != nil {
		return err
	}

	revision, err := history.Tip(fa.rev)
	if err != nil {
		return err
	}

	committed, err := releaseInstant(history, revision)
	if err != nil {
		return err
	}

	prov := &imagefacts.Provenance{
		ServerURL: fa.serverURL, Repository: fa.repo,
		Revision: revision, Committed: committed,
	}

	if derr := readDeclarations(fa, prov, out); derr != nil {
		return derr
	}

	if prov.Licence == "" {
		if lerr := licenceFromForge(owner, repo, prov, out); lerr != nil {
			return lerr
		}
	}

	editorial := imagefacts.Editorial{Title: fa.title, Description: fa.description}
	if editorial.Description == "" {
		editorial.Description, err = newMetaClient().Description(owner, repo)
		if err != nil {
			return fmt.Errorf("derive facts: %w", err)
		}
	}

	facts, err := imagefacts.Resolve(archetypeOf(fa), prov, editorial)
	if err != nil {
		return err
	}

	return reportFacts(facts, out)
}

// archetypeOf builds the archetype the flags name. The two shapes are
// two types, so the version travels with the archetype that has one.
//
//nolint:ireturn // the sealed archetype is the point
func archetypeOf(fa *factsArgs) imagefacts.Archetype {
	if fa.archetype == archetypeVersioned {
		return imagefacts.Versioned{Version: fa.version}
	}

	return imagefacts.Continuous{}
}

// releaseInstant reads the released commit's own time. Taken from the
// resolved revision rather than the caller's ref, so the instant and
// the revision cannot name different commits.
func releaseInstant(history factsHistory, revision string) (time.Time, error) {
	stamp, err := history.CommitTime(revision)
	if err != nil {
		return time.Time{}, err
	}

	at, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return time.Time{}, fmt.Errorf("derive facts: %s reported no usable commit date (%q): %w", revision, stamp, err)
	}

	return at, nil
}

// readDeclarations reads what the tree itself says: the licence and,
// where declared, the repository URL the facts are held against.
func readDeclarations(fa *factsArgs, prov *imagefacts.Provenance, out *latch) error {
	licence, ok, err := manifest.CargoPackageField(fa.tree, "license")
	if err != nil {
		return err
	}

	if ok {
		prov.Licence = licence

		out.logf("licence declared by the manifest: %s", licence)
	}

	repository, ok, err := manifest.CargoPackageField(fa.tree, "repository")
	if err != nil {
		return err
	}

	if ok {
		prov.RepositoryField = repository
	}

	return nil
}

// licenceFromForge is the fallback for a tree with no manifest: the
// forge's own detection over the licence file at the released
// revision.
//
// The tiers are NOT cross-checked against each other, deliberately.
// The in-tree field is the author's declaration; the forge's answer
// is a heuristic reading of one file which flattens `MIT OR
// Apache-2.0` to a single id. They are not independent statements of
// one fact, so a mismatch would mean nothing — unlike the repository
// URL, which is checked precisely because it IS one.
func licenceFromForge(owner, repo string, prov *imagefacts.Provenance, out *latch) error {
	id, ok, err := newMetaClient().Licence(owner, repo, prov.Revision)
	if err != nil {
		return fmt.Errorf("derive facts: %w", err)
	}

	if !ok {
		return fmt.Errorf("derive facts: no derivable licence: the tree declares none and the forge detects"+
			" nothing usable at %s", prov.Revision)
	}

	prov.Licence = id

	out.logf("licence detected by the forge: %s", id)

	return nil
}

// reportFacts renders the two values a caller consumes, in the
// key=value shape `derive version` established.
func reportFacts(facts *imagefacts.Facts, out *latch) error {
	encoded, err := jsonx.Marshal(facts.Map())
	if err != nil {
		return fmt.Errorf("derive facts: %w", err)
	}

	if len(encoded) == 0 {
		return errors.New("derive facts: the fact set rendered nothing")
	}

	out.logf("facts=%s", encoded)
	out.logf("epoch=%d", facts.Epoch())

	return nil
}
