// `derive claims`: the enforcement state, read from the forge at this
// moment, turned into the control claims the emitter signs (#40).
//
// The payload this writes is the type the emitter decodes —
// claims.Payload on both sides of the job boundary. The two stages
// must hold disjoint capabilities (the reading credential can never
// be in the signing job, .github#240), so the payload travels as
// bytes; what it must NOT do is travel as two definitions of one
// shape. The `jq -e` shape check the calling action performs today is
// exactly that second definition, and it goes with this cutover.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/claims"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
)

// deriveClaims is the mode name.
const deriveClaims = "claims"

// The rules-reading seam. Concrete on purpose: the live client is
// both a Forge and a RulesReader, and a capture wraps the former to
// record the latter — typing this as one interface would force a
// type assertion whose failure branch no test can reach honestly.
// Tests reach the engine through --snapshot, which is the seam that
// matters.
//
//nolint:gochecknoglobals // test seam, written only by test setup
var newRulesClient = func() *gh.Client {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}

	return gh.New(token)
}

// claimsArgs is everything `derive claims` reads.
type claimsArgs struct {
	policyPath  string
	repo        string
	branch      string
	canonRoot   string
	canonRef    string
	out         string
	snapshotDir string
	captureDir  string
}

// treeDir is the reviewed org tree as a TreeReader: a directory plus
// the ref that names it, so a gated claim's evidence says which
// reviewed code defined the control.
//
// Reads are confined to the tree by construction — a declared path
// that escapes the root is refused rather than followed, because the
// path comes from a policy file and a policy is data.
type treeDir struct {
	root string
	ref  string
}

//nolint:gocritic // unnamedResult: content, found, error — the TreeReader shape
func (t treeDir) File(path string) ([]byte, bool, error) {
	full := filepath.Join(t.root, filepath.FromSlash(path))

	rel, err := filepath.Rel(t.root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, false, fmt.Errorf("claims: %q escapes the reviewed tree", path)
	}

	content, err := os.ReadFile(full) //nolint:gosec // the path is policy-declared and confined above
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}

	if err != nil {
		return nil, false, fmt.Errorf("claims: %w", err)
	}

	return content, true, nil
}

func (t treeDir) Ref() string { return t.ref }

// parseClaimsArgs reads the flag surface.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseClaimsArgs(args []string, stderr io.Writer) (*claimsArgs, int) {
	ca := &claimsArgs{}

	flags := flag.NewFlagSet("stele derive claims", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&ca.policyPath, "policy", "",
		"path to the committed policy whose source.claims declares the control table (required)")
	flags.StringVar(&ca.repo, "repo", "", "owner/name whose enforcement state is read (required)")
	flags.StringVar(&ca.branch, "branch", "", "branch the claims are derived for (required)")
	flags.StringVar(&ca.canonRoot, "canon-root", "",
		"reviewed org tree a gated claim rests on; required when the table declares gatedTask properties")
	flags.StringVar(&ca.canonRef, "canon-digest", "",
		"the ref naming that tree, recorded in gated evidence")
	flags.StringVar(&ca.out, "out", "", "file to write the claims payload to; empty prints to stdout")
	flags.StringVar(&ca.snapshotDir, "snapshot", "", "replay a captured snapshot directory instead of the live API")
	flags.StringVar(&ca.captureDir, "capture", "", "record every live answer into this directory while reading")

	if err := flags.Parse(args); err != nil {
		return ca, exitUsage
	}

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele derive claims: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch {
	case ca.policyPath == "":
		return ca, usageFail("--policy is required")
	case ca.repo == "":
		return ca, usageFail("--repo is required")
	case !strings.Contains(ca.repo, "/"):
		return ca, usageFail("--repo must be owner/name")
	case ca.branch == "":
		return ca, usageFail("--branch is required")
	case ca.snapshotDir != "" && ca.captureDir != "":
		return ca, usageFail("--snapshot and --capture are exclusive: replay reads, capture writes")
	}

	return ca, exitOK
}

// runDeriveClaims loads the table, reads enforcement, and writes the
// payload.
func runDeriveClaims(ca *claimsArgs, doc io.Writer, out *latch) error {
	table, err := claimsTable(ca.policyPath)
	if err != nil {
		return err
	}

	if table.NeedsTree() && ca.canonRoot == "" {
		return errors.New("derive claims: the table declares gatedTask properties, so --canon-root is required —" +
			" a claim carried by the gate rests on the reviewed tree that defines it")
	}

	if table.NeedsTree() && ca.canonRef == "" {
		return errors.New("derive claims: --canon-digest is required beside --canon-root — a gated claim's" +
			" evidence names the tree it rests on, and an unnamed tree is not evidence")
	}

	var rules gh.RulesReader

	switch {
	case ca.snapshotDir != "":
		rules = gh.Snapshot{Dir: ca.snapshotDir}
	case ca.captureDir != "":
		rules = gh.Capture{Live: newRulesClient(), Dir: ca.captureDir}
	default:
		rules = newRulesClient()
	}

	owner, repo, _ := strings.Cut(ca.repo, "/")

	deriver := &claims.Deriver{
		Rules: rules,
		Tree:  treeDir{root: ca.canonRoot, ref: ca.canonRef},
		Now:   func() time.Time { return time.Now().UTC() },
		Log:   out.logf,
	}

	payload, err := deriver.Derive(table, owner, repo, ca.branch)
	if err != nil {
		return err
	}

	// The producing side validates what the consuming side will
	// validate, with the same code. A payload that would be refused at
	// the emitter must not leave here looking like an answer.
	if err := payload.Validate(); err != nil {
		return err
	}

	if err := writeJSONDoc(ca.out, payload, doc, out); err != nil {
		return err
	}

	out.logf("claims: %d control(s) over %s@%s", len(*payload.Controls), ca.repo, ca.branch)

	return nil
}

// claimsTable loads the policy and returns its declared control
// table, refusing at USE when the section is undeclared — the
// universality law: absent means the obligation does not exist, and
// the verb that needs it says so by name.
func claimsTable(path string) (*claims.Table, error) {
	f, err := os.Open(path) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return nil, fmt.Errorf("derive claims: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only close

	pol, err := policy.Load(f)
	if err != nil {
		return nil, err
	}

	if pol.Source == nil || pol.Source.Claims == nil {
		return nil, errors.New("derive claims: the policy declares no source.claims table — the control table is" +
			" an obligation an org declares, and this one has not")
	}

	return pol.Source.Claims, nil
}

// writeJSONDoc places one document: a named file, or the document
// stream when unnamed. The latch is passed for its error latch alone,
// so a failed document write is the same exitIO every other stream
// failure is.
func writeJSONDoc(path string, doc any, stream io.Writer, out *latch) error {
	if path == "" {
		if out.err == nil {
			out.err = jsonx.Encode(stream, doc)
		}

		return nil
	}

	f, err := os.Create(path) //nolint:gosec // the path is the --out flag; writing where asked is the feature
	if err != nil {
		return fmt.Errorf("derive: %w", err)
	}

	if err := jsonx.Encode(f, doc); err != nil {
		return errors.Join(err, f.Close())
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("derive: %w", err)
	}

	return nil
}
