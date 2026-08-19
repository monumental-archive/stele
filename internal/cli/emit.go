// The emit verb: argument surface for the two emission modes. `emit
// chain` assembles, signs (via cosign — the capability boundary stays
// above this tool) and appends source chain links; `emit vsa` runs
// the full release verification and renders the build-track VSA
// predicate the workflow then signs — fed by the verdict type, so a
// predicate cannot exist unearned.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/claims"
	"github.com/monumental-archive/stele/internal/emit"
	"github.com/monumental-archive/stele/internal/gitrepo"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/verify"
)

// The two emission modes, the dispatch vocabulary.
const (
	emitChain = "chain"
	emitVSA   = "vsa"
)

// ownerRW is the mode for files this process stages for itself.
const ownerRW = 0o600

// The emit-side effect seams, swapped only by tests — the same
// pattern as the verify seams above.
//
//nolint:gochecknoglobals // test seams, written only by test setup
var (
	newSigner = func(workDir string) emit.Signer {
		return cosignSigner{dir: workDir}
	}

	openEmitGit = func(dir, notesRef, remote, token string) (emit.Git, error) {
		r, err := gitrepo.Open(dir, notesRef)
		if err != nil {
			return nil, err
		}

		return emitGit{Repo: r, remote: remote, token: token}, nil
	}

	// cloneEmitGit prepares a scratch tree and fetches exactly the refs
	// the run needs — the branch under attestation and the ledger the
	// POLICY names. Separate seam from openEmitGit because it is the
	// one that networks, and a run that does not ask for it does not.
	cloneEmitGit = func(dir, notesRef, remote, token, branch, name, email string) (emit.Git, error) {
		r, err := gitrepo.Clone(dir, remote, token, name, email, branch, notesRef)
		if err != nil {
			return nil, err
		}

		if err := r.SetNotesRef(notesRef); err != nil {
			return nil, err
		}

		return emitGit{Repo: r, remote: remote, token: token}, nil
	}

	emitNow = time.Now
)

// emitGit curries the network coordinates onto the repository so the
// engine only ever says fetch and push.
type emitGit struct {
	*gitrepo.Repo

	remote, token string
}

func (g emitGit) FetchNotes() error { return g.Repo.FetchNotes(g.remote, g.token) }

func (g emitGit) DryRunPushNotes(rev string) error {
	return g.Repo.DryRunPushNotes(g.remote, g.token, rev)
}
func (g emitGit) PushNotes() error { return g.Repo.PushNotes(g.remote, g.token) }

// cosignSigner signs by exec'ing cosign sign-blob: the signature and
// its certificate come from the ambient workflow identity, which is
// exactly the point — this binary has no identity of its own.
type cosignSigner struct {
	dir string
}

// Check proves cosign is present and executable — the preflight's
// tooling half, refused by name instead of dying mid-append.
func (c cosignSigner) Check() error {
	//nolint:noctx // local probe, no cancellation surface
	if out, err := exec.Command("cosign", "version").CombinedOutput(); err != nil {
		return fmt.Errorf("cosign is not usable on PATH: %w: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}

func (c cosignSigner) Sign(payload []byte) ([]byte, error) {
	payloadPath := filepath.Join(c.dir, "payload.json")
	bundlePath := filepath.Join(c.dir, "bundle.json")

	if err := os.WriteFile(payloadPath, payload, ownerRW); err != nil {
		return nil, fmt.Errorf("staging the payload: %w", err)
	}

	//nolint:gosec,noctx // fixed executable, paths this process just built
	cmd := exec.Command("cosign", "sign-blob", "--yes", "--bundle", bundlePath, payloadPath)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("cosign sign-blob: %w: %s", err, strings.TrimSpace(string(out)))
	}

	bundle, err := os.ReadFile(bundlePath) //nolint:gosec // G304: a path this process just built in its own temp dir
	if err != nil {
		return nil, fmt.Errorf("reading the signed bundle: %w", err)
	}

	return bundle, nil
}

// emitArgs is everything the two modes read, parsed in one place.
type emitArgs struct {
	policyPath string
	root       rootFlags
	repo       string
	mode       string

	// chain
	gitDir       string
	ref          string
	rev          string
	claims       string
	actor        string
	actorID      string
	remote       string
	clone        string
	committer    string
	genesis      bool
	policyURI    string
	machineryPin string

	// vsa
	tag         string
	subjects    string
	sboms       string
	inventories string
	signerPin   string
	out         string

	p             *policy.Policy
	coords        verify.Coords
	subjectList   []verify.Subject
	sbomList      []verify.Subject
	inventoryList []verify.Subject
	bv            verify.BundleVerifier
	claimsDoc     *claims.Payload
}

// emitCmd dispatches `stele emit <mode>`.
func emitCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		if _, err := fmt.Fprintln(stderr, "stele emit: a mode is required: chain, vsa or manifest"); err != nil {
			return exitIO
		}

		return exitUsage
	}

	mode := args[0]
	switch mode {
	case emitChain, emitVSA:
	case emitManifest:
		// Its own path: it shares none of the chain/vsa flag surface.
		return emitManifestCmd(args[1:], stdout, stderr)
	default:
		if _, err := fmt.Fprintf(stderr, "stele emit: unknown mode %q (chain, vsa, manifest)\n", mode); err != nil {
			return exitIO
		}

		return exitUsage
	}

	ea, code := parseEmitArgs(mode, args[1:], stderr)
	if code != exitOK {
		return code
	}

	out := &latch{w: stdout}

	err := runEmit(ea, out)
	if out.err != nil {
		return exitIO
	}

	if err != nil {
		if _, werr := fmt.Fprintf(stderr, "%v\n", err); werr != nil {
			return exitIO
		}

		return exitRefused
	}

	return exitOK
}

// parseEmitArgs parses flags and loads every file input — all
// refusals land here, before anything signs or writes.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseEmitArgs(mode string, args []string, stderr io.Writer) (*emitArgs, int) {
	ea := &emitArgs{mode: mode}

	fs := flag.NewFlagSet("stele emit "+mode, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&ea.policyPath, "policy", "", "path to the committed verify policy (required)")
	ea.root.register(fs)
	fs.StringVar(&ea.repo, "repo", "", "owner/repo being attested (required)")
	fs.StringVar(&ea.machineryPin, "machinery-digest", "",
		"commit digest the policy tree is pinned at — the VSA's policy.digest (required)")
	fs.StringVar(&ea.policyURI, "policy-uri", "",
		"URI where a stranger reads the policy at that pin (required)")

	switch mode {
	case emitChain:
		fs.StringVar(&ea.gitDir, "git-dir", "",
			"local clone with the branch and notes ref fetched (required without --clone; refused with it)")
		fs.StringVar(&ea.ref, "ref", "refs/heads/main", "fully qualified protected branch ref")
		fs.StringVar(&ea.rev, "rev", "", "the pushed revision (required)")
		fs.StringVar(&ea.claims, "claims", "", "path to the claims stage's payload JSON (required)")
		fs.StringVar(&ea.actor, "actor", "", "login of the actor who triggered the run (required)")
		fs.StringVar(&ea.actorID, "actor-id", "", "id of the actor who triggered the run (required)")
		fs.StringVar(&ea.remote, "remote", "origin", "remote the notes ref is fetched from and pushed to")
		fs.StringVar(&ea.clone, "clone", "",
			"clone URL: the engine materializes its own scratch repository and fetches the branch under "+
				"attestation and the ledger this policy names. Omitted, --git-dir must already exist and "+
				"nothing networks before the push")
		fs.StringVar(&ea.committer, "committer", "",
			"name <email> every note this run writes is authored by; required with --clone, since a scratch "+
				"tree has no identity to inherit and the author lands in a permanent ledger")
		fs.BoolVar(&ea.genesis, "genesis", false,
			"found the chain: refused when any link already exists on the walked history")
	case emitVSA:
		fs.StringVar(&ea.tag, "tag", "", "release tag (required)")
		fs.StringVar(&ea.subjects, "subjects", "", "sha256sum manifest of release subjects (required)")
		fs.StringVar(&ea.sboms, "sboms", "", "sha256sum manifest of the release's SBOM assets (required)")
		fs.StringVar(&ea.inventories, "inventories", "", inventoriesUsage)
		fs.StringVar(&ea.signerPin, "signer-digest", "", "commit digest the signer identity is pinned at (required)")
		fs.StringVar(&ea.out, "out", "", "write the predicate here instead of stdout")
	}

	if err := fs.Parse(args); err != nil {
		return nil, exitUsage
	}

	if code := ea.load(stderr); code != exitOK {
		return nil, code
	}

	return ea, exitOK
}

// load reads and validates the file-backed inputs.
func (ea *emitArgs) load(stderr io.Writer) int {
	fail := func(err error) int {
		if _, werr := fmt.Fprintf(stderr, "stele emit %s: %v\n", ea.mode, err); werr != nil {
			return exitIO
		}

		return exitUsage
	}

	owner, repo, ok := strings.Cut(ea.repo, "/")
	if !ok || owner == "" || repo == "" {
		return fail(errors.New("--repo must be owner/repo"))
	}

	ea.coords = verify.Coords{Owner: owner, Repo: repo, Tag: ea.tag}

	if ea.policyPath == "" {
		return fail(errors.New("--policy is required"))
	}

	pf, err := os.Open(ea.policyPath)
	if err != nil {
		return fail(err)
	}
	defer pf.Close() //nolint:errcheck // read-only close

	ea.p, err = policy.Load(pf)
	if err != nil {
		return fail(err)
	}

	rootJSON, err := ea.root.resolve()
	if err != nil {
		return fail(err)
	}

	ea.bv, err = newBundleVerifier(rootJSON)
	if err != nil {
		return fail(err)
	}

	if ea.mode == emitChain {
		return ea.loadChain(fail)
	}

	return ea.loadVSA(fail)
}

// loadChain reads the chain mode's file inputs.
func (ea *emitArgs) loadChain(fail func(error) int) int {
	switch {
	case ea.clone != "" && ea.gitDir != "":
		return fail(errors.New("--git-dir cannot accompany --clone — the engine materializes its own scratch " +
			"repository, and a caller-named path is the restated preparation --clone exists to remove"))
	case ea.clone == "" && ea.gitDir == "":
		return fail(errors.New("--git-dir is required without --clone"))
	}

	if ea.claims == "" {
		return fail(errors.New("--claims is required"))
	}

	claimsJSON, err := os.ReadFile(ea.claims)
	if err != nil {
		return fail(err)
	}

	ea.claimsDoc, err = jsonx.DecodeBytes[claims.Payload](claimsJSON)
	if err != nil {
		return fail(fmt.Errorf("claims payload: %w", err))
	}

	return exitOK
}

// loadVSA reads the vsa mode's manifests.
func (ea *emitArgs) loadVSA(fail func(error) int) int {
	if ea.subjects == "" {
		return fail(errors.New("--subjects is required"))
	}

	manifest, err := os.ReadFile(ea.subjects)
	if err != nil {
		return fail(err)
	}

	ea.subjectList, err = parseManifest(string(manifest))
	if err != nil {
		return fail(err)
	}

	if ea.sboms == "" {
		return fail(errors.New("--sboms is required"))
	}

	manifest, err = os.ReadFile(ea.sboms)
	if err != nil {
		return fail(err)
	}

	ea.sbomList, err = parseManifest(string(manifest))
	if err != nil {
		return fail(err)
	}

	if ea.inventories != "" {
		manifest, err = os.ReadFile(ea.inventories)
		if err != nil {
			return fail(err)
		}

		ea.inventoryList, err = parsePlan(string(manifest))
		if err != nil {
			return fail(err)
		}
	}

	return exitOK
}

// runEmit runs the selected mode against real dependencies.
func runEmit(ea *emitArgs, out *latch) error {
	if ea.mode == emitChain {
		return runEmitChain(ea, out)
	}

	return runEmitVSA(ea, out)
}

// runEmitChain assembles the engine's dependencies and emits.
func runEmitChain(ea *emitArgs, out *latch) error {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}

	workDir, err := os.MkdirTemp("", "stele-emit-*")
	if err != nil {
		return fmt.Errorf("emit: staging directory: %w", err)
	}
	defer os.RemoveAll(workDir) //nolint:errcheck // best-effort cleanup of a temp dir

	g, err := emitRepo(ea, token, workDir)
	if err != nil {
		return err
	}

	in := &emit.ChainInputs{
		Owner:        ea.coords.Owner,
		Repo:         ea.coords.Repo,
		Ref:          ea.ref,
		Rev:          ea.rev,
		Genesis:      ea.genesis,
		WorkflowRef:  os.Getenv("GITHUB_WORKFLOW_REF"),
		ActorLogin:   ea.actor,
		ActorID:      ea.actorID,
		MachineryRef: ea.machineryPin,
		PolicyURI:    ea.policyURI,
		Claims:       ea.claimsDoc,
	}

	return emit.Chain(ea.p, in, g, newSigner(workDir), ea.bv, emitNow, out.logf)
}

// runEmitVSA verifies the release in full and renders the verdict
// predicate — written whole or not at all.
func runEmitVSA(ea *emitArgs, out *latch) error {
	pins := verify.Pins{Signer: ea.signerPin, Machinery: ea.machineryPin}

	sboms := verify.SBOMs{Assets: ea.sbomList, Planned: ea.inventoryList}

	verdict, err := verify.Release(ea.p, ea.coords, ea.subjectList, sboms, pins, newStore(false), ea.bv, out.logf)
	if err != nil {
		return err
	}

	// The fold's single answer, stated for the orchestration layer:
	// enrichment fetches lockfiles at exactly this revision, and after
	// a passing verdict there is exactly one (the fold refused any
	// disagreement), so printing it here is the safe hand-off.
	out.logf("emit: source revision %s", verdict.SourceRevision())

	when := emitNow().UTC().Truncate(time.Second).Format(time.RFC3339)

	pred, err := verdict.VSAPredicate(ea.p, ea.coords, ea.policyURI, ea.machineryPin, when)
	if err != nil {
		return err
	}

	if ea.out == "" {
		out.logf("%s", pred)

		return nil
	}

	if err := os.WriteFile(ea.out, append(pred, '\n'), ownerRW); err != nil {
		return fmt.Errorf("emit: writing the predicate: %w", err)
	}

	out.logf("emit: vsa predicate for %s@%s written to %s", ea.coords.Slug(), ea.coords.Tag, ea.out)

	return nil
}

// emitRepo opens the tree, preparing it first when the caller asked
// for a clone.
//
// The refs a clone fetches come from the policy this run already
// loaded, which is the point of moving the preparation in: the caller
// used to restate the ledger's ref in a fetch refspec, so a policy
// that named a different one left the emitter looking for a ledger
// nobody brought down — and founding a new chain rather than
// extending one.
//
// The scratch location under --clone is engine-owned: a directory
// inside this run's staging temp, never a caller-named path — the
// missing-directory class that took source-attest down org-wide is
// unrepresentable when no caller supplies a path at all.
//
//nolint:ireturn // the git seam is the point
func emitRepo(ea *emitArgs, token, workDir string) (emit.Git, error) {
	notesRef := *ea.p.Source.NotesRef
	if ea.clone == "" {
		return openEmitGit(ea.gitDir, notesRef, ea.remote, token)
	}

	name, email, err := splitCommitter(ea.committer)
	if err != nil {
		return nil, err
	}

	branch := ea.ref
	if branch == "" {
		return nil, errors.New("emit: --clone needs --ref: the branch under attestation is what it fetches")
	}

	return cloneEmitGit(filepath.Join(workDir, "scratch-repo"), notesRef, ea.clone, token, branch, name, email)
}

// splitCommitter reads a `Name <email>` identity, returning the name,
// the address, and any refusal.
//
//nolint:gocritic // unnamedResult: named results are refused by nonamedreturns
func splitCommitter(spec string) (string, string, error) {
	open := strings.LastIndex(spec, "<")
	if open < 0 || !strings.HasSuffix(strings.TrimSpace(spec), ">") {
		return "", "", fmt.Errorf("emit: --committer %q is not `Name <email>`", spec)
	}

	name := strings.TrimSpace(spec[:open])
	email := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(spec)[open+1:], ">"))

	if name == "" || email == "" {
		return "", "", fmt.Errorf("emit: --committer %q names no author", spec)
	}

	return name, email, nil
}
