// The signer-certificate target's inputs (stele#387): a policy naming
// the log and its signers, a checkpoint file the caller keeps, and the
// one decision a person makes — where a new checkpoint starts.
//
// Where the checkpoint is kept between runs and who is told about a
// finding are the caller's; this verb reads the file it is named and
// writes it back, and nothing else.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/ctlog"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/gitfetch"
	"github.com/monumental-archive/stele/internal/population"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/trust"
)

// defaultSignerBudget bounds a run that names no budget (stele#387).
const defaultSignerBudget = 20 * time.Minute

// The signer target's seams, swapped only by tests: the log's
// transport and clock, and the reconciliation's forge.
//
//nolint:gochecknoglobals // test seams, written only by test setup
var (
	newLogHTTP = func() ctlog.Doer { return &http.Client{} }

	newLogClock = func() ctlog.Clock { return ctlog.WallClock{} }

	newSignerForge = func(forge gh.Forge, git *gitfetch.Session) (assert.SignerForge, string, error) {
		f, server, err := signerForgeOf(forge, git)
		if err != nil {
			return nil, "", err
		}

		return f, server, nil
	}
)

// startAtFlag is --start-at: a tree size, and whether one was given —
// zero is a real place to start, so "unset" cannot be spelled as zero.
type startAtFlag struct {
	size uint64
	set  bool
}

func (s *startAtFlag) String() string {
	if !s.set {
		return ""
	}

	return strconv.FormatUint(s.size, 10)
}

func (s *startAtFlag) Set(v string) error {
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return fmt.Errorf("--start-at takes a tree size: %w", err)
	}

	s.size, s.set = n, true

	return nil
}

// signerArgs is everything the target reads, parsed in one place.
type signerArgs struct {
	jsonOut             bool
	policyPath, cpPath  string
	org, repo, debtPath string
	budget              time.Duration
	startAt             startAtFlag
	root                rootFlags
}

// assertSignerCertificates runs the signer-certificate watch.
func assertSignerCertificates(args []string, stdout, stderr io.Writer) int {
	var a signerArgs

	flags := flag.NewFlagSet("stele assert signer-certificates", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&a.policyPath, "policy", "", "path to the committed assert policy (required)")
	flags.StringVar(&a.cpPath, "checkpoint", "",
		"the checkpoint file this run resumes from and rewrites after every done chunk (required)")
	flags.Var(&a.startAt, "start-at",
		"found a new checkpoint at this tree size — refused when the checkpoint file exists")
	flags.DurationVar(&a.budget, "budget", defaultSignerBudget,
		"how long the run may read; it stops at its last done chunk when this ends")
	flags.StringVar(&a.org, "org", "", "organisation whose population ran the signings (this or --repo)")
	flags.StringVar(&a.repo, "repo", "",
		"owner/name — the single-repository population (this or --org)")
	debtFlag(flags, &a.debtPath)
	a.root.register(flags)
	flags.BoolVar(&a.jsonOut, "json", false,
		"emit the verdict as one JSON report document on stdout (progress moves to stderr)")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele assert signer-certificates: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	if msg := a.refusal(flags.NArg()); msg != "" {
		return usageFail(msg)
	}

	pol, cp, msg := a.load()
	if msg != "" {
		return usageFail(msg)
	}

	verifier, err := a.verifier(pol)
	if err != nil {
		return usageFail(err.Error())
	}

	return a.run(pol, cp, verifier, stdout, stderr)
}

// refusal names the first thing wrong with the invocation itself, ""
// when nothing is.
func (a *signerArgs) refusal(extra int) string {
	switch {
	case a.policyPath == "":
		return "--policy is required"
	case a.cpPath == "":
		return "--checkpoint is required: where the judged prefix is kept is the caller's to say"
	case a.org == "" && a.repo == "":
		return "--org or --repo is required: a certificate's run must be in the population, and the population has an owner"
	case a.org != "" && a.repo != "":
		return "--org and --repo are exclusive: one population, named once"
	case a.repo != "" && !strings.Contains(a.repo, "/"):
		return "--repo must be owner/name"
	case a.budget <= 0:
		return "--budget must be a positive duration"
	case extra > 0:
		return "the log and its signers come from --policy; extra arguments name nothing"
	}

	return ""
}

// load reads the policy and the checkpoint, and refuses every way the
// two disagree with what this run was asked to do.
func (a *signerArgs) load() (*assert.Policy, *ctlog.Checkpoint, string) {
	pf, err := os.Open(a.policyPath)
	if err != nil {
		return nil, nil, err.Error()
	}
	defer pf.Close() //nolint:errcheck // read-only close

	pol, err := assert.LoadPolicy(pf)
	if err != nil {
		return nil, nil, err.Error()
	}

	if pol.SignerCertificates == nil {
		return nil, nil, "the policy declares no signerCertificates section"
	}

	cp, err := ctlog.ReadCheckpoint(a.cpPath)

	switch {
	case errors.Is(err, ctlog.ErrNoCheckpoint) && !a.startAt.set:
		return nil, nil, fmt.Sprintf("no checkpoint at %s and no --start-at: starting is a decision a person makes, "+
			"never one a missing file makes — pass --start-at <tree size> to found one", a.cpPath)
	case errors.Is(err, ctlog.ErrNoCheckpoint):
		return pol, nil, ""
	case err != nil:
		return nil, nil, err.Error()
	case a.startAt.set:
		return nil, nil, fmt.Sprintf("--start-at founds a new checkpoint and %s already holds one "+
			"(next %d): resume without --start-at, or remove the file knowingly", a.cpPath, cp.Next)
	case cp.Log != *pol.SignerCertificates.Log:
		return nil, nil, fmt.Sprintf("the checkpoint at %s is %s's and the policy reads %s",
			a.cpPath, cp.Log, *pol.SignerCertificates.Log)
	}

	return pol, cp, ""
}

// verifier resolves the trusted root and takes its keys for the
// policy's log.
func (a *signerArgs) verifier(pol *assert.Policy) (*ctlog.Verifier, error) {
	rootJSON, err := a.root.resolve()
	if err != nil {
		return nil, err
	}

	trusted, err := trust.LoadRoot(rootJSON)
	if err != nil {
		return nil, err
	}

	return ctlog.NewVerifier(trusted, *pol.SignerCertificates.Log)
}

// run resolves the population and the forge, and runs the watch.
func (a *signerArgs) run(
	pol *assert.Policy, cp *ctlog.Checkpoint, verifier *ctlog.Verifier, stdout, stderr io.Writer,
) int {
	out := &latch{w: stdout}
	if a.jsonOut {
		out = &latch{w: stderr}
	}

	// Whether a commit is on its repository's default branch is read
	// from the fetched history (stele#384): every branch, commits-only,
	// one fetch per repository a match names — none for a range that
	// holds no match.
	git := newGitSession(gitfetch.Want{Heads: true}, out.logf)
	if cerr := git.Check(); cerr != nil {
		if _, werr := fmt.Fprintf(stderr, "stele assert signer-certificates: %v\n", cerr); werr != nil {
			return exitIO
		}

		return exitUsage
	}
	defer closeSession(git, stderr)

	forge := newForge()
	scope := population.Scope{Org: a.org, Repo: a.repo}

	pop, err := resolvePopulation(scope, forge, pol.Population)
	if err != nil {
		return refuseToStart(targetSignerCertificates, scope.Subject(), err, a.jsonOut, stdout, stderr)
	}

	sforge, server, err := newSignerForge(forge, git)
	if err != nil {
		return refuseToStart(targetSignerCertificates, scope.Subject(), err, a.jsonOut, stdout, stderr)
	}

	j, code := openJournal(debtPathFor(pol, a.debtPath), targetSignerCertificates, stderr)
	if code != exitOK {
		return code
	}

	clock := newLogClock()
	path := a.cpPath

	w := &assert.SignerWatch{
		Policy:     pol,
		Population: pop,
		Server:     server,
		Log: &ctlog.Client{
			URL:       *pol.SignerCertificates.Log,
			HTTP:      newLogHTTP(),
			Clock:     clock,
			Deadline:  clock.Now().Add(a.budget),
			UserAgent: "stele assert signer-certificates",
		},
		Verifier:   verifier,
		Forge:      sforge,
		Checkpoint: cp,
		StartAt:    a.startAt.size,
		Save:       func(next *ctlog.Checkpoint) error { return ctlog.WriteCheckpoint(path, next) },
		Progress:   out.logf,
	}

	rep, err := assert.SignerCertificates(context.Background(), w, j)
	if out.err != nil {
		return exitIO
	}

	if err != nil {
		if _, werr := fmt.Fprintf(stderr, "%v\n", err); werr != nil {
			return exitIO
		}

		rep = refusal(targetSignerCertificates, *pol.SignerCertificates.Log, err.Error(),
			report.PopulationFromEvidence(0, "the log's tree head was not verified"))
	}

	return emitReport(rep, a.jsonOut, stdout, stderr)
}

// liveSignerForge is the reconciliation's forge: the run and the file
// are the forge client's own REST reads, and whether a commit is on its
// repository's default branch is the default branch, read from the
// forge, asked of the fetched history (stele#384) — every branch,
// commits-only, at full depth — never a second ancestry reader beside
// it. A commit that history does not hold is on no branch, and so not
// on the default one: the deleted-branch forgery is a finding.
type liveSignerForge struct {
	*gh.Client

	git *gitfetch.Session
}

// OnDefaultBranch implements assert.SignerForge. A repository the
// forge answers 404 for is a read that could not complete — absent and
// invisible to this credential are one answer — never a commit judged
// off its branch. So is a fetch or a git read that fails.
func (f liveSignerForge) OnDefaultBranch(owner, repo, sha string) (bool, error) {
	branch, found, err := f.DefaultBranch(owner, repo)
	if err != nil {
		return false, err
	}

	if !found {
		return false, fmt.Errorf("the forge answers 404 for %s/%s: absent, or not visible to this credential", owner, repo)
	}

	return f.git.OnBranch(owner, repo, sha, "refs/heads/"+branch)
}

// signerForgeOf is the live reconciliation forge over the run's forge
// client and git session, and the web origin certificates name that
// forge by: the server the client was built for (Client.Download is
// that origin, by NewForServer's construction).
func signerForgeOf(forge gh.Forge, git *gitfetch.Session) (liveSignerForge, string, error) {
	c, ok := forge.(*gh.Client)
	if !ok {
		return liveSignerForge{}, "", errors.New("this forge cannot read workflow runs")
	}

	return liveSignerForge{Client: c, git: git}, strings.TrimSuffix(c.Download, "/"), nil
}
