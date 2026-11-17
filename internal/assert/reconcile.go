// The reconciliation: the canon's reconcile.py (.github#1250), ported
// condition for condition, with its one literal — "the canon", the
// repository it ran in — replaced by each signer's declared callers.
// A match is accepted only when all of these hold:
//
//	run            the run exists, in a repository of the population;
//	foreign        every reusable workflow the run called belongs to a
//	               callers repository or is the signer workflow;
//	signer-in-run  the signer workflow was called at exactly D;
//	caller-branch  every candidate caller file is at a commit on its
//	               repository's default branch;
//	chain          at least one candidate, read at that commit, has a
//	               `uses:` of the signer workflow pinned to D;
//	direct         outside the callers, the run's top-level workflow
//	               does not call the signer itself;
//	signer-branch  D is on the signer repository's default branch.
//
// Candidates are the callers' workflows the run called, and — when the
// run is in a callers repository — its own top-level workflow at the
// run's head commit.
//
// "On the default branch" is decided from the repository's default
// branch, as the forge names it, and the fetched history of every
// branch at full depth (stele#384): a commit that history does not
// hold is on no branch — a branch pushed, a certificate minted, the
// branch deleted — and fails `signer-branch` or `caller-branch` as any
// commit off the branch does.
//
// A run the forge answers 404 for is a finding on `run`: deleted
// cannot be told from never existed. Any other read that cannot be
// completed is not a finding — the chunk it sits in is not done.
// Workflow files are read through internal/workflow, the one reader,
// where the canon's matched a regular expression over the text.

package assert

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/monumental-archive/stele/internal/ctlog"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/workflow"
)

// The seven conditions, named as the findings name them.
const (
	assertSignerRun     = "run"
	assertSignerForeign = "foreign"
	assertSignerInRun   = "signer-in-run"
	assertCallerBranch  = "caller-branch"
	assertSignerChain   = "chain"
	assertSignerDirect  = "direct"
	assertSignerBranch  = "signer-branch"
)

// SignerForge is the forge as the reconciliation reads it. found=false
// is the forge's 404 — an answer; an error is a read that did not
// complete. The run is the forge's own decoding (gh.WorkflowRun): one
// definition of what a run is, whichever reader holds it.
type SignerForge interface {
	WorkflowRun(owner, repo string, id uint64) (run *gh.WorkflowRun, found bool, err error)
	FileAt(owner, repo, path, ref string) (content []byte, found bool, err error)
	OnDefaultBranch(owner, repo, sha string) (bool, error)
}

// commitRE is what a Build Signer Digest must be: a git commit, in
// either of git's object formats.
var commitRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// runURIRE is the path of a Run Invocation URI under the forge's web
// origin: /owner/repo/actions/runs/id, optionally one attempt.
var runURIRE = regexp.MustCompile(`^/([^/]+)/([^/]+)/actions/runs/([0-9]+)(?:/attempts/[0-9]+)?$`)

// signer is one declared signing workflow, ready to match.
type signer struct {
	workflow string
	repo     string
	// subject is the URI prefix every certificate issued to this
	// workflow carries: <server>/<workflow>@.
	subject string
	callers map[string]bool
}

// reconciler holds the declared signers, the population and the
// forge, and remembers every completed forge read for the run: a
// release mints one certificate per signing, and each is reconciled
// against the same run and files.
type reconciler struct {
	server  string
	issuer  string
	signers []signer
	members map[string]bool
	forge   SignerForge

	runs     map[string]runRead
	files    map[string]fileRead
	branches map[string]bool

	matches, reconciled int
}

type runRead struct {
	run   *gh.WorkflowRun
	found bool
}

type fileRead struct {
	content []byte
	found   bool
}

func newReconciler(w *SignerWatch, names []string) *reconciler {
	r := &reconciler{
		server:   strings.TrimSuffix(w.Server, "/"),
		issuer:   *w.Policy.Issuer,
		members:  map[string]bool{},
		forge:    w.Forge,
		runs:     map[string]runRead{},
		files:    map[string]fileRead{},
		branches: map[string]bool{},
	}

	for _, name := range names {
		r.members[w.Population.Owner()+"/"+name] = true
	}

	for _, sp := range w.Policy.SignerCertificates.Signers {
		parts := strings.SplitN(*sp.Workflow, "/", minWorkflowSegments)
		s := signer{
			workflow: *sp.Workflow,
			repo:     parts[0] + "/" + parts[1],
			subject:  r.server + "/" + *sp.Workflow + "@",
			callers:  map[string]bool{},
		}

		for _, c := range sp.Callers {
			s.callers[c] = true
		}

		r.signers = append(r.signers, s)
	}

	return r
}

// signerMatch is one certificate issued to a declared signer.
type signerMatch struct {
	index  uint64
	signer *signer
	uri    string
	ext    certificate.Extensions
	// unreadable says why, when the certificate carries a signer's
	// subject but its claims could not be read: still a match, never
	// skipped.
	unreadable string
}

// match reports whether an entry's certificate was issued to a
// declared signer: its subject is the signer's, and its issuer is the
// policy's — the identity is the pair. Most entries never reach the
// certificate parser: a certificate whose subject begins with a
// signer's carries those bytes verbatim, so an entry without them
// cannot be one — the scan is exact, and costs a byte search.
func (r *reconciler) match(e *ctlog.Entry) *signerMatch {
	var hit *signer

	for i := range r.signers {
		if bytes.Contains(e.LeafInput, []byte(r.signers[i].subject)) {
			hit = &r.signers[i]

			break
		}
	}

	if hit == nil {
		return nil
	}

	cert, err := ctlog.ParseLeaf(e.LeafInput)
	if err != nil {
		r.matches++

		return &signerMatch{index: e.Index, signer: hit, unreadable: err.Error()}
	}

	m := r.subjectMatch(e.Index, cert)
	if m == nil {
		return nil
	}

	ext, err := cert.Fulcio()

	switch {
	case err != nil:
		m.unreadable = err.Error()
	case ext.Issuer != r.issuer:
		return nil
	default:
		m.ext = ext
	}

	r.matches++

	return m
}

// subjectMatch finds the signer whose subject one of the certificate's
// URI names begins with.
func (r *reconciler) subjectMatch(index uint64, cert *ctlog.Certificate) *signerMatch {
	for i := range r.signers {
		for _, uri := range cert.URIs {
			if strings.HasPrefix(uri, r.signers[i].subject) {
				return &signerMatch{index: index, signer: &r.signers[i], uri: uri}
			}
		}
	}

	return nil
}

// signerVerdict is one certificate's reconciliation: what was checked,
// what failed and why, and what held.
type signerVerdict struct {
	index   uint64
	claims  string
	checked []string
	failed  []signerFailure
	held    []string
}

type signerFailure struct {
	condition, why string
}

func (v *signerVerdict) check(condition string) {
	if !slices.Contains(v.checked, condition) {
		v.checked = append(v.checked, condition)
	}
}

// fail records a failed condition. A condition fails once per
// certificate however many files failed it — the reasons are joined,
// so the finding a person reads names every file without the report
// counting the same failure seventeen times.
func (v *signerVerdict) fail(condition, why string) {
	v.check(condition)

	for i := range v.failed {
		if v.failed[i].condition == condition {
			v.failed[i].why += "; " + why

			return
		}
	}

	v.failed = append(v.failed, signerFailure{condition: condition, why: why})
}

// subject is the finding subject: the entry's index in the log.
func (v *signerVerdict) subject() string { return "CT index " + strconv.FormatUint(v.index, 10) }

// record writes the verdict through the journal: every condition it
// checked, and a finding per failure carrying the claims read.
func (v *signerVerdict) record(j *report.Journal, log string) {
	for _, c := range v.checked {
		check := j.Check(v.subject(), c)

		for _, f := range v.failed {
			if f.condition == c {
				check.Diverged(fmt.Sprintf("%s (CT index %d of %s; claims read: %s)", f.why, v.index, log, v.claims))
			}
		}
	}
}

// line is the verdict as one log line.
func (v *signerVerdict) line() string {
	if len(v.failed) == 0 {
		return fmt.Sprintf("reconciled %s: %s", v.subject(), strings.Join(v.held, "; "))
	}

	names := make([]string, 0, len(v.failed))
	for _, f := range v.failed {
		names = append(names, f.condition)
	}

	return fmt.Sprintf("NOT reconciled %s (%s)", v.subject(), strings.Join(names, ", "))
}

// reconcile judges one match. An error is a forge read that did not
// complete, and leaves the match unjudged.
func (r *reconciler) reconcile(m *signerMatch) (*signerVerdict, error) {
	v := &signerVerdict{index: m.index, claims: renderClaims(m)}

	if m.unreadable != "" {
		v.fail(assertSignerInRun, "signer claim unreadable: "+m.unreadable)

		return v, nil
	}

	digest := m.ext.BuildSignerDigest
	if !commitRE.MatchString(digest) {
		v.fail(assertSignerInRun, fmt.Sprintf("signer claim unreadable: Build Signer Digest %q is not a commit", digest))

		return v, nil
	}

	run, found, err := r.readRun(v, m)
	if err != nil {
		return nil, err
	}

	if found {
		candidates := r.candidates(v, run, m.signer, digest)

		if derr := r.direct(v, run, m.signer); derr != nil {
			return nil, derr
		}

		if cerr := r.chain(v, candidates, m.signer, digest); cerr != nil {
			return nil, cerr
		}
	}

	owner, repo, _ := strings.Cut(m.signer.repo, "/")

	onBranch, err := r.onDefaultBranch(owner, repo, digest)
	if err != nil {
		return nil, err
	}

	v.check(assertSignerBranch)

	if onBranch {
		v.held = append(v.held, fmt.Sprintf("signer %s on default branch", short(digest)))
	} else {
		v.fail(assertSignerBranch, fmt.Sprintf("signer commit %s is not on %s's default branch", digest, m.signer.repo))
	}

	if len(v.failed) == 0 {
		r.reconciled++
	}

	return v, nil
}

// readRun reads the run the certificate names, judging `run`. found
// is false when `run` failed — a finding, recorded on the verdict.
func (r *reconciler) readRun(v *signerVerdict, m *signerMatch) (*gh.WorkflowRun, bool, error) {
	uri := m.ext.RunInvocationURI

	path, ok := strings.CutPrefix(uri, r.server)
	parts := runURIRE.FindStringSubmatch(path)

	if !ok || parts == nil {
		v.fail(assertSignerRun, fmt.Sprintf("no Run Invocation URI a run can be read from: %q", uri))

		return nil, false, nil
	}

	owner, name := parts[1], parts[2]
	repo := owner + "/" + name

	if !r.members[repo] {
		v.fail(assertSignerRun, repo+" is not a repository of the population")

		return nil, false, nil
	}

	id, ok := runID(parts[3])
	if !ok {
		v.fail(assertSignerRun, fmt.Sprintf("no Run Invocation URI a run can be read from: %q", uri))

		return nil, false, nil
	}

	key := repo + "#" + parts[3]

	read, seen := r.runs[key]
	if !seen {
		got, exists, rerr := r.forge.WorkflowRun(owner, name, id)
		if rerr != nil {
			return nil, false, fmt.Errorf("reading run %d in %s: %w", id, repo, rerr)
		}

		read = runRead{run: got, found: exists}
		r.runs[key] = read
	}

	if !read.found {
		v.fail(assertSignerRun, fmt.Sprintf("run %d does not exist in %s (never existed, or deleted)", id, repo))

		return nil, false, nil
	}

	v.check(assertSignerRun)
	v.held = append(v.held, fmt.Sprintf("run %s (%s, %s)", read.run.HTMLURL, read.run.Path, read.run.Event))

	return read.run, true, nil
}

// runID reads a run id; the URI pattern has already made it digits, so
// what can still fail is a number no run id can be.
func runID(digits string) (uint64, bool) {
	id, err := strconv.ParseUint(digits, 10, 64)

	return id, err == nil
}

// candidate is one caller file the chain may run through.
type candidate struct {
	repo, path, sha string
}

// candidates judges `foreign` and `signer-in-run` over the reusable
// workflows the run called, and collects the chain's candidates.
func (r *reconciler) candidates(v *signerVerdict, run *gh.WorkflowRun, s *signer, digest string) []candidate {
	v.check(assertSignerForeign)
	v.check(assertSignerInRun)

	var (
		signerSHAs []string
		out        []candidate
	)

	for _, ref := range run.Referenced {
		target, _, _ := strings.Cut(ref.Path, "@")
		parts := strings.SplitN(target, "/", minWorkflowSegments)

		switch {
		case target == s.workflow:
			signerSHAs = append(signerSHAs, ref.SHA)
		case len(parts) == minWorkflowSegments && s.callers[parts[0]+"/"+parts[1]]:
			out = append(out, candidate{repo: parts[0] + "/" + parts[1], path: parts[2], sha: ref.SHA})
		default:
			v.fail(assertSignerForeign, fmt.Sprintf(
				"the run called %s, which is neither a callers repository's workflow nor the signer's", ref.Path,
			))
		}
	}

	if !slices.Contains(signerSHAs, digest) {
		called := "no commit"
		if len(signerSHAs) > 0 {
			slices.Sort(signerSHAs)
			called = strings.Join(slices.Compact(signerSHAs), ", ")
		}

		v.fail(assertSignerInRun, fmt.Sprintf("the run called %s at %s, the certificate says %s", s.workflow, called, digest))
	}

	if s.callers[run.Repository] {
		out = append(out, candidate{repo: run.Repository, path: run.Path, sha: run.HeadSHA})
	}

	slices.SortFunc(out, func(a, b candidate) int {
		return strings.Compare(a.repo+"/"+a.path+"@"+a.sha, b.repo+"/"+b.path+"@"+b.sha)
	})

	return slices.Compact(out)
}

// direct judges `direct`: outside the callers, the run's own workflow
// must not call the signer — a repository reaches the signer only
// through a callers repository's workflow.
func (r *reconciler) direct(v *signerVerdict, run *gh.WorkflowRun, s *signer) error {
	if s.callers[run.Repository] {
		return nil
	}

	v.check(assertSignerDirect)

	owner, name, _ := strings.Cut(run.Repository, "/")

	content, found, err := r.fileAt(owner, name, run.Path, run.HeadSHA)
	if err != nil {
		return err
	}

	where := fmt.Sprintf("%s's %s at %s", run.Repository, run.Path, run.HeadSHA)

	if !found {
		// The run exists and its workflow does not, at the run's own
		// commit: nothing shows the file does not call the signer.
		v.fail(assertSignerDirect, where+" is absent, so it cannot be shown not to call the signer")

		return nil
	}

	calls, perr := callsSigner(content, s, "")

	switch {
	case perr != nil:
		v.fail(assertSignerDirect, fmt.Sprintf("%s does not parse, so it cannot be shown not to call the signer: %v",
			where, perr))
	case calls:
		v.fail(assertSignerDirect, where+" calls the signer itself")
	}

	return nil
}

// chain judges `caller-branch` over every candidate and `chain` over
// the first that pins the signer at the certificate's digest.
func (r *reconciler) chain(v *signerVerdict, cands []candidate, s *signer, digest string) error {
	v.check(assertSignerChain)

	if len(cands) > 0 {
		v.check(assertCallerBranch)
	}

	for _, c := range cands {
		owner, name, _ := strings.Cut(c.repo, "/")

		on, err := r.onDefaultBranch(owner, name, c.sha)
		if err != nil {
			return err
		}

		if !on {
			v.fail(assertCallerBranch, fmt.Sprintf("%s/%s at %s is not on %s's default branch", c.repo, c.path, c.sha, c.repo))
		}
	}

	var unread []string

	for _, c := range cands {
		owner, name, _ := strings.Cut(c.repo, "/")

		content, found, err := r.fileAt(owner, name, c.path, c.sha)
		if err != nil {
			return err
		}

		if !found {
			unread = append(unread, fmt.Sprintf("%s/%s@%s is absent", c.repo, c.path, c.sha))

			continue
		}

		pins, perr := callsSigner(content, s, digest)
		if perr != nil {
			unread = append(unread, fmt.Sprintf("%s/%s@%s does not parse: %v", c.repo, c.path, c.sha, perr))

			continue
		}

		if pins {
			v.held = append(v.held, fmt.Sprintf("chain %s/%s@%s calls %s@%s", c.repo, c.path, short(c.sha),
				s.workflow, short(digest)))

			return nil
		}
	}

	why := fmt.Sprintf("no callers workflow the run used calls %s@%s", s.workflow, digest)
	if len(unread) > 0 {
		why += " (" + strings.Join(unread, "; ") + ")"
	}

	v.fail(assertSignerChain, why)

	return nil
}

// callsSigner reports whether a workflow file has a job calling the
// signer — at digest when one is given, at any ref otherwise. A
// `uses:` the platform's grammar cannot read is not a call this file
// makes: the platform would refuse it too.
func callsSigner(content []byte, s *signer, digest string) (bool, error) {
	doc, err := workflow.Parse(content)
	if err != nil {
		return false, err
	}

	for _, job := range doc.Jobs {
		if job.Uses == "" {
			continue
		}

		ref, rerr := workflow.ParseRef(job.Uses)
		if rerr != nil || ref.Local {
			continue
		}

		if ref.Owner+"/"+ref.Repo+"/"+ref.Path == s.workflow && (digest == "" || ref.Version == digest) {
			return true, nil
		}
	}

	return false, nil
}

// fileAt reads a file at a commit once per run.
//
//nolint:gocritic // unnamedResult: the forge seam's own shape (SignerForge.FileAt), and nonamedreturns forbids names
func (r *reconciler) fileAt(owner, repo, path, sha string) ([]byte, bool, error) {
	key := owner + "/" + repo + "/" + path + "@" + sha

	if read, ok := r.files[key]; ok {
		return read.content, read.found, nil
	}

	content, found, err := r.forge.FileAt(owner, repo, path, sha)
	if err != nil {
		return nil, false, fmt.Errorf("reading %s: %w", key, err)
	}

	r.files[key] = fileRead{content: content, found: found}

	return content, found, nil
}

func (r *reconciler) onDefaultBranch(owner, repo, sha string) (bool, error) {
	key := owner + "/" + repo + "@" + sha

	if on, ok := r.branches[key]; ok {
		return on, nil
	}

	on, err := r.forge.OnDefaultBranch(owner, repo, sha)
	if err != nil {
		return false, fmt.Errorf("asking whether %s is on its default branch: %w", key, err)
	}

	r.branches[key] = on

	return on, nil
}

// renderClaims is the claims a finding carries: what the certificate
// said, so a person can read the certificate's story without the log.
func renderClaims(m *signerMatch) string {
	if m.unreadable != "" {
		return "san=" + m.uri
	}

	pairs := [][2]string{
		{"build_config_uri", m.ext.BuildConfigURI},
		{"build_signer_digest", m.ext.BuildSignerDigest},
		{"build_signer_uri", m.ext.BuildSignerURI},
		{"issuer", m.ext.Issuer},
		{"run_invocation_uri", m.ext.RunInvocationURI},
		{"san", m.uri},
		{"source_repository_digest", m.ext.SourceRepositoryDigest},
		{"source_repository_ref", m.ext.SourceRepositoryRef},
		{"source_repository_uri", m.ext.SourceRepositoryURI},
	}

	out := make([]string, 0, len(pairs))

	for _, p := range pairs {
		if p[1] != "" {
			out = append(out, p[0]+"="+p[1])
		}
	}

	return strings.Join(out, ", ")
}

// shortLen is how much of a commit a log line prints.
const shortLen = 12

func short(sha string) string { return sha[:min(len(sha), shortLen)] }
