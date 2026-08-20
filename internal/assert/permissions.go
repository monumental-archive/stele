// The caller/callee permissions join (stele#148): what a shared
// workflow's jobs ask for is what its callers must grant.
//
// The platform makes `permissions:` caller-owned. A reusable workflow
// inherits its caller's grant and can only narrow it, so a callee
// that gains a capability is a breaking change to every caller —
// enforced at run time as a startup failure with no jobs and no log,
// the worst available enforcement point. The requirement is
// nevertheless statically computable: the union of the callee's job
// grants is exactly what a caller must hold. This file computes that
// union and compares it, so the seam reddens at the change that adds
// the capability rather than at the first consumer that dies on it.
//
// It is a genuine cross-check, not a derivation verified by its own
// inverse: caller grants are hand-written and callee requirements are
// computed, and the two meet here.
//
// Every convention is DECLARED (the permissions policy section):
// which repository holds the shared workflows, where its tree sits,
// which directories hold callers. Nothing in this file knows an
// owner, a repository or a path. The one thing it does know is the
// platform's own grammar — that a job's `uses:` names either a
// workflow in the caller's own repository or one in another
// repository at a ref — and that is a fact about the forge, the same
// class as the certificate host in store.go.
//
// The walk is closed under its own coverage claim: a call this run
// cannot read, cannot locate, or locates in a file that will not
// parse is a FINDING, never a skip. An unchecked grant that reports
// green is the failure class the whole join exists to remove. The one
// deliberate exception is a call into a repository the policy does
// not declare — third-party and sibling reusable workflows this run
// holds no tree for. Those are outside the declared scope by
// declaration rather than by accident, so they are counted and
// reported as a fact instead of being silently invisible.

package assert

import (
	"errors"
	"path"
	"strconv"

	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/workflow"
)

// The assertion vocabulary for permissions findings.
const (
	assertCallerGrant  = "caller-grant"
	assertCallShape    = "call-shape"
	assertCalleeAbsent = "callee-absent"
	assertCalleeUnread = "callee-unreadable"
	assertCalleeClosed = "callee-not-callable"
	assertWorkflowRead = "workflow-shape"
)

// CallerSet is one tree of workflow files read as callers: a
// repository's own workflows, or one declared directory of the
// checkout. Sets are separate rather than merged because a local
// (`./`) call names a workflow in the CALLER's repository, so which
// files a local call may resolve against is a property of the set,
// not of the run.
type CallerSet struct {
	// Origin names the set in findings — an owner/name for a walked
	// repository, a directory for a local checkout.
	Origin string
	// Dir is the repository-relative directory these files occupy,
	// which is what a local call's path must name to resolve here.
	Dir string
	// Files are the set's workflow files, in the order they are
	// judged.
	Files []workflow.File
}

// Permissions judges every caller against the requirements computed
// from the declared reusable tree and from each caller set's own
// files, and seals the verdict.
//
// tree holds the declared shared-workflow tree's files; it is unused,
// and must be empty, when the policy declares no reusable tree.
func Permissions(
	pol *Policy, subject string, tree []workflow.File, callers []CallerSet, j *report.Journal, log Logf,
) (*report.Report, error) {
	pp := pol.Permissions
	if pp == nil {
		return nil, errors.New("assert: the policy declares no permissions section")
	}

	if pp.Reusable != nil && len(tree) == 0 {
		return nil, errors.New(
			"assert: the policy declares a reusable tree and this run holds no file from it — " +
				"every call into it would read as absent")
	}

	w := &permWalk{pp: pp, tree: indexWorkflows(tree), j: j, log: log}

	w.log("assert: permissions: the declared tree holds %d reusable workflow(s)", w.tree.reusable())

	for _, cs := range callers {
		w.set(cs)
	}

	facts := []report.Fact{
		{Name: "callsChecked", Value: strconv.Itoa(w.checked)},
		{Name: "callsOutsideDeclaredTrees", Value: strconv.Itoa(w.outside)},
		{Name: "reusableWorkflows", Value: strconv.Itoa(w.tree.reusable())},
	}

	pop := report.PopulationFromEvidence(w.files, "workflow files examined for calls")

	// No judged set: nothing downstream iterates the calls this walk
	// checked — the gate and the audit read the verdict, and a set
	// nobody consumes is weight the document does not need.
	return report.Seal("assert permissions", subject, pop, j,
		report.NoCanary(), report.NoJudgedSet(), facts...), nil
}

// wfIndex is one parsed set of workflow files: what read, and why
// what did not. A file that will not parse is kept BY NAME rather
// than dropped, so a call landing on it is answered with the parse
// failure instead of the wrong "no such workflow".
type wfIndex struct {
	docs   map[string]*workflow.Doc
	broken map[string]error
}

func indexWorkflows(files []workflow.File) *wfIndex {
	idx := &wfIndex{docs: map[string]*workflow.Doc{}, broken: map[string]error{}}

	for _, f := range files {
		doc, err := workflow.Parse(f.Content)
		if err != nil {
			idx.broken[f.Name] = err

			continue
		}

		idx.docs[f.Name] = doc
	}

	return idx
}

// reusable counts the callable workflows in the set — the size of the
// requirement side, reported as a fact so a run against an empty or
// misplaced tree is visible in the document rather than only in a
// wave of callee-absent findings.
func (i *wfIndex) reusable() int {
	n := 0

	for _, doc := range i.docs {
		if doc.Reusable {
			n++
		}
	}

	return n
}

type permWalk struct {
	pp      *PermissionsPolicy
	tree    *wfIndex
	j       *report.Journal
	log     Logf
	files   int
	checked int
	outside int
}

// check records one performed check and returns the handle its
// divergence — if it has one — is reported through. Every question
// this walk asks goes through here whether the answer is clean or
// not: an excuse for a check nobody performed must never read as
// stale (#147).
func (w *permWalk) check(subject, assertion string) report.Check {
	return w.j.Check(subject, assertion)
}

// set walks one caller set: its own files index first, because a
// local call resolves against exactly these files.
func (w *permWalk) set(cs CallerSet) {
	own := indexWorkflows(cs.Files)
	before := w.checked

	for _, f := range cs.Files {
		w.files++

		file := path.Join(cs.Origin, f.Name)

		doc, ok := own.docs[f.Name]
		if c := w.check(file, assertWorkflowRead); !ok {
			c.Diverged("the workflow does not read: " + own.broken[f.Name].Error())

			continue
		}

		for i := range doc.Jobs {
			w.job(file, doc, &doc.Jobs[i], &cs, own)
		}
	}

	w.log("assert: permissions: %s: %d file(s), %d call(s) checked", cs.Origin, len(cs.Files), w.checked-before)
}

// job judges one job's call, if it makes one.
func (w *permWalk) job(file string, doc *workflow.Doc, job *workflow.Job, cs *CallerSet, own *wfIndex) {
	if job.Uses == "" {
		return
	}

	subject := file + ":" + job.Name

	ref, err := workflow.ParseRef(job.Uses)
	if c := w.check(subject, assertCallShape); err != nil {
		c.DivergedFrom("", job.Uses,
			"the call does not read ("+err.Error()+") — a call the join cannot read is an unchecked grant")

		return
	}

	callee, ok := w.locate(subject, ref, cs, own)
	if !ok {
		return
	}

	w.checked++
	w.grants(subject, ref.Path, callee.Requirement(), doc.Effective(job))
}

// locate resolves one reference to the callee's parsed workflow,
// reporting every way that can fail. ok=false means no judgment was
// made — either a finding was recorded, or the call is outside the
// declared trees and was counted as such.
func (w *permWalk) locate(subject string, ref workflow.Ref, cs *CallerSet, own *wfIndex) (*workflow.Doc, bool) {
	idx, dir := own, cs.Dir

	if !ref.Local {
		r := w.pp.Reusable
		if r == nil || ref.Owner+"/"+ref.Repo != *r.Repo {
			// Another repository's reusable workflow: this run holds no
			// tree to compute its requirement from, and inventing one
			// would be a guess. Counted, never silent.
			w.outside++

			return nil, false
		}

		idx, dir = w.tree, *r.Dir
	}

	if c := w.check(subject, assertCallShape); ref.Path != path.Join(dir, ref.Name()) {
		c.DivergedFrom(path.Join(dir, ref.Name()), ref.Path,
			"the call names a path outside the tree this run holds for it, so its requirement cannot be computed")

		return nil, false
	}

	err, broken := idx.broken[ref.Name()]
	if c := w.check(subject, assertCalleeUnread); broken {
		c.DivergedFrom("", ref.Path,
			"the callee does not read ("+err.Error()+"), so what it asks of this caller is unknown")

		return nil, false
	}

	doc, found := idx.docs[ref.Name()]
	if c := w.check(subject, assertCalleeAbsent); !found {
		c.DivergedFrom("", ref.Path,
			"the callee is absent from the tree this run holds — an unrecognised callee is an unchecked grant")

		return nil, false
	}

	if c := w.check(subject, assertCalleeClosed); !doc.Reusable {
		c.DivergedFrom("", ref.Path,
			"the callee declares no workflow_call trigger, so this call cannot start at all")

		return nil, false
	}

	return doc, true
}

// grants is the comparison the whole file exists for: every scope the
// callee's jobs ask for, held at least as high by the caller.
func (w *permWalk) grants(subject, callee string, req, granted *workflow.Grant) {
	// A blanket ask is answered by a blanket grant alone. Expanding
	// `read-all` across an enumerated caller grant would need the
	// platform's full scope vocabulary, and a vocabulary hardcoded
	// here goes stale the next time the platform adds a scope —
	// silently, and in the direction that under-reports. Saying so is
	// the honest answer; guessing is not.
	// One recorded check for the comparison, taken before its outcome:
	// a caller whose grants hold is a check that ran clean, which is
	// what an excuse naming it is answered by.
	c := w.check(subject, assertCallerGrant)

	if req.All() > workflow.LevelNone && granted.All() < req.All() {
		c.DivergedFrom("(every scope): "+req.All().String(), "(every scope): "+granted.All().String(),
			"the callee "+callee+" asks for a blanket grant and this caller does not hold one — "+
				"an enumerated grant cannot be proven sufficient without the platform's full scope list")
	}

	for _, scope := range req.Scopes() {
		want, have := req.Level(scope), granted.Level(scope)
		if have >= want {
			continue
		}

		c.DivergedFrom(scope+": "+want.String(), scope+": "+have.String(),
			"the callee "+callee+" asks for it and this caller does not grant it — "+
				"the run dies as a startup failure, no jobs, no log")
	}
}
