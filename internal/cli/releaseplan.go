// `derive release-plan`: the release decisions as one document, for a
// forge executor to run (stele#155). The canon's three release scripts
// each re-derived what the others knew — the version from a tag
// describe here, from a manifest there, from a commit subject in the
// third — and every re-derivation was a place the three could disagree
// about what was being released.
//
// The mode reads and, with --prepare, writes exactly what the plan it
// emits names: the version mirrors and the changelog section. The
// preparation is the plan's own file list applied, never a second
// reading of the tree, so "what was prepared" and "what the executor
// commits" are one list.

package cli

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/monumental-archive/stele/internal/derive"
	"github.com/monumental-archive/stele/internal/manifest"
	"github.com/monumental-archive/stele/internal/release"
)

// deriveReleasePlan is the mode name.
const deriveReleasePlan = "release-plan"

// planArgs is what the plan reads beyond the shared version and notes
// flags. Every value here is an org convention, so every one arrives
// from the caller: a branch name or a subject line in this tool's code
// would be one organisation's release shape made unclaimable by every
// other.
type planArgs struct {
	branch  string
	staging string
	subject string
	also    string
	prepare bool
	out     string
}

// registerPlanFlags adds the plan's own surface to the derive flag set.
func registerPlanFlags(fs *flag.FlagSet, pa *planArgs) {
	fs.StringVar(&pa.branch, "branch", "release/next",
		"branch the release commit lands on; one branch, never one per version")
	fs.StringVar(&pa.staging, "staging", "release-staging/next",
		"disposable ref the release commit is built on, so the release branch never equals the default one")
	fs.StringVar(&pa.subject, "subject", "chore: release "+derive.DefaultTagPrefix+release.VersionToken,
		"release commit subject template, carrying "+release.VersionToken+
			"; the tag leg compares a candidate commit against this rendering")
	fs.StringVar(&pa.also, "also", "",
		"comma-separated further files the release commit carries — the lockfiles an ecosystem's own "+
			"derivation refreshes beside the mirrors")
	fs.BoolVar(&pa.prepare, "prepare", false,
		"write the tree the plan describes: the version mirrors, and the changelog section when --changelog is given")
	fs.StringVar(&pa.out, "out", "", "file to write the plan to; empty prints to stdout")
}

// runDeriveReleasePlan assembles the plan and, under --prepare, writes
// the tree it names.
func runDeriveReleasePlan(da *deriveArgs, na *notesArgs, pa *planArgs, doc io.Writer, out *latch) error {
	d, err := deriveRelease(da, out)
	if err != nil {
		return err
	}

	notes, err := renderNotes(da, na, d)
	if err != nil {
		return err
	}

	in, err := planInputs(da, na, pa, d, notes, out)
	if err != nil {
		return err
	}

	plan, err := release.Assemble(in)
	if err != nil {
		return err
	}

	// The changelog splice is judged on EVERY run, not only the one
	// that writes it (stele#261). A plan is a claim about what the
	// prepare leg will do, so a splice that leg would refuse must
	// refuse here too — a gate running the plain derive that passes on
	// a tree whose release refuses learns it on main, which is the most
	// expensive place to learn it. Judged before the plan is reported
	// or placed, so no document and no progress line ever claims an
	// edit to a changelog state this refuses.
	edit, err := planSplice(da, na, plan)
	if err != nil {
		return err
	}

	if err := reportPlan(plan, out); err != nil {
		return err
	}

	// Preparation happens only for a plan that stands. A refused plan
	// describes a tree state nobody should act on, and writing the
	// mirrors anyway would be the tool overwriting the very evidence it
	// just refused on.
	if pa.prepare && plan.Release {
		if err := preparePlan(da, na, d, plan, edit, out); err != nil {
			return err
		}
	}

	// The same placement every document mode uses: a named file, or
	// the document stream when unnamed.
	if err := writeJSONDoc(pa.out, plan, doc, out); err != nil {
		return err
	}

	if len(plan.Refusals) > 0 {
		return fmt.Errorf("derive release-plan: %s", plan.Refusals[0].Detail)
	}

	return nil
}

// planInputs gathers the tree facts the plan is assembled from. The
// mirrors come from the one detection that also rewrites them, and the
// names already taken from every tag in the repository — reachability
// is the right question for measuring a range and the wrong one for
// minting a name.
func planInputs(
	da *deriveArgs, na *notesArgs, pa *planArgs, d *derived, notes string, out *latch,
) (*release.Inputs, error) {
	set, err := manifest.Detect(da.gitDir)
	if err != nil {
		return nil, err
	}

	in := &release.Inputs{
		Root: da.gitDir, Base: d.base.Version, TagPrefix: da.prefix,
		AppliedBump: d.decision.Applied().String(), RequestedBump: d.decision.Requested().String(),
		Declared: d.decision.Declared(), Notes: notes, Changelog: na.changelog,
		Also: splitTypes(pa.also), Subject: pa.subject, Branch: pa.branch, Staging: pa.staging,
	}

	if next, releases := d.decision.Next(); releases {
		in.Next = next
	}

	if len(set.Sites) > 0 {
		current, verr := set.Version()
		if verr != nil {
			return nil, verr
		}

		in.MirrorsFound = true
		in.MirrorVersion = current
		in.MirrorFiles = set.Files()
	}

	all, err := d.history.AllTags()
	if err != nil {
		return nil, err
	}

	taken, skipped := derive.Versions(da.prefix, all)
	in.Taken = taken

	// Named, never merely dropped: a name checked against a set
	// something was quietly left out of is a weaker check than the
	// reader is being shown.
	for _, tag := range skipped {
		out.logf("skipped %q: in the %q namespace but not a version", tag, da.prefix)
	}

	return in, nil
}

// changelogEdit is the changelog splice a plan names: the path, and
// the bytes the prepare leg places there. Computed once, so the run
// that only judges the splice and the run that performs it cannot be
// two readings of one file.
//
// The zero value names nothing, which is a state and not a defect: no
// changelog was given, or the range releases nothing, and neither has
// a splice to judge.
type changelogEdit struct {
	path    string
	content []byte
}

// named reports whether this edit names a splice at all.
func (e changelogEdit) named() bool { return e.path != "" }

// planSplice computes the plan's changelog edit and writes nothing.
func planSplice(da *deriveArgs, na *notesArgs, plan *release.Plan) (changelogEdit, error) {
	if na.changelog == "" || !plan.Release {
		return changelogEdit{}, nil
	}

	// Tree-relative, like every other path the plan names: the
	// changelog is one of the release commit's contents, and a
	// commit's contents are paths inside the tree.
	path := filepath.Join(da.gitDir, na.changelog)

	content, err := spliced(path, plan.Notes, plan.Version, plan.Tag)
	if err != nil {
		return changelogEdit{}, err
	}

	return changelogEdit{path: path, content: content}, nil
}

// preparePlan writes the tree the plan names: the mirrors to the
// planned version, and the changelog section that is the plan's own
// notes — one rendering reaching the file and the document, so the
// text a reviewer approves and the text a release carries cannot be
// two renderings.
func preparePlan(
	da *deriveArgs, na *notesArgs, d *derived, plan *release.Plan, edit changelogEdit, out *latch,
) error {
	set, err := manifest.Detect(da.gitDir)
	if err != nil {
		return err
	}

	if len(set.Sites) > 0 || set.DateSite != nil {
		date := na.date
		if date == "" {
			if date, err = d.date(); err != nil {
				return err
			}
		}

		files, rerr := set.Rewrite(plan.Version, date)
		if rerr != nil {
			return rerr
		}

		out.logf("prepared mirrors: %s", strings.Join(files, " "))
	}

	// The bytes already computed, never a second splice: the run that
	// judged the changelog and the run that writes it are one reading,
	// so what was judged is what lands.
	if edit.named() {
		if err := writeSpliced(edit.path, edit.content, plan.Version, out); err != nil {
			return err
		}

		out.logf("prepared changelog: %s", na.changelog)
	}

	return nil
}

// reportPlan states the decision on the progress stream, in the
// key=value shape the other derive modes established.
func reportPlan(plan *release.Plan, out *latch) error {
	for _, refusal := range plan.Refusals {
		out.logf("refused=%s", refusal.Cause)
	}

	out.logf("release=%t", plan.Release)

	if plan.Release {
		out.logf("version=%s", plan.Version)
		out.logf("tag=%s", plan.Tag)
		out.logf("declared=%t", plan.Bump.Declared)
		out.logf("files=%s", strings.Join(plan.Commit.Additions, " "))
	}

	return nil
}
