// The permissions target's inputs: two trees and no more. The
// reusable tree is read once from the checkout `--tree` names; the
// callers come either from the checkout `--callers` names — the
// policy's declared caller directories under it — or from every
// repository in the population, walked through the forge.
//
// Both caller shapes exist because the same question is asked at two
// moments. At a pin bump, the callers are the bumping repository's
// own stubs and the tree is the canon it just pinned: the answer is
// actionable in the pull request that changed it. On a schedule, the
// callers are every consumer in the population and the tree is the
// shared repository's current state: the answer is a forecast of the
// next bump. One engine, one policy, two populations.

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

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/population"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/workflow"
)

// assertPermissions runs the caller/callee permissions join.
func assertPermissions(args []string, stdout, stderr io.Writer) int {
	var (
		jsonOut                 bool
		policyPath, treeDir     string
		callersDir, org, repo   string
		debtPath                string
		snapshotDir, captureDir string
	)

	flags := flag.NewFlagSet("stele assert permissions", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&policyPath, "policy", "", "path to the committed assert policy (required)")
	debtFlag(flags, &debtPath)
	flags.StringVar(&treeDir, "tree", ".",
		"checkout root holding the policy's declared reusable workflow tree")
	flags.StringVar(&callersDir, "callers", "",
		`checkout root whose declared caller directories are judged (default ".", exclusive with --org/--repo)`)
	flags.StringVar(&org, "org", "",
		"organisation whose repositories are judged as callers, through the forge (this or --repo)")
	flags.StringVar(&repo, "repo", "",
		"owner/name judged as a caller — the single-repository population (this or --org)")
	flags.StringVar(&snapshotDir, "snapshot", "", "replay a captured snapshot directory instead of the live API")
	flags.StringVar(&captureDir, "capture", "", "record every live answer into this directory while walking")
	flags.BoolVar(&jsonOut, "json", false,
		"emit the verdict as one JSON report document on stdout (progress moves to stderr)")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele assert permissions: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	walked := org != "" || repo != ""

	switch {
	case policyPath == "":
		return usageFail("--policy is required")
	case org != "" && repo != "":
		return usageFail("--org and --repo are exclusive: one population, named once")
	case repo != "" && !strings.Contains(repo, "/"):
		return usageFail("--repo must be owner/name")
	case callersDir != "" && walked:
		return usageFail("--callers reads a checkout and --org/--repo walk the forge: name one caller population")
	case snapshotDir != "" && captureDir != "":
		return usageFail("--snapshot and --capture are exclusive: replay reads, capture writes")
	case (snapshotDir != "" || captureDir != "") && !walked:
		return usageFail("--snapshot and --capture record a forge walk: name --org or --repo")
	case flags.NArg() > 0:
		// Silently ignoring named files would report a green check over
		// a population the caller did not get.
		return usageFail("the callers come from --callers, --org or --repo; extra arguments name nothing")
	}

	pol, code := loadPermissionsPolicy(policyPath, stderr)
	if code != exitOK {
		return code
	}

	tree, err := reusableTree(pol.Permissions, treeDir)
	if err != nil {
		return usageFail(err.Error())
	}

	out := &latch{w: stdout}
	if jsonOut {
		out = &latch{w: stderr}
	}

	// The forge is built only for a walk: a checkout-local run reads
	// nothing over the network, so it needs no credential and no
	// client.
	var forge gh.Forge

	if walked {
		forge = newForge()
		if snapshotDir != "" {
			forge = gh.Snapshot{Dir: snapshotDir}
		} else if captureDir != "" {
			forge = gh.Capture{Live: forge, Dir: captureDir}
		}
	}

	scope := population.Scope{Org: org, Repo: repo}

	j, code := openJournal(debtPathFor(pol, debtPath), targetPermissions, stderr)
	if code != exitOK {
		return code
	}

	subject, callers, err := permissionCallers(pol, scope, callersDir, forge)
	if err != nil {
		return emitReport(blindPermissions(subject, err), jsonOut, stdout, stderr)
	}

	rep, err := assert.Permissions(pol, subject, tree, callers, j, out.logf)
	if out.err != nil {
		return exitIO
	}

	if err != nil {
		if _, werr := fmt.Fprintf(stderr, "%v\n", err); werr != nil {
			return exitIO
		}

		rep = blindPermissions(subject, err)
	}

	return emitReport(rep, jsonOut, stdout, stderr)
}

// blindPermissions seals the report a run that could not gather its
// inputs must still produce: an empty population, so the verdict is
// CANNOT_JUDGE, carrying the reason as a finding rather than only on
// stderr.
func blindPermissions(subject string, err error) *report.Report {
	return refusal(targetPermissions, subject, err.Error(),
		report.PopulationFromEvidence(0, "walk incomplete"))
}

// loadPermissionsPolicy loads the assert policy and refuses one that
// declares no permissions section — the section's PRESENCE is the
// declared obligation, so its absence is a run that was asked for
// nothing, never a run that found nothing.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func loadPermissionsPolicy(path string, stderr io.Writer) (*assert.Policy, int) {
	fail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele assert permissions: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	pf, err := os.Open(path) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return nil, fail(err.Error())
	}
	defer pf.Close() //nolint:errcheck // read-only close

	pol, err := assert.LoadPolicy(pf)
	if err != nil {
		return nil, fail(err.Error())
	}

	if pol.Permissions == nil {
		return nil, fail("the policy declares no permissions section")
	}

	return pol, exitOK
}

// reusableTree reads the declared shared-workflow tree out of the
// checkout. A policy that declares no reusable tree reads none: an
// adopter whose reusable workflows all live beside their callers has
// a join covering local calls alone, and handing it a tree would be
// this tool inventing a convention.
func reusableTree(pp *assert.PermissionsPolicy, root string) ([]workflow.File, error) {
	if pp.Reusable == nil {
		return nil, nil
	}

	files, found, err := workflowDir(root, *pp.Reusable.Dir)
	if err != nil {
		return nil, err
	}

	if !found {
		// Absence here is blindness, not an answer: every call into the
		// declared tree would read as a missing callee, which is a wave
		// of findings that says "the tree is not here" in the least
		// legible way available.
		return nil, fmt.Errorf(
			"the policy declares the reusable tree %s of %s and %s holds no such directory",
			*pp.Reusable.Dir, *pp.Reusable.Repo, root)
	}

	return files, nil
}

// permissionCallers builds the caller sets and the report subject. A
// nil forge is the checkout-local run: no forge, no walk — and no
// population either, because a checkout is not an organisation and
// the declaration says nothing about the directories in front of it.
func permissionCallers(
	pol *assert.Policy, scope population.Scope, callersDir string, forge gh.Forge,
) (string, []assert.CallerSet, error) {
	if forge == nil {
		if callersDir == "" {
			callersDir = "."
		}

		sets, err := localCallers(pol.Permissions, callersDir)

		return callersDir, sets, err
	}

	pop, err := resolvePopulation(scope, forge, pol.Population)
	if err != nil {
		return scope.Subject(), nil, err
	}

	repos, err := assert.PermissionsSubjects.Enumerate(pop)
	if err != nil {
		return scope.Subject(), nil, err
	}

	sets, err := forgeCallers(pop.Owner(), repos, forge)

	return scope.Subject(), sets, err
}

// localCallers reads each declared caller directory out of one
// checkout. A declared directory the checkout does not carry is an
// ANSWER, not a defect: an org declares the directories its trees may
// use, and a consumer that keeps one of them is conforming. What such
// a run judged is carried by the population count, which is files,
// never directories.
func localCallers(pp *assert.PermissionsPolicy, root string) ([]assert.CallerSet, error) {
	sets := make([]assert.CallerSet, 0, len(pp.CallerDirs))

	for _, dir := range pp.CallerDirs {
		files, found, err := workflowDir(root, dir)
		if err != nil {
			return nil, err
		}

		if !found {
			continue
		}

		sets = append(sets, assert.CallerSet{Origin: dir, Dir: dir, Files: files})
	}

	return sets, nil
}

// forgeCallers reads every population member's workflows. One set per
// repository, because a local call names a workflow in its OWN
// repository — merging the population into one set would let one
// repository's workflow answer another's call.
func forgeCallers(owner string, repos []string, forge gh.Forge) ([]assert.CallerSet, error) {
	sets := make([]assert.CallerSet, 0, len(repos))

	for _, repo := range repos {
		files, err := forge.Workflows(owner, repo)
		if err != nil {
			return nil, err
		}

		sets = append(sets, assert.CallerSet{
			Origin: owner + "/" + repo, Dir: gh.WorkflowDir, Files: files,
		})
	}

	return sets, nil
}

// workflowDir reads one directory's workflow files, in name order.
// found=false is the directory's absence, which callers judge for
// themselves: absent is an answer for a caller directory and
// blindness for the reusable tree.
func workflowDir(root, dir string) ([]workflow.File, bool, error) {
	full := filepath.Join(root, dir)

	entries, err := os.ReadDir(full)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}

	if err != nil {
		return nil, false, fmt.Errorf("reading %s: %w", full, err)
	}

	var files []workflow.File

	for _, e := range entries {
		if e.IsDir() || !isWorkflowName(e.Name()) {
			continue
		}

		content, rerr := os.ReadFile(filepath.Join(full, e.Name())) //nolint:gosec // the checkout is operator-supplied
		if rerr != nil {
			return nil, false, fmt.Errorf("reading %s: %w", filepath.Join(full, e.Name()), rerr)
		}

		files = append(files, workflow.File{Name: e.Name(), Content: content})
	}

	return files, true, nil
}

// isWorkflowName reports whether a directory entry is a workflow
// file. The two extensions are the platform's, not an org's — it
// reads workflows from these and ignores everything else in the
// directory, which is why the org's own properties.json files beside
// its templates are not workflows this walk must refuse.
func isWorkflowName(name string) bool {
	ext := filepath.Ext(name)

	return ext == ".yml" || ext == ".yaml"
}
