// `verify repro`'s pre-release form (stele#401): the first build
// against the rebuild, before anything is published. The canon's
// publish run used to compare them in shell — two subject manifests
// as equal strings with a raw `diff` on failure, and the image classes'
// digest files one `cmp` at a time — so the gate that decides whether
// a release may publish spoke a different language from the verdict
// the post-release form gives the same question afterwards.
//
// One comparison engine serves both forms (verify.Repro): the first
// build is the population, the rebuild is the lookup, and every
// artifact is one typed finding — diverged, absent from the rebuild,
// or produced only by the rebuild. What is new here is only where the
// two sets come from.

package cli

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/monumental-archive/stele/internal/release"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/verify"
)

// buildInputs is the repeatable `<class>=<path>` flag naming one
// build's output for one class: a sha256sum manifest for a class that
// ships files, the directory of digest files for a class that pushes
// to a registry. Which it is, is the class's definition.
type buildInputs map[string]string

// String implements flag.Value.
func (b *buildInputs) String() string {
	names := make([]string, 0, len(*b))
	for class := range *b {
		names = append(names, class)
	}

	return strings.Join(names, ",")
}

// Set implements flag.Value. One class has one output per build:
// naming it twice is two answers for what that build produced.
func (b *buildInputs) Set(v string) error {
	class, path, ok := strings.Cut(v, "=")

	class, path = strings.TrimSpace(class), strings.TrimSpace(path)
	if !ok || class == "" || path == "" {
		return fmt.Errorf("%q is not <class>=<path>", v)
	}

	if *b == nil {
		*b = buildInputs{}
	}

	if _, twice := (*b)[class]; twice {
		return fmt.Errorf("%s is named twice — one build has one output per class", class)
	}

	(*b)[class] = path

	return nil
}

// preReleaseArgs is the pre-release form's surface.
type preReleaseArgs struct {
	repo, tag, classes string
	// policy is the assert policy whose evidence.classes declare each
	// requested class's subject shape: whether it ships files or pushes
	// to a registry, and how its legs record what they pushed. No class
	// is named in code (stele#442).
	policy             string
	first, rebuild     buildInputs
	rehearsal, jsonOut bool
}

// classBuilds is one class's output from each build.
type classBuilds struct {
	first, rebuilt []verify.Subject
}

// emptyProof is the refusal both "nothing" states share, in the
// words the shell used.
const emptyProof = "an empty proof is not a proof"

// reproRefusal is a refusal and the exit code it carries: a flag
// error is a usage error, a run that proved nothing is refused.
type reproRefusal struct {
	code int
	msg  string
}

// preReleaseRun is what the read phase settled.
type preReleaseRun struct {
	compared, skipped []string
	reads             []classBuilds
}

// runPreReleaseRepro compares the two builds class by class and seals
// one verdict. Refusals — a requested class one build produced nothing
// for, a run that compared nothing — exit refused with the class named:
// they are judgments about the run, not about the flags.
func runPreReleaseRepro(pa *preReleaseArgs, stdout, stderr io.Writer) int {
	// Every refusal is settled before anything is compared or said: a
	// run that will refuse prints no progress a reader could mistake
	// for a partial verdict.
	run, refusal := readPreRelease(pa)
	if refusal != nil {
		if _, err := fmt.Fprintf(stderr, "stele verify repro: %s\n", refusal.msg); err != nil {
			return exitIO
		}

		return refusal.code
	}

	out := &latch{w: stdout}
	if pa.jsonOut {
		out = &latch{w: stderr}
	}

	for _, class := range run.skipped {
		out.logf("repro: rehearsal: %s pushed nothing, not compared", class)
	}

	j := report.NewJournal()
	judged := 0

	for _, r := range run.reads {
		divergences := verify.Repro(verify.ReproSets{Judged: r.first, Rebuilt: r.rebuilt, Published: r.first}, out.logf)

		for i := range r.first {
			j.Check(r.first[i].Name, "repro")
		}

		judged += len(r.first)

		for _, d := range divergences {
			j.Check(d.Name, "repro/"+d.Kind).
				DivergedFrom(d.Released, d.Rebuilt, "the rebuild did not reproduce the first build")
		}
	}

	if out.err != nil {
		return exitIO
	}

	facts := []report.Fact{
		{Name: "form", Value: "pre-release"},
		{Name: "classesCompared", Value: strings.Join(run.compared, ",")},
		{Name: "judgedArtifacts", Value: strconv.Itoa(judged)},
	}
	if len(run.skipped) > 0 {
		facts = append(facts, report.Fact{Name: "rehearsalNotCompared", Value: strings.Join(run.skipped, ",")})
	}

	rep := report.Seal("verify repro", pa.repo+"@"+pa.tag,
		report.PopulationFromEvidence(judged, "first-build subjects under rebuild"),
		j, report.NoCanary(), report.NoJudgedSet(), facts...)

	return emitReport(rep, pa.jsonOut, stdout, stderr)
}

// requestedClasses checks the request against the outputs given.
func requestedClasses(pa *preReleaseArgs) ([]string, *reproRefusal) {
	requested := splitTypes(pa.classes)

	seen := map[string]bool{}
	for _, c := range requested {
		if seen[c] {
			return nil, &reproRefusal{exitUsage, fmt.Sprintf("--classes names %s twice", c)}
		}

		seen[c] = true
	}

	for flagName, inputs := range map[string]buildInputs{"--first": pa.first, "--rebuild": pa.rebuild} {
		for class := range inputs {
			if !seen[class] {
				return nil, &reproRefusal{
					exitUsage, fmt.Sprintf("%s names %s, which --classes does not request", flagName, class),
				}
			}
		}
	}

	return requested, nil
}

// readPreRelease reads every requested class from both builds.
func readPreRelease(pa *preReleaseArgs) (*preReleaseRun, *reproRefusal) {
	requested, refusal := requestedClasses(pa)
	if refusal != nil {
		return nil, refusal
	}

	run := &preReleaseRun{}

	for _, class := range requested {
		// Whether the class is a registry class, and how its digest
		// files read, is its declaration; a class the policy does not
		// declare, or declares with no subjects, refuses by name.
		shape, err := subjectShape(pa.policy, class)
		if err != nil {
			return nil, &reproRefusal{exitUsage, err.Error()}
		}

		if pa.rehearsal && shape.Registry != nil {
			if pa.first[class] != "" || pa.rebuild[class] != "" {
				return nil, &reproRefusal{exitUsage, class + ": a rehearsal pushes no image, so there are no digests to give"}
			}

			run.skipped = append(run.skipped, class)

			continue
		}

		both, err := readBothBuilds(class, shape.Registry, pa.first[class], pa.rebuild[class])
		if err != nil {
			return nil, &reproRefusal{exitUsage, err.Error()}
		}

		if len(both.first) == 0 || len(both.rebuilt) == 0 {
			return nil, &reproRefusal{exitRefused, class + ": a build produced no subjects — " + emptyProof}
		}

		run.reads = append(run.reads, both)
		run.compared = append(run.compared, class)
	}

	if len(run.compared) == 0 {
		return nil, &reproRefusal{exitRefused, "the gate compared nothing — " + emptyProof}
	}

	return run, nil
}

// readBothBuilds reads one class's output from each build. A side
// that was not given at all is the same answer as one that holds
// nothing: the build produced no subjects for a class it was asked
// to build.
func readBothBuilds(class string, registry *release.RegistryClass, firstPath, rebuildPath string) (classBuilds, error) {
	first, err := readBuild(class, registry, firstPath)
	if err != nil {
		return classBuilds{}, fmt.Errorf("--first %s: %w", class, err)
	}

	rebuilt, err := readBuild(class, registry, rebuildPath)
	if err != nil {
		return classBuilds{}, fmt.Errorf("--rebuild %s: %w", class, err)
	}

	return classBuilds{first: first, rebuilt: rebuilt}, nil
}

// readBuild reads one build's output for one class, by the class's
// declared shape: a registry class's digest files through the one
// reader of both forms, labelled `<class>/<leg>` so a finding names the
// image it is about; a files class's sha256sum manifest.
func readBuild(class string, registry *release.RegistryClass, path string) ([]verify.Subject, error) {
	if path == "" {
		return nil, nil
	}

	if registry == nil {
		return digestManifest(path)
	}

	digests, err := registry.Digests(path)
	if err != nil {
		return nil, err
	}

	subjects := make([]verify.Subject, 0, len(digests))
	for _, d := range digests {
		subjects = append(subjects, verify.Subject{Name: class + "/" + d.Label, SHA256: d.SHA256})
	}

	return subjects, nil
}
