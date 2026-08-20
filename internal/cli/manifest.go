// `stele emit manifest`: the release evidence manifest — the declared
// contract a stranger reads at the tag (#40, scope moved from #109).
//
// The document is the JSON that gets signed: the publish machinery
// writes it, attests it, and uploads it beside the release, and from
// then on `assert evidence` derives the release's obligations from it
// rather than from the caller's workflow at the tag. Every value here
// is a declared fact the caller states — which classes shipped, the
// verdict layout, its own version, which assets it published — and
// none is derived from the machinery's own state, because this verb
// runs inside the machinery being described and that derivation would
// be the machinery grading itself.
//
// The one thing this command computes is each asset's TYPE
// (stele#156), and it computes it from the org's committed policy
// rather than from the run: which names mark a document ABOUT the
// release is a declared org fact, and stamping it HERE is the whole
// point — this is the only moment the knowledge exists natively, and
// every walk downstream reads the answer instead of deriving a second
// one.
//
// Which LEG built each artifact — its class (stele#185) and the
// target that leg built (stele#223) — is the same kind of fact and
// lands the same way, but it is one no policy can answer: no
// vocabulary names a release's build artifacts by the leg that
// produced them, and only the publisher holds the split — one subject
// manifest per build leg, which is what `--leg-subjects` takes. An
// artifact no leg claims refuses the manifest rather than shipping
// unattributed: a scoped rebuild would then judge a population that
// silently omitted it, which is the same defect as an untyped entry
// one field over.
//
// What leaves this command is proven readable, not assumed: the
// rendered bytes are read back through the same internal/evidence
// seam the assert reader uses, so a manifest this writer can produce
// and a manifest the reader admits are one set by construction.

package cli

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/evidence"
	"github.com/monumental-archive/stele/internal/verify"
)

// emitManifest is the mode name.
const emitManifest = "manifest"

// manifestArgs is everything `emit manifest` reads.
type manifestArgs struct {
	classes          []string
	storeVSA         bool
	machineryVersion string
	entries          []evidence.Entry
	out              string
}

// legSubjects is the repeatable `--leg-subjects <class>:<target>=<path>`
// flag: one build leg's subject manifest per occurrence, which is the
// shape the publisher already holds — every matrix job emits the
// digests of what it produced, and this reads them back rather than
// asking a caller to restate the split in some new spelling.
//
// A leg is a (class, target) pair (stele#223), because that is the
// unit a build job and a rebuild both have. Keying it by class alone
// left the manifest unable to say which artifacts one target's
// rebuild covers, and a judge that cannot ask that question grades
// artifacts nobody rebuilt.
type legSubjects []legSubjectSet

// legSubjectSet is one leg: the class, the target it built, and the
// sha256sum manifest of the artifacts that produced.
type legSubjectSet struct {
	class  string
	target string
	path   string
}

// key spells one leg for a diagnostic and for the duplicate check —
// the same spelling the flag takes, so a message names the thing the
// caller typed.
func (l legSubjectSet) key() string { return l.class + ":" + l.target }

// String implements flag.Value — the legs named so far, which is what
// a usage dump should show; the paths are noise there.
func (l *legSubjects) String() string {
	names := make([]string, 0, len(*l))
	for _, leg := range *l {
		names = append(names, leg.key())
	}

	return strings.Join(names, ",")
}

// Set implements flag.Value. A leg named twice is refused here rather
// than merged: two manifests for one leg means the caller holds two
// answers for what that leg built, and merging them would pick one
// silently.
//
// The path is cut off first, at the leftmost `=`, so a path may carry
// either delimiter; class and target may carry neither, which is the
// price of a delimiter and is paid where the values are short and the
// publisher chooses them.
func (l *legSubjects) Set(v string) error {
	leg, path, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("--leg-subjects %q is not <class>:<target>=<path>", v)
	}

	class, target, named := strings.Cut(leg, ":")

	class, target, path = strings.TrimSpace(class), strings.TrimSpace(target), strings.TrimSpace(path)
	if !named || class == "" || target == "" || path == "" {
		return fmt.Errorf("--leg-subjects %q is not <class>:<target>=<path>", v)
	}

	set := legSubjectSet{class: class, target: target, path: path}

	for _, other := range *l {
		if other.key() == set.key() {
			return fmt.Errorf("--leg-subjects names %s twice — one build leg has one subject set", set.key())
		}
	}

	*l = append(*l, set)

	return nil
}

// parseManifestArgs reads the flag surface.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseManifestArgs(args []string, stderr io.Writer) (*manifestArgs, int) {
	ma := &manifestArgs{}

	var (
		classes, storeVSA, assets, policyPath string
		perLeg                                legSubjects
	)

	flags := flag.NewFlagSet("stele emit manifest", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&classes, "classes", "",
		"comma-separated evidence classes this release ships (required)")
	flags.StringVar(&storeVSA, "store-vsa", "",
		"true when verdicts live in the attestation store, false for legacy bundle assets (required; "+
			"a layout is declared, never defaulted)")
	flags.StringVar(&ma.machineryVersion, "machinery-version", "",
		"version of the publish machinery producing this release (required) — the attested spelling of "+
			"the fact the policy epochs derive obligations from")
	flags.StringVar(&assets, "assets", "",
		"sha256sum manifest of the assets this release publishes beside the manifest (required) — each "+
			"entry is pinned and typed, and a manifest cannot pin itself")
	flags.StringVar(&policyPath, "assert-policy", "",
		"assert policy whose evidence vocabulary types each asset (required) — which names mark a "+
			"document ABOUT the release is a declared org fact, never this tool's knowledge. Named for "+
			"the document it takes: --policy is the VERIFY policy in this verb's other modes")
	flags.Var(&perLeg, "leg-subjects",
		"the sha256sum manifest of the artifacts ONE build leg produced, as `<class>:<target>=<path>`, "+
			"repeatable once per leg — the split only the publisher holds, and the answer a rebuild "+
			"scopes its population by, at the grain a rebuild actually covers. Every build subject in "+
			"--assets must be claimed by exactly one of these")
	flags.StringVar(&ma.out, "out", "", "file to write the manifest to; empty prints to stdout")

	if err := flags.Parse(args); err != nil {
		return ma, exitUsage
	}

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele emit manifest: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch {
	case classes == "":
		return ma, usageFail("--classes is required — a manifest declaring no classes declares nothing")
	case storeVSA == "":
		return ma, usageFail("--store-vsa is required: true or false — the verdict layout is declared, never defaulted")
	case ma.machineryVersion == "":
		return ma, usageFail("--machinery-version is required — obligations are derived from it through the" +
			" policy epochs, and a manifest without it cannot answer them")
	case assets == "":
		return ma, usageFail("--assets is required — a manifest that lists nothing says nothing about what" +
			" the release published")
	case policyPath == "":
		return ma, usageFail("--assert-policy is required: the asset types come from the org's declared" +
			" evidence vocabulary, and this tool holds no names of its own")
	}

	layout, err := strconv.ParseBool(storeVSA)
	if err != nil {
		return ma, usageFail(fmt.Sprintf("--store-vsa %q is not true or false", storeVSA))
	}

	entries, err := typedEntries(assets, policyPath, perLeg)
	if err != nil {
		return ma, usageFail(err.Error())
	}

	ma.storeVSA = layout
	ma.entries = entries
	ma.classes = splitTypes(classes)

	return ma, exitOK
}

// typedEntries reads the release's asset manifest and stamps each
// asset with what it IS, through the policy's declared vocabulary.
//
// The classification is the engine's (internal/assert), never a
// caller's: the flag it replaced asked callers for "the RELEASED
// artifacts", a set only this tool's private knowledge could draw, so
// every caller that honoured it reimplemented the tool in workflow
// bash (stele#156).
// The class and target attribution is the CALLER's, and it is the one
// thing here that is: no declared vocabulary names a release's build
// artifacts by the leg that produced them, so the split arrives as one
// subject manifest per leg and is joined to the release's assets by
// name and digest — never trusted as a second list of what shipped
// (stele#185, at target grain stele#223).
func typedEntries(assets, policyPath string, perLeg legSubjects) ([]evidence.Entry, error) {
	pf, err := os.Open(policyPath) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return nil, err //nolint:wrapcheck // the path is in the message; a prefix would say it twice
	}
	defer pf.Close() //nolint:errcheck // read-only close

	pol, err := assert.LoadPolicy(pf)
	if err != nil {
		return nil, err
	}

	listed, err := digestManifest(assets)
	if err != nil {
		return nil, err
	}

	built, err := legOfAsset(listed, perLeg, pol.Evidence)
	if err != nil {
		return nil, err
	}

	entries := make([]evidence.Entry, 0, len(listed))

	for _, a := range listed {
		if pol.Evidence.Classify(a.Name) == evidence.TypeEvidence {
			entries = append(entries, evidence.NewEvidence(a.Name, a.SHA256))

			continue
		}

		leg, claimed := built[a.Name]
		if !claimed {
			return nil, fmt.Errorf("%s is a build subject no --leg-subjects manifest claims — an"+
				" artifact with no class and no target goes unjudged by every scoped rebuild, in silence",
				a.Name)
		}

		entries = append(entries, evidence.NewSubject(a.Name, a.SHA256, leg.class, leg.target))
	}

	return entries, nil
}

// legOfAsset joins the per-leg subject manifests onto the assets the
// release publishes: name to the leg that built it.
//
// The join is checked in both directions, because a caller's split is
// a SECOND statement about the same release and the two must agree or
// one of them is wrong. An artifact named by a leg but absent from
// the release did not ship; one whose digest disagrees is not the same
// bytes; one claimed by two legs has no answer; and a document the
// release publishes about itself is not an artifact any leg built.
func legOfAsset(
	listed []verify.Subject, perLeg legSubjects, pol *assert.EvidencePolicy,
) (map[string]legSubjectSet, error) {
	shipped := make(map[string]string, len(listed))
	for _, a := range listed {
		shipped[a.Name] = a.SHA256
	}

	built := make(map[string]legSubjectSet)

	for _, leg := range perLeg {
		subjects, err := digestManifest(leg.path)
		if err != nil {
			return nil, err
		}

		for _, s := range subjects {
			switch digest, ok := shipped[s.Name]; {
			case !ok:
				return nil, fmt.Errorf("--leg-subjects %s names %s, which this release does not publish"+
					" — a leg cannot claim an artifact that did not ship", leg.key(), s.Name)
			case digest != s.SHA256:
				return nil, fmt.Errorf("--leg-subjects %s pins %s at %s, but the release publishes %s"+
					" — one artifact, two digests", leg.key(), s.Name, s.SHA256, digest)
			case pol.Classify(s.Name) == evidence.TypeEvidence:
				return nil, fmt.Errorf("--leg-subjects %s names %s, which the evidence vocabulary calls a"+
					" document ABOUT the release — a document belongs to no one leg", leg.key(), s.Name)
			}

			if other, claimed := built[s.Name]; claimed {
				return nil, fmt.Errorf("%s is claimed by both %s and %s — one artifact has one build leg",
					s.Name, other.key(), leg.key())
			}

			built[s.Name] = leg
		}
	}

	return built, nil
}

// digestManifest reads one sha256sum manifest from disk through the
// ONE reader for the format, shared with every other leg that takes
// one: two parsers of one format drift into a writer whose output the
// reader refuses.
func digestManifest(path string) ([]verify.Subject, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the manifest path is operator-supplied by design
	if err != nil {
		return nil, err //nolint:wrapcheck // the path is in the message; a prefix would say it twice
	}

	return parseManifest(string(raw))
}

// runEmitManifest builds, proves, and writes the manifest.
func runEmitManifest(ma *manifestArgs, doc io.Writer, out *latch) error {
	manifest, err := evidence.New(ma.classes, ma.storeVSA, ma.machineryVersion, ma.entries)
	if err != nil {
		return fmt.Errorf("emit manifest: %w", err)
	}

	// The proof is on the BYTES, through the reader: a writer verified
	// by its own bookkeeping passes its own exam, so what gets checked
	// is exactly what a stranger's assert walk will decode.
	var rendered bytes.Buffer
	if err := manifest.Encode(&rendered); err != nil {
		return fmt.Errorf("emit manifest: %w", err)
	}

	if _, err := evidence.Parse(rendered.Bytes()); err != nil {
		return fmt.Errorf("emit manifest: the rendered bytes do not read back: %w", err)
	}

	if err := writeJSONDoc(ma.out, manifest, doc, out); err != nil {
		return err
	}

	out.logf("manifest: %d class(es), %d entr(ies) of which %d build subject(s), storeVsa=%t, machinery %s",
		len(ma.classes), len(ma.entries), len(manifest.Subjects()), ma.storeVSA, ma.machineryVersion)

	return nil
}

// emitManifestCmd runs the manifest mode — its own path through
// emitCmd, because it shares none of the chain/vsa flag surface: it
// signs nothing and walks nothing, and the policy it does read is the
// assert vocabulary that types the assets, not the verify policy the
// other modes carry. Wired through the document-mode seam, so the document
// owns stdout and progress moves to stderr when no --out is given —
// a progress line spliced into a JSON document is a corruption that
// only surfaces in production.
func emitManifestCmd(args []string, stdout, stderr io.Writer) int {
	ma, code := parseManifestArgs(args, stderr)
	if code != exitOK {
		return code
	}

	return runDeriveMode(ma.out, stdout, stderr,
		func(doc io.Writer, log *latch) error { return runEmitManifest(ma, doc, log) })
}
