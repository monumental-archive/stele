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
// produced them, and only the publisher holds the split — each class's
// subject lines as its legs emitted them, `<target> <sha256>  <name>`,
// which is what `--leg-lines` takes and splits here (stele#400). An
// artifact no leg claims refuses the manifest rather than shipping
// unattributed: a scoped rebuild would then judge a population that
// silently omitted it, which is the same defect as an untyped entry
// one field over.
//
// What the release published somewhere OTHER than its assets — a
// container image, a registry package — is the third such fact
// (stele#329), and the one with no asset to join against: nothing in
// the asset directory can name it, so a release that shipped only an
// image listed no artifact at all and every walk downstream had to
// recover the subject from the proofs about it. It arrives the way a
// leg's artifacts do, `--registry-lines <class>=<file>`, and is held
// to the one rule the join can still make: a registry subject is not
// also an asset.
//
// The inputs are the run's own (stele#400): the directory of what
// ships, hashed here; the attestation bundles, placed into it under
// the names the policy declares; and the machinery tree, whose version
// mirror states the machinery version. The shell that used to hash,
// split and rename in front of this command decided what a subject
// line means without a test.
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
	// notes are what preparing the inputs did — bundles placed, a
	// rehearsal's missing bundle — reported once the manifest stands.
	notes []string
}

// legSubjects are the release's build legs. A leg is a (class, target)
// pair (stele#223), because that is the unit a build job and a rebuild
// both have. Keying it by class alone left the manifest unable to say
// which artifacts one target's rebuild covers, and a judge that cannot
// ask that question grades artifacts nobody rebuilt.
type legSubjects []legSubjectSet

// legSubjectSet is one leg: the class, the target it built, and the
// subjects that leg emitted.
type legSubjectSet struct {
	class    string
	target   string
	subjects []verify.Subject
	// flag is the flag that supplied the leg, so a refusal names the
	// input the caller wrote.
	flag string
}

// key spells one leg for a diagnostic and for the duplicate check.
func (l *legSubjectSet) key() string { return l.class + ":" + l.target }

// manifestFlags is the raw flag surface, before anything is read.
type manifestFlags struct {
	classes, storeVSA, policyPath string
	assetsDir, bundlesDir         string
	machineryTree                 string
	rehearsal                     bool
	legLines, registryLines       classLines
}

// parseManifestArgs reads the flag surface, then prepares the inputs:
// the policy, the bundles placed, the directory hashed, the lines
// split and every asset typed.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseManifestArgs(args []string, stderr io.Writer) (*manifestArgs, int) {
	ma := &manifestArgs{}
	mf := &manifestFlags{}

	flags := flag.NewFlagSet("stele emit manifest", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&mf.classes, "classes", "",
		"comma-separated evidence classes this release ships (required)")
	flags.StringVar(&mf.storeVSA, "store-vsa", "",
		"true when verdicts live in the attestation store, false for legacy bundle assets (required; "+
			"a layout is declared, never defaulted)")
	flags.StringVar(&mf.machineryTree, "machinery-tree", "",
		"the publish machinery's tree (required) — its version mirror states the machinery version, the"+
			" fact the policy epochs derive obligations from")
	flags.StringVar(&mf.assetsDir, "assets-dir", "",
		"directory of every asset this release publishes beside the manifest (required) — hashed here,"+
			" each entry pinned and typed; a manifest cannot pin itself")
	flags.StringVar(&mf.bundlesDir, "bundles-dir", "",
		"directory of the release's attestation bundles (required): each subdirectory holds one bundle and"+
			" is the name it is placed under, or one flat file is the policy's umbrella bundle")
	flags.BoolVar(&mf.rehearsal, "rehearsal", false,
		"the run is a rehearsal: a release with no bundle is reported, not refused")
	flags.StringVar(&mf.policyPath, "assert-policy", "",
		"assert policy whose evidence vocabulary types each asset (required) — which names mark a "+
			"document ABOUT the release is a declared org fact, never this tool's knowledge. Named for "+
			"the document it takes: --policy is the VERIFY policy in this verb's other modes")
	flags.Var(&mf.legLines, "leg-lines",
		"one class's build subject lines as its legs emitted them, `<target> <sha256>  <name>`, as"+
			" `<class>=<file>`, repeatable once per class — the split only the publisher holds, and the"+
			" answer a rebuild scopes its population by. Every build subject must be claimed by one leg")
	flags.Var(&mf.registryLines, "registry-lines",
		"one class's registry subject lines, `<target> <sha256>  <name>`, as `<class>=<file>`,"+
			" repeatable once per class — what a leg published somewhere other than the release's assets;"+
			" none may also be an asset")
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
	case flags.NArg() > 0:
		return ma, usageFail(fmt.Sprintf("unexpected argument %q", flags.Arg(0)))
	case mf.classes == "":
		return ma, usageFail("--classes is required — a manifest declaring no classes declares nothing")
	case mf.storeVSA == "":
		return ma, usageFail("--store-vsa is required: true or false — the verdict layout is declared, never defaulted")
	case mf.machineryTree == "":
		return ma, usageFail("--machinery-tree is required — obligations are derived from its version through" +
			" the policy epochs, and a manifest without it cannot answer them")
	case mf.assetsDir == "":
		return ma, usageFail("--assets-dir is required — a manifest that lists nothing says nothing about what" +
			" the release published")
	case mf.bundlesDir == "":
		return ma, usageFail("--bundles-dir is required — a release's provenance is placed beside what it" +
			" describes, or its absence is declared a rehearsal")
	case mf.policyPath == "":
		return ma, usageFail("--assert-policy is required: the asset types come from the org's declared" +
			" evidence vocabulary, and this tool holds no names of its own")
	}

	layout, err := strconv.ParseBool(mf.storeVSA)
	if err != nil {
		return ma, usageFail(fmt.Sprintf("--store-vsa %q is not true or false", mf.storeVSA))
	}

	if err := prepareManifest(ma, mf); err != nil {
		return ma, usageFail(err.Error())
	}

	ma.storeVSA = layout
	ma.classes = splitTypes(mf.classes)

	return ma, exitOK
}

// prepareManifest reads every input in the one order that is correct:
// the policy (it names the bundles), the bundles placed (they ship),
// then the directory hashed (it now holds them), then the lines split
// and joined against what was hashed.
func prepareManifest(ma *manifestArgs, mf *manifestFlags) error {
	version, err := machineryOfTree(mf.machineryTree)
	if err != nil {
		return err
	}

	pol, err := loadEvidencePolicy(mf.policyPath)
	if err != nil {
		return err
	}

	if derr := assetsDirectory(mf.assetsDir); derr != nil {
		return derr
	}

	notes, err := placeBundles(mf.bundlesDir, mf.assetsDir, pol, mf.rehearsal)
	if err != nil {
		return err
	}

	listed, err := hashAssetsDir(mf.assetsDir)
	if err != nil {
		return err
	}

	entries, err := manifestEntries(listed, pol, mf.legLines, mf.registryLines)
	if err != nil {
		return err
	}

	ma.machineryVersion = version
	ma.entries = entries
	ma.notes = notes

	return nil
}

// loadEvidencePolicy reads the assert policy's evidence vocabulary.
func loadEvidencePolicy(path string) (*assert.EvidencePolicy, error) {
	pf, err := os.Open(path) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return nil, err //nolint:wrapcheck // the path is in the message; a prefix would say it twice
	}
	defer pf.Close() //nolint:errcheck // read-only close

	// The loader refuses a policy with no evidence section, so the
	// vocabulary is always there to type with.
	pol, err := assert.LoadPolicy(pf)
	if err != nil {
		return nil, err
	}

	return pol.Evidence, nil
}

// manifestEntries splits each class's lines into legs and stamps each
// asset with what it IS.
func manifestEntries(
	listed []verify.Subject, pol *assert.EvidencePolicy, legLines, registryLines classLines,
) ([]evidence.Entry, error) {
	var perLeg, registry legSubjects

	if err := joinClassLines(&perLeg, flagLegLines, legLines); err != nil {
		return nil, err
	}

	if err := joinClassLines(&registry, flagRegistryLines, registryLines); err != nil {
		return nil, err
	}

	return typedEntries(listed, pol, perLeg, registry)
}

// typedEntries stamps each asset with what it IS, through the policy's
// declared vocabulary.
//
// The classification is the engine's (internal/assert), never a
// caller's: the flag it replaced asked callers for "the RELEASED
// artifacts", a set only this tool's private knowledge could draw, so
// every caller that honoured it reimplemented the tool in workflow
// bash (stele#156).
// The class and target attribution is the CALLER's, and it is the one
// thing here that is: no declared vocabulary names a release's build
// artifacts by the leg that produced them, so the split arrives as
// each class's lines and is joined to the release's assets by name
// and digest — never trusted as a second list of what shipped
// (stele#185, at target grain stele#223).
func typedEntries(
	listed []verify.Subject, pol *assert.EvidencePolicy, perLeg, registry legSubjects,
) ([]evidence.Entry, error) {
	built, err := legOfAsset(listed, perLeg, pol)
	if err != nil {
		return nil, err
	}

	entries := make([]evidence.Entry, 0, len(listed))

	for _, a := range listed {
		if pol.Classify(a.Name) == evidence.TypeEvidence {
			entries = append(entries, evidence.NewEvidence(a.Name, a.SHA256))

			continue
		}

		leg, claimed := built[a.Name]
		if !claimed {
			return nil, fmt.Errorf("%s is a build subject no %s line claims — an artifact with no class"+
				" and no target goes unjudged by every scoped rebuild, in silence", a.Name, flagLegLines)
		}

		entries = append(entries, evidence.NewSubject(a.Name, a.SHA256, leg.class, leg.target))
	}

	published, err := registryEntries(listed, registry)
	if err != nil {
		return nil, err
	}

	return append(entries, published...), nil
}

// registryEntries reads what each leg published somewhere other than
// the release's assets (stele#329).
//
// There is no second list to join these against — that absence is the
// reason the flag exists — so the one cross-statement check left is
// the one that keeps the two populations apart: a name the release
// publishes as an asset is an asset, claimed by --leg-lines and
// pinned by the checksum manifest, and stating it here as well would
// hand a walk two answers about where one artifact lives. Everything
// else about an entry (a class the release declared, one answer per
// name, no subject twice) is the manifest's own rule and is refused
// where every writer and reader shares it.
func registryEntries(listed []verify.Subject, registry legSubjects) ([]evidence.Entry, error) {
	shipped := make(map[string]bool, len(listed))
	for _, a := range listed {
		shipped[a.Name] = true
	}

	var entries []evidence.Entry

	for _, leg := range registry {
		for _, s := range leg.subjects {
			if shipped[s.Name] {
				return nil, fmt.Errorf("%s %s names %s, which this release publishes as an asset — an"+
					" asset is claimed by %s, and one artifact lives in one place",
					leg.flag, leg.key(), s.Name, flagLegLines)
			}

			entries = append(entries, evidence.NewRegistrySubject(s.Name, s.SHA256, leg.class, leg.target))
		}
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
		for _, s := range leg.subjects {
			switch digest, ok := shipped[s.Name]; {
			case !ok:
				return nil, fmt.Errorf("%s %s names %s, which this release does not publish"+
					" — a leg cannot claim an artifact that did not ship", leg.flag, leg.key(), s.Name)
			case digest != s.SHA256:
				return nil, fmt.Errorf("%s %s pins %s at %s, but the release publishes %s"+
					" — one artifact, two digests", leg.flag, leg.key(), s.Name, s.SHA256, digest)
			case pol.Classify(s.Name) == evidence.TypeEvidence:
				return nil, fmt.Errorf("%s %s names %s, which the evidence vocabulary calls a"+
					" document ABOUT the release — a document belongs to no one leg", leg.flag, leg.key(), s.Name)
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

// joinClassLines splits each class's lines into legs. A leg cannot
// arrive twice: one class's lines are split once, merging a target's
// lines into one leg, and a class named twice is refused by the split.
func joinClassLines(into *legSubjects, flagName string, files classLines) error {
	legs, err := splitClassLines(flagName, files)
	if err != nil {
		return err
	}

	*into = append(*into, legs...)

	return nil
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

	for _, note := range ma.notes {
		out.logf("%s", note)
	}

	registry, _ := manifest.RegistrySubjects()

	out.logf("manifest: %d class(es), %d entr(ies) of which %d build subject(s) and %d registry subject(s),"+
		" storeVsa=%t, machinery %s", len(ma.classes), len(ma.entries), len(manifest.Subjects()), len(registry),
		ma.storeVSA, ma.machineryVersion)

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
