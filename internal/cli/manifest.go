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

// parseManifestArgs reads the flag surface.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseManifestArgs(args []string, stderr io.Writer) (*manifestArgs, int) {
	ma := &manifestArgs{}

	var classes, storeVSA, assets, policyPath string

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

	entries, err := typedEntries(assets, policyPath)
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
func typedEntries(assets, policyPath string) ([]evidence.Entry, error) {
	pf, err := os.Open(policyPath) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return nil, err //nolint:wrapcheck // the path is in the message; a prefix would say it twice
	}
	defer pf.Close() //nolint:errcheck // read-only close

	pol, err := assert.LoadPolicy(pf)
	if err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(assets) //nolint:gosec // the manifest path is operator-supplied by design
	if err != nil {
		return nil, err //nolint:wrapcheck // the path is in the message; a prefix would say it twice
	}

	// One reader for the sha256sum format, shared with every other leg
	// that takes one: two parsers of one format drift into a writer
	// whose output the reader refuses.
	listed, err := parseManifest(string(raw))
	if err != nil {
		return nil, err
	}

	entries := make([]evidence.Entry, 0, len(listed))
	for _, a := range listed {
		entries = append(entries, evidence.NewEntry(a.Name, a.SHA256, pol.Evidence.Classify(a.Name)))
	}

	return entries, nil
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
