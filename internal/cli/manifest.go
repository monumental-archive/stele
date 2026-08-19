// `stele emit manifest`: the release evidence manifest — the declared
// contract a stranger reads at the tag (#40, scope moved from #109).
//
// The document is the JSON that gets signed: the publish machinery
// writes it, attests it, and uploads it beside the release, and from
// then on `assert evidence` derives the release's obligations from it
// rather than from the caller's workflow at the tag. Every value here
// is a declared fact the caller states — which classes shipped, the
// verdict layout, its own version — and none is derived, because this
// verb runs inside the machinery being described and a derivation
// would be the machinery grading itself.
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
	"strconv"

	"github.com/monumental-archive/stele/internal/evidence"
)

// emitManifest is the mode name.
const emitManifest = "manifest"

// manifestArgs is everything `emit manifest` reads.
type manifestArgs struct {
	classes          []string
	storeVSA         bool
	machineryVersion string
	out              string
}

// parseManifestArgs reads the flag surface.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseManifestArgs(args []string, stderr io.Writer) (*manifestArgs, int) {
	ma := &manifestArgs{}

	var classes, storeVSA string

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
	}

	layout, err := strconv.ParseBool(storeVSA)
	if err != nil {
		return ma, usageFail(fmt.Sprintf("--store-vsa %q is not true or false", storeVSA))
	}

	ma.storeVSA = layout
	ma.classes = splitTypes(classes)

	return ma, exitOK
}

// runEmitManifest builds, proves, and writes the manifest.
func runEmitManifest(ma *manifestArgs, doc io.Writer, out *latch) error {
	manifest, err := evidence.New(ma.classes, ma.storeVSA, ma.machineryVersion)
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

	out.logf("manifest: %d class(es), storeVsa=%t, machinery %s",
		len(ma.classes), ma.storeVSA, ma.machineryVersion)

	return nil
}

// emitManifestCmd runs the manifest mode — its own path through
// emitCmd, because it shares none of the chain/vsa flag surface: it
// signs nothing, walks nothing, and needs no policy to render a
// declaration. Wired through the document-mode seam, so the document
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
