// The policy load-check (stele#210): the one entry point that runs a
// committed document through the engine's own loader and answers with
// nothing but that loader's verdict.
//
// Every other policy-taking invocation loads the document and then
// does its verb's work, so "does this committed policy load against
// the engine I pin?" could only be asked by running a real verb and
// dragging in that verb's network, repository and evidence reads.
// This asks it alone: a file is opened, a loader runs, and the process
// exits. Nothing is fetched, cloned, or written.
//
// The command adds no opinion of its own. It never reads the
// implemented epoch, never compares it to anything, and never
// reformats what the loader said — a consumer that had to re-derive
// the epoch to interpret the answer would be holding a third copy of a
// definition that already has exactly one (jsonx.Epoch), which is the
// defect this exists to remove. The exit status IS the verdict and the
// message IS the engine's.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/policy"
)

// modePolicy is the dispatch name for the load-check.
const modePolicy = "policy"

// policyDoc is one resolved request: the document to open, and the
// engine loader that owns its kind.
type policyDoc struct {
	path string
	load func(io.Reader) error
}

// loadPolicyDoc runs `stele verify policy`. It takes no trust
// material, no repository and no store: the document under test is the
// whole input, and the answer is whether the engine accepts it.
func loadPolicyDoc(args []string, stderr io.Writer) int {
	var assertPath, verifyPath string

	fs := flag.NewFlagSet("stele verify policy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&assertPath, "assert-policy", "",
		"path to a committed assert policy to load (exclusive with --verify-policy)")
	fs.StringVar(&verifyPath, "verify-policy", "",
		"path to a committed verify policy to load (exclusive with --assert-policy)")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele verify policy: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	doc, err := policyUnderTest(assertPath, verifyPath)
	if err != nil {
		return usageFail(err.Error())
	}

	// A path that will not OPEN is the operator's error, not the
	// document's verdict: the loader never ran, so this is a usage
	// refusal and not the refusal that means "your committed policy has
	// drifted". A lint demanding exit 0 fails either way; a human
	// reading the two needs them to be different answers.
	//
	// The boundary sits exactly where the operating system puts it. A
	// path that opens and then fails to read — a directory, on every
	// Unix — is refused INSIDE the loader and reported as its verdict.
	// Statting first to pre-empt that would be this command deciding
	// what a readable document is, which is an opinion beside the
	// engine's, and having none is the whole point.
	f, err := os.Open(doc.path)
	if err != nil {
		return usageFail(err.Error())
	}
	defer f.Close() //nolint:errcheck // read-only close

	if err := doc.load(f); err != nil {
		// Verbatim, unwrapped and unimproved. This IS the engine's
		// opinion; a prefix of our own would make it ours. The verbs
		// print the same loader message behind their own name, because
		// there the policy is an input to some other question; here it
		// is the whole question.
		if _, werr := fmt.Fprintf(stderr, "%v\n", err); werr != nil {
			return exitIO
		}

		// exitRefused, where the verbs answer exitUsage on the very same
		// document (measured on the canon's pre-#626 pair: both verbs
		// exit 2, this exits 1). Deliberate, and the codes' own
		// definitions decide it: 2 is "you invoked me wrong", which is
		// false — the invocation was right and found exactly what it
		// looked for — and 1 is "a judgment that found divergence",
		// which is what a drifted policy is. It also keeps the two
		// failures a consumer's lint must tell apart on separate codes:
		// 1 means bump the document, 2 means fix the lint's own path.
		return exitRefused
	}

	return exitOK
}

// policyUnderTest resolves which document kind was named, and hands
// back the engine loader that owns it.
//
// The two kinds have two loaders — internal/policy for what the
// verifying verbs read, internal/assert for what the assert targets
// read — and the check must BE the loader the verbs use, never a third
// reader that happens to agree with them today. They share a version
// gate (both gate on jsonx.Epoch before strict decode, stele#107) and
// nothing else: the shapes they accept and the messages they refuse
// with are their own.
//
// Exactly one flag, because the kind cannot be sniffed from the
// document without inventing a fourth definition of which is which.
// Naming neither leaves nothing to load; naming both asks two
// questions and leaves one exit code to answer them.
func policyUnderTest(assertPath, verifyPath string) (policyDoc, error) {
	switch {
	case assertPath == "" && verifyPath == "":
		return policyDoc{}, errors.New(
			"one of --assert-policy or --verify-policy is required — the two document kinds have two loaders",
		)
	case assertPath != "" && verifyPath != "":
		return policyDoc{}, errors.New(
			"--assert-policy and --verify-policy are exclusive — one run loads one document",
		)
	case assertPath != "":
		return policyDoc{path: assertPath, load: func(r io.Reader) error {
			_, err := assert.LoadPolicy(r)

			return err
		}}, nil
	default:
		return policyDoc{path: verifyPath, load: func(r io.Reader) error {
			_, err := policy.Load(r)

			return err
		}}, nil
	}
}
