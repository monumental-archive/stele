// Package cli owns argument dispatch for the stele command. Run is the
// whole surface: it never calls os.Exit and never touches process
// globals, so every path — the guard branches above all — is reachable
// from a table test.
package cli

import (
	"fmt"
	"io"
	"runtime/debug"
)

// The multi-mode verbs.
const (
	verbVerify = "verify"
	verbEmit   = "emit"
	verbDerive = "derive"
	verbAssert = "assert"
)

// cmdVersion reports the binary's own build version — distinct from the
// derive mode that happens to share the word.
const cmdVersion = "version"

// develVersion is the toolchain's stamp for a build no tag names.
const develVersion = "(devel)"

// Exit codes: 0 success, 2 usage error, 3 output-stream failure.
const (
	exitOK    = 0
	exitUsage = 2
	exitIO    = 3
)

// Run dispatches args and reports the process exit code. Output-stream
// failures are their own exit code rather than a swallowed error: a
// tool whose job is asserting facts must not report success after
// failing to write its output.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		if err := usage(stderr); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch args[0] {
	case "help":
		if err := usage(stdout); err != nil {
			return exitIO
		}

		return exitOK
	case cmdVersion:
		if err := version(stdout); err != nil {
			return exitIO
		}

		return exitOK
	case verbVerify:
		return verifyCmd(args[1:], stdout, stderr)
	case verbEmit:
		return emitCmd(args[1:], stdout, stderr)
	case verbDerive:
		return deriveCmd(args[1:], stdout, stderr)
	case verbAssert:
		return assertCmd(args[1:], stdout, stderr)
	default:
		if _, err := fmt.Fprintf(stderr, "stele: unknown command %q (run `stele help`)\n", args[0]); err != nil {
			return exitIO
		}

		return exitUsage
	}
}

// usage writes the command synopsis.
func usage(w io.Writer) error {
	const text = `stele — SLSA evidence engine and verifier

usage:
  stele help             show this synopsis
  stele version          report the build's module version
  stele verify <mode>    verify published evidence; modes:
    release   every attestation of one release against the pinned
              signer identity, the four verifying-artifacts
              comparisons, subject coverage, the release decision
    vsa       the published verdict, as the spec's consumer procedure
    chain     the source chain: coverage tip→genesis and the ledger
    level     chain, then the honest computed source level

  stele derive <mode>    turn facts into claims; modes:
    version   the release this history's conventional commits call
              for, measured within one tag namespace
    notes     that release's changelog section, in the Keep a
              Changelog shape, printed or spliced into a file
    sbom      the release SBOM, read from the shipped binaries'
              embedded module lists (SPDX 2.3, one union document
              over every platform leg)

  stele assert <target>  compare published evidence to a declaration;
                         exit 0 pass, 1 fail, 4 could-not-judge:
    image-facts  a published image's index annotations and every
                 per-arch config's labels equal the resolved facts
                 map (env contract: IMAGE, DIGEST, FACTS)
    evidence     nothing ships unattested: every release's declared
                 evidence contract is met and every covered subject
                 carries a store-resident verdict (--org|--repo
                 --policy [--debt --snapshot|--capture])
    blast-radius every SBOM scanned, every advisory finding joined
                 against the committed VEX decisions by exact
                 (advisory, package, version) triple (--org|--repo
                 --policy --vex [--snapshot|--capture])
    tags         every release tag: minted by the declared role,
                 signed from the repository's epoch on (verified
                 natively, no gitsign binary), target carries a
                 source chain link (--org|--repo --policy
                 [--trusted-root --snapshot|--capture])

  stele emit <mode>      produce and place signed evidence; modes:
    chain     source chain links for the pushed revision and any
              holes earlier lapses left, signed via cosign, appended
              to the notes ledger with a compare-and-swap push
    vsa       run release verification in full and render the
              build-track VSA predicate the workflow signs

derive sbom flags: [--out --expect-version] <binary>...; the other
derive modes take --git-dir [--ref --tag-prefix --paths --minor-types
--silent-types --zero-major-bumps-minor]; notes adds [--groups
--group-order --breaking-group --compare-url --release-url --pull-url
--date --changelog].

verify flags: --policy --trusted-root --repo; release/vsa add
--tag --subjects --signer-digest --machinery-digest; chain/level add
--git-dir [--ref]. emit adds --machinery-digest --policy-uri; emit chain
adds --git-dir --rev --claims --actor --actor-id [--ref --remote
--genesis]; emit vsa adds --tag --subjects --sboms --signer-digest
[--out]. GITHUB_TOKEN/GH_TOKEN authenticates store reads and the
notes push.
`

	if _, err := io.WriteString(w, text); err != nil {
		return fmt.Errorf("write usage: %w", err)
	}

	return nil
}

// version reports the module version stamped into the binary by the Go
// toolchain — read from the shipped bytes, never from a constant that
// could drift from them.
func version(w io.Writer) error {
	ver := develVersion
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		ver = info.Main.Version
	}

	if _, err := fmt.Fprintf(w, "stele %s\n", ver); err != nil {
		return fmt.Errorf("write version: %w", err)
	}

	return nil
}
