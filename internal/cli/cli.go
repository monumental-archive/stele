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
	verbLevel  = "level"
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
	case verbLevel:
		return levelCmd(args[1:], stdout, stderr)
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
    repro     the reproducibility rebuild: the release's checksum
              manifest against the rebuild's, one typed finding per
              artifact that failed to reproduce

  stele derive <mode>    turn facts into claims; modes:
    version   the release this history's conventional commits call
              for, measured within one tag namespace
    notes     that release's changelog section, in the Keep a
              Changelog shape, printed or spliced into a file
    bump      that release's version written into the tree's version
              mirrors (Cargo workspace or single-crate version,
              internal path-dependency constraints, CITATION.cff),
              parsed and re-read, never pattern-matched; --check
              instead asserts the mirrors carry the released version
    sbom      an artifact's inventory (SPDX 2.3), from one of three
              sources: the shipped binaries' embedded module lists,
              a Cargo package's own resolved closure scoped to the
              target it was built for, or an aggregation of
              per-artifact documents into the release view — which is
              folded from them, never derived a second time
    facts     the OCI image metadata one release asserts on its
              images: provenance from the released commit and the
              forge, editorial with derived defaults, licence
              validated as an SPDX expression and shipped canonical
    vex       this release's coverage document: every shipped
              inventory scanned, every finding joined to the recorded
              decisions by exact (advisory, package, version), and a
              refusal when a gate-class finding has no decision
    claims    the control claims for one branch, matched by RULE
              CONTENT against the forge's live enforcement state
              through the policy's declared table; a lapsed control
              is absent, an unreadable one refuses

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
                 [--snapshot|--capture])
    chains       every repository in the population: a founded source
                 chain verifies end to end over every protected
                 branch, or the repository is a declared exception —
                 cloneless, over the forge's own API (--org|--repo
                 --policy --verify-policy [--snapshot|--capture])

  stele level <track>    what the evidence supports, per track, from
                         SLSA's own requirements; exit 0 pass, 1 fail,
                         4 could-not-judge. Takes --repo or --org and
                         nothing else: no clone, no policy, no trusted
                         root. An --org population is the forge's own
                         listing, folded to its weakest member:
    build       provenance, its authenticity, and the platform's own
                certificate claims about the runner and the workflow
                that held the signing capability
    source      the source chain measured with no expected identity:
                the summary attestation, continuity, history, the
                controls each link records, and two-party review
    dependency  the DRAFT dependency track (not part of SLSA v1.2,
                and marked draft in every output): an inventory per
                shipped artifact, findings triaged, and where the
                build fetched its dependencies from

  stele emit <mode>      produce and place signed evidence; modes:
    chain     source chain links for the pushed revision and any
              holes earlier lapses left, signed via cosign, appended
              to the notes ledger with a compare-and-swap push
    vsa       run release verification in full and render the
              build-track VSA predicate the workflow signs
    manifest  the release evidence manifest — the declared contract a
              stranger reads at the tag; every value a stated fact,
              read back through the assert reader before it leaves

derive sbom flags: [--out --expect-version] <binary>..., or
--cargo-package --tree --created [--target --features
--no-default-features --all-features], or --union --union-name
--created; derive claims
takes --policy --repo --branch [--canon-root --canon-digest --out
--snapshot|--capture]; derive facts takes --archetype --repo --git-dir --server-url
[--version --rev --tree --title --description]; derive vex
takes --subjects --vex --author --id --released [--base-ecosystems
--out]; the other
derive modes take --git-dir [--ref
--tag-prefix --paths --minor-types
--silent-types --zero-major-bumps-minor]; notes adds [--groups
--group-order --breaking-group --compare-url --release-url --pull-url
--date --changelog]; bump adds [--check --date].

Trust material: every verifying verb takes [--trusted-root] for an
offline document, or [--tuf-root --tuf-mirror] for a private Sigstore
instance; naming none resolves one through TUF from the anchor pinned
in this binary.

verify flags: --policy --repo; release/vsa add
--tag --subjects --signer-digest --machinery-digest; chain adds
--git-dir [--ref]; repro takes --repo --tag --subjects --rebuilt
[--json] and no trust material — a digest comparison signs nothing.
level takes --repo|--org [--ref --notes-ref --tag --json
--shield <path>], where --shield writes a shields.io endpoint document
from the same seal as the report. emit adds --machinery-digest --policy-uri; emit chain
adds --git-dir --rev --claims --actor --actor-id [--ref --remote
--clone --committer --genesis]; emit vsa adds --tag --subjects --sboms --signer-digest
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
