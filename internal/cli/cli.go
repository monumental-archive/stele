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

// The exit codes this package owns. The judging verbs add their own
// two — exitRefused (1) in verify.go, exitBlind (4) in assert.go —
// beside the verdicts that produce them; all five are printed by
// `stele help` and enumerated in MAINTENANCE.md, which
// surface_test.go holds to the binary.
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
	const text = `stele — SLSA evidence engine and verifier, and the
release engine that produces the evidence

usage:
  stele help             show this synopsis
  stele version          report the build's module version
  stele verify <mode>    verify published evidence, and the documents
                         that judge it; modes:
    release   every attestation of one release against the pinned
              signer identity, the four verifying-artifacts
              comparisons, subject coverage, the release decision
    vsa       the published verdict, as the spec's consumer procedure
    source-vsa  a release tag's source verdict, read from the release
              asset the assert policy names and held against the
              tag's commit and that commit's chain link as they stand
    chain     the source chain: coverage tip→genesis and the ledger
    repro     the reproducibility rebuild: the release's checksum
              manifest against the rebuild's, over the class and
              targets the rebuild declares it covered, one typed
              finding per artifact that failed to reproduce
    policy    one committed policy document against this engine's own
              loader, offline and reaching nothing: exit 0 if it
              loads, else the loader's refusal verbatim. The drift
              guard for a pinned binary — the engine is asked, never
              an epoch re-derived beside it

  stele derive <mode>    turn facts into claims; modes:
    version   the release this history's conventional commits call
              for, measured within one tag namespace; --release-as
              declares a version instead, judged against the derived
              base and the names the namespace has taken
    notes     that release's changelog section, in the Keep a
              Changelog shape, printed or spliced into a file
    bump      that release's version written into the tree's version
              mirrors (Cargo workspace or single-crate version,
              internal path-dependency constraints, CITATION.cff),
              parsed and re-read, never pattern-matched; --check
              instead asserts the mirrors carry the released version
    release-plan  the release decisions as one document a forge
              executor runs: the version, the notes, the commit's
              contents, the branch it lands on and the tag that
              follows — safe to compute twice, and --prepare writes
              the tree it names
    sbom      an artifact's inventory (SPDX 2.3), from one of three
              sources: the shipped binaries' embedded module lists
              (stamped with the released commit, --expect-revision),
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
              refusal when a gate-class finding has no decision; the
              base-layer ecosystems and the author are the assert
              policy's, and --inventories finds the documents itself
    claims    the control claims for one branch, matched by RULE
              CONTENT against the forge's live enforcement state
              through the policy's declared table; a lapsed control
              is absent, an unreadable one refuses
    vex-subjects  the signing plan for VEX decisions: per decision,
              which published releases it reaches and the subjects
              a claim about it is signed over — the assert engine's
              own inventory walk and join, read from the other
              direction — or why it is refused; with
              --unsigned-only, the decisions the store already holds
              are omitted (exit 4 when the store cannot be read)
    signer-digest  the one commit a workflow tree pins its trusted
              signer at, read from the job-level uses: lines the
              platform runs; the signer is the policy's, a tree
              pinning none or two refuses
    subjects  the digests a build's provenance names: every asset
              the class's planned legs must produce, present exactly
              once and nothing unplanned, as sha256 lines flat and
              grouped by leg — or a registry class's image digests
    inventories  a release's every inventory in one call: the plans
              judged as assert plans judges them, one document per
              judged entry and the release view folded from them, or
              the shipped binaries' own, or the forge's dependency
              graph for a tree tracking no manifest — and the list of
              documents the release decision covers on stdout
    inventory-plan  a build leg's inventory plan, the document
              assert plans judges, by the kind the class declares in
              the assert policy: one entry per packaged crate, or one
              per variant cell, named under the class's planned prefix
    population  the population every assert target walks, printed:
              each member's resolved tracks and the reconciliation
              by name; exit 1 when roster and listing disagree, 4
              when the listing cannot be read. With --repo and
              --tracks: is it a member, and do the tracks match
    classes   the evidence classes a release request declares: each
              requested class validated against the assert policy's
              evidence.classes and expanded as its declares say,
              printed as classes=<list> and each declared output

  stele assert <target>  compare published evidence to a declaration;
                         exit 0 pass, 1 fail, 4 could-not-judge. Every
                         target reads the policy's debtFile — written-
                         down defects are reported, not failed — and
                         --debt points one run at another file:
    image-facts  a published image's index annotations and every
                 per-arch config's labels equal the resolved facts
                 map (env contract: IMAGE, DIGEST, FACTS)
    evidence     nothing ships unattested: every release's declared
                 evidence contract is met and every covered subject
                 carries a store-resident verdict (--org|--repo
                 --policy [--debt --snapshot|--capture]; the
                 snapshot flags replay presence depth only)
    blast-radius every SBOM scanned, every advisory finding joined
                 against the committed VEX decisions by exact
                 (advisory, package, version) triple (--org|--repo
                 --policy --vex [--debt --snapshot|--capture])
    tags         every release tag: minted by the declared role,
                 signed from the repository's epoch on (verified
                 natively, no gitsign binary), target carries a
                 source chain link — over the history it fetches with
                 git (--org|--repo --policy [--debt])
    chains       every repository in the population: a founded source
                 chain verifies end to end over every protected
                 branch, or the repository is a declared exception —
                 over the history it fetches with git, no checkout and
                 no source (--org|--repo --policy --verify-policy
                 [--debt])
    plans        pre-publish: the build legs' inventory plans against
                 the planned obligations the post-publish walk reads,
                 and the judged plan set emitted for the derivation
                 leg to iterate (--policy --classes --machinery-version
                 [--debt --out] <plan files...>)
    permissions  the caller/callee join: every caller's permissions:
                 grant covers what the reusable tree it calls
                 requires — one checkout's callers at a pin bump, or
                 the whole population on a schedule (--policy [--debt
                 --tree --callers | --org|--repo] [--snapshot|--capture])
    advisories   one module's govulncheck scan joined against the
                 committed VEX decisions: only a reachable (called)
                 advisory gates, and only a decision DENYING that the
                 advisory applies excuses it — one that admits,
                 withholds or claims a fix is reported on the finding
                 (--scan --vex --subject [--json])
    inventory    each handed inventory document (an image
                 scanner's SPDX, for one) carries PURLs and every one
                 versioned; one that will not read or parse is
                 CANNOT_JUDGE ([--json] <document>...)
    signer-certificates  every certificate a transparency log holds
                 for a declared signing workflow reconciles against
                 a signing the population performed; read in chunks
                 from a checkpoint the caller keeps, each done chunk
                 written back, the rest reported outstanding
                 (--policy --checkpoint --org|--repo [--start-at
                 --budget --debt --json])
    published    a release's declared subjects against the stores
                 that serve them: every file pulled back and compared
                 to its built digest (a 404 waited on for ten
                 minutes, any other failure tried three times), every
                 image tag resolved to its attested index; the
                 policy's published section says which registry
                 serves which file (--policy --repo [--subjects
                 --images --release-tag --package --mode --rehearsal
                 --out --debt --json])

  stele level <track>    what the evidence supports, per track, from
                         SLSA's own requirements; exit 0 pass, 1 fail,
                         4 could-not-judge. Takes --repo or --org: no
                         clone, no trusted root, and the only policy
                         it reads decides who is ASKED, never what the
                         answer is. An --org population is the forge's
                         own listing, narrowed by whatever the org
                         declared, folded to its weakest member. With
                         --out-dir and no track it publishes every
                         cell instead of folding, and never over a
                         level already proven:
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
              to the notes ledger with a compare-and-swap push; with
              --no-append it signs and writes the links out, and
              never touches the ledger
    chain-append  append links chain --no-append wrote, holding no
              signing identity: each verified as verify would, its
              predecessor proven the ledger's tip, then pushed; a
              rejected push refuses (re-run the signing job)
    vsa       run release verification in full and render the
              build-track VSA predicate the workflow signs; when the
              assert policy owes one, also sign the tag's source
              verdict — both written, or neither
    manifest  the release evidence manifest — the declared contract a
              stranger reads at the tag; every value a stated fact and
              every published asset pinned and typed, read back
              through the assert reader before it leaves
    enrichment  the build-enrichment predicate the workflow signs:
              the names the policy's build.enrichment requires and
              permits, each computed from the source the caller
              declares — a file of the policy tree or of the released
              source, or rows of a TOML table file for the keys the
              build consumed (--policy --policy-tree --policy-repo
              --machinery-digest --repo --tag --source-revision
              [--file --rows --rows-tables --rows-prefix --rows-file
              --rows-keys --out])
    decision  the release decision a commit point signs: every
              required proof judged by name, the covered documents
              hashed into subject lines, read back through the
              verifier's decision reader before it is written

derive sbom flags: [--out --expect-version --expect-revision] <binary>..., or
--cargo-package --tree --created [--target --features
--no-default-features --all-features], or --union --union-name
--created; derive claims
takes --policy --repo --branch [--canon-root --canon-digest --out
--snapshot|--capture]; derive facts takes --archetype --repo --git-dir --server-url
[--version --rev --tree --title --description]; derive vex
takes --policy --subjects|--inventories --vex --released [--out --id
--repo --version|--run --release-view --verify-policy];
derive vex-subjects takes --policy --decision... --org|--repo
[--snapshot --out --unsigned-only --store]; derive signer-digest takes --policy
--workflows|--workflow [--repo]; derive subjects takes --policy
--class --expected --dir [--subjects-out --leg-subjects-out
--registry-subjects-out]; derive inventory-plan takes --class --policy
[--dir --version | --crate-dir --variant] [--out]; derive inventories
takes --policy --classes --repo --version --created --out-dir
[--evidence-classes --machinery-version --name --tree --binaries-dir
--expect-revision --variants] [<plan>...]; derive population takes --policy
--org|--repo [--tracks --out]; derive classes takes --policy --classes
[--given name=value...]; the other
derive modes take --git-dir [--ref
--tag-prefix --paths --minor-types
--silent-types --zero-major-bumps-minor --release-as]; notes adds [--groups
--group-order --breaking-group --compare-url --release-url --pull-url
--date --changelog]; bump adds [--check --date]; release-plan takes the
notes flags plus [--branch --staging --subject --also --prepare --out].

exit codes: 0 success; 1 refused — a judgment that found divergence,
or a derivation that will not stand; 2 usage error; 3 output-stream
failure; 4 CANNOT_JUDGE, the run could not see enough to judge. "I
found divergence" and "I could not look" are different answers and
never share a code.

Trust material: every verifying verb takes [--trusted-root] for an
offline document, or [--tuf-root --tuf-mirror] for a private Sigstore
instance; naming none resolves one through TUF from the anchor pinned
in this binary.

verify flags: --policy --repo; release/vsa add --tag [--subjects
--signer-digest --machinery-digest --assert-policy], and release adds
[--sboms --inventories]. An absent digest is derived from the trees
at the tag, the walk's own resolution; absent --subjects, --sboms and
their plan are read from the release's own evidence, which the
publisher's --assert-policy locates — one of --subjects or
--assert-policy is required. Every derived value is printed; a flag
that is given is used as given. chain adds
--git-dir [--ref]; source-vsa adds --tag --git-dir --assert-policy
--machinery-digest; repro takes --repo --tag --released --rebuilt
[--class --targets --assert-policy --json] and no trust material — a
digest comparison signs nothing; --assert-policy types an UNTYPED
released manifest, --class and --targets scope the judged population
to what the rebuild covered.
verify policy takes exactly one of --assert-policy or --verify-policy,
naming the document to load, and nothing else.
level takes --repo|--org [--ref --notes-ref --tag --json
--shield <path>], where --shield writes a shields.io endpoint document
from the same seal as the report; --org adds [--policy] for the
declared population, and --org --out-dir <dir> with no track publishes
<repo>/<track>.report.json and .shield.json per cell; [--published
<dir>] seeds the empty --out-dir from the board as published, measures
over it, and names every cell on which the two disagree (exit 1, or 4
when a cell judged before cannot be judged now). emit adds --machinery-digest --policy-uri; emit chain
adds --git-dir --rev --claims --actor --actor-id [--ref --remote
--clone --committer --genesis --no-append --out], where --no-append
signs and writes the links to --out without appending; emit
chain-append takes --policy --repo --git-dir|--clone --links [--ref
--remote --committer] and no --machinery-digest or --policy-uri, and
verifies, appends and pushes those links holding no signing identity;
emit vsa adds --tag --subjects --sboms --signer-digest
[--out --assert-policy --git-dir --source-out]; emit manifest takes --classes --store-vsa
--machinery-tree --assets-dir --bundles-dir --assert-policy
[--leg-lines --registry-lines --rehearsal --out]
and none of the above; emit decision takes --policy --classes --proof
--covered --predicate-out --subjects-out and --tag or --stream
[--inventory --also], and none of the above either.
GITHUB_TOKEN/GH_TOKEN authenticates store reads and the notes push.
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
