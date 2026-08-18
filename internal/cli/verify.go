// The verify verb: argument surface for the four verification modes
// (release, vsa, chain, level), each a thin assembly of the policy,
// the trust boundary and the engine. Effectful constructors sit
// behind package seams so every guard branch here is reachable from
// a table test; the constructors themselves are proven in their own
// packages and in shadow mode.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/monumental-archive/stele/internal/ghstore"
	"github.com/monumental-archive/stele/internal/gitrepo"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
)

// exitRefused is verification's own failure: the evidence did not
// prove the claim. Distinct from usage (2) and stream failure (3).
const exitRefused = 1

// The four mode names, the dispatch vocabulary.
const (
	modeRelease = "release"
	modeVSA     = "vsa"
	modeChain   = "chain"
)

// The effect seams, swapped only by tests: building the
// cryptographic verifier from a trusted root, the attestation store,
// and the git history. Everything below them is table-tested;
// everything behind them is tested in its own package and proven in
// shadow mode. Mutable package state is exactly what the rule
// guards against; these are written only by test setup, and the
// alternative (threading constructors through Run) would widen the
// one deliberately thin public surface.
//
//nolint:gochecknoglobals // test seams, written only by test setup
var (
	newBundleVerifier = func(rootJSON []byte) (verify.BundleVerifier, error) {
		tr, err := trust.LoadRoot(rootJSON)
		if err != nil {
			return nil, fmt.Errorf("trusted root: %w", err)
		}

		v, err := trust.NewVerifier(tr)
		if err != nil {
			return nil, fmt.Errorf("verifier: %w", err)
		}

		return trustAdapter{v: v}, nil
	}

	newStore = func(noRetry bool) verify.Store {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			token = os.Getenv("GH_TOKEN")
		}

		c := ghstore.New(token)
		if noRetry {
			// The auditor stance: a wrong digest refuses now instead of
			// riding the just-published propagation ladder (#19 item 4).
			c.Attempts = 1
		}

		return c
	}

	openHistory = func(dir, notesRef string) (verify.History, error) {
		return gitrepo.Open(dir, notesRef)
	}
)

// trustAdapter implements the engine's BundleVerifier over the trust
// package: bundle parsing plus the org verification stance.
type trustAdapter struct {
	v *trust.Verifier
}

func (a trustAdapter) Attestation(bundleJSON []byte, id trust.Identity, sha256Hex string) (*trust.Verified, error) {
	b, err := trust.LoadBundle(bundleJSON)
	if err != nil {
		return nil, fmt.Errorf("attestation: %w", err)
	}

	v, err := a.v.Verify(b, id, "sha256", sha256Hex)
	if err != nil {
		return nil, fmt.Errorf("attestation: %w", err)
	}

	return v, nil
}

func (a trustAdapter) Blob(bundleJSON []byte, id trust.Identity, sha256Hex string) (*trust.Verified, error) {
	b, err := trust.LoadBundle(bundleJSON)
	if err != nil {
		return nil, fmt.Errorf("blob: %w", err)
	}

	v, err := a.v.VerifyBlob(b, id, "sha256", sha256Hex)
	if err != nil {
		return nil, fmt.Errorf("blob: %w", err)
	}

	return v, nil
}

// MeasureBlob proves a bundle and reports who signed, asserting no
// identity — the measurement path (internal/verify/measure.go), never
// a gate.
func (a trustAdapter) MeasureBlob(bundleJSON []byte, sha256Hex string) (*trust.Verified, error) {
	b, err := trust.LoadBundle(bundleJSON)
	if err != nil {
		return nil, fmt.Errorf("measure: %w", err)
	}

	v, err := a.v.MeasureBlob(b, "sha256", sha256Hex)
	if err != nil {
		return nil, fmt.Errorf("measure: %w", err)
	}

	return v, nil
}

// MeasureAttestation proves a DSSE bundle and returns what it said,
// asserting no identity — the measurement path, never a gate.
func (a trustAdapter) MeasureAttestation(bundleJSON []byte, sha256Hex string) (*trust.Verified, error) {
	b, err := trust.LoadBundle(bundleJSON)
	if err != nil {
		return nil, fmt.Errorf("measure: %w", err)
	}

	v, err := a.v.MeasureAttestation(b, "sha256", sha256Hex)
	if err != nil {
		return nil, fmt.Errorf("measure: %w", err)
	}

	return v, nil
}

func (a trustAdapter) Peek(bundleJSON []byte) ([]byte, error) {
	payload, err := trust.PeekStatement(bundleJSON)
	if err != nil {
		return nil, fmt.Errorf("peek: %w", err)
	}

	return payload, nil
}

// latch adapts a writer into the engine's Logf, remembering the
// first write failure: a verifier must not report success after
// failing to say what it verified.
type latch struct {
	w   io.Writer
	err error
}

func (l *latch) logf(format string, args ...any) {
	if l.err != nil {
		return
	}

	_, l.err = fmt.Fprintf(l.w, format+"\n", args...)
}

// verifyArgs is everything the four modes read, parsed in one place.
type verifyArgs struct {
	policyPath   string
	root         rootFlags
	repo         string
	tag          string
	subjects     string
	sboms        string
	signerPin    string
	machineryPin string
	gitDir       string
	ref          string
	mode         string
	jsonOut      bool
	noRetry      bool
	p            *policy.Policy
	coords       verify.Coords
	subjectList  []verify.Subject
	sbomList     []verify.Subject
	bv           verify.BundleVerifier
}

// verifyCmd dispatches `stele verify <mode>`.
func verifyCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		if _, err := fmt.Fprintln(stderr, "stele verify: a mode is required: release, vsa or chain"); err != nil {
			return exitIO
		}

		return exitUsage
	}

	mode := args[0]
	switch mode {
	case modeRelease, modeVSA, modeChain:
	default:
		if _, err := fmt.Fprintf(stderr, "stele verify: unknown mode %q (release, vsa, chain)\n", mode); err != nil {
			return exitIO
		}

		return exitUsage
	}

	va, code := parseVerifyArgs(mode, args[1:], stderr)
	if code != exitOK {
		return code
	}

	// With --json, stdout carries exactly one report document, so
	// progress moves to stderr — a consumer parses the stream whole.
	out := &latch{w: stdout}
	if va.jsonOut {
		out = &latch{w: stderr}
	}

	outcome, err := runVerify(va, out)
	if out.err != nil {
		return exitIO
	}

	if va.jsonOut {
		if encErr := sealVerifyReport(va, outcome, err).Encode(stdout); encErr != nil {
			return exitIO
		}
	}

	if err != nil {
		if _, werr := fmt.Fprintf(stderr, "%v\n", err); werr != nil {
			return exitIO
		}

		return exitRefused
	}

	return exitOK
}

// verifyOutcome carries what a completed mode proved, for the report:
// the population it covered and the facts worth reporting beside the
// verdict. Built only by the mode runners from verdict accessors —
// never from unverified inputs.
type verifyOutcome struct {
	pop   report.Population
	facts []report.Fact
}

// sealVerifyReport turns a mode's outcome (or refusal) into the one
// sealed report --json emits. A refusal is a FAIL over the declared
// population with the engine's message as the finding; a refusal
// before any population existed (an empty subject manifest) seals as
// CANNOT_JUDGE by the population rule, which is the honest reading.
func sealVerifyReport(va *verifyArgs, outcome *verifyOutcome, err error) *report.Report {
	subject := va.coords.Slug()
	if va.tag != "" {
		subject += "@" + va.tag
	}

	target := "verify " + va.mode

	// What the run trusted travels with every verdict, clean or
	// refused: a verification document that does not name its trust
	// material has not said what it proved.
	trusted := va.root.facts()

	if err == nil {
		return report.Seal(target, subject, outcome.pop, nil, nil, report.NoCanary(),
			append(trusted, outcome.facts...)...)
	}

	findings := []report.Finding{{Subject: subject, Assertion: va.mode, Detail: err.Error()}}

	return report.Seal(target, subject, declaredPop(va), findings, nil, report.NoCanary(), trusted...)
}

// declaredPop reports what a refused run HAD under test: the subject
// manifest for the release modes, the one branch ref for the walks.
func declaredPop(va *verifyArgs) report.Population {
	if va.mode == modeRelease || va.mode == modeVSA {
		return report.PopulationFromEvidence(len(va.subjectList), "release subjects")
	}

	return report.PopulationFromEvidence(1, "branch ref under walk")
}

// parseVerifyArgs parses flags, loads and validates every file input
// and builds the trust boundary — all refusals land here, before any
// verification starts. The int is a process exit code, the same
// vocabulary Run speaks.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func parseVerifyArgs(mode string, args []string, stderr io.Writer) (*verifyArgs, int) {
	va := &verifyArgs{mode: mode}

	fs := flag.NewFlagSet("stele verify "+mode, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&va.policyPath, "policy", "", "path to the committed verify policy (required)")
	va.root.register(fs)
	fs.StringVar(&va.repo, "repo", "", "owner/repo under verification (required)")
	fs.BoolVar(&va.jsonOut, "json", false,
		"emit the verdict as one JSON report document on stdout (progress moves to stderr)")
	fs.BoolVar(&va.noRetry, "no-retry", false,
		"fail fast on store reads instead of waiting out publication propagation (auditing history)")

	switch mode {
	case modeRelease, modeVSA:
		fs.StringVar(&va.tag, "tag", "", "release tag (required)")
		fs.StringVar(&va.subjects, "subjects", "", "sha256sum manifest of release subjects (required)")
		fs.StringVar(&va.sboms, "sboms", "",
			"sha256sum manifest of the release's SBOM assets — the decision candidates (release mode, required)")
		fs.StringVar(&va.signerPin, "signer-digest", "", "commit digest the signer identity is pinned at (required)")
		fs.StringVar(&va.machineryPin, "machinery-digest", "",
			"commit digest the verifier/decision identities are pinned at (required)")
	case modeChain:
		fs.StringVar(&va.gitDir, "git-dir", "", "local clone with the branch and notes ref fetched (required)")
		fs.StringVar(&va.ref, "ref", "refs/heads/main", "fully qualified branch ref to walk")
	}

	if err := fs.Parse(args); err != nil {
		return nil, exitUsage
	}

	if code := va.load(stderr); code != exitOK {
		return nil, code
	}

	return va, exitOK
}

// load reads and validates the file-backed inputs.
func (va *verifyArgs) load(stderr io.Writer) int {
	fail := func(err error) int {
		if _, werr := fmt.Fprintf(stderr, "stele verify %s: %v\n", va.mode, err); werr != nil {
			return exitIO
		}

		return exitUsage
	}

	owner, repo, ok := strings.Cut(va.repo, "/")
	if !ok || owner == "" || repo == "" {
		return fail(errors.New("--repo must be owner/repo"))
	}

	va.coords = verify.Coords{Owner: owner, Repo: repo, Tag: va.tag}

	if va.policyPath == "" {
		return fail(errors.New("--policy is required"))
	}

	pf, err := os.Open(va.policyPath)
	if err != nil {
		return fail(err)
	}
	defer pf.Close() //nolint:errcheck // read-only close

	va.p, err = policy.Load(pf)
	if err != nil {
		return fail(err)
	}

	rootJSON, err := va.root.resolve()
	if err != nil {
		return fail(err)
	}

	va.bv, err = newBundleVerifier(rootJSON)
	if err != nil {
		return fail(err)
	}

	if va.mode == modeRelease || va.mode == modeVSA {
		if va.subjects == "" {
			return fail(errors.New("--subjects is required"))
		}

		manifest, err := os.ReadFile(va.subjects)
		if err != nil {
			return fail(err)
		}

		va.subjectList, err = parseManifest(string(manifest))
		if err != nil {
			return fail(err)
		}
	}

	if va.mode == modeRelease {
		if va.sboms == "" {
			return fail(errors.New("--sboms is required"))
		}

		manifest, err := os.ReadFile(va.sboms)
		if err != nil {
			return fail(err)
		}

		va.sbomList, err = parseManifest(string(manifest))
		if err != nil {
			return fail(err)
		}
	}

	if va.mode == modeChain && va.gitDir == "" {
		return fail(errors.New("--git-dir is required"))
	}

	return exitOK
}

// parseManifest reads a sha256sum manifest: "<64 hex>  <name>" per
// line, the exact format the build writes and the signer attests.
func parseManifest(text string) ([]verify.Subject, error) {
	var subjects []verify.Subject

	line := 0

	for raw := range strings.Lines(text) {
		line++

		trimmed := strings.TrimRight(raw, "\r\n")
		if trimmed == "" {
			continue
		}

		digest, name, ok := strings.Cut(trimmed, "  ")
		if !ok || digest == "" || name == "" {
			return nil, fmt.Errorf("subjects line %d is not a sha256sum record", line)
		}

		subjects = append(subjects, verify.Subject{Name: name, SHA256: digest})
	}

	return subjects, nil
}

// runVerify runs the selected mode against real dependencies and
// reports what it proved.
func runVerify(va *verifyArgs, out *latch) (*verifyOutcome, error) {
	pins := verify.Pins{Signer: va.signerPin, Machinery: va.machineryPin}

	switch va.mode {
	case modeRelease:
		verdict, err := verify.Release(
			va.p, va.coords, va.subjectList, va.sbomList, pins, newStore(va.noRetry), va.bv, out.logf)
		if err != nil {
			return nil, err
		}

		return &verifyOutcome{
			pop:   report.PopulationFromEvidence(len(va.subjectList), "release subjects"),
			facts: []report.Fact{{Name: "sourceRevision", Value: verdict.SourceRevision()}},
		}, nil
	case modeVSA:
		// The empty demand, never nil: a stranger has no evidence
		// classes, and gets the whole universal obligation.
		verdict, err := verify.VSA(
			va.p, va.coords, va.subjectList, pins, newStore(va.noRetry), va.bv, out.logf,
			&verify.EnrichmentDemand{})
		if err != nil {
			return nil, err
		}

		facts := []report.Fact{{Name: "verifiedLevels", Value: strings.Join(verdict.Levels(), " ")}}

		// The commit the release was built from, as the verified
		// enrichment claims it — present only where the policy
		// declares that obligation, because a verdict alone does not
		// carry it.
		if rev := verdict.SourceRevision(); rev != "" {
			facts = append(facts, report.Fact{Name: "sourceRevision", Value: rev})
		}

		return &verifyOutcome{
			pop:   report.PopulationFromEvidence(len(va.subjectList), "release subjects"),
			facts: facts,
		}, nil
	default: // chain — the mode switch upstream admits no other value
		return runWalk(va, out)
	}
}

// runWalk runs the chain walk. The honest computed level moved to
// `stele level source` — one level computation, in the package that
// owns the ladder.
func runWalk(va *verifyArgs, out *latch) (*verifyOutcome, error) {
	h, err := openHistory(va.gitDir, *va.p.Source.NotesRef)
	if err != nil {
		return nil, err
	}

	verdict, err := verify.Chain(va.p, va.coords, va.ref, h, va.bv, out.logf)
	if err != nil {
		return nil, err
	}

	return &verifyOutcome{
		pop:   report.PopulationFromEvidence(1, "branch ref under walk"),
		facts: []report.Fact{{Name: "links", Value: strconv.Itoa(verdict.Links())}},
	}, nil
}
