// The verify verb: argument surface for the four verification modes
// (release, vsa, chain, level), each a thin assembly of the policy,
// the trust boundary and the engine. Effectful constructors sit
// behind package seams so every guard branch here is reachable from
// a table test; the constructors themselves are proven in their own
// packages and in shadow mode.

package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/evidence"
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
	modeRepro   = "repro"
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
	policyPath    string
	root          rootFlags
	repo          string
	tag           string
	subjects      string
	sboms         string
	inventories   string
	signerPin     string
	machineryPin  string
	gitDir        string
	ref           string
	mode          string
	jsonOut       bool
	noRetry       bool
	p             *policy.Policy
	coords        verify.Coords
	subjectList   []verify.Subject
	sbomList      []verify.Subject
	inventoryList []verify.Subject
	bv            verify.BundleVerifier
}

// verifyCmd dispatches `stele verify <mode>`.
func verifyCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		if _, err := fmt.Fprintln(stderr, "stele verify: a mode is required: release, vsa, chain or repro"); err != nil {
			return exitIO
		}

		return exitUsage
	}

	mode := args[0]
	switch mode {
	case modeRepro:
		// Repro is a pure comparison: no policy, no trust material, no
		// store — its argument surface shares nothing with the three
		// cryptographic modes, so it parses its own.
		return verifyRepro(args[1:], stdout, stderr)
	case modeRelease, modeVSA, modeChain:
	default:
		if _, err := fmt.Fprintf(stderr, "stele verify: unknown mode %q (release, vsa, chain, repro)\n", mode); err != nil {
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

// verifyRepro runs the reproducibility comparison (stele#96): the
// release's own manifest against the digests an independent rebuild
// produced. The rebuild itself is orchestration and stays with the
// caller; only the judgment lives here, and it speaks the report's
// tri-state — an empty subject population is a population of zero,
// which seals CANNOT_JUDGE, never PASS, because a repro claim over
// nothing is not a proof.
//
// The released manifest is taken WHOLE (stele#156). The flag it
// replaced asked for "the RELEASED artifacts" — a set only this
// engine's private knowledge could draw, so a caller could honour the
// contract only by reimplementing the tool, which is exactly what the
// canon's audit did in thirty lines of workflow bash. Now the engine
// reads which entries are build subjects: from the manifest's own
// typing where it carries one, and from the org's declared vocabulary
// where a legacy or foreign manifest does not.
//
// A rebuild that covers ONE class says so with --class (stele#185).
// Judging the whole release against a single class's rebuild reported
// every other class as absent from it — thirteen artifacts of a
// fourteen-artifact release, and two supply-chain issues filed against
// a release that was fine (release-lab v0.25.3). The scope is
// narrowed only where the released manifest can answer it; where it
// cannot, the population stays the whole release and the verdict says
// which of the two it is.
func verifyRepro(args []string, stdout, stderr io.Writer) int {
	var (
		repo, tag, released, rebuilt, policyPath, class string
		jsonOut                                         bool
	)

	fs := flag.NewFlagSet("stele verify repro", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&repo, "repo", "", "owner/repo whose release is under rebuild (required)")
	fs.StringVar(&tag, "tag", "", "release tag under rebuild (required)")
	fs.StringVar(&released, "released", "",
		"the RELEASED manifest, whole (required) — a typed evidence manifest, whose build-subject "+
			"entries are the population, or a legacy sha256sum manifest classified through --assert-policy")
	fs.StringVar(&rebuilt, "rebuilt", "", "sha256sum manifest of the REBUILT artifacts (required)")
	fs.StringVar(&policyPath, "assert-policy", "",
		"assert policy whose evidence vocabulary types an UNTYPED released manifest; unused, and not "+
			"read, when the manifest carries its own typing. Named for the document it takes: --policy "+
			"is the VERIFY policy everywhere else under this verb, and this comparison verifies nothing")
	fs.StringVar(&class, "class", "",
		"the evidence class this rebuild covers — the population narrows to the artifacts the released "+
			"manifest says that class built. Omit when the rebuild covers the whole release. A manifest "+
			"carrying no class answer keeps the whole-release population and reports that it did")
	fs.BoolVar(&jsonOut, "json", false,
		"emit the verdict as one JSON report document on stdout (progress moves to stderr)")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	fail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele verify repro: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch {
	case repo == "" || !strings.Contains(repo, "/"):
		return fail("--repo must be owner/repo")
	case tag == "":
		return fail("--tag is required")
	case released == "":
		return fail("--released is required")
	case rebuilt == "":
		return fail("--rebuilt is required")
	}

	pop, err := reproSubjects(released, policyPath, class)
	if err != nil {
		return fail("released: " + err.Error())
	}

	built, err := digestManifest(rebuilt)
	if err != nil {
		return fail("rebuilt: " + err.Error())
	}

	subjects := pop.subjects

	out := &latch{w: stdout}
	if jsonOut {
		out = &latch{w: stderr}
	}

	// Loud, never inferred: a caller that asked for one class and got
	// the whole release must read it here, not deduce it from a count.
	if pop.unmet != "" {
		out.logf("repro: the released manifest carries no class answer, so %s cannot be scoped:"+
			" judging every build subject the release published", class)
	}

	divergences := verify.Repro(subjects, built, out.logf)
	if out.err != nil {
		return exitIO
	}

	// The comparison is one recorded check per released artifact:
	// verify carries no exceptions (below), so the journal's coverage
	// answers nothing here — but a finding still reaches a report
	// through the one door, whichever verb sealed it.
	j := report.NewJournal()
	for i := range subjects {
		j.Check(subjects[i].Name, "repro")
	}

	for _, d := range divergences {
		j.Check(d.Name, "repro/"+d.Kind).
			DivergedFrom(d.Released, d.Rebuilt, "the rebuild did not reproduce the release")
	}

	rep := report.Seal("verify repro", repo+"@"+tag,
		report.PopulationFromEvidence(len(subjects), pop.describe()),
		j, report.NoCanary(), report.NoJudgedSet(), pop.facts(len(built))...)

	return emitReport(rep, jsonOut, stdout, stderr)
}

// The two ways a released manifest's build subjects become known,
// reported as a fact so a reader of the verdict knows which one
// answered.
const (
	// typingManifest: the manifest typed its own entries.
	typingManifest = "manifest"
	// typingPolicy: an untyped manifest, classified through the org's
	// declared evidence vocabulary.
	typingPolicy = "policy"
)

// What the judged population COVERS, reported as a fact for the same
// reason the typing is: a verdict over one class and a verdict over
// the whole release are different claims, and a reader must never
// have to infer which one it is holding.
//
// scopeWholeRelease is every build subject the release published —
// because no class was asked for, or because one was and the released
// manifest could not answer it. WHICH of those two is a separate fact
// below, never a second half spliced into this string: a value a
// reader has to split is two facts wearing one name.
const scopeWholeRelease = "whole-release"

// Why a requested class scope went unmet, reported beside the scope
// and only when there was a request to miss. The population stays the
// whole release and the verdict says nothing about that class alone,
// which is the honest reading and must be STATED rather than left
// looking like a scoped one.
//
// The vocabulary is closed at one entry: a released manifest either
// carries the class answer or it does not, and which KIND of manifest
// could not answer — one below the schema that types it, or one with
// no typing at all — is already the subjectTyping fact beside it. A
// second spelling of that here would be the same two-facts-one-name
// defect one field over.
const unmetNoClassAnswer = "no-class-answer"

// reproPopulation is the released set a rebuild is judged against and
// how it was drawn: which typing answered, what the set covers, and
// why that is not what was asked for where it is not. One value,
// because they travel together into one sealed report and a caller
// holding some of them has a verdict it cannot describe.
type reproPopulation struct {
	subjects []verify.Subject
	typing   string
	scope    string
	unmet    string
}

// describe names the population for the report — the scope in words,
// beside the count the seal carries.
func (p *reproPopulation) describe() string {
	if p.scope == scopeWholeRelease {
		return "released build subjects under rebuild"
	}

	return "released " + p.scope + " build subjects under rebuild"
}

// facts renders what this population is, for the seal. The unmet
// reason appears only when there is one: a fact whose absence is the
// answer beats a fact carrying a word for "nothing to report".
func (p *reproPopulation) facts(rebuilt int) []report.Fact {
	facts := []report.Fact{
		{Name: "rebuiltArtifacts", Value: strconv.Itoa(rebuilt)},
		{Name: "subjectTyping", Value: p.typing},
		{Name: "classScope", Value: p.scope},
	}

	if p.unmet != "" {
		facts = append(facts, report.Fact{Name: "classScopeUnmet", Value: p.unmet})
	}

	return facts
}

// reproSubjects reads the released manifest whole and returns the
// build subjects alone, with the source of that classification and
// what the resulting population covers.
//
// The two formats are told apart by the FIRST byte, never by trying
// one and falling back to the other: a typed manifest whose schema or
// shape this build refuses must refuse the walk, and a fallback would
// launder that refusal into a text parse that happens to fail
// differently.
func reproSubjects(path, policyPath, class string) (*reproPopulation, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the manifest path is operator-supplied by design
	if err != nil {
		return nil, err //nolint:wrapcheck // reported under the flag's own name by the caller
	}

	if bytes.HasPrefix(bytes.TrimLeft(raw, " \t\r\n"), []byte("{")) {
		return reproFromManifest(raw, class)
	}

	listed, err := parseManifest(string(raw))
	if err != nil {
		return nil, err
	}

	if policyPath == "" {
		return nil, errors.New("this manifest carries no typing, so --assert-policy is required: which" +
			" assets are build subjects can only come from the org's declared evidence vocabulary")
	}

	pf, err := os.Open(policyPath) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return nil, err //nolint:wrapcheck // the path is in the message; a prefix would say it twice
	}
	defer pf.Close() //nolint:errcheck // read-only close

	pol, err := assert.LoadPolicy(pf)
	if err != nil {
		return nil, err
	}

	var subjects []verify.Subject

	for _, s := range listed {
		if pol.Evidence.Classify(s.Name) == evidence.TypeBuildSubject {
			subjects = append(subjects, s)
		}
	}

	// A sha256sum manifest names assets and nothing else. It cannot
	// say which class built one, and it does not carry the release's
	// declared class list either — so a class asked for here is
	// neither honoured nor refused, it is unanswerable, and the
	// verdict says exactly that.
	return newReproPopulation(subjects, typingPolicy, class, false), nil
}

// reproFromManifest draws the population from a typed evidence
// manifest — its own answer, read rather than re-derived.
func reproFromManifest(raw []byte, class string) (*reproPopulation, error) {
	doc, err := evidence.Parse(raw)
	if err != nil {
		return nil, err
	}

	// A class the release never shipped refuses rather than sealing
	// over the population of zero it would otherwise draw: zero is an
	// honest CANNOT_JUDGE for a class that built nothing, and a
	// misspelling that seals the same way is a verdict nobody asked
	// for.
	if class != "" && !doc.Declares(class) {
		return nil, fmt.Errorf("this release declared no class %q — it shipped %s",
			class, strings.Join(doc.Classes, ", "))
	}

	typed, scoped := doc.Subjects(), false

	if class != "" {
		if of, ok := doc.SubjectsOf(class); ok {
			typed, scoped = of, true
		}
	}

	subjects := make([]verify.Subject, 0, len(typed))
	for _, a := range typed {
		subjects = append(subjects, verify.Subject{Name: a.Name, SHA256: a.SHA256})
	}

	return newReproPopulation(subjects, typingManifest, class, scoped), nil
}

// newReproPopulation assembles the judged set and names what it
// covers. The ONE constructor, so the scope and the unmet reason
// cannot be set apart from the subjects they describe — they are two
// facts, but they answer one question and a caller holding a
// half-filled pair has a verdict it cannot state.
func newReproPopulation(subjects []verify.Subject, typing, class string, scoped bool) *reproPopulation {
	p := &reproPopulation{subjects: subjects, typing: typing, scope: scopeWholeRelease}

	switch {
	case class == "":
		return p
	case scoped:
		p.scope = class
	default:
		p.unmet = unmetNoClassAnswer
	}

	return p
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

	// `verify` carries NO exceptions, by law rather than by omission
	// (#147): it proves one artifact for a stranger, and an org file
	// that could say "ignore this failure" would be a lie about the
	// artifact. Written-down defects belong to the corpus walk, which
	// judges immutable history — assert's question, not this one's.
	j := report.NewJournal()

	if err == nil {
		return report.Seal(target, subject, outcome.pop, j, report.NoCanary(), report.NoJudgedSet(),
			append(trusted, outcome.facts...)...)
	}

	j.Check(subject, va.mode).Diverged(err.Error())

	return report.Seal(target, subject, declaredPop(va), j,
		report.NoCanary(), report.NoJudgedSet(), trusted...)
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
		fs.StringVar(&va.inventories, "inventories", "", inventoriesUsage+" (release mode)")
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
		if serr := va.loadSubjects(); serr != nil {
			return fail(serr)
		}
	}

	if va.mode == modeRelease {
		if berr := va.loadSBOMs(); berr != nil {
			return fail(berr)
		}
	}

	if va.mode == modeChain && va.gitDir == "" {
		return fail(errors.New("--git-dir is required"))
	}

	return exitOK
}

// loadSubjects reads the release's subject manifest — the bytes the
// release claims, which every provenance check is held against.
func (va *verifyArgs) loadSubjects() error {
	if va.subjects == "" {
		return errors.New("--subjects is required")
	}

	manifest, err := os.ReadFile(va.subjects)
	if err != nil {
		return fmt.Errorf("reading the subject manifest: %w", err)
	}

	va.subjectList, err = parseManifest(string(manifest))

	return err
}

// loadSBOMs reads the decision candidates and, when the release
// declares one, its inventory plan — the decision's denominator.
func (va *verifyArgs) loadSBOMs() error {
	if va.sboms == "" {
		return errors.New("--sboms is required")
	}

	manifest, err := os.ReadFile(va.sboms)
	if err != nil {
		return fmt.Errorf("reading the SBOM manifest: %w", err)
	}

	if va.sbomList, err = parseManifest(string(manifest)); err != nil {
		return err
	}

	if va.inventories == "" {
		return nil
	}

	manifest, err = os.ReadFile(va.inventories)
	if err != nil {
		return fmt.Errorf("reading the inventory plan: %w", err)
	}

	va.inventoryList, err = parsePlan(string(manifest))

	return err
}

// inventoriesUsage is the one spelling of what the plan input IS,
// stated where both modes read it: the flag exists on `verify
// release` and `emit vsa` because they run the same engine, and two
// descriptions of one input drift.
const inventoriesUsage = "sha256sum manifest of the release's PLANNED inventory documents — " +
	"the inventory plan as digests, each owing its own release decision; " +
	"absent declares a release with no plan, judged under the whole-release decision invariant"

// parsePlan reads the inventory plan manifest — the same sha256sum
// shape as every other manifest input, because the plan reaches the
// engine as digests. A plan document that names nothing is refused:
// declaring a plan and planning nothing is not the same claim as
// declaring no plan, and only the second one may soften the gate.
func parsePlan(text string) ([]verify.Subject, error) {
	planned, err := parseManifest(text)
	if err != nil {
		return nil, err
	}

	if len(planned) == 0 {
		return nil, errors.New(
			"the inventory plan names no document — a declared plan that plans nothing is not an absent plan")
	}

	return planned, nil
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
			return nil, fmt.Errorf("manifest line %d is not a sha256sum record", line)
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
		sboms := verify.SBOMs{Assets: va.sbomList, Planned: va.inventoryList}

		verdict, err := verify.Release(
			va.p, va.coords, va.subjectList, sboms, pins, newStore(va.noRetry), va.bv, out.logf)
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
