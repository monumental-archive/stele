// The assert verb: read evidence, read a declaration, report
// divergence. Exit codes split three ways because the report's
// verdicts do (docs/report-schema.md): 0 PASS, 1 FAIL, and 4 for
// CANNOT_JUDGE — a run that could not look must never exit like one
// that looked and found drift, or like one that found none.
//
// image-facts keeps the environment contract its bash predecessor
// declared (IMAGE, DIGEST, FACTS): the canon passes values via env:,
// never ${{ }} interpolated into shell, and the callers already
// speak it.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/oci"
	"github.com/monumental-archive/stele/internal/osv"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/trust"
	"github.com/monumental-archive/stele/internal/verify"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

// exitBlind is CANNOT_JUDGE's own exit code: the run could not see
// enough to judge. Distinct from FAIL (1), usage (2) and stream
// failure (3).
const exitBlind = 4

// The evidence walk's depths.
const (
	depthPresence = "presence"
	depthFull     = "full"
)

// The assert targets.
const (
	targetImageFacts  = "image-facts"
	targetEvidence    = "evidence"
	targetBlastRadius = "blast-radius"
	targetTags        = "tags"
)

// The effect seams, swapped only by tests.
//
//nolint:gochecknoglobals // test seams, written only by test setup
var (
	newOCIReader = func() oci.Reader { return oci.Client{} }

	newScanner = func() osv.Scanner { return osv.Runner{} }

	newAttestor = func(forge gh.Forge, bv verify.BundleVerifier, issuer string) assert.Attestor {
		return storeAttestor{forge: forge, bv: bv, issuer: issuer}
	}

	newForge = func() gh.Forge {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			token = os.Getenv("GH_TOKEN")
		}

		return gh.New(token)
	}
)

// assertCmd dispatches `stele assert <target>`.
func assertCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		if _, err := fmt.Fprintln(stderr, "stele assert: a target is required: image-facts"); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch args[0] {
	case targetImageFacts:
		return assertImageFacts(args[1:], stdout, stderr)
	case targetEvidence:
		return assertEvidence(args[1:], stdout, stderr)
	case targetBlastRadius:
		return assertBlastRadius(args[1:], stdout, stderr)
	case targetTags:
		return assertTags(args[1:], stdout, stderr)
	default:
		if _, err := fmt.Fprintf(stderr,
			"stele assert: unknown target %q (image-facts, evidence, blast-radius, tags)\n", args[0]); err != nil {
			return exitIO
		}

		return exitUsage
	}
}

// storeAttestor proves store-resident attestations through the same
// trust boundary the verify verb uses — the single-binary payoff: the
// walk asserting "this verifies" and the verifier deciding what
// verifying MEANS are one implementation.
type storeAttestor struct {
	forge  gh.Forge
	bv     verify.BundleVerifier
	issuer string
}

// Verify implements assert.Attestor. A bundle counts only if it
// verifies under the identity AND was signed from an expected pin
// (when pins are given) AND carries the required predicate type.
func (a storeAttestor) Verify(
	owner, repo, subjectDigest string, candidates []assert.Candidate, predicateType string,
) error {
	hex := strings.TrimPrefix(subjectDigest, "sha256:")

	bundles, err := a.forge.Attestations(owner, repo, hex)
	if err != nil {
		return fmt.Errorf("store read: %w", err)
	}

	if len(bundles) == 0 {
		return errNoAttestation
	}

	var last error

	for _, raw := range bundles {
		for _, c := range candidates {
			id := trust.Identity{SAN: c.Identity, Issuer: a.issuer}

			verified, verr := a.bv.Attestation(raw, id, hex)
			if verr != nil {
				last = verr

				continue
			}

			if perr := predicateMatches(verified.Payload, predicateType); perr != nil {
				last = perr

				continue
			}

			// The commit-level binding, independent of how the SAN
			// spells the ref: the signing tree must BE the pinned one.
			if c.SignerPin != "" && verified.Extensions.BuildSignerDigest != c.SignerPin {
				last = fmt.Errorf("signed at %q, not the declared pin %q",
					verified.Extensions.BuildSignerDigest, c.SignerPin)

				continue
			}

			return nil
		}
	}

	if last == nil {
		last = errNoAttestation
	}

	return last
}

// errNoAttestation names an empty store, so a caller can tell it from
// a bundle that was present and refused.
var errNoAttestation = errors.New("the store holds no attestation for this subject")

// predicateMatches checks a verified payload's predicate type when
// one is required. Empty means any predicate is acceptable.
func predicateMatches(payload []byte, predicateType string) error {
	if predicateType == "" {
		return nil
	}

	stmt, err := jsonx.DecodeForeign[struct {
		PredicateType *string `json:"predicateType"`
	}](payload)
	if err != nil {
		return fmt.Errorf("verified payload is not a statement: %w", err)
	}

	if stmt.PredicateType == nil || *stmt.PredicateType != predicateType {
		return fmt.Errorf("predicate type is not %s", predicateType)
	}

	return nil
}

// assertEvidence runs the evidence-completeness walk: policy loaded,
// the forge chosen (live, snapshot replay, or capture-through), the
// contract sources stacked manifest-first, the debt file parsed into
// declared exceptions.
func assertEvidence(args []string, stdout, stderr io.Writer) int {
	var (
		jsonOut                   bool
		org, policyPath, debtPath string
		repo                      string
		root                      rootFlags
		pinPath                   string
		depth, verifyPolicyPath   string
		snapshotDir, captureDir   string
	)

	flags := flag.NewFlagSet("stele assert evidence", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&org, "org", "", "organisation whose releases are walked (this or --repo)")
	flags.StringVar(&repo, "repo", "",
		"owner/name whose releases are walked — the single-repository population (this or --org)")
	flags.StringVar(&policyPath, "policy", "", "path to the committed assert policy (required)")
	flags.StringVar(&debtPath, "debt", "", "path to the committed evidence-debt file (defaults to the policy's debtFile)")
	root.register(flags)
	flags.StringVar(&pinPath, "base-pins", "",
		"path to the committed base-image pin file (defaults to the policy's baseImages.pinFile)")
	flags.StringVar(&depth, "depth", depthPresence,
		"presence (default) or full — full re-verifies every covered release through the verify engine (#4)")
	flags.StringVar(&verifyPolicyPath, "verify-policy", "",
		"path to the committed verify policy (required with --depth full: it names the trust identities)")
	flags.StringVar(&snapshotDir, "snapshot", "", "replay a captured snapshot directory instead of the live API")
	flags.StringVar(&captureDir, "capture", "", "record every live answer into this directory while walking")
	flags.BoolVar(&jsonOut, "json", false,
		"emit the verdict as one JSON report document on stdout (progress moves to stderr)")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele assert evidence: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch {
	case org == "" && repo == "":
		return usageFail("--org or --repo is required")
	case org != "" && repo != "":
		return usageFail("--org and --repo are exclusive: one population, named once")
	case repo != "" && !strings.Contains(repo, "/"):
		return usageFail("--repo must be owner/name")
	case policyPath == "":
		return usageFail("--policy is required")
	case snapshotDir != "" && captureDir != "":
		return usageFail("--snapshot and --capture are exclusive: replay reads, capture writes")
	}

	// Depth is validated before anything is opened: asking for full
	// depth without the trust authority is a usage refusal, never a
	// shallower walk that looks like the deep one.
	switch {
	case depth != depthPresence && depth != depthFull:
		return usageFail(fmt.Sprintf("--depth %q is not a depth (presence, full)", depth))
	case depth == depthFull && verifyPolicyPath == "":
		return usageFail("--verify-policy is required with --depth full: it names the trust identities")
	}

	pf, err := os.Open(policyPath) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return usageFail(err.Error())
	}
	defer pf.Close() //nolint:errcheck // read-only close

	pol, err := assert.LoadPolicy(pf)
	if err != nil {
		return usageFail(err.Error())
	}

	if debtPath == "" {
		debtPath = *pol.Evidence.DebtFile
	}

	debt, code := loadDebt(debtPath, stderr)
	if code != exitOK {
		return code
	}

	forge := newForge()
	if snapshotDir != "" {
		forge = gh.Snapshot{Dir: snapshotDir}
	} else if captureDir != "" {
		forge = gh.Capture{Live: forge, Dir: captureDir}
	}

	src := assert.Sources{
		assert.ManifestSource{Forge: forge, Policy: pol.Evidence, Asset: *pol.Evidence.ManifestAsset},
		assert.WorkflowSource{Forge: forge, Policy: pol.Evidence},
	}

	// One run, one root of trust: both halves that verify are handed
	// the same document, resolved once. Re-resolving per half could
	// hand two halves of one verdict two different trust anchors.
	var rootJSON []byte

	if depth == depthFull || storeHalvesDeclared(pol) {
		var rerr error
		if rootJSON, rerr = root.resolve(); rerr != nil {
			return usageFail(rerr.Error())
		}
	}

	attestor, pinFile, serr := loadStoreInputs(pol, forge, rootJSON, pinPath)
	if serr != nil {
		return usageFail(serr.Error())
	}

	// The full-depth leg (#4): the walk hands every covered release to
	// the verify engine, so it needs the trust authority (the verify
	// policy) and the cryptographic boundary.
	var full *assert.FullDepth

	if depth == depthFull {
		fd, derr := loadFullDepth(verifyPolicyPath, rootJSON, forge)
		if derr != nil {
			return usageFail(derr.Error())
		}

		full = fd
	}

	out := &latch{w: stdout}
	if jsonOut {
		out = &latch{w: stderr}
	}

	pop := assert.Population{Org: org, Repo: repo}

	rep, err := assert.Evidence(pol, pop, forge, src, attestor, debt, pinFile, full, out.logf, root.facts()...)
	if out.err != nil {
		return exitIO
	}

	if err != nil {
		rep = report.Seal("assert "+targetEvidence, pop.Subject(),
			report.PopulationFromListing(0, "walk incomplete"),
			[]report.Finding{{Subject: pop.Subject(), Assertion: targetEvidence, Detail: err.Error()}},
			nil, report.NoCanary())

		if _, werr := fmt.Fprintf(stderr, "%v\n", err); werr != nil {
			return exitIO
		}
	}

	return emitReport(rep, jsonOut, stdout, stderr)
}

// loadDebt parses the committed debt file. An absent file is no debt
// — the walk owes nothing to a file nobody wrote; a malformed one is
// a usage refusal, because a reviewed file that parses as nothing
// would excuse nothing silently.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func loadDebt(path string, stderr io.Writer) ([]report.Exception, int) {
	content, err := os.ReadFile(path) //nolint:gosec // the debt path is operator-supplied by design
	if errors.Is(err, fs.ErrNotExist) {
		return nil, exitOK
	}

	if err == nil {
		parsed, perr := assert.ParseDebt(content, path)
		if perr == nil {
			return parsed, exitOK
		}

		err = perr
	}

	if _, werr := fmt.Fprintf(stderr, "stele assert evidence: %v\n", err); werr != nil {
		return nil, exitIO
	}

	return nil, exitUsage
}

// assertImageFacts runs the image-facts target: env contract read and
// refused by name (#82 — a missing input fails by its name, never by
// expanding to nothing), the engine judged, the report sealed out.
func assertImageFacts(args []string, stdout, stderr io.Writer) int {
	var jsonOut bool

	flags := flag.NewFlagSet("stele assert image-facts", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.BoolVar(&jsonOut, "json", false,
		"emit the verdict as one JSON report document on stdout (progress moves to stderr)")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	image, digest, facts := os.Getenv("IMAGE"), os.Getenv("DIGEST"), os.Getenv("FACTS")

	for name, v := range map[string]string{"IMAGE": image, "DIGEST": digest, "FACTS": facts} {
		if v == "" {
			if _, err := fmt.Fprintf(stderr, "stele assert image-facts: %s must be set\n", name); err != nil {
				return exitIO
			}

			return exitUsage
		}
	}

	out := &latch{w: stdout}
	if jsonOut {
		out = &latch{w: stderr}
	}

	rep, err := assert.ImageFacts(image, digest, []byte(facts), newOCIReader(), out.logf)
	if out.err != nil {
		return exitIO
	}

	if err != nil {
		// Infrastructure refused before the engine could judge: sealed
		// as CANNOT_JUDGE over an empty population, the error carried
		// as the finding — partial sight is reported, never a verdict.
		rep = report.Seal("assert "+targetImageFacts, image+"@"+digest,
			report.PopulationFromEvidence(0, "registry read incomplete"),
			[]report.Finding{{Subject: image + "@" + digest, Assertion: targetImageFacts, Detail: err.Error()}},
			nil, report.NoCanary())

		if _, werr := fmt.Fprintf(stderr, "%v\n", err); werr != nil {
			return exitIO
		}
	}

	return emitReport(rep, jsonOut, stdout, stderr)
}

// emitReport writes the sealed report (JSON or the human lines) and
// maps its verdict to the exit code.
func emitReport(rep *report.Report, jsonOut bool, stdout, stderr io.Writer) int {
	if jsonOut {
		if err := rep.Encode(stdout); err != nil {
			return exitIO
		}
	} else {
		out := &latch{w: stdout}
		findings := rep.Findings()
		for i := range findings {
			out.logf("assert: %s: %s: %s", findings[i].Subject, findings[i].Assertion, findingLine(&findings[i]))
		}

		out.logf("assert: %s", rep.Verdict())

		if out.err != nil {
			return exitIO
		}
	}

	if rep.Verdict() == report.VerdictPass {
		return exitOK
	}

	if rep.Verdict() == report.VerdictFail {
		return exitRefused
	}

	// CANNOT_JUDGE — Seal admits no fourth verdict.
	if _, err := fmt.Fprintln(stderr, "stele assert: the run could not see enough to judge"); err != nil {
		return exitIO
	}

	return exitBlind
}

// findingLine renders one finding's substance for the human stream.
func findingLine(f *report.Finding) string {
	if f.Expected != "" || f.Actual != "" {
		return fmt.Sprintf("%s (expected %q, actual %q)", f.Detail, f.Expected, f.Actual)
	}

	return f.Detail
}

// assertBlastRadius runs the SBOM scan walk: policy and VEX decisions
// loaded, the forge and scanner seams resolved, the verdict sealed.
func assertBlastRadius(args []string, stdout, stderr io.Writer) int {
	var (
		jsonOut                 bool
		org, policyPath, vexDir string
		repo                    string
		snapshotDir, captureDir string
	)

	flags := flag.NewFlagSet("stele assert blast-radius", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&org, "org", "", "organisation whose SBOMs are scanned (this or --repo)")
	flags.StringVar(&repo, "repo", "",
		"owner/name whose SBOMs are scanned — the single-repository population (this or --org)")
	flags.StringVar(&policyPath, "policy", "", "path to the committed assert policy (required)")
	flags.StringVar(&vexDir, "vex", "", "directory of committed *.openvex.json decisions (required)")
	flags.StringVar(&snapshotDir, "snapshot", "", "replay a captured snapshot directory instead of the live API")
	flags.StringVar(&captureDir, "capture", "", "record every live answer into this directory while walking")
	flags.BoolVar(&jsonOut, "json", false,
		"emit the verdict as one JSON report document on stdout (progress moves to stderr)")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele assert blast-radius: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch {
	case org == "" && repo == "":
		return usageFail("--org or --repo is required")
	case org != "" && repo != "":
		return usageFail("--org and --repo are exclusive: one population, named once")
	case repo != "" && !strings.Contains(repo, "/"):
		return usageFail("--repo must be owner/name")
	case policyPath == "":
		return usageFail("--policy is required")
	case vexDir == "":
		return usageFail("--vex is required")
	case snapshotDir != "" && captureDir != "":
		return usageFail("--snapshot and --capture are exclusive: replay reads, capture writes")
	}

	pf, err := os.Open(policyPath) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return usageFail(err.Error())
	}
	defer pf.Close() //nolint:errcheck // read-only close

	pol, err := assert.LoadPolicy(pf)
	if err != nil {
		return usageFail(err.Error())
	}

	decisions, code := loadVEX(vexDir, stderr)
	if code != exitOK {
		return code
	}

	forge := newForge()
	if snapshotDir != "" {
		forge = gh.Snapshot{Dir: snapshotDir}
	} else if captureDir != "" {
		forge = gh.Capture{Live: forge, Dir: captureDir}
	}

	out := &latch{w: stdout}
	if jsonOut {
		out = &latch{w: stderr}
	}

	pop := assert.Population{Org: org, Repo: repo}

	rep, err := assert.BlastRadius(pol, pop, forge, newScanner(), decisions, out.logf)
	if out.err != nil {
		return exitIO
	}

	if err != nil {
		rep = report.Seal("assert "+targetBlastRadius, pop.Subject(),
			report.PopulationFromListing(0, "walk incomplete"),
			[]report.Finding{{Subject: pop.Subject(), Assertion: targetBlastRadius, Detail: err.Error()}},
			nil, report.NoCanary())

		if _, werr := fmt.Fprintf(stderr, "%v\n", err); werr != nil {
			return exitIO
		}
	}

	return emitReport(rep, jsonOut, stdout, stderr)
}

// loadVEX parses every committed OpenVEX document in the directory.
// An empty or absent directory decides NOTHING (the vexjoin law); a
// malformed statement refuses, because a reviewed decision that
// parses as nothing decides nothing silently.
//
//nolint:gocritic // unnamedResult: the int is an exit code, cli.Run's established vocabulary
func loadVEX(dir string, stderr io.Writer) (*vexjoin.Decisions, int) {
	decisions, err := readVEXDir(dir)
	if err != nil {
		if _, werr := fmt.Fprintf(stderr, "stele assert blast-radius: %v\n", err); werr != nil {
			return nil, exitIO
		}

		return nil, exitUsage
	}

	return decisions, exitOK
}

// readVEXDir is the shared load: it carries the cause as an error so
// each verb reports the refusal in its own name — a shared loader that
// baked one verb's prefix into the message would misattribute the
// other's failures.
func readVEXDir(dir string) (*vexjoin.Decisions, error) {
	decisions := &vexjoin.Decisions{}

	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return decisions, nil
	}

	if err != nil {
		return nil, fmt.Errorf("vex decisions: %w", err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".openvex.json") {
			continue
		}

		doc, rerr := os.ReadFile(dir + "/" + e.Name()) //nolint:gosec // the vex dir is operator-supplied by design
		if rerr != nil {
			return nil, fmt.Errorf("vex decisions: %w", rerr)
		}

		if perr := vexjoin.Parse(decisions, doc, e.Name()); perr != nil {
			return nil, perr
		}
	}

	return decisions, nil
}

// assertTags runs the tag audit (stele#83): policy loaded, the tag
// verifier bound to the trust boundary, the walk sealed out.
func assertTags(args []string, stdout, stderr io.Writer) int {
	var (
		jsonOut                 bool
		org, repo, policyPath   string
		root                    rootFlags
		snapshotDir, captureDir string
	)

	flags := flag.NewFlagSet("stele assert tags", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&org, "org", "", "organisation whose tags are audited (this or --repo)")
	flags.StringVar(&repo, "repo", "",
		"owner/name whose tags are audited — the single-repository population (this or --org)")
	flags.StringVar(&policyPath, "policy", "", "path to the committed assert policy (required)")
	root.register(flags)
	flags.StringVar(&snapshotDir, "snapshot", "", "replay a captured snapshot directory instead of the live API")
	flags.StringVar(&captureDir, "capture", "", "record every live answer into this directory while walking")
	flags.BoolVar(&jsonOut, "json", false,
		"emit the verdict as one JSON report document on stdout (progress moves to stderr)")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	usageFail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele assert tags: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch {
	case org == "" && repo == "":
		return usageFail("--org or --repo is required")
	case org != "" && repo != "":
		return usageFail("--org and --repo are exclusive: one population, named once")
	case repo != "" && !strings.Contains(repo, "/"):
		return usageFail("--repo must be owner/name")
	case policyPath == "":
		return usageFail("--policy is required")
	case snapshotDir != "" && captureDir != "":
		return usageFail("--snapshot and --capture are exclusive: replay reads, capture writes")
	}

	pf, err := os.Open(policyPath) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return usageFail(err.Error())
	}
	defer pf.Close() //nolint:errcheck // read-only close

	pol, err := assert.LoadPolicy(pf)
	if err != nil {
		return usageFail(err.Error())
	}

	if pol.Tags == nil {
		return usageFail("the policy declares no tags section")
	}

	tv, code := loadTagVerifier(pol, &root, stderr)
	if code != exitOK {
		return code
	}

	forge := newForge()
	if snapshotDir != "" {
		forge = gh.Snapshot{Dir: snapshotDir}
	} else if captureDir != "" {
		forge = gh.Capture{Live: forge, Dir: captureDir}
	}

	tags, ok := forge.(gh.TagReader)
	if !ok {
		return usageFail("this forge cannot read tags")
	}

	pop := assert.Population{Org: org, Repo: repo}

	out := &latch{w: stdout}
	if jsonOut {
		out = &latch{w: stderr}
	}

	rep, err := assert.Tags(pol, pop, forge, tags, tv, out.logf, root.facts()...)
	if out.err != nil {
		return exitIO
	}

	if err != nil {
		rep = report.Seal("assert "+targetTags, pop.Subject(),
			report.PopulationFromListing(0, "walk incomplete"),
			[]report.Finding{{Subject: pop.Subject(), Assertion: targetTags, Detail: err.Error()}},
			nil, report.NoCanary())

		if _, werr := fmt.Fprintf(stderr, "%v\n", err); werr != nil {
			return exitIO
		}
	}

	return emitReport(rep, jsonOut, stdout, stderr)
}

// loadTagVerifier binds the tag audit's trust boundary. Signing
// obligations exist exactly when some epoch is not pending; only
// then is the trusted root required.
//
//nolint:gocritic,ireturn // exit-code result; the walk's own seam type is the point
func loadTagVerifier(pol *assert.Policy, root *rootFlags, stderr io.Writer) (assert.TagVerifier, int) {
	signing := false

	for _, epoch := range pol.Tags.Epochs {
		if epoch != assert.EpochPending {
			signing = true

			break
		}
	}

	if !signing {
		return nil, exitOK
	}

	fail := func(msg string) (assert.TagVerifier, int) {
		if _, err := fmt.Fprintf(stderr, "stele assert tags: %s\n", msg); err != nil {
			return nil, exitIO
		}

		return nil, exitUsage
	}

	rootJSON, err := root.resolve()
	if err != nil {
		return fail(err.Error())
	}

	tv, err := newTagVerifier(rootJSON, *pol.Tags.IdentityPattern, *pol.Issuer)
	if err != nil {
		return fail(err.Error())
	}

	return tv, exitOK
}

// newTagVerifier builds the gitsign verifier over the trust package.
// Swappable in tests.
//
//nolint:gochecknoglobals // test seam, written only by test setup
var newTagVerifier = func(rootJSON []byte, sanPattern, issuer string) (assert.TagVerifier, error) {
	tr, err := trust.LoadRoot(rootJSON)
	if err != nil {
		return nil, fmt.Errorf("trusted root: %w", err)
	}

	v, err := trust.NewVerifier(tr)
	if err != nil {
		return nil, fmt.Errorf("verifier: %w", err)
	}

	re, err := regexp.Compile(sanPattern)
	if err != nil {
		return nil, fmt.Errorf("identity pattern: %w", err)
	}

	return tagTrust{v: v, id: trust.TagIdentity{SANPattern: re, Issuer: issuer}}, nil
}

// tagTrust adapts trust.VerifyTag to the walk's seam.
type tagTrust struct {
	v  *trust.Verifier
	id trust.TagIdentity
}

func (t tagTrust) Verify(payload, signature []byte) (string, error) {
	san, err := t.v.VerifyTag(payload, signature, t.id)
	if err != nil {
		return "", err
	}

	return san, nil
}
