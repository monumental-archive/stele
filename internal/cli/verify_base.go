// The build-time base gate (stele#402): every reference a build is
// about to instantiate, judged BEFORE it is instantiated, under the
// one declaration in the assert policy that claims it — a first-party
// scope's provenance judgment, of whichever kind the scope is, or an
// official image's published provenance held to its declared source.
// The corpus walk (assert evidence) applies the same first-party
// judgments to the whole population; this is the gate at the one
// moment the bytes are about to be used.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/baseimage"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/oci"
	"github.com/monumental-archive/stele/internal/report"
)

// modeBase is the dispatch name for the build-time base gate.
const modeBase = "base"

// The upstream half's effect seam: the registry read of an index's
// per-platform provenance. Everything below it is table-tested; the
// read itself is proven in internal/oci against an in-process registry.
//
//nolint:gochecknoglobals // test seam, written only by test setup
var newStatementReader = func() oci.StatementReader { return oci.Client{} }

// baseRefs is the repeatable --ref: the references a build names, in
// the order it names them.
type baseRefs []string

// String implements flag.Value.
func (r *baseRefs) String() string { return strings.Join(*r, ",") }

// Set implements flag.Value. An empty reference is refused rather than
// dropped: a caller whose list rendered a blank has a declaration with
// a hole in it, and dropping the hole would judge one base fewer than
// the build uses while looking whole.
func (r *baseRefs) Set(v string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New("an empty --ref is refused rather than dropped — a list with a hole in it is not one")
	}

	*r = append(*r, v)

	return nil
}

// baseBinds is the repeatable --bind: the caller's own reading of one
// tag group of the upstream reference, cross-checked against what the
// entry's tag pattern reads.
type baseBinds map[string]string

// String implements flag.Value — the groups bound so far.
func (b *baseBinds) String() string { return strings.Join(slices.Sorted(maps.Keys(*b)), ",") }

// Set implements flag.Value.
func (b *baseBinds) Set(v string) error {
	group, value, ok := strings.Cut(v, "=")
	if !ok || group == "" || value == "" {
		return fmt.Errorf("--bind %q is not <group>=<value>", v)
	}

	if *b == nil {
		*b = baseBinds{}
	}

	if _, dup := (*b)[group]; dup {
		return fmt.Errorf("--bind names group %q twice — one group, one value", group)
	}

	(*b)[group] = value

	return nil
}

// baseClaim is one reference and the declaration that claims it:
// exactly one of scope and upstream is set.
type baseClaim struct {
	ref      string
	scope    *assert.BaseImageScope
	upstream *assert.UpstreamBase
}

func (c *baseClaim) assertion() string {
	if c.scope != nil {
		return c.scope.Assertion()
	}

	return c.upstream.Assertion()
}

// planBases partitions the references a build names: each distinct
// one claimed by the one declaration covering it, or by none. A build
// naming one base in two stages instantiates it once, so it is judged
// once.
//
//nolint:gocritic // unnamedResult: claimed, then outside — the doc names both
func planBases(b *assert.BaseImagesPolicy, refs []string) ([]baseClaim, []string) {
	var (
		claims  []baseClaim
		outside []string
	)

	seen := map[string]bool{}

	for _, ref := range refs {
		if seen[ref] {
			continue
		}

		seen[ref] = true

		if s := b.Claimant(ref); s != nil {
			claims = append(claims, baseClaim{ref: ref, scope: s})
		} else if u := b.UpstreamFor(ref); u != nil {
			claims = append(claims, baseClaim{ref: ref, upstream: u})
		} else {
			outside = append(outside, ref)
		}
	}

	return claims, outside
}

// checkUpstreamFlags refuses --bind and --facts-out unless exactly one
// reference is under an upstream entry. Both describe ONE official
// image — the caller's row key for it, the facts its approval signs —
// so neither is applied across several, nor to none.
func checkUpstreamFlags(claims []baseClaim, binds baseBinds, factsOut string) error {
	if len(binds) == 0 && factsOut == "" {
		return nil
	}

	var upstream []*baseClaim

	for i := range claims {
		if claims[i].upstream != nil {
			upstream = append(upstream, &claims[i])
		}
	}

	if len(upstream) != 1 {
		return fmt.Errorf("--bind and --facts-out describe one upstream image, and %d of the references are"+
			" under an upstream entry", len(upstream))
	}

	if err := upstream[0].upstream.CheckBinds(binds); err != nil {
		return fmt.Errorf("%s: %w", upstream[0].ref, err)
	}

	return nil
}

// nothingToJudge is the plain line a run with no claimed reference
// ends on, saying why: no reference at all (a FROM-scratch build, or
// one of stages only), or none of the distinct references named any
// declaration claims.
func nothingToJudge(refs int) string {
	if refs == 0 {
		return "no base to judge — the build names no base reference (scratch, or stages only)"
	}

	return "no base to judge — none of the " + strconv.Itoa(refs) +
		" reference(s) is under a declared scope or upstream entry"
}

// baseRun is what one judging run holds: the claims, the journal they
// are recorded in, and what the judgments produced.
type baseRun struct {
	claims   []baseClaim
	binds    baseBinds
	att      assert.Attestor
	reader   oci.StatementReader
	out      *latch
	journal  *report.Journal
	judged   int
	facts    []report.Fact
	upstream baseimage.UpstreamFacts
}

// judge runs every claim in order, recording what is wrong with each
// base in the journal. A read the run could not make ends the run: the
// references after it are unjudged, and the population says so.
func (r *baseRun) judge() {
	for i := range r.claims {
		c := &r.claims[i]
		check := r.journal.Check(c.ref, c.assertion())

		if c.scope != nil {
			approval, err := c.scope.JudgeBase(c.ref, r.att, check.Diverged)
			if err != nil {
				r.out.logf("verify base: %v", err)

				return
			}

			if approval.Approved() {
				r.out.logf("verify base: approved first-party base: %s (%s)", c.ref, approval)
				r.facts = append(r.facts, report.Fact{Name: approval.Fact + ":" + c.ref, Value: approval.Value})
			}
		} else {
			facts, err := c.upstream.JudgeUpstream(c.ref, r.binds, r.reader, check.Diverged)
			if err != nil {
				r.out.logf("verify base: %v", err)

				return
			}

			if len(facts.Platforms) > 0 {
				r.out.logf("verify base: %s: upstream provenance verified across %d platform(s)",
					c.ref, len(facts.Platforms))
				r.facts = append(r.facts, report.Fact{Name: "upstream:" + c.ref, Value: strings.Join(facts.Sources, " ")})
				r.upstream = facts
			}
		}

		r.judged++
	}
}

// verifyBase runs the build-time base gate.
func verifyBase(args []string, stdout, stderr io.Writer) int {
	var (
		policyPath, factsOut string
		refs                 baseRefs
		binds                baseBinds
		jsonOut              bool
		root                 rootFlags
	)

	fs := flag.NewFlagSet("stele verify base", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&policyPath, "assert-policy", "",
		"the assert policy whose evidence.baseImages declares the first-party scopes and upstream entries a"+
			" reference is judged under (required)")
	fs.Var(&refs, "ref",
		"one base reference the build instantiates, as its build file pins it (image:tag@sha256:…); repeatable."+
			" Each is judged under the one declaration that claims it, and one nothing claims is named as not"+
			" judged. None at all (a FROM-scratch build) judges nothing and exits 0")
	fs.Var(&binds, "bind",
		"<group>=<value>: the caller's own reading of one tag group of the upstream reference, held to what"+
			" its entry's tag pattern reads; repeatable. Needs exactly one reference under an upstream entry")
	fs.StringVar(&factsOut, "facts-out", "",
		"write the verified facts (sources, platforms, provenanceType) of the one reference under an upstream"+
			" entry to this path, and only on PASS — the facts an approval of it signs")
	fs.BoolVar(&jsonOut, "json", false,
		"emit the verdict as one JSON report document on stdout (progress moves to stderr); a run with nothing"+
			" to judge seals no verdict and writes no document")
	root.register(fs)

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	fail := func(msg string) int {
		if _, err := fmt.Fprintf(stderr, "stele verify base: %s\n", msg); err != nil {
			return exitIO
		}

		return exitUsage
	}

	switch {
	case fs.NArg() > 0:
		return fail(fmt.Sprintf("unexpected argument %q — every reference is passed as --ref", fs.Arg(0)))
	case policyPath == "":
		return fail("--assert-policy is required")
	}

	pol, err := loadBasePolicy(policyPath)
	if err != nil {
		return fail(err.Error())
	}

	claims, outside := planBases(pol.Evidence.BaseImages, refs)

	if err := checkUpstreamFlags(claims, binds, factsOut); err != nil {
		return fail(err.Error())
	}

	out := &latch{w: stdout}
	if jsonOut {
		out = &latch{w: stderr}
	}

	for _, ref := range outside {
		out.logf("verify base: not judged: %s — no declared scope's prefix or upstream entry claims it", ref)
	}

	// Nothing claimed is nothing judged: the run seals no verdict at
	// all, because PASS over no subject is a pass nothing earned, and
	// CANNOT_JUDGE would contradict the exit a build with no base to
	// judge is owed. The reason is said instead.
	if len(claims) == 0 {
		out.logf("verify base: %s", nothingToJudge(len(outside)))

		if out.err != nil {
			return exitIO
		}

		return exitOK
	}

	run := &baseRun{
		claims: claims, binds: binds, reader: newStatementReader(), out: out, journal: report.NewJournal(),
	}

	if slices.ContainsFunc(claims, func(c baseClaim) bool { return c.scope != nil }) {
		att, aerr := baseAttestor(&root, *pol.Issuer)
		if aerr != nil {
			return fail(aerr.Error())
		}

		run.att = att
	}

	run.judge()

	if out.err != nil {
		return exitIO
	}

	rep := report.Seal("verify base", "base images", report.PopulationAgainstDeclared(run.judged, len(claims),
		"base references under a declared scope or upstream entry"), run.journal, report.NoCanary(),
		report.NoJudgedSet(), run.facts...)

	code := emitReport(rep, jsonOut, stdout, stderr)
	if code != exitOK || factsOut == "" {
		return code
	}

	if err := writeUpstreamFacts(factsOut, &run.upstream); err != nil {
		if _, werr := fmt.Fprintf(stderr, "stele verify base: %v\n", err); werr != nil {
			return exitIO
		}

		return exitIO
	}

	return exitOK
}

// loadBasePolicy reads the assert policy and refuses one with no
// evidence.baseImages section: a gate with nothing to judge against
// would name every reference not judged and pass, and the likelier
// cause is the wrong policy file.
func loadBasePolicy(path string) (*assert.Policy, error) {
	pf, err := os.Open(path) //nolint:gosec // the policy path is operator-supplied by design
	if err != nil {
		return nil, err //nolint:wrapcheck // the path is in the message; a prefix would say it twice
	}
	defer pf.Close() //nolint:errcheck // read-only close

	pol, err := assert.LoadPolicy(pf)
	if err != nil {
		return nil, err
	}

	if pol.Evidence.BaseImages == nil {
		return nil, fmt.Errorf("%s declares no evidence.baseImages section — there is nothing to judge a base"+
			" against", path)
	}

	return pol, nil
}

// baseAttestor builds the store attestor a first-party judgment proves
// through: the trust boundary over the resolved root, and the forge.
//
//nolint:ireturn // the judgment's own parameter type — the seam is the point
func baseAttestor(root *rootFlags, issuer string) (assert.Attestor, error) {
	rootJSON, err := root.resolve()
	if err != nil {
		return nil, err
	}

	bv, err := newBundleVerifier(rootJSON)
	if err != nil {
		return nil, err
	}

	return newAttestor(newForge(), bv, issuer), nil
}

// writeUpstreamFacts writes the verified upstream facts, the document
// an approval of the image signs.
func writeUpstreamFacts(path string, facts *baseimage.UpstreamFacts) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, ownerRW) //nolint:gosec // operator-supplied
	if err != nil {
		return fmt.Errorf("--facts-out: %w", err)
	}

	if err := jsonx.Encode(f, facts); err != nil {
		_ = f.Close() //nolint:errcheck // the encode failure is the one reported

		return fmt.Errorf("--facts-out: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("--facts-out: %w", err)
	}

	return nil
}
