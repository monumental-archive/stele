// The judgment journal (#147): what a run DID, not only what it
// found. A report handed findings alone cannot tell "no finding
// because clean" from "no finding because nobody looked" — the same
// blindness the population law fixed at the subject level, one level
// down. It surfaced as a lie about exceptions: an excuse the run
// never exercised was reported stale, which is a retirement claim
// made without evidence.
//
// So every check is recorded through the door a divergence must pass
// through anyway. Taking the handle IS the record, and the handle is
// taken before the outcome is known — so a check that turns out clean
// records itself, and a divergence without a recorded check is
// unrepresentable. A walk that forgets a check leaves an excuse
// unexercised (visible, carried) rather than falsely retired: the
// failure direction is the conservative one.

package report

// Finding is one observed divergence — a fact, carrying no verdict of
// its own; Seal decides what the set of facts amounts to. Fields are
// exported because a finding hides nothing: Subject names what
// diverged, Assertion which check saw it, Expected/Actual the two
// sides where a comparison has two sides, Detail the prose.
//
// Constructed only through a Check: the journal's door is the only
// way one reaches a report.
type Finding struct {
	Subject   string `json:"subject"`
	Assertion string `json:"assertion"`
	Expected  string `json:"expected,omitempty"`
	Actual    string `json:"actual,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Journal is one run's record of what it judged and what may excuse
// it. Walks RECEIVE one rather than building one: the layer that
// reads the committed exceptions file opens it, so a walk cannot emit
// findings past the excuses that answer them — which is the defect
// #147 found, where one walk read the debt file and the others could
// not.
type Journal struct {
	checks     map[string]map[string]bool
	swept      map[string]bool
	findings   []Finding
	exceptions []Exception
}

// NewJournal opens a journal carrying the exceptions declared before
// the walk began — the committed file's lines. A walk adds the ones
// it derives itself through Except, as it derives them.
func NewJournal(declared ...Exception) *Journal {
	return &Journal{
		checks:     map[string]map[string]bool{},
		swept:      map[string]bool{},
		exceptions: append([]Exception(nil), declared...),
	}
}

// Check records one performed check and returns the handle its
// divergence — if it has one — is reported through.
func (j *Journal) Check(subject, assertion string) Check {
	if j.checks[subject] == nil {
		j.checks[subject] = map[string]bool{}
	}

	j.checks[subject][assertion] = true

	return Check{j: j, subject: subject, assertion: assertion}
}

// Swept records that one subject was enumerated exhaustively: the run
// discovered what was there rather than asking a fixed set of
// questions, so every assertion it did NOT observe on that subject
// was observed to be absent. It is a claim of the same kind as the
// population's — use it only where the walk genuinely discovers (a
// scan), never to widen a walk that enumerates obligations.
func (j *Journal) Swept(subject string) { j.swept[subject] = true }

// Except adds an exception the run itself asserted — derived from
// evidence, or declared by a policy section the run read. Committed
// file lines arrive through NewJournal instead.
func (j *Journal) Except(e Exception) { j.exceptions = append(j.exceptions, e) }

// Findings returns the divergences recorded so far, copied — for a
// walk deriving an exception FROM its own findings (the burned-release
// derivation reads which verdicts a tag is missing).
func (j *Journal) Findings() []Finding {
	out := make([]Finding, len(j.findings))
	copy(out, j.findings)

	return out
}

// exercised reports whether this run was in a position to see the
// divergence the exception names — the question staleness rests on.
// An exception whose coordinate was never checked says nothing about
// this run and this run says nothing about it.
func (j *Journal) exercised(e *Exception) bool {
	switch {
	case e.subject == "":
		// Subject-agnostic (a triage decision keyed by advisory,
		// package and version, which excuses that finding wherever it
		// appears): the sweep is what puts the run in a position to
		// see it at all.
		return len(j.swept) > 0
	case j.swept[e.subject]:
		return true
	case e.assertion == "":
		return len(j.checks[e.subject]) > 0
	default:
		return j.checks[e.subject][e.assertion]
	}
}

// Check is the handle for one recorded check. The zero value panics
// rather than recording nothing: Journal.Check is the only door, and
// a divergence swallowed silently is the failure this whole layer
// exists to prevent.
type Check struct {
	j                  *Journal
	subject, assertion string
}

// Diverged records that this check found divergence.
func (c Check) Diverged(detail string) {
	c.record(&Finding{Subject: c.subject, Assertion: c.assertion, Detail: detail})
}

// DivergedFrom records a divergence with two sides — the comparison
// checks, where "expected X, actual Y" is the whole finding.
func (c Check) DivergedFrom(expected, actual, detail string) {
	c.record(&Finding{
		Subject: c.subject, Assertion: c.assertion,
		Expected: expected, Actual: actual, Detail: detail,
	})
}

func (c Check) record(f *Finding) {
	c.j.findings = append(c.j.findings, *f)
}
