// The signer-certificate watch (stele#387): every certificate a
// certificate transparency log holds for a declared signing workflow
// must reconcile against a signing the declared population performed.
// A forged issuance looks exactly like a real one in the log, so a
// match alone tells nobody anything; each is reconciled against the
// forge, and only the run id and the Build Signer Digest are taken
// from the certificate.
//
// The walk is the reader half the canon's patched upstream monitor
// could not be (.github#1237, .github#1339): it reads the log in
// chunks, and a chunk is done only when every entry in it has been
// scanned and every match in it reconciled. After each done chunk the
// checkpoint is rewritten, so memory is bounded by one chunk and never
// by the range, and a run that ends partway keeps what it judged. A
// backlog is a normal state — it costs runs, never memory, and the
// rest of the range is reported outstanding, never as a failure of
// what was read.

package assert

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/monumental-archive/stele/internal/ctlog"
	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/population"
	"github.com/monumental-archive/stele/internal/report"
)

// SignerChunk is the most entries one chunk holds (stele#387): the
// unit of work the checkpoint advances by, and the bound on what a run
// has read but not yet judged. At the log's measured thousand-entry
// pages it is ten requests.
const SignerChunk = 10_000

// SignerWatch is one run of the watch: what it reads, and where its
// progress goes.
type SignerWatch struct {
	Policy *Policy
	// Population is the declared population; a certificate's run must
	// be in one of its repositories.
	Population *population.Set
	// Server is the forge's web origin (https://github.com): the
	// prefix of every subject and run URI a certificate carries. A
	// fact about the forge the run reads, never about an organisation.
	Server string
	// Log reads the policy's log, bounded by the run's budget.
	Log *ctlog.Client
	// Verifier holds the trusted root's keys for that log.
	Verifier *ctlog.Verifier
	// Forge answers the reconciliation's reads.
	Forge SignerForge
	// Checkpoint is the checkpoint the run resumes from, already known
	// to be the policy's log's; nil founds a new one at StartAt, which
	// only a person decides to do.
	Checkpoint *ctlog.Checkpoint
	StartAt    uint64
	// Save writes the checkpoint whole, atomically.
	Save func(cp *ctlog.Checkpoint) error
	// Chunk overrides SignerChunk; zero means SignerChunk.
	Chunk uint64
	// Progress receives the run's human log.
	Progress Logf
}

// stopped is why a run ended before the head: the read or the forge
// read that could not complete, or the budget.
type stopped struct {
	at  uint64
	err error
}

// SignerCertificates runs the watch and seals its verdict. An error is
// a refusal before anything was judged — the log's head could not be
// read or verified, or does not extend the checkpoint's — and leaves
// the checkpoint exactly as it was found. Everything after that is a
// report: a stop partway seals CANNOT_JUDGE over what was judged,
// naming the outstanding range.
func SignerCertificates(ctx context.Context, w *SignerWatch, j *report.Journal) (*report.Report, error) {
	sp := w.Policy.SignerCertificates
	if sp == nil {
		return nil, errors.New("assert: the policy declares no signerCertificates section")
	}

	names, err := SignerCertificatesSubjects.Enumerate(w.Population)
	if err != nil {
		return nil, err
	}

	rec := newReconciler(w, names)

	head, cp, err := w.verifiedStart(ctx)
	if err != nil {
		return nil, err
	}

	from := cp.Next
	w.Progress("assert: signer-certificates: %s at size %d (%s); judging %s",
		*sp.Log, head.TreeSize, head.Time().Format(timeLayout), span(from, head.TreeSize))

	stop := w.judge(ctx, cp, rec, j)

	facts := []report.Fact{
		{Name: "log", Value: *sp.Log},
		{Name: "treeHead", Value: fmt.Sprintf("%d at %s", head.TreeSize, cp.HeadTime())},
		{Name: "judged", Value: span(from, cp.Next)},
		{Name: "outstanding", Value: span(cp.Next, head.TreeSize)},
		{Name: "checkpointNext", Value: strconv.FormatUint(cp.Next, 10)},
	}

	if stop != nil {
		facts = append(facts, report.Fact{Name: "stopped", Value: stopReason(stop.err) + ": " + stop.err.Error()})
		w.Progress("assert: signer-certificates: stopped at %d: %v", stop.at, stop.err)
		w.Progress("assert: signer-certificates: outstanding %s; everything before %d is judged",
			span(cp.Next, head.TreeSize), cp.Next)
	}

	stats := w.Log.Stats()
	facts = append(facts,
		report.Fact{Name: "entriesRead", Value: strconv.Itoa(stats.Entries)},
		report.Fact{Name: "requests", Value: strconv.Itoa(stats.Requests)},
		report.Fact{Name: "throttled", Value: strconv.Itoa(stats.Throttled)},
		report.Fact{Name: "unavailable", Value: strconv.Itoa(stats.Unavailable)},
		report.Fact{Name: "matches", Value: strconv.Itoa(rec.matches)},
		report.Fact{Name: "reconciled", Value: strconv.Itoa(rec.reconciled)},
	)

	// The range is the population: the entries between the checkpoint
	// this run started from and the head it verified. The log declared
	// that range in a signed statement, and a run that judged less of
	// it than it declared cannot pass.
	pop := report.PopulationAgainstDeclared(intSize(cp.Next-from), intSize(head.TreeSize-from),
		"log entries judged, of the range between the checkpoint and the verified tree head")

	return report.Seal("assert signer-certificates", *sp.Log, pop, j,
		report.NoCanary(), report.NoJudgedSet(), facts...), nil
}

// timeLayout is how a tree head's moment is printed.
const timeLayout = "2006-01-02T15:04:05Z07:00"

// verifiedStart reads the log's head, verifies it, proves it extends
// the checkpoint — or founds the checkpoint a person asked for — and
// writes the result before any entry is read: the next run proves
// consistency from the newest head this one verified, whatever happens
// to the chunks.
func (w *SignerWatch) verifiedStart(ctx context.Context) (*ctlog.TreeHead, *ctlog.Checkpoint, error) {
	log := *w.Policy.SignerCertificates.Log

	head, err := w.Log.TreeHead(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("assert: signer-certificates: %w", err)
	}

	if err := w.Verifier.VerifyTreeHead(head); err != nil {
		return nil, nil, fmt.Errorf("assert: signer-certificates: %w", err)
	}

	var cp *ctlog.Checkpoint

	switch w.Checkpoint {
	case nil:
		if w.StartAt > head.TreeSize {
			return nil, nil, fmt.Errorf(
				"assert: signer-certificates: --start-at %d is beyond the log's tree size %d", w.StartAt, head.TreeSize,
			)
		}

		cp = &ctlog.Checkpoint{Log: log, TreeHead: *head, Next: w.StartAt}
	default:
		if err := ctlog.VerifyConsistency(ctx, &w.Checkpoint.TreeHead, head, w.Log); err != nil {
			return nil, nil, fmt.Errorf("assert: signer-certificates: %w", err)
		}

		cp = &ctlog.Checkpoint{Log: log, TreeHead: *head, Next: w.Checkpoint.Next}
	}

	if err := w.Save(cp); err != nil {
		return nil, nil, fmt.Errorf("assert: signer-certificates: %w", err)
	}

	return head, cp, nil
}

// judge works through the range a chunk at a time, advancing cp after
// each done chunk, and returns why it stopped short — nil when it
// reached the head.
func (w *SignerWatch) judge(ctx context.Context, cp *ctlog.Checkpoint, rec *reconciler, j *report.Journal) *stopped {
	size := cp.TreeHead.TreeSize

	chunk := w.Chunk
	if chunk == 0 {
		chunk = SignerChunk
	}

	for cp.Next < size {
		start := cp.Next
		end := min(start+chunk, size)

		verdicts, err := w.chunk(ctx, rec, start, end)
		if err != nil {
			return &stopped{at: start, err: err}
		}

		next := *cp
		next.Next = end

		if err := w.Save(&next); err != nil {
			return &stopped{at: start, err: fmt.Errorf("writing the checkpoint: %w", err)}
		}

		cp.Next = end

		// Recorded only once the checkpoint has moved past them: a
		// chunk that is not done is judged again by the next run, and
		// its findings with it.
		for _, v := range verdicts {
			v.record(j, *w.Policy.SignerCertificates.Log)
		}
	}

	return nil
}

// chunk scans [start, end) page by page and reconciles every match in
// it. An error means the chunk is not done: nothing in it is judged.
func (w *SignerWatch) chunk(ctx context.Context, rec *reconciler, start, end uint64) ([]*signerVerdict, error) {
	var found []*signerMatch

	// One request per page, advancing by what each answer carried and
	// never by what was asked: measured against ctfe.sigstore.dev on
	// 2026-11-17, an answer holds at most 1,000 entries and ends at the
	// next multiple of 1,000 (from 447,842,897 it returned 103; from
	// 447,843,000, 1,000; from 447,843,500, 500), at about 5 MB and 2.5
	// to 5.5 s a page. A chunk of 10,000 is about ten requests.
	for pos := start; pos < end; {
		page, err := w.Log.Entries(ctx, pos, end-1)
		if err != nil {
			return nil, err
		}

		for i := range page {
			if m := rec.match(&page[i]); m != nil {
				found = append(found, m)
			}
		}

		pos += uint64(len(page))
	}

	// The budget bounds the forge's reads too: a chunk scanned at the
	// deadline is left for the next run rather than reconciled past it.
	if now := w.Log.Clock.Now(); !now.Before(w.Log.Deadline) && len(found) > 0 {
		return nil, fmt.Errorf("%w before the chunk's %d match(es) were reconciled", ctlog.ErrBudget, len(found))
	}

	verdicts := make([]*signerVerdict, 0, len(found))

	for _, m := range found {
		v, err := rec.reconcile(m)
		if err != nil {
			return nil, fmt.Errorf("reconciling CT index %d: %w", m.index, err)
		}

		w.Progress("assert: signer-certificates: %s", v.line())
		verdicts = append(verdicts, v)
	}

	return verdicts, nil
}

// span renders a half-open index range the way a person reads one.
func span(from, to uint64) string {
	if from >= to {
		return "none"
	}

	return fmt.Sprintf("%d..%d", from, to-1)
}

// intSize converts an entry count to the report's int. A log beyond
// the int range is not one this reader can be judging.
func intSize(n uint64) int {
	const maxInt = int(^uint(0) >> 1)

	if n > uint64(maxInt) {
		return maxInt
	}

	return int(n)
}

// stopReason names what ended a run short of the head: the budget, a
// throttle that outlasted nothing (a forge read's ladder gave up), or
// anything else that left a chunk not done. None is a judgment.
func stopReason(err error) string {
	switch {
	case errors.Is(err, ctlog.ErrBudget):
		return "budget"
	case errors.Is(err, gh.ErrThrottled):
		return "throttled"
	default:
		return "incomplete"
	}
}
