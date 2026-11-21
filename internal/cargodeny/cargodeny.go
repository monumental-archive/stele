// Package cargodeny reads what `cargo deny --format json check
// advisories` emits: one JSON object per line, of which this package
// reads two kinds — the diagnostics the check raised, and the summary
// that says the check finished and how many errors it counted.
//
// Reading only, never running. The scan is the caller's to perform
// (it needs the network and a Rust toolchain), and cargo-deny writes
// this stream to stderr and exits 1 for a finding and for a failure
// alike — so the exit status says nothing a reader can use, and the
// stream is the whole of the evidence. This package's job is to say
// what the stream contains, so the judgment above it never parses
// somebody else's format twice.
//
// cargo-deny has no reachability ranking. A diagnostic's severity is
// the scanner's own answer to "does this gate", and the reader keeps
// it rather than inventing a level.
package cargodeny

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// PurlType is the purl type naming the ecosystem this scanner reports
// on. cargo-deny judges a Cargo lock and nothing else, so a finding it
// makes is a cargo finding by construction — there is no ecosystem
// field in the stream to read, and this constant is the honest
// replacement for one.
const PurlType = "cargo"

// Scanner names the tool, because the stream does not: no message
// cargo-deny writes carries its own name or version.
const Scanner = "cargo-deny"

// SeverityError is the one severity that gates. The others cargo-deny
// writes (warning, note, help) are counted, never judged.
const SeverityError = "error"

// Finding is one error diagnostic against one crate version.
//
// Advisory is empty for an error diagnostic that names no advisory —
// a yanked crate is the measured case — which no decision can excuse,
// because a decision is keyed by the advisory it decides.
type Finding struct {
	Advisory string
	Code     string
	Crate    string
	Version  string
}

// Purl is the package URL of the crate version the finding is about.
func (f Finding) Purl() string {
	return "pkg:" + PurlType + "/" + f.Crate + "@" + f.Version
}

// String names the finding in one stable order for sorting.
func (f Finding) String() string {
	return f.Advisory + ":" + f.Code + ":" + f.Crate + "@" + f.Version
}

// Severities is the count of diagnostics read, by severity.
type Severities map[string]int

// Scan is one cargo-deny advisories check: what it found that gates,
// and how many diagnostics of each severity it raised.
type Scan struct {
	Findings   []Finding
	Severities Severities
}

// The refusals. Each is a way a scan that did not finish, or did not
// say what it found, arrives looking like a scan that found nothing.
var (
	// ErrNoSummary reports a stream with no summary line carrying the
	// advisories counts. cargo-deny writes that line last, so its
	// absence is a check that stopped — or a stream that is not
	// cargo-deny's at all.
	ErrNoSummary = errors.New("cargo-deny: the stream carries no advisories summary — the check did not finish")

	// ErrTwoSummaries reports a stream with more than one advisories
	// summary: two runs concatenated, whose counts belong to neither.
	ErrTwoSummaries = errors.New("cargo-deny: the stream carries more than one advisories summary")

	// ErrCountMismatch reports a summary whose error count is not the
	// number of error diagnostics read: lines were lost or added
	// between the check and this reader.
	ErrCountMismatch = errors.New("cargo-deny: the summary's error count disagrees with the diagnostics read")

	// ErrNoSeverity reports a diagnostic carrying no severity, which
	// cannot be told apart from an error.
	ErrNoSeverity = errors.New("cargo-deny: a diagnostic carries no severity")

	// ErrUnkeyed reports an error diagnostic naming no crate version
	// to key on, an advisory with no id, or neither an advisory nor a
	// code: a gating finding with nothing to report it against.
	ErrUnkeyed = errors.New("cargo-deny: an error diagnostic names no crate version, advisory id or code")
)

// message is one line of the stream. Foreign: cargo-deny owns this
// schema and extends it, so unknown fields are tolerated and a line of
// a type this package does not read decodes and is skipped.
//
// Pointers throughout: absent and zero must stay distinguishable — a
// summary with no error count is not a summary counting none.
type message struct {
	Type   *string `json:"type"`
	Fields *fields `json:"fields"`
}

// fields carries both shapes this package reads: a diagnostic's
// (severity, code, advisory, graphs) and a summary's (advisories).
type fields struct {
	Severity   *string   `json:"severity"`
	Code       *string   `json:"code"`
	Advisory   *advisory `json:"advisory"`
	Graphs     []graph   `json:"graphs"`
	Advisories *counts   `json:"advisories"`
}

type advisory struct {
	ID *string `json:"id"`
}

// graph is one inclusion path; its Krate is the crate version the
// diagnostic is about, and its parents are the path that reached it.
type graph struct {
	Krate *struct {
		Name    *string `json:"name"`
		Version *string `json:"version"`
	} `json:"Krate"`
}

type counts struct {
	Errors *int `json:"errors"`
}

// Read decodes one cargo-deny JSON stream.
//
// An error diagnostic is a finding for each entry of its graphs, and
// findings are merged to one record per (advisory, code, crate,
// version) because one crate version can arrive by several graphs.
// The count the summary is checked against is diagnostics, not
// findings: that is what cargo-deny counts.
func Read(r io.Reader) (*Scan, error) {
	msgs, err := jsonx.DecodeForeignStream[message](r)
	if err != nil {
		return nil, fmt.Errorf("cargo-deny: %w", err)
	}

	scan := &Scan{Severities: Severities{}}
	found := map[Finding]bool{}

	var summary *int

	for i := range msgs {
		m := &msgs[i]
		if m.Type == nil || m.Fields == nil {
			continue
		}

		switch *m.Type {
		case "summary":
			if m.Fields.Advisories == nil || m.Fields.Advisories.Errors == nil {
				continue
			}

			if summary != nil {
				return nil, ErrTwoSummaries
			}

			summary = m.Fields.Advisories.Errors
		case "diagnostic":
			if err := diagnostic(scan, found, m.Fields); err != nil {
				return nil, err
			}
		}
	}

	if summary == nil {
		return nil, ErrNoSummary
	}

	if *summary != scan.Severities[SeverityError] {
		return nil, fmt.Errorf("%w: the summary counts %d, the stream carries %d",
			ErrCountMismatch, *summary, scan.Severities[SeverityError])
	}

	scan.Findings = sorted(found)

	return scan, nil
}

// diagnostic counts one diagnostic and, when it is an error, folds its
// findings into the found set.
func diagnostic(scan *Scan, found map[Finding]bool, f *fields) error {
	if f.Severity == nil {
		return ErrNoSeverity
	}

	scan.Severities[*f.Severity]++

	if *f.Severity != SeverityError {
		return nil
	}

	id := ""

	if f.Advisory != nil {
		if f.Advisory.ID == nil || *f.Advisory.ID == "" {
			return ErrUnkeyed
		}

		id = *f.Advisory.ID
	} else if deref(f.Code) == "" {
		// With no advisory, the code is the whole assertion.
		return ErrUnkeyed
	}

	// An error with no graph names no crate, and an error that names
	// nothing would gate nothing: refused, never dropped.
	if len(f.Graphs) == 0 {
		return ErrUnkeyed
	}

	for i := range f.Graphs {
		k := f.Graphs[i].Krate
		if k == nil || deref(k.Name) == "" || deref(k.Version) == "" {
			return ErrUnkeyed
		}

		found[Finding{Advisory: id, Code: deref(f.Code), Crate: *k.Name, Version: *k.Version}] = true
	}

	return nil
}

// sorted renders the found set in one order, so two reads of one
// stream produce the same list.
func sorted(found map[Finding]bool) []Finding {
	out := make([]Finding, 0, len(found))
	for f := range found {
		out = append(out, f)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })

	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}
