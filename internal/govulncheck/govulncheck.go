// Package govulncheck reads what govulncheck's JSON mode emits: a
// concatenated stream of messages, one per event, of which this
// package reads two kinds — the config that says a scan happened, and
// the findings it made.
//
// Reading only, never running. The scan is the caller's to perform
// (it needs the network and a Go toolchain, which is why the org runs
// it from a task and pipes the stream in); this package's job is to
// say what the stream contains, so the judgment above it never parses
// somebody else's format twice.
//
// The ranking is govulncheck's own vocabulary, kept rather than
// renamed so a reader can put this beside the text report and see the
// same population.
package govulncheck

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// PurlType is the purl type naming the ecosystem this scanner reports
// on. govulncheck scans Go modules and nothing else, so a finding it
// makes is a golang finding by construction — there is no ecosystem
// field in the stream to read, and this constant is the honest
// replacement for one.
const PurlType = "golang"

// Level is how far into the code a finding reached — govulncheck's
// own ranking, weakest first.
type Level string

// The three levels. Only Called means a vulnerable symbol is
// reachable from this module's code; the other two are the graph
// around it, which is population, not a gate.
const (
	// LevelRequired is a vulnerable module in the graph with no
	// package of it imported.
	LevelRequired Level = "required"
	// LevelImported is a vulnerable package imported, with no
	// vulnerable symbol called.
	LevelImported Level = "imported"
	// LevelCalled is a vulnerable symbol reachable from this module's
	// own code.
	LevelCalled Level = "called"
)

// The merge order, weakest first. A level this package does not know
// ranks below every level it does, so an unrecognised frame can never
// promote a finding past a reach the scanner actually reported.
const (
	rankUnknown = iota
	rankRequired
	rankImported
	rankCalled
)

// rank orders the levels for the highest-reached merge.
func (l Level) rank() int {
	switch l {
	case LevelCalled:
		return rankCalled
	case LevelImported:
		return rankImported
	case LevelRequired:
		return rankRequired
	default:
		return rankUnknown
	}
}

// Finding is one advisory against one module version, at the deepest
// level the scan reached for it.
type Finding struct {
	Advisory string
	Module   string
	Version  string
	Level    Level
}

// String names the finding the way a report names it.
func (f Finding) String() string {
	return f.Advisory + ":" + f.Module + "@" + f.Version
}

// Called reports whether a vulnerable symbol is reachable — the only
// level that gates.
func (f Finding) Called() bool { return f.Level == LevelCalled }

// Scan is one govulncheck run: what did the scanning, and what it
// found.
type Scan struct {
	Scanner   string
	Version   string
	DB        string
	DBTime    string
	ScanLevel string
	Findings  []Finding
}

// ErrNoConfig reports a stream carrying no config message.
//
// It is its own error because the failure it names is the dangerous
// one: a truncated stream, an empty file, or the output of something
// that is not govulncheck all yield zero findings, and zero findings
// renders as "nothing reachable, clean". A scan that did not happen
// must never be read as a scan that found nothing.
var ErrNoConfig = errors.New("govulncheck: the stream carries no config message — the scan did not run")

// message is one event in the stream. Foreign: govulncheck owns this
// schema and extends it (v1.7.0 emits SBOM and progress messages this
// package has no use for), so unknown fields are tolerated and
// unrecognised message kinds decode to a struct of nils.
//
// Pointers throughout: a message is identified BY WHICH FIELD IS
// PRESENT, so absent and zero must stay distinguishable — the one
// property a plain-struct decode would destroy.
type message struct {
	Config  *config  `json:"config"`
	Finding *finding `json:"finding"`
}

type config struct {
	ScannerName    *string `json:"scanner_name"`
	ScannerVersion *string `json:"scanner_version"`
	DB             *string `json:"db"`
	DBLastModified *string `json:"db_last_modified"`
	ScanLevel      *string `json:"scan_level"`
}

type finding struct {
	OSV   *string `json:"osv"`
	Trace []struct {
		Module   *string `json:"module"`
		Version  *string `json:"version"`
		Package  *string `json:"package"`
		Function *string `json:"function"`
	} `json:"trace"`
}

// key identifies one finding for the highest-level merge.
type key struct {
	advisory string
	module   string
	version  string
}

// Read decodes one govulncheck JSON stream.
//
// Findings are merged to one record per (advisory, module, version)
// at the highest level reached, because govulncheck reports a finding
// once per trace and a module can be reached several ways; the
// strongest reach is the fact that matters, and it is what
// govulncheck's own text renderer shows.
func Read(r io.Reader) (*Scan, error) {
	msgs, err := jsonx.DecodeForeignStream[message](r)
	if err != nil {
		return nil, fmt.Errorf("govulncheck: %w", err)
	}

	scan := &Scan{}
	found := map[key]Finding{}

	seen := false

	for i := range msgs {
		if c := msgs[i].Config; c != nil {
			seen = true
			scan.Scanner = deref(c.ScannerName)
			scan.Version = deref(c.ScannerVersion)
			scan.DB = deref(c.DB)
			scan.DBTime = deref(c.DBLastModified)
			scan.ScanLevel = deref(c.ScanLevel)
		}

		if f := msgs[i].Finding; f != nil {
			merge(found, f)
		}
	}

	if !seen {
		return nil, ErrNoConfig
	}

	scan.Findings = sorted(found)

	return scan, nil
}

// merge folds one finding message into the record for its triple.
func merge(found map[key]Finding, f *finding) {
	// trace[0] is the vulnerable frame; the rest is the path that
	// reached it. A finding with no trace names no module, so there is
	// nothing to key on and nothing to report.
	if len(f.Trace) == 0 {
		return
	}

	frame := f.Trace[0]

	k := key{advisory: deref(f.OSV), module: deref(frame.Module), version: deref(frame.Version)}
	if k.advisory == "" || k.module == "" {
		return
	}

	level := LevelRequired

	switch {
	case deref(frame.Function) != "":
		level = LevelCalled
	case deref(frame.Package) != "":
		level = LevelImported
	}

	if prior, ok := found[k]; ok && prior.Level.rank() >= level.rank() {
		return
	}

	found[k] = Finding{Advisory: k.advisory, Module: k.module, Version: k.version, Level: level}
}

// sorted renders the found set in one order, so two reads of one
// stream produce the same list.
func sorted(found map[key]Finding) []Finding {
	out := make([]Finding, 0, len(found))
	for k := range found {
		out = append(out, found[k])
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
