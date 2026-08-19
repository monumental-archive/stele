// Package vexjoin owns the triage join: an advisory finding is
// decided iff a VEX statement exists for its exact (advisory,
// package, version) triple — keyed by the dependency, never by
// release tag, so coverage is derived rather than stored, and a
// release that bumps a decided package's version matches no decision
// and surfaces for a fresh judgment. The empty-set semantics are
// explicit and tested by name: an empty VEX directory means NOTHING
// decided, never everything — the grep -f landmine this package
// exists to make unrepresentable. Shared by `assert blast-radius`
// and the derive verb's VEX leg (#40).
package vexjoin

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// Key is the exact triple a decision matches on.
type Key struct {
	Advisory string
	Package  string
	Version  string
}

// Decision is one parsed VEX decision: the triple it matches, the
// origin so a report can point at the reviewed statement, and the
// judgment itself so a DERIVED document can carry the human's words
// rather than paraphrase them.
//
// Decided is the moment the judgment was made. It travels with the
// decision because a derived statement inherits the judgment, not the
// derivation: dating an inherited statement by the run that copied it
// asserts a judgment nobody made then, and makes the derived document
// unreproducible.
type Decision struct {
	Key    Key
	Origin string
	// Purl is the product identifier the decision was recorded
	// against, carried verbatim so a derived statement names the
	// subcomponent the human named rather than one reassembled from
	// the parsed name and version.
	Purl string

	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
	Decided         time.Time
}

// Decisions is the decided set. The zero value decides nothing.
type Decisions struct {
	byKey map[Key]Decision
}

// Has reports whether the exact triple is decided.
func (d *Decisions) Has(k Key) bool {
	if d == nil || d.byKey == nil {
		return false
	}

	_, ok := d.byKey[k]

	return ok
}

// Get returns the decision covering one key, and whether one does.
// The pair is the whole point: a lookup that answered a miss with a
// zero Decision would hand the caller a fabricated judgment — a
// decision nobody made, carrying no status and no moment.
func (d *Decisions) Get(k Key) (Decision, bool) {
	dec, ok := d.byKey[k]

	return dec, ok
}

// All returns every decision, for stale-decision derivation.
func (d *Decisions) All() []Decision {
	if d == nil {
		return nil
	}

	out := make([]Decision, 0, len(d.byKey))
	for k := range d.byKey {
		out = append(out, d.byKey[k])
	}

	return out
}

// Len reports how many decisions are held.
func (d *Decisions) Len() int {
	if d == nil {
		return 0
	}

	return len(d.byKey)
}

// purlRE captures name@version from a product purl, in the dialect
// the scanner reports — no epoch, no encoding.
var purlRE = regexp.MustCompile(`^pkg:.*/([^/@]+)@(.+)$`)

// openVEX is the OpenVEX shape this parse reads — a foreign format
// with a spec, decoded leniently, but statements missing what the
// join needs are an error, never a silent skip: a decision that
// parses as nothing decides nothing silently.
type openVEX struct {
	Timestamp  *string `json:"timestamp"`
	Statements []struct {
		Vulnerability *struct {
			Name *string `json:"name"`
		} `json:"vulnerability"`
		Products []struct {
			ID *string `json:"@id"`
		} `json:"products"`
		Status          *string `json:"status"`
		Justification   *string `json:"justification"`
		ImpactStatement *string `json:"impact_statement"`
		ActionStatement *string `json:"action_statement"`
		Timestamp       *string `json:"timestamp"`
	} `json:"statements"`
}

// Parse reads one OpenVEX document's decisions into the set. origin
// names the file for the report.
func Parse(d *Decisions, doc []byte, origin string) error {
	decoded, err := jsonx.DecodeForeign[openVEX](doc)
	if err != nil {
		return fmt.Errorf("vexjoin: %s: %w", origin, err)
	}

	if d.byKey == nil {
		d.byKey = map[Key]Decision{}
	}

	for i, stmt := range decoded.Statements {
		if stmt.Vulnerability == nil || stmt.Vulnerability.Name == nil || *stmt.Vulnerability.Name == "" {
			return fmt.Errorf("vexjoin: %s: statement %d names no vulnerability", origin, i)
		}

		if stmt.Status == nil || *stmt.Status == "" {
			return fmt.Errorf("vexjoin: %s: statement %d carries no status — a decision that decides"+
				" nothing is not a decision", origin, i)
		}

		// A statement dates itself where the format allows it, and
		// falls back to its document. Absent from both is refused: a
		// judgment with no moment cannot be carried into a derived
		// document honestly, and substituting a clock would invent one.
		decided, derr := statementTime(stmt.Timestamp, decoded.Timestamp)
		if derr != nil {
			return fmt.Errorf("vexjoin: %s: statement %d: %w", origin, i, derr)
		}

		for _, p := range stmt.Products {
			if p.ID == nil {
				continue
			}

			m := purlRE.FindStringSubmatch(*p.ID)
			if m == nil {
				continue // a product that is not a versioned purl cannot join
			}

			k := Key{Advisory: *stmt.Vulnerability.Name, Package: m[1], Version: m[2]}

			// Two decisions for one triple is a contradiction to
			// surface, never a race the parse order settles: the files
			// arrive in directory order, so "last one wins" would let
			// a filename decide which judgment enters signed evidence.
			// The human retires one; this code picks neither.
			if prior, dup := d.byKey[k]; dup {
				return fmt.Errorf("vexjoin: %s and %s both decide %s on %s@%s — one finding, one decision;"+
					" retire one", prior.Origin, origin, k.Advisory, k.Package, k.Version)
			}

			d.byKey[k] = Decision{
				Key: k, Origin: origin, Purl: *p.ID,
				Status:          *stmt.Status,
				Justification:   deref(stmt.Justification),
				ImpactStatement: deref(stmt.ImpactStatement),
				ActionStatement: deref(stmt.ActionStatement),
				Decided:         decided,
			}
		}
	}

	return nil
}

// statementTime reads a judgment's moment, preferring the statement's
// own over its document's.
func statementTime(statement, document *string) (time.Time, error) {
	for _, candidate := range []*string{statement, document} {
		if candidate == nil || *candidate == "" {
			continue
		}

		at, err := time.Parse(time.RFC3339, *candidate)
		if err != nil {
			return time.Time{}, fmt.Errorf("timestamp %q is not RFC 3339: %w", *candidate, err)
		}

		return at, nil
	}

	return time.Time{}, errors.New("no timestamp on the statement or its document")
}

func deref(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}
