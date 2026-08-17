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
	"fmt"
	"regexp"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// Key is the exact triple a decision matches on.
type Key struct {
	Advisory string
	Package  string
	Version  string
}

// Decision is one parsed VEX decision with its origin, so a report
// can point at the reviewed statement.
type Decision struct {
	Key    Key
	Origin string
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

// All returns every decision, for stale-decision derivation.
func (d *Decisions) All() []Decision {
	if d == nil {
		return nil
	}

	out := make([]Decision, 0, len(d.byKey))
	for _, dec := range d.byKey {
		out = append(out, dec)
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
	Statements []struct {
		Vulnerability *struct {
			Name *string `json:"name"`
		} `json:"vulnerability"`
		Products []struct {
			ID *string `json:"@id"`
		} `json:"products"`
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

		for _, p := range stmt.Products {
			if p.ID == nil {
				continue
			}

			m := purlRE.FindStringSubmatch(*p.ID)
			if m == nil {
				continue // a product that is not a versioned purl cannot join
			}

			k := Key{Advisory: *stmt.Vulnerability.Name, Package: m[1], Version: m[2]}
			d.byKey[k] = Decision{Key: k, Origin: origin}
		}
	}

	return nil
}
