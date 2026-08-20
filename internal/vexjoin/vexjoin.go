// Package vexjoin owns the triage join: an advisory finding is
// decided iff a VEX statement exists for its exact (advisory,
// package, version) triple — keyed by the dependency, never by
// release tag, so coverage is derived rather than stored, and a
// release that bumps a decided package's version matches no decision
// and surfaces for a fresh judgment.
//
// Exact is per component, and the package name's identity is its
// ecosystem's, not this package's opinion: a golang purl name is
// case-insensitive because its purl type declares it so, everything
// else compares as written. The rule is written once in
// docs/vex-join.md and implemented once below: anything joining these
// decisions a second time has to reach the same answers, and two
// dialects decide different things about one finding.
//
// Whether a decision EXCUSES is a second question, asked of its
// status and answered here for the same reason (Excuses): a caller
// that asked only "is there a decision?" would clear a finding on the
// strength of a statement admitting it.
//
// The empty-set semantics are explicit and tested by name: an empty
// VEX directory means NOTHING decided, never everything — the grep -f
// landmine this package exists to make unrepresentable. Shared by
// `assert blast-radius`, `assert advisories` and the derive verb's
// VEX leg (#40).
package vexjoin

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// Key is the exact triple a decision matches on.
//
// The fields are sealed behind KeyFromFinding and KeyFromPurl because
// the package name carries a normalisation the two sides of the join
// must reach independently (docs/vex-join.md): a hand-built literal
// is a second spelling of that rule, and a key that spells it
// differently does not fail — it silently decides nothing. This key
// has already missed silently twice, once on the namespace and once
// on case, so construction is the one door.
type Key struct {
	advisory string
	pkg      string
	version  string
}

// Advisory is the vulnerability identifier the key joins on.
func (k Key) Advisory() string { return k.advisory }

// Package is the package name in its canonical form for the
// ecosystem — the spelling both sides of the join compare, which for
// a case-insensitive type is not necessarily the spelling either side
// arrived in (docs/vex-join.md).
func (k Key) Package() string { return k.pkg }

// Version is the package version the key joins on, verbatim: no purl
// type declares versions case-insensitive, so nothing normalises them.
func (k Key) Version() string { return k.version }

// String renders the triple the way a report names it — one
// definition, shared by the finding that carries the key and by the
// decision that excuses it, so the two can never disagree about what
// they are talking about.
func (k Key) String() string {
	return k.advisory + ":" + k.pkg + "@" + k.version
}

// KeyFromFinding mints the key one scanner finding joins on.
// ecosystem is the label the scanner reports it under — OSV's
// vocabulary ("Go", "crates.io", "Debian:12"), not a purl type.
func KeyFromFinding(advisory, ecosystem, name, version string) Key {
	return newKey(ecosystem, advisory, name, version)
}

// KeyFromPurl mints the key one VEX product identifies, and reports
// whether the product can join at all: a product that is not a
// versioned package URL names no triple.
//
// The purl carries its own ecosystem in the type, so the caller never
// states one — the decision side cannot disagree with the document it
// is reading.
func KeyFromPurl(advisory, purl string) (Key, bool) {
	typ, name, version, ok := parsePurl(purl)
	if !ok {
		return Key{}, false
	}

	return newKey(typ, advisory, name, version), true
}

// newKey is the ONE place a Key is built. Both doors delegate here so
// the fold happens once in the code, not once per entry point.
func newKey(ecosystem, advisory, name, version string) Key {
	return Key{advisory: advisory, pkg: canonicalName(ecosystem, name), version: version}
}

// canonicalName renders a package name in the form both sides of the
// join must reach independently. The rule is written once, in
// docs/vex-join.md, and cited from every implementation of it — this
// one and the canon's mirrored join.
func canonicalName(ecosystem, name string) string {
	if !foldsNames(ecosystem) {
		return name
	}

	return strings.ToLower(name)
}

// foldsNames reports whether names in the named ecosystem compare
// case-insensitively, per the purl spec's definition of that
// ecosystem's type. The label arrives in either vocabulary — a purl
// TYPE from a decision, an OSV ECOSYSTEM from a finding — because the
// two sides of the join speak different ones and there is exactly one
// rule between them.
//
// The default is case-SENSITIVE: purl declares a name case-sensitive
// unless its type says otherwise, so an ecosystem nobody has read the
// spec for folds nothing. That is the safe direction. A missed fold
// surfaces a finding as undecided, which is loud; a wrong fold
// excuses a vulnerability in some OTHER package, which is silent.
func foldsNames(ecosystem string) bool {
	// OSV qualifies distro ecosystems with a release ("Debian:12",
	// "Alpine:v3.18"); the release names no different ecosystem.
	label, _, _ := strings.Cut(strings.ToLower(ecosystem), ":")

	switch label {
	// The purl golang type declares the namespace and name lowercased,
	// which makes them case-insensitive: pkg:golang/github.com/A and
	// pkg:golang/github.com/a name one module. OSV reports the same
	// ecosystem as "Go".
	case "golang", "go":
		return true
	default:
		return false
	}
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
	// purlType is the product's purl type, parsed once here rather
	// than re-derived by a caller: a second purl parser outside this
	// package is a second opinion about what a statement covers.
	purlType string

	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
	Decided         time.Time
}

// The statuses that EXCUSE a finding. The rule is one question asked
// of the status: does it DENY that the advisory applies to the
// product? Only a denial excuses; everything else is a decision that
// was made and reported, never one that clears a gate.
//
//   - not_affected — OpenVEX's denial. Excuses.
//   - false_positive — the spelling other VEX dialects use for the
//     same denial, accepted so a decision written in one does not
//     silently decide nothing. It is not OpenVEX v0.2.0 vocabulary;
//     accepting it is a reading choice, and a document using it is
//     still read as denying.
//   - affected — an ADMISSION. Excusing on it would let a statement
//     saying "this product is affected" clear the finding it admits.
//   - under_investigation — a judgment not yet made. A gate held open
//     by an unfinished judgment is the finding, not an exception to it.
//   - fixed — asserts the product was remediated, which is not a
//     denial that the advisory applies. It is also contradicted by
//     the evidence in hand: this join meets a decision only where a
//     scan CURRENTLY reports that exact triple, so a `fixed`
//     statement matching a live finding is a remediation claim the
//     scanner just disproved. Excusing on it would let a stale claim
//     silence the scan that refutes it.
//
// A status this list does not name is not a denial either — an
// unrecognised judgment is not a judgment this code may act on — so
// it does not excuse, and the caller reports it like any other
// non-excusing decision.
const (
	statusNotAffected   = "not_affected"
	statusFalsePositive = "false_positive"
)

// Excuses reports whether this decision's status denies that the
// advisory applies, which is the only ground on which a decision
// clears a finding. One door: a caller that asked "is there a
// decision?" instead would excuse a finding on the strength of a
// statement admitting it.
func (d *Decision) Excuses() bool {
	return d.Status == statusNotAffected || d.Status == statusFalsePositive
}

// PurlType is the purl type of the product this decision names,
// lowercased. It says which ecosystem's rules the product's name is
// read under, and lets a caller scanning ONE ecosystem tell a
// decision it could meet from one it never could — a Go scan and a
// cargo decision are not a stale pair, they are strangers.
func (d *Decision) PurlType() string { return d.purlType }

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

// purlPrefixRE splits a package URL's scheme and type from the
// namespace, name and version a decision joins on. The type is
// captured, not discarded: it is the purl's own statement of which
// ecosystem's rules the name is read under.
var purlPrefixRE = regexp.MustCompile(`^pkg:([A-Za-z0-9.+-]+)/`)

// parsePurl splits a product package URL into the type, package name
// and version a scanner finding is keyed by.
//
// The name is the NAMESPACE AND NAME TOGETHER, not the last path
// segment. A purl's namespace is part of the package's identity —
// pkg:golang/example.com/dep names the module example.com/dep, and
// keying it as "dep" would decide a vulnerability in some other
// package that happens to end the same way, while failing to decide
// the one the statement was written for. Scanners report the joined
// form (a Go module path, an npm scoped name), so this is also the
// spelling a finding arrives in.
//
// Single-segment ecosystems are unaffected: pkg:cargo/serde_cbor
// names serde_cbor either way, which is why the narrower reading
// survived until a Go module needed a decision.
//
//nolint:gocritic // unnamedResult: type, name, version, ok — the stdlib shape
func parsePurl(purl string) (string, string, string, bool) {
	m := purlPrefixRE.FindStringSubmatch(purl)
	if m == nil {
		return "", "", "", false // no scheme and type: not a package URL
	}

	typ, rest := m[1], purl[len(m[0]):]

	// Qualifiers and subpath are not part of the identity.
	rest, _, _ = strings.Cut(rest, "?")
	rest, _, _ = strings.Cut(rest, "#")

	// The LAST @ separates the version: an npm scoped name opens with
	// one, so cutting at the first would split the name in half.
	at := strings.LastIndex(rest, "@")
	if at <= 0 || at == len(rest)-1 {
		return "", "", "", false // unversioned products cannot join
	}

	name, err := url.PathUnescape(rest[:at])
	if err != nil {
		return "", "", "", false
	}

	return typ, name, rest[at+1:], true
}

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

			typ, name, version, ok := parsePurl(*p.ID)
			if !ok {
				continue // a product that is not a versioned purl cannot join
			}

			k := newKey(typ, *stmt.Vulnerability.Name, name, version)

			// Two decisions for one triple is a contradiction to
			// surface, never a race the parse order settles: the files
			// arrive in directory order, so "last one wins" would let
			// a filename decide which judgment enters signed evidence.
			// The human retires one; this code picks neither.
			if prior, dup := d.byKey[k]; dup {
				return fmt.Errorf("vexjoin: %s and %s both decide %s on %s@%s — one finding, one decision;"+
					" retire one", prior.Origin, origin, k.Advisory(), k.Package(), k.Version())
			}

			d.byKey[k] = Decision{
				Key: k, Origin: origin, Purl: *p.ID, purlType: strings.ToLower(typ),
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
