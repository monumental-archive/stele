// Package vex renders an OpenVEX document from decisions that have
// been joined to an inventory.
//
// The format is openvex.dev's, so the field names, the context URI
// and the statement shape are code. What an org chooses to call
// itself, and how it spells a document identifier, are inputs — this
// package holds no name of its own.
//
// Two properties the document must have, and one of them is a
// divergence from the bash this replaces:
//
//   - The document is a fact about a release, so rendering it twice
//     from the same inputs must produce the same bytes. It is
//     attested, and an attested artifact that differs on every run
//     cannot be reproduced by anyone checking it. The bash stamps
//     `date -u` into the document AND into every statement.
//   - A statement's timestamp is when the JUDGMENT was made, which
//     is a property of the decision a human recorded, not of the
//     release that later inherits it. Carrying the decision's own
//     timestamp is both more honest and what makes the first
//     property achievable; the document timestamp is the release's
//     instant, which is likewise a fact rather than a clock reading.
package vex

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// Context is the OpenVEX context URI this renderer writes. Spec, not
// policy: it names the format these field names belong to.
const Context = "https://openvex.dev/ns/v0.2.0"

// Document is an OpenVEX document. Encode side only.
type Document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Version    int         `json:"version"`
	Timestamp  string      `json:"timestamp"`
	Statements []Statement `json:"statements"`
}

// Statement is one judgment about one product.
type Statement struct {
	Vulnerability   Vulnerability `json:"vulnerability"`
	Timestamp       string        `json:"timestamp"`
	Products        []Product     `json:"products"`
	Status          string        `json:"status"`
	Justification   string        `json:"justification,omitempty"`
	ImpactStatement string        `json:"impact_statement,omitempty"`
	ActionStatement string        `json:"action_statement,omitempty"`
}

// Vulnerability names the advisory.
type Vulnerability struct {
	Name string `json:"name"`
}

// Product is what a statement is about: the artifact a consumer
// holds, and the dependency inside it the judgment concerns.
type Product struct {
	ID            string      `json:"@id"`
	Subcomponents []Component `json:"subcomponents,omitempty"`
}

// Component is one subcomponent identifier.
type Component struct {
	ID string `json:"@id"`
}

// Coverage is one decision applied to one product: the artifact it
// covers, the dependency it concerns, and the judgment itself.
type Coverage struct {
	// Product is the artifact a consumer verifies — a release, or a
	// single artifact within one. The caller decides which, because
	// the unit of description is the unit of consumption and only the
	// caller knows what it published.
	Product string
	// Subcomponent is the dependency purl the judgment was recorded
	// against.
	Subcomponent string
	// Advisory, Status and the optional statements come from the
	// recorded decision.
	Advisory        string
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
	// Decided is when the judgment was made. Zero means the source
	// decision recorded no timestamp, and the renderer refuses rather
	// than substituting a clock: a statement dated by the machine
	// that copied it asserts a judgment nobody made then.
	Decided time.Time
}

// Options are the inputs an org supplies. No default is invented for
// any of them — a document authored by "" or identified by "" is not
// a document, and guessing would put this package's opinion into
// signed evidence.
type Options struct {
	// ID is the document identifier.
	ID string
	// Author is who asserts these statements.
	Author string
	// Released is the instant the document describes — the release's
	// own, never a clock reading.
	Released time.Time
}

// ErrNoCoverage reports a render with nothing to say. Named so a
// caller can treat "no decision applies" as the ordinary outcome it
// is, rather than as a failure.
var ErrNoCoverage = errors.New("vex: no decision covers this inventory")

// Render builds the document. Statements are ordered and deduplicated
// so one set of inputs renders one set of bytes.
func Render(opts Options, coverage []Coverage) (*Document, error) {
	switch {
	case opts.ID == "":
		return nil, errors.New("vex: a document id is required")
	case opts.Author == "":
		return nil, errors.New("vex: an author is required")
	case opts.Released.IsZero():
		return nil, errors.New("vex: a release instant is required — a document dated by a clock is not reproducible")
	case len(coverage) == 0:
		return nil, ErrNoCoverage
	}

	statements := make([]Statement, 0, len(coverage))
	seen := map[string]bool{}

	for i := range coverage {
		c := &coverage[i]
		if err := c.validate(); err != nil {
			return nil, err
		}

		key := c.Advisory + "\x00" + c.Product + "\x00" + c.Subcomponent
		if seen[key] {
			continue
		}

		seen[key] = true

		statements = append(statements, Statement{
			Vulnerability:   Vulnerability{Name: c.Advisory},
			Timestamp:       c.Decided.UTC().Format(time.RFC3339),
			Products:        []Product{{ID: c.Product, Subcomponents: subcomponents(c.Subcomponent)}},
			Status:          c.Status,
			Justification:   c.Justification,
			ImpactStatement: c.ImpactStatement,
			ActionStatement: c.ActionStatement,
		})
	}

	sort.Slice(statements, func(i, j int) bool {
		if statements[i].Vulnerability.Name != statements[j].Vulnerability.Name {
			return statements[i].Vulnerability.Name < statements[j].Vulnerability.Name
		}

		return statements[i].Products[0].ID+statements[i].Products[0].subcomponentID() <
			statements[j].Products[0].ID+statements[j].Products[0].subcomponentID()
	})

	return &Document{
		Context:    Context,
		ID:         opts.ID,
		Author:     opts.Author,
		Version:    1,
		Timestamp:  opts.Released.UTC().Format(time.RFC3339),
		Statements: statements,
	}, nil
}

// Encode writes the document as one JSON value plus newline.
func (d *Document) Encode(w io.Writer) error {
	if err := jsonx.Encode(w, d); err != nil {
		return fmt.Errorf("vex: %w", err)
	}

	return nil
}

func (c *Coverage) validate() error {
	switch {
	case c.Advisory == "":
		return errors.New("vex: a statement names no vulnerability")
	case c.Product == "":
		return fmt.Errorf("vex: %s names no product", c.Advisory)
	case c.Status == "":
		return fmt.Errorf("vex: %s carries no status", c.Advisory)
	case c.Decided.IsZero():
		return fmt.Errorf("vex: %s has no decision time — a statement dated by the machine that copied it"+
			" asserts a judgment nobody made then", c.Advisory)
	}

	return nil
}

func subcomponents(id string) []Component {
	if id == "" {
		return nil
	}

	return []Component{{ID: id}}
}

func (p Product) subcomponentID() string {
	if len(p.Subcomponents) == 0 {
		return ""
	}

	return p.Subcomponents[0].ID
}
