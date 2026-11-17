// This file: the signing plan (stele#398) — which of several VEX
// decisions to sign, over which subjects, and which the run refuses.
// It replaces the canon's shell planner: the OpenVEX check, the
// derivation per decision, the store probe that asks whether a
// decision is already signed, and the matrix cell the signer reads.
// Which decision files changed in a push, the one-decision-per-merge
// rule and the push/recover mode stay in the workflow: they are facts
// about a CI event, not evidence.

package vexsubjects

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/vex"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

// decisionSuffix is the extension a decision file carries, stripped
// from its name to make the cell's slug.
const decisionSuffix = ".openvex.json"

// Store is the attestation store the plan probes for decisions it
// already holds, and the control read that makes a 404 there mean
// "nothing stored" rather than "repository unreadable".
type Store interface {
	// Attestations returns the bundles stored for one digest; an
	// empty answer is the store's 404, and an error is a read that
	// failed.
	Attestations(owner, repo, sha256Hex string) ([]jsonx.Raw, error)
	// DefaultBranch reads the store's repository; found=false is the
	// forge's 404 for the repository itself.
	DefaultBranch(owner, repo string) (string, bool, error)
}

// DecisionFile is one decision document as the caller read it.
type DecisionFile struct {
	Path string
	Raw  []byte
	// Err is a read that failed: the file is refused by name, and the
	// rest are still planned.
	Err error
}

// Cell is one decision to sign: what the signer's matrix leg reads.
// Subjects is the sha256sum manifest the signer takes, and Predicate
// the decision document as one compact JSON string — both exactly as
// the workflow handed them to the signer before this moved here.
type Cell struct {
	Decision  string    `json:"decision"`
	Slug      string    `json:"slug"`
	Subjects  string    `json:"subjects"`
	Predicate string    `json:"predicate"`
	Releases  []Release `json:"releases"`
}

// Refusal is one decision the run will not sign, and why.
// CannotJudge marks the refusal that is an absence of sight — the
// store could not be read — rather than a judgment about the
// decision, so it is never mistaken for either "signed" or
// "unsigned".
type Refusal struct {
	Decision    string `json:"decision"`
	Reason      string `json:"reason"`
	CannotJudge bool   `json:"cannotJudge"`
}

// Plan is the run's answer for every decision it was given: a cell to
// sign, a decision the store already holds, or a refusal.
type Plan struct {
	Cells   []Cell    `json:"cells"`
	Held    []string  `json:"held"`
	Refused []Refusal `json:"refused"`
}

// Blind reports whether any decision went unjudged because the store
// could not be read.
func (p *Plan) Blind() bool {
	for _, r := range p.Refused {
		if r.CannotJudge {
			return true
		}
	}

	return false
}

// Planner holds what one plan needs. Derive is the affected-release
// derivation over the run's population (Deriver.Affected); Store,
// StoreOwner and StoreRepo are set only when the plan omits decisions
// the store already holds.
type Planner struct {
	Derive       func(decisions *vexjoin.Decisions, origin string) (*Document, error)
	UnsignedOnly bool
	Store        Store
	StoreOwner   string
	StoreRepo    string
	Log          Logf
}

// ErrStoreUnreadable is the control read failing: the store's own
// repository could not be read, so no 404 under it means anything.
var ErrStoreUnreadable = errors.New("vexsubjects: the attestation store's repository is unreadable — refusing to" +
	" read that as an empty store")

// Plan answers for every decision file, in order. One decision's
// refusal never hides the state of the rest: every refusal is named
// and planning carries on.
//
// With UnsignedOnly, one control read of the store's repository runs
// first: the attestations endpoint answers a missing repository and a
// digest that carries nothing with the same 404, so "404 means nothing
// stored" holds only once the repository is known readable. A control
// read that fails refuses the whole plan.
func (pl *Planner) Plan(files []DecisionFile) (*Plan, error) {
	if pl.UnsignedOnly {
		if err := pl.controlRead(); err != nil {
			return nil, err
		}
	}

	plan := &Plan{Cells: []Cell{}, Held: []string{}, Refused: []Refusal{}}

	for _, f := range files {
		pl.one(plan, f)
	}

	return plan, nil
}

// controlRead proves the store's repository is readable.
func (pl *Planner) controlRead() error {
	if pl.Store == nil || pl.StoreOwner == "" || pl.StoreRepo == "" {
		return errors.New("vexsubjects: omitting held decisions needs the store to ask: none was named")
	}

	_, found, err := pl.Store.DefaultBranch(pl.StoreOwner, pl.StoreRepo)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStoreUnreadable, err)
	}

	if !found {
		return fmt.Errorf("%w: %s/%s answered 404", ErrStoreUnreadable, pl.StoreOwner, pl.StoreRepo)
	}

	return nil
}

// one places a single decision in the plan.
func (pl *Planner) one(plan *Plan, f DecisionFile) {
	refuse := func(reason string, cannotJudge bool) {
		plan.Refused = append(plan.Refused, Refusal{Decision: f.Path, Reason: reason, CannotJudge: cannotJudge})
		pl.logf("derive: vex-subjects: %s: refused: %s", f.Path, reason)
	}

	if f.Err != nil {
		refuse(f.Path+": unreadable: "+f.Err.Error(), false)

		return
	}

	want, predicate, ok := openVEX(f.Raw)
	if !ok {
		refuse(f.Path+" is not an OpenVEX document", false)

		return
	}

	decisions := &vexjoin.Decisions{}
	if err := vexjoin.Parse(decisions, f.Raw, f.Path); err != nil {
		refuse(f.Path+": the affected-release derivation refused: "+err.Error(), false)

		return
	}

	doc, err := pl.Derive(decisions, f.Path)
	if err != nil {
		refuse(f.Path+": the affected-release derivation refused: "+err.Error(), false)

		return
	}

	// The derivation refuses a decision bound to nothing itself; the
	// plan holds the same line rather than trusting it, because the
	// store probe and the signer both need a subject to stand on.
	if len(doc.Subjects) == 0 {
		refuse(f.Path+": the derivation bound it to no subject — a claim bound to nothing is not signed", false)

		return
	}

	if pl.UnsignedOnly {
		held, herr := pl.held(doc, want)
		if herr != nil {
			refuse(f.Path+": the attestation store could not be read — refusing to read that as unsigned: "+
				herr.Error(), true)

			return
		}

		if held {
			plan.Held = append(plan.Held, f.Path)
			pl.logf("derive: vex-subjects: %s: the store already holds this decision — nothing to sign", f.Path)

			return
		}
	}

	plan.Cells = append(plan.Cells, Cell{
		Decision:  f.Path,
		Slug:      slug(f.Path),
		Subjects:  manifest(doc.Subjects),
		Predicate: string(predicate),
		Releases:  doc.Releases,
	})

	names := make([]string, 0, len(doc.Releases))
	for _, r := range doc.Releases {
		names = append(names, r.Subject())
	}

	pl.logf("derive: vex-subjects: %s: affected releases: %s", f.Path, strings.Join(names, " "))
	pl.logf("derive: vex-subjects: signing %s over %d subject(s)", f.Path, len(doc.Subjects))
}

// openVEX reports whether a document is OpenVEX — an object carrying
// both an @context and statements — and returns it as a value for the
// store comparison and compacted for the signer.
//
//nolint:gocritic // unnamedResult: the value, its compact bytes, and whether it is OpenVEX at all
func openVEX(raw []byte) (any, []byte, bool) {
	v, err := jsonx.Value(raw)
	if err != nil {
		return nil, nil, false
	}

	obj, isObj := v.(map[string]any)
	if !isObj || !truthy(obj["@context"]) || !truthy(obj["statements"]) {
		return nil, nil, false
	}

	compact, err := jsonx.Compact(raw)
	if err != nil {
		return nil, nil, false
	}

	return v, compact, true
}

// truthy is the document check's notion of present: anything but
// absent, null or false.
func truthy(v any) bool {
	if v == nil {
		return false
	}

	b, isBool := v.(bool)

	return !isBool || b
}

// held asks the store whether it already holds THIS decision. The
// store is keyed by subject digest and nothing else, so the question
// is asked through a subject the claim binds — the derived set's first
// and last, because a newly published release lands at the head of
// the set and probing the tail as well keeps an already-public
// decision from being signed again every time the population grows —
// and answered by comparing predicates: the OpenVEX type, and the
// document itself, deep and key-order-insensitive. The decision's
// @id is not the key: a store can hold earlier versions of a decision
// under the identifier the current one still carries.
//
// It can be wrong in one direction only. A miss signs again, which
// costs a run; a hit is a positive match on bytes the store returned;
// a read that fails is an error, never either.
func (pl *Planner) held(doc *Document, want any) (bool, error) {
	probes := []string{doc.Subjects[0].SHA256}
	if last := doc.Subjects[len(doc.Subjects)-1].SHA256; last != probes[0] {
		probes = append(probes, last)
	}

	for _, digest := range probes {
		bundles, err := pl.Store.Attestations(pl.StoreOwner, pl.StoreRepo, digest)
		if err != nil {
			return false, err
		}

		for _, b := range bundles {
			if holdsDecision(b, want) {
				return true, nil
			}
		}
	}

	return false, nil
}

// bundlePayload is the one field of a stored bundle the probe reads.
type bundlePayload struct {
	DSSEEnvelope *struct {
		Payload *string `json:"payload"`
	} `json:"dsseEnvelope"`
}

// holdsDecision reports whether one stored bundle carries the
// decision. A bundle whose payload cannot be read is simply not this
// decision.
func holdsDecision(bundle jsonx.Raw, want any) bool {
	b, err := jsonx.DecodeForeign[bundlePayload](bundle)
	if err != nil || b.DSSEEnvelope == nil || b.DSSEEnvelope.Payload == nil {
		return false
	}

	payload, err := base64.StdEncoding.DecodeString(*b.DSSEEnvelope.Payload)
	if err != nil {
		return false
	}

	v, err := jsonx.Value(payload)
	if err != nil {
		return false
	}

	stmt, isObj := v.(map[string]any)
	if !isObj || stmt["predicateType"] != vex.Context {
		return false
	}

	return jsonEqual(stmt["predicate"], want)
}

// jsonEqual is JSON value equality: objects by key whatever their
// order, arrays by position, numbers by value rather than spelling.
func jsonEqual(a, b any) bool {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}

		for k, x := range av {
			y, present := bv[k]
			if !present || !jsonEqual(x, y) {
				return false
			}
		}

		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}

		for i := range av {
			if !jsonEqual(av[i], bv[i]) {
				return false
			}
		}

		return true
	case jsonx.Number:
		bv, ok := b.(jsonx.Number)

		return ok && numbersEqual(av, bv)
	default:
		return a == b
	}
}

// numbersEqual compares two JSON numbers by value.
func numbersEqual(a, b jsonx.Number) bool {
	x, okx := new(big.Rat).SetString(string(a))
	y, oky := new(big.Rat).SetString(string(b))

	return okx && oky && x.Cmp(y) == 0
}

// slug is the decision's file-safe name: its base name without the
// decision suffix, every character outside [A-Za-z0-9._-] replaced.
func slug(path string) string {
	name := strings.TrimSuffix(filepath.Base(path), decisionSuffix)

	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		default:
			return '-'
		}
	}, name)
}

// manifest renders the subjects as the sha256sum lines the signer
// takes, one per subject, no trailing newline.
func manifest(subjects []Subject) string {
	lines := make([]string, 0, len(subjects))
	for _, s := range subjects {
		lines = append(lines, s.SHA256+"  "+s.Name)
	}

	return strings.Join(lines, "\n")
}

// logf emits a progress line when the caller wanted them.
func (pl *Planner) logf(format string, args ...any) {
	if pl.Log != nil {
		pl.Log(format, args...)
	}
}
