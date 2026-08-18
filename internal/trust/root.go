// Trusted-root acquisition: which document one run verifies against,
// and where those bytes come from. Two rules make it a boundary
// rather than a convenience. The decision is PURE and single-valued
// — a verifier that tries sources until one works has no boundary at
// all — and both origins return the trusted-root document's OWN
// bytes, so exactly one parser (LoadRoot) interprets what either
// path produced. The TUF path is a bytes-producer, not a second
// trust path: nothing below this file knows it exists.

package trust

import (
	"errors"
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/tuf"
)

// TrustedRootTarget is the TUF target name Sigstore publishes the
// trusted-root document under — a repository convention identical at
// every instance, so it is code, not policy.
const TrustedRootTarget = "trusted_root.json"

// DefaultMirror is the Sigstore public-good TUF instance: the
// default when the invocation names no other. Taken from the
// library rather than retyped — one spelling of one URL.
const DefaultMirror = tuf.DefaultMirror

// RootOrigin names where one run's trusted root comes from. The set
// is closed: an origin outside it is a planning defect, not a
// fallback.
type RootOrigin string

// The two origins, and only two.
const (
	// OriginFile is an operator-supplied trusted-root document: no
	// network at all, which is what makes offline, air-gapped and
	// test verification possible.
	OriginFile RootOrigin = "file"
	// OriginTUF resolves the document through TUF from a pinned
	// initial root — reviewed data, never fetched blind.
	OriginTUF RootOrigin = "tuf"
)

// RootPlan is the single answer to "where does this run's trusted
// root come from". It is produced once per process by PlanRoot and
// carries everything ResolveRoot needs, so the decision cannot be
// re-taken differently further down.
type RootPlan struct {
	// Origin is which of the two paths this run takes.
	Origin RootOrigin
	// File is the trusted-root document's path (OriginFile only).
	File string
	// Anchor is the path to the pinned initial root (OriginTUF).
	// Empty means the anchor compiled into the binary through the
	// pinned sigstore-go module — the reviewed artifact go.sum
	// covers.
	Anchor string
	// Mirror is the TUF instance's base URL (OriginTUF only).
	Mirror string
}

// BuiltinAnchor reports whether this plan trusts the anchor the
// pinned dependency ships rather than one the operator supplied.
func (p RootPlan) BuiltinAnchor() bool { return p.Origin == OriginTUF && p.Anchor == "" }

// Describe renders where this run's trust material came from, for
// the verification record. A report that does not say which trusted
// root it held has not said what it proved, and a verb that reaches
// the network on an absent flag must say so out loud.
func (p RootPlan) Describe() string {
	switch {
	case p.Origin == OriginFile:
		return "file " + p.File
	case p.BuiltinAnchor():
		return "tuf " + p.Mirror + " (anchor pinned in this binary)"
	default:
		return "tuf " + p.Mirror + " (anchor " + p.Anchor + ")"
	}
}

// PlanRoot decides one run's root origin from the invocation. It is
// pure — no file is opened, no packet is sent — so every refusal
// below is reachable from a table, and the network lives strictly on
// the far side of ResolveRoot.
//
// The refusals are the design: naming two sources means the caller
// does not know which root it wants, and naming half the TUF pair is
// a declaration with a hole in it — an anchor without its instance
// verifies nothing, an instance without its anchor is fetched blind.
func PlanRoot(file, anchor, mirror string) (RootPlan, error) {
	switch {
	case file != "" && (anchor != "" || mirror != ""):
		return RootPlan{}, errors.New(
			"trust: a trusted-root file and a TUF instance are exclusive — one root, named once")

	case (anchor == "") != (mirror == ""):
		return RootPlan{}, errors.New(
			"trust: the TUF anchor and its mirror are declared together or not at all — " +
				"an anchor without its instance verifies nothing, an instance without its anchor is fetched blind")

	case file != "":
		return RootPlan{Origin: OriginFile, File: file}, nil

	case anchor != "":
		return RootPlan{Origin: OriginTUF, Anchor: anchor, Mirror: mirror}, nil

	default:
		return RootPlan{Origin: OriginTUF, Mirror: DefaultMirror}, nil
	}
}

// ResolveRoot obtains the trusted-root document's bytes for one
// plan. Both origins return the document itself — never a
// re-encoding, never an already-parsed type — which is what lets
// LoadRoot stay the single place the bytes become trust material.
func ResolveRoot(p RootPlan) ([]byte, error) {
	switch p.Origin {
	case OriginFile:
		content, err := os.ReadFile(p.File)
		if err != nil {
			return nil, fmt.Errorf("trust: read trusted root: %w", err)
		}

		return content, nil

	case OriginTUF:
		return fetchTUF(p)

	default:
		return nil, fmt.Errorf("trust: unplanned root origin %q — the plan did not come from PlanRoot", p.Origin)
	}
}

// fetchTUF walks the TUF metadata chain from the plan's anchor and
// returns the trusted-root target's bytes.
//
// Coverage note, deliberate: this function is the network boundary.
// Exercising it means either reaching the live public-good instance
// — a network dependency the gate refuses by law — or standing up a
// fake TUF repository, which would prove the fake and not the
// instance. It is proven where a network boundary can honestly be
// proven: in shadow mode against the real instance before cutover.
// The DECISION that reaches it (PlanRoot) is table-tested whole.
func fetchTUF(p RootPlan) ([]byte, error) {
	opts := tuf.DefaultOptions()
	opts.RepositoryBaseURL = p.Mirror

	if p.Anchor != "" {
		anchor, err := os.ReadFile(p.Anchor)
		if err != nil {
			return nil, fmt.Errorf("trust: read TUF anchor: %w", err)
		}

		opts.Root = anchor
	}

	client, err := tuf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("trust: TUF client for %s: %w", p.Mirror, err)
	}

	content, err := client.GetTarget(TrustedRootTarget)
	if err != nil {
		return nil, fmt.Errorf("trust: fetch %s from %s: %w", TrustedRootTarget, p.Mirror, err)
	}

	return content, nil
}
