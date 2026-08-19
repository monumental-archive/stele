// Package emit is the emission engine behind `stele emit` — the
// producer half of the evidence layer, replacing the canon's bash
// emitter (chain.sh, emit.sh, lib.sh, append.sh). It renders the JSON
// that gets signed and owns the ledger append; it never signs:
// signing stays behind the Signer seam (cosign in production), so the
// capability boundary — the Fulcio identity — lives strictly above
// this code.
//
// The .github#434 defect class is made unrepresentable here, not
// fixed: the ledger digest is chain.SHA256Hex, the same function the
// verify walk calls; a predecessor's hash is computed from the note
// blob READ BACK out of the object store, never from bytes this
// process wrote; and the whole discover→sign→append sequence is one
// compare-and-swap attempt — a rejected push refetches and rebuilds,
// so the hash that lands was computed against the state that won.
package emit

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/claims"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/trust"
)

// Git is the repository surface the chain leg reads and writes,
// composed of its read half and its ledger half. The implementation
// (gitrepo) carries remote and credentials; the engine only ever
// says fetch and push.
type Git interface {
	GitReader
	GitLedger
}

// GitReader is the history read half — the verify walk's surface.
type GitReader interface {
	Tip(ref string) (string, error)
	Parent(rev string) (string, error)
	Parents(rev string) ([]string, error)
	Note(rev string) ([]byte, error)
	CommitTime(rev string) (string, error)
	IsAncestor(rev, ref string) (bool, error)
}

// GitLedger is the write-and-prove half: note writes, the notes-ref
// network pair, and the two preflight proofs — CommitterIdent proves
// the storage identity is usable, DryRunPushNotes proves the push
// can land before signing mints anything irreversible (#236).
type GitLedger interface {
	AddNote(rev string, note []byte) error
	FetchNotes() error
	PushNotes() error
	CommitterIdent() error
	DryRunPushNotes(rev string) error
}

// Signer signs one payload and returns the Sigstore bundle JSON. The
// production implementation execs cosign under the workflow's OIDC
// identity; the engine never holds key material or a certificate.
type Signer interface {
	Sign(payload []byte) ([]byte, error)
	// Check proves the signing tool is present and executable before
	// the run makes any irreversible mark.
	Check() error
}

// BlobVerifier is the self-check boundary: every bundle this engine
// writes into a note is first verified with exactly a stranger's
// inputs — the published identity and the statement digest.
type BlobVerifier interface {
	Blob(bundleJSON []byte, id trust.Identity, sha256Hex string) (*trust.Verified, error)
}

// Logf receives progress lines; the caller owns the stream.
type Logf func(format string, args ...any)

// serverURL is the host every GitHub identity and repository URI
// lives under — buildType semantics, so code, not policy.
const serverURL = "https://github.com"

var (
	revRE  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	refRE  = regexp.MustCompile(`^refs/.+$`)
	nameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// expand substitutes the policy template vocabulary — the same closed
// set the verify engine substitutes, nothing else.
func expand(tmpl, owner, repo string) string {
	return strings.NewReplacer("{owner}", owner, "{repo}", repo).Replace(tmpl)
}

// level computes the honest source level for one revision — the same
// rule the verify engine applies to a tip link, shared by intent so
// the emitter and the verifier cannot disagree by construction:
// the branch's target when every required property whose continuity
// start predates the commit is present; the underclaim level when one
// is missing, when the branch's healed-continuity stance refuses
// healed links, or when a healed link cannot PROVE rule continuity
// across its gap (no readable change times, or a contributing ruleset
// changed at or after the commit). A guard that cannot prove
// under-claims; it never guesses.
func level(
	p *policy.Policy, pb *policy.ProtectedBranch, payload *claims.Payload,
	commitTime time.Time, healed bool, log Logf,
) (string, error) {
	present := payload.Properties()

	for _, rp := range pb.RequiredProperties {
		since, err := time.Parse(time.RFC3339, *rp.Since)
		if err != nil {
			return "", fmt.Errorf("emit: policy since for %s: %w", *rp.Name, err)
		}

		if since.After(commitTime) {
			continue // not yet required when this commit landed
		}

		if !present[*rp.Name] {
			log("emit: required property %s is not live — under-claiming %s", *rp.Name, *p.Source.UnderclaimLevel)

			return *p.Source.UnderclaimLevel, nil
		}
	}

	if healed {
		if !*p.Source.HealedContinuity {
			log("emit: healed link and the policy refuses healed continuity — under-claiming %s", *p.Source.UnderclaimLevel)

			return *p.Source.UnderclaimLevel, nil
		}

		if maxE, ok := payload.Horizon(); !ok || maxE >= commitTime.Unix() {
			log("emit: healed link and ruleset continuity across the gap is unprovable — under-claiming %s",
				*p.Source.UnderclaimLevel)

			return *p.Source.UnderclaimLevel, nil
		}
	}

	return *pb.TargetLevel, nil
}
