// Package verify is the verification engine behind `stele verify` —
// the read-only, fail-closed core that replaces the canon's bash
// verifier. Its design rule is #208 made structural: a verdict type
// (ReleaseVerdict, VSAVerdict, ChainVerdict) has unexported fields
// and exactly one constructor, the function that performed every
// check — so downstream code (the emit verb's VSA assembly, the
// level report) cannot hold a verdict the checks did not return.
//
// Org conventions enter through the policy; effects enter through
// the Store, History and BundleVerifier interfaces so every guard
// branch is reachable from a table test (the repo law). Spec
// constants live in the spec packages this engine composes.
package verify

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/trust"
)

// Logf receives the engine's progress lines. The caller owns the
// stream and its failure handling — a CLI that must not report
// success after failing to write latches errors in the closure.
type Logf func(format string, args ...any)

// Coords names the release (or repository) under verification —
// the verification subject every expectation is derived from,
// never the verifier's own identity (docs/policy-schema.md,
// disagreement 2).
type Coords struct {
	Owner string
	Repo  string
	Tag   string
}

// Slug is the owner/repo form GitHub APIs and policies speak.
func (c Coords) Slug() string { return c.Owner + "/" + c.Repo }

// Version is the tag without its leading v — the org convention
// linking the two, applied in one place.
func (c Coords) Version() string { return strings.TrimPrefix(c.Tag, "v") }

// Subject is one released artifact: a file's name or an image's
// untagged reference, and the sha256 the release claims for it.
type Subject struct {
	Name   string
	SHA256 string
}

// Pins are the commit digests the roots of trust are pinned at for
// this invocation — derived from the consuming tree or supplied
// explicitly, never read from the policy (the #314 lesson).
// Signer pins the signer's tree; Machinery pins the tree of the
// repository carrying the shared release machinery — the verifier
// and decision workflows. A repository carrying its own machinery
// pins its own tree.
type Pins struct {
	Signer    string
	Machinery string
}

// StoredBundle is one attestation bundle as fetched: the raw bundle
// JSON and the URI it was fetched from, kept together so the verdict
// can name its evidence by address (inputAttestations).
type StoredBundle struct {
	URI    string
	Bundle []byte
}

// Store fetches the attestation bundles published for one artifact
// digest — the same API a stranger queries, which is what makes a
// fetch here also a persistence proof.
type Store interface {
	Bundles(slug, sha256Hex string) ([]StoredBundle, error)
}

// BundleVerifier is the cryptographic boundary, interface-shaped so
// the engine's guards are table-testable. Attestation proves a DSSE
// bundle and returns the signed statement bytes; Blob proves a
// message-signature bundle over artifact bytes the caller already
// holds. Both bind the given sha256 and the exact identity. Peek
// returns a bundle's payload UNVERIFIED, for selection only — the
// engine never judges peeked bytes.
type BundleVerifier interface {
	Attestation(bundleJSON []byte, id trust.Identity, sha256Hex string) (*trust.Verified, error)
	Blob(bundleJSON []byte, id trust.Identity, sha256Hex string) (*trust.Verified, error)
	Peek(bundleJSON []byte) ([]byte, error)
}

// serverURL is the host every GitHub Actions identity URI lives
// under — part of the buildType's semantics, so code, not policy.
const serverURL = "https://github.com"

var (
	tagRE   = regexp.MustCompile(`^v[0-9A-Za-z.+-]+$`)
	nameRE  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	hex40RE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// Any fully qualified ref: the caller may fetch the branch into a
	// local mapping (the audit's refs/sa/main); the BRANCH the policy
	// judges is named separately.
	refRE = regexp.MustCompile(`^refs/.+$`)
)

// validateCoords refuses coordinates that could not name a release:
// every downstream expectation is substituted from these, so a
// malformed coordinate is a malformed expectation.
func validateCoords(c Coords, requireTag bool) error {
	if !nameRE.MatchString(c.Owner) || !nameRE.MatchString(c.Repo) {
		return fmt.Errorf("verify: owner/repo %q/%q is not a plausible repository", c.Owner, c.Repo)
	}

	if requireTag && !tagRE.MatchString(c.Tag) {
		return fmt.Errorf("verify: tag %q is not a plausible release tag", c.Tag)
	}

	return nil
}

// validateSubjects refuses a manifest that could not have come from
// sha256sum, and an empty one: an empty proof is not a proof.
func validateSubjects(subjects []Subject) error {
	if len(subjects) == 0 {
		return errors.New("verify: no subjects — an empty proof is not a proof")
	}

	for i, s := range subjects {
		if !hex64RE.MatchString(s.SHA256) {
			return fmt.Errorf("verify: subject %d digest is not 64 lowercase hex", i)
		}

		if s.Name == "" || strings.ContainsAny(s.Name, " \t\r\n") {
			return fmt.Errorf("verify: subject %d name is empty or carries whitespace", i)
		}
	}

	return nil
}

// expand substitutes the policy template vocabulary — verbatim,
// nothing else interpolated (docs/policy-schema.md).
func expand(tmpl string, c Coords) string {
	return strings.NewReplacer(
		"{owner}", c.Owner,
		"{repo}", c.Repo,
		"{tag}", c.Tag,
		"{version}", c.Version(),
	).Replace(tmpl)
}

// expandWorkflow substitutes the identity-role placeholders (#82):
// a workflow identity templated `{owner}/{repo}/…` names the
// repository under verification's own workflow — the self-attesting
// topology. Only owner and repo: identities are roles, not per-tag
// wildcards (the policy loader enforces the vocabulary).
func expandWorkflow(workflow string, c Coords) string {
	return strings.NewReplacer("{owner}", c.Owner, "{repo}", c.Repo).Replace(workflow)
}

// workflowSAN renders the certificate identity a workflow signs
// under: its path on the given host, at an exact ref. Exact — a ref
// wildcard here would turn the identity check into a suggestion.
func workflowSAN(workflow, ref string) string {
	return serverURL + "/" + workflow + "@" + ref
}

// identityRef derives the exact ref a trusted workflow's certificate
// carries for this release. A workflow living in the repository
// UNDER verification runs as that repo's own workflow at the release
// tag; a foreign consumer reaches it through a commit-pinned uses:.
// Deterministic — never a try-each: which world applies is a fact of
// the coordinates, and the commit binding is asserted separately via
// the certificate's signer digest in both worlds.
func identityRef(workflow string, c Coords, pin string) string {
	if strings.HasPrefix(workflow, c.Slug()+"/") {
		return "refs/tags/" + c.Tag
	}

	return pin
}

// sha256Hex is the one digest rendering the engine compares — the
// chain format's, shared with the emit leg (.github#434 rule 1).
func sha256Hex(b []byte) string {
	return chain.SHA256Hex(b)
}
