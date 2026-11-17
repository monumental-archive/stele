package trust

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/verify"
)

// WorkflowIdentity is the expectation for an artifact a workflow
// signed in a run of its own, before the run verifying it began — a
// base image another release published (stele#402). Its anchors are
// the signing workflow, the issuer, the source repository's owner, the
// source ref and the runner environment, all exact, all checked here.
//
// What is relaxed, and only this: the ref after "@" in the signer's
// SAN. Identity's exact SAN pins the signer at one commit, which is
// right for an artifact signed in the run being verified — that run's
// tree pins the commit. It is wrong for someone else's published
// artifact, whose signer commit is whatever the tree that published it
// pinned: a base is normally signed at an OLDER signer commit than the
// tree building on it (measured by the canon, build-oci-image.yml:
// release-lab v0.27.0's index carries signer e4a285f8 while the tree
// verifying it pins e90a971e). The workflow's host, owner, repository
// and path stay exact — trust builds the pattern itself, from the
// quoted path, and no caller ever supplies one.
//
// Nothing may use this type for an artifact signed in the same run:
// there the signer commit is known, and Identity pins it.
//
// Constructor: NewWorkflowIdentity, alone. Its fields are unexported
// so no caller can build one with an anchor missing.
type WorkflowIdentity struct {
	workflow string
	issuer   string
	ownerURI string
	ref      string
	runner   string
}

// workflowPathRE is a workflow's repository-qualified path: an owner,
// a repository, and the file beneath them.
var workflowPathRE = regexp.MustCompile(`^/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+\.ya?ml$`)

// NewWorkflowIdentity builds the expectation from its five anchors,
// every one required: the signing workflow's URL without a ref
// (https://<host>/<owner>/<repo>/<path>), the OIDC issuer, the source
// repository's owner (on the workflow's host), the source ref the run
// built, and the runner environment it must have run in.
func NewWorkflowIdentity(workflow, issuer, owner, sourceRef, runnerEnvironment string) (WorkflowIdentity, error) {
	u, err := url.Parse(workflow)

	switch {
	case err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || strings.Contains(workflow, "@") || !workflowPathRE.MatchString(u.Path):
		return WorkflowIdentity{}, fmt.Errorf("trust: workflow %q is not https://<host>/<owner>/<repo>/<path>"+
			" with no ref", workflow)
	case !strings.HasPrefix(issuer, "https://"):
		return WorkflowIdentity{}, fmt.Errorf("trust: issuer %q is not an https URL", issuer)
	case owner == "" || strings.ContainsAny(owner, "/@ \t"):
		return WorkflowIdentity{}, fmt.Errorf("trust: source owner %q is not an owner name", owner)
	case !strings.HasPrefix(sourceRef, "refs/"):
		return WorkflowIdentity{}, fmt.Errorf("trust: source ref %q is not a fully qualified ref", sourceRef)
	case runnerEnvironment == "":
		return WorkflowIdentity{}, errors.New("trust: the runner environment is required — a run on any runner" +
			" is not an anchor")
	}

	return WorkflowIdentity{
		workflow: workflow,
		issuer:   issuer,
		ownerURI: u.Scheme + "://" + u.Host + "/" + owner,
		ref:      sourceRef,
		runner:   runnerEnvironment,
	}, nil
}

// String renders the expectation for a refusal or a log line.
func (id WorkflowIdentity) String() string {
	return fmt.Sprintf("%s@* from %s at %s on %s", id.workflow, id.ownerURI, id.ref, id.runner)
}

// VerifyFromWorkflow proves one DSSE attestation under a
// WorkflowIdentity: the full stance — signature chain, log, observer
// timestamp, certificate transparency, artifact digest — with the SAN
// matched as the workflow at any ref, then every other anchor held to
// the certificate's own extensions. It returns the envelope's payload
// bytes, as Verify does. The identity constructor's error is fail-closed
// posture, as Verify's note says of its own: the pattern is built here
// from a quoted path, so it cannot fail to compile.
func (t *Verifier) VerifyFromWorkflow(
	entity verify.SignedEntity, id *WorkflowIdentity, alg, digestHex string,
) (*Verified, error) {
	if id == nil || id.workflow == "" {
		return nil, errors.New("trust: a workflow identity is built by NewWorkflowIdentity, never by hand")
	}

	digest, err := hexDigest(digestHex)
	if err != nil {
		return nil, err
	}

	pattern := "^" + regexp.QuoteMeta(id.workflow) + "@[^@]+$"

	ci, err := verify.NewShortCertificateIdentity(id.issuer, "", "", pattern)
	if err != nil {
		return nil, fmt.Errorf("trust: identity: %w", err)
	}

	result, observed, err := t.verifyAs(entity, &ci, alg, digest)
	if err != nil {
		return nil, err
	}

	verified, err := attestation(entity, result, observed)
	if err != nil {
		return nil, err
	}

	ext := verified.Extensions

	switch {
	case ext.SourceRepositoryOwnerURI != id.ownerURI:
		return nil, fmt.Errorf("trust: certificate source owner %q is not %q", ext.SourceRepositoryOwnerURI, id.ownerURI)
	case ext.SourceRepositoryRef != id.ref:
		return nil, fmt.Errorf("trust: certificate source ref %q is not %q", ext.SourceRepositoryRef, id.ref)
	case ext.RunnerEnvironment != id.runner:
		return nil, fmt.Errorf("trust: certificate runner environment %q is not %q", ext.RunnerEnvironment, id.runner)
	}

	return verified, nil
}
