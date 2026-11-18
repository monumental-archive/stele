// The workflow identity in the synthesized world: a base published by
// another run, signed by the org's signer workflow at whatever commit
// that run's tree pinned. One row per anchor, each breaking only that
// anchor of a real signed attestation and asserting the refusal.

package trust_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/trust"
)

const (
	signerWorkflow = "https://github.com/acme/signer/.github/workflows/sign.yml"
	sourceRef      = "refs/tags/v1.2.3"
	hosted         = "github-hosted"

	// The canon's measured case: the base was signed at one signer
	// commit, the tree verifying it pins another.
	signedAt = "e4a285f8e4a285f8e4a285f8e4a285f8e4a285f8"
)

// The Fulcio extension arcs the world mints.
const (
	extRunner = 11
	extRef    = 14
	extOwner  = 16
)

// published is one base another run published: its SAN, its
// certificate's extensions, and the statement it signed.
type published struct {
	san  string
	exts map[int]string
}

func orgBase() published {
	return published{
		san: signerWorkflow + "@" + signedAt,
		exts: map[int]string{
			extRunner: hosted,
			extRef:    sourceRef,
			extOwner:  "https://github.com/acme",
		},
	}
}

// attestPublished mints the base's attestation in w, with p's SAN and
// extensions.
func attestPublished(t *testing.T, w *world, p published, body []byte) *entity {
	t.Helper()

	leaf, key := w.issueLeaf(t, &leafSpec{
		san: p.san, issuer: issuer, exts: p.exts,
		notBefore: time.Unix(worldEpoch-300, 0), notAfter: time.Unix(worldEpoch+300, 0),
	})

	return w.attestWithLeaf(t, leaf, key, body)
}

func orgIdentity(t *testing.T) *trust.WorkflowIdentity {
	t.Helper()

	id, err := trust.NewWorkflowIdentity(signerWorkflow, issuer, "acme", sourceRef, hosted)
	if err != nil {
		t.Fatalf("NewWorkflowIdentity = %v", err)
	}

	return &id
}

func TestVerifyFromWorkflow(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	v, err := trust.NewVerifier(w.material(t))
	if err != nil {
		t.Fatal(err)
	}

	body := statementOver([]byte("the base's index"))
	digestHex := digestOf([]byte("the base's index"))

	// The relaxation, and only it: the signer at a commit the verifying
	// tree does not pin still verifies, and so does any other.
	for _, at := range []string{signedAt, "e90a971ee90a971ee90a971ee90a971ee90a971e", "refs/heads/main"} {
		p := orgBase()
		p.san = signerWorkflow + "@" + at

		got, verr := v.VerifyFromWorkflow(attestPublished(t, w, p, body), orgIdentity(t), algSHA256, digestHex)
		if verr != nil {
			t.Fatalf("signed at %s: VerifyFromWorkflow = %v", at, verr)
		}

		if !bytes.Equal(got.Payload, body) || got.SAN != p.san {
			t.Fatalf("signed at %s: payload %q, SAN %q", at, got.Payload, got.SAN)
		}
	}
}

func TestVerifyFromWorkflowRefusals(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	v, err := trust.NewVerifier(w.material(t))
	if err != nil {
		t.Fatal(err)
	}

	body := statementOver([]byte("the base's index"))
	digestHex := digestOf([]byte("the base's index"))
	other := sha256.Sum256([]byte("other bytes"))

	edit := func(f func(*published)) published {
		p := orgBase()
		f(&p)

		return p
	}

	tests := []struct {
		name   string
		signed published
		digest string
		want   string
	}{
		{
			"signed by another workflow in the signer repository",
			edit(func(p *published) { p.san = "https://github.com/acme/signer/.github/workflows/other.yml@" + signedAt }),
			digestHex, "trust: verify",
		},
		{
			"signed by the same path in another repository",
			edit(func(p *published) { p.san = "https://github.com/acme/forked-signer/.github/workflows/sign.yml@x" }),
			digestHex, "trust: verify",
		},
		{
			"signed by the same path on another host",
			edit(func(p *published) { p.san = "https://evil.example/acme/signer/.github/workflows/sign.yml@x" }),
			digestHex, "trust: verify",
		},
		{
			"a path that only starts like the signer's",
			edit(func(p *published) { p.san = signerWorkflow + ".evil.yml@" + signedAt }),
			digestHex, "trust: verify",
		},
		{
			"a SAN with no ref at all",
			edit(func(p *published) { p.san = signerWorkflow }),
			digestHex, "trust: verify",
		},
		{
			"built from another owner's repository",
			edit(func(p *published) { p.exts[extOwner] = "https://github.com/mallory" }),
			digestHex,
			`trust: certificate source owner "https://github.com/mallory" is not "https://github.com/acme"`,
		},
		{
			"built at another ref",
			edit(func(p *published) { p.exts[extRef] = "refs/heads/feature" }),
			digestHex, `trust: certificate source ref "refs/heads/feature" is not "refs/tags/v1.2.3"`,
		},
		{
			"built on a self-hosted runner",
			edit(func(p *published) { p.exts[extRunner] = "self-hosted" }),
			digestHex, `trust: certificate runner environment "self-hosted" is not "github-hosted"`,
		},
		{
			"a certificate that states no runner",
			edit(func(p *published) { delete(p.exts, extRunner) }),
			digestHex, `trust: certificate runner environment "" is not "github-hosted"`,
		},
		{"other bytes than were signed", orgBase(), hex.EncodeToString(other[:]), "trust: verify"},
		{"a digest that is not hex", orgBase(), "zz", "trust: artifact digest is not hex"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := v.VerifyFromWorkflow(attestPublished(t, w, tt.signed, body), orgIdentity(t), algSHA256, tt.digest)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("VerifyFromWorkflow = %+v, %v; want the refusal %q", got, err, tt.want)
			}
		})
	}

	// A bare signature over the bytes attests nothing, whoever made it.
	artifact := []byte("the base's index")
	bare := w.sign(t, signerWorkflow+"@"+signedAt, issuer, artifact)

	if _, berr := v.VerifyFromWorkflow(bare, orgIdentity(t), algSHA256, digestOf(artifact)); berr == nil ||
		!strings.Contains(berr.Error(), "carries no DSSE envelope") {
		t.Fatalf("a bare signature = %v", berr)
	}

	// The issuer is exact too.
	id, ierr := trust.NewWorkflowIdentity(signerWorkflow, "https://issuer.example.com", "acme", sourceRef, hosted)
	if ierr != nil {
		t.Fatal(ierr)
	}

	if _, verr := v.VerifyFromWorkflow(attestPublished(t, w, orgBase(), body), &id, algSHA256, digestHex); verr == nil ||
		!strings.Contains(verr.Error(), "trust: verify") {
		t.Fatalf("another issuer = %v", verr)
	}

	// A zero identity is not one: it can only come from not using the
	// constructor, and it verifies nothing.
	for _, zero := range []*trust.WorkflowIdentity{nil, {}} {
		if _, zerr := v.VerifyFromWorkflow(attestPublished(t, w, orgBase(), body), zero, algSHA256,
			digestHex); zerr == nil || !strings.Contains(zerr.Error(), "built by NewWorkflowIdentity") {
			t.Fatalf("a zero identity = %v", zerr)
		}
	}
}

func TestNewWorkflowIdentityRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                                    string
		workflow, iss, owner, ref, runner, want string
	}{
		{"no workflow", "", issuer, "acme", sourceRef, hosted, `trust: workflow "" is not`},
		{
			"a workflow with a ref", signerWorkflow + "@main", issuer, "acme", sourceRef, hosted,
			"with no ref",
		},
		{
			"a plain-http workflow", "http://github.com/acme/signer/.github/workflows/sign.yml", issuer, "acme",
			sourceRef, hosted, "is not https://",
		},
		{"a workflow with no path", "https://github.com", issuer, "acme", sourceRef, hosted, "is not https://"},
		{
			"a workflow that is no workflow file", "https://github.com/acme/signer/README.md", issuer, "acme",
			sourceRef, hosted, "is not https://",
		},
		{"a workflow with a query", signerWorkflow + "?ref=x", issuer, "acme", sourceRef, hosted, "is not https://"},
		{"no issuer", signerWorkflow, "", "acme", sourceRef, hosted, `trust: issuer "" is not an https URL`},
		{"no owner", signerWorkflow, issuer, "", sourceRef, hosted, `trust: source owner "" is not an owner name`},
		{"an owner with a path", signerWorkflow, issuer, "acme/signer", sourceRef, hosted, "is not an owner name"},
		{"no source ref", signerWorkflow, issuer, "acme", "", hosted, `trust: source ref "" is not a fully qualified ref`},
		{"a bare tag", signerWorkflow, issuer, "acme", "v1.2.3", hosted, "is not a fully qualified ref"},
		{"no runner requirement", signerWorkflow, issuer, "acme", sourceRef, "", "the runner environment is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := trust.NewWorkflowIdentity(tt.workflow, tt.iss, tt.owner, tt.ref, tt.runner)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("NewWorkflowIdentity = %v, want the refusal %q", err, tt.want)
			}
		})
	}

	if got := orgIdentity(t).String(); got !=
		signerWorkflow+"@* from https://github.com/acme at refs/tags/v1.2.3 on github-hosted" {
		t.Fatalf("String = %s", got)
	}
}
