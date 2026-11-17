// The attestation-storage read against a real in-process registry: an
// index laid out the way BuildKit writes one — a platform manifest
// with its attestation manifest beside it, a platform with none, and a
// platform whose attestation carries only an SBOM — read back through
// the production client.

package oci_test

import (
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/monumental-archive/stele/internal/oci"
)

const (
	provV02 = "https://slsa.dev/provenance/v0.2"
	spdx    = "https://spdx.dev/Document"
)

// statementLayer is one in-toto layer annotated with its predicate.
func statementLayer(predicateType, body string) mutate.Addendum {
	return mutate.Addendum{
		Layer:       static.NewLayer([]byte(body), types.MediaType("application/vnd.in-toto+json")),
		Annotations: map[string]string{"in-toto.io/predicate-type": predicateType},
	}
}

// attestationFor builds the attestation manifest for one platform
// manifest, carrying the given layers.
func (w *world) attestationFor(t *testing.T, platform v1.Image, layers ...mutate.Addendum) mutate.IndexAddendum {
	t.Helper()

	att, err := mutate.Append(mutate.MediaType(empty.Image, types.OCIManifestSchema1), layers...)
	if err != nil {
		t.Fatalf("building the attestation manifest: %v", err)
	}

	ref, err := platform.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	return mutate.IndexAddendum{
		Add:      att,
		Platform: &v1.Platform{OS: "unknown", Architecture: "unknown"},
		Annotations: map[string]string{
			"vnd.docker.reference.type":   "attestation-manifest",
			"vnd.docker.reference.digest": ref.String(),
		},
	}
}

//nolint:ireturn // go-containerregistry builds images as its Image interface
func platformImage(t *testing.T) v1.Image {
	t.Helper()

	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatalf("building an image: %v", err)
	}

	return img
}

func TestStatements(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	amd64, arm, s390x := platformImage(t), platformImage(t), platformImage(t)

	on := func(arch string) v1.Descriptor {
		return v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}}
	}

	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: s390x, Descriptor: on("s390x")},
		w.attestationFor(t, s390x, statementLayer(spdx, `{"sbom": true}`)),
		mutate.IndexAddendum{Add: amd64, Descriptor: on("amd64")},
		w.attestationFor(t, amd64, statementLayer(spdx, `{"sbom": true}`), statementLayer(provV02, `{"prov": "amd64"}`)),
		mutate.IndexAddendum{
			Add:      arm,
			Platform: &v1.Platform{OS: "linux", Architecture: "arm", Variant: "v7"},
		},
	)

	if err := remote.WriteIndex(w.tag("multi"), idx); err != nil {
		t.Fatalf("pushing the index: %v", err)
	}

	dig, err := idx.Digest()
	if err != nil {
		t.Fatal(err)
	}

	got, err := oci.Client{}.Statements(w.repo, dig.String(), provV02)
	if err != nil {
		t.Fatalf("Statements = %v", err)
	}

	// Platform order; the attestation manifests themselves are not
	// platforms; a platform with no attestation, or with no layer of
	// the asked type, carries no statements and is still listed.
	var lines []string
	for _, p := range got {
		var bodies []string
		for _, s := range p.Statements {
			bodies = append(bodies, string(s))
		}

		lines = append(lines, p.Platform+"="+strings.Join(bodies, "|"))
	}

	want := []string{`linux/amd64={"prov": "amd64"}`, "linux/arm/v7=", "linux/s390x="}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Statements =\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}

	amdDigest, err := amd64.Digest()
	if err != nil {
		t.Fatal(err)
	}

	if got[0].Digest != amdDigest.String() {
		t.Fatalf("digest = %s, want the platform manifest's %s", got[0].Digest, amdDigest)
	}
}

func TestStatementsRefusals(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	if _, err := (oci.Client{}).Statements(w.repo, "not-a-digest", provV02); err == nil ||
		!strings.Contains(err.Error(), "oci: "+w.repo+"@not-a-digest") {
		t.Fatalf("a malformed reference = %v", err)
	}

	if _, err := (oci.Client{}).Statements(w.repo, absentBlob, provV02); err == nil ||
		!strings.Contains(err.Error(), "oci: fetching index") {
		t.Fatalf("an absent index = %v", err)
	}
}
