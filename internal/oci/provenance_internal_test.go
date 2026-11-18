// The attestation walk's degraded reads, one per guard: each row wraps
// a real in-memory index and breaks exactly one read beneath it.

package oci

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const provType = "https://slsa.dev/provenance/v0.2"

var errBroken = errors.New("broken read")

// realIndex renames the interface so embedding it does not collide
// with the ImageIndex method every index carries.
type realIndex interface{ v1.ImageIndex }

// brokenIndex is a real index with one read broken.
type brokenIndex struct {
	realIndex

	manifest bool
	image    bool
	wrap     func(v1.Image) v1.Image
}

func (b brokenIndex) IndexManifest() (*v1.IndexManifest, error) {
	if b.manifest {
		return nil, errBroken
	}

	m, err := b.realIndex.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("index manifest: %w", err)
	}

	return m, nil
}

//nolint:ireturn // go-containerregistry's ImageIndex contract returns its Image interface
func (b brokenIndex) Image(h v1.Hash) (v1.Image, error) {
	if b.image {
		return nil, errBroken
	}

	img, err := b.realIndex.Image(h)
	if err != nil {
		return nil, fmt.Errorf("image: %w", err)
	}

	if b.wrap == nil {
		return img, nil
	}

	return b.wrap(img), nil
}

// brokenImage is a real attestation manifest with one read broken.
type brokenImage struct {
	v1.Image

	manifest, byDigest bool
	layer              func(v1.Layer) v1.Layer
}

func (b brokenImage) Manifest() (*v1.Manifest, error) {
	if b.manifest {
		return nil, errBroken
	}

	m, err := b.Image.Manifest()
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}

	return m, nil
}

//nolint:ireturn // go-containerregistry's Image contract returns its Layer interface
func (b brokenImage) LayerByDigest(h v1.Hash) (v1.Layer, error) {
	if b.byDigest {
		return nil, errBroken
	}

	l, err := b.Image.LayerByDigest(h)
	if err != nil {
		return nil, fmt.Errorf("layer: %w", err)
	}

	if b.layer == nil {
		return l, nil
	}

	return b.layer(l), nil
}

// brokenLayer is a real layer whose bytes do not arrive: refused at
// open, or breaking off after the first byte.
type brokenLayer struct {
	v1.Layer

	open bool
}

func (b brokenLayer) Compressed() (io.ReadCloser, error) {
	if b.open {
		return nil, errBroken
	}

	return io.NopCloser(io.MultiReader(strings.NewReader("{"), errReader{})), nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errBroken }

// attestedIndex is one platform and its attestation, carrying body as
// its provenance statement.
//
//nolint:ireturn // go-containerregistry builds indexes as its ImageIndex interface
func attestedIndex(t *testing.T, body []byte) v1.ImageIndex {
	t.Helper()

	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}

	dig, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}

	att, err := mutate.Append(mutate.MediaType(empty.Image, types.OCIManifestSchema1), mutate.Addendum{
		Layer:       static.NewLayer(body, types.MediaType(mediaTypeInToto)),
		Annotations: map[string]string{annotationPredicate: provType},
	})
	if err != nil {
		t.Fatal(err)
	}

	return mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: img, Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
		mutate.IndexAddendum{
			Add:         att,
			Platform:    &v1.Platform{OS: "unknown", Architecture: "unknown"},
			Annotations: map[string]string{annotationRefType: refTypeAttestation, annotationRefDigest: dig.String()},
		},
	)
}

func TestIndexStatementsRefusals(t *testing.T) {
	t.Parallel()

	whole := attestedIndex(t, []byte(`{"prov": true}`))

	tests := []struct {
		name string
		idx  v1.ImageIndex
		want string
	}{
		{"the index manifest", brokenIndex{realIndex: whole, manifest: true}, "oci: index manifest: broken read"},
		{
			"the attestation manifest",
			brokenIndex{realIndex: whole, image: true},
			"oci: attestations of linux/amd64: fetching",
		},
		{
			"the attestation manifest's own manifest",
			brokenIndex{realIndex: whole, wrap: func(i v1.Image) v1.Image { return brokenImage{Image: i, manifest: true} }},
			"oci: attestations of linux/amd64: manifest",
		},
		{
			"the statement layer",
			brokenIndex{realIndex: whole, wrap: func(i v1.Image) v1.Image { return brokenImage{Image: i, byDigest: true} }},
			"oci: attestations of linux/amd64: layer",
		},
		{
			"the statement's bytes, at open",
			brokenIndex{realIndex: whole, wrap: func(i v1.Image) v1.Image {
				return brokenImage{Image: i, layer: func(l v1.Layer) v1.Layer { return brokenLayer{Layer: l, open: true} }}
			}},
			"broken read",
		},
		{
			"the statement's bytes, mid-read",
			brokenIndex{realIndex: whole, wrap: func(i v1.Image) v1.Image {
				return brokenImage{Image: i, layer: func(l v1.Layer) v1.Layer { return brokenLayer{Layer: l} }}
			}},
			"broken read",
		},
		{
			"a statement larger than a statement may be",
			attestedIndex(t, bytes.Repeat([]byte("x"), maxStatementBytes+1)),
			"is larger than a statement may be",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := indexStatements(tt.idx, provType)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("indexStatements = %v, %v; want the refusal %q", got, err, tt.want)
			}
		})
	}
}

func TestPlatformName(t *testing.T) {
	t.Parallel()

	for p, want := range map[*v1.Platform]string{
		nil:                                  "unknown/unknown",
		{OS: "linux", Architecture: "amd64"}: "linux/amd64",
		{OS: "linux", Architecture: "arm64", Variant: "v8"}: "linux/arm64/v8",
	} {
		if got := platformName(p); got != want {
			t.Errorf("platformName(%v) = %s, want %s", p, got, want)
		}
	}
}
