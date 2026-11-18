// This file: the provenance an image index carries in BuildKit's
// attestation storage — the standard layout docker buildx writes and a
// Docker Official Image publishes (stele#392's sibling, stele#402). An
// index holds, beside each platform manifest, an attestation manifest
// with platform unknown/unknown whose annotations name the platform
// manifest it describes; its layers are in-toto statements, each
// annotated with its predicate type. Nothing here judges a statement:
// it reads what the index carries, platform by platform, and says which
// platforms carry none.

package oci

import (
	"fmt"
	"io"
	"sort"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// The attestation-storage vocabulary, as BuildKit writes it.
const (
	annotationRefType     = "vnd.docker.reference.type"
	annotationRefDigest   = "vnd.docker.reference.digest"
	refTypeAttestation    = "attestation-manifest"
	annotationPredicate   = "in-toto.io/predicate-type"
	mediaTypeInToto       = "application/vnd.in-toto+json"
	maxStatementBytes     = 16 << 20
	unknownPlatformMarker = "unknown"
)

// PlatformStatements is one platform manifest of an index and the
// in-toto statements of the asked predicate type its attestation
// manifest carries — none when it carries none, or has no attestation
// manifest at all. Statements are the layer bytes as served.
type PlatformStatements struct {
	Platform   string
	Digest     string
	Statements [][]byte
}

// StatementReader reads the attestation statements an index carries.
// Its own interface rather than a method on Reader, so the readers that
// never ask it keep their surface.
type StatementReader interface {
	// Statements returns every platform manifest of the index at
	// image@digest, in platform order, each with the statements of
	// predicateType its attestation manifest carries. Only layers
	// annotated with that predicate type are fetched: an index also
	// carries SBOM layers megabytes large that this read never needs.
	Statements(image, digest, predicateType string) ([]PlatformStatements, error)
}

// Statements implements StatementReader.
func (Client) Statements(image, digest, predicateType string) ([]PlatformStatements, error) {
	ref, err := name.NewDigest(image + "@" + digest)
	if err != nil {
		return nil, fmt.Errorf("oci: %s@%s: %w", image, digest, err)
	}

	idx, err := remote.Index(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, fmt.Errorf("oci: fetching index %s@%s: %w", image, digest, err)
	}

	return indexStatements(idx, predicateType)
}

// indexStatements walks one index: the platform manifests, and for each
// the attestation manifest that names it.
func indexStatements(idx v1.ImageIndex, predicateType string) ([]PlatformStatements, error) {
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("oci: index manifest: %w", err)
	}

	attestations := map[string]v1.Hash{}

	var platforms []PlatformStatements

	for i := range im.Manifests {
		d := &im.Manifests[i]

		if d.Annotations[annotationRefType] == refTypeAttestation {
			attestations[d.Annotations[annotationRefDigest]] = d.Digest

			continue
		}

		platforms = append(platforms, PlatformStatements{Platform: platformName(d.Platform), Digest: d.Digest.String()})
	}

	sort.Slice(platforms, func(i, j int) bool { return platforms[i].Platform < platforms[j].Platform })

	for i := range platforms {
		att, ok := attestations[platforms[i].Digest]
		if !ok {
			continue
		}

		statements, err := attestationStatements(idx, att, predicateType)
		if err != nil {
			return nil, fmt.Errorf("oci: attestations of %s: %w", platforms[i].Platform, err)
		}

		platforms[i].Statements = statements
	}

	return platforms, nil
}

// attestationStatements reads the statements of one predicate type from
// one attestation manifest.
func attestationStatements(idx v1.ImageIndex, att v1.Hash, predicateType string) ([][]byte, error) {
	img, err := idx.Image(att)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", att, err)
	}

	m, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("manifest %s: %w", att, err)
	}

	var out [][]byte

	for i := range m.Layers {
		l := &m.Layers[i]

		if string(l.MediaType) != mediaTypeInToto || l.Annotations[annotationPredicate] != predicateType {
			continue
		}

		statement, err := readLayer(img, l.Digest)
		if err != nil {
			return nil, err
		}

		out = append(out, statement)
	}

	return out, nil
}

// readLayer reads one statement layer's bytes, bounded. The registry
// transport verifies the bytes against the layer's digest as they are
// read, so what is returned is what the manifest names.
func readLayer(img v1.Image, digest v1.Hash) ([]byte, error) {
	layer, err := img.LayerByDigest(digest)
	if err != nil {
		return nil, fmt.Errorf("layer %s: %w", digest, err)
	}

	rc, err := layer.Compressed()
	if err != nil {
		return nil, fmt.Errorf("layer %s: %w", digest, err)
	}
	defer rc.Close() //nolint:errcheck // a read-only body close has nothing to report

	b, err := io.ReadAll(io.LimitReader(rc, maxStatementBytes+1))
	if err != nil {
		return nil, fmt.Errorf("layer %s: %w", digest, err)
	}

	if len(b) > maxStatementBytes {
		return nil, fmt.Errorf("layer %s is larger than a statement may be", digest)
	}

	return b, nil
}

// platformName renders a platform the way the OCI spec spells it:
// os/architecture[/variant].
func platformName(p *v1.Platform) string {
	if p == nil {
		return unknownPlatformMarker + "/" + unknownPlatformMarker
	}

	out := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		out += "/" + p.Variant
	}

	return out
}
