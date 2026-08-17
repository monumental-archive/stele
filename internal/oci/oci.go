// Package oci is the registry read seam: the assert engine's view of
// a published image, interface-shaped so every guard branch is
// reachable from a table test. The production implementation speaks
// the OCI distribution API through go-containerregistry — no docker
// daemon, so the buildx pathway that silently drops index
// annotations (docker/buildx#1965) is not even in the process. Reads
// are by digest and digest-validated by the transport: the bytes
// judged are the bytes a stranger pulls, or an error.
package oci

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Reader is the registry-side surface the assert engine judges
// through.
type Reader interface {
	// Index fetches the raw manifest bytes at image@digest — an index
	// or a single manifest; the engine judges the shape.
	Index(image, digest string) ([]byte, error)
	// ConfigLabels fetches the image config's labels for one child
	// manifest at image@digest. A config with no labels is an empty
	// map, never nil.
	ConfigLabels(image, digest string) (map[string]string, error)
}

// Client is the production Reader over the live registry, using the
// ambient keychain (the same credentials docker login writes).
type Client struct{}

// Index implements Reader.
func (Client) Index(image, digest string) ([]byte, error) {
	ref, err := name.NewDigest(image + "@" + digest)
	if err != nil {
		return nil, fmt.Errorf("oci: %s@%s: %w", image, digest, err)
	}

	desc, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, fmt.Errorf("oci: fetching %s@%s: %w", image, digest, err)
	}

	return desc.Manifest, nil
}

// ConfigLabels implements Reader.
func (Client) ConfigLabels(image, digest string) (map[string]string, error) {
	ref, err := name.NewDigest(image + "@" + digest)
	if err != nil {
		return nil, fmt.Errorf("oci: %s@%s: %w", image, digest, err)
	}

	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, fmt.Errorf("oci: fetching image %s@%s: %w", image, digest, err)
	}

	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("oci: config of %s@%s: %w", image, digest, err)
	}

	if cfg.Config.Labels == nil {
		return map[string]string{}, nil
	}

	return cfg.Config.Labels, nil
}
