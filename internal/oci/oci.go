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
	"errors"
	"fmt"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// Reader is the registry-side surface the assert engine judges
// through.
type Reader interface {
	// Resolve reports the digest a tag names right now, or "" when the
	// registry holds nothing under it — a rolling tag pointing at
	// nothing is an answer, not an error.
	//
	// It is the one read here that takes a tag, and it exists because
	// a rolling tag is the only address a continuous publish has: the
	// stream has no version, so "what is published" is a question only
	// the registry can answer, and every read after this one is by the
	// digest it returns. The registry's OWN answer, rather than a
	// platform's package API, because the surface that declares a
	// registry must be readable at any registry — a stranger's
	// included.
	Resolve(image, tag string) (string, error)
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

// Resolve implements Reader. A tag the registry does not hold comes
// back empty rather than as an error: the caller's next move is to
// say so in a report, and an error would make "nothing is published
// under this tag" indistinguishable from "the registry could not be
// reached".
func (Client) Resolve(image, tag string) (string, error) {
	ref, err := name.NewTag(image + ":" + tag)
	if err != nil {
		return "", fmt.Errorf("oci: %s:%s: %w", image, tag, err)
	}

	desc, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
			return "", nil
		}

		return "", fmt.Errorf("oci: resolving %s:%s: %w", image, tag, err)
	}

	return desc.Digest.String(), nil
}

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
