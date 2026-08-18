// The registry read seam against a real in-process distribution
// registry: what this package's guards judge is what the transport
// served, so every branch is exercised over the wire rather than
// through a stand-in Reader. Each case breaks exactly one fact — the
// reference, the manifest, or the config blob.

package oci_test

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/monumental-archive/stele/internal/oci"
)

// absentBlob is a well-formed digest of bytes nothing ever uploaded.
const absentBlob = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// world is one in-process registry and the repository under test. The
// production client parses references with no options, so the test
// cannot hand it an insecure flag: the address must be the "localhost:"
// form, which is the only host name.NewDigest reads as http.
type world struct {
	t    *testing.T
	repo string
}

func newWorld(t *testing.T) *world {
	t.Helper()

	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)

	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parsing %q: %v", srv.URL, err)
	}

	return &world{t: t, repo: "localhost:" + parsed.Port() + "/app"}
}

// tag builds a reference into the repository under test.
func (w *world) tag(ref string) name.Tag {
	w.t.Helper()

	tag, err := name.NewTag(w.repo + ":" + ref)
	if err != nil {
		w.t.Fatalf("tag %s: %v", ref, err)
	}

	return tag
}

// pushImage writes one image, labelled if labels is non-nil, and
// returns the digest it landed at.
func (w *world) pushImage(labels map[string]string) string {
	w.t.Helper()

	img, err := random.Image(256, 1)
	if err != nil {
		w.t.Fatalf("building an image: %v", err)
	}

	if labels != nil {
		if img, err = mutate.Config(img, v1.Config{Labels: labels}); err != nil {
			w.t.Fatalf("setting labels: %v", err)
		}
	}

	if writeErr := remote.Write(w.tag("latest"), img); writeErr != nil {
		w.t.Fatalf("pushing: %v", writeErr)
	}

	dig, err := img.Digest()
	if err != nil {
		w.t.Fatalf("digest: %v", err)
	}

	return dig.String()
}

// pushIndex writes a one-child index — the multi-platform shape the
// assert engine actually reads — and returns the index's digest.
func (w *world) pushIndex() string {
	w.t.Helper()

	img, err := random.Image(256, 1)
	if err != nil {
		w.t.Fatalf("building an image: %v", err)
	}

	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add:        img,
		Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
	})

	if writeErr := remote.WriteIndex(w.tag("index"), idx); writeErr != nil {
		w.t.Fatalf("pushing the index: %v", writeErr)
	}

	dig, err := idx.Digest()
	if err != nil {
		w.t.Fatalf("index digest: %v", err)
	}

	return dig.String()
}

// TestIndexServesTheManifestBytes: a read by digest returns the raw
// manifest the registry holds — an index stays an index, because the
// shape is the engine's to judge, not this seam's to normalise. The
// child it names is then read on its own, so the bytes are proven to
// address real manifests rather than merely to parse.
func TestIndexServesTheManifestBytes(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	got, err := oci.Client{}.Index(w.repo, w.pushIndex())
	if err != nil {
		t.Fatalf("Index = %v", err)
	}

	parsed, err := v1.ParseIndexManifest(strings.NewReader(string(got)))
	if err != nil {
		t.Fatalf("Index returned %s, which is not an index manifest: %v", got, err)
	}

	if !parsed.MediaType.IsIndex() {
		t.Errorf("media type = %s, want the index type unchanged", parsed.MediaType)
	}

	if len(parsed.Manifests) != 1 {
		t.Fatalf("manifests = %d, want the one child pushed", len(parsed.Manifests))
	}

	if _, err := (oci.Client{}).ConfigLabels(w.repo, parsed.Manifests[0].Digest.String()); err != nil {
		t.Errorf("the child the index names does not resolve: %v", err)
	}
}

// TestConfigLabels covers both halves of the documented contract: the
// labels a config carries come back verbatim, and a config with none
// comes back as an empty map — never nil, which every caller would
// otherwise have to guard separately.
func TestConfigLabels(t *testing.T) {
	t.Parallel()

	t.Run("labels come back verbatim", func(t *testing.T) {
		t.Parallel()

		w := newWorld(t)
		digest := w.pushImage(map[string]string{"org.opencontainers.image.revision": "cafe"})

		got, err := oci.Client{}.ConfigLabels(w.repo, digest)
		if err != nil {
			t.Fatalf("ConfigLabels = %v", err)
		}

		if got["org.opencontainers.image.revision"] != "cafe" {
			t.Errorf("ConfigLabels = %v, want the revision label", got)
		}
	})

	t.Run("no labels is an empty map, never nil", func(t *testing.T) {
		t.Parallel()

		w := newWorld(t)

		got, err := oci.Client{}.ConfigLabels(w.repo, w.pushImage(nil))
		if err != nil {
			t.Fatalf("ConfigLabels = %v", err)
		}

		if got == nil {
			t.Fatal("ConfigLabels returned nil — the contract says empty map")
		}

		if len(got) != 0 {
			t.Errorf("ConfigLabels = %v, want empty", got)
		}
	})
}

// TestRefusals walks every way a read can fail: a reference that is
// not a digest at all, a digest the registry does not hold, and a
// manifest whose config blob was never uploaded. Each must surface as
// an error naming the image — never as an empty answer a caller could
// read as "no labels".
func TestRefusals(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.pushImage(nil)

	// Both reads resolve the same reference, so a reference fault is a
	// refusal from either one.
	refs := []struct {
		name   string
		digest string
		want   string
	}{
		{"a tag is not a digest", "latest", "latest"},
		{"a digest the registry does not hold", absentBlob, "fetching"},
	}

	for _, tc := range refs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := (oci.Client{}).Index(w.repo, tc.digest); err == nil {
				t.Error("Index accepted what it must refuse")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Index = %v, want it to name %q", err, tc.want)
			}

			_, err := (oci.Client{}).ConfigLabels(w.repo, tc.digest)
			if err == nil {
				t.Fatal("ConfigLabels accepted what it must refuse")
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ConfigLabels = %v, want it to name %q", err, tc.want)
			}
		})
	}

	// The config blob is read by exactly one of the two, which is why
	// a manifest can be whole while its labels are unreadable.
	t.Run("a config blob nothing uploaded", func(t *testing.T) {
		t.Parallel()

		headless := w.pushConfiglessManifest()

		if _, err := (oci.Client{}).Index(w.repo, headless); err != nil {
			t.Errorf("Index = %v — the manifest itself is intact", err)
		}

		_, err := (oci.Client{}).ConfigLabels(w.repo, headless)
		if err == nil || !strings.Contains(err.Error(), "config of") {
			t.Fatalf("ConfigLabels = %v, want the config refusal", err)
		}
	})
}

// pushConfiglessManifest PUTs an image manifest whose config
// descriptor points at bytes nothing uploaded — the registry stores
// manifests without checking their blobs, so the fault surfaces only
// when the config is read. It returns the manifest's digest.
func (w *world) pushConfiglessManifest() string {
	w.t.Helper()

	const mediaType = "application/vnd.oci.image.manifest.v1+json"

	manifest := `{"schemaVersion":2,"mediaType":"` + mediaType + `",` +
		`"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":2,` +
		`"digest":"` + absentBlob + `"},"layers":[]}`

	slash := strings.Index(w.repo, "/")
	endpoint := "http://" + w.repo[:slash] + "/v2/" + w.repo[slash+1:] + "/manifests/headless"

	req, err := http.NewRequestWithContext(w.t.Context(), http.MethodPut, endpoint, strings.NewReader(manifest))
	if err != nil {
		w.t.Fatalf("building the manifest PUT: %v", err)
	}

	req.Header.Set("Content-Type", mediaType)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatalf("PUT %s: %v", endpoint, err)
	}
	defer resp.Body.Close() //nolint:errcheck // a read-only body close has nothing to report

	if resp.StatusCode != http.StatusCreated {
		w.t.Fatalf("PUT %s = HTTP %d", endpoint, resp.StatusCode)
	}

	return resp.Header.Get("Docker-Content-Digest")
}
