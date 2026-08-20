// Every divergence class the image-facts assertion exists to catch
// is a row: the silent buildx annotation drop (a Docker manifest
// list), per-key annotation and label drift in both directions, the
// hygiene re-check, and the coverage guards — an index with no
// platform manifests cannot pass, and a registry read that dies is
// an error, never a verdict.

package assert_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/report"
)

const (
	testImage  = "ghcr.io/acme/widget"
	testDigest = "sha256:" + hex64
	hex64      = "1111111111111111111111111111111111111111111111111111111111111111"
	childA     = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	childB     = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

const goodFacts = `{"org.opencontainers.image.revision": "abc", "org.opencontainers.image.version": "1.2.3"}`

// fakeRegistry scripts the Reader.
type fakeRegistry struct {
	index     string
	indexErr  error
	labels    map[string]map[string]string
	labelsErr error
}

func (f fakeRegistry) Index(_, _ string) ([]byte, error) {
	if f.indexErr != nil {
		return nil, f.indexErr
	}

	return []byte(f.index), nil
}

func (f fakeRegistry) ConfigLabels(_, digest string) (map[string]string, error) {
	if f.labelsErr != nil {
		return nil, f.labelsErr
	}

	return f.labels[digest], nil
}

// goodIndex renders an OCI index whose annotations equal goodFacts,
// with two platform children and one BuildKit attestation manifest
// (unknown/unknown) that must be skipped.
func goodIndex() string {
	return `{
	  "schemaVersion": 2,
	  "mediaType": "application/vnd.oci.image.index.v1+json",
	  "annotations": {"org.opencontainers.image.revision": "abc", "org.opencontainers.image.version": "1.2.3"},
	  "manifests": [
	    {"digest": "` + childA + `", "platform": {"os": "linux", "architecture": "amd64"}},
	    {"digest": "` + childB + `", "platform": {"os": "linux", "architecture": "arm64"}},
	    {"digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
	     "platform": {"os": "unknown", "architecture": "unknown"}}
	  ]
	}`
}

func goodLabels() map[string]map[string]string {
	m := map[string]string{
		"org.opencontainers.image.revision": "abc",
		"org.opencontainers.image.version":  "1.2.3",
	}

	return map[string]map[string]string{childA: m, childB: m}
}

func discard(string, ...any) {}

func TestImageFactsVerdicts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		reg     fakeRegistry
		facts   string
		want    report.Verdict
		finding string // substring of some finding's detail; "" = none expected
	}{
		{
			"published image equal to the facts map passes",
			fakeRegistry{index: goodIndex(), labels: goodLabels()},
			goodFacts, report.VerdictPass, "",
		},
		{
			"docker manifest list fails — annotations were dropped silently",
			fakeRegistry{
				index: strings.Replace(goodIndex(),
					"application/vnd.oci.image.index.v1+json",
					"application/vnd.docker.distribution.manifest.list.v2+json", 1),
				labels: goodLabels(),
			},
			goodFacts, report.VerdictFail, "not an OCI index",
		},
		{
			"a drifted index annotation names its key",
			fakeRegistry{
				index:  strings.Replace(goodIndex(), `image.revision": "abc"`, `image.revision": "zzz"`, 1),
				labels: goodLabels(),
			},
			goodFacts, report.VerdictFail, "diverges",
		},
		{
			"an index annotation missing from the published bytes fails",
			fakeRegistry{
				index: strings.Replace(goodIndex(),
					`"org.opencontainers.image.revision": "abc", `, "", 1),
				labels: goodLabels(),
			},
			goodFacts, report.VerdictFail, "absent",
		},
		{
			"a surplus published annotation fails — equality, not presence",
			fakeRegistry{
				index: strings.Replace(goodIndex(),
					`"org.opencontainers.image.version": "1.2.3"`,
					`"org.opencontainers.image.version": "1.2.3", "extra": "x"`, 1),
				labels: goodLabels(),
			},
			goodFacts, report.VerdictFail, "not in the facts map",
		},
		{
			"a drifted per-arch config label fails",
			fakeRegistry{
				index: goodIndex(),
				labels: map[string]map[string]string{
					childA: goodLabels()[childA],
					childB: {
						"org.opencontainers.image.revision": "zzz",
						"org.opencontainers.image.version":  "1.2.3",
					},
				},
			},
			goodFacts, report.VerdictFail, "diverges",
		},
		{
			"an empty fact value fails hygiene independently of the registry",
			fakeRegistry{index: goodIndex(), labels: goodLabels()},
			`{"org.opencontainers.image.revision": "abc", "org.opencontainers.image.version": "1.2.3", "empty": ""}`,
			report.VerdictFail, "is empty",
		},
		{
			"a control character in a fact value fails hygiene",
			fakeRegistry{index: goodIndex(), labels: goodLabels()},
			`{"org.opencontainers.image.revision": "abc", "org.opencontainers.image.version": "1.2.3", "ctl": "a\u0007b"}`,
			report.VerdictFail, "control characters",
		},
		{
			"an index with no platform manifests cannot pass",
			fakeRegistry{
				index: `{"mediaType": "application/vnd.oci.image.index.v1+json",
				  "annotations": {"org.opencontainers.image.revision": "abc", "org.opencontainers.image.version": "1.2.3"},
				  "manifests": []}`,
				labels: goodLabels(),
			},
			goodFacts, report.VerdictCannotJudge, "",
		},
		{
			"attestation-only children cannot pass either — nothing judgeable",
			fakeRegistry{
				index: `{"mediaType": "application/vnd.oci.image.index.v1+json",
				  "annotations": {"org.opencontainers.image.revision": "abc", "org.opencontainers.image.version": "1.2.3"},
				  "manifests": [{"digest": "` + childA + `", "platform": {"os": "unknown", "architecture": "unknown"}}]}`,
				labels: goodLabels(),
			},
			goodFacts, report.VerdictCannotJudge, "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rep, err := assert.ImageFacts(testImage, testDigest, []byte(tt.facts), tt.reg, report.NewJournal(), discard)
			if err != nil {
				t.Fatalf("ImageFacts: %v", err)
			}

			if got := rep.Verdict(); got != tt.want {
				t.Fatalf("verdict = %s, want %s\nfindings: %+v", got, tt.want, rep.Findings())
			}

			if tt.finding == "" {
				return
			}

			found := false

			for _, f := range rep.Findings() {
				if strings.Contains(f.Detail, tt.finding) {
					found = true
				}
			}

			if !found {
				t.Fatalf("no finding contains %q: %+v", tt.finding, rep.Findings())
			}
		})
	}
}

// TestImageFactsRefusals pins the error paths: malformed inputs and
// dead registry reads refuse with an error — never a verdict.
func TestImageFactsRefusals(t *testing.T) {
	t.Parallel()

	reg := fakeRegistry{index: goodIndex(), labels: goodLabels()}

	tests := []struct {
		name   string
		image  string
		digest string
		facts  string
		reg    fakeRegistry
		want   string
	}{
		{"empty image", "", testDigest, goodFacts, reg, "IMAGE is required"},
		{"malformed digest", testImage, "sha256:short", goodFacts, reg, "not a sha256 digest"},
		{"facts not a flat map", testImage, testDigest, `{"a": {"b": "c"}}`, reg, "flat string map"},
		{"facts with trailing data", testImage, testDigest, `{"a": "b"} {}`, reg, "flat string map"},
		{
			"index fetch dies", testImage, testDigest, goodFacts,
			fakeRegistry{indexErr: errors.New("registry torn")},
			"registry torn",
		},
		{
			"index bytes are not a manifest", testImage, testDigest, goodFacts,
			fakeRegistry{index: "not json"},
			"index at",
		},
		{
			"config fetch dies", testImage, testDigest, goodFacts,
			fakeRegistry{index: goodIndex(), labelsErr: errors.New("config torn")},
			"config torn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := assert.ImageFacts(tt.image, tt.digest, []byte(tt.facts), tt.reg, report.NewJournal(), discard)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}
