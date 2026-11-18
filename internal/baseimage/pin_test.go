// The pin and the ref it implies, under the canon's own convention:
// `latest` is the continuous stream, built from the default branch; a
// version, optionally class-decorated (1.2.3-pg18), names its tag.

package baseimage_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/baseimage"
)

const pinDigest = "sha256:8fd73f31851b7f982946c5df603c799d75fa96ab88e7fe4018c26ff596664378"

// orgRules is the canon's convention as declared rules.
func orgRules() []baseimage.RefRule {
	return []baseimage.RefRule{
		{Tag: regexp.MustCompile(`^latest$`), Ref: "refs/heads/main"},
		{Tag: regexp.MustCompile(`^(?P<version>\d+\.\d+\.\d+)(-.*)?$`), Ref: "refs/tags/v${version}"},
	}
}

func TestParsePin(t *testing.T) {
	t.Parallel()

	for ref, want := range map[string]baseimage.Pin{
		"ghcr.io/acme/db:latest@" + pinDigest: {Repository: "ghcr.io/acme/db", Tag: "latest", Digest: pinDigest},
		"ghcr.io/acme/ext:1.2.3-pg18@" + pinDigest: {
			Repository: "ghcr.io/acme/ext", Tag: "1.2.3-pg18", Digest: pinDigest,
		},
		"localhost:5000/acme/ext:1@" + pinDigest: {Repository: "localhost:5000/acme/ext", Tag: "1", Digest: pinDigest},
		// Docker's short form resolves as the build resolves it.
		"postgres:14-bookworm@" + pinDigest: {
			Repository: "index.docker.io/library/postgres", Tag: "14-bookworm", Digest: pinDigest,
		},
	} {
		got, err := baseimage.ParsePin(ref)
		if err != nil {
			t.Fatalf("ParsePin(%s) = %v", ref, err)
		}

		want.Ref = ref
		if got != want {
			t.Errorf("ParsePin(%s) = %+v, want %+v", ref, got, want)
		}
	}
}

func TestParsePinRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, ref, want string
	}{
		{
			"no digest — nothing to verify",
			"ghcr.io/acme/db:latest",
			"ghcr.io/acme/db:latest is a first-party base with no digest — there is nothing to verify;" +
				" pin as image:tag@sha256:…",
		},
		{
			"no tag — no ref can be derived",
			"ghcr.io/acme/db@" + pinDigest,
			"ghcr.io/acme/db@" + pinDigest + " carries a digest but no tag, so the ref that produced it cannot be" +
				" derived — pin as image:tag@sha256:… (Renovate rolls both together)",
		},
		{
			// The grammar would default the tag to latest; the pin
			// refuses rather than derive from a tag nobody wrote.
			"a short name with no tag — never defaulted to latest",
			"postgres@" + pinDigest,
			"postgres@" + pinDigest + " carries a digest but no tag",
		},
		{
			"a registry port is not a tag",
			"localhost:5000/acme/db@" + pinDigest,
			"carries a digest but no tag",
		},
		{
			"an empty tag",
			"ghcr.io/acme/db:@" + pinDigest,
			"is not an image reference",
		},
		{
			"a digest that is not one",
			"ghcr.io/acme/db:latest@sha256:abc",
			"ghcr.io/acme/db:latest@sha256:abc: the digest is not sha256:<64 lowercase hex>",
		},
		{
			"not a reference at all",
			"ghcr.io/Acme/db:latest@" + pinDigest,
			"is not an image reference; pin as image:tag@sha256:…",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := baseimage.ParsePin(tt.ref)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ParsePin = %+v, %v; want the refusal %q", got, err, tt.want)
			}
		})
	}
}

// TestParseUpstreamPin holds the upstream reading's own words: the
// same pin form, its refusals naming an upstream base and the source
// its tag derives.
func TestParseUpstreamPin(t *testing.T) {
	t.Parallel()

	got, err := baseimage.ParseUpstreamPin("docker.io/library/postgres:14-bookworm@" + pinDigest)
	if err != nil || got.Repository != "index.docker.io/library/postgres" || got.Tag != "14-bookworm" {
		t.Fatalf("ParseUpstreamPin = %+v, %v", got, err)
	}

	for ref, want := range map[string]string{
		"postgres:14-bookworm": "postgres:14-bookworm is an upstream base with no digest — there is nothing to" +
			" verify; pin as image:tag@sha256:…",
		"postgres@" + pinDigest: "postgres@" + pinDigest + " carries a digest but no tag, so the source it must" +
			" name cannot be derived — pin as image:tag@sha256:… (Renovate rolls both together)",
	} {
		if _, err := baseimage.ParseUpstreamPin(ref); err == nil || err.Error() != want {
			t.Errorf("ParseUpstreamPin(%s) = %v, want %q", ref, err, want)
		}
	}
}

func TestDeriveRef(t *testing.T) {
	t.Parallel()

	for tag, want := range map[string]string{
		"latest":              "refs/heads/main",
		"1.2.3":               "refs/tags/v1.2.3",
		"1.2.3-pg18":          "refs/tags/v1.2.3",
		"1.2.3-pg18-artifact": "refs/tags/v1.2.3",
		"10.20.30":            "refs/tags/v10.20.30",
	} {
		got, err := baseimage.DeriveRef(baseimage.Pin{Ref: "x:" + tag, Tag: tag}, orgRules())
		if err != nil {
			t.Fatalf("DeriveRef(%s) = %v", tag, err)
		}

		if got != want {
			t.Errorf("DeriveRef(%s) = %s, want %s", tag, got, want)
		}
	}

	// The first rule that matches decides, even when a later one would.
	first := []baseimage.RefRule{
		{Tag: regexp.MustCompile(`^1\.`), Ref: "refs/heads/legacy"},
		orgRules()[1],
	}
	if got, err := baseimage.DeriveRef(baseimage.Pin{Tag: "1.2.3"}, first); err != nil || got != "refs/heads/legacy" {
		t.Fatalf("first match = %s, %v", got, err)
	}
}

func TestDeriveRefRefusals(t *testing.T) {
	t.Parallel()

	for _, tag := range []string{"nightly", "1.2", "v1.2.3", "1.2.3+build", "latest-pg18"} {
		_, err := baseimage.DeriveRef(baseimage.Pin{Ref: "ghcr.io/acme/db:" + tag, Tag: tag}, orgRules())

		want := "ghcr.io/acme/db:" + tag + ": cannot derive the ref that produced it from tag '" + tag +
			"' — the declared tags are ^latest$, ^(?P<version>\\d+\\.\\d+\\.\\d+)(-.*)?$"
		if err == nil || err.Error() != want {
			t.Errorf("DeriveRef(%s) = %v, want %q", tag, err, want)
		}
	}
}
