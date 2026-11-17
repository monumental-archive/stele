// The upstream entries beside the scopes: their grammar at load, and
// the judgment of one official image under one entry — the tag read,
// the caller's binding held, the provenance judged — each refusal
// asserting its message.

package assert_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/assert"
	"github.com/monumental-archive/stele/internal/baseimage"
	"github.com/monumental-archive/stele/internal/oci"
)

const (
	pgEntry = `{"image": "docker.io/library/postgres",
	  "tagPattern": "^(?P<major>[0-9]+)-(?P<suite>[a-z]+)$",
	  "source": "https://github.com/docker-library/postgres.git",
	  "path": "${major}/${suite}"}`
	pgPinDigest = "sha256:a54c8b1e143b22f16b0fd3e249e9297a6f08828a143ee7108b1b5ca51f352765"
	pgPinRef    = "docker.io/library/postgres:14-bookworm@" + pgPinDigest
	pgSourceURI = "https://github.com/docker-library/postgres.git#9becbc9d:14/bookworm"
)

// upstreamPolicy loads a store policy whose baseImages section carries
// the given JSON members.
func upstreamPolicy(t *testing.T, members string) *assert.Policy {
	t.Helper()

	pol, err := assert.LoadPolicy(strings.NewReader(storePolicy(`"baseImages": {` + members + `}`)))
	if err != nil {
		t.Fatalf("LoadPolicy = %v", err)
	}

	return pol
}

func TestUpstreamLoads(t *testing.T) {
	t.Parallel()

	// An org may verify only upstream images: the scopes are not owed.
	pol := upstreamPolicy(t, `"upstream": [`+pgEntry+`]`)
	if len(pol.Evidence.BaseImages.Upstream) != 1 || len(pol.Evidence.BaseImages.Scopes) != 0 {
		t.Fatalf("baseImages = %+v", pol.Evidence.BaseImages)
	}

	if pol = upstreamPolicy(t, `"scopes": [`+provenanceScopeJSON+`], "upstream": [`+pgEntry+`]`); len(
		pol.Evidence.BaseImages.Upstream,
	) != 1 {
		t.Fatal("scopes and upstream together did not both load")
	}
}

func TestUpstreamRefusals(t *testing.T) {
	t.Parallel()

	with := func(from, to string) string {
		return `"upstream": [` + strings.Replace(pgEntry, from, to, 1) + `]`
	}

	tests := []struct {
		name, members, want string
	}{
		{"no image", with(`"image": "docker.io/library/postgres",`, ""), "upstream[0].image is absent or empty"},
		{
			"no tag pattern", with(`"tagPattern": "^(?P<major>[0-9]+)-(?P<suite>[a-z]+)$",`, ""),
			"upstream[0].tagPattern is absent or empty",
		},
		{
			"no source", with(`"source": "https://github.com/docker-library/postgres.git",`, ""),
			"upstream[0].source is absent or empty",
		},
		{"no path", with(`,
	  "path": "${major}/${suite}"`, ""), "upstream[0].path is absent or empty"},
		{
			"a tagged image", with(`"docker.io/library/postgres"`, `"docker.io/library/postgres:14"`),
			`upstream[0].image "docker.io/library/postgres:14" is not an untagged image reference`,
		},
		{
			"an image that is not one", with(`"docker.io/library/postgres"`, `"docker.io/Library/postgres"`),
			"is not an untagged image reference",
		},
		{
			"an unanchored tag pattern", with(`"^(?P<major>[0-9]+)-(?P<suite>[a-z]+)$"`, `"(?P<major>[0-9]+)"`),
			`upstream[0].tagPattern "(?P<major>[0-9]+)" is not anchored`,
		},
		{
			"a tag pattern that does not compile", with(`"^(?P<major>[0-9]+)-(?P<suite>[a-z]+)$"`, `"^(?P<major>$"`),
			"upstream[0].tagPattern:",
		},
		{
			"a path naming a group the pattern never captures", with(`"${major}/${suite}"`, `"${major}/${variant}"`),
			`upstream[0].path names the capture group "variant", which its pattern does not define`,
		},
		{"a source that is not https", with(`"https://github.com/docker-library/postgres.git"`,
			`"git://github.com/docker-library/postgres.git"`), "upstream[0].source"},
		{"a source carrying a ref", with(`"https://github.com/docker-library/postgres.git"`,
			`"https://github.com/docker-library/postgres.git#main"`), "is not an https repository URL"},
		{
			"one image twice", `"upstream": [` + pgEntry + `, ` + strings.Replace(pgEntry,
				`"docker.io/library/postgres"`, `"index.docker.io/library/postgres"`, 1) + `]`,
			"upstream[1].image \"index.docker.io/library/postgres\" is declared twice",
		},
		{
			"an image under a first-party prefix", `"scopes": [` + provenanceScopeJSON + `], "upstream": [` +
				strings.Replace(pgEntry, `"docker.io/library/postgres"`, `"ghcr.io/acme/postgres"`, 1) + `]`,
			`upstream[0].image "ghcr.io/acme/postgres" is under scope org-bases's prefix — one reference, one judgment`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := assert.LoadPolicy(strings.NewReader(storePolicy(`"baseImages": {` + tt.members + `}`)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("LoadPolicy = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

// statements scripts the registry's provenance read.
type statements struct {
	platforms []oci.PlatformStatements
	err       error
}

func (s statements) Statements(_, _, _ string) ([]oci.PlatformStatements, error) {
	return s.platforms, s.err
}

func pgPlatforms(uri string) []oci.PlatformStatements {
	st := `{"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://slsa.dev/provenance/v0.2",` +
		` "predicate": {"invocation": {"configSource": {"uri": "` + uri + `"}}}}`

	return []oci.PlatformStatements{
		{Platform: "linux/amd64", Statements: [][]byte{[]byte(st)}},
		{Platform: "linux/arm64/v8", Statements: [][]byte{[]byte(st)}},
	}
}

func pgPin(t *testing.T, ref string) baseimage.Pin {
	t.Helper()

	pin, err := baseimage.ParsePin(ref)
	if err != nil {
		t.Fatal(err)
	}

	return pin
}

func TestUpstreamJudgment(t *testing.T) {
	t.Parallel()

	entry := &upstreamPolicy(t, `"upstream": [`+pgEntry+`]`).Evidence.BaseImages.Upstream[0]

	// The entry covers its image however the build spells it, pinned
	// or not: an unpinned reference is still this image's, and is
	// refused under it rather than passed by as nobody's.
	for _, ref := range []string{
		"index.docker.io/library/postgres:14-bookworm@" + pgPinDigest,
		"postgres:14-bookworm@" + pgPinDigest,
		"postgres:14-bookworm",
		"postgres",
	} {
		if !entry.Covers(ref) {
			t.Fatalf("the entry does not cover %s", ref)
		}
	}

	for _, ref := range []string{
		"docker.io/library/mysql:8-bookworm@" + pgPinDigest,
		"ghcr.io/library/postgres:14-bookworm@" + pgPinDigest,
		"docker.io/Library/postgres:14",
	} {
		if entry.Covers(ref) {
			t.Fatalf("the entry covers %s", ref)
		}
	}

	tests := []struct {
		name   string
		ref    string
		binds  map[string]string
		reader statements
		want   string // "" for verified
	}{
		{
			name: "verified, the caller's binding agreeing", ref: pgPinRef, binds: map[string]string{"major": "14"},
			reader: statements{platforms: pgPlatforms(pgSourceURI)},
		},
		{
			// The pin file's row key is the major; a row pinning another
			// major's image is the defect the binding catches.
			name: "a tag disagreeing with the caller's binding", ref: pgPinRef,
			binds: map[string]string{"major": "15"},
			want:  pgPinRef + `: the tag's major is "14", the caller bound "15"`,
		},
		{
			name: "no digest — nothing to verify", ref: "postgres:14-bookworm",
			want: "postgres:14-bookworm is an upstream base with no digest — there is nothing to verify",
		},
		{
			name: "a digest but no tag — nothing to derive the source from", ref: "postgres@" + pgPinDigest,
			want: "carries a digest but no tag, so the source it must name cannot be derived",
		},
		{
			name: "Docker's short form, verified", ref: "postgres:14-bookworm@" + pgPinDigest,
			reader: statements{platforms: pgPlatforms(pgSourceURI)},
		},
		{
			name: "a tag the pattern does not read", ref: "docker.io/library/postgres:latest@" + pgPinDigest,
			want: "tag 'latest' does not match ^(?P<major>[0-9]+)-(?P<suite>[a-z]+)$ — the source it must name" +
				" cannot be derived",
		},
		{
			name: "a platform naming another directory", ref: pgPinRef,
			reader: statements{platforms: pgPlatforms(strings.Replace(pgSourceURI, "bookworm", "bullseye", 1))},
			want:   "linux/amd64's provenance names",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var findings []string

			facts, err := entry.JudgeUpstream(tt.ref, tt.binds, tt.reader,
				func(d string) { findings = append(findings, d) })
			if err != nil {
				t.Fatalf("JudgeUpstream = %v", err)
			}

			switch {
			case tt.want == "" && (len(findings) != 0 || len(facts.Platforms) != 2 || facts.Sources[0] != pgSourceURI):
				t.Fatalf("findings = %q, facts = %+v; want verified", findings, facts)
			case tt.want == "":
			case len(findings) != 1 || !strings.Contains(findings[0], tt.want) || len(facts.Platforms) != 0:
				t.Fatalf("findings = %q, facts = %+v; want one finding containing %q", findings, facts, tt.want)
			}
		})
	}

	// The registry not answering is a read the run could not make,
	// never a finding about the image.
	_, err := entry.JudgeUpstream(pgPinRef, nil, statements{err: errors.New("connection refused")},
		func(string) { t.Fatal("a failed read was recorded as a finding") })
	if err == nil || !strings.Contains(err.Error(), "verify: reading "+pgPinRef+"'s provenance: connection refused") {
		t.Fatalf("a failed read = %v", err)
	}
}

func TestUpstreamBinds(t *testing.T) {
	t.Parallel()

	entry := &upstreamPolicy(t, `"upstream": [`+pgEntry+`]`).Evidence.BaseImages.Upstream[0]

	if err := entry.CheckBinds(map[string]string{"major": "14", "suite": "bookworm"}); err != nil {
		t.Fatalf("CheckBinds = %v", err)
	}

	for _, group := range []string{"variant", ""} {
		err := entry.CheckBinds(map[string]string{group: "x"})
		if err == nil || !strings.Contains(err.Error(), `--bind names "`+group+`", which docker.io/library/postgres's`+
			" tag pattern ^(?P<major>[0-9]+)-(?P<suite>[a-z]+)$ does not capture") {
			t.Fatalf("CheckBinds(%q) = %v", group, err)
		}
	}
}

// TestUpstreamHandBuilt holds the guards LoadPolicy shadows: an entry
// built by hand with a pattern that does not compile, or an image that
// is no reference, refuses rather than judging.
func TestUpstreamHandBuilt(t *testing.T) {
	t.Parallel()

	bad, image := "^(?P<major>$", "docker.io/Library/postgres"
	entry := upstreamPolicy(t, `"upstream": [`+pgEntry+`]`).Evidence.BaseImages.Upstream[0]
	entry.TagPattern = &bad

	if err := entry.CheckBinds(nil); err == nil || !strings.Contains(err.Error(), "assert: upstream") {
		t.Fatalf("CheckBinds = %v", err)
	}

	if _, err := entry.Expected(pgPin(t, pgPinRef), nil); err == nil || !strings.Contains(err.Error(), "tagPattern") {
		t.Fatalf("Expected = %v", err)
	}

	entry.Image = &image
	if entry.Covers(pgPinRef) {
		t.Fatal("an entry whose image is no reference covered a pin")
	}
}

// TestBaseClaimants holds the one-claimant rule the build-time gate
// dispatches on: a reference under a scope's prefix is that scope's,
// one of an upstream entry's image is that entry's, and anything else
// is nobody's.
func TestBaseClaimants(t *testing.T) {
	t.Parallel()

	b := upstreamPolicy(t, `"scopes": [`+pinFileScopeJSON+`, `+provenanceScopeJSON+`], "upstream": [`+
		pgEntry+`]`).Evidence.BaseImages

	if s := b.Claimant("ghcr.io/acme/db:latest@" + pgPinDigest); s == nil || *s.Name != "org-bases" {
		t.Fatalf("Claimant(first-party) = %+v, want org-bases", s)
	}

	if u := b.UpstreamFor("postgres:14-bookworm@" + pgPinDigest); u == nil || *u.Image != "docker.io/library/postgres" {
		t.Fatalf("UpstreamFor(postgres) = %+v", u)
	}

	// A pin-file scope declares no prefix and claims nothing here: its
	// population is its pin file, which only the corpus walk reads.
	for _, ref := range []string{"docker.io/library/debian:trixie@" + pgPinDigest, "ghcr.io/other/db:1.0.0"} {
		if b.Claimant(ref) != nil || b.UpstreamFor(ref) != nil {
			t.Fatalf("%s has a claimant", ref)
		}
	}
}
